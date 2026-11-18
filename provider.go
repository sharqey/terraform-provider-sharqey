package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/sharqey/goclient/localvault"
	"github.com/sharqey/terraform-provider-sharqey/internal/client"
	"github.com/sharqey/terraform-provider-sharqey/internal/localstate"
)

// providerMode — which backend sharqey_secret/data source operate against,
// decided once in Configure from whether local_vault_path/
// local_vault_password were set (see sharqeyProviderModel below).
type providerMode string

const (
	modeAPI   providerMode = "api"
	modeLocal providerMode = "local"
)

// localModeData — state for "local mode" (task 066): the provider talks
// directly to a `.sharqey` vault file on disk instead of the Sharqey API.
//
// vault is unlocked exactly ONCE, in Configure, via
// password-manager-goclient/localvault (the single Go implementation of the
// .sharqey format, shared with the CLI and desktop — TASK-004) and kept for
// the rest of the run. It holds only the derived group key, never the
// passphrase.
//
// mu MUST be held for the full duration of every read-modify-write against
// path (see withLocalVault in local_mode.go). This is a correctness
// requirement, not caution: Terraform parallelizes resource operations by
// default (-parallelism=10), and this provider represents ONE vault file as
// potentially MANY sharqey_secret resources. Each Create/Update/Delete does
// a naive "read whole file -> mutate one entry -> write whole file"; without
// serializing that against a single mutex, two concurrent operations racing
// on the same file would silently lose one write (last write wins) with no
// error from Terraform. There is exactly one vault file per provider
// instance, so one mutex per providerData is sufficient — a second
// `provider "sharqey" { alias = "..." }` block pointed at a different file
// gets its own providerData and its own mutex.
type localModeData struct {
	vault *localvault.Vault
	mu    *sync.Mutex
}

// providerData — wstrzykiwane w Configure, dostępne w każdym
// resource/data-source przez req.ProviderData (patrz resource_secret.go,
// ephemeral_secret.go). mode decides which of (api+keychain) vs local is
// populated — the other is left zero-valued.
type providerData struct {
	mode providerMode

	api      *client.Client
	keychain localstate.KeychainFile

	local *localModeData
}

// requireAPIMode — sharqey_group/sharqey_service_account only make sense
// against the online API (a local vault has no groups/subgroups/service
// accounts at all, see localModeData doc). Without this check, calling any
// of their CRUD methods in local vault mode would dereference the nil
// *client.Client left in providerData.api (Configure never populates it in
// local mode) and panic instead of failing with a diagnostic (code review
// finding).
func (d *providerData) requireAPIMode(resourceType string, diags *diag.Diagnostics) bool {
	if d.mode != modeAPI {
		diags.AddError(
			fmt.Sprintf("%s is not supported in local vault mode", resourceType),
			"The provider is configured with local_vault_path/local_vault_password — a local vault file has no groups or service accounts, only a flat list of secrets (sharqey_secret). Remove this resource or switch the provider back to API mode.",
		)
		return false
	}
	return true
}

// privateKeyForOrg — ten sam lookup co `sharqey get` (cmd/cli/ls_get.go):
// SecretEntry.OrgID (root grupy, zwrócony przez server) musi mieć
// odpowiadający wpis w lokalnym keychainie. Used only in API mode.
func (d *providerData) privateKeyForOrg(orgID string) (string, bool) {
	for _, e := range d.keychain.Entries {
		if e.OrgID == orgID {
			return e.PrivateKeyArmored, true
		}
	}
	return "", false
}

type sharqeyProvider struct{}

func New() provider.Provider {
	return &sharqeyProvider{}
}

// sharqeyProviderModel — provider-level config. Setting neither
// LocalVaultPassword nor LocalVaultIdentityKeyFile (together with
// LocalVaultPath) keeps today's behavior (auth from local `sharqey login`
// session, talk to the API); setting local_vault_path with EXACTLY ONE of
// the other two switches to local vault mode (enforced in ValidateConfig) —
// local_vault_password unlocks the file's own passphrase-protected identity,
// local_vault_identity_key_file (task 067) unlocks it with a private key
// supplied from outside the file entirely (a file on disk holding an armored
// PGP key — the vault's own generated identity exported once, or a real key
// from the caller's own GPG keyring), mirroring how `sops` uses PGP keys
// that live in the user's keyring rather than in the encrypted file.
type sharqeyProviderModel struct {
	LocalVaultPath                  types.String `tfsdk:"local_vault_path"`
	LocalVaultPassword              types.String `tfsdk:"local_vault_password"`
	LocalVaultIdentityKeyFile       types.String `tfsdk:"local_vault_identity_key_file"`
	LocalVaultIdentityKeyPassphrase types.String `tfsdk:"local_vault_identity_key_passphrase"`
	LocalVaultUseSystemGPG          types.Bool   `tfsdk:"local_vault_use_system_gpg"`
}

func (p *sharqeyProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sharqey"
}

// Schema — mostly still empty for the online path (PoC celowo NIE ma
// provider-level auth attrybutów server_url/token — auth jest WYŁĄCZNIE
// lokalna sesja CLI, zgodnie z DoD tasku 026). local_vault_path/
// local_vault_password (task 066) are the one deliberate exception: they
// don't authenticate against the API at all, they replace it entirely with
// a local file, so they don't reopen that original decision.
func (p *sharqeyProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "PoC provider dla Sharqey — auth lokalna z sesji `sharqey login`, brak własnego mechanizmu logowania. Alternatively, set local_vault_path together with EXACTLY ONE of local_vault_password / local_vault_identity_key_file to operate directly on an offline `.sharqey` vault file instead of the API.",
		Attributes: map[string]schema.Attribute{
			"local_vault_path": schema.StringAttribute{
				Optional:    true,
				Description: "Path to a local `.sharqey` vault file (format_version 4). When set (together with local_vault_password or local_vault_identity_key_file), this provider operates entirely on that file instead of the Sharqey API — no `sharqey login` session is required. Must be set together with exactly one of those two, or not at all.",
			},
			"local_vault_password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Master password for the vault's own passphrase-protected identity recipient at local_vault_path. Mutually exclusive with local_vault_identity_key_file.",
			},
			"local_vault_identity_key_file": schema.StringAttribute{
				Optional:    true,
				Description: "Path to an armored PGP private key file on disk — unlocks the vault at local_vault_path as one of its recipients, WITHOUT needing local_vault_password (task 067: mirrors how `sops` uses PGP keys that live in the caller's own keyring/CI secrets rather than in the encrypted file). The key must match one of the vault's recipients (see password-manager-desktop's AddRecipient) — it does not have to be the vault's own generated identity. Mutually exclusive with local_vault_password.",
			},
			"local_vault_identity_key_passphrase": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Passphrase protecting the key at local_vault_identity_key_file, if it has one (a plaintext-exported key needs none). Only valid together with local_vault_identity_key_file — this is a different secret than local_vault_password.",
			},
			"local_vault_use_system_gpg": schema.BoolAttribute{
				Optional:    true,
				Description: "Unlock the vault at local_vault_path by shelling out to the local `gpg` binary (task 067 \"Faza 3\") instead of supplying a private key to this config at all — gpg-agent/pinentry own the key and its passphrase, this provider never sees either. This is the direct equivalent of how `carlpett/sops` decrypts PGP files today, and the recommended option when the vault's recipient is a real, already-unlocked personal GPG key rather than a dedicated machine key. Mutually exclusive with local_vault_password and local_vault_identity_key_file.",
			},
		},
	}
}

// ValidateConfig enforces that local_vault_path is set together with
// EXACTLY ONE of local_vault_password / local_vault_identity_key_file, or
// none of the three at all (API mode) — a path with neither auth mode can
// never be unlocked, an auth mode with no path has nothing to unlock, and
// both auth modes at once is an ambiguous config (not "password wins" or
// "key file wins") — so it's better to fail fast here than to fall through
// to whichever branch Configure happens to check first.
func (p *sharqeyProvider) ValidateConfig(ctx context.Context, req provider.ValidateConfigRequest, resp *provider.ValidateConfigResponse) {
	var cfg sharqeyProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Unknown values (e.g. derived from a resource/data source not yet
	// applied) can't be validated yet — Terraform re-validates once they're
	// known, so just skip rather than false-alarm.
	if cfg.LocalVaultPath.IsUnknown() || cfg.LocalVaultPassword.IsUnknown() ||
		cfg.LocalVaultIdentityKeyFile.IsUnknown() || cfg.LocalVaultIdentityKeyPassphrase.IsUnknown() ||
		cfg.LocalVaultUseSystemGPG.IsUnknown() {
		return
	}

	// IsNull, NOT ValueString() != "" — a vault created without a
	// passphrase (localvault.Unlock succeeds with an empty
	// password) is a real,
	// supported shape; treating an explicitly-set empty string the same as
	// "not set" would make such a vault impossible to configure here (code
	// review finding). Same reasoning applies to an unprotected
	// local_vault_identity_key_file (empty local_vault_identity_key_passphrase).
	hasPath := !cfg.LocalVaultPath.IsNull()
	hasPassword := !cfg.LocalVaultPassword.IsNull()
	hasIdentityKeyFile := !cfg.LocalVaultIdentityKeyFile.IsNull()
	hasIdentityKeyPassphrase := !cfg.LocalVaultIdentityKeyPassphrase.IsNull()
	hasSystemGPG := !cfg.LocalVaultUseSystemGPG.IsNull() && cfg.LocalVaultUseSystemGPG.ValueBool()

	authModesSet := 0
	for _, set := range []bool{hasPassword, hasIdentityKeyFile, hasSystemGPG} {
		if set {
			authModesSet++
		}
	}
	if authModesSet > 1 {
		resp.Diagnostics.AddError(
			"Conflicting local vault auth configuration",
			"local_vault_password, local_vault_identity_key_file and local_vault_use_system_gpg are mutually exclusive — set at most one of them.",
		)
		return
	}
	if hasIdentityKeyPassphrase && !hasIdentityKeyFile {
		resp.Diagnostics.AddError(
			"Incomplete local vault configuration",
			"local_vault_identity_key_passphrase is only valid together with local_vault_identity_key_file.",
		)
		return
	}

	hasAnyAuth := authModesSet > 0
	if hasPath != hasAnyAuth {
		resp.Diagnostics.AddError(
			"Incomplete local vault configuration",
			"local_vault_path must be set together with exactly one of local_vault_password / local_vault_identity_key_file / local_vault_use_system_gpg, or none of those at all (to use the Sharqey API instead).",
		)
	}
}

func (p *sharqeyProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg sharqeyProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := cfg.LocalVaultPath.ValueString()
	// !IsNull(), matching ValidateConfig — an explicitly empty
	// local_vault_password/local_vault_identity_key_passphrase is a real,
	// supported shape (no passphrase), not "not set".
	if !cfg.LocalVaultPath.IsNull() {
		if resp.Diagnostics.Append(checkLocalDatabaseExists(path)...); resp.Diagnostics.HasError() {
			return
		}
		var v *localvault.Vault
		var err error
		switch {
		case !cfg.LocalVaultPassword.IsNull():
			v, err = localvault.Unlock(path, cfg.LocalVaultPassword.ValueString())
		case !cfg.LocalVaultIdentityKeyFile.IsNull():
			keyBytes, readErr := os.ReadFile(cfg.LocalVaultIdentityKeyFile.ValueString())
			if readErr != nil {
				resp.Diagnostics.AddError("Failed to read local_vault_identity_key_file", readErr.Error())
				return
			}
			v, err = localvault.UnlockWithExternalKey(path, string(keyBytes), cfg.LocalVaultIdentityKeyPassphrase.ValueString())
		case !cfg.LocalVaultUseSystemGPG.IsNull() && cfg.LocalVaultUseSystemGPG.ValueBool():
			v, err = localvault.UnlockWithSystemGPG(path)
		default:
			resp.Diagnostics.AddError("Incomplete local vault configuration", "local_vault_path needs one of local_vault_password / local_vault_identity_key_file / local_vault_use_system_gpg.")
			return
		}
		if err != nil {
			resp.Diagnostics.AddError("Failed to unlock local vault", err.Error())
			return
		}
		pd := &providerData{
			mode:  modeLocal,
			local: &localModeData{vault: v, mu: &sync.Mutex{}},
		}
		resp.DataSourceData = pd
		resp.ResourceData = pd
		resp.EphemeralResourceData = pd
		return
	}

	cliCfg := localstate.LoadConfig()
	if cliCfg.Token == "" {
		resp.Diagnostics.AddError(
			"Not signed in",
			"No local Sharqey session found. Run `sharqey login` first (or configure local_vault_path/local_vault_password to use an offline vault file instead).",
		)
		return
	}
	kc, err := localstate.LoadKeychain()
	if err != nil {
		resp.Diagnostics.AddError("Failed to read local keychain", err.Error())
		return
	}
	if len(kc.Entries) == 0 {
		resp.Diagnostics.AddError(
			"No keys in local keychain",
			"Run `sharqey login` and approve the device-link request in the browser extension.",
		)
		return
	}

	pd := &providerData{
		mode:     modeAPI,
		api:      client.New(cliCfg.ServerURL, cliCfg.Token),
		keychain: kc,
	}
	resp.DataSourceData = pd
	resp.ResourceData = pd
	resp.EphemeralResourceData = pd
}

func (p *sharqeyProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSecretResource,
		NewGroupResource,
		NewServiceAccountResource,
		NewFileSecretResource,
		NewSSOResource,
	}
}

// DataSources — data "sharqey_secret" kładzie odszyfrowaną wartość w
// stanie; domyślną drogą jest ephemeral o tej samej nazwie (TASK-002).
func (p *sharqeyProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSecretDataSource,
	}
}

func (p *sharqeyProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		NewSecretEphemeral,
	}
}

var _ provider.ProviderWithEphemeralResources = &sharqeyProvider{}
