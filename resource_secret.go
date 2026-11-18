package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/sharqey/goclient/localvault"
	"github.com/sharqey/goclient/pgpcrypto"
	"github.com/sharqey/terraform-provider-sharqey/internal/client"
	"github.com/sharqey/terraform-provider-sharqey/internal/secretcrypto"
)

type secretResource struct {
	pd *providerData
}

func NewSecretResource() resource.Resource {
	return &secretResource{}
}

type secretResourceModel struct {
	ID       types.String `tfsdk:"id"`
	Group    types.String `tfsdk:"group"`
	Type     types.String `tfsdk:"type"`
	Title    types.String `tfsdk:"title"`
	Username types.String `tfsdk:"username"`
	URL      types.String `tfsdk:"url"`
	// Value/Notes — write-only (TASK-002): w planie i stanie zawsze null,
	// prawdziwe wartości są tylko w req.Config.
	Value     types.String `tfsdk:"value"`
	Notes     types.String `tfsdk:"notes"`
	UpdatedAt types.String `tfsdk:"updated_at"`
}

func (r *secretResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// Version 1 — TASK-002 (write-only), migracja w state_upgrade.go.
		Version:     1,
		Description: "A Sharqey secret (account or env). In API mode (default) it lives inside an existing group (\"group\" required). In local vault mode (provider's local_vault_path/local_vault_password set) it lives in the flat vault file instead and \"group\" must be omitted — secrets are identified by \"title\", which must be unique within the vault.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Secret ID — server-assigned UUID in API mode, a random local ID in local vault mode.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"group": schema.StringAttribute{
				Optional:    true,
				Description: "Full path of the group this secret lives in, e.g. \"acme-corp/engineering\". Required in API mode, forbidden in local vault mode (a local vault is one flat list of secrets, no subgroups).",
			},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "\"account\" or \"env\".",
			},
			"title": schema.StringAttribute{
				Required:    true,
				Description: "In local vault mode this is also the sole identifier used to find the secret (must be unique within the vault).",
			},
			"username": schema.StringAttribute{
				Optional: true,
			},
			"url": schema.StringAttribute{
				Optional: true,
			},
			"value": schema.StringAttribute{
				Required:    true,
				WriteOnly:   true,
				Sensitive:   true,
				Description: "The secret value (password for \"account\", value for \"env\"). Write-only: never stored in Terraform state. Encrypted locally before it ever reaches the server / the vault file. Changes are detected by decrypting the stored ciphertext during plan and comparing.",
			},
			"notes": schema.StringAttribute{
				Optional:    true,
				WriteOnly:   true,
				Description: "Notes, encrypted together with the value. Write-only, like \"value\".",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Server-side last modification time (API mode). Null in local vault mode. Becomes unknown in the plan whenever the secret will be rewritten, including when only the write-only value differs.",
			},
		},
	}
}

func (r *secretResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	pd, ok := req.ProviderData.(*providerData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type", fmt.Sprintf("%T", req.ProviderData))
		return
	}
	r.pd = pd
}

// ValidateConfig enforces the "group" required-in-API-mode /
// forbidden-in-local-mode rule described in the schema. This only runs the
// mode-specific half of the check when r.pd is already populated: Terraform
// can invoke ValidateConfig (e.g. during `terraform validate`) before
// Configure has ever run for this resource, in which case the provider's
// mode isn't known yet and we have nothing to check against — Create/Update
// re-validate group-vs-mode defensively anyway (see requireGroupForMode
// below), so an early `terraform validate` without a configured provider
// isn't a hole, just a missed opportunity to fail slightly earlier.
func (r *secretResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg secretResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.pd == nil || cfg.Group.IsUnknown() {
		return
	}
	hasGroup := !cfg.Group.IsNull() && cfg.Group.ValueString() != ""
	switch r.pd.mode {
	case modeLocal:
		if hasGroup {
			resp.Diagnostics.AddError("\"group\" not allowed in local vault mode", "The provider is configured with local_vault_path/local_vault_password — a local vault is a flat list of secrets with no subgroups, so \"group\" must be omitted.")
		}
	case modeAPI:
		if !hasGroup {
			resp.Diagnostics.AddError("\"group\" is required", "\"group\" must be set when the provider is talking to the Sharqey API (local_vault_path/local_vault_password not set).")
		}
	}
}

// requireGroupForMode — defensive runtime re-check of the ValidateConfig
// rule above, for the case ValidateConfig ran before Configure and thus
// couldn't check mode yet (see comment there).
func (r *secretResource) requireGroupForMode(group string) error {
	hasGroup := group != ""
	if r.pd.mode == modeLocal && hasGroup {
		return fmt.Errorf("\"group\" is not allowed in local vault mode")
	}
	if r.pd.mode == modeAPI && !hasGroup {
		return fmt.Errorf("\"group\" is required in API mode")
	}
	return nil
}

// secretPlaintext — kształt DOKŁADNIE taki jak group/show.html buduje przed
// szyfrowaniem (`JSON.stringify({password, totp_secret, notes})` dla
// "account", `{value, notes}` dla "env") — patrz project_prototype_status
// w pamięci projektu. TotpSecret zawsze pusty: provider nie zarządza TOTP.
// Współdzielone między API mode i local vault mode (treść sekretu w
// lokalnym vaulcie to dokładnie ten sam JSON string).
type secretPlaintext struct {
	Password   string `json:"password,omitempty"`
	Value      string `json:"value,omitempty"`
	TOTPSecret string `json:"totp_secret,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

func buildPlaintext(secretType, value, notes string) (string, error) {
	p := secretPlaintext{Notes: notes}
	switch secretType {
	case "account":
		p.Password = value
	case "env":
		p.Value = value
	default:
		return "", fmt.Errorf("invalid type %q — must be \"account\" or \"env\"", secretType)
	}
	b, err := json.Marshal(p)
	return string(b), err
}

// optionalString — serwer zwraca "" dla nieustawionych opcjonalnych pól
// (username/url/notes), ale config Terraform je zostawia jako null (nie
// ""), gdy user ich nie poda. Bez tego rozróżnienia Read() ustawiłby state
// na "" na zawsze inne niż null z configu → wieczny fałszywy diff przy
// KAŻDYM planie, nawet bez żadnej realnej zmiany.
func optionalString(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

func parsePlaintext(plaintext string) (value, notes string, err error) {
	var p secretPlaintext
	if err := json.Unmarshal([]byte(plaintext), &p); err != nil {
		return "", "", err
	}
	if p.Password != "" {
		return p.Password, p.Notes, nil
	}
	return p.Value, p.Notes, nil
}

// encryptForGroup — GetMyGroupKey + EncryptGroupSecret, wspólne dla Create/Update.
// groupFullPath (nie groupID!) bo OrgIDForPath potrzebuje ścieżki, żeby
// wyłuskać pierwszy segment (slug roota) — groupID to UUID subgrupy, nie
// niesie tej informacji. Zwraca od razu materiał do private state — ten
// sam, który poleci na serwer, więc po zapisie nie trzeba robić GetSecret.
func (r *secretResource) encryptForGroup(groupID, groupFullPath string, private bool, secretType, value, notes string) (*storedSecret, error) {
	orgID, err := r.pd.api.OrgIDForPath(groupFullPath)
	if err != nil {
		return nil, err
	}
	privateKey, ok := r.pd.privateKeyForOrg(orgID)
	if !ok {
		return nil, fmt.Errorf("no local key for organization %s — run `sharqey login`", orgID)
	}
	plaintext, err := buildPlaintext(secretType, value, notes)
	if err != nil {
		return nil, err
	}
	if private {
		// Drzewo Private nie ma group_key: sekret idzie wprost do klucza
		// publicznego właściciela (jak sharqey_file_secret).
		pub, err := pgpcrypto.PublicKeyFromPrivateKeyArmored(privateKey)
		if err != nil {
			return nil, fmt.Errorf("derive public key: %w", err)
		}
		ciphertext, ownerKey, err := pgpcrypto.EncryptOwnerSecret(plaintext, pub)
		if err != nil {
			return nil, err
		}
		return &storedSecret{OrgID: orgID, GroupID: groupID, Ciphertext: ciphertext, OwnerEncryptedSecretKey: ownerKey}, nil
	}
	myGroupKey, err := r.pd.api.GetMyGroupKey(groupID)
	if err != nil {
		return nil, fmt.Errorf("get my-group-key: %w", err)
	}
	ciphertext, groupEncryptedSecretKey, err := secretcrypto.EncryptGroupSecret(plaintext, myGroupKey, privateKey, "")
	if err != nil {
		return nil, err
	}
	return &storedSecret{
		OrgID:                   orgID,
		GroupID:                 groupID,
		Ciphertext:              ciphertext,
		GroupEncryptedSecretKey: groupEncryptedSecretKey,
		GroupKey:                myGroupKey,
	}, nil
}

// findEntry — metadane sekretu z listy grupy (nil, gdy go nie ma). Jedyne
// źródło updated_at: GetSecret go nie zwraca.
func (r *secretResource) findEntry(groupID, secretID string) (*client.SecretEntry, error) {
	secrets, err := r.pd.api.GroupSecrets(groupID)
	if err != nil {
		return nil, fmt.Errorf("list group secrets: %w", err)
	}
	for i := range secrets {
		if secrets[i].ID == secretID {
			return &secrets[i], nil
		}
	}
	return nil, nil
}

// secretConfig — write-only value/notes; są wyłącznie w configu.
func secretConfig(ctx context.Context, cfg tfsdk.Config) (value, notes types.String, diags diag.Diagnostics) {
	diags.Append(cfg.GetAttribute(ctx, path.Root("value"), &value)...)
	diags.Append(cfg.GetAttribute(ctx, path.Root("notes"), &notes)...)
	return value, notes, diags
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan secretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	value, notes, diags := secretConfig(ctx, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.requireGroupForMode(plan.Group.ValueString()); err != nil {
		resp.Diagnostics.AddError("Invalid configuration", err.Error())
		return
	}

	if r.pd.mode == modeLocal {
		r.createLocal(ctx, &plan, value.ValueString(), notes.ValueString(), resp)
		return
	}

	group, err := r.pd.api.ResolveGroup(plan.Group.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve group", err.Error())
		return
	}

	// encryptForGroup wywołuje OrgIDForPath z group.FullPath (nie
	// plan.Group.ValueString(), które może mieć nadmiarowe "/") — resolveGroup
	// zwraca już znormalizowaną ścieżkę.
	stored, err := r.encryptForGroup(group.ID, group.FullPath, group.IsPrivate, plan.Type.ValueString(), value.ValueString(), notes.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to encrypt secret", err.Error())
		return
	}

	secretID, err := r.pd.api.CreateGroupSecret(client.CreateGroupSecretParams{
		GroupID:                 group.ID,
		Type:                    plan.Type.ValueString(),
		Title:                   plan.Title.ValueString(),
		Username:                plan.Username.ValueString(),
		URL:                     plan.URL.ValueString(),
		Ciphertext:              stored.Ciphertext,
		GroupEncryptedSecretKey: stored.GroupEncryptedSecretKey,
		OwnerEncryptedSecretKey: stored.OwnerEncryptedSecretKey,
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to create secret", err.Error())
		return
	}

	plan.ID = types.StringValue(secretID)
	plan.Group = types.StringValue(group.FullPath)
	resp.Diagnostics.Append(r.finishAPIWrite(ctx, &plan, stored, resp.Private)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// finishAPIWrite — po Create/Update: updated_at z listy grupy (serwer go
// nadaje) i świeżo zapisany ciphertext do private state.
func (r *secretResource) finishAPIWrite(ctx context.Context, m *secretResourceModel, stored *storedSecret, private privateWriter) diag.Diagnostics {
	var diags diag.Diagnostics
	entry, err := r.findEntry(stored.GroupID, m.ID.ValueString())
	if err != nil {
		diags.AddError("Failed to read back secret", err.Error())
		return diags
	}
	if entry == nil {
		diags.AddError("Failed to read back secret", fmt.Sprintf("secret %s not found right after writing it", m.ID.ValueString()))
		return diags
	}
	m.UpdatedAt = updatedAtValue(entry.UpdatedAt)
	return saveStored(ctx, private, stored)
}

// createLocal appends a brand-new secret to the local vault file. Titles
// must be unique within the vault (see findLocalByTitle) — a title
// collision is an error, not a silent overwrite of the existing secret.
func (r *secretResource) createLocal(ctx context.Context, plan *secretResourceModel, value, notes string, resp *resource.CreateResponse) {
	title := plan.Title.ValueString()
	plaintext, err := buildPlaintext(plan.Type.ValueString(), value, notes)
	if err != nil {
		resp.Diagnostics.AddError("Failed to build secret plaintext", err.Error())
		return
	}

	var newID string
	err = withLocalVault(r.pd, func(v *localvault.Vault) error {
		_, exists, ferr := findLocalByTitle(v, title, "")
		if ferr != nil {
			return ferr
		}
		if exists {
			return fmt.Errorf("a secret titled %q already exists in the local vault", title)
		}
		s, addErr := v.AddSecret(plan.Type.ValueString(), title, plan.Username.ValueString(), plan.URL.ValueString(), "", false, []byte(plaintext))
		if addErr != nil {
			return addErr
		}
		newID = s.ID
		return nil
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to create secret in local vault", err.Error())
		return
	}

	plan.ID = types.StringValue(newID)
	plan.Group = types.StringNull()
	plan.UpdatedAt = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read odświeża wyłącznie metadane — nic tu nie jest odszyfrowywane
// (TASK-002). W API mode lista grupy (jeden request) daje updated_at; gdy
// jest taki sam jak w stanie, private state jest aktualny i nie ma czego
// pobierać. Gdy się zmienił (edycja w UI, inny klient), dociągamy nowy
// ciphertext do private state — porównanie z configiem robi ModifyPlan.
func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.pd.mode == modeLocal {
		r.readLocal(ctx, &state, resp)
		return
	}

	group, err := r.pd.api.ResolveGroup(state.Group.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve group", err.Error())
		return
	}
	found, err := r.findEntry(group.ID, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to list group secrets", err.Error())
		return
	}
	if found == nil {
		// Sekret zniknął po drugiej stronie (usunięty ręcznie w web UI) —
		// standardowa konwencja frameworka: puste ID w state = "usuń z planu".
		resp.State.RemoveResource(ctx)
		return
	}

	stored, diags := loadStored(ctx, req.Private)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	updatedAt := updatedAtValue(found.UpdatedAt)
	if stored == nil || stored.GroupID != group.ID || !updatedAt.Equal(state.UpdatedAt) {
		detail, err := r.pd.api.GetSecret(group.ID, found.ID)
		if err != nil {
			resp.Diagnostics.AddError("Failed to get secret", err.Error())
			return
		}
		stored = &storedSecret{OrgID: found.OrgID, GroupID: group.ID}
		stored.setDetail(detail)
		resp.Diagnostics.Append(saveStored(ctx, resp.Private, stored)...)
	}

	state.Type = types.StringValue(found.Type)
	state.Title = types.StringValue(found.Title)
	state.Username = optionalString(found.Username)
	state.URL = optionalString(found.URL)
	state.UpdatedAt = updatedAt
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// readLocal re-reads the vault file (see withLocalVault doc for why: another
// process could have changed it since Create/last Read) and looks up the
// secret by ID. If the ID is gone the secret was removed elsewhere (e.g. a
// hand-edit of the vault file, or another tool) — same "drop from state"
// convention as the API-mode Read above. Only metadata; the encrypted value
// is compared in ModifyPlan.
func (r *secretResource) readLocal(ctx context.Context, state *secretResourceModel, resp *resource.ReadResponse) {
	var secret localvault.Secret
	found := false

	err := withLocalVault(r.pd, func(v *localvault.Vault) error {
		var lookupErr error
		secret, found, lookupErr = v.SecretByID(state.ID.ValueString())
		return lookupErr
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to read local vault", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	state.Type = types.StringValue(secret.Type)
	state.Title = types.StringValue(secret.Title)
	state.Username = optionalString(secret.Username)
	state.URL = optionalString(secret.URL)
	state.Group = types.StringNull()
	state.UpdatedAt = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// ModifyPlan wykrywa zmianę write-only value/notes: odszyfrowuje bieżący
// sekret (API mode: ciphertext z private state, bez sieci; local mode:
// z pliku) i porównuje z configiem. Różnica oznacza update, sygnalizowany
// przez updated_at = unknown — sam value jest w planie zawsze null.
func (r *secretResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() || r.pd == nil {
		return
	}
	var state secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	value, notes, diags := secretConfig(ctx, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	changed := value.IsUnknown() || notes.IsUnknown()
	if !changed {
		curValue, curNotes, ok := r.currentPlaintext(ctx, state, req.Private, resp)
		if resp.Diagnostics.HasError() {
			return
		}
		changed = !ok || curValue != value.ValueString() || curNotes != notes.ValueString()
	}
	if changed {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("updated_at"), types.StringUnknown())...)
	}
}

// currentPlaintext — ok=false, gdy nie ma czego porównać (brak materiału w
// private state albo sekretu w pliku) — wtedy plan zakłada zmianę.
func (r *secretResource) currentPlaintext(ctx context.Context, state secretResourceModel, private privateReader, resp *resource.ModifyPlanResponse) (value, notes string, ok bool) {
	var plaintext string
	if r.pd.mode == modeLocal {
		err := withLocalVault(r.pd, func(v *localvault.Vault) error {
			if _, found, err := v.SecretByID(state.ID.ValueString()); err != nil || !found {
				return err
			}
			_, content, err := v.DecryptSecret(state.ID.ValueString())
			plaintext, ok = string(content), err == nil
			return err
		})
		if err != nil {
			resp.Diagnostics.AddError("Failed to read local vault", err.Error())
			return "", "", false
		}
	} else {
		stored, diags := loadStored(ctx, private)
		resp.Diagnostics.Append(diags...)
		if stored == nil {
			return "", "", false
		}
		var err error
		plaintext, err = decryptStored(r.pd, stored, state.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Failed to decrypt secret", err.Error())
			return "", "", false
		}
		// decryptStored mógł dociągnąć świeży materiał (inna tożsamość).
		resp.Diagnostics.Append(saveStored(ctx, resp.Private, stored)...)
		ok = true
	}
	if !ok {
		return "", "", false
	}
	value, notes, err := parsePlaintext(plaintext)
	if err != nil {
		resp.Diagnostics.AddError("Failed to parse decrypted secret", err.Error())
		return "", "", false
	}
	return value, notes, true
}

func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan secretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	var state secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	value, notes, diags := secretConfig(ctx, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.requireGroupForMode(plan.Group.ValueString()); err != nil {
		resp.Diagnostics.AddError("Invalid configuration", err.Error())
		return
	}

	if r.pd.mode == modeLocal {
		r.updateLocal(ctx, &plan, &state, value.ValueString(), notes.ValueString(), resp)
		return
	}

	group, err := r.pd.api.ResolveGroup(plan.Group.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve group", err.Error())
		return
	}

	stored, err := r.encryptForGroup(group.ID, group.FullPath, group.IsPrivate, plan.Type.ValueString(), value.ValueString(), notes.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to encrypt secret", err.Error())
		return
	}

	err = r.pd.api.UpdateGroupSecret(client.UpdateGroupSecretParams{
		GroupID:                 group.ID,
		SecretID:                state.ID.ValueString(),
		Title:                   plan.Title.ValueString(),
		Username:                plan.Username.ValueString(),
		URL:                     plan.URL.ValueString(),
		Ciphertext:              &stored.Ciphertext,
		GroupEncryptedSecretKey: ownerOrNil(stored.GroupEncryptedSecretKey),
		OwnerEncryptedSecretKey: ownerOrNil(stored.OwnerEncryptedSecretKey),
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to update secret", err.Error())
		return
	}

	plan.ID = state.ID
	plan.Group = types.StringValue(group.FullPath)
	resp.Diagnostics.Append(r.finishAPIWrite(ctx, &plan, stored, resp.Private)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// updateLocal re-encrypts the secret identified by state.ID and rewrites its
// title, checking the same title-uniqueness rule as createLocal — except
// here "the same title as some OTHER secret" is the only collision that
// matters, since the plan is allowed to keep this secret's own current
// title unchanged. Group and has_totp (set in other clients, not managed
// here) are preserved. Changing the type of a local secret in place isn't
// supported by the vault format's update path — recreate it instead.
func (r *secretResource) updateLocal(ctx context.Context, plan, state *secretResourceModel, value, notes string, resp *resource.UpdateResponse) {
	title := plan.Title.ValueString()
	plaintext, err := buildPlaintext(plan.Type.ValueString(), value, notes)
	if err != nil {
		resp.Diagnostics.AddError("Failed to build secret plaintext", err.Error())
		return
	}

	err = withLocalVault(r.pd, func(v *localvault.Vault) error {
		id := state.ID.ValueString()
		_, clash, ferr := findLocalByTitle(v, title, id)
		if ferr != nil {
			return ferr
		}
		if clash {
			return fmt.Errorf("a different secret titled %q already exists in the local vault", title)
		}
		existing, ok, lookupErr := v.SecretByID(id)
		if lookupErr != nil {
			return lookupErr
		}
		if !ok {
			return fmt.Errorf("secret id %q no longer exists in the local vault", id)
		}
		if existing.Type != plan.Type.ValueString() {
			return fmt.Errorf("changing the type of a local vault secret (%q -> %q) is not supported — remove and recreate it (e.g. `terraform apply -replace=...`)", existing.Type, plan.Type.ValueString())
		}
		return v.UpdateSecret(id, title, plan.Username.ValueString(), plan.URL.ValueString(), existing.GroupID, existing.HasTOTP, []byte(plaintext))
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to update secret in local vault", err.Error())
		return
	}

	plan.ID = state.ID
	plan.Group = types.StringNull()
	plan.UpdatedAt = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.pd.mode == modeLocal {
		r.deleteLocal(state, resp)
		return
	}

	group, err := r.pd.api.ResolveGroup(state.Group.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve group", err.Error())
		return
	}
	if err := r.pd.api.DeleteGroupSecret(group.ID, state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to delete secret", err.Error())
		return
	}
}

// deleteLocal removes the secret by ID. A missing ID (already gone) is not
// an error — Delete is expected to be idempotent, same as the API path
// treats a 404 from DeleteGroupSecret (handled inside client.Client, not
// shown here) as success.
func (r *secretResource) deleteLocal(state secretResourceModel, resp *resource.DeleteResponse) {
	err := withLocalVault(r.pd, func(v *localvault.Vault) error {
		if _, ok, err := v.SecretByID(state.ID.ValueString()); err != nil || !ok {
			return err
		}
		return v.DeleteSecret(state.ID.ValueString())
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to delete secret from local vault", err.Error())
	}
}

var (
	_ resource.Resource                   = &secretResource{}
	_ resource.ResourceWithModifyPlan     = &secretResource{}
	_ resource.ResourceWithValidateConfig = &secretResource{}
)

// ownerOrNil — puste pole klucza oznacza „nie dotyczy tego trybu” (grupa z
// group_key vs. drzewo Private), więc nie jest wysyłane.
func ownerOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
