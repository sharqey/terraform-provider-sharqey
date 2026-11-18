package main

import (
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/sharqey/goclient/localvault"
	"github.com/sharqey/terraform-provider-sharqey/internal/client"
)

// Odczyt istniejącego sekretu — wspólny dla ephemeral "sharqey_secret"
// (domyślna droga, nic nie trafia do stanu) i data "sharqey_secret"
// (wartość ląduje w stanie; tylko dla konsumentów, którzy nie przyjmują
// wartości ephemeral, np. gitea_repository_actions_secret.secret_value).

type secretLookupModel struct {
	Group    types.String `tfsdk:"group"`
	Slug     types.String `tfsdk:"slug"`
	Title    types.String `tfsdk:"title"`
	ID       types.String `tfsdk:"id"`
	Type     types.String `tfsdk:"type"`
	Username types.String `tfsdk:"username"`
	URL      types.String `tfsdk:"url"`
	Value    types.String `tfsdk:"value"`
	Notes    types.String `tfsdk:"notes"`
	// Filename/ContentBase64 — tylko dla sekretów typu "file" (tryb lokalnego
	// vaulta od format_version 5 — password-manager-cli TASK-004 — i tryb API).
	Filename      types.String `tfsdk:"filename"`
	ContentBase64 types.String `tfsdk:"content_base64"`
}

// secretLookupAttr — opis jednego atrybutu, z którego oba pakiety schematów
// (ephemeral/schema, datasource/schema) budują swoje StringAttribute.
type secretLookupAttr struct {
	optional, sensitive bool
	description         string
}

var secretLookupAttrs = map[string]secretLookupAttr{
	"group":          {optional: true, description: "Full path of the group this secret lives in, e.g. \"acme-corp/engineering\". Required in API mode, forbidden in local vault mode."},
	"slug":           {optional: true, description: "Secret slug within that group (same as `sharqey ls` shows). Used in API mode; mutually exclusive with \"title\"."},
	"title":          {optional: true, description: "Secret title, used to look it up in local vault mode instead of \"slug\". Must be unique within the vault."},
	"id":             {},
	"type":           {},
	"username":       {},
	"url":            {},
	"value":          {sensitive: true, description: "Decrypted secret value."},
	"notes":          {},
	"filename":       {description: "Original file name, for secrets of type \"file\". Null for other types."},
	"content_base64": {sensitive: true, description: "File content, base64-encoded, for secrets of type \"file\". Null for other types; \"value\" is empty for files."},
}

const secretLookupDescription = "In API mode (default), identify it with \"group\" + \"slug\". In local vault mode (provider's local_vault_path/local_vault_password set), identify it with \"title\" instead — \"group\" and \"slug\" are not used."

// validateSecretLookup — same "know the mode before we can fully validate"
// caveat as secretResource.ValidateConfig: the mode-specific checks only run
// once pd is populated (Configure has run). The universal "not both slug and
// title" check runs regardless, since that's never valid in either mode.
func validateSecretLookup(pd *providerData, cfg secretLookupModel) diag.Diagnostics {
	var diags diag.Diagnostics
	hasGroup := !cfg.Group.IsNull() && !cfg.Group.IsUnknown() && cfg.Group.ValueString() != ""
	hasSlug := !cfg.Slug.IsNull() && !cfg.Slug.IsUnknown() && cfg.Slug.ValueString() != ""
	hasTitle := !cfg.Title.IsNull() && !cfg.Title.IsUnknown() && cfg.Title.ValueString() != ""

	if hasSlug && hasTitle {
		diags.AddError("Only one of \"slug\" or \"title\" may be set", "\"slug\" identifies a secret in API mode, \"title\" in local vault mode — set only the one matching how the provider is configured.")
	}

	if pd == nil {
		return diags
	}
	switch pd.mode {
	case modeLocal:
		if hasGroup {
			diags.AddError("\"group\" not allowed in local vault mode", "The provider is configured with local_vault_path/local_vault_password — a local vault is a flat list of secrets with no subgroups, so \"group\" must be omitted.")
		}
		if hasSlug {
			diags.AddError("\"slug\" not allowed in local vault mode", "Use \"title\" instead of \"slug\" to identify a secret when the provider is configured with local_vault_path.")
		}
		if !hasTitle {
			diags.AddError("\"title\" is required in local vault mode", "Set \"title\" to identify the secret to read from the local vault.")
		}
	case modeAPI:
		if !hasGroup {
			diags.AddError("\"group\" is required", "\"group\" must be set when the provider is talking to the Sharqey API.")
		}
		if hasTitle {
			diags.AddError("\"title\" not allowed in API mode", "Use \"slug\" instead of \"title\" to identify a secret when the provider is talking to the Sharqey API.")
		}
		if !hasSlug {
			diags.AddError("\"slug\" is required", "Set \"slug\" to identify the secret to read from the API.")
		}
	}
	return diags
}

// lookupSecret uzupełnia m (z configu: group+slug albo title) o metadane i
// odszyfrowaną wartość.
func lookupSecret(pd *providerData, m *secretLookupModel) diag.Diagnostics {
	if pd.mode == modeLocal {
		return lookupSecretLocal(pd, m)
	}
	var diags diag.Diagnostics

	group, err := pd.api.ResolveGroup(m.Group.ValueString())
	if err != nil {
		diags.AddError("Failed to resolve group", err.Error())
		return diags
	}
	secrets, err := pd.api.GroupSecrets(group.ID)
	if err != nil {
		diags.AddError("Failed to list group secrets", err.Error())
		return diags
	}
	var found *client.SecretEntry
	for i := range secrets {
		if secrets[i].Slug == m.Slug.ValueString() {
			found = &secrets[i]
			break
		}
	}
	if found == nil {
		diags.AddError("Secret not found", fmt.Sprintf("no secret with slug %q in group %q", m.Slug.ValueString(), group.FullPath))
		return diags
	}

	m.ID = types.StringValue(found.ID)
	m.Type = types.StringValue(found.Type)
	m.Title = types.StringValue(found.Title)
	m.Username = types.StringValue(found.Username)
	m.URL = types.StringValue(found.URL)
	m.Filename = types.StringNull()
	m.ContentBase64 = types.StringNull()

	// Plik — ta sama ścieżka co sharqey_file_secret.Read (metadane + blob
	// przez goclient/filesecret), wynik w tych samych atrybutach co w
	// trybie local vault.
	if found.Type == "file" {
		s, err := newFileSession(pd, group.FullPath)
		if err != nil {
			diags.AddError("Failed to prepare file secret", err.Error())
			return diags
		}
		data, meta, err := s.download(found.ID)
		if err != nil {
			diags.AddError("Failed to download file secret", err.Error())
			return diags
		}
		m.Value = types.StringValue("")
		m.Notes = types.StringValue("")
		m.Filename = types.StringValue(meta.Filename)
		m.ContentBase64 = types.StringValue(base64.StdEncoding.EncodeToString(data))
		return diags
	}

	privateKey, ok := pd.privateKeyForOrg(found.OrgID)
	if !ok {
		diags.AddError("No local key", fmt.Sprintf("no local key for organization %s — run `sharqey login`", found.OrgID))
		return diags
	}

	// Ciphertext + klucze dociągnięte leniwo (2026-08-29, patrz HANDOFF.md) —
	// GroupSecrets zwraca już tylko metadane.
	detail, err := pd.api.GetSecret(group.ID, found.ID)
	if err != nil {
		diags.AddError("Failed to get secret", err.Error())
		return diags
	}

	material := &storedSecret{}
	material.setDetail(detail)
	plaintext, err := material.decrypt(privateKey)
	if err != nil {
		diags.AddError("Failed to decrypt secret", err.Error())
		return diags
	}
	value, notes, err := parsePlaintext(plaintext)
	if err != nil {
		diags.AddError("Failed to parse decrypted secret", err.Error())
		return diags
	}
	m.Value = types.StringValue(value)
	m.Notes = types.StringValue(notes)
	return diags
}

// lookupSecretLocal looks the secret up by title (see findLocalByTitle for
// the uniqueness rule) and decrypts it. A "file" secret yields filename +
// content_base64 instead of value/notes.
func lookupSecretLocal(pd *providerData, m *secretLookupModel) diag.Diagnostics {
	var diags diag.Diagnostics
	title := m.Title.ValueString()

	var secret localvault.Secret
	var content, fileData []byte
	found := false

	err := withLocalVault(pd, func(v *localvault.Vault) error {
		s, ok, ferr := findLocalByTitle(v, title, "")
		if ferr != nil || !ok {
			return ferr
		}
		found = true
		if s.Type == localvault.TypeFile {
			var readErr error
			secret, fileData, readErr = v.ReadFile(s.ID)
			return readErr
		}
		var decErr error
		secret, content, decErr = v.DecryptSecret(s.ID)
		return decErr
	})
	if err != nil {
		diags.AddError("Failed to read local vault", err.Error())
		return diags
	}
	if !found {
		diags.AddError("Secret not found", fmt.Sprintf("no secret titled %q in local vault", title))
		return diags
	}

	m.ID = types.StringValue(secret.ID)
	m.Type = types.StringValue(secret.Type)
	m.Title = types.StringValue(title)
	m.Username = types.StringValue(secret.Username)
	m.URL = types.StringValue(secret.URL)
	m.Filename = types.StringNull()
	m.ContentBase64 = types.StringNull()
	if secret.Type == localvault.TypeFile {
		m.Value = types.StringValue("")
		m.Notes = types.StringValue("")
		m.Filename = types.StringValue(secret.Filename)
		m.ContentBase64 = types.StringValue(base64.StdEncoding.EncodeToString(fileData))
		return diags
	}

	value, notes, err := parsePlaintext(string(content))
	if err != nil {
		diags.AddError("Failed to parse decrypted secret", err.Error())
		return diags
	}
	m.Value = types.StringValue(value)
	m.Notes = types.StringValue(notes)
	return diags
}

// providerDataFrom — wspólne dla Configure ephemerala i data source'a.
func providerDataFrom(raw any, diags *diag.Diagnostics) *providerData {
	if raw == nil {
		return nil
	}
	pd, ok := raw.(*providerData)
	if !ok {
		diags.AddError("Unexpected provider data type", fmt.Sprintf("%T", raw))
	}
	return pd
}
