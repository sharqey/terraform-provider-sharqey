package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/sharqey/goclient/apiclient"
	"github.com/sharqey/goclient/filesecret"
	"github.com/sharqey/goclient/localvault"
	"github.com/sharqey/goclient/pgpcrypto"
)

// sharqey_file_secret — sekret typu "file" (TASK-001, password-manager
// tasks/todo/075), w trybie API albo local vault (resource_file_secret_local.go,
// ten sam kształt co sharqey_secret: bez "group", po "title"). Osobny resource zamiast type = "file" w
// sharqey_secret: inne atrybuty (plik zamiast value/username/url) i inny
// przepływ (upload bloba przez presigned URL). Format bloba, upload i
// download to password-manager-goclient/filesecret — dokładnie ta sama
// ścieżka co `sharqey file put/get`, a nie kolejna kopia.
//
// State (TASK-002): content_base64 jest write-only, bajty pliku nigdy nie
// trafiają do stanu. W API mode private state trzyma zaszyfrowane metadane
// pliku i HMAC treści z kluczem file_key (storedSecret.ContentMAC) —
// ModifyPlan odszyfrowuje metadane i porównuje HMAC configu, bez pobierania
// bloba. Blob pobiera tylko Read, i tylko gdy zmienił się updated_at.
type fileSecretResource struct {
	pd *providerData
}

func NewFileSecretResource() resource.Resource {
	return &fileSecretResource{}
}

type fileSecretResourceModel struct {
	ID       types.String `tfsdk:"id"`
	Group    types.String `tfsdk:"group"`
	Title    types.String `tfsdk:"title"`
	Slug     types.String `tfsdk:"slug"`
	Filename types.String `tfsdk:"filename"`
	// ContentBase64 — write-only: w planie i stanie zawsze null, bajty są
	// tylko w req.Config (fileConfigContent).
	ContentBase64 types.String `tfsdk:"content_base64"`
	UpdatedAt     types.String `tfsdk:"updated_at"`
}

func (r *fileSecretResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file_secret"
}

func (r *fileSecretResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// Version 1 — TASK-002 (write-only), migracja w state_upgrade.go.
		Version:     1,
		Description: "A Sharqey secret of type \"file\" (certificate, provisioning profile, key…), encrypted end-to-end like `sharqey file put`. In API mode it lives in a group (\"group\" required, import with `<group full path>/<slug>`). In local vault mode it is stored inline in the `.sharqey` file like `sharqey local file put` — \"group\" must be omitted, the secret is identified by \"title\" (unique within the vault, import with the title). The file content is write-only and never stored in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"group": schema.StringAttribute{
				Optional:      true,
				Description:   "Full path of the group, e.g. \"acme-corp/engineering/ios\". Required in API mode, forbidden in local vault mode.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"title": schema.StringAttribute{
				Required: true,
			},
			"slug": schema.StringAttribute{
				Computed:    true,
				Description: "Slug assigned by the server (what `sharqey file get <group>/<slug>` and SHARQEY_FILE_<SLUG> use). Null in local vault mode.",
			},
			"filename": schema.StringAttribute{
				Required:    true,
				Description: "File name stored in the (encrypted) metadata — what `sharqey file get`/`files pull` write to disk.",
			},
			"content_base64": schema.StringAttribute{
				Required:    true,
				WriteOnly:   true,
				Sensitive:   true,
				Description: "File content, base64-encoded (e.g. filebase64(...) or ephemeral.sharqey_secret.x.content_base64). Write-only: never stored in Terraform state; changes are detected during plan against the stored encrypted metadata.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Server-side last modification time (API mode). Null in local vault mode. Becomes unknown in the plan whenever the secret will be rewritten, including when only the write-only content differs.",
			},
		},
	}
}

func (r *fileSecretResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// ValidateConfig — ta sama reguła "group" co sharqey_secret
// (secretResource.ValidateConfig): wymagane w API mode, zabronione w local
// mode; tryb znany dopiero po Configure, stąd też checkGroupForMode w
// Create/Update.
func (r *fileSecretResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg fileSecretResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() || r.pd == nil || cfg.Group.IsUnknown() {
		return
	}
	if err := r.checkGroupForMode(cfg.Group.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("group"), "Invalid \"group\" for provider mode", err.Error())
	}
}

func (r *fileSecretResource) checkGroupForMode(group string) error {
	if r.pd.mode == modeLocal && group != "" {
		return fmt.Errorf("\"group\" is not allowed in local vault mode — a local vault is a flat list of secrets, identified by \"title\"")
	}
	if r.pd.mode == modeAPI && group == "" {
		return fmt.Errorf("\"group\" is required in API mode")
	}
	return nil
}

// setLocalState — wynik operacji w local mode; group, slug i updated_at nie
// istnieją.
func setLocalState(m *fileSecretResourceModel, s localvault.Secret) {
	m.ID = types.StringValue(s.ID)
	m.Group = types.StringNull()
	m.Slug = types.StringNull()
	m.Title = types.StringValue(s.Title)
	m.Filename = types.StringValue(s.Filename)
	m.UpdatedAt = types.StringNull()
}

// fileSession — wszystko, czego potrzebuje jedna operacja na pliku w grupie.
type fileSession struct {
	api        *apiclient.Client
	orgID      string
	groupID    string
	groupPath  string
	privateKey string
}

func (r *fileSecretResource) session(groupPath string) (*fileSession, error) {
	return newFileSession(r.pd, groupPath)
}

// newFileSession — współdzielone z ephemeral sharqey_secret (odczyt
// sekretu typu file w trybie API).
func newFileSession(pd *providerData, groupPath string) (*fileSession, error) {
	group, err := pd.api.ResolveGroup(groupPath)
	if err != nil {
		return nil, fmt.Errorf("resolve group: %w", err)
	}
	orgID, err := pd.api.OrgIDForPath(group.FullPath)
	if err != nil {
		return nil, err
	}
	privateKey, ok := pd.privateKeyForOrg(orgID)
	if !ok {
		return nil, fmt.Errorf("no local key for organization %s — run `sharqey login`", orgID)
	}
	api := apiclient.New(pd.api.BaseURL())
	api.SetToken(pd.api.Token())
	return &fileSession{api: api, orgID: orgID, groupID: group.ID, groupPath: group.FullPath, privateKey: privateKey}, nil
}

// encryptMetadata — jak runFilePut w password-manager-cli: grupa z
// group_key (EncryptWithGroupKey) albo grupa Private bez group_key (404 na
// my-group-key -> EncryptOwnerSecret do własnego klucza publicznego). Wynik
// od razu w kształcie private state.
func (s *fileSession) encryptMetadata(meta filesecret.Metadata) (*storedSecret, error) {
	stored := &storedSecret{OrgID: s.orgID, GroupID: s.groupID}
	encryptedGroupKey, err := s.api.GetMyGroupKey(s.groupID)
	switch {
	case apiclient.IsNotFound(err):
		pub, perr := pgpcrypto.PublicKeyFromPrivateKeyArmored(s.privateKey)
		if perr != nil {
			return nil, perr
		}
		stored.Ciphertext, stored.OwnerEncryptedSecretKey, err = pgpcrypto.EncryptOwnerSecret(meta.JSON(), pub)
	case err != nil:
		return nil, fmt.Errorf("group key: %w", err)
	default:
		stored.GroupKey = encryptedGroupKey
		stored.Ciphertext, stored.GroupEncryptedSecretKey, err = pgpcrypto.EncryptWithGroupKey(meta.JSON(), encryptedGroupKey, s.privateKey)
	}
	return stored, err
}

// upload — nowy blob + zaszyfrowane metadane; wynik do CreateSecret/UpdateSecret.
func (s *fileSession) upload(filename string, data []byte) (blobID string, stored *storedSecret, err error) {
	blobID, meta, err := filesecret.Upload(s.api, s.groupID, filename, data)
	if err != nil {
		return "", nil, fmt.Errorf("upload: %w", err)
	}
	stored, err = s.encryptMetadata(meta)
	if err != nil {
		return "", nil, fmt.Errorf("encrypt metadata: %w", err)
	}
	if stored.ContentMAC, err = fileContentMAC(meta.FileKey, data); err != nil {
		return "", nil, err
	}
	return blobID, stored, nil
}

// find — sekret po ID w grupie (nil gdy nie istnieje).
func (s *fileSession) find(id string) (*apiclient.SearchResult, error) {
	secrets, err := s.api.GroupSecrets(s.groupID)
	if err != nil {
		return nil, fmt.Errorf("group secrets: %w", err)
	}
	for i := range secrets {
		if secrets[i].ID == id {
			return &secrets[i], nil
		}
	}
	return nil, nil
}

// fetch — aktualny materiał z serwera (do private state), odszyfrowane
// metadane i bajty pliku.
func (s *fileSession) fetch(id string) (*storedSecret, []byte, filesecret.Metadata, error) {
	detail, err := s.api.GetSecret(s.groupID, id)
	if err != nil {
		return nil, nil, filesecret.Metadata{}, err
	}
	stored := &storedSecret{
		OrgID:                   s.orgID,
		GroupID:                 s.groupID,
		Ciphertext:              detail.Ciphertext,
		GroupEncryptedSecretKey: detail.GroupEncryptedSecretKey,
		OwnerEncryptedSecretKey: detail.OwnerEncryptedSecretKey,
		DirectKey:               detail.DirectKey,
		GroupKey:                detail.GroupKey,
	}
	plaintext, err := stored.decrypt(s.privateKey)
	if err != nil {
		return nil, nil, filesecret.Metadata{}, fmt.Errorf("decrypt metadata: %w", err)
	}
	data, meta, err := filesecret.Download(s.api, s.groupID, id, plaintext)
	if err != nil {
		return nil, nil, meta, err
	}
	if stored.ContentMAC, err = fileContentMAC(meta.FileKey, data); err != nil {
		return nil, nil, meta, err
	}
	return stored, data, meta, nil
}

// download — odszyfrowane metadane i bajty pliku (ephemeral sharqey_secret).
func (s *fileSession) download(id string) ([]byte, filesecret.Metadata, error) {
	_, data, meta, err := s.fetch(id)
	return data, meta, err
}

// refreshMeta — slug i updated_at nadaje serwer, więc po zapisie czytamy je
// z listy.
func (s *fileSession) refreshMeta(m *fileSecretResourceModel) error {
	found, err := s.find(m.ID.ValueString())
	if err != nil {
		return err
	}
	if found == nil {
		return fmt.Errorf("secret %s not found right after writing it", m.ID.ValueString())
	}
	m.Slug = types.StringValue(found.Slug)
	m.UpdatedAt = updatedAtValue(found.UpdatedAt)
	return nil
}

// fileConfigContent — write-only content_base64 z configu. unknown=true,
// gdy wartość będzie znana dopiero przy apply.
func fileConfigContent(ctx context.Context, cfg tfsdk.Config) (data []byte, unknown bool, diags diag.Diagnostics) {
	var b64 types.String
	diags.Append(cfg.GetAttribute(ctx, path.Root("content_base64"), &b64)...)
	if diags.HasError() {
		return nil, false, diags
	}
	if b64.IsUnknown() {
		return nil, true, diags
	}
	data, err := base64.StdEncoding.DecodeString(b64.ValueString())
	if err != nil {
		diags.AddAttributeError(path.Root("content_base64"), "Invalid content_base64", fmt.Sprintf("content_base64 is not valid base64: %v", err))
	}
	return data, false, diags
}

// contentMatches — czy treść pliku w Sharqey jest identyczna z data.
// Local mode: porównanie z plikiem w vaulcie. API mode: HMAC z private
// state (klucz file_key z odszyfrowanych metadanych) — bez pobierania
// bloba. stored (API mode) wraca, bo decryptStored mógł go odświeżyć.
func (r *fileSecretResource) contentMatches(ctx context.Context, id string, data []byte, private privateReader) (bool, *storedSecret, diag.Diagnostics) {
	var diags diag.Diagnostics
	if r.pd.mode == modeLocal {
		_, current, found, err := localFileRead(r.pd, id)
		if err != nil {
			diags.AddError("Failed to read file secret from local vault", err.Error())
			return false, nil, diags
		}
		return found && bytes.Equal(current, data), nil, diags
	}
	stored, d := loadStored(ctx, private)
	diags.Append(d...)
	if stored == nil || stored.ContentMAC == "" {
		return false, stored, diags
	}
	plaintext, err := decryptStored(r.pd, stored, id)
	if err != nil {
		diags.AddError("Failed to decrypt file metadata", err.Error())
		return false, stored, diags
	}
	meta, err := filesecret.ParseMetadata(plaintext)
	if err != nil {
		diags.AddError("Failed to parse file metadata", err.Error())
		return false, stored, diags
	}
	mac, err := fileContentMAC(meta.FileKey, data)
	if err != nil {
		diags.AddError("Failed to hash file content", err.Error())
		return false, stored, diags
	}
	return mac == stored.ContentMAC, stored, diags
}

func (r *fileSecretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan fileSecretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	data, _, diags := fileConfigContent(ctx, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.checkGroupForMode(plan.Group.ValueString()); err != nil {
		resp.Diagnostics.AddError("Invalid \"group\" for provider mode", err.Error())
		return
	}
	if r.pd.mode == modeLocal {
		sec, err := localFileCreate(r.pd, plan.Title.ValueString(), plan.Filename.ValueString(), data)
		if err != nil {
			resp.Diagnostics.AddError("Failed to create file secret in local vault", err.Error())
			return
		}
		setLocalState(&plan, sec)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}
	s, err := r.session(plan.Group.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to prepare file secret", err.Error())
		return
	}
	blobID, stored, err := s.upload(plan.Filename.ValueString(), data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to upload file", err.Error())
		return
	}
	id, err := s.api.CreateSecret(s.groupID, apiclient.CreateSecretParams{
		Type: "file", Title: plan.Title.ValueString(), Ciphertext: stored.Ciphertext,
		GroupEncryptedSecretKey: stored.GroupEncryptedSecretKey, OwnerEncryptedSecretKey: stored.OwnerEncryptedSecretKey, BlobID: blobID,
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to create file secret", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	plan.Group = types.StringValue(s.groupPath)
	if err := s.refreshMeta(&plan); err != nil {
		resp.Diagnostics.AddError("Failed to read back file secret", err.Error())
		return
	}
	resp.Diagnostics.Append(saveStored(ctx, resp.Private, stored)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read — tylko metadane. W API mode blob jest pobierany (i HMAC liczony na
// nowo) wyłącznie wtedy, gdy updated_at z serwera różni się od tego w
// stanie; wtedy odświeża się też filename z odszyfrowanych metadanych.
func (r *fileSecretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state fileSecretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.pd.mode == modeLocal {
		sec, found, err := localFileMeta(r.pd, state.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Failed to read file secret from local vault", err.Error())
			return
		}
		if !found {
			resp.State.RemoveResource(ctx)
			return
		}
		setLocalState(&state, sec)
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	s, err := r.session(state.Group.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to prepare file secret", err.Error())
		return
	}
	found, err := s.find(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to list group secrets", err.Error())
		return
	}
	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	if found.Type != "file" {
		resp.Diagnostics.AddError("Not a file secret", fmt.Sprintf("secret %s in %s is a %q secret", found.ID, s.groupPath, found.Type))
		return
	}
	stored, diags := loadStored(ctx, req.Private)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	updatedAt := updatedAtValue(found.UpdatedAt)
	if stored == nil || stored.ContentMAC == "" || stored.GroupID != s.groupID || !updatedAt.Equal(state.UpdatedAt) {
		stored, _, meta, err := s.fetch(found.ID)
		if err != nil {
			resp.Diagnostics.AddError("Failed to download file secret", err.Error())
			return
		}
		state.Filename = types.StringValue(meta.Filename)
		resp.Diagnostics.Append(saveStored(ctx, resp.Private, stored)...)
	}
	state.Group = types.StringValue(s.groupPath)
	state.Title = types.StringValue(found.Title)
	state.Slug = types.StringValue(found.Slug)
	state.UpdatedAt = updatedAt
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ModifyPlan — zmiana write-only content_base64 nie jest widoczna w diffie
// atrybutów, więc porównujemy treść z tym, co jest w Sharqey
// (contentMatches) i przy różnicy oznaczamy updated_at jako unknown.
func (r *fileSecretResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() || r.pd == nil {
		return
	}
	var state fileSecretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	data, unknown, diags := fileConfigContent(ctx, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	changed := unknown
	if !changed {
		matches, stored, diags := r.contentMatches(ctx, state.ID.ValueString(), data, req.Private)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		if stored != nil {
			resp.Diagnostics.Append(saveStored(ctx, resp.Private, stored)...)
		}
		changed = !matches
	}
	if changed {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("updated_at"), types.StringUnknown())...)
	}
}

func (r *fileSecretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state fileSecretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	data, _, diags := fileConfigContent(ctx, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.checkGroupForMode(plan.Group.ValueString()); err != nil {
		resp.Diagnostics.AddError("Invalid \"group\" for provider mode", err.Error())
		return
	}
	// Plik (albo jego nazwa w metadanych) się zmienił -> nowy blob i
	// metadane z nowym file_key. Sama zmiana tytułu nie rusza bloba.
	matches, stored, diags := r.contentMatches(ctx, state.ID.ValueString(), data, req.Private)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	contentChanged := !matches || !plan.Filename.Equal(state.Filename)
	if r.pd.mode == modeLocal {
		sec, err := localFileUpdate(r.pd, state.ID.ValueString(), plan.Title.ValueString(), plan.Filename.ValueString(), data, contentChanged)
		if err != nil {
			resp.Diagnostics.AddError("Failed to update file secret in local vault", err.Error())
			return
		}
		setLocalState(&plan, sec)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}
	s, err := r.session(plan.Group.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to prepare file secret", err.Error())
		return
	}
	p := apiclient.UpdateSecretParams{Title: plan.Title.ValueString()}
	if contentChanged {
		var blobID string
		blobID, stored, err = s.upload(plan.Filename.ValueString(), data)
		if err != nil {
			resp.Diagnostics.AddError("Failed to upload file", err.Error())
			return
		}
		p.Ciphertext, p.BlobID = &stored.Ciphertext, &blobID
		if stored.OwnerEncryptedSecretKey != "" {
			p.OwnerEncryptedSecretKey = &stored.OwnerEncryptedSecretKey
		} else {
			p.GroupEncryptedSecretKey = &stored.GroupEncryptedSecretKey
		}
	}
	if err := s.api.UpdateSecret(s.groupID, state.ID.ValueString(), p); err != nil {
		resp.Diagnostics.AddError("Failed to update file secret", err.Error())
		return
	}
	plan.ID = state.ID
	plan.Group = types.StringValue(s.groupPath)
	if err := s.refreshMeta(&plan); err != nil {
		resp.Diagnostics.AddError("Failed to read back file secret", err.Error())
		return
	}
	resp.Diagnostics.Append(saveStored(ctx, resp.Private, stored)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *fileSecretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state fileSecretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.pd.mode == modeLocal {
		if err := localFileDelete(r.pd, state.ID.ValueString()); err != nil {
			resp.Diagnostics.AddError("Failed to delete file secret from local vault", err.Error())
		}
		return
	}
	group, err := r.pd.api.ResolveGroup(state.Group.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve group", err.Error())
		return
	}
	if err := r.pd.api.DeleteGroupSecret(group.ID, state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to delete file secret", err.Error())
	}
}

// ImportState — ID importu to "<pełna ścieżka grupy>/<slug>", np.
// "acme/engineering/sharqey/password-manager-flutter/runner-p12" (ten sam
// zapis co `sharqey file get`); w local mode sam tytuł. Read dociąga resztę,
// łącznie z plikiem.
func (r *fileSecretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if r.pd.mode == modeLocal {
		id, err := localFileIDByTitle(r.pd, req.ID)
		if err != nil {
			resp.Diagnostics.AddError("Failed to import file secret from local vault", err.Error())
			return
		}
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
		return
	}
	full := strings.Trim(req.ID, "/")
	idx := strings.LastIndex(full, "/")
	if idx < 0 {
		resp.Diagnostics.AddError("Invalid import ID", "expected <group full path>/<slug>, e.g. acme/ci/ios-signing/runner-p12")
		return
	}
	groupPath, slug := full[:idx], full[idx+1:]
	s, err := r.session(groupPath)
	if err != nil {
		resp.Diagnostics.AddError("Failed to prepare file secret", err.Error())
		return
	}
	secrets, err := s.api.GroupSecrets(s.groupID)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list group secrets", err.Error())
		return
	}
	for _, sec := range secrets {
		if sec.Slug != slug {
			continue
		}
		if sec.Type != "file" {
			resp.Diagnostics.AddError("Not a file secret", fmt.Sprintf("%s is a %q secret — import it as sharqey_secret", full, sec.Type))
			return
		}
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), sec.ID)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("group"), s.groupPath)...)
		return
	}
	resp.Diagnostics.AddError("Secret not found", fmt.Sprintf("no secret with slug %q in %s", slug, s.groupPath))
}

var (
	_ resource.Resource                   = &fileSecretResource{}
	_ resource.ResourceWithImportState    = &fileSecretResource{}
	_ resource.ResourceWithModifyPlan     = &fileSecretResource{}
	_ resource.ResourceWithValidateConfig = &fileSecretResource{}
)
