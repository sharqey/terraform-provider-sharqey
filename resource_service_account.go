package main

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/sharqey/terraform-provider-sharqey/internal/secretcrypto"
)

var saSlugNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// serviceAccountIdentityEmail — email dla UID-a klucza PGP nowego service
// accounta, w formacie "{slug-nazwy}@tokens.{domena-serwera}" zamiast pustego
// emaila (dawniej klucz nie miał w ogóle adresu, co utrudniało rozpoznanie
// czyj to keyring np. w gpg --list-keys). Domena wyprowadzona z ServerURL
// providera (ten sam host co API, niezależnie od tego czy to sharqey.com czy
// dev/self-hosted instancja) — nie ma osobnego configu domeny.
func serviceAccountIdentityEmail(name, serverURL string) string {
	slug := strings.Trim(saSlugNonAlnum.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if slug == "" {
		slug = "sa"
	}
	domain := "tokens.invalid"
	if u, err := url.Parse(serverURL); err == nil && u.Hostname() != "" {
		domain = "tokens." + u.Hostname()
	}
	return slug + "@" + domain
}

// serviceAccountResource — sharqey_service_account. Auth wyłącznie
// "token" w v1 (OIDC binding to dalszy zakres, password-manager/
// tasks/todo/062). Token wraca WYŁĄCZNIE raz, przy Create — trafia do
// Terraform state jako sensitive, tak jak private_key. Nie ma endpointu do
// zmiany name/role/parenta po stronie serwera — każda zmiana configu
// niszczy i tworzy service account na nowo (nowy keypair, nowy token,
// stary token natychmiast przestaje działać po stronie serwera bo
// group_keys tej subgrupy dla starego usera znika przy Delete).
type serviceAccountResource struct {
	pd *providerData
}

func NewServiceAccountResource() resource.Resource {
	return &serviceAccountResource{}
}

type serviceAccountResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Group       types.String `tfsdk:"group"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Role        types.String `tfsdk:"role"`
	TTLDays     types.Int64  `tfsdk:"ttl_days"`
	Token       types.String `tfsdk:"token"`
	PrivateKey  types.String `tfsdk:"private_key"`
	ExpiresAt   types.String `tfsdk:"expires_at"`
}

func (r *serviceAccountResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account"
}

func (r *serviceAccountResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A Sharqey service account (machine identity for CI), scoped to a subgroup. Token-based auth only — see SHARQEY_SA_TOKEN/SHARQEY_SA_PRIVATE_KEY in `sharqey` CLI. There is no update API: any config change replaces the resource (new keypair, new token, old one revoked).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Service account user UUID, assigned by the server.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"group": schema.StringAttribute{
				Required:    true,
				Description: "Full path of the subgroup this service account is scoped to. Must NOT be an organization root — the server rejects that.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"role": schema.StringAttribute{
				Optional:    true,
				Description: "Role within the group: \"viewer\" (default) or \"contributor\".",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ttl_days": schema.Int64Attribute{
				Optional:    true,
				Description: "Token lifetime in days (1-365, default 90 server-side). Only takes effect when the token is (re)created — changing it alone does not rotate an existing token, since it isn't a RequiresReplace attribute.",
			},
			"token": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Raw bearer token, returned once by the server at creation time. Use as SHARQEY_SA_TOKEN.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"private_key": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Armored OpenPGP private key generated locally for this service account, without passphrase. Use as SHARQEY_SA_PRIVATE_KEY. Never sent to the server.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"expires_at": schema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 expiry of the token issued at creation time.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *serviceAccountResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *serviceAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !r.pd.requireAPIMode("sharqey_service_account", &resp.Diagnostics) {
		return
	}
	var plan serviceAccountResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	group, err := r.pd.api.ResolveGroup(plan.Group.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve group", err.Error())
		return
	}

	role := plan.Role.ValueString()
	if role == "" {
		role = "viewer"
	}
	created, err := r.pd.api.CreateServiceAccount(group.ID, plan.Name.ValueString(), plan.Description.ValueString(), role, "token")
	if err != nil {
		resp.Diagnostics.AddError("Failed to create service account", err.Error())
		return
	}

	identityEmail := serviceAccountIdentityEmail(plan.Name.ValueString(), r.pd.api.BaseURL())
	publicKey, privateKey, err := secretcrypto.GenerateIdentityKeypair("Sharqey Service Account", identityEmail)
	if err != nil {
		resp.Diagnostics.AddError("Failed to generate identity keypair", err.Error())
		return
	}
	if err := r.pd.api.SetServiceAccountIdentityKey(created.UserID, publicKey); err != nil {
		resp.Diagnostics.AddError("Failed to set service account identity key", err.Error())
		return
	}

	// Udostępnij service accountowi klucze CAŁEJ gałęzi — rola kaskaduje w dół
	// (floor), więc bez kluczy podgrup SA miałby tam rolę i nic nie mógłby
	// odszyfrować. Ten sam mechanizm co "Add member" w web UI: klucze
	// wywołującego z gałęzi jednym zapytaniem, przepakowane lokalnie do klucza
	// SA, zapisane jedną transakcją. Podgrupy, których klucza wywołujący nie
	// ma, zostają pominięte (serwer ich nie zwraca) — tam musi zrobić Sync
	// ktoś, kto go ma.
	orgID, err := r.pd.api.OrgIDForPath(group.FullPath)
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve organization for group", err.Error())
		return
	}
	ownPrivateKey, ok := r.pd.privateKeyForOrg(orgID)
	if !ok {
		resp.Diagnostics.AddError("No local key", fmt.Sprintf("no local key for organization %s — run `sharqey login`", orgID))
		return
	}
	subtree, err := r.pd.api.KeyedSubtree(group.ID)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list group keys of the subtree", err.Error())
		return
	}
	keys, err := rewrapGroupKeys(subtree, ownPrivateKey, publicKey)
	if err != nil {
		resp.Diagnostics.AddError("Failed to re-encrypt group keys for service account", err.Error())
		return
	}
	if !containsGroup(keys, group.ID) {
		resp.Diagnostics.AddError("No group key", fmt.Sprintf("you have no key for %s — ask someone who has it to Sync it to you first", group.FullPath))
		return
	}
	if err := r.pd.api.ShareSubtreeGroupKeys(group.ID, created.UserID, keys); err != nil {
		resp.Diagnostics.AddError("Failed to share group keys with service account", err.Error())
		return
	}

	ttlDays := int(plan.TTLDays.ValueInt64())
	tokenResult, err := r.pd.api.CreateServiceAccountToken(created.UserID, ttlDays)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create service account token", err.Error())
		return
	}

	plan.ID = types.StringValue(created.UserID)
	plan.Role = types.StringValue(role)
	plan.Token = types.StringValue(tokenResult.Token)
	plan.PrivateKey = types.StringValue(privateKey)
	plan.ExpiresAt = types.StringValue(tokenResult.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !r.pd.requireAPIMode("sharqey_service_account", &resp.Diagnostics) {
		return
	}
	var state serviceAccountResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	group, err := r.pd.api.ResolveGroup(state.Group.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve group", err.Error())
		return
	}
	accounts, err := r.pd.api.ListServiceAccounts(group.ID)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list service accounts", err.Error())
		return
	}
	for _, a := range accounts {
		if a.UserID == state.ID.ValueString() {
			state.Name = types.StringValue(a.Name)
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}
	// Service account zniknął po drugiej stronie (usunięty ręcznie) —
	// standardowa konwencja frameworka: RemoveResource = "usuń z planu".
	// Token/private_key i tak nie da się odzyskać od serwera (nigdy go nie
	// widzi) — nie ma co tu odświeżać poza samym istnieniem/nazwą.
	resp.State.RemoveResource(ctx)
}

// Update — świadomie nieosiągalne: wszystkie atrybuty poza computed mają
// RequiresReplace (brak endpointu PATCH po stronie serwera dla service
// accountów — jedyne operacje to create/remove).
func (r *serviceAccountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "sharqey_service_account has no mutable attributes — this should be unreachable (all inputs force replacement).")
}

func (r *serviceAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.pd.requireAPIMode("sharqey_service_account", &resp.Diagnostics) {
		return
	}
	var state serviceAccountResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	group, err := r.pd.api.ResolveGroup(state.Group.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve group", err.Error())
		return
	}
	if err := r.pd.api.RemoveServiceAccount(group.ID, state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to remove service account", err.Error())
		return
	}
}
