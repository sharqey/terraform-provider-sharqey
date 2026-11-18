package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/sharqey/terraform-provider-sharqey/internal/client"
)

// ssoResource — sharqey_sso: SSO connection dla ORG-u. Organizacja wskazana
// ścieżką roota (`organization = "acme"`), jak parent/group w reszcie
// providera — organizacji nie tworzy się Terraformem (DECISIONS.md), więc
// nie ma zasobu, z którego dałoby się wziąć jej UUID. UUID rozwiązywany
// przez OrgIDForPath i trzymany jako id. Backend ma dokładnie
// JEDEN connection per organizacja (PUT /g/{orgID}/sso/config to upsert —
// zawsze zastępuje istniejący, nigdy nie tworzy drugiego), więc Create i
// Update tego resource'u mają identyczne ciało.
//
// oidc_client_secret/saml_idp_certificate są write-only z perspektywy
// serwera: GetConfig nigdy ich nie zwraca (tylko has_saml_certificate bool),
// więc Read świadomie ich NIE dotyka — Terraform zachowuje wartość z
// poprzedniego state, ten sam wzorzec co token/private_key w
// resource_service_account.go (zwykłe Sensitive, nie ephemeral/write-only
// atrybuty frameworka).
type ssoResource struct {
	pd *providerData
}

func NewSSOResource() resource.Resource {
	return &ssoResource{}
}

type ssoResourceModel struct {
	ID                 types.String `tfsdk:"id"`
	Organization       types.String `tfsdk:"organization"`
	Protocol           types.String `tfsdk:"protocol"`
	Enabled            types.Bool   `tfsdk:"enabled"`
	SSOOnly            types.Bool   `tfsdk:"sso_only"`
	OIDCIssuerURL      types.String `tfsdk:"oidc_issuer_url"`
	OIDCClientID       types.String `tfsdk:"oidc_client_id"`
	OIDCClientSecret   types.String `tfsdk:"oidc_client_secret"`
	SAMLIdPEntityID    types.String `tfsdk:"saml_idp_entity_id"`
	SAMLIdPSSOURL      types.String `tfsdk:"saml_idp_sso_url"`
	SAMLIdPCertificate types.String `tfsdk:"saml_idp_certificate"`
	SPEntityID         types.String `tfsdk:"sp_entity_id"`
	SPACSURL           types.String `tfsdk:"sp_acs_url"`
	OIDCRedirectURI    types.String `tfsdk:"oidc_redirect_uri"`
}

func (r *ssoResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sso"
}

func (r *ssoResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An SSO connection (SAML or generic OIDC) for a Sharqey organization. One connection per organization — applying this resource replaces any existing connection for that organization. Requires org-admin+ role.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "UUID of the organization — one connection per organization.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"organization": schema.StringAttribute{
				Required:    true,
				Description: "Root path (slug) of the organization this connection belongs to, e.g. \"acme\". Organizations are created outside Terraform (web UI).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"protocol": schema.StringAttribute{
				Required:    true,
				Description: "\"oidc\" or \"saml\". The server validates protocol-specific required fields on apply.",
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether this connection is active for login. Defaults to the value last applied; set explicitly to avoid surprises.",
			},
			"sso_only": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Requires SSO for NEW joins to this organization (invites still allow per-invite opt-out). Does not affect existing members' ability to log in with a password.",
			},
			"oidc_issuer_url": schema.StringAttribute{
				Optional:    true,
				Description: "Required for protocol=\"oidc\".",
			},
			"oidc_client_id": schema.StringAttribute{
				Optional:    true,
				Description: "Required for protocol=\"oidc\".",
			},
			"oidc_client_secret": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Required for protocol=\"oidc\". The server never returns this back — Terraform can't detect out-of-band drift on it, only config changes trigger a re-apply.",
			},
			"saml_idp_entity_id": schema.StringAttribute{
				Optional:    true,
				Description: "Required for protocol=\"saml\".",
			},
			"saml_idp_sso_url": schema.StringAttribute{
				Optional:    true,
				Description: "Required for protocol=\"saml\".",
			},
			"saml_idp_certificate": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Required for protocol=\"saml\". PEM X.509 certificate. The server never returns this back — same drift caveat as oidc_client_secret.",
			},
			"sp_entity_id": schema.StringAttribute{
				Computed:    true,
				Description: "This Sharqey instance's SAML SP entity ID for this organization — paste into the IdP.",
			},
			"sp_acs_url": schema.StringAttribute{
				Computed:    true,
				Description: "This Sharqey instance's SAML ACS URL for this organization — paste into the IdP.",
			},
			"oidc_redirect_uri": schema.StringAttribute{
				Computed:    true,
				Description: "This Sharqey instance's OIDC redirect URI — paste into the IdP's OAuth client config.",
			},
		},
	}
}

func (r *ssoResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// save — ciało wspólne Create/Update (upsert po stronie serwera, patrz
// komentarz przy ssoResource).
func (r *ssoResource) save(plan *ssoResourceModel) error {
	orgPath := plan.Organization.ValueString()
	if strings.Contains(strings.Trim(orgPath, "/"), "/") {
		return fmt.Errorf("organization must be an organization root path like \"acme\", got %q", orgPath)
	}
	orgID, err := r.pd.api.OrgIDForPath(orgPath)
	if err != nil {
		return err
	}
	err = r.pd.api.SaveSSOConfig(orgID, client.SaveSSOConfigParams{
		Protocol:           plan.Protocol.ValueString(),
		Enabled:            plan.Enabled.ValueBool(),
		SSOOnly:            plan.SSOOnly.ValueBool(),
		OIDCIssuerURL:      plan.OIDCIssuerURL.ValueString(),
		OIDCClientID:       plan.OIDCClientID.ValueString(),
		OIDCClientSecret:   plan.OIDCClientSecret.ValueString(),
		SAMLIdPEntityID:    plan.SAMLIdPEntityID.ValueString(),
		SAMLIdPSSOURL:      plan.SAMLIdPSSOURL.ValueString(),
		SAMLIdPCertificate: plan.SAMLIdPCertificate.ValueString(),
	})
	if err != nil {
		return err
	}

	cfg, err := r.pd.api.GetSSOConfig(orgID)
	if err != nil {
		return err
	}
	plan.ID = types.StringValue(orgID)
	plan.Enabled = types.BoolValue(cfg.Enabled)
	plan.SSOOnly = types.BoolValue(cfg.SSOOnly)
	plan.SPEntityID = types.StringValue(cfg.SPEntityID)
	plan.SPACSURL = types.StringValue(cfg.SPACSURL)
	plan.OIDCRedirectURI = types.StringValue(cfg.OIDCRedirectURI)
	// oidc_client_secret/saml_idp_certificate świadomie NIE dotknięte —
	// patrz komentarz przy ssoResource.
	return nil
}

func (r *ssoResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !r.pd.requireAPIMode("sharqey_sso", &resp.Diagnostics) {
		return
	}
	var plan ssoResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.save(&plan); err != nil {
		resp.Diagnostics.AddError("Failed to save SSO configuration", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ssoResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !r.pd.requireAPIMode("sharqey_sso", &resp.Diagnostics) {
		return
	}
	var state ssoResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Po `terraform import <path>` id jeszcze nie ma.
	if state.ID.IsNull() || state.ID.ValueString() == "" {
		orgID, err := r.pd.api.OrgIDForPath(state.Organization.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Failed to resolve organization", err.Error())
			return
		}
		state.ID = types.StringValue(orgID)
	}
	cfg, err := r.pd.api.GetSSOConfig(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read SSO configuration", err.Error())
		return
	}
	if !cfg.Configured {
		resp.State.RemoveResource(ctx)
		return
	}
	state.Protocol = types.StringValue(cfg.Protocol)
	state.Enabled = types.BoolValue(cfg.Enabled)
	state.SSOOnly = types.BoolValue(cfg.SSOOnly)
	state.OIDCIssuerURL = optionalString(cfg.OIDCIssuerURL)
	state.OIDCClientID = optionalString(cfg.OIDCClientID)
	state.SAMLIdPEntityID = optionalString(cfg.SAMLIdPEntityID)
	state.SAMLIdPSSOURL = optionalString(cfg.SAMLIdPSSOURL)
	state.SPEntityID = types.StringValue(cfg.SPEntityID)
	state.SPACSURL = types.StringValue(cfg.SPACSURL)
	state.OIDCRedirectURI = types.StringValue(cfg.OIDCRedirectURI)
	// oidc_client_secret/saml_idp_certificate świadomie NIE dotknięte —
	// serwer ich nie oddaje, Terraform zachowuje to co już było w state.
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ssoResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !r.pd.requireAPIMode("sharqey_sso", &resp.Diagnostics) {
		return
	}
	var plan ssoResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.save(&plan); err != nil {
		resp.Diagnostics.AddError("Failed to save SSO configuration", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ssoResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.pd.requireAPIMode("sharqey_sso", &resp.Diagnostics) {
		return
	}
	var state ssoResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.pd.api.DeleteSSOConfig(state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to delete SSO configuration", err.Error())
		return
	}
}

func (r *ssoResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("organization"), req, resp)
}

var _ resource.ResourceWithImportState = &ssoResource{}
