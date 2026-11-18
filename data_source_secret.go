package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
)

// data "sharqey_secret" — ten sam odczyt co ephemeral "sharqey_secret"
// (secret_lookup.go), ale wynik ZAPISUJE SIĘ W STANIE jawnym tekstem.
// Tylko dla konsumentów, którzy nie przyjmują wartości ephemeral (atrybut
// innego providera bez wariantu write-only, np.
// gitea_repository_actions_secret.secret_value — tam sekret i tak trafia
// do stanu przez sam resource docelowy). Wszędzie indziej: ephemeral.
type secretDataSource struct {
	pd *providerData
}

func NewSecretDataSource() datasource.DataSource {
	return &secretDataSource{}
}

func (d *secretDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *secretDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attrs := map[string]schema.Attribute{}
	for name, a := range secretLookupAttrs {
		attrs[name] = schema.StringAttribute{Optional: a.optional, Computed: !a.optional, Sensitive: a.sensitive, Description: a.description}
	}
	resp.Schema = schema.Schema{
		Description: "Reads an existing Sharqey secret, decrypted locally. WARNING: the decrypted value is stored in Terraform state in plain text — prefer the ephemeral \"sharqey_secret\" and use this data source only for arguments that cannot take ephemeral values. " + secretLookupDescription,
		Attributes:  attrs,
	}
}

func (d *secretDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *secretDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var cfg secretLookupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(validateSecretLookup(d.pd, cfg)...)
}

func (d *secretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m secretLookupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if resp.Diagnostics.Append(lookupSecret(d.pd, &m)...); resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

var (
	_ datasource.DataSource                   = &secretDataSource{}
	_ datasource.DataSourceWithConfigure      = &secretDataSource{}
	_ datasource.DataSourceWithValidateConfig = &secretDataSource{}
)
