package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
)

// ephemeral "sharqey_secret" — domyślny odczyt istniejącego sekretu
// (TASK-002). Wynik żyje tylko w trakcie runu i nigdy nie trafia do stanu
// ani planu; można go przekazać do atrybutów write-only (sharqey_secret.
// value, sharqey_file_secret.content_base64), konfiguracji providerów i
// innych ephemerali. Logika odczytu: secret_lookup.go.
type secretEphemeral struct {
	pd *providerData
}

func NewSecretEphemeral() ephemeral.EphemeralResource {
	return &secretEphemeral{}
}

func (d *secretEphemeral) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *secretEphemeral) Schema(ctx context.Context, req ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	attrs := map[string]schema.Attribute{}
	for name, a := range secretLookupAttrs {
		attrs[name] = schema.StringAttribute{Optional: a.optional, Computed: !a.optional, Sensitive: a.sensitive, Description: a.description}
	}
	resp.Schema = schema.Schema{
		Description: "Reads an existing Sharqey secret, decrypted locally. Ephemeral: the result is never stored in plan or state — pass it to write-only arguments (sharqey_secret.value, sharqey_file_secret.content_base64), provider configuration or other ephemeral values. " + secretLookupDescription,
		Attributes:  attrs,
	}
}

func (d *secretEphemeral) Configure(ctx context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *secretEphemeral) ValidateConfig(ctx context.Context, req ephemeral.ValidateConfigRequest, resp *ephemeral.ValidateConfigResponse) {
	var cfg secretLookupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(validateSecretLookup(d.pd, cfg)...)
}

func (d *secretEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var m secretLookupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if resp.Diagnostics.Append(lookupSecret(d.pd, &m)...); resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.Result.Set(ctx, &m)...)
}

var (
	_ ephemeral.EphemeralResource                   = &secretEphemeral{}
	_ ephemeral.EphemeralResourceWithConfigure      = &secretEphemeral{}
	_ ephemeral.EphemeralResourceWithValidateConfig = &secretEphemeral{}
)
