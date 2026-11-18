package main

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Migracja stanu sprzed TASK-002 (schema version 0): value/notes/
// content_base64 leżały w stanie jawnym tekstem, a sharqey_file_secret miał
// content_sha256/size. Przy niezmienionej wersji schematu framework robi
// passthrough starego stanu i Terraform odrzuca go ("returned an actual
// value for the write-only attribute"), dlatego wersja 1 + upgrader, który
// przepisuje wyłącznie metadane. updated_at zostaje null, więc pierwszy
// Read dociągnie ciphertext do private state.

// rawStateAttrs — atrybuty z surowego JSON-a stanu v0 (bez schematu v0:
// potrzebne są tylko pola, które przetrwały w v1).
func rawStateAttrs(req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) (map[string]json.RawMessage, bool) {
	var attrs map[string]json.RawMessage
	if req.RawState == nil || json.Unmarshal(req.RawState.JSON, &attrs) != nil {
		resp.Diagnostics.AddError("Unable to upgrade state", "The prior (version 0) state could not be parsed as JSON.")
		return nil, false
	}
	return attrs, true
}

func rawString(attrs map[string]json.RawMessage, key string) types.String {
	var s *string
	if raw, ok := attrs[key]; !ok || json.Unmarshal(raw, &s) != nil || s == nil {
		return types.StringNull()
	}
	return types.StringValue(*s)
}

func (r *secretResource) UpgradeState(ctx context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{
		0: {StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
			attrs, ok := rawStateAttrs(req, resp)
			if !ok {
				return
			}
			resp.Diagnostics.Append(resp.State.Set(ctx, secretResourceModel{
				ID:        rawString(attrs, "id"),
				Group:     rawString(attrs, "group"),
				Type:      rawString(attrs, "type"),
				Title:     rawString(attrs, "title"),
				Username:  rawString(attrs, "username"),
				URL:       rawString(attrs, "url"),
				Value:     types.StringNull(),
				Notes:     types.StringNull(),
				UpdatedAt: types.StringNull(),
			})...)
		}},
	}
}

func (r *fileSecretResource) UpgradeState(ctx context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{
		0: {StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
			attrs, ok := rawStateAttrs(req, resp)
			if !ok {
				return
			}
			resp.Diagnostics.Append(resp.State.Set(ctx, fileSecretResourceModel{
				ID:            rawString(attrs, "id"),
				Group:         rawString(attrs, "group"),
				Title:         rawString(attrs, "title"),
				Slug:          rawString(attrs, "slug"),
				Filename:      rawString(attrs, "filename"),
				ContentBase64: types.StringNull(),
				UpdatedAt:     types.StringNull(),
			})...)
		}},
	}
}

var (
	_ resource.ResourceWithUpgradeState = &secretResource{}
	_ resource.ResourceWithUpgradeState = &fileSecretResource{}
)
