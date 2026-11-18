package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/sharqey/terraform-provider-sharqey/internal/secretcrypto"
)

// groupResource — sharqey_group, WYŁĄCZNIE subgrupy pod istniejącym rootem
// organizacji. Tworzenie roota (nowa organizacja = nowy org_identity_key)
// świadomie poza zakresem: dziś to interaktywny flow (generowanie klucza w
// przeglądarce) który nie ma sensownego nieinteraktywnego odpowiednika —
// patrz password-manager/tasks/todo/062. Root musi istnieć z góry (założony
// ręcznie raz), Terraform zarządza tylko subgrupami pod nim — dlatego
// "parent" jest Required, nie ma osobnego "org_root" atrybutu.
type groupResource struct {
	pd *providerData
}

func NewGroupResource() resource.Resource {
	return &groupResource{}
}

type groupResourceModel struct {
	ID       types.String `tfsdk:"id"`
	Parent   types.String `tfsdk:"parent"`
	Name     types.String `tfsdk:"name"`
	FullPath types.String `tfsdk:"full_path"`
}

func (r *groupResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (r *groupResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A Sharqey subgroup, created under an existing group/organization root. Renaming/moving is not supported by the server API — changing \"parent\" or \"name\" replaces the resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Group UUID, assigned by the server.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"parent": schema.StringAttribute{
				Required:    true,
				Description: "Full path of the parent group, e.g. \"acme-corp\" or \"acme-corp/infra\". Must already exist — this provider never creates an organization root.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Display name of the new subgroup.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"full_path": schema.StringAttribute{
				Computed:    true,
				Description: "Full path of the created subgroup, e.g. \"acme-corp/infra/ci\".",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *groupResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *groupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !r.pd.requireAPIMode("sharqey_group", &resp.Diagnostics) {
		return
	}
	var plan groupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parent, err := r.pd.api.ResolveGroup(plan.Parent.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve parent group", err.Error())
		return
	}

	created, err := r.pd.api.CreateSubGroup(parent.ID, plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to create group", err.Error())
		return
	}

	// Podgrupa własnej prywatnej grupy dziedziczy prywatność: nie ma group_key
	// (sekrety są szyfrowane wprost kluczem właściciela), więc nie ma czego
	// bootstrapować ani udostępniać.
	if parent.IsPrivate {
		plan.ID = types.StringValue(created.GroupID)
		plan.FullPath = types.StringValue(created.FullPath)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	// Świeżo utworzona subgrupa ma zero wpisów group_keys — self-wrap
	// NOWEGO klucza AES-256 do WŁASNEGO klucza publicznego, dokładnie ten
	// sam "bootstrap" wyjątek co web UI (group.Handler.StoreGroupKey w
	// password-manager: twórca bez jeszcze żadnej roli w tej grupie może
	// zapisać PIERWSZY klucz raz, dopóki HasGroupKeys==false).
	orgID, err := r.pd.api.OrgIDForPath(parent.FullPath)
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve organization for parent group", err.Error())
		return
	}
	privateKey, ok := r.pd.privateKeyForOrg(orgID)
	if !ok {
		resp.Diagnostics.AddError("No local key", fmt.Sprintf("no local key for organization %s — run `sharqey login`", orgID))
		return
	}
	publicKey, err := secretcrypto.PublicKeyFromPrivateKeyArmored(privateKey)
	if err != nil {
		resp.Diagnostics.AddError("Failed to derive public key", err.Error())
		return
	}
	groupKeyHex, encryptedGroupKey, err := secretcrypto.GenerateGroupKey(publicKey)
	if err != nil {
		resp.Diagnostics.AddError("Failed to generate group key", err.Error())
		return
	}
	if err := r.pd.api.StoreGroupKey(created.GroupID, "", encryptedGroupKey); err != nil {
		resp.Diagnostics.AddError("Failed to store group key", err.Error())
		return
	}

	plan.ID = types.StringValue(created.GroupID)
	plan.FullPath = types.StringValue(created.FullPath)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)

	// Auto-Sync jak createSubgroup w web UI: członkowie i service accounty
	// rodzica mają w nowej podgrupie rolę (floor-cascade), ale bez klucza nie
	// odszyfrują w niej niczego. Grupa już jest w stanie, więc niepowodzenie
	// to ostrzeżenie (Sync w UI zostaje jako fallback), nie błąd, który
	// zostawiłby grupę poza stanem Terraforma.
	if err := shareWithMembersNeedingKey(r.pd.api, created.GroupID, groupKeyHex); err != nil {
		resp.Diagnostics.AddWarning("Group key not shared with all inherited members",
			fmt.Sprintf("%s: %s — use Sync on the group page", created.FullPath, err))
	}
}

func (r *groupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !r.pd.requireAPIMode("sharqey_group", &resp.Diagnostics) {
		return
	}
	var state groupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parent, err := r.pd.api.ResolveGroup(state.Parent.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve parent group", err.Error())
		return
	}
	tree, err := r.pd.api.GroupTree(parent.FullPath)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list group tree", err.Error())
		return
	}
	for _, n := range tree {
		if n.ID == state.ID.ValueString() {
			state.FullPath = types.StringValue(n.FullPath)
			state.Name = types.StringValue(n.Name)
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}
	// Grupa zniknęła po drugiej stronie (skasowana ręcznie w web UI) —
	// standardowa konwencja frameworka: RemoveResource = "usuń z planu".
	resp.State.RemoveResource(ctx)
}

// Update — świadomie nieosiągalne: "parent" i "name" mają RequiresReplace,
// więc każda ich zmiana zawsze idzie przez Create/Delete, nigdy przez Update.
// Framework i tak wymaga zaimplementowanej metody Update na resource.Resource.
func (r *groupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "sharqey_group has no mutable attributes — this should be unreachable (parent/name force replacement).")
}

func (r *groupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.pd.requireAPIMode("sharqey_group", &resp.Diagnostics) {
		return
	}
	var state groupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.pd.api.DeleteGroup(state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to delete group", err.Error())
		return
	}
}
