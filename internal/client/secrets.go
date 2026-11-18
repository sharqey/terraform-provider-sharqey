package client

import (
	"net/url"
	"time"
)

// Workspace/GroupNode/SecretEntry — klient dla REALNEGO API grup/subgrup
// (internal/group, internal/secret), w odróżnieniu od Org/Secret w models.go
// które celują w martwe /api/v1/orgs/* (nigdy nie zarejestrowane w
// cmd/server/main.go — patrz tasks/todo/026).

type Workspace struct {
	ID       string `json:"id"`
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	FullPath string `json:"full_path"`
}

type workspacesResponse struct {
	Workspaces   []Workspace `json:"workspaces"`
	CanCreateOrg bool        `json:"can_create_org"`
}

// ListWorkspaces — GET /api/v1/me/workspaces, root grupy (organizacje) do
// których user ma dostęp.
func (c *Client) ListWorkspaces() ([]Workspace, error) {
	resp, err := c.do("GET", "/api/v1/me/workspaces", nil)
	if err != nil {
		return nil, err
	}
	result, err := decode[workspacesResponse](resp)
	if err != nil {
		return nil, err
	}
	return result.Workspaces, nil
}

type GroupNode struct {
	ID       string  `json:"id"`
	ParentID *string `json:"parent_id"`
	Slug     string  `json:"slug"`
	Name     string  `json:"name"`
	FullPath string  `json:"full_path"`
	Depth    int     `json:"depth"`
	// IsPrivate — własna prywatna grupa użytkownika albo jej podgrupa. W tym
	// drzewie nie ma group_key: sekrety szyfruje się wprost kluczem
	// publicznym właściciela (owner_encrypted_secret_key).
	IsPrivate bool `json:"is_private"`
}

// GroupTree — GET /api/v1/groups/tree?root_path=..., płaska lista całego
// poddrzewa danego workspace'u (rootPath = Workspace.FullPath).
func (c *Client) GroupTree(rootPath string) ([]GroupNode, error) {
	resp, err := c.do("GET", "/api/v1/groups/tree?root_path="+url.QueryEscape(rootPath), nil)
	if err != nil {
		return nil, err
	}
	return decode[[]GroupNode](resp)
}

// SecretEntry — odpowiednik internal/secret.SearchResult, jak zwraca
// GET /g/{groupID}/secrets. WYŁĄCZNIE metadane (2026-08-29, patrz
// HANDOFF.md) — ciphertext/group_encrypted_secret_key/group_key/direct_key
// (surowy materiał kryptograficzny) już tu nie lecą, dociągnąć trzeba
// osobno przez GetSecret, dopiero gdy faktycznie chcesz odszyfrować JEDEN
// konkretny sekret (patrz cmd/cli/ls_get.go runGet).
type SecretEntry struct {
	ID            string    `json:"id"`
	GroupID       string    `json:"group_id"`
	Type          string    `json:"type"`
	Slug          string    `json:"slug"`
	Title         string    `json:"title"`
	Username      string    `json:"username"`
	URL           string    `json:"url"`
	HasTOTP       bool      `json:"has_totp"`
	UpdatedAt     time.Time `json:"updated_at"`
	GroupFullPath string    `json:"group_full_path"`
	GroupName     string    `json:"group_name"`
	OrgName       string    `json:"org_name,omitempty"`
	OrgID         string    `json:"org_id,omitempty"`
}

// GroupSecrets — GET /g/{groupID}/secrets — wszystkie sekrety DOKŁADNIE tej
// grupy (nie poddrzewa).
func (c *Client) GroupSecrets(groupID string) ([]SecretEntry, error) {
	resp, err := c.do("GET", "/g/"+groupID+"/secrets", nil)
	if err != nil {
		return nil, err
	}
	return decode[[]SecretEntry](resp)
}

// SecretDetail — GET /g/{groupID}/secrets/{secretID}, jedyne miejsce gdzie
// backend oddaje ciphertext + klucze szyfrujące JEDNEGO sekretu (2026-08-29,
// patrz HANDOFF.md) — surowy materiał kryptograficzny do lokalnego
// odszyfrowania (patrz cmd/cli/crypto.go decryptGroupSecret), serwer nigdy
// nie widzi plaintextu.
type SecretDetail struct {
	Ciphertext              string `json:"ciphertext"`
	GroupEncryptedSecretKey string `json:"group_encrypted_secret_key"`
	// OwnerEncryptedSecretKey — tylko grupa Private (bez group_key), patrz
	// goclient apiclient.SecretDetail.
	OwnerEncryptedSecretKey string `json:"owner_encrypted_secret_key,omitempty"`
	DirectKey               string `json:"direct_key,omitempty"`
	DirectRole              string `json:"direct_role,omitempty"`
	GroupKey                string `json:"group_key"`
}

// GetSecret — GET /g/{groupID}/secrets/{secretID} — ciphertext + klucze
// JEDNEGO sekretu, wołane leniwie zamiast razem z GroupSecrets/Search.
func (c *Client) GetSecret(groupID, secretID string) (*SecretDetail, error) {
	resp, err := c.do("GET", "/g/"+groupID+"/secrets/"+secretID, nil)
	if err != nil {
		return nil, err
	}
	result, err := decode[SecretDetail](resp)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetMyGroupKey — GET /g/{groupID}/my-group-key, własny wpis group_keys
// (armored PGP, zawiera hex klucza AES grupy) wywołującego — potrzebny do
// EncryptGroupSecret (pkg/secretcrypto) przy tworzeniu/edycji sekretu.
func (c *Client) GetMyGroupKey(groupID string) (string, error) {
	resp, err := c.do("GET", "/g/"+groupID+"/my-group-key", nil)
	if err != nil {
		return "", err
	}
	result, err := decode[map[string]string](resp)
	if err != nil {
		return "", err
	}
	return result["encrypted_key"], nil
}

type CreateGroupSecretParams struct {
	GroupID                 string
	Type                    string // "account" | "env"
	Title                   string
	Username                string
	URL                     string
	HasTOTP                 bool
	Ciphertext              string
	GroupEncryptedSecretKey string
	// OwnerEncryptedSecretKey — zamiast GroupEncryptedSecretKey w drzewie Private.
	OwnerEncryptedSecretKey string
}

// CreateGroupSecret — POST /g/{groupID}/secrets. Form-urlencoded (nie
// JSON!) — patrz internal/secret.Handler.Create, r.FormValue. Zwraca
// secret_id.
func (c *Client) CreateGroupSecret(p CreateGroupSecretParams) (string, error) {
	form := url.Values{
		"type":                       {p.Type},
		"title":                      {p.Title},
		"username":                   {p.Username},
		"url":                        {p.URL},
		"ciphertext":                 {p.Ciphertext},
		"group_encrypted_secret_key": {p.GroupEncryptedSecretKey},
	}
	if p.OwnerEncryptedSecretKey != "" {
		form.Set("owner_encrypted_secret_key", p.OwnerEncryptedSecretKey)
	}
	if p.HasTOTP {
		form.Set("has_totp", "1")
	}
	resp, err := c.doForm("POST", "/g/"+p.GroupID+"/secrets", form)
	if err != nil {
		return "", err
	}
	result, err := decode[map[string]string](resp)
	if err != nil {
		return "", err
	}
	return result["secret_id"], nil
}

type UpdateGroupSecretParams struct {
	GroupID                 string
	SecretID                string
	Title                   string
	Username                string
	URL                     string
	HasTOTP                 bool
	Ciphertext              *string
	GroupEncryptedSecretKey *string
	OwnerEncryptedSecretKey *string
}

// UpdateGroupSecret — PUT /g/{groupID}/secrets/{secretID}. JSON (nie form
// — inny endpoint, inna konwencja, patrz internal/secret.Handler.Update).
// Ciphertext/GroupEncryptedSecretKey to wskaźniki: nil = nie zmieniaj
// (tylko metadane typu title/username się zmieniły).
func (c *Client) UpdateGroupSecret(p UpdateGroupSecretParams) error {
	resp, err := c.do("PUT", "/g/"+p.GroupID+"/secrets/"+p.SecretID, map[string]any{
		"title":                      p.Title,
		"username":                   p.Username,
		"url":                        p.URL,
		"has_totp":                   p.HasTOTP,
		"ciphertext":                 p.Ciphertext,
		"group_encrypted_secret_key": p.GroupEncryptedSecretKey,
		"owner_encrypted_secret_key": p.OwnerEncryptedSecretKey,
	})
	if err != nil {
		return err
	}
	_, err = decode[map[string]string](resp)
	return err
}

// DeleteGroupSecret — DELETE /g/{groupID}/secrets/{secretID}.
func (c *Client) DeleteGroupSecret(groupID, secretID string) error {
	resp, err := c.do("DELETE", "/g/"+groupID+"/secrets/"+secretID, nil)
	if err != nil {
		return err
	}
	_, err = decode[map[string]string](resp)
	return err
}
