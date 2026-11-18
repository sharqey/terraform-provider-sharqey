package client

import "time"

// CreateSubGroupResult — odpowiedź POST /g/{parentGroupID}/groups.
type CreateSubGroupResult struct {
	GroupID  string `json:"group_id"`
	FullPath string `json:"full_path"`
}

// CreateSubGroup — POST /g/{parentGroupID}/groups. Wyłącznie subgrupy — nie
// da się tak utworzyć nowego roota organizacji (internal/group.Handler.CreateSub
// w password-manager wymaga istniejącego parenta; tworzenie organizacji to
// osobny, interaktywny flow — generowanie org_identity_key w przeglądarce —
// świadomie poza zakresem tego providera, patrz password-manager/tasks/todo/062).
// Caller musi mieć rolę "manager"+ na parencie. Świeżo utworzona subgrupa NIE
// ma jeszcze żadnego group_keys wpisu — wywołujący musi zaraz potem wywołać
// StoreGroupKey (self-wrap), patrz resource_group.go.
func (c *Client) CreateSubGroup(parentGroupID, name string) (CreateSubGroupResult, error) {
	resp, err := c.do("POST", "/g/"+parentGroupID+"/groups", map[string]string{"name": name})
	if err != nil {
		return CreateSubGroupResult{}, err
	}
	return decode[CreateSubGroupResult](resp)
}

// DeleteGroup — DELETE /g/{groupID}. Wyłącznie subgrupy (serwer odrzuca dla
// organizacji-roota, ParentID == nil) — kasuje kaskadowo sekrety/group_keys/
// membershipy tej subgrupy po stronie DB.
func (c *Client) DeleteGroup(groupID string) error {
	resp, err := c.do("DELETE", "/g/"+groupID, nil)
	if err != nil {
		return err
	}
	_, err = decode[map[string]string](resp)
	return err
}

// StoreGroupKey — POST /g/{groupID}/group-key. targetUserID pusty = zapisz
// dla SIEBIE (self-wrap przy tworzeniu grupy); niepusty = udostępnij innemu
// userowi/service accountowi (encryptedKey musi być zaszyfrowany DO JEGO
// klucza publicznego, nie własnego).
func (c *Client) StoreGroupKey(groupID, targetUserID, encryptedKey string) error {
	body := map[string]string{"encrypted_key": encryptedKey}
	if targetUserID != "" {
		body["target_user_id"] = targetUserID
	}
	resp, err := c.do("POST", "/g/"+groupID+"/group-key", body)
	if err != nil {
		return err
	}
	_, err = decode[map[string]string](resp)
	return err
}

// CreateServiceAccountResult — odpowiedź POST /g/{groupID}/service-accounts.
type CreateServiceAccountResult struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`
	Name   string `json:"name"`
}

// CreateServiceAccount — POST /g/{groupID}/service-accounts. WYŁĄCZNIE
// subgrupy (nigdy org root, patrz internal/serviceaccount.Handler.Create w
// password-manager). authType dziś tylko "token" jest wspierane przez ten
// provider (OIDC binding to dalszy zakres, tasks/todo/062).
func (c *Client) CreateServiceAccount(groupID, name, description, role, authType string) (CreateServiceAccountResult, error) {
	resp, err := c.do("POST", "/g/"+groupID+"/service-accounts", map[string]string{
		"name": name, "description": description, "role": role, "auth_type": authType,
	})
	if err != nil {
		return CreateServiceAccountResult{}, err
	}
	return decode[CreateServiceAccountResult](resp)
}

// SetServiceAccountIdentityKey — POST /service-accounts/{userID}/identity-key.
// Musi być wołane RAZ, zaraz po CreateServiceAccount — serwer odrzuca drugie
// wywołanie (409, patrz handler).
func (c *Client) SetServiceAccountIdentityKey(userID, publicKeyArmored string) error {
	resp, err := c.do("POST", "/service-accounts/"+userID+"/identity-key", map[string]string{"public_key": publicKeyArmored})
	if err != nil {
		return err
	}
	_, err = decode[map[string]string](resp)
	return err
}

// CreateServiceAccountTokenResult — odpowiedź POST /service-accounts/{userID}/token.
type CreateServiceAccountTokenResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateServiceAccountToken — POST /service-accounts/{userID}/token. Token
// surowy zwracany DOKŁADNIE RAZ (serwer trzyma tylko hash) — provider go
// widzi tylko w tym jednym wywołaniu Create, musi go od razu zapisać w state.
func (c *Client) CreateServiceAccountToken(userID string, ttlDays int) (CreateServiceAccountTokenResult, error) {
	resp, err := c.do("POST", "/service-accounts/"+userID+"/token", map[string]int{"ttl_days": ttlDays})
	if err != nil {
		return CreateServiceAccountTokenResult{}, err
	}
	return decode[CreateServiceAccountTokenResult](resp)
}

// ServiceAccountEntry — jeden wpis z GET /g/{groupID}/service-accounts.
// UWAGA: internal/serviceaccount.ServiceAccount (password-manager) nie ma
// json struct tagów — writeJSON serializuje pola pod ich DOKŁADNĄ nazwą Go
// (np. "UserID", nie "user_id"). Pola tutaj muszą się nazywać identycznie
// (encoding/json dopasowuje bez tagu case-insensitive po nazwie pola, nie
// po tagu) — jeśli password-manager kiedyś doda tagi, to się rozjedzie i
// trzeba będzie to zsynchronizować.
type ServiceAccountEntry struct {
	UserID string `json:"UserID"`
	Name   string `json:"Name"`
}

// ListServiceAccounts — GET /g/{groupID}/service-accounts. Roster BEZ
// kaskady — dokładnie tej grupy, nie poddrzewa (jak group_keys).
func (c *Client) ListServiceAccounts(groupID string) ([]ServiceAccountEntry, error) {
	resp, err := c.do("GET", "/g/"+groupID+"/service-accounts", nil)
	if err != nil {
		return nil, err
	}
	return decode[[]ServiceAccountEntry](resp)
}

// RemoveServiceAccount — DELETE /g/{groupID}/service-accounts/{userID}.
func (c *Client) RemoveServiceAccount(groupID, userID string) error {
	resp, err := c.do("DELETE", "/g/"+groupID+"/service-accounts/"+userID, nil)
	if err != nil {
		return err
	}
	_, err = decode[map[string]string](resp)
	return err
}
