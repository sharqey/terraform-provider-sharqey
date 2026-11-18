package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		baseURL:    baseURL,
		token:      token,
		httpClient: &http.Client{},
	}
}

// BaseURL — adres serwera skonfigurowany dla tego klienta (patrz
// localstate.Config.ServerURL). Używane m.in. do wyprowadzenia domeny dla
// UID-a klucza PGP nowego service accounta (resource_service_account.go).
func (c *Client) BaseURL() string {
	return c.baseURL
}

func (c *Client) SetToken(token string) { c.token = token }
func (c *Client) Token() string         { return c.token }

func (c *Client) do(method, path string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.httpClient.Do(req)
}

// doForm — application/x-www-form-urlencoded, dla endpointów które (jak
// internal/secret.Handler.Create) czytają r.FormValue zamiast JSON body.
func (c *Client) doForm(method, path string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequest(method, c.baseURL+path, bytes.NewReader([]byte(form.Encode())))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.httpClient.Do(req)
}

func decode[T any](resp *http.Response) (T, error) {
	var v T
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e map[string]string
		json.NewDecoder(resp.Body).Decode(&e)
		return v, fmt.Errorf("API error %d: %s", resp.StatusCode, e["error"])
	}
	return v, json.NewDecoder(resp.Body).Decode(&v)
}

func (c *Client) Login(email, password string) (string, error) {
	resp, err := c.do("POST", "/api/v1/login", map[string]string{"email": email, "password": password})
	if err != nil {
		return "", err
	}
	result, err := decode[map[string]string](resp)
	if err != nil {
		return "", err
	}
	return result["token"], nil
}

// ServiceAccountLogin wymienia kredencjał service accounta (tasks/029) —
// dokładnie jeden z token/webIdentityToken niepusty — na krótkotrwałą sesję
// Sharqey. webIdentityToken to surowy id_token z workload identity
// federation danej platformy CI (np. GitLab CI `id_tokens:`), branżowy
// wzorzec jak AWS AssumeRoleWithWebIdentity/Vault JWT auth.
func (c *Client) ServiceAccountLogin(token, webIdentityToken string) (string, error) {
	resp, err := c.do("POST", "/api/v1/service-accounts/login", map[string]string{
		"token":              token,
		"web_identity_token": webIdentityToken,
	})
	if err != nil {
		return "", err
	}
	result, err := decode[map[string]any](resp)
	if err != nil {
		return "", err
	}
	accessToken, _ := result["access_token"].(string)
	if accessToken == "" {
		return "", fmt.Errorf("no access_token in response")
	}
	return accessToken, nil
}

// ServiceAccountSelf — GET /api/v1/service-accounts/me. Wołane zamiast
// ListWorkspaces po service-account loginie: SA nigdy nie jest membershipem
// org roota (tylko subgrupy), więc ListWorkspaces zawsze zwróciłby pustą
// listę dla niego.
type ServiceAccountSelf struct {
	OrgID       string `json:"org_id"`
	OrgSlug     string `json:"org_slug"`
	OrgName     string `json:"org_name"`
	OrgFullPath string `json:"org_full_path"`
}

func (c *Client) ServiceAccountSelf() (ServiceAccountSelf, error) {
	resp, err := c.do("GET", "/api/v1/service-accounts/me", nil)
	if err != nil {
		return ServiceAccountSelf{}, err
	}
	return decode[ServiceAccountSelf](resp)
}

func (c *Client) ListOrgs() ([]Org, error) {
	resp, err := c.do("GET", "/api/v1/orgs", nil)
	if err != nil {
		return nil, err
	}
	return decode[[]Org](resp)
}

func (c *Client) CreateOrg(name string) (Org, error) {
	resp, err := c.do("POST", "/api/v1/orgs", map[string]string{"name": name})
	if err != nil {
		return Org{}, err
	}
	return decode[Org](resp)
}

func (c *Client) GetOrg(id string) (Org, []Member, error) {
	resp, err := c.do("GET", "/api/v1/orgs/"+id, nil)
	if err != nil {
		return Org{}, nil, err
	}
	result, err := decode[map[string]json.RawMessage](resp)
	if err != nil {
		return Org{}, nil, err
	}
	var org Org
	var members []Member
	json.Unmarshal(result["org"], &org)
	json.Unmarshal(result["members"], &members)
	return org, members, nil
}

func (c *Client) AddMember(orgID, email string) error {
	resp, err := c.do("POST", "/api/v1/orgs/"+orgID+"/members", map[string]string{"email": email})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e map[string]string
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("%s", e["error"])
	}
	return nil
}

func (c *Client) ListSecrets(orgID string) ([]Secret, error) {
	resp, err := c.do("GET", "/api/v1/orgs/"+orgID+"/secrets", nil)
	if err != nil {
		return nil, err
	}
	return decode[[]Secret](resp)
}

func (c *Client) CreateSecret(orgID, name, ciphertext, encryptedKey string) (Secret, error) {
	resp, err := c.do("POST", "/api/v1/orgs/"+orgID+"/secrets", map[string]string{
		"name": name, "ciphertext": ciphertext, "encrypted_key": encryptedKey,
	})
	if err != nil {
		return Secret{}, err
	}
	return decode[Secret](resp)
}

// ── Device linking (tasks/005) ──────────────────────────────────────────────
// CLI jako B: musi być zalogowane (c.token już ustawiony przez Login()) —
// login i posiadanie kluczy szyfrujących to niezależne rzeczy w tym systemie,
// patrz internal/device. Brak osobnej "bez auth" ścieżki — nie jest tu
// potrzebna.

type DeviceLinkRequestResult struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	ExpiresAt   string `json:"expires_at"`
}

func (c *Client) StartDeviceLinkRequest(ephemeralPublicKey, deviceLabel, linkedVia string) (DeviceLinkRequestResult, error) {
	resp, err := c.do("POST", "/api/v1/device-link/requests", map[string]string{
		"ephemeral_public_key": ephemeralPublicKey,
		"device_label":         deviceLabel,
		"linked_via":           linkedVia,
	})
	if err != nil {
		return DeviceLinkRequestResult{}, err
	}
	return decode[DeviceLinkRequestResult](resp)
}

type DeviceLinkPollResult struct {
	Status        string `json:"status"`
	EncryptedBlob string `json:"encrypted_blob"`
}

func (c *Client) PollDeviceLinkRequest(requestID string) (DeviceLinkPollResult, error) {
	resp, err := c.do("GET", "/api/v1/device-link/requests/"+requestID+"/poll", nil)
	if err != nil {
		return DeviceLinkPollResult{}, err
	}
	return decode[DeviceLinkPollResult](resp)
}

// ── CLI login (device-code flow, tasks/todo/026) ────────────────────────────
// Świadomie BEZ tokenu w obu wywołaniach — to jest KROK w którym CLI
// dopiero zdobywa token, nie ma go jeszcze skąd wziąć.

type CLILoginRequestResult struct {
	ID        string `json:"id"`
	Code      string `json:"code"`
	ExpiresAt string `json:"expires_at"`
}

func (c *Client) CreateCLILoginRequest(deviceLabel string) (CLILoginRequestResult, error) {
	resp, err := c.do("POST", "/api/v1/cli/login-requests", map[string]string{"device_label": deviceLabel})
	if err != nil {
		return CLILoginRequestResult{}, err
	}
	return decode[CLILoginRequestResult](resp)
}

type CLILoginPollResult struct {
	Status string `json:"status"`
	Token  string `json:"token"`
}

func (c *Client) PollCLILoginRequest(requestID string) (CLILoginPollResult, error) {
	resp, err := c.do("GET", "/api/v1/cli/login-requests/"+requestID+"/poll", nil)
	if err != nil {
		return CLILoginPollResult{}, err
	}
	return decode[CLILoginPollResult](resp)
}

func (c *Client) ShareSecret(orgID, secretID, userID, encryptedKey string) error {
	resp, err := c.do("POST", fmt.Sprintf("/api/v1/orgs/%s/secrets/%s/share", orgID, secretID),
		map[string]string{"user_id": userID, "encrypted_key": encryptedKey})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e map[string]string
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("%s", e["error"])
	}
	return nil
}
