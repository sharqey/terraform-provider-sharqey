package client

// SSOConfig — odpowiedź GET /g/{orgID}/sso/config (sso.Handler.GetConfig,
// password-manager). sp_entity_id/sp_acs_url/oidc_redirect_uri są
// DETERMINISTYCZNE (wynikają z baseURL+orgID, nie z zapisanego connection)
// i wracają ZAWSZE, nawet gdy Configured==false — admin potrzebuje ich
// PRZED zapisaniem connection (np. AWS IAM Identity Center wymaga wpisania
// "naszego" ACS URL zanim IdP odda swoje wartości do SaveConfig).
// OIDCClientSecret/SAMLIdPCertificate świadomie NIEOBECNE — serwer nigdy
// ich nie oddaje z powrotem (write-only), stąd tylko HasSAMLCert (bool).
type SSOConfig struct {
	Configured      bool   `json:"configured"`
	Protocol        string `json:"protocol,omitempty"`
	Enabled         bool   `json:"enabled"`
	SSOOnly         bool   `json:"sso_only"`
	OIDCIssuerURL   string `json:"oidc_issuer_url"`
	OIDCClientID    string `json:"oidc_client_id"`
	SAMLIdPEntityID string `json:"saml_idp_entity_id"`
	SAMLIdPSSOURL   string `json:"saml_idp_sso_url"`
	HasSAMLCert     bool   `json:"has_saml_certificate"`
	SPEntityID      string `json:"sp_entity_id"`
	SPACSURL        string `json:"sp_acs_url"`
	OIDCRedirectURI string `json:"oidc_redirect_uri"`
}

// GetSSOConfig — GET /g/{orgID}/sso/config. Wymaga roli org-admin+
// (requireOrgAdmin w sso.Handler — OrgRole(role).AtLeast(OrgRoleAdmin)).
func (c *Client) GetSSOConfig(orgID string) (SSOConfig, error) {
	resp, err := c.do("GET", "/g/"+orgID+"/sso/config", nil)
	if err != nil {
		return SSOConfig{}, err
	}
	return decode[SSOConfig](resp)
}

// SaveSSOConfigParams — body PUT /g/{orgID}/sso/config. Protocol musi być
// "oidc" albo "saml" (sso.Handler.SaveConfig waliduje server-side i odrzuca
// z 400 czytelnym komunikatem jeśli brakuje wymaganych pól dla wybranego
// protokołu — świadomie NIE zduplikowane jako client-side walidacja tutaj,
// patrz plan resilient-plotting-garden.md).
type SaveSSOConfigParams struct {
	Protocol           string
	Enabled            bool
	SSOOnly            bool
	OIDCIssuerURL      string
	OIDCClientID       string
	OIDCClientSecret   string
	SAMLIdPEntityID    string
	SAMLIdPSSOURL      string
	SAMLIdPCertificate string
}

// SaveSSOConfig — PUT /g/{orgID}/sso/config. Upsert: jeden connection per
// organizacja, wołanie ponowne po prostu nadpisuje poprzedni (Create i
// Update w resource_sso.go mają więc identyczne ciało).
func (c *Client) SaveSSOConfig(orgID string, p SaveSSOConfigParams) error {
	resp, err := c.do("PUT", "/g/"+orgID+"/sso/config", map[string]any{
		"protocol":             p.Protocol,
		"enabled":              p.Enabled,
		"sso_only":             p.SSOOnly,
		"oidc_issuer_url":      p.OIDCIssuerURL,
		"oidc_client_id":       p.OIDCClientID,
		"oidc_client_secret":   p.OIDCClientSecret,
		"saml_idp_entity_id":   p.SAMLIdPEntityID,
		"saml_idp_sso_url":     p.SAMLIdPSSOURL,
		"saml_idp_certificate": p.SAMLIdPCertificate,
	})
	if err != nil {
		return err
	}
	_, err = decode[map[string]bool](resp)
	return err
}

// DeleteSSOConfig — DELETE /g/{orgID}/sso/config.
func (c *Client) DeleteSSOConfig(orgID string) error {
	resp, err := c.do("DELETE", "/g/"+orgID+"/sso/config", nil)
	if err != nil {
		return err
	}
	_, err = decode[map[string]bool](resp)
	return err
}
