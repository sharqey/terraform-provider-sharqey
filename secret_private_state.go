package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/sharqey/goclient/pgpcrypto"
	"github.com/sharqey/terraform-provider-sharqey/internal/client"
)

// Private state sekretów w API mode (TASK-002). Stan Terraform nie trzyma
// żadnego plaintextu: wartość/treść pliku to atrybuty write-only, a do
// wykrywania różnic służy ciphertext z serwera trzymany w private state
// (niewidoczny w diffach planu). Leży tu dokładnie to, co i tak leży na
// serwerze — ciphertext i klucze zawinięte kluczem grupy/publicznym.
const privateKeySecret = "secret"

type storedSecret struct {
	OrgID                   string `json:"org_id"`
	GroupID                 string `json:"group_id"`
	Ciphertext              string `json:"ciphertext"`
	GroupEncryptedSecretKey string `json:"group_encrypted_secret_key,omitempty"`
	OwnerEncryptedSecretKey string `json:"owner_encrypted_secret_key,omitempty"`
	DirectKey               string `json:"direct_key,omitempty"`
	// GroupKey — wpis group_keys tożsamości, która ostatnio zapisała ten
	// materiał (zawinięty JEJ kluczem publicznym). Inna tożsamość (np.
	// service account w CI) go nie odszyfruje — decryptStored dociąga
	// wtedy świeży materiał.
	GroupKey string `json:"group_key,omitempty"`
	// ContentMAC — tylko sharqey_file_secret: HMAC-SHA256 treści pliku z
	// kluczem file_key (z zaszyfrowanych metadanych), patrz fileContentMAC.
	ContentMAC string `json:"content_mac,omitempty"`
}

// privateReader/privateWriter — *privatestate.ProviderData jest w pakiecie
// internal frameworka, więc nie da się go nazwać wprost.
type privateReader interface {
	GetKey(ctx context.Context, key string) ([]byte, diag.Diagnostics)
}

type privateWriter interface {
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

// loadStored — nil, gdy private state jeszcze nie ma materiału (np. tuż po
// imporcie, przed pierwszym Read).
func loadStored(ctx context.Context, p privateReader) (*storedSecret, diag.Diagnostics) {
	raw, diags := p.GetKey(ctx, privateKeySecret)
	if diags.HasError() || len(raw) == 0 {
		return nil, diags
	}
	var s storedSecret
	if err := json.Unmarshal(raw, &s); err != nil {
		diags.AddError("Corrupted private state", fmt.Sprintf("private state %q: %v", privateKeySecret, err))
		return nil, diags
	}
	return &s, diags
}

func saveStored(ctx context.Context, p privateWriter, s *storedSecret) diag.Diagnostics {
	raw, err := json.Marshal(s)
	if err != nil {
		var diags diag.Diagnostics
		diags.AddError("Failed to encode private state", err.Error())
		return diags
	}
	return p.SetKey(ctx, privateKeySecret, raw)
}

func (s *storedSecret) setDetail(d *client.SecretDetail) {
	s.Ciphertext = d.Ciphertext
	s.GroupEncryptedSecretKey = d.GroupEncryptedSecretKey
	s.OwnerEncryptedSecretKey = d.OwnerEncryptedSecretKey
	s.DirectKey = d.DirectKey
	s.GroupKey = d.GroupKey
}

// decrypt — te same trzy ścieżki co `sharqey get`: grupa Private (owner
// key), udostępnienie per-sekret (direct key), zwykła grupa (group key).
func (s *storedSecret) decrypt(privateKey string) (string, error) {
	switch {
	case s.OwnerEncryptedSecretKey != "":
		return pgpcrypto.DecryptDirectSecret(s.Ciphertext, s.OwnerEncryptedSecretKey, privateKey, "")
	case s.DirectKey != "":
		return pgpcrypto.DecryptDirectSecret(s.Ciphertext, s.DirectKey, privateKey, "")
	default:
		return pgpcrypto.DecryptWithGroupKey(s.Ciphertext, s.GroupEncryptedSecretKey, s.GroupKey, privateKey)
	}
}

// decryptStored odszyfrowuje ciphertext z private state kluczem bieżącej
// tożsamości. Gdy się nie da (materiał zapisała inna tożsamość, klucz grupy
// zrotowano), dociąga świeży materiał z serwera i próbuje jeszcze raz — s
// jest wtedy zaktualizowany, wołający powinien go zapisać z powrotem.
func decryptStored(pd *providerData, s *storedSecret, secretID string) (string, error) {
	privateKey, ok := pd.privateKeyForOrg(s.OrgID)
	if !ok {
		return "", fmt.Errorf("no local key for organization %s — run `sharqey login`", s.OrgID)
	}
	plaintext, err := s.decrypt(privateKey)
	if err == nil {
		return plaintext, nil
	}
	detail, fetchErr := pd.api.GetSecret(s.GroupID, secretID)
	if fetchErr != nil {
		return "", fmt.Errorf("decrypt stored secret: %v; refetch: %w", err, fetchErr)
	}
	s.setDetail(detail)
	return s.decrypt(privateKey)
}

// fileContentMAC — odcisk treści pliku, który zweryfikuje tylko ktoś
// znający file_key (czyli zdolny odszyfrować metadane pliku). Zwykły
// SHA-256 plaintextu w stanie pozwalałby zgadywać krótkie pliki.
func fileContentMAC(fileKeyHex string, data []byte) (string, error) {
	key, err := hex.DecodeString(strings.TrimSpace(fileKeyHex))
	if err != nil {
		return "", fmt.Errorf("decode file key: %w", err)
	}
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// updatedAtValue — wartość atrybutu updated_at; porównywana z serwerem
// dosłownie (nigdy z lokalnym zegarem).
func updatedAtValue(t time.Time) types.String {
	return types.StringValue(t.UTC().Format(time.RFC3339Nano))
}
