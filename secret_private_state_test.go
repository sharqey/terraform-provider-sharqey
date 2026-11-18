package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sharqey/goclient/pgpcrypto"
	"github.com/sharqey/terraform-provider-sharqey/internal/client"
	"github.com/sharqey/terraform-provider-sharqey/internal/localstate"
	"github.com/sharqey/terraform-provider-sharqey/internal/secretcrypto"
)

// Dwie tożsamości w tej samej grupie (np. człowiek lokalnie i service
// account w CI): każda ma własny wpis group_keys, klucz grupy ten sam.
type testGroup struct {
	orgID, groupID string
	human, ci      *pgpcrypto.Keypair
	humanGroupKey  string // wpis group_keys zawinięty kluczem human
	ciGroupKey     string // ten sam klucz grupy zawinięty kluczem ci
}

func newTestGroup(t *testing.T) testGroup {
	t.Helper()
	human, err := pgpcrypto.GenerateEphemeralKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ci, err := pgpcrypto.GenerateEphemeralKeypair()
	if err != nil {
		t.Fatal(err)
	}
	groupKeyHex, humanGroupKey, err := pgpcrypto.GenerateEncryptedGroupKey(human.PublicKeyArmored)
	if err != nil {
		t.Fatal(err)
	}
	ciGroupKey, err := pgpcrypto.EncryptArmoredMessage(groupKeyHex, ci.PublicKeyArmored)
	if err != nil {
		t.Fatal(err)
	}
	return testGroup{orgID: "org-1", groupID: "group-1", human: human, ci: ci, humanGroupKey: humanGroupKey, ciGroupKey: ciGroupKey}
}

func apiProviderAs(orgID string, kp *pgpcrypto.Keypair, api *client.Client) *providerData {
	return &providerData{
		mode: modeAPI,
		api:  api,
		keychain: localstate.KeychainFile{Entries: []localstate.KeychainEntry{
			{OrgID: orgID, PrivateKeyArmored: kp.PrivateKeyArmored},
		}},
	}
}

// Ścieżka szczęśliwa ModifyPlan: materiał zapisany przez tę samą tożsamość
// odszyfrowuje się bez żadnego requestu (api == nil wywaliłoby panic).
func TestDecryptStoredWithoutNetwork(t *testing.T) {
	g := newTestGroup(t)
	plaintext, _ := buildPlaintext("env", "s3cret", "notatka")
	ct, gesk, err := secretcrypto.EncryptGroupSecret(plaintext, g.humanGroupKey, g.human.PrivateKeyArmored, "")
	if err != nil {
		t.Fatal(err)
	}
	stored := &storedSecret{OrgID: g.orgID, GroupID: g.groupID, Ciphertext: ct, GroupEncryptedSecretKey: gesk, GroupKey: g.humanGroupKey}

	got, err := decryptStored(apiProviderAs(g.orgID, g.human, nil), stored, "secret-1")
	if err != nil {
		t.Fatalf("decryptStored: %v", err)
	}
	value, notes, _ := parsePlaintext(got)
	if value != "s3cret" || notes != "notatka" {
		t.Fatalf("got %q/%q", value, notes)
	}
}

// Private state zapisał człowiek, plan robi CI: wpis group_key w private
// state jest nie do odszyfrowania dla CI, więc decryptStored dociąga
// materiał CI przez GetSecret i aktualizuje stored.
func TestDecryptStoredRefetchesForOtherIdentity(t *testing.T) {
	g := newTestGroup(t)
	plaintext, _ := buildPlaintext("account", "hunter2", "")
	ct, gesk, err := secretcrypto.EncryptGroupSecret(plaintext, g.humanGroupKey, g.human.PrivateKeyArmored, "")
	if err != nil {
		t.Fatal(err)
	}

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/g/"+g.groupID+"/secrets/secret-1" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(client.SecretDetail{Ciphertext: ct, GroupEncryptedSecretKey: gesk, GroupKey: g.ciGroupKey})
	}))
	defer srv.Close()

	stored := &storedSecret{OrgID: g.orgID, GroupID: g.groupID, Ciphertext: ct, GroupEncryptedSecretKey: gesk, GroupKey: g.humanGroupKey}
	got, err := decryptStored(apiProviderAs(g.orgID, g.ci, client.New(srv.URL, "token")), stored, "secret-1")
	if err != nil {
		t.Fatalf("decryptStored: %v", err)
	}
	if value, _, _ := parsePlaintext(got); value != "hunter2" {
		t.Fatalf("value = %q", value)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	if stored.GroupKey != g.ciGroupKey {
		t.Fatal("stored.GroupKey not refreshed to the CI identity's entry")
	}
}

// Materiał w private state jest ciphertextem — nie może zawierać plaintextu.
func TestStoredSecretHasNoPlaintext(t *testing.T) {
	g := newTestGroup(t)
	plaintext, _ := buildPlaintext("env", "very-unique-value-123", "")
	ct, gesk, err := secretcrypto.EncryptGroupSecret(plaintext, g.humanGroupKey, g.human.PrivateKeyArmored, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(storedSecret{OrgID: g.orgID, GroupID: g.groupID, Ciphertext: ct, GroupEncryptedSecretKey: gesk, GroupKey: g.humanGroupKey})
	if strings.Contains(string(raw), "very-unique-value-123") {
		t.Fatal("plaintext leaked into private state")
	}
}

func TestFileContentMAC(t *testing.T) {
	k1 := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	k2 := "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
	a, _ := fileContentMAC(k1, []byte("profile-v1"))
	b, _ := fileContentMAC(k1, []byte("profile-v1"))
	c, _ := fileContentMAC(k1, []byte("profile-v2"))
	d, _ := fileContentMAC(k2, []byte("profile-v1"))
	if a != b {
		t.Fatal("same key+content must give the same MAC")
	}
	if a == c {
		t.Fatal("different content must give a different MAC")
	}
	if a == d {
		t.Fatal("different file_key must give a different MAC")
	}
	if _, err := fileContentMAC("not-hex", nil); err == nil {
		t.Fatal("invalid key must fail")
	}
}
