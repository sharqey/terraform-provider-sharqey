package secretcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgparmor "github.com/ProtonMail/go-crypto/openpgp/armor"
	pgppacket "github.com/ProtonMail/go-crypto/openpgp/packet"
)

// generateTestKeypair — sam algorytm co cmd/cli/keygen.go
// generateEphemeralKeypair, zduplikowany tu celowo (test-only helper, nie
// warto po to importować cmd/cli z pkg/).
func generateTestKeypair(t *testing.T) (publicArmored, privateArmored string) {
	t.Helper()
	entity, err := openpgp.NewEntity("Test", "", "", &pgppacket.Config{
		Algorithm: pgppacket.PubKeyAlgoEdDSA,
	})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var pubBuf, privBuf bytes.Buffer
	pubWriter, _ := pgparmor.Encode(&pubBuf, openpgp.PublicKeyType, nil)
	entity.Serialize(pubWriter)
	pubWriter.Close()
	privWriter, _ := pgparmor.Encode(&privBuf, openpgp.PrivateKeyType, nil)
	entity.SerializePrivate(privWriter, nil)
	privWriter.Close()
	return pubBuf.String(), privBuf.String()
}

// gpgEncryptTestHelper — odpowiednik gpgEncrypt z extension/src/groupkey.js,
// tylko w Go i tylko dla testu (żeby zasymulować "wpis group_keys" jaki
// serwer zwraca z GET /g/{groupID}/my-group-key — sam plaintext w środku to
// zwykły hex string klucza, dokładnie jak generateGroupKey robi w JS).
func gpgEncryptTestHelper(t *testing.T, plaintext, publicArmored string) string {
	t.Helper()
	pubKeys, err := openpgp.ReadArmoredKeyRing(strings.NewReader(publicArmored))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	var buf bytes.Buffer
	armorWriter, _ := pgparmor.Encode(&buf, "PGP MESSAGE", nil)
	w, err := openpgp.Encrypt(armorWriter, pubKeys, nil, nil, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	w.Write([]byte(plaintext))
	w.Close()
	armorWriter.Close()
	return buf.String()
}

func TestGroupSecretRoundTrip(t *testing.T) {
	publicArmored, privateArmored := generateTestKeypair(t)

	groupKeyBytes := make([]byte, 32)
	for i := range groupKeyBytes {
		groupKeyBytes[i] = byte(i)
	}
	groupKeyHex := hex.EncodeToString(groupKeyBytes)
	groupEncryptedKey := gpgEncryptTestHelper(t, groupKeyHex, publicArmored)

	plaintext := `{"password":"sup3r-s3cr3t","totp_secret":"","notes":"test"}`

	ciphertext, groupEncryptedSecretKey, err := EncryptGroupSecret(plaintext, groupEncryptedKey, privateArmored, "")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ciphertext == "" || groupEncryptedSecretKey == "" {
		t.Fatal("expected non-empty ciphertext and group_encrypted_secret_key")
	}

	got, err := DecryptGroupSecret(ciphertext, groupEncryptedSecretKey, groupEncryptedKey, privateArmored, "")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != plaintext {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, plaintext)
	}

	// Każde wywołanie EncryptGroupSecret losuje NOWY klucz sekretu — dwa
	// szyfrowania tego samego plaintextu nie powinny dać tego samego
	// ciphertextu (inny nonce, inny klucz).
	ciphertext2, _, err := EncryptGroupSecret(plaintext, groupEncryptedKey, privateArmored, "")
	if err != nil {
		t.Fatalf("encrypt (2nd): %v", err)
	}
	if ciphertext2 == ciphertext {
		t.Fatal("expected different ciphertext on second encrypt (random nonce/key)")
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i * 7)
	}
	keyHex := hex.EncodeToString(keyBytes)

	ciphertext, err := AESGCMEncrypt("hello world", keyHex)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plaintext, err := AESGCMDecrypt(ciphertext, keyHex)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plaintext != "hello world" {
		t.Fatalf("got %q, want %q", plaintext, "hello world")
	}
}

// Pusty wpis group_keys (nikt nie udostępnił klucza) daje ErrNoGroupKey.
func TestEmptyGroupKeyGivesErrNoGroupKey(t *testing.T) {
	if _, err := DecryptGroupSecret("ct", "gesk", "", "priv", ""); !errors.Is(err, ErrNoGroupKey) {
		t.Fatalf("decrypt: want ErrNoGroupKey, got %v", err)
	}
	if _, _, err := EncryptGroupSecret("pt", " ", "priv", ""); !errors.Is(err, ErrNoGroupKey) {
		t.Fatalf("encrypt: want ErrNoGroupKey, got %v", err)
	}
}
