package secretcrypto

import "testing"

// TestGroupKeyBootstrapRoundTrip odtwarza cały łańcuch resource_group.go
// Create: nowy keypair (jak twórca subgrupy) -> wyprowadzenie klucza
// publicznego z prywatnego -> self-wrap nowego group key -> odszyfrowanie
// tym samym kluczem prywatnym, dokładnie jak zrobiłby to kolejny Read/apply.
func TestGroupKeyBootstrapRoundTrip(t *testing.T) {
	_, privateKey, err := GenerateIdentityKeypair("Test", "")
	if err != nil {
		t.Fatalf("GenerateIdentityKeypair: %v", err)
	}
	publicKey, err := PublicKeyFromPrivateKeyArmored(privateKey)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivateKeyArmored: %v", err)
	}
	groupKeyHex, encryptedGroupKey, err := GenerateGroupKey(publicKey)
	if err != nil {
		t.Fatalf("GenerateGroupKey: %v", err)
	}
	decrypted, err := DecryptOpenPGP(encryptedGroupKey, privateKey, "")
	if err != nil {
		t.Fatalf("DecryptOpenPGP: %v", err)
	}
	if decrypted != groupKeyHex {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, groupKeyHex)
	}
}

// TestServiceAccountGroupKeyShareRoundTrip odtwarza resource_service_account.go
// Create: "manager" ma już groupKeyHex (jakby z GetMyGroupKey+DecryptOpenPGP),
// nowy SA keypair jest generowany, group key jest re-szyfrowany DO klucza
// publicznego SA, a SA musi umieć go odszyfrować swoim kluczem prywatnym.
func TestServiceAccountGroupKeyShareRoundTrip(t *testing.T) {
	managerPublic, managerPrivate, err := GenerateIdentityKeypair("Test", "")
	if err != nil {
		t.Fatalf("GenerateIdentityKeypair (manager): %v", err)
	}
	groupKeyHex, encryptedForManager, err := GenerateGroupKey(managerPublic)
	if err != nil {
		t.Fatalf("GenerateGroupKey: %v", err)
	}
	decryptedByManager, err := DecryptOpenPGP(encryptedForManager, managerPrivate, "")
	if err != nil {
		t.Fatalf("DecryptOpenPGP (manager): %v", err)
	}
	if decryptedByManager != groupKeyHex {
		t.Fatalf("manager round-trip mismatch: got %q, want %q", decryptedByManager, groupKeyHex)
	}

	saPublic, saPrivate, err := GenerateIdentityKeypair("Test", "")
	if err != nil {
		t.Fatalf("GenerateIdentityKeypair (service account): %v", err)
	}
	encryptedForSA, err := EncryptOpenPGP(decryptedByManager, saPublic)
	if err != nil {
		t.Fatalf("EncryptOpenPGP: %v", err)
	}
	decryptedBySA, err := DecryptOpenPGP(encryptedForSA, saPrivate, "")
	if err != nil {
		t.Fatalf("DecryptOpenPGP (service account): %v", err)
	}
	if decryptedBySA != groupKeyHex {
		t.Fatalf("service account round-trip mismatch: got %q, want %q", decryptedBySA, groupKeyHex)
	}
}
