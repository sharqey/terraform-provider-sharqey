package main

import (
	"testing"

	"github.com/sharqey/goclient/pgpcrypto"
	"github.com/sharqey/terraform-provider-sharqey/internal/secretcrypto"
)

// Drzewo Private szyfruje sekret wprost kluczem właściciela, a storedSecret
// (private state) odszyfrowuje go tą samą ścieżką co `sharqey get`.
func TestOwnerEncryptedSecretRoundTrip(t *testing.T) {
	pub, priv, err := secretcrypto.GenerateIdentityKeypair("Owner", "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := buildPlaintext("env", "s3cr3t", "")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, ownerKey, err := pgpcrypto.EncryptOwnerSecret(plaintext, pub)
	if err != nil {
		t.Fatal(err)
	}
	stored := &storedSecret{Ciphertext: ciphertext, OwnerEncryptedSecretKey: ownerKey}
	got, err := stored.decrypt(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != plaintext {
		t.Fatalf("round trip mismatch: %q != %q", got, plaintext)
	}
}

func TestOwnerOrNil(t *testing.T) {
	if ownerOrNil("") != nil {
		t.Fatal("empty key must not be sent")
	}
	if p := ownerOrNil("k"); p == nil || *p != "k" {
		t.Fatal("non-empty key must be sent")
	}
}
