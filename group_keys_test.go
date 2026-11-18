package main

import (
	"testing"

	"github.com/sharqey/terraform-provider-sharqey/internal/client"
	"github.com/sharqey/terraform-provider-sharqey/internal/secretcrypto"
)

func TestRewrapGroupKeys(t *testing.T) {
	ownPub, ownPriv, err := secretcrypto.GenerateIdentityKeypair("Owner", "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	saPub, saPriv, err := secretcrypto.GenerateIdentityKeypair("SA", "sa@tokens.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var subtree []client.SubtreeKey
	want := map[string]string{}
	for _, id := range []string{"g-root", "g-child", "g-grandchild"} {
		hex, enc, err := secretcrypto.GenerateGroupKey(ownPub)
		if err != nil {
			t.Fatal(err)
		}
		want[id] = hex
		subtree = append(subtree, client.SubtreeKey{ID: id, FullPath: "org/" + id, MyEncryptedKey: enc})
	}

	keys, err := rewrapGroupKeys(subtree, ownPriv, saPub)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != len(subtree) {
		t.Fatalf("got %d keys, want %d", len(keys), len(subtree))
	}
	for _, k := range keys {
		got, err := secretcrypto.DecryptOpenPGP(k.EncryptedKey, saPriv, "")
		if err != nil {
			t.Fatalf("%s: SA cannot decrypt: %v", k.GroupID, err)
		}
		if got != want[k.GroupID] {
			t.Errorf("%s: group key mismatch", k.GroupID)
		}
	}
	if !containsGroup(keys, "g-root") || containsGroup(keys, "other") {
		t.Error("containsGroup")
	}
}
