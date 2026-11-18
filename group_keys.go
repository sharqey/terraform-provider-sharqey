package main

import (
	"fmt"

	"github.com/sharqey/terraform-provider-sharqey/internal/client"
	"github.com/sharqey/terraform-provider-sharqey/internal/secretcrypto"
)

// rewrapGroupKeys odszyfrowuje klucze grup wywołującego (subtree z
// KeyedSubtree) jego kluczem prywatnym i szyfruje je do klucza publicznego
// odbiorcy. Serwer nigdy nie widzi surowego klucza grupy (E2E), więc
// udostępnienie gałęzi to zawsze praca klienta: raz na grupę, nie raz na
// sekret.
func rewrapGroupKeys(subtree []client.SubtreeKey, ownPrivateKey, recipientPublicKey string) ([]client.GroupKeyForUser, error) {
	out := make([]client.GroupKeyForUser, 0, len(subtree))
	for _, g := range subtree {
		groupKeyHex, err := secretcrypto.DecryptOpenPGP(g.MyEncryptedKey, ownPrivateKey, "")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", g.FullPath, err)
		}
		enc, err := secretcrypto.EncryptOpenPGP(groupKeyHex, recipientPublicKey)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", g.FullPath, err)
		}
		out = append(out, client.GroupKeyForUser{GroupID: g.ID, EncryptedKey: enc})
	}
	return out, nil
}

func containsGroup(keys []client.GroupKeyForUser, groupID string) bool {
	for _, k := range keys {
		if k.GroupID == groupID {
			return true
		}
	}
	return false
}

// shareWithMembersNeedingKey udostępnia klucz świeżo utworzonej grupy
// wszystkim, którzy mają w niej rolę (także odziedziczoną), a klucza nie.
func shareWithMembersNeedingKey(api *client.Client, groupID, groupKeyHex string) error {
	members, err := api.MembersNeedingKey(groupID)
	if err != nil {
		return err
	}
	for _, m := range members {
		enc, err := secretcrypto.EncryptOpenPGP(groupKeyHex, m.PublicKey)
		if err != nil {
			return fmt.Errorf("user %s: %w", m.UserID, err)
		}
		if err := api.StoreGroupKey(groupID, m.UserID, enc); err != nil {
			return fmt.Errorf("user %s: %w", m.UserID, err)
		}
	}
	return nil
}
