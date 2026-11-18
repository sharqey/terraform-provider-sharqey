package client

// SubtreeKey — grupa z gałęzi razem z group_keys wywołującego
// (GET /g/{groupID}/keyed-subtree?with_keys=1).
type SubtreeKey struct {
	ID             string `json:"id"`
	FullPath       string `json:"full_path"`
	MyEncryptedKey string `json:"my_encrypted_key"`
}

// KeyedSubtree — wszystkie grupy z gałęzi groupID (ona sama i niżej), do
// których wywołujący MA klucz, jednym zapytaniem. Grupy bez jego klucza są
// pominięte — tam udostępnić może tylko ktoś, kto go ma.
func (c *Client) KeyedSubtree(groupID string) ([]SubtreeKey, error) {
	resp, err := c.do("GET", "/g/"+groupID+"/keyed-subtree?with_keys=1", nil)
	if err != nil {
		return nil, err
	}
	return decode[[]SubtreeKey](resp)
}

// GroupKeyForUser — klucz jednej grupy zaszyfrowany do klucza publicznego
// odbiorcy.
type GroupKeyForUser struct {
	GroupID      string `json:"group_id"`
	EncryptedKey string `json:"encrypted_key"`
}

// ShareSubtreeGroupKeys — POST /g/{groupID}/subtree-group-keys: klucze wielu
// grup z gałęzi groupID dla jednego usera, w jednej transakcji (wszystkie
// albo żaden). Wywołujący musi zarządzać każdą z tych grup.
func (c *Client) ShareSubtreeGroupKeys(groupID, targetUserID string, keys []GroupKeyForUser) error {
	resp, err := c.do("POST", "/g/"+groupID+"/subtree-group-keys", map[string]any{
		"target_user_id": targetUserID, "keys": keys,
	})
	if err != nil {
		return err
	}
	_, err = decode[map[string]int](resp)
	return err
}

// MemberNeedingKey — członek z rolą w grupie (także odziedziczoną z rodzica),
// bez group_keys tej grupy.
type MemberNeedingKey struct {
	UserID    string `json:"user_id"`
	PublicKey string `json:"public_key"`
}

// MembersNeedingKey — GET /g/{groupID}/members-needing-key. Ta sama lista co
// "Sync" w web UI; pomija wywołującego i członków bez klucza w organizacji.
func (c *Client) MembersNeedingKey(groupID string) ([]MemberNeedingKey, error) {
	resp, err := c.do("GET", "/g/"+groupID+"/members-needing-key", nil)
	if err != nil {
		return nil, err
	}
	return decode[[]MemberNeedingKey](resp)
}
