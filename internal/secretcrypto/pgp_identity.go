// Kryptografia potrzebna dopiero przez sharqey_group/sharqey_service_account
// (tasks/todo/062 w password-manager): generowanie nowych keypairów OpenPGP i
// szyfrowanie DO klucza publicznego — operacje odwrotne do tych w crypto.go
// (które tylko deszyfrują/AES-szyfrują istniejący materiał). Port 1:1 z
// password-manager-goclient/pgpcrypto (GenerateIdentityKeypair/
// PublicKeyFromPrivateKeyArmored/EncryptArmoredMessage/GenerateEncryptedGroupKey)
// — nie zaimportowane stamtąd (świadoma decyzja o kopii, patrz README tego repo),
// tylko przepisane z użyciem tych samych bibliotek co reszta tego pakietu.
package secretcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgparmor "github.com/ProtonMail/go-crypto/openpgp/armor"
	pgppacket "github.com/ProtonMail/go-crypto/openpgp/packet"
)

func serializeArmored(blockType string, write func(w io.Writer) error) (string, error) {
	buf := new(bytes.Buffer)
	w, err := pgparmor.Encode(buf, blockType, nil)
	if err != nil {
		return "", err
	}
	if err := write(w); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// GenerateIdentityKeypair — nowy keypair OpenPGP RSA-4096 (dokładnie ten sam
// algorytm co org_identity_keys ludzi, patrz fundament #1 w CLAUDE.md tego
// projektu) BEZ passphrase — ani service account, ani `sharqey_identity_key`
// (resource_identity_key.go) nie logują się interaktywnie, więc nie ma kto
// by tę passphrase później podał (ten sam, zaakceptowany branżowo tradeoff
// co CI-only GPG key w sops, patrz password-manager/tasks/todo/029). Klucz
// prywatny trafia do Terraform state jako sensitive — state Terraforma jest
// już traktowany jako wrażliwy (zawiera też np. tokeny), zgodnie z
// branżowym standardem (Vault/AWS Secrets Manager providery robią to samo).
// name — UID display name w kluczu (np. "Sharqey Service Account" dla SA,
// dowolne dla sharqey_identity_key — user decyduje co tam wpisać).
func GenerateIdentityKeypair(name, email string) (publicKeyArmored, privateKeyArmored string, err error) {
	entity, err := openpgp.NewEntity(name, "", email, &pgppacket.Config{
		Algorithm: pgppacket.PubKeyAlgoRSA,
		RSABits:   4096,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate keypair: %w", err)
	}
	publicKeyArmored, err = serializeArmored("PGP PUBLIC KEY BLOCK", entity.Serialize)
	if err != nil {
		return "", "", fmt.Errorf("armor public key: %w", err)
	}
	privateKeyArmored, err = serializeArmored("PGP PRIVATE KEY BLOCK", func(w io.Writer) error {
		return entity.SerializePrivateWithoutSigning(w, nil)
	})
	if err != nil {
		return "", "", fmt.Errorf("armor private key: %w", err)
	}
	return publicKeyArmored, privateKeyArmored, nil
}

// PublicKeyFromPrivateKeyArmored wyłuskuje klucz publiczny z armorowanego
// keyringa prywatnego — go-crypto po ReadArmoredKeyRing wypełnia część
// publiczną entity nawet dla private-key-ringa, więc zwykłe Serialize()
// wystarcza (ten sam trik co password-manager-goclient/pgpcrypto).
func PublicKeyFromPrivateKeyArmored(armoredPrivateKey string) (string, error) {
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPrivateKey))
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	if len(entities) == 0 {
		return "", fmt.Errorf("private key ring is empty")
	}
	pub, err := serializeArmored("PGP PUBLIC KEY BLOCK", entities[0].Serialize)
	if err != nil {
		return "", fmt.Errorf("armor public key: %w", err)
	}
	return pub, nil
}

// EncryptOpenPGP szyfruje plaintext do armorowanego klucza PUBLICZNEGO —
// operacja odwrotna do DecryptOpenPGP (crypto.go). Używane do zawinięcia
// group key do WŁASNEGO klucza publicznego (nowa subgrupa, patrz
// GenerateGroupKey) albo do klucza publicznego nowego service accounta
// (resource_service_account.go).
func EncryptOpenPGP(plaintext, armoredPublicKey string) (string, error) {
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPublicKey))
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	buf := new(bytes.Buffer)
	aw, err := pgparmor.Encode(buf, "PGP MESSAGE", nil)
	if err != nil {
		return "", fmt.Errorf("armor encode: %w", err)
	}
	w, err := openpgp.Encrypt(aw, entities, nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		return "", fmt.Errorf("write plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("close message writer: %w", err)
	}
	if err := aw.Close(); err != nil {
		return "", fmt.Errorf("close armor writer: %w", err)
	}
	return buf.String(), nil
}

// GenerateGroupKey — losowy klucz AES-256 (32 bajty, hex) dla świeżo
// utworzonej subgrupy, zaszyfrowany do podanego klucza publicznego (typowo:
// WŁASNY, przy self-wrap zaraz po utworzeniu grupy — patrz
// group.Handler.StoreGroupKey w password-manager, gałąź "bootstrap" dla
// twórcy grupy bez jeszcze żadnego group_key). Odpowiednik
// extension/src/groupkey.js:generateGroupKey.
func GenerateGroupKey(armoredPublicKey string) (groupKeyHex, encryptedGroupKey string, err error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", fmt.Errorf("generate group key: %w", err)
	}
	groupKeyHex = hex.EncodeToString(keyBytes)
	encryptedGroupKey, err = EncryptOpenPGP(groupKeyHex, armoredPublicKey)
	if err != nil {
		return "", "", fmt.Errorf("encrypt group key: %w", err)
	}
	return groupKeyHex, encryptedGroupKey, nil
}
