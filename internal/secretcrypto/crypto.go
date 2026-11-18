// Package secretcrypto to lokalna (klient-side) kryptografia sekretów —
// dokładnie te operacje, które w przeglądarce robi
// extension/src/groupkey.js, w Go.
//
// Skopiowane 2026-09-06 z password-manager/pkg/secretcrypto przy wydzieleniu
// tego repo (password-manager/tasks/todo/062) — świadomie KOPIA, nie import
// współdzielonego modułu, patrz uzasadnienie w internal/localstate/config.go.
package secretcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgparmor "github.com/ProtonMail/go-crypto/openpgp/armor"
	pgppacket "github.com/ProtonMail/go-crypto/openpgp/packet"
)

// GPGDecrypt odszyfrowuje ciphertext zawinięty jednopoziomowo — ścieżka
// DirectKey (per-secret share, tasks/done/022): symetryczny klucz sekretu
// zawinięty WPROST kluczem publicznym usera, bez pośredniczenia przez
// klucz grupy.
func GPGDecrypt(ciphertext, encryptedKey, privateKeyArmored, passphrase string) (string, error) {
	symKeyHex, err := DecryptOpenPGP(encryptedKey, privateKeyArmored, passphrase)
	if err != nil {
		return "", err
	}
	return AESGCMDecrypt(ciphertext, strings.TrimSpace(symKeyHex))
}

// ErrNoGroupKey — konto ma rolę w grupie, ale nikt mu nie udostępnił klucza
// grupy (np. service account dodany do grupy-rodzica: rola kaskaduje, klucz
// nie). Ten sam komunikat co goclient pgpcrypto.ErrNoGroupKey; wcześniej
// wychodziło "decrypt group key: armor decode: EOF" (password-manager
// BUGS.md 2026-09-12).
var ErrNoGroupKey = errors.New("this account has a role in the group, but nobody has shared the group's key with it yet — a group manager needs to open the group in Sharqey and click Sync")

// DecryptGroupSecret odszyfrowuje sekret grupowy — 3-etapowy łańcuch:
// klucz prywatny org identity usera odblokowuje wpis group_keys tego usera
// dla tej grupy (groupKey, hex), groupKey odblokowuje per-sekretowy klucz
// AES (secretKey, hex), secretKey odszyfrowuje właściwy ciphertext. Replika
// extension/src/groupkey.js:decryptWithGroupKey.
func DecryptGroupSecret(ciphertext, groupEncryptedSecretKey, groupEncryptedKey, privateKeyArmored, passphrase string) (string, error) {
	if strings.TrimSpace(groupEncryptedKey) == "" {
		return "", ErrNoGroupKey
	}
	groupKeyHex, err := DecryptOpenPGP(groupEncryptedKey, privateKeyArmored, passphrase)
	if err != nil {
		return "", fmt.Errorf("decrypt group key: %w", err)
	}
	secretKeyHex, err := AESGCMDecrypt(groupEncryptedSecretKey, strings.TrimSpace(groupKeyHex))
	if err != nil {
		return "", fmt.Errorf("decrypt secret key: %w", err)
	}
	return AESGCMDecrypt(ciphertext, strings.TrimSpace(secretKeyHex))
}

// EncryptGroupSecret to odwrotność DecryptGroupSecret — używane przy
// tworzeniu/edycji sekretu (dziś: tylko przez terraform provider, web UI
// robi to samo po stronie JS w extension/src/groupkey.js:encryptWithGroupKey).
// groupEncryptedKey to WŁASNY wpis group_keys wywołującego (z
// GET /g/{groupID}/my-group-key) — funkcja generuje NOWY losowy klucz
// sekretu przy każdym wywołaniu (spójne z tym co robi web UI), nie reużywa
// istniejącego, nawet przy edycji.
func EncryptGroupSecret(plaintext, groupEncryptedKey, privateKeyArmored, passphrase string) (ciphertext, groupEncryptedSecretKey string, err error) {
	if strings.TrimSpace(groupEncryptedKey) == "" {
		return "", "", ErrNoGroupKey
	}
	groupKeyHex, err := DecryptOpenPGP(groupEncryptedKey, privateKeyArmored, passphrase)
	if err != nil {
		return "", "", fmt.Errorf("decrypt group key: %w", err)
	}
	groupKeyHex = strings.TrimSpace(groupKeyHex)

	secretKeyBytes := make([]byte, 32)
	if _, err := rand.Read(secretKeyBytes); err != nil {
		return "", "", fmt.Errorf("generate secret key: %w", err)
	}
	secretKeyHex := hex.EncodeToString(secretKeyBytes)

	ciphertext, err = AESGCMEncrypt(plaintext, secretKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("encrypt content: %w", err)
	}
	groupEncryptedSecretKey, err = AESGCMEncrypt(secretKeyHex, groupKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("encrypt secret key: %w", err)
	}
	return ciphertext, groupEncryptedSecretKey, nil
}

func DecryptOpenPGP(encryptedMsg, privateKeyArmored, passphrase string) (string, error) {
	block, err := pgparmor.Decode(strings.NewReader(privateKeyArmored))
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}

	cfg := &pgppacket.Config{}
	entities, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return "", fmt.Errorf("read key: %w", err)
	}

	for _, e := range entities {
		if e.PrivateKey != nil && e.PrivateKey.Encrypted {
			if err := e.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
				return "", fmt.Errorf("invalid key passphrase")
			}
		}
		for _, sub := range e.Subkeys {
			if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
				_ = sub.PrivateKey.Decrypt([]byte(passphrase))
			}
		}
	}

	msgBlock, err := pgparmor.Decode(strings.NewReader(encryptedMsg))
	if err != nil {
		return "", fmt.Errorf("parse encrypted message: %w", err)
	}

	md, err := openpgp.ReadMessage(msgBlock.Body, entities, nil, cfg)
	if err != nil {
		return "", fmt.Errorf("decrypt failed — wrong key?: %w", err)
	}

	plain, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", fmt.Errorf("read decrypted message: %w", err)
	}
	return string(plain), nil
}

func AESGCMDecrypt(ciphertextB64, symKeyHex string) (string, error) {
	keyBytes, err := hex.DecodeString(symKeyHex)
	if err != nil {
		return "", fmt.Errorf("hex decode key: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("base64 decode ciphertext: %w", err)
	}
	if len(raw) < 12 {
		return "", fmt.Errorf("ciphertext too short")
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, raw[:12], raw[12:], nil)
	if err != nil {
		return "", fmt.Errorf("gcm decrypt: %w", err)
	}
	return string(plaintext), nil
}

// AESGCMEncrypt — base64(nonce(12B) || ciphertext+tag), tożsame z
// extension/src/groupkey.js:aesEncrypt (Web Crypto AES-GCM, 128-bit tag
// domyślnie doklejony przez crypto.subtle.encrypt).
func AESGCMEncrypt(plaintext, symKeyHex string) (string, error) {
	keyBytes, err := hex.DecodeString(symKeyHex)
	if err != nil {
		return "", fmt.Errorf("hex decode key: %w", err)
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	combined := append(nonce, sealed...)
	return base64.StdEncoding.EncodeToString(combined), nil
}
