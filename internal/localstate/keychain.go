package localstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/99designs/keyring"
)

// KeychainEntry — kształt DOKŁADNIE taki jak `entries` w payloadzie, który
// extension/background.js:handleConfirmLinkRequest wysyła przez device-link
// (camelCase, nie snake_case! — to jest zwykły JS, nie wire format
// zaprojektowany pod Go). Były tu kiedyś tagi snake_case (`org_id` itp.) —
// json.Unmarshal cicho zostawiał wszystkie pola na zero-value zamiast
// błędu, więc `sharqey login` "działał" (bez errora), ale zapisywał
// puste org_id I pusty klucz prywatny; nic tego nie łapało bo istniejący
// test (TestGenerateEphemeralKeypairRoundTrip) sprawdzał tylko roundtrip
// PGP-armora, nie unmarshal do tej struktury. IsPersonal nie istnieje w
// ogóle w payloadzie rozszerzenia (CLAUDE.md: brak "Personal workspace"
// od tasks/016) — nigdy nie było go czym wypełnić.
type KeychainEntry struct {
	OrgID             string `json:"orgId"`
	OrgName           string `json:"orgName"`
	PublicKeyArmored  string `json:"publicKeyArmored"`
	PrivateKeyArmored string `json:"privateKeyArmored"`
}

type KeychainFile struct {
	Version int             `json:"version"`
	Entries []KeychainEntry `json:"entries"`
}

const keychainRingKey = "keychain"

// terminalPromptRejectEmpty — jak keyring.TerminalPrompt, ale re-pyta na
// pustą odpowiedź zamiast cicho zaszyfrować/odblokować FileBackend pustym
// hasłem. Skopiowane 2026-09-06 z password-manager/pkg/localstate razem z
// resztą tego pliku — patrz jego komentarz przy tej samej funkcji.
func terminalPromptRejectEmpty(prompt string) (string, error) {
	for {
		pwd, err := keyring.TerminalPrompt(prompt)
		if err != nil {
			return "", err
		}
		if pwd != "" {
			return pwd, nil
		}
		fmt.Println("Passphrase cannot be empty — this protects the local file at rest.")
	}
}

// openKeyring — natywny secret store per platforma (macOS Keychain, Windows
// Credential Manager, Linux Secret Service/kwallet), z fallbackiem do
// zaszyfrowanego pliku tam gdzie nic z tego nie ma — ważne dla headless
// CI/serwerów bez sesji desktopowej (tasks/todo/026). SHARQEY_CLI_KEYRING_BACKEND
// wymusza konkretny backend (np. "file") zamiast auto-detekcji — używane w
// testach (żeby nie dotykać prawdziwego OS keychaina) i dostępne też dla CI.
func openKeyring() (keyring.Keyring, error) {
	cfg := keyring.Config{
		ServiceName: "sharqey-cli",
		// KeychainName celowo puste — bez tego 99designs/keyring na macOS
		// tworzy NOWY, osobny plik pęku kluczy (wymaga ustawienia mu
		// własnego hasła przy pierwszym użyciu). Pusta wartość = domyślny
		// pęk "login" usera, już odblokowany sesją — macOS zapyta tylko o
		// zgodę dostępu dla tej binarki ("Zawsze zezwalaj"), bez tworzenia
		// nowego hasła.
		FileDir:          filepath.Join(filepath.Dir(ConfigPath()), "keyring"),
		FilePasswordFunc: terminalPromptRejectEmpty,
		// Bez tego macOS Keychain backend ustawia puste TrustedApplications
		// (nie nil!) na zapisywanym itemie, co w Security frameworku znaczy
		// "żadna aplikacja, łącznie z tą która zapisała, nie jest zaufana" —
		// KAŻDY dostęp (także odczyt przez TĘ SAMĄ binarkę chwilę później)
		// wymaga osobnej autoryzacji, i po rebuildzie binarki (inny hash =
		// inna tożsamość dla ACL) stare entries stają się nieczytelne mimo
		// poprawnego hasła do pęku. true = ufaj wywołującej aplikacji.
		KeychainTrustApplication: true,
	}
	if backend := os.Getenv("SHARQEY_CLI_KEYRING_BACKEND"); backend != "" {
		cfg.AllowedBackends = []keyring.BackendType{keyring.BackendType(backend)}
	}
	if pass := os.Getenv("SHARQEY_CLI_KEYRING_PASSWORD"); pass != "" {
		cfg.FilePasswordFunc = keyring.FixedStringPrompt(pass)
	}
	return keyring.Open(cfg)
}

func LoadKeychain() (KeychainFile, error) {
	kr, err := openKeyring()
	if err != nil {
		return KeychainFile{}, err
	}
	item, err := kr.Get(keychainRingKey)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return KeychainFile{}, nil
		}
		return KeychainFile{}, err
	}
	var kc KeychainFile
	if err := json.Unmarshal(item.Data, &kc); err != nil {
		return KeychainFile{}, err
	}
	return kc, nil
}

func SaveKeychain(kc KeychainFile) error {
	kr, err := openKeyring()
	if err != nil {
		return err
	}
	data, err := json.Marshal(kc)
	if err != nil {
		return err
	}
	return kr.Set(keyring.Item{
		Key:         keychainRingKey,
		Data:        data,
		Label:       "Sharqey CLI keychain",
		Description: "Zawinięte klucze OpenPGP per organizacja (patrz pkg/localstate/keychain.go)",
	})
}

func ForgetKeychain() error {
	kr, err := openKeyring()
	if err != nil {
		return err
	}
	err = kr.Remove(keychainRingKey)
	// Backend-zależne: FileBackend zwraca surowy os.ErrNotExist z os.Remove,
	// inne backendy (macOS Keychain itp.) zwracają keyring.ErrKeyNotFound.
	if errors.Is(err, keyring.ErrKeyNotFound) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
