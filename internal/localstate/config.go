// Package localstate to lokalny stan zostawiony na dysku przez `sharqey
// login` — config.json (server URL + JWT token) i OS keychain (klucze
// prywatne per organizacja). Provider czyta ten sam lokalny stan zamiast
// mieć własny mechanizm login — "provider NIE ma własnego login, tylko
// czyta lokalny stan CLI", wzorem providera AWS czytającego
// ~/.aws/credentials (patrz password-manager/tasks/todo/026).
//
// Skopiowane 2026-09-06 z password-manager/pkg/localstate przy wydzieleniu
// tego repo (password-manager/tasks/todo/062) — świadomie KOPIA, nie import
// współdzielonego modułu. `password-manager/cmd/cli` ma i nadal będzie mieć
// własną kopię tego pakietu (potrzebuje go niezależnie od tego repo). Ten
// pakiet był w monorepo trzymany w `pkg/` (nie `internal/`) dokładnie po to
// żeby ta migracja była czysto mechaniczna (kopiuj + zmień prefiks importu),
// a nie przeprojektowaniem — jeśli oba miejsca kiedyś realnie rozjadą się w
// zachowaniu, dopiero wtedy warto rozważyć wspólny moduł (na wzór
// password-manager-goclient, który pełni tę rolę dla CLI/desktop, ale
// pokrywa inny zakres — device-linking/generic API, nie lokalny stan sesji
// CLI ani service-account secret CRUD).
package localstate

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
	KeyFile   string `json:"key_file"` // ścieżka do private_key.asc (legacy TUI flow)
}

func ConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sharqey", "config.json")
}

func LoadConfig() Config {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return Config{ServerURL: "http://localhost:8080"}
	}
	var cfg Config
	json.Unmarshal(data, &cfg)
	if cfg.ServerURL == "" {
		cfg.ServerURL = "http://localhost:8080"
	}
	return cfg
}

func SaveConfig(cfg Config) {
	os.MkdirAll(filepath.Dir(ConfigPath()), 0700)
	data, _ := json.Marshal(cfg)
	os.WriteFile(ConfigPath(), data, 0600)
}
