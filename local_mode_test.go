package main

import (
	"encoding/base64"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/sharqey/goclient/localvault"
)

func newTestLocalProvider(t *testing.T) (*providerData, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sharqey")
	if _, err := localvault.Create(path, "Test", "pw"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	v, err := localvault.Unlock(path, "pw")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return &providerData{mode: modeLocal, local: &localModeData{vault: v, mu: &sync.Mutex{}}}, path
}

// TestWithLocalVaultSerializesConcurrentWrites is the test for the
// correctness-critical claim in localModeData's doc comment (provider.go):
// without pd.local.mu serializing every check-then-write, concurrent Create
// calls against the same file (exactly what Terraform's default
// -parallelism=10 produces for multiple sharqey_secret resources) could lose
// writes or duplicate titles. Every one of n concurrent creates must survive.
func TestWithLocalVaultSerializesConcurrentWrites(t *testing.T) {
	pd, path := newTestLocalProvider(t)

	const n = 30
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			title := "secret-" + strconv.Itoa(i)
			errs <- withLocalVault(pd, func(v *localvault.Vault) error {
				_, err := v.AddSecret("env", title, "", "", "", false, []byte(`{"value":"x"}`))
				return err
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("withLocalVault: %v", err)
		}
	}

	final, err := localvault.Unlock(path, "pw")
	if err != nil {
		t.Fatalf("Unlock (final): %v", err)
	}
	secrets, err := final.ListSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != n {
		t.Fatalf("expected %d secrets after %d concurrent creates, got %d — writes were lost", n, n, len(secrets))
	}
}

// TestWithLocalVaultSeesExternalWrites — a file secret added by another
// process (`sharqey local file put`) after Configure must be visible, and
// the vault's groups must survive a write from the provider (the old
// provider-private copy of the format dropped groups/group_id on save).
func TestWithLocalVaultSeesExternalWrites(t *testing.T) {
	pd, path := newTestLocalProvider(t)

	other, err := localvault.Unlock(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	g, err := other.CreateGroup("ios", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.AddFile("runner.p12", g.ID, "runner.p12", []byte("cert")); err != nil {
		t.Fatal(err)
	}

	var data []byte
	err = withLocalVault(pd, func(v *localvault.Vault) error {
		s, ok, err := findLocalByTitle(v, "runner.p12", "")
		if err != nil || !ok {
			t.Fatalf("findLocalByTitle = %v, %v", ok, err)
		}
		_, data, err = v.ReadFile(s.ID)
		if err != nil {
			return err
		}
		_, err = v.AddSecret("env", "P12_PASSWORD", "", "", "", false, []byte(`{"value":"x"}`))
		return err
	})
	if err != nil {
		t.Fatalf("withLocalVault: %v", err)
	}
	if base64.StdEncoding.EncodeToString(data) != base64.StdEncoding.EncodeToString([]byte("cert")) {
		t.Fatalf("file content = %q", data)
	}
	check, _ := localvault.Unlock(path, "pw")
	if groups := check.ListGroups(); len(groups) != 1 {
		t.Fatalf("groups after provider write: %+v", groups)
	}
}

func TestFindLocalByTitleRejectsDuplicates(t *testing.T) {
	pd, _ := newTestLocalProvider(t)
	for i := 0; i < 2; i++ {
		if _, err := pd.local.vault.AddSecret("env", "Dup", "", "", "", false, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := findLocalByTitle(pd.local.vault, "Dup", ""); err == nil {
		t.Fatal("expected duplicate-title error")
	}
}

func TestCheckLocalDatabaseExistsPointsToCLI(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.sharqey")
	diags := checkLocalDatabaseExists(missing)
	if !diags.HasError() {
		t.Fatal("expected an error for a missing database file")
	}
	if d := diags[0].Detail(); !strings.Contains(d, "sharqey local create --file "+missing) {
		t.Errorf("detail should point to `sharqey local create`, got: %s", d)
	}

	_, existing := newTestLocalProvider(t)
	if diags := checkLocalDatabaseExists(existing); diags.HasError() {
		t.Errorf("unexpected error for an existing file: %v", diags)
	}
}
