package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/sharqey/goclient/localvault"
)

// checkLocalDatabaseExists — the provider never creates a .sharqey database
// (Configure unlocks it before any resource runs, so a resource can't create
// the file the same provider instance needs). A missing file gets a pointer
// to `sharqey local create` instead of goclient's raw "no such file"
// wrapped in "Failed to unlock". Other stat errors fall through to Unlock,
// which reports them.
func checkLocalDatabaseExists(path string) diag.Diagnostics {
	var diags diag.Diagnostics
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		diags.AddError(
			"Local database file not found",
			fmt.Sprintf("%s does not exist. Terraform does not create .sharqey databases — create it with `sharqey local create --file %s` (or in the desktop app), then re-run terraform.", path, path),
		)
	}
	return diags
}

// withLocalVault serializes ALL local-vault read-modify-write operations
// through pd.local.mu — see the doc comment on localModeData in provider.go
// for why this mutex is load-bearing (Terraform's default -parallelism=10
// means multiple sharqey_secret resources can run Create/Update/Delete
// concurrently against the very same file).
//
// It reloads the file from disk before every call rather than trusting the
// in-memory copy from Configure: within one `terraform apply`, that's the
// only way to see writes made by earlier resources in the same graph and to
// tolerate a file that changed on disk between operations (hand-edit, a
// separate `sharqey` CLI invocation). Mutations (AddSecret/UpdateSecret/
// DeleteSecret) additionally reload right before writing, inside
// goclient/localvault — the mutex here is what makes "check title
// uniqueness, then write" atomic across resources.
func withLocalVault(pd *providerData, fn func(v *localvault.Vault) error) error {
	pd.local.mu.Lock()
	defer pd.local.mu.Unlock()
	if err := pd.local.vault.Reload(); err != nil {
		return fmt.Errorf("read local vault: %w", err)
	}
	return fn(pd.local.vault)
}

// findLocalByTitle returns the secret titled exactly title (case-sensitive),
// found=false if none. Titles must be unique within the vault for this
// provider (a flat vault has no other stable, human-chosen identifier) — more
// than one match is an error rather than a silent pick of "the first one",
// since guessing wrong would read/update/delete the wrong secret. skipID
// excludes one secret (the one being updated).
func findLocalByTitle(v *localvault.Vault, title, skipID string) (s localvault.Secret, found bool, err error) {
	secrets, err := v.ListSecrets()
	if err != nil {
		return localvault.Secret{}, false, err
	}
	count := 0
	for _, cand := range secrets {
		if cand.Title == title && cand.ID != skipID {
			s = cand
			count++
		}
	}
	if count > 1 {
		return localvault.Secret{}, false, fmt.Errorf("%d secrets titled %q in local vault — titles must be unique for this provider to identify a secret", count, title)
	}
	return s, count == 1, nil
}
