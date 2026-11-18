package main

import (
	"fmt"

	"github.com/sharqey/goclient/localvault"
)

// Tryb local vault dla sharqey_file_secret — ten sam kształt co
// sharqey_secret w local mode: bez "group" (płaski vault), sekret
// identyfikowany po "title" (unikalny w vaulcie, findLocalByTitle), plik
// zapisany inline w .sharqey (format_version 5, goclient/localvault
// AddFile/ReplaceFile/ReadFile — ta sama ścieżka co `sharqey local file
// put/get`). Każda operacja pod withLocalVault (mutex + reload z dysku).

// localFileCreate — nowy sekret-plik; tytuł zajęty = błąd, nie nadpisanie.
func localFileCreate(pd *providerData, title, filename string, data []byte) (localvault.Secret, error) {
	var out localvault.Secret
	err := withLocalVault(pd, func(v *localvault.Vault) error {
		_, exists, err := findLocalByTitle(v, title, "")
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("a secret titled %q already exists in the local vault", title)
		}
		out, err = v.AddFile(title, "", filename, data)
		return err
	})
	return out, err
}

// localFileRead — found=false, gdy sekretu o tym ID już nie ma (Read usuwa
// wtedy resource ze state'u, jak w API mode).
func localFileRead(pd *providerData, id string) (sec localvault.Secret, data []byte, found bool, err error) {
	err = withLocalVault(pd, func(v *localvault.Vault) error {
		s, ok, ferr := v.SecretByID(id)
		if ferr != nil || !ok {
			return ferr
		}
		if s.Type != localvault.TypeFile {
			return fmt.Errorf("secret %q in the local vault is a %q secret, not a file", s.Title, s.Type)
		}
		found = true
		sec, data, ferr = v.ReadFile(id)
		return ferr
	})
	return sec, data, found, err
}

// localFileMeta — jak localFileRead, ale bez odszyfrowania bloba (Read
// potrzebuje tylko tytułu i nazwy pliku z koperty).
func localFileMeta(pd *providerData, id string) (sec localvault.Secret, found bool, err error) {
	err = withLocalVault(pd, func(v *localvault.Vault) error {
		var ferr error
		sec, found, ferr = v.SecretByID(id)
		if ferr != nil || !found {
			return ferr
		}
		if sec.Type != localvault.TypeFile {
			return fmt.Errorf("secret %q in the local vault is a %q secret, not a file", sec.Title, sec.Type)
		}
		return nil
	})
	return sec, found, err
}

// localFileUpdate — zmiana tytułu przez UpdateSecret (plaintext nil = treść
// i blob bez zmian), zmiana pliku/nazwy przez ReplaceFile (nowy file_key).
func localFileUpdate(pd *providerData, id, title, filename string, data []byte, replaceContent bool) (localvault.Secret, error) {
	var out localvault.Secret
	err := withLocalVault(pd, func(v *localvault.Vault) error {
		_, clash, err := findLocalByTitle(v, title, id)
		if err != nil {
			return err
		}
		if clash {
			return fmt.Errorf("a different secret titled %q already exists in the local vault", title)
		}
		existing, ok, err := v.SecretByID(id)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("secret id %q no longer exists in the local vault", id)
		}
		if existing.Title != title {
			if err := v.UpdateSecret(id, title, existing.Username, existing.URL, existing.GroupID, existing.HasTOTP, nil); err != nil {
				return err
			}
		}
		if replaceContent {
			if _, err := v.ReplaceFile(id, filename, data); err != nil {
				return err
			}
		}
		out, _, err = v.ReadFile(id)
		return err
	})
	return out, err
}

// localFileDelete — brak sekretu (już usunięty poza terraformem) to nie błąd.
func localFileDelete(pd *providerData, id string) error {
	return withLocalVault(pd, func(v *localvault.Vault) error {
		_, ok, err := v.SecretByID(id)
		if err != nil || !ok {
			return err
		}
		return v.DeleteSecret(id)
	})
}

// localFileIDByTitle — import w local mode: ID importu to tytuł.
func localFileIDByTitle(pd *providerData, title string) (string, error) {
	var id string
	err := withLocalVault(pd, func(v *localvault.Vault) error {
		s, ok, err := findLocalByTitle(v, title, "")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no secret titled %q in the local vault", title)
		}
		if s.Type != localvault.TypeFile {
			return fmt.Errorf("%q is a %q secret — import it as sharqey_secret", title, s.Type)
		}
		id = s.ID
		return nil
	})
	return id, err
}
