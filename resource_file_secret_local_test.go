package main

import (
	"bytes"
	"testing"

	"github.com/sharqey/goclient/localvault"
)

// Pełny cykl sharqey_file_secret w local mode, sprawdzany drugim,
// niezależnym Unlock tego samego pliku (to, co zobaczy `sharqey local file get`).
func TestLocalFileSecretLifecycle(t *testing.T) {
	pd, path := newTestLocalProvider(t)

	created, err := localFileCreate(pd, "runner_p12", "runner.p12", []byte("v1"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	sec, data, found, err := localFileRead(pd, created.ID)
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	if sec.Title != "runner_p12" || sec.Filename != "runner.p12" || string(data) != "v1" {
		t.Fatalf("read: got %q/%q/%q", sec.Title, sec.Filename, data)
	}

	if _, err := localFileUpdate(pd, created.ID, "runner_p12_renamed", "runner-new.p12", []byte("v2"), true); err != nil {
		t.Fatalf("update: %v", err)
	}
	other, err := localvault.Unlock(path, "pw")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	sec, data, err = other.ReadFile(created.ID)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if sec.Title != "runner_p12_renamed" || sec.Filename != "runner-new.p12" || !bytes.Equal(data, []byte("v2")) {
		t.Fatalf("after update: got %q/%q/%q", sec.Title, sec.Filename, data)
	}

	// Sama zmiana tytułu nie rusza pliku.
	if _, err := localFileUpdate(pd, created.ID, "only_title", "runner-new.p12", []byte("v2"), false); err != nil {
		t.Fatalf("rename: %v", err)
	}
	sec, data, _, _ = localFileRead(pd, created.ID)
	if sec.Title != "only_title" || string(data) != "v2" {
		t.Fatalf("after rename: got %q/%q", sec.Title, data)
	}

	id, err := localFileIDByTitle(pd, "only_title")
	if err != nil || id != created.ID {
		t.Fatalf("import by title: id=%q err=%v", id, err)
	}

	if err := localFileDelete(pd, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, found, err := localFileRead(pd, created.ID); err != nil || found {
		t.Fatalf("read after delete: found=%v err=%v", found, err)
	}
	// Drugi delete (sekret usunięty poza terraformem) to nie błąd.
	if err := localFileDelete(pd, created.ID); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

func TestLocalFileSecretTitleClashes(t *testing.T) {
	pd, _ := newTestLocalProvider(t)

	a, err := localFileCreate(pd, "a", "a.bin", []byte("a"))
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	if _, err := localFileCreate(pd, "a", "other.bin", []byte("x")); err == nil {
		t.Fatal("create with a duplicate title succeeded")
	}
	if _, err := localFileCreate(pd, "b", "b.bin", []byte("b")); err != nil {
		t.Fatalf("create b: %v", err)
	}
	if _, err := localFileUpdate(pd, a.ID, "b", "a.bin", []byte("a"), false); err == nil {
		t.Fatal("rename onto an existing title succeeded")
	}
}

// sharqey_file_secret nie może przejąć ani zaimportować zwykłego sekretu env.
func TestLocalFileSecretRejectsNonFile(t *testing.T) {
	pd, _ := newTestLocalProvider(t)

	var envID string
	if err := withLocalVault(pd, func(v *localvault.Vault) error {
		s, err := v.AddSecret("env", "token", "", "", "", false, []byte(`{"value":"x"}`))
		envID = s.ID
		return err
	}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	if _, err := localFileIDByTitle(pd, "token"); err == nil {
		t.Fatal("import of an env secret as a file succeeded")
	}
	if _, _, _, err := localFileRead(pd, envID); err == nil {
		t.Fatal("read of an env secret as a file succeeded")
	}
}
