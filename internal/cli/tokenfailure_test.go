package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

// TestTokenCommandsRefuseAMissingDevice runs every token command against a
// path that does not exist, so each fails at luks2.Open.
func TestTokenCommandsRefuseAMissingDevice(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.img")
	cases := []struct {
		name string
		run  func(context.Context, *env, []string) error
		args []string
	}{
		{"show", runTokenShow, []string{missing, "0"}},
		{"export", runTokenExport, []string{missing, "0"}},
		{"import", runTokenImport, []string{"--file", "-", missing, "0"}},
		{"remove", runTokenRemove, []string{missing, "0"}},
		{"free", runTokenFree, []string{missing}},
		{"exists", runTokenExists, []string{missing, "0"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, _, _, _, _ := newTestEnv(bytes.NewBufferString(`{"type":"x","keyslots":[]}`))
			if err := c.run(context.Background(), e, c.args); err == nil {
				t.Fatalf("token %s: want an error for a device that does not exist", c.name)
			}
		})
	}
}

// TestTokenCommandsRefuseABadTokenID covers the id argument of each command.
func TestTokenCommandsRefuseABadTokenID(t *testing.T) {
	path := newTestVolumeImage(t, "token-bad-id.img")
	cases := []struct {
		name string
		run  func(context.Context, *env, []string) error
		args []string
	}{
		{"show", runTokenShow, []string{path, "x"}},
		{"export", runTokenExport, []string{path, "x"}},
		{"import", runTokenImport, []string{"--file", "-", path, "x"}},
		{"remove", runTokenRemove, []string{path, "x"}},
		{"exists", runTokenExists, []string{path, "x"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
			if err := c.run(context.Background(), e, c.args); err == nil {
				t.Fatalf("token %s: want an error for an id that is not a number", c.name)
			}
		})
	}
}

// TestRunTokenImportFailures covers the input side of import: a --file that
// cannot be read, JSON that is not a token, and standard input past the bound.
func TestRunTokenImportFailures(t *testing.T) {
	path := newTestVolumeImage(t, "token-import-fail.img")

	t.Run("unreadable file", func(t *testing.T) {
		e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
		missing := filepath.Join(t.TempDir(), "nope.json")
		if err := runTokenImport(context.Background(), e, []string{"--file", missing, path, "3"}); err == nil {
			t.Fatal("want an error for a --file that does not exist")
		}
	})
	t.Run("not json", func(t *testing.T) {
		e, _, _, _, _ := newTestEnv(bytes.NewBufferString("this is not json"))
		if err := runTokenImport(context.Background(), e, []string{"--file", "-", path, "3"}); err == nil {
			t.Fatal("want an error for JSON that does not parse")
		}
	})
	t.Run("oversized stdin", func(t *testing.T) {
		e, _, _, _, _ := newTestEnv(bytes.NewBuffer(bytes.Repeat([]byte("a"), maxTokenJSONSize+1)))
		if err := runTokenImport(context.Background(), e, []string{"--file", "-", path, "3"}); err == nil {
			t.Fatal("want an error for standard input past the bound")
		}
	})
}

// TestRunTokenExportRefusesAnUncreatableFile points --file into a directory
// that does not exist, for a token that does.
func TestRunTokenExportRefusesAnUncreatableFile(t *testing.T) {
	path := newTestVolumeImage(t, "token-export-fail.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString(`{"type":"test-token","keyslots":[]}`))
	if err := runTokenImport(context.Background(), e, []string{"--file", "-", path, "3"}); err != nil {
		t.Fatalf("runTokenImport: %v", err)
	}
	out := filepath.Join(t.TempDir(), "no-such-dir", "token.json")
	if err := runTokenExport(context.Background(), e, []string{"--file", out, path, "3"}); err == nil {
		t.Fatal("runTokenExport: want an error for a --file in a missing directory")
	}
}
