// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// The tests in this file pin rows of the CLI SPEC (docs/*/cli.md) that no
// other test in the package names.

// assertHeaderIntact fails t unless the LUKS2 header at path still parses:
// a refusal must come before anything is destroyed.
func assertHeaderIntact(t *testing.T, path string) {
	t.Helper()
	v, err := luks2.Open(context.Background(), path, luks2.WithReadOnly())
	if err != nil {
		t.Fatalf("Open after a refused wipe: %v", err)
	}
	defer func() { _ = v.Close() }()
	if _, err := v.Header(context.Background()); err != nil {
		t.Fatalf("Header after a refused wipe: %v, want the header intact", err)
	}
}

// docs/wipe/cli.md: options may come before or after <device>, a relative
// path is resolved against the working directory, and --yes skips the
// question as --batch-mode does.
func TestRunWipeOptionsAfterTheDeviceOnARelativePath(t *testing.T) {
	path := newPlainImage(t, "wipe-relative.img")
	t.Chdir(filepath.Dir(path))
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runWipe(context.Background(), e, []string{filepath.Base(path), "--full", "--yes"}); err != nil {
		t.Fatalf("runWipe <relative device> --full --yes: %v", err)
	}
	if !strings.Contains(stdout.String(), path) {
		t.Errorf("stdout = %q, want the device resolved to %s", stdout.String(), path)
	}
}

// docs/wipe/cli.md: --passes is 1 to 100 and the whole value must be a
// number; anything else is a usage error (exit 1) before anything is wiped.
func TestRunWipeRefusesPassesOutsideOneToAHundred(t *testing.T) {
	for _, passes := range []string{"0", "101", "-1", "2x", " 1", ""} {
		path := newTestVolumeImage(t, "wipe-passes.img")
		e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))

		err := runWipe(context.Background(), e, []string{"--full", "--passes", passes, path})
		var ue *UsageError
		if !errors.As(err, &ue) {
			t.Fatalf("runWipe --passes %q = %v, want a *UsageError", passes, err)
		}
		if got := exitCode(err); got != 1 {
			t.Errorf("runWipe --passes %q: exit %d, want 1", passes, got)
		}
		assertHeaderIntact(t, path)
	}
}

// docs/wipe/cli.md: any answer but YES, end of input or a read error prints
// "Wipe canceled" and exits 1, on both the header-only and the full wipe.
func TestRunWipeCanceledExitsOne(t *testing.T) {
	stdins := map[string]func() *env{
		"other answer": func() *env { e, _, _, _, _ := newTestEnv(bytes.NewBufferString("yes\n")); return e },
		"end of input": func() *env { e, _, _, _, _ := newTestEnv(&bytes.Buffer{}); return e },
		"read error": func() *env {
			e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
			e.stdin = iotest.ErrReader(errors.New("stdin read failed"))
			return e
		},
	}
	for name, newEnv := range stdins {
		for _, mode := range [][]string{nil, {"--full"}} {
			path := newTestVolumeImage(t, "wipe-cancel.img")
			e := newEnv()
			stderr := &bytes.Buffer{}
			e.stderr = stderr

			err := runWipe(context.Background(), e, append(append([]string{}, mode...), path))
			var ce *ConfirmationError
			if !errors.As(err, &ce) {
				t.Fatalf("%s %v: runWipe = %v, want *ConfirmationError", name, mode, err)
			}
			if got := exitCode(err); got != 1 {
				t.Errorf("%s %v: exit %d, want 1", name, mode, got)
			}
			if !strings.Contains(stderr.String(), "Wipe canceled") {
				t.Errorf("%s %v: stderr = %q, want \"Wipe canceled\"", name, mode, stderr.String())
			}
			assertHeaderIntact(t, path)
		}
	}
}

// docs/tokens/cli.md: export --file - writes to standard output; exists
// answers in its exit status (0 present, 1 absent) while other failures keep
// their own; remove deletes the token only, so its keyslot still opens.
func TestRunTokenExportExistsAndRemoveRows(t *testing.T) {
	ctx := context.Background()
	path := newTestVolumeImage(t, "token-rows.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString(`{"type":"user-defined","keyslots":["0"]}`))
	if err := runTokenImport(ctx, e, []string{"--file", "-", path, "0"}); err != nil {
		t.Fatalf("runTokenImport: %v", err)
	}

	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenExport(ctx, e, []string{path, "0", "--file", "-"}); err != nil {
		t.Fatalf("runTokenExport --file -: %v", err)
	}
	if !strings.Contains(stdout.String(), "user-defined") {
		t.Errorf("export --file - stdout = %q, want the token JSON", stdout.String())
	}

	e, _, _, _, _ = newTestEnv(&bytes.Buffer{})
	if got := exitCode(runTokenExists(ctx, e, []string{path, "0"})); got != 0 {
		t.Errorf("exists on a present token: exit %d, want 0", got)
	}
	e, _, _, _, _ = newTestEnv(&bytes.Buffer{})
	if got := exitCode(runTokenExists(ctx, e, []string{path, "5"})); got != 1 {
		t.Errorf("exists on an absent token: exit %d, want 1", got)
	}
	e, _, _, _, _ = newTestEnv(&bytes.Buffer{})
	if got := exitCode(runTokenExists(ctx, e, []string{newPlainImage(t, "not-luks.img"), "0"})); got != 4 {
		t.Errorf("exists on a non-LUKS2 device: exit %d, want 4 (its own status, not absent)", got)
	}

	e, _, _, _, _ = newTestEnv(&bytes.Buffer{})
	if err := runTokenRemove(ctx, e, []string{path, "0"}); err != nil {
		t.Fatalf("runTokenRemove: %v", err)
	}
	e, _, _, _, _ = newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	if err := runTestKey(ctx, e, []string{path}); err != nil {
		t.Errorf("testkey after token remove: %v, want keyslot 0 still to open the volume", err)
	}
}

// docs/filesystems/cli.md: without -t, a mapping on which Detect finds no
// filesystem, more than one signature or a non-filesystem is refused with
// exit 1, and nothing is mounted.
func TestRunMountRefusesAnUndetectedFilesystem(t *testing.T) {
	e, act, mnt, _, _ := newTestEnv(&bytes.Buffer{})
	act.mapping = mapping{name: "myvolume"}
	mnt.detectErr = &filesystem.Error{Kind: filesystem.ErrNotDetected, Detail: "no signature"}

	err := runMount(context.Background(), e, []string{"myvolume", filepath.Join(t.TempDir(), "mnt")})
	if !errors.Is(err, filesystem.ErrNotDetected) {
		t.Fatalf("runMount = %v, want ErrNotDetected", err)
	}
	if got := exitCode(err); got != 1 {
		t.Errorf("exit %d, want 1", got)
	}
	if len(mnt.mountCalls) != 0 {
		t.Errorf("mountCalls = %v, want none", mnt.mountCalls)
	}
}
