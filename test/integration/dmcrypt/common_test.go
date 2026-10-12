// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package dmcrypt_test

import (
	"context"
	"crypto"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

var runSuite *harness.Suite

func runVolume(t *testing.T, base string) string {
	t.Helper()
	if runSuite == nil {
		t.Fatalf("runVolume(%q): TestMain did not register the suite, so this name would be "+
			"host-global and could collide with a concurrent run.", base)
	}
	name, err := runSuite.VolumeName(base)
	if err != nil {
		t.Fatalf("runVolume(%q): %v", base, err)
	}
	return name
}

// releaseVolume closes volumeName through pkg/dmcrypt.Deactivate and FAILS
// THE TEST if a device-mapper mapping is left behind on the host (#100),
// the same reasoning as every other test/integration/<pkg> package's own
// releaseVolume.
func releaseVolume(t *testing.T, volumeName string) {
	t.Helper()

	const timeout = 10 * time.Second
	var last error
	deadline := time.Now().Add(timeout)
	for {
		if err := dmcrypt.Deactivate(context.Background(), volumeName); err != nil && !errors.Is(err, dmcrypt.ErrNotActive) {
			last = err
		}
		if mappingConfirmedGone(volumeName) {
			return
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("device-mapper mapping %q is STILL PRESENT after %s. Last error from Deactivate: %v", volumeName, timeout, last)
}

func mappingConfirmedGone(volumeName string) bool {
	out, err := exec.Command("dmsetup", "info", volumeName).CombinedOutput()
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "device does not exist")
}

func requireRoot(t *testing.T) {
	t.Helper()
	if uid := os.Getuid(); uid != 0 {
		t.Fatalf("THIS INTEGRATION TEST REQUIRES ROOT -- running as uid %d.", uid)
	}
}

func requireCryptsetupDeclared(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Fatalf("cryptsetup is not installed (%v). This tier DECLARES it.", err)
	}
}

const canonicalPassphrase = "conformance-test-passphrase"

func cryptsetupRun(t *testing.T, stdin string, args ...string) {
	t.Helper()
	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- arguments are test constants and temp paths
	cmd.Stdin = strings.NewReader(stdin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cryptsetup %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// formatWithLibraryCheap formats path through pkg/luks2's own Format with
// canonicalPassphrase, for a fixture that will be mutated and never
// byte-compared.
func formatWithLibraryCheap(t *testing.T, path string) {
	t.Helper()
	ctx := context.Background()
	v, err := luks2.Open(ctx, path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()
	pass, err := enclave.NewMemoryCopy([]byte(canonicalPassphrase))
	if err != nil {
		t.Fatalf("NewMemoryCopy failed: %v", err)
	}
	defer func() { _ = pass.Destroy() }()
	if err := v.Format(ctx, pass, luks2.FormatParams{
		Cipher:     "aes-xts-plain64",
		KeySize:    512,
		Hash:       crypto.SHA512,
		SectorSize: 512,
		KDF:        luks2.KDFParams{Type: luks2.KDFPBKDF2, Hash: crypto.SHA512, Iterations: 210_000},
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
}

// blockNodeRdev reports the device number of the block special file at
// path, the argument internal/dm.IsOurNode needs.
func blockNodeRdev(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Rdev), nil //nolint:unconvert // Rdev is not uint64 on every GOARCH
}

func TestMain(m *testing.M) {
	suite, err := harness.BeginSuite(os.Stderr)
	if err != nil {
		os.Stderr.WriteString("integration suite: " + err.Error() + "\n")
		os.Exit(1)
	}
	runSuite = suite
	os.Exit(suite.Finish(m.Run(), os.Stderr))
}
