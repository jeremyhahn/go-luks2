// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package wipe_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// Unlock, Lock, IsUnlocked and GetMappedDevicePath are the old
// luks2.Unlock/Lock/IsUnlocked/GetMappedDevicePath free functions, forwarded
// across the two packages they collapsed into (#268): pkg/luks2 derives the
// key and pkg/dmcrypt activates it. See cmd/luks2/cli.go's
// DefaultLuksOperations for the same forward.
func Unlock(device string, passphrase []byte, name string) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryCopy(passphrase)
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return err
	}
	defer key.Destroy()

	// Write-ahead (#96, #348): the mapping is in the run ledger before
	// Activate creates it, so a run that dies at any point after -- a
	// timeout, a kill, a container torn down mid-test -- leaves an entry a
	// later run's reaper can attribute and remove. A record failure refuses
	// the activation. A live mapping that does not carry its recorded
	// identity is removed here, because the reaper would leave it.
	var mapping *dmcrypt.Mapping
	err = runSuite.Ledger.ActivateRecordedAhead(runSuite.Remover, device, name, func() error {
		var err error
		mapping, err = dmcrypt.Activate(ctx, v, key, name)
		return err
	})
	if err != nil && mapping != nil {
		_ = dmcrypt.Deactivate(ctx, name)
	}
	return err
}

func Lock(name string) error {
	return dmcrypt.Deactivate(context.Background(), name)
}

func IsUnlocked(name string) bool {
	_, err := dmcrypt.Lookup(context.Background(), name)
	return err == nil
}

func GetMappedDevicePath(name string) (string, error) {
	m, err := dmcrypt.Lookup(context.Background(), name)
	if err != nil {
		return "", err
	}
	return m.Path(), nil
}

// runSuite is the harness suite this process registered; see
// test/integration/luks2/runvolume_test.go for the full reasoning, which
// this package mirrors.
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

// releaseVolume closes volumeName and FAILS THE TEST if a device-mapper
// mapping is left behind on the host (#100). Mirrors
// the releaseVolume of test/integration/filesystem.
func releaseVolume(t *testing.T, volumeName string) {
	t.Helper()

	const timeout = 10 * time.Second
	var last error
	deadline := time.Now().Add(timeout)
	for {
		if err := Lock(volumeName); err != nil && !errors.Is(err, dmcrypt.ErrNotActive) {
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

	t.Errorf("device-mapper mapping %q is STILL PRESENT after %s. Last error from Lock: %v", volumeName, timeout, last)
}

func mappingConfirmedGone(volumeName string) bool {
	out, err := exec.Command("dmsetup", "info", volumeName).CombinedOutput()
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "device does not exist")
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
