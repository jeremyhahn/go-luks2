// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package filesystem_test

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

// Unlock, Lock, IsUnlocked and GetMappedDevicePath forward to pkg/luks2 for the key and pkg/dmcrypt for activation.
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

	// Record the mapping in the run ledger before Activate creates it; a record failure refuses the activation, and a mapping without its recorded identity is removed.
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

func requireRoot(t *testing.T) {
	t.Helper()
	if uid := os.Getuid(); uid != 0 {
		t.Fatalf("THIS INTEGRATION TEST REQUIRES ROOT -- running as uid %d.", uid)
	}
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
