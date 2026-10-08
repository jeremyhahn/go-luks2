// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func TestRunTestKeyAcceptsTheRightPassphrase(t *testing.T) {
	path := newTestVolumeImage(t, "testkey.img")
	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))

	if err := runTestKey(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runTestKey: %v", err)
	}
	if !strings.Contains(stdout.String(), "opens") {
		t.Errorf("stdout = %q, want it to report success", stdout.String())
	}
}

func TestRunTestKeyRefusesTheWrongPassphrase(t *testing.T) {
	path := newTestVolumeImage(t, "testkey-wrong.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("not it\n"))

	if err := runTestKey(context.Background(), e, []string{path}); err == nil {
		t.Fatal("runTestKey: want an error for the wrong passphrase")
	}
}

func TestRunTestKeyMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runTestKey(context.Background(), e, nil); err == nil {
		t.Fatal("runTestKey: want a usage error with no arguments")
	}
}

func TestRunKeyslotsListsSlots(t *testing.T) {
	path := newTestVolumeImage(t, "keyslots.img")
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runKeyslots(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runKeyslots: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "Slot") || !strings.Contains(out, "0") {
		t.Errorf("stdout = %q, want a slot table with slot 0", out)
	}
}

func TestRunKeyslotsNoKeyslots(t *testing.T) {
	path := newPlainImage(t, "keyslots-plain.img")
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})

	if err := runKeyslots(context.Background(), e, []string{path}); err == nil {
		t.Fatal("runKeyslots: want an error for a device that is not LUKS2")
	}
}

func TestRunAddKeyAddsSecondPassphrase(t *testing.T) {
	path := newTestVolumeImage(t, "addkey.img")
	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\nsecond-pass\n"))

	if err := runAddKey(context.Background(), e, []string{"--pbkdf", "pbkdf2", "--hash", "sha256", "--iter-time", "10", path}); err != nil {
		t.Fatalf("runAddKey: %v", err)
	}
	if !strings.Contains(stdout.String(), "Passphrase added") {
		t.Errorf("stdout = %q, want confirmation", stdout.String())
	}

	e2, _, _, _, _ := newTestEnv(bytes.NewBufferString("second-pass\n"))
	if err := runTestKey(context.Background(), e2, []string{path}); err != nil {
		t.Fatalf("runTestKey with the new passphrase: %v", err)
	}
}

func TestRunAddKeyRefusesPBKDF2SHA1(t *testing.T) {
	path := newTestVolumeImage(t, "addkey-sha1.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\nsecond-pass\n"))

	err := runAddKey(context.Background(), e, []string{"--pbkdf", "pbkdf2", "--hash", "sha1", path})
	var ue *UsageError
	if !errors.As(err, &ue) {
		t.Fatalf("runAddKey error = %T, want *UsageError", err)
	}
}

func TestRunChangeKeyReplacesPassphrase(t *testing.T) {
	path := newTestVolumeImage(t, "changekey.img")
	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\nreplacement\n"))

	if err := runChangeKey(context.Background(), e, []string{"--pbkdf", "pbkdf2", "--iter-time", "10", path, "0"}); err != nil {
		t.Fatalf("runChangeKey: %v", err)
	}
	if !strings.Contains(stdout.String(), "Keyslot 0") {
		t.Errorf("stdout = %q, want it to name slot 0", stdout.String())
	}

	e2, _, _, _, _ := newTestEnv(bytes.NewBufferString("replacement\n"))
	if err := runTestKey(context.Background(), e2, []string{path}); err != nil {
		t.Fatalf("runTestKey with the replacement passphrase: %v", err)
	}

	e3, _, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	if err := runTestKey(context.Background(), e3, []string{path}); err == nil {
		t.Fatal("runTestKey: want the old passphrase to no longer open the volume")
	}
}

// slotIterations re-reads keyslot slot's PBKDF2 iteration count from path.
func slotIterations(t *testing.T, path string, slot int) int {
	t.Helper()
	v, err := luks2.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = v.Close() }()
	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header: %v", err)
	}
	for _, s := range h.Keyslots() {
		if s.ID == slot {
			return s.KDF.Iterations
		}
	}
	t.Fatalf("keyslot %d not found in %s", slot, path)
	return 0
}

// changekey's KDF options re-cost the slot, as luksChangeKey's do: the count
// --pbkdf-force-iterations names is the count on disk afterwards.
func TestRunChangeKeyForceIterationsRecostsTheSlot(t *testing.T) {
	path := newTestVolumeImage(t, "changekey-recost.img")
	want := 2 * slotIterations(t, path, 0)
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\nreplacement\n"))

	args := []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", strconv.Itoa(want), path, "0"}
	if err := runChangeKey(context.Background(), e, args); err != nil {
		t.Fatalf("runChangeKey: %v", err)
	}
	if got := slotIterations(t, path, 0); got != want {
		t.Errorf("keyslot 0 iterations after changekey = %d, want %d", got, want)
	}
}

func TestRunRemoveKeyRemovesItsOwnSlot(t *testing.T) {
	path := newTwoSlotVolumeImage(t, "removekey.img")

	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString(testSecondPassphrase + "\n"))
	if err := runRemoveKey(context.Background(), e, []string{path, "1"}); err != nil {
		t.Fatalf("runRemoveKey: %v", err)
	}
	if !strings.Contains(stdout.String(), "Keyslot 1 removed") {
		t.Errorf("stdout = %q, want confirmation", stdout.String())
	}

	e2, _, _, _, _ := newTestEnv(bytes.NewBufferString(testSecondPassphrase + "\n"))
	if err := runTestKey(context.Background(), e2, []string{path}); err == nil {
		t.Fatal("runTestKey: want the removed passphrase to no longer open the volume")
	}
}

func TestRunKillSlotRemovesSlotWithAnyPassphrase(t *testing.T) {
	path := newTwoSlotVolumeImage(t, "killslot.img")

	// Authenticate with slot 0's passphrase while killing slot 1.
	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	if err := runKillSlot(context.Background(), e, []string{path, "1"}); err != nil {
		t.Fatalf("runKillSlot: %v", err)
	}
	if !strings.Contains(stdout.String(), "Keyslot 1 removed") {
		t.Errorf("stdout = %q, want confirmation", stdout.String())
	}

	e2, _, _, _, _ := newTestEnv(bytes.NewBufferString(testSecondPassphrase + "\n"))
	if err := runTestKey(context.Background(), e2, []string{path}); err == nil {
		t.Fatal("runTestKey: want the killed passphrase to no longer open the volume")
	}
}

func TestRunChangeKeyMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runChangeKey(context.Background(), e, nil); err == nil {
		t.Fatal("runChangeKey: want a usage error with no arguments")
	}
}

func TestParseKeyslotOutOfRange(t *testing.T) {
	if _, err := parseKeyslot("removekey", "99"); err == nil {
		t.Fatal("parseKeyslot: want an error for an out-of-range slot")
	}
	if _, err := parseKeyslot("removekey", "nope"); err == nil {
		t.Fatal("parseKeyslot: want an error for a non-numeric slot")
	}
}
