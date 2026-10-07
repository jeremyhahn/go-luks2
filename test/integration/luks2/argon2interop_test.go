// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	kdfpkg "github.com/jeremyhahn/go-luks2/internal/kdf"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// Interop against an Argon2 container formatted BELOW this package's create
// floor -- the container a low-memory or embedded device produces, and the
// one cryptsetup makes without complaint. See pkg/luks2's own (now-moved)
// argon2interop_integration_test.go for the full reasoning.

// lowMemoryArgon2KB is below MinArgon2MemoryKB and well above the accept
// floor. cryptsetup formats at this happily.
const lowMemoryArgon2KB = 32768

func cryptsetupOpens(t *testing.T, path, passphrase, stage string) {
	t.Helper()

	cmd := exec.Command("cryptsetup", "luksOpen", "--test-passphrase", path) // #nosec G204 -- path is under t.TempDir()
	cmd.Stdin = strings.NewReader(passphrase)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: cryptsetup cannot open the container: %v\n%s", stage, err, out)
	}
}

func formatLowMemoryArgon2(t *testing.T, name string) string {
	t.Helper()

	path := canonicalImage(t, name)
	cmd := exec.Command("cryptsetup", "luksFormat", // #nosec G204 -- arguments are test constants
		"--type", "luks2",
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--hash", "sha512",
		"--sector-size", "512",
		"--pbkdf", "argon2id",
		"--pbkdf-memory", fmt.Sprint(lowMemoryArgon2KB),
		"--pbkdf-force-iterations", "4",
		"--pbkdf-parallel", "1",
		"--batch-mode",
		path,
	)
	cmd.Stdin = strings.NewReader(canonicalPassphrase)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cryptsetup could not format at %d KB of Argon2 memory: %v\n%s", lowMemoryArgon2KB, err, out)
	}
	return path
}

func TestLowMemoryArgon2ContainerRemainsFullyManageable(t *testing.T) {
	requireCryptsetupDeclared(t)

	path := formatLowMemoryArgon2(t, "lowmem-argon2.img")

	_, metadata, err := harness.ReadHeader(path)
	if err != nil {
		t.Fatalf("this package cannot read a %d KB Argon2 container: %v", lowMemoryArgon2KB, err)
	}
	if got := metadata.Keyslots["0"].KDF.Memory; got == nil || *got != lowMemoryArgon2KB {
		t.Fatalf("fixture memory cost is %v, want %d", got, lowMemoryArgon2KB)
	}
	if lowMemoryArgon2KB >= kdfpkg.MinArgon2MemoryKB {
		t.Fatalf("the fixture's %d KB is not below the create floor of %d; this test measures nothing",
			lowMemoryArgon2KB, kdfpkg.MinArgon2MemoryKB)
	}

	original := []byte(canonicalPassphrase)
	second := []byte("a-second-credential")
	rotated := []byte("the-rotated-credential")

	t.Run("open", func(t *testing.T) {
		if err := harness.TestKey(path, original); err != nil {
			t.Fatalf("TestKey: %v", err)
		}
		cryptsetupOpens(t, path, canonicalPassphrase, "after format")
	})

	t.Run("AddKey inherits the container's low memory cost exactly", func(t *testing.T) {
		opts := &AddKeyOptions{KDFType: "argon2id"}
		info, err := AddKey(path, original, second, opts)
		if err != nil {
			t.Fatalf("AddKey: %v", err)
		}

		if got := info.KDF.MemoryKiB; got != lowMemoryArgon2KB {
			t.Fatalf("reported inherited memory %d, want the container's %d", got, lowMemoryArgon2KB)
		}

		_, metadata, err := harness.ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
		added := newlyAddedSlot(t, path, map[int]bool{0: true})
		kdf := metadata.Keyslots[strconv.Itoa(added)].KDF
		if kdf.Memory == nil || *kdf.Memory != lowMemoryArgon2KB {
			t.Fatalf("the added keyslot has memory %v, want the container's %d preserved exactly",
				kdf.Memory, lowMemoryArgon2KB)
		}
		if *kdf.Memory == kdfpkg.MinArgon2MemoryKB {
			t.Fatal("the added keyslot was clamped to the create floor")
		}
		if *kdf.Memory == 1048576 {
			t.Fatal("the added keyslot took the hardcoded 1 GiB default rather than the container's cost")
		}

		if err := harness.TestKey(path, second); err != nil {
			t.Fatalf("the added credential does not open the volume: %v", err)
		}
		cryptsetupOpens(t, path, string(second), "after AddKey")
	})

	t.Run("ChangeKey preserves the container's low memory cost", func(t *testing.T) {
		if err := changeKeyForTest(path, original, rotated, 0); err != nil {
			t.Fatalf("ChangeKey on a below-floor container: %v", err)
		}

		_, after, err := harness.ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
		if got := after.Keyslots["0"].KDF.Memory; got == nil || *got != lowMemoryArgon2KB {
			t.Fatalf("ChangeKey wrote memory %v; an inherited %d must be preserved", got, lowMemoryArgon2KB)
		}
		if got := after.Keyslots["0"].KDF.Memory; got != nil && *got == kdfpkg.MinArgon2MemoryKB {
			t.Fatal("ChangeKey raised the inherited cost to the create floor")
		}
		if err := harness.TestKey(path, rotated); err != nil {
			t.Fatalf("the rotated credential does not open the volume: %v", err)
		}
		if err := harness.TestKey(path, original); err == nil {
			t.Fatal("the old credential still opens the volume")
		}
		cryptsetupOpens(t, path, string(rotated), "after ChangeKey")

		slots, err := harness.ListKeyslots(path)
		if err != nil {
			t.Fatalf("ListKeyslots: %v", err)
		}
		for _, slot := range slots {
			if slot.ID == 0 && slot.KDF.MemoryKiB != lowMemoryArgon2KB {
				t.Fatalf("ListKeyslots reports slot 0 at %d KiB, want the preserved %d",
					slot.KDF.MemoryKiB, lowMemoryArgon2KB)
			}
		}
	})

	t.Run("RemoveKey", func(t *testing.T) {
		if err := removeKeyForTest(path, rotated, 0); err != nil {
			t.Fatalf("RemoveKey: %v", err)
		}
		if err := harness.TestKey(path, rotated); err == nil {
			t.Fatal("the removed credential still opens the volume")
		}
		cryptsetupOpens(t, path, string(second), "after RemoveKey")
	})

	t.Run("KillSlot", func(t *testing.T) {
		existing := slotIDs(t, path)

		third := []byte("a-third-credential")
		if _, err := AddKey(path, second, third, &AddKeyOptions{
			KDFType:         "pbkdf2",
			Hash:            "sha512",
			PBKDFIterations: canonicalCheapIterations,
		}); err != nil {
			t.Fatalf("AddKey before KillSlot: %v", err)
		}

		target := newlyAddedSlot(t, path, existing)

		if err := killSlotForTest(path, second, target); err != nil {
			t.Fatalf("KillSlot: %v", err)
		}
		if err := harness.TestKey(path, third); err == nil {
			t.Fatal("the killed credential still opens the volume")
		}
		cryptsetupOpens(t, path, string(second), "after KillSlot")
	})
}

func slotIDs(t *testing.T, path string) map[int]bool {
	t.Helper()

	slots, err := harness.ListKeyslots(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}
	ids := make(map[int]bool, len(slots))
	for _, slot := range slots {
		ids[slot.ID] = true
	}
	return ids
}

func newlyAddedSlot(t *testing.T, path string, before map[int]bool) int {
	t.Helper()

	target := -1
	for id := range slotIDs(t, path) {
		if !before[id] {
			if target >= 0 {
				t.Fatalf("more than one keyslot appeared: %d and %d", target, id)
			}
			target = id
		}
	}
	if target < 0 {
		t.Fatal("AddKey did not create a keyslot")
	}
	return target
}

func TestAddKeyInheritsAHealthyContainersArgon2Cost(t *testing.T) {
	requireCryptsetupDeclared(t)

	const chosenMemory = 512000

	path := canonicalImage(t, "chosen-cost.img")
	cmd := exec.Command("cryptsetup", "luksFormat", // #nosec G204 -- arguments are test constants
		"--type", "luks2", "--cipher", "aes-xts-plain64", "--key-size", "512",
		"--hash", "sha512", "--sector-size", "512",
		"--pbkdf", "argon2id",
		"--pbkdf-memory", fmt.Sprint(chosenMemory),
		"--pbkdf-force-iterations", "4",
		"--pbkdf-parallel", "1",
		"--batch-mode", path,
	)
	cmd.Stdin = strings.NewReader(canonicalPassphrase)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cryptsetup luksFormat: %v\n%s", err, out)
	}

	opts := &AddKeyOptions{KDFType: "argon2id"}
	if _, err := AddKey(path, []byte(canonicalPassphrase), []byte("a-recovery-credential"), opts); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	_, metadata, err := harness.ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	for id, keyslot := range metadata.Keyslots {
		if keyslot.KDF.Memory == nil || *keyslot.KDF.Memory != chosenMemory {
			t.Fatalf("keyslot %s has memory %v, want the volume's chosen %d",
				id, keyslot.KDF.Memory, chosenMemory)
		}
	}
	cryptsetupOpens(t, path, "a-recovery-credential", "after AddKey at the volume's chosen cost")
}

func TestCreateFloorStillRefusesACallerChosenWeakArgon2Cost(t *testing.T) {
	requireCryptsetupDeclared(t)

	t.Run("Format", func(t *testing.T) {
		path := canonicalImage(t, "weak-format.img")
		err := Format(FormatOptions{
			Device:       path,
			Passphrase:   []byte(canonicalPassphrase),
			KDFType:      "argon2id",
			Argon2Memory: lowMemoryArgon2KB,
			Argon2Time:   4,
		})
		if !errors.Is(err, luks2.ErrInvalidArgument) {
			t.Fatalf("Format = %v, want ErrInvalidArgon2Memory", err)
		}
	})

	t.Run("AddKey", func(t *testing.T) {
		path := formatLowMemoryArgon2(t, "weak-addkey.img")

		_, before, err := harness.ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}

		_, err = AddKey(path, []byte(canonicalPassphrase), []byte("a-second-credential"), &AddKeyOptions{
			KDFType:      "argon2id",
			Argon2Memory: lowMemoryArgon2KB,
			Argon2Time:   4,
		})
		if !errors.Is(err, luks2.ErrInvalidArgument) {
			t.Fatalf("AddKey = %v, want ErrInvalidArgon2Memory", err)
		}

		_, after, err := harness.ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader after the refusal: %v", err)
		}
		if len(after.Keyslots) != len(before.Keyslots) {
			t.Fatalf("a refused AddKey still changed the keyslot count: %d, was %d",
				len(after.Keyslots), len(before.Keyslots))
		}
		cryptsetupOpens(t, path, canonicalPassphrase, "after a refused AddKey")
	})
}
