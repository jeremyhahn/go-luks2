// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// Interop against an Argon2 container formatted BELOW this package's create
// floor -- the container a low-memory or embedded device produces, and the one
// cryptsetup makes without complaint.
//
// # WHY THIS IS AN END-TO-END TEST AND NOT A VALIDATOR ASSERTION
//
// The question is not "does the validator return nil". It is whether an
// operator holding such a volume can still add, rotate and remove credentials
// with this library, and whether cryptsetup can still open what this library
// wrote. A unit test on the bound answers neither: the bound could be removed
// and the operation still fail three layers down, and a keyslot could be
// written that this package opens and cryptsetup does not. So every step here
// goes through the real API and is then handed back to cryptsetup.

// lowMemoryArgon2KB is below MinArgon2MemoryKB and well above the accept floor
// (minArgon2Memory, 8 KiB). cryptsetup formats at this happily.
const lowMemoryArgon2KB = 32768

// cryptsetupOpens asserts cryptsetup can still open the container with the
// given passphrase. It is the half of the test this package cannot fake: a
// keyslot only we can read is not interop.
func cryptsetupOpens(t *testing.T, path, passphrase, stage string) {
	t.Helper()

	cmd := exec.Command("cryptsetup", "luksOpen", "--test-passphrase", path) // #nosec G204 -- path is under t.TempDir()
	cmd.Stdin = strings.NewReader(passphrase)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: cryptsetup cannot open the container: %v\n%s", stage, err, out)
	}
}

// formatLowMemoryArgon2 produces the fixture with cryptsetup, because this
// package deliberately cannot: Format refuses this memory cost, which is the
// create floor doing its job.
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

// TestLowMemoryArgon2ContainerRemainsFullyManageable is the proof the owner
// asked for: format below the floor with cryptsetup, then drive every mutating
// operation this package offers against it, handing the result back to
// cryptsetup at each step.
func TestLowMemoryArgon2ContainerRemainsFullyManageable(t *testing.T) {
	requireCryptsetupDeclared(t)

	path := formatLowMemoryArgon2(t, "lowmem-argon2.img")

	// The fixture is what it claims to be. Without this the whole test could
	// pass against a container that never had a low memory cost.
	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("this package cannot read a %d KB Argon2 container: %v", lowMemoryArgon2KB, err)
	}
	if got := metadata.Keyslots["0"].KDF.Memory; got == nil || *got != lowMemoryArgon2KB {
		t.Fatalf("fixture memory cost is %v, want %d", got, lowMemoryArgon2KB)
	}
	if lowMemoryArgon2KB >= MinArgon2MemoryKB {
		t.Fatalf("the fixture's %d KB is not below the create floor of %d; this test measures nothing",
			lowMemoryArgon2KB, MinArgon2MemoryKB)
	}

	original := []byte(canonicalPassphrase)
	second := []byte("a-second-credential")
	rotated := []byte("the-rotated-credential")

	t.Run("open", func(t *testing.T) {
		if err := TestKey(path, original); err != nil {
			t.Fatalf("TestKey: %v", err)
		}
		cryptsetupOpens(t, path, canonicalPassphrase, "after format")
	})

	t.Run("AddKey inherits the container's low memory cost exactly", func(t *testing.T) {
		// No Argon2 options: the default path, the one the owner's volume
		// takes, and the one that used to land on a hardcoded 1 GiB.
		//
		// THIS SUBTEST ENCODES THE INVARIANT -- every keyslot in a volume
		// should be derivable by the hardware that owns the volume. Note that
		// the machine running this test has plenty of RAM, which is precisely
		// the situation that makes a clamp dangerous: it would succeed here and
		// write a slot the 32 MiB target could never derive.
		opts := &AddKeyOptions{KDFType: KDFTypeArgon2id}
		if _, err := AddKey(path, original, second, opts); err != nil {
			t.Fatalf("AddKey: %v", err)
		}

		if opts.InheritedArgon2Cost == nil {
			t.Fatal("AddKey did not report inheriting the container's cost")
		}
		if got := opts.InheritedArgon2Cost.Memory; got == nil || *got != lowMemoryArgon2KB {
			t.Fatalf("reported inherited memory %v, want the container's %d", got, lowMemoryArgon2KB)
		}

		_, metadata, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
		added := newlyAddedSlot(t, path, map[int]bool{0: true})
		kdf := metadata.Keyslots[strconv.Itoa(added)].KDF
		if kdf.Memory == nil || *kdf.Memory != lowMemoryArgon2KB {
			t.Fatalf("the added keyslot has memory %v, want the container's %d preserved exactly",
				kdf.Memory, lowMemoryArgon2KB)
		}
		if *kdf.Memory == MinArgon2MemoryKB {
			t.Fatal("the added keyslot was clamped to the create floor; the owning hardware " +
				"could not derive it, and a volume is only as strong as its weakest slot anyway")
		}
		if *kdf.Memory == 1048576 {
			t.Fatal("the added keyslot took the hardcoded 1 GiB default rather than the container's cost")
		}

		if err := TestKey(path, second); err != nil {
			t.Fatalf("the added credential does not open the volume: %v", err)
		}
		cryptsetupOpens(t, path, string(second), "after AddKey")
	})

	t.Run("ChangeKey preserves the container's low memory cost", func(t *testing.T) {
		if err := ChangeKey(path, original, rotated, 0); err != nil {
			t.Fatalf("ChangeKey on a below-floor container: %v", err)
		}

		_, after, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
		// PRESERVED, not raised to the create floor. The container's cost is
		// evidence about the hardware: a volume formatted at 32 MiB was
		// formatted by something that had 32 MiB, and raising it asks that
		// machine for memory it may not have -- the failure being a keyslot
		// that cannot be derived at all, on the only hardware that uses the
		// volume. See ChangeKey for why this is the one place the create floor
		// deliberately does not reach.
		if got := after.Keyslots["0"].KDF.Memory; got == nil || *got != lowMemoryArgon2KB {
			t.Fatalf("ChangeKey wrote memory %v; an inherited %d must be preserved", got, lowMemoryArgon2KB)
		}
		if got := after.Keyslots["0"].KDF.Memory; got != nil && *got == MinArgon2MemoryKB {
			t.Fatal("ChangeKey raised the inherited cost to the create floor; rotation must not " +
				"demand memory the formatting hardware may not have")
		}
		if err := TestKey(path, rotated); err != nil {
			t.Fatalf("the rotated credential does not open the volume: %v", err)
		}
		if err := TestKey(path, original); err == nil {
			t.Fatal("the old credential still opens the volume")
		}
		cryptsetupOpens(t, path, string(rotated), "after ChangeKey")

		// The preserved cost must be OBSERVABLE. ChangeKey has no options
		// struct to report through, so the listing is the surface an operator
		// has; without this the slot sits below the create floor invisibly.
		slots, err := ListKeyslots(path)
		if err != nil {
			t.Fatalf("ListKeyslots: %v", err)
		}
		for _, slot := range slots {
			if slot.ID == 0 && slot.Argon2MemoryKB != lowMemoryArgon2KB {
				t.Fatalf("ListKeyslots reports slot 0 at %d KiB, want the preserved %d",
					slot.Argon2MemoryKB, lowMemoryArgon2KB)
			}
		}
	})

	t.Run("RemoveKey", func(t *testing.T) {
		if err := RemoveKey(path, rotated, 0); err != nil {
			t.Fatalf("RemoveKey: %v", err)
		}
		if err := TestKey(path, rotated); err == nil {
			t.Fatal("the removed credential still opens the volume")
		}
		cryptsetupOpens(t, path, string(second), "after RemoveKey")
	})

	t.Run("KillSlot", func(t *testing.T) {
		// One usable keyslot remains, so killing it is refused by design --
		// that guard is not what this test is about. Add one back, then kill it.
		existing := slotIDs(t, path)

		third := []byte("a-third-credential")
		if _, err := AddKey(path, second, third, &AddKeyOptions{
			KDFType:         KDFTypePBKDF2,
			Hash:            "sha512",
			PBKDFIterations: canonicalCheapIterations,
		}); err != nil {
			t.Fatalf("AddKey before KillSlot: %v", err)
		}

		target := newlyAddedSlot(t, path, existing)

		if err := KillSlot(path, second, target); err != nil {
			t.Fatalf("KillSlot: %v", err)
		}
		if err := TestKey(path, third); err == nil {
			t.Fatal("the killed credential still opens the volume")
		}
		cryptsetupOpens(t, path, string(second), "after KillSlot")
	})
}

// slotIDs returns the keyslot ids currently present.
func slotIDs(t *testing.T, path string) map[int]bool {
	t.Helper()

	slots, err := ListKeyslots(path)
	if err != nil {
		t.Fatalf("ListKeyslots: %v", err)
	}
	ids := make(map[int]bool, len(slots))
	for _, slot := range slots {
		ids[slot.ID] = true
	}
	return ids
}

// newlyAddedSlot returns the one id present now that was not present before.
//
// AddKey chooses the slot, and asking which one it chose by trying the
// passphrase against each would make the test depend on the unlock path it is
// not testing. A set difference asks the question directly.
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

// TestAddKeyInheritsAHealthyContainersArgon2Cost is the owner's actual case:
// a volume formatted at a deliberately chosen cost ABOVE the floor, where
// inheriting must reproduce it exactly rather than clamp or default.
func TestAddKeyInheritsAHealthyContainersArgon2Cost(t *testing.T) {
	requireCryptsetupDeclared(t)

	// 512 MiB, the cost chosen for the owner's vault so it stays openable from
	// a rescue USB. The old behavior wrote 1 GiB here.
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

	opts := &AddKeyOptions{KDFType: KDFTypeArgon2id}
	if _, err := AddKey(path, []byte(canonicalPassphrase), []byte("a-recovery-credential"), opts); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	for id, keyslot := range metadata.Keyslots {
		if keyslot.KDF.Memory == nil || *keyslot.KDF.Memory != chosenMemory {
			t.Fatalf("keyslot %s has memory %v, want the volume's chosen %d -- a keyslot that "+
				"does not match its neighbors is the defect this inherits to avoid",
				id, keyslot.KDF.Memory, chosenMemory)
		}
	}
	cryptsetupOpens(t, path, "a-recovery-credential", "after AddKey at the volume's chosen cost")
}

// TestCreateFloorStillRefusesACallerChosenWeakArgon2Cost is the other half.
// Making the accept side liberal must not have made the CREATE side permissive:
// a cost a caller asks for is still bounded, on both entry points that write a
// keyslot.
func TestCreateFloorStillRefusesACallerChosenWeakArgon2Cost(t *testing.T) {
	requireCryptsetupDeclared(t)

	t.Run("Format", func(t *testing.T) {
		path := canonicalImage(t, "weak-format.img")
		err := Format(FormatOptions{
			Device:       path,
			Passphrase:   []byte(canonicalPassphrase),
			KDFType:      KDFTypeArgon2id,
			Argon2Memory: lowMemoryArgon2KB,
			Argon2Time:   4,
		})
		if !errors.Is(err, ErrInvalidArgon2Memory) {
			t.Fatalf("Format = %v, want ErrInvalidArgon2Memory", err)
		}
	})

	// AddKey is the entry point where this floor did NOT hold: an explicit
	// Argon2Memory of 32 was written, producing a keyslot Format refuses.
	t.Run("AddKey", func(t *testing.T) {
		path := formatLowMemoryArgon2(t, "weak-addkey.img")

		_, before, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}

		_, err = AddKey(path, []byte(canonicalPassphrase), []byte("a-second-credential"), &AddKeyOptions{
			KDFType:      KDFTypeArgon2id,
			Argon2Memory: lowMemoryArgon2KB,
			Argon2Time:   4,
		})
		if !errors.Is(err, ErrInvalidArgon2Memory) {
			t.Fatalf("AddKey = %v, want ErrInvalidArgon2Memory", err)
		}

		_, after, err := ReadHeader(path)
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
