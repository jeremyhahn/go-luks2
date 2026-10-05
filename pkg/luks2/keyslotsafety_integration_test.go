// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #249 (Lane A) against the real kernel: a volume cryptsetup wrote with every
// shape the unit tier proves on file images -- a 4 KiB key file, a keyslot key
// size that differs from the volume key's, and an unbound keyslot beside the
// one holding the volume key -- driven on a LOOP DEVICE, where the size comes
// from BLKGETSIZE64 rather than Stat, and opened through device-mapper.
//
// The data written through this package's mapping is read back through
// cryptsetup's own. That is the one check nothing in the unit tier can make:
// a mapping keyed with the wrong key succeeds, and only reading the plaintext
// through a third party's mapping tells.

// cryptsetupRun runs cryptsetup with stdin and fails the test on a non-zero exit.
func cryptsetupRun(t *testing.T, stdin string, args ...string) {
	t.Helper()

	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- arguments are test constants and temp paths
	cmd.Stdin = strings.NewReader(stdin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cryptsetup %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// waitForNode waits for a mapping's device node to appear.
func waitForNode(t *testing.T, name string) string {
	t.Helper()

	for i := 0; i < 50; i++ {
		if path, err := GetMappedDevicePath(name); err == nil {
			return path
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the mapping %s never appeared", name)
	return ""
}

func TestCryptsetupKeyfileVolumeWithAnUnboundKeyOnARealDevice(t *testing.T) {
	requireRoot(t)
	requireCryptsetupDeclared(t)

	image := canonicalImage(t, "lane-a.img")
	keyFile := make([]byte, 4096)
	if _, err := rand.Read(keyFile); err != nil {
		t.Fatalf("rand: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, keyFile, 0o600); err != nil {
		t.Fatalf("write the key file: %v", err)
	}

	cheap := []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--batch-mode"}
	cryptsetupRun(t, "", append([]string{"luksFormat", "--type", "luks2", "--key-file", keyPath,
		"--key-size", "512", "--keyslot-cipher", "aes-xts-plain64", "--keyslot-key-size", "256"}, append(cheap, image)...)...)
	cryptsetupRun(t, "unbound-key-passphrase", append([]string{"luksAddKey", "--unbound", "--key-size", "512"}, append(cheap, image)...)...)

	loop, err := SetupLoopDevice(image)
	if err != nil {
		t.Fatalf("SetupLoopDevice: %v", err)
	}
	defer func() { _ = DetachLoopDevice(loop) }()

	// A1, on a block device: the unbound keyslot is not a survivor.
	if err := KillKeyslot(loop, 0); !errors.Is(err, ErrLastKeyslot) {
		t.Fatalf("KillKeyslot(0) beside only an unbound keyslot returned %v, want ErrLastKeyslot", err)
	}
	if err := TestKey(loop, []byte("unbound-key-passphrase")); !errors.Is(err, ErrMasterKeyVerification) {
		t.Fatalf("the unbound passphrase tested as opening the volume: %v", err)
	}

	// A6 and A7: the 4 KiB key file opens a keyslot whose area key is 32 bytes
	// under a 64-byte volume key, and the mapping it makes is the right one.
	ours := runVolume(t, "lane-a-ours")
	defer releaseVolume(t, ours)
	if err := Unlock(loop, keyFile, ours); err != nil {
		t.Fatalf("Unlock with cryptsetup's 4 KiB key file failed: %v", err)
	}
	pattern := bytes.Repeat([]byte("lane-a plaintext "), 4096)
	node := waitForNode(t, ours)
	if err := os.WriteFile(node, pattern, 0o600); err != nil {
		t.Fatalf("write through this package's mapping: %v", err)
	}
	if err := Lock(ours); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	theirs := runVolume(t, "lane-a-theirs")
	defer releaseVolume(t, theirs)
	cryptsetupRun(t, "", "open", "--type", "luks2", "--key-file", keyPath, loop, theirs)
	got := make([]byte, len(pattern))
	f, err := os.Open(waitForNode(t, theirs))
	if err != nil {
		t.Fatalf("open cryptsetup's mapping: %v", err)
	}
	_, err = f.ReadAt(got, 0)
	_ = f.Close()
	if err != nil {
		t.Fatalf("read through cryptsetup's mapping: %v", err)
	}
	if !bytes.Equal(got, pattern) {
		t.Fatal("cryptsetup reads something else through its mapping: this package mapped the volume with the wrong key")
	}
	cryptsetupRun(t, "", "close", theirs)

	// A3 and A10 on the block device: the passphrase change goes through the
	// locked descriptor, is read back before the old area is wiped, and leaves
	// a keyslot cryptsetup opens.
	if err := ChangeKey(loop, keyFile, []byte("rotated-keyslot-passphrase"), 0); err != nil {
		t.Fatalf("ChangeKey from the key file failed: %v", err)
	}
	cryptsetupRun(t, "rotated-keyslot-passphrase", "luksOpen", "--test-passphrase", "--batch-mode", loop)
}
