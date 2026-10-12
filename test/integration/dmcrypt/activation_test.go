// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package dmcrypt_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anatol/devmapper.go"
	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/sys/unix"

	dm "github.com/jeremyhahn/go-luks2/internal/dm"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// Activation's safety properties against the real kernel and cryptsetup
// (#250), moved from pkg/luks2/activation_integration_test.go to
// pkg/dmcrypt's own API (#274, #268): rollback, keyring release, readiness
// and busy handling, and the mapping-name scope. The happy path (Activate /
// Deactivate / Lookup round trip, the already-active refusal, the
// not-active Lookup/Deactivate, the CheckKeyring preflight) is
// pkg/dmcrypt/activate_integration_test.go's own, in-package suite; this
// file covers what that one does not: adversarial real-kernel scenarios
// that need the black-box fixtures (runVolume, cryptsetup) this tier's
// sibling packages share.

func activationImage(t *testing.T, name string, sizeMiB int, fill []byte) string {
	t.Helper()

	image := filepath.Join(t.TempDir(), name)
	f, err := os.Create(image) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatalf("creating %s failed: %v", image, err)
	}
	if err := f.Truncate(int64(sizeMiB) << 20); err != nil {
		t.Fatalf("sizing %s failed: %v", image, err)
	}
	if fill != nil {
		if _, err := f.WriteAt(fill, 0); err != nil {
			t.Fatalf("filling %s failed: %v", image, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing %s failed: %v", image, err)
	}
	return image
}

func attachLoop(t *testing.T, image string) string {
	t.Helper()
	loopDev, err := harness.SetupLoopDevice(image)
	if err != nil {
		t.Fatalf("attaching %s failed: %v", image, err)
	}
	t.Cleanup(func() { _ = harness.DetachLoopDevice(loopDev) })
	return loopDev
}

func activationLoop(t *testing.T, name string, sizeMiB int, fill []byte) (loopDev, image string) {
	t.Helper()
	image = activationImage(t, name, sizeMiB, fill)
	return attachLoop(t, image), image
}

func libraryVolumeLoop(t *testing.T, name string) string {
	t.Helper()
	image := activationImage(t, name, 64, nil)
	formatWithLibraryCheap(t, image)
	return attachLoop(t, image)
}

func deviceDigest(t *testing.T, device string, n int64) [32]byte {
	t.Helper()
	f, err := os.Open(device) // #nosec G304 -- a loop device this test attached
	if err != nil {
		t.Fatalf("opening %s failed: %v", device, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.CopyN(h, f, n); err != nil {
		t.Fatalf("reading %s failed: %v", device, err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// openAndUnlock opens device and derives its master key with passphrase,
// the half of the old luks2.Unlock that stayed in pkg/luks2 (#268).
func openAndUnlock(t *testing.T, device string, passphrase []byte) (*luks2.Volume, *luks2.Key) {
	t.Helper()

	v, err := luks2.Open(context.Background(), device)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		t.Fatalf("could not hold the passphrase in protected memory: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	t.Cleanup(key.Destroy)

	return v, key
}

// activateRecorded is dmcrypt.Activate with the mapping recorded in the run
// ledger before it is created (#96, #348), so a run that dies at any point
// after still leaves an entry a later run's reaper can remove. A record failure
// refuses the activation; a mapping live under an identity other than the
// recorded one is deactivated rather than left unattributable.
func activateRecorded(v *luks2.Volume, key *luks2.Key, name string) error {
	ctx := context.Background()
	var mapping *dmcrypt.Mapping
	err := runSuite.Ledger.ActivateRecordedAhead(runSuite.Remover, v.Path(), name, func() error {
		var err error
		mapping, err = dmcrypt.Activate(ctx, v, key, name)
		return err
	})
	if err != nil && mapping != nil {
		_ = dmcrypt.Deactivate(ctx, name)
	}
	return err
}

// mappedPath resolves name's mapping to its device-mapper path, the old
// luks2.GetMappedDevicePath (#268), now pkg/dmcrypt.Lookup plus
// Mapping.Path.
func mappedPath(t *testing.T, name string) (string, error) {
	t.Helper()
	m, err := dmcrypt.Lookup(context.Background(), name)
	if err != nil {
		return "", err
	}
	return m.Path(), nil
}

func isActive(name string) bool {
	_, err := dmcrypt.Lookup(context.Background(), name)
	return err == nil
}

func TestMappingNameTraversalIsRefusedOnTheRealKernel(t *testing.T) {
	requireRoot(t)

	pattern := bytes.Repeat([]byte("raw-disk-must-survive "), 1<<14)
	loopDev, _ := activationLoop(t, "traversal-victim.img", 16, pattern)
	before := deviceDigest(t, loopDev, 16<<20)

	name := "../" + filepath.Base(loopDev)
	if fi, err := os.Stat(filepath.Join("/dev/mapper", name)); err != nil || fi.Mode()&os.ModeDevice == 0 {
		t.Fatalf("fixture: /dev/mapper/%s does not reach the raw device (%v), so this test proves nothing", name, err)
	}

	if isActive(name) {
		t.Errorf("Lookup(%q) reports a live mapping", name)
	}
	if path, err := mappedPath(t, name); !errors.Is(err, dmcrypt.ErrInvalidName) {
		t.Errorf("Lookup(%q) = %q, %v; want ErrInvalidName", name, path, err)
	}
	if err := harness.MakeFilesystem(name, "ext4", "pwned"); !errors.Is(err, dmcrypt.ErrInvalidName) {
		t.Errorf("MakeFilesystem(%q) = %v; want ErrInvalidName", name, err)
	}
	mountPoint := t.TempDir()
	if err := harness.Mount(harness.MountOptions{Device: name, MountPoint: mountPoint, FSType: "ext4"}); !errors.Is(err, dmcrypt.ErrInvalidName) {
		_ = harness.Unmount(mountPoint, 0)
		t.Errorf("Mount(%q) = %v; want ErrInvalidName", name, err)
	}
	if _, err := harness.IsMappingMounted(name); !errors.Is(err, dmcrypt.ErrInvalidName) {
		t.Errorf("IsMappingMounted(%q) = %v; want ErrInvalidName", name, err)
	}
	if _, err := dmcrypt.Activate(context.Background(), nil, nil, name); !errors.Is(err, dmcrypt.ErrInvalidName) {
		t.Errorf("Activate(%q) = %v; want ErrInvalidName", name, err)
	}

	if deviceDigest(t, loopDev, 16<<20) != before {
		t.Fatal("the raw device behind /dev/mapper/" + name + " was modified")
	}
}

func writeThroughMapping(t *testing.T, name string, data []byte) {
	t.Helper()
	path, err := mappedPath(t, name)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- the mapping this test opened
	if err != nil {
		t.Fatalf("opening %s failed: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(data, 0); err != nil {
		t.Fatalf("writing through %s failed: %v", path, err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("syncing %s failed: %v", path, err)
	}
}

func readThroughMapping(t *testing.T, name string, n int) []byte {
	t.Helper()
	path, err := mappedPath(t, name)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	f, err := os.Open(path) // #nosec G304 -- the mapping this test opened
	if err != nil {
		t.Fatalf("opening %s failed: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, 0); err != nil {
		t.Fatalf("reading through %s failed: %v", path, err)
	}
	return buf
}

// TestConcurrentActivatesLeaveTheWinnersMappingIntact is
// TestConcurrentUnlocksLeaveTheWinnersMappingIntact (now Activate's own
// race, since activation -- not key derivation -- is what device-mapper's
// create ioctl makes exclusive).
func TestConcurrentActivatesLeaveTheWinnersMappingIntact(t *testing.T) {
	requireRoot(t)

	loopDev := libraryVolumeLoop(t, "race.img")
	v, key := openAndUnlock(t, loopDev, []byte(canonicalPassphrase))

	name := runVolume(t, "race")
	defer releaseVolume(t, name)

	marker := []byte("written-through-the-winners-mapping")
	if err := activateRecorded(v, key, name); err != nil {
		t.Fatalf("the setup activation failed: %v", err)
	}
	writeThroughMapping(t, name, marker)
	if err := dmcrypt.Deactivate(context.Background(), name); err != nil {
		t.Fatal(err)
	}

	const rounds = 15
	for round := range rounds {
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, 2)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = activateRecorded(v, key, name)
			}()
		}
		close(start)
		wg.Wait()

		winners := 0
		for _, err := range errs {
			switch {
			case err == nil:
				winners++
			case errors.Is(err, dmcrypt.ErrActive), errors.Is(err, dmcrypt.ErrKeyringEntryExists):
			default:
				t.Fatalf("round %d: a loser failed with an untyped or wrong error: %v", round, err)
			}
			if errors.Is(err, dmcrypt.ErrStillLive) {
				t.Fatalf("round %d: a loser claims a mapping of its own: %v", round, err)
			}
		}
		if winners != 1 {
			t.Fatalf("round %d: %d activations succeeded, want exactly 1 (errors %v)", round, winners, errs)
		}
		if !isActive(name) {
			t.Fatalf("round %d: the winner's mapping is gone after the loser returned", round)
		}
		if got := readThroughMapping(t, name, len(marker)); !bytes.Equal(got, marker) {
			t.Fatalf("round %d: the surviving mapping does not decrypt the volume: read %q", round, got)
		}
		if err := dmcrypt.Deactivate(context.Background(), name); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
}

func TestActivateUnderTheLongestValidNameOnTheRealKernel(t *testing.T) {
	overhead := len(runVolume(t, "x")) - 1
	name := runVolume(t, strings.Repeat("l", dmcrypt.MaxNameLength-overhead))
	if len(name) != dmcrypt.MaxNameLength {
		t.Fatalf("fixture: the name is %d bytes, want %d", len(name), dmcrypt.MaxNameLength)
	}
	loopDev := libraryVolumeLoop(t, "long-name.img")
	v, key := openAndUnlock(t, loopDev, []byte(canonicalPassphrase))

	defer releaseVolume(t, name)
	if err := activateRecorded(v, key, name); err != nil {
		t.Fatalf("Activate under a valid %d-byte name failed: %v", len(name), err)
	}
	info, err := devmapper.InfoByName(name)
	if err != nil {
		t.Fatalf("dm lookup failed: %v", err)
	}
	const dmUUIDMaxLength = 128
	if len(info.UUID) != dmUUIDMaxLength {
		t.Fatalf("the kernel holds a %d-byte UUID %q, want %d", len(info.UUID), info.UUID, dmUUIDMaxLength)
	}
	if err := dmcrypt.Deactivate(context.Background(), name); err != nil {
		t.Fatalf("Deactivate failed: %v", err)
	}
	if isActive(name) {
		t.Fatal("the mapping is still there after Deactivate")
	}
}

func TestAStaleMapperNodeIsNotTrusted(t *testing.T) {
	requireRoot(t)

	pattern := bytes.Repeat([]byte("stale-node-victim "), 1<<14)
	victim, _ := activationLoop(t, "stale-victim.img", 16, pattern)
	before := deviceDigest(t, victim, 16<<20)

	name := runVolume(t, "stale")
	defer releaseVolume(t, name)
	stale := dm.MapperPath("/dev", name)
	if err := os.MkdirAll(dm.MapperDir("/dev"), 0o750); err != nil {
		t.Fatalf("creating %s failed: %v", dm.MapperDir("/dev"), err)
	}
	if err := os.Symlink(victim, stale); err != nil {
		t.Fatalf("planting the stale node failed: %v", err)
	}
	defer func() {
		if target, err := os.Readlink(stale); err == nil && target == victim {
			_ = os.Remove(stale)
		}
	}()

	if isActive(name) {
		t.Error("Lookup trusted the stale node")
	}
	if path, err := mappedPath(t, name); !errors.Is(err, dmcrypt.ErrNotActive) {
		t.Errorf("Lookup = %q, %v; want ErrNotActive", path, err)
	}
	if err := harness.MakeFilesystem(name, "ext4", "pwned"); !errors.Is(err, dmcrypt.ErrNotActive) {
		t.Errorf("MakeFilesystem = %v; want ErrNotActive", err)
	}
	if deviceDigest(t, victim, 16<<20) != before {
		t.Fatal("the device behind the stale node was modified")
	}

	loopDev := libraryVolumeLoop(t, "stale-volume.img")
	v, key := openAndUnlock(t, loopDev, []byte(canonicalPassphrase))

	if err := activateRecorded(v, key, name); err != nil {
		t.Fatalf("Activate under a name with a stale node failed: %v", err)
	}
	info, err := devmapper.InfoByName(name)
	if err != nil {
		t.Fatalf("dm lookup failed: %v", err)
	}
	path, err := mappedPath(t, name)
	if err != nil {
		t.Fatalf("Lookup after the activation failed: %v", err)
	}
	if !dm.IsOurNode(blockNodeRdev, path, info) || !dm.IsOurNode(blockNodeRdev, stale, info) {
		t.Fatalf("after the activation, %s / %s do not name the mapping", path, stale)
	}
	if deviceDigest(t, victim, 16<<20) != before {
		t.Fatal("the device behind the stale node was modified")
	}
}

func TestAnInterruptedCryptsetupReencryptIsRefusedForActivation(t *testing.T) {
	requireRoot(t)
	requireCryptsetupDeclared(t)

	const passphrase = "reencrypt-interrupted"
	loopDev, _ := activationLoop(t, "reencrypt.img", 96, nil)
	cryptsetupRun(t, passphrase, "luksFormat", "--type", "luks2", "--batch-mode",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-", loopDev)

	cmd := exec.Command("cryptsetup", "reencrypt", "--batch-mode", // #nosec G204 -- test constants and a test-owned loop device
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
		"--resilience", "journal", "--hotzone-size", "64k", "--key-file", "-", loopDev)
	cmd.Stdin = strings.NewReader(passphrase)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting cryptsetup reencrypt failed: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	var midway bool
	for range 2000 {
		if _, metadata, err := harness.ReadHeader(loopDev); err == nil &&
			metadata.Config.Requirements != nil && len(metadata.Segments) > 1 {
			midway = true
			break
		}
		select {
		case err := <-exited:
			t.Fatalf("cryptsetup reencrypt finished (%v) before it could be interrupted:\n%s", err, output.String())
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := cmd.Process.Signal(unix.SIGKILL); err != nil {
		t.Fatalf("killing cryptsetup failed: %v", err)
	}
	<-exited
	if !midway {
		t.Fatalf("the header never showed the reencryption under way:\n%s", output.String())
	}

	// The kill can land mid-way through cryptsetup rewriting the primary
	// copy, so read the copy cryptsetup itself would use.
	_, metadata, err := harness.ReadCurrentHeader(loopDev)
	if err != nil {
		t.Fatalf("ReadCurrentHeader after the interruption failed: %v", err)
	}
	if metadata.Config.Requirements == nil || len(metadata.Config.Requirements.Mandatory) == 0 ||
		metadata.Config.Requirements.Mandatory[0] != "online-reencrypt-v2" {
		t.Fatalf("the interrupted container declares %+v, want online-reencrypt-v2", metadata.Config.Requirements)
	}
	if len(metadata.Segments) < 2 {
		t.Fatalf("the interrupted container has %d segment(s); it is not mid-reencryption", len(metadata.Segments))
	}

	name := runVolume(t, "reencrypt")
	defer releaseVolume(t, name)

	v, err := luks2.Open(context.Background(), loopDev)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()
	pass, err := enclave.NewMemoryEnclaveCopy([]byte(passphrase))
	if err != nil {
		t.Fatalf("could not hold the passphrase in protected memory: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	_, err = v.Unlock(context.Background(), pass)
	if !errors.Is(err, luks2.ErrUnsupportedRequirement) {
		t.Fatalf("Unlock = %v, want ErrUnsupportedRequirement for a container mid-reencryption", err)
	}
	if isActive(name) {
		t.Fatal("a mapping exists after the refused unlock")
	}
}

func TestAnUnboundCryptsetupKeyslotDoesNotActivate(t *testing.T) {
	requireRoot(t)
	requireCryptsetupDeclared(t)

	const passphrase = "bound-passphrase-1"
	const unbound = "unbound-passphrase-1"
	loopDev, _ := activationLoop(t, "unbound.img", 32, nil)
	cryptsetupRun(t, passphrase, "luksFormat", "--type", "luks2", "--batch-mode",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-", loopDev)
	keyFile := filepath.Join(t.TempDir(), "unbound.key")
	if err := os.WriteFile(keyFile, []byte(unbound), 0o600); err != nil {
		t.Fatalf("writing the key file failed: %v", err)
	}
	cryptsetupRun(t, "", "luksAddKey", "--batch-mode", "--unbound", "--key-size", "512",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", loopDev, keyFile)

	name := runVolume(t, "unbound")
	defer releaseVolume(t, name)

	v, err := luks2.Open(context.Background(), loopDev)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	unboundPass, err := enclave.NewMemoryEnclaveCopy([]byte(unbound))
	if err != nil {
		t.Fatalf("could not hold the passphrase in protected memory: %v", err)
	}
	defer func() { _ = unboundPass.Destroy() }()
	if _, err := v.Unlock(context.Background(), unboundPass); !errors.Is(err, luks2.ErrWrongKey) {
		t.Fatalf("Unlock with the unbound keyslot's passphrase = %v, want ErrWrongKey", err)
	}
	if isActive(name) {
		t.Fatal("the unbound key was mapped")
	}

	boundPass, err := enclave.NewMemoryEnclaveCopy([]byte(passphrase))
	if err != nil {
		t.Fatalf("could not hold the passphrase in protected memory: %v", err)
	}
	defer func() { _ = boundPass.Destroy() }()
	key, err := v.Unlock(context.Background(), boundPass)
	if err != nil {
		t.Fatalf("Unlock with the bound passphrase failed: %v", err)
	}
	defer key.Destroy()
	if err := activateRecorded(v, key, name); err != nil {
		t.Fatalf("Activate with the bound passphrase's key failed: %v", err)
	}
}
