// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// Unlock, Lock, IsUnlocked and GetMappedDevicePath are the old
// luks2.Unlock/Lock/IsUnlocked/GetMappedDevicePath free functions, forwarded
// across the two packages they collapsed into (#268): pkg/luks2 derives the
// key and pkg/dmcrypt activates it. See cmd/luks2/cli.go's
// DefaultLuksOperations for the same forward. volumename_test.go's
// mapping-name audit keys on the bare selector names "Unlock" and "Lock",
// which is why these keep the old capitalization despite being
// package-local.
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

// FormatOptions and Format are the old FormatOptions/luks2.Format
// free-function shape, forwarded onto (*luks2.Volume).Format the same way
// Unlock above forwards onto (*luks2.Volume).Unlock plus dmcrypt.Activate:
// B.6 moved Format behind the Volume, and the on-disk container it writes
// is the same regardless of which shape chose it. Only the KDF spellings
// and cipher fields this package's own fixtures actually pass are
// supported; it is a test fixture builder, not a second implementation of
// the option-resolution rules (*luks2.Volume).Format itself applies.
type FormatOptions struct {
	Device          string
	Passphrase      []byte
	Label           string
	Subsystem       string
	Cipher          string
	CipherMode      string
	KeySize         int
	HashAlgo        string
	SectorSize      int
	KDFType         string
	PBKDFIterTime   int
	PBKDFIterations int
	Argon2Time      int
	Argon2Memory    int
	Argon2Parallel  int
	MetadataSize    int
}

func Format(opts FormatOptions) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, opts.Device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryCopy(opts.Passphrase)
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()

	return v.Format(ctx, pass, formatParamsForTest(opts))
}

// formatParamsForTest converts the old flat FormatOptions shape into
// FormatParams, resolving only the spellings this package's own fixtures
// pass.
func formatParamsForTest(opts FormatOptions) luks2.FormatParams {
	cipher := opts.Cipher
	if cipher != "" {
		mode := opts.CipherMode
		if mode == "" {
			mode = "xts-plain64"
		}
		cipher = cipher + "-" + mode
	}

	var hash crypto.Hash
	switch opts.HashAlgo {
	case "sha512":
		hash = crypto.SHA512
	case "sha256":
		hash = crypto.SHA256
	}

	kdf := luks2.KDFParams{
		IterTime:   time.Duration(opts.PBKDFIterTime) * time.Millisecond,
		Iterations: opts.PBKDFIterations,
		Time:       opts.Argon2Time,
		MemoryKiB:  opts.Argon2Memory,
		Parallel:   opts.Argon2Parallel,
	}
	switch opts.KDFType {
	case "", "pbkdf2":
		// The old HashAlgo named the keyslot's PRF as well as the digest's.
		kdf.Type, kdf.Hash = luks2.KDFPBKDF2, hash
	case "pbkdf2-sha256":
		kdf.Type, kdf.Hash = luks2.KDFPBKDF2, crypto.SHA256
	case "pbkdf2-sha512":
		kdf.Type, kdf.Hash = luks2.KDFPBKDF2, crypto.SHA512
	case string(luks2.KDFArgon2i):
		kdf.Type = luks2.KDFArgon2i
	case string(luks2.KDFArgon2id):
		kdf.Type = luks2.KDFArgon2id
	}

	return luks2.FormatParams{
		Label: opts.Label, Subsystem: opts.Subsystem,
		Cipher: cipher, KeySize: opts.KeySize, Hash: hash,
		SectorSize: opts.SectorSize, MetadataSize: opts.MetadataSize,
		KDF: kdf,
	}
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

// AddKeyOptions and AddKey are the old free-function shape, forwarded onto
// (*luks2.Volume).AddKeyslot the same way Format above forwards onto
// (*luks2.Volume).Format: B.6 moved AddKey behind the Volume and the Key
// type. Every caller here discards the old int-slot return, so AddKey
// returns the new KeyslotInfo instead -- the one caller that used to read
// AddKeyOptions.InheritedArgon2Cost reads KeyslotInfo.KDF directly now; see
// argon2interop_test.go.
type AddKeyOptions struct {
	Keyslot         *int
	KDFType         string
	Hash            string
	Argon2Time      int
	Argon2Memory    int
	Argon2Parallel  int
	PBKDFIterTime   int
	PBKDFIterations int
}

func AddKey(device string, existing, newPassphrase []byte, opts *AddKeyOptions) (luks2.KeyslotInfo, error) {
	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return luks2.KeyslotInfo{}, err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryCopy(existing)
	if err != nil {
		return luks2.KeyslotInfo{}, err
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return luks2.KeyslotInfo{}, err
	}
	defer key.Destroy()

	newCred, err := enclave.NewMemoryCopy(newPassphrase)
	if err != nil {
		return luks2.KeyslotInfo{}, err
	}
	defer func() { _ = newCred.Destroy() }()

	return v.AddKeyslot(ctx, key, newCred, keyslotParamsForTest(opts))
}

// changeKeyForTest unlocks slot with oldPass and replaces its credential
// with newPass, the way the pre-redesign library's
// luks2.ChangeKey(device, oldPass, newPass, slot) did before B.6 moved it
// behind (*luks2.Volume).ChangeKeyslot.
func changeKeyForTest(device string, oldPass, newPass []byte, slot int) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	old, err := enclave.NewMemoryCopy(oldPass)
	if err != nil {
		return err
	}
	defer func() { _ = old.Destroy() }()
	key, err := v.UnlockKeyslot(ctx, slot, old)
	if err != nil {
		return err
	}
	defer key.Destroy()

	newCred, err := enclave.NewMemoryCopy(newPass)
	if err != nil {
		return err
	}
	defer func() { _ = newCred.Destroy() }()

	_, err = v.ChangeKeyslot(ctx, key, newCred, luks2.KeyslotParams{})
	return err
}

// removeKeyForTest unlocks slot with passphrase and removes it, the way
// the pre-redesign library's luks2.RemoveKey(device, passphrase, slot) did
// before B.6 deleted it: credential checks are CLI policy now
// (Unlock/UnlockKeyslot, then RemoveKeyslot).
func removeKeyForTest(device string, passphrase []byte, slot int) error {
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
	key, err := v.UnlockKeyslot(ctx, slot, pass)
	if err != nil {
		return err
	}
	key.Destroy()

	return v.RemoveKeyslot(ctx, slot)
}

// killSlotForTest authenticates with passphrase against ANY bound keyslot
// and then removes targetSlot regardless of which slot verified it, the
// way the pre-redesign library's luks2.KillSlot(device, passphrase,
// targetSlot) did before B.6 deleted it.
func killSlotForTest(device string, passphrase []byte, targetSlot int) error {
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
	key.Destroy()

	return v.RemoveKeyslot(ctx, targetSlot)
}

// keyslotParamsForTest converts the old flat AddKeyOptions shape into
// KeyslotParams, resolving only the spellings this package's own fixtures
// pass. Priority defaults to PriorityNormal: KeyslotParams's zero value is
// PriorityIgnore, and every AddKeyOptions-shaped caller expects the old
// AddKey's always-normal-priority behavior, not a silently ignored slot.
func keyslotParamsForTest(opts *AddKeyOptions) luks2.KeyslotParams {
	if opts == nil {
		return luks2.KeyslotParams{Priority: luks2.PriorityNormal}
	}

	kdf := luks2.KDFParams{
		IterTime:   time.Duration(opts.PBKDFIterTime) * time.Millisecond,
		Iterations: opts.PBKDFIterations,
		Time:       opts.Argon2Time,
		MemoryKiB:  opts.Argon2Memory,
		Parallel:   opts.Argon2Parallel,
	}
	switch opts.KDFType {
	case "", "pbkdf2":
		kdf.Type = luks2.KDFPBKDF2
	case string(luks2.KDFArgon2i):
		kdf.Type = luks2.KDFArgon2i
	case string(luks2.KDFArgon2id):
		kdf.Type = luks2.KDFArgon2id
	}
	switch opts.Hash {
	case "sha256":
		kdf.Hash = crypto.SHA256
	case "sha512":
		kdf.Hash = crypto.SHA512
	}

	return luks2.KeyslotParams{Slot: opts.Keyslot, Priority: luks2.PriorityNormal, KDF: kdf}
}

// requireRoot fails the calling test when it is not running as uid 0, and
// does so LOUDLY: this tier exists to exercise the device-mapper, loop and
// mount syscalls a non-root process cannot reach, so a bare uid check that
// quietly skips converts "root was not available" into a pass, and the
// whole reason this tier is privileged is so that is never true.
func requireRoot(t *testing.T) {
	t.Helper()

	if uid := os.Getuid(); uid != 0 {
		t.Fatalf("THIS INTEGRATION TEST REQUIRES ROOT -- running as uid %d. "+
			"Use `make integration-test` (Docker, root by default) or "+
			"`make host-integration-test` (re-execs under sudo); do not invoke "+
			"`go test -tags=integration` directly from a non-root shell.", uid)
	}
}

// releaseVolume retries lock (expected to be func() error { return
// Lock(volumeName) }, written out at the call site rather than closed over
// here) until volumeName's mapping is gone, and FAILS THE TEST if one is
// left behind on the host (#100).
//
// lock is a parameter, not a direct call to Lock, so that the actual
// Lock(volumeName) call -- the one the device-mapper-name safety gate
// (volumename_test.go) must see traced to runVolume -- is written at each
// call site, where volumeName really is a local assigned from runVolume.
// This function only ever sees volumeName as an opaque parameter, which the
// gate's single-file AST walk cannot trace back across a call boundary; a
// Lock(volumeName) written here would be flagged as unprovably scoped even
// though it is safe, because every call site is independently checked.
//
// Same helper and reasoning as the other integration suites': this package cannot
// reach pkg/luks2's own unexported releaseVolumeErr (which additionally
// unmounts whatever is mounted from the volume's own device), so a caller
// that mounted a filesystem on the mapping must unmount it itself before
// relying on this to close cleanly.
func releaseVolume(t *testing.T, volumeName string, lock func() error) {
	t.Helper()

	const timeout = 10 * time.Second
	var last error
	deadline := time.Now().Add(timeout)
	for {
		if err := lock(); err != nil && !errors.Is(err, dmcrypt.ErrNotActive) {
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

	t.Errorf("device-mapper mapping %q is STILL PRESENT after %s, so this run "+
		"is leaving it on the host for the next job, which will refuse to "+
		"start. Last error from Lock: %v", volumeName, timeout, last)
}

// mappingConfirmedGone reports whether the mapping is CONFIRMED absent, by
// asking dmsetup directly rather than trusting luks2.IsUnlocked -- see
// the measured "Device does not exist." string below, and why "unknown" must
// be treated as present.
func mappingConfirmedGone(volumeName string) bool {
	out, err := exec.Command("dmsetup", "info", volumeName).CombinedOutput()
	if err == nil {
		return false
	}
	if strings.Contains(strings.ToLower(string(out)), "device does not exist") {
		return true
	}
	return false
}

// canonicalPassphrase is used by every fixture in this package that does not
// care what the passphrase is.
const canonicalPassphrase = "conformance-test-passphrase"

// canonicalCheapIterations is the sha512 PBKDF2 floor: the cheapest keyslot
// cost a container formatted for mutation (never byte-compared) can carry.
const canonicalCheapIterations = 210_000

func requireCryptsetupDeclared(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Fatalf("cryptsetup is not installed (%v). This tier DECLARES it -- "+
			"the integration stage of build/docker/devcontainer/Dockerfile installs cryptsetup-bin -- so its absence is a broken "+
			"environment, not a reason to report success. Nothing here was verified against a "+
			"third-party LUKS2 implementation.", err)
	}
}

// canonicalImage creates a sparse 64 MiB image under t.TempDir().
func canonicalImage(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to create %s: %v", path, err)
	}
	if err := f.Truncate(64 << 20); err != nil {
		_ = f.Close()
		t.Fatalf("failed to size %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close %s: %v", path, err)
	}
	return path
}

// formatWithCryptsetupForced formats with an exact pbkdf2 iteration count --
// the only way to produce a container carrying a count below this package's
// create floor, which no caller of pkg/luks2 can create otherwise.
func formatWithCryptsetupForced(t *testing.T, path string, iterations int) {
	t.Helper()

	cmd := exec.Command("cryptsetup", "luksFormat", // #nosec G204 -- arguments are test constants
		"--type", "luks2",
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--hash", "sha512",
		"--sector-size", "512",
		"--pbkdf", "pbkdf2",
		"--pbkdf-force-iterations", strconv.Itoa(iterations),
		"--batch-mode",
		path,
	)
	cmd.Stdin = strings.NewReader(canonicalPassphrase)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cryptsetup luksFormat: %v\n%s", err, out)
	}
}

// formatWithCryptsetupCheap formats a cryptsetup container for a test that
// does NOT compare bytes: see formatWithCryptsetupForced.
func formatWithCryptsetupCheap(t *testing.T, path string) {
	t.Helper()
	formatWithCryptsetupForced(t, path, canonicalCheapIterations)
}

// formatWithLibraryCheap formats a container, through pkg/luks2's own
// Format, for a test that will mutate it and never compares its bytes
// against cryptsetup's -- so unlike pkg/luks2's own canonicalconformance
// fixtures, the UUID and random material are NOT pinned: that seam is
// unexported and this package is external to pkg/luks2.
func formatWithLibraryCheap(t *testing.T, path string) {
	t.Helper()

	if err := Format(FormatOptions{
		Device:          path,
		Passphrase:      []byte(canonicalPassphrase),
		Cipher:          "aes",
		CipherMode:      "xts-plain64",
		KeySize:         512,
		HashAlgo:        "sha512",
		SectorSize:      512,
		KDFType:         "pbkdf2",
		PBKDFIterations: canonicalCheapIterations,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
}

// readJSONArea returns the JSON of a header copy, without its NUL
// terminator or the zero padding that follows.
func readJSONArea(t *testing.T, path string) []byte {
	t.Helper()

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, header.DefaultSize)
	if _, err := f.ReadAt(buf, header.HeaderSize); err != nil {
		t.Fatalf("failed to read the JSON area of %s: %v", path, err)
	}
	end := bytes.IndexByte(buf, 0)
	if end < 0 {
		t.Fatalf("the JSON area of %s has no NUL terminator", path)
	}
	return buf[:end]
}

// laneDLoop formats a fresh image attached to a loop device and returns the
// loop device and the image path.
func laneDLoop(t *testing.T) (loop, image string) {
	t.Helper()
	requireRoot(t)

	image = canonicalImage(t, "lane-d.img")
	loopDev, err := harness.SetupLoopDevice(image)
	if err != nil {
		t.Fatalf("SetupLoopDevice: %v", err)
	}
	t.Cleanup(func() { _ = harness.DetachLoopDevice(loopDev) })
	if err := Format(FormatOptions{
		Device: loopDev, Passphrase: []byte(canonicalPassphrase),
		KDFType: "pbkdf2", PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format: %v", err)
	}
	return loopDev, image
}

// stampTokens replaces a container's token map with exactly the map given,
// bypassing ImportToken's canonicalization, so entries the exported token
// API cannot create -- a non-canonical id, in particular -- reach the disk.
//
// It is pkg/luks2's own craftedheader_test.go's writeHeaderUnvalidated,
// reimplemented here with internal/header's exported codec (EncodeMetadata,
// WriteEncodedHeader, WriteSecondaryCopy): LUKS2BinaryHeader and
// LUKS2Metadata are type aliases of header.BinaryHeader/header.Metadata
// (pkg/luks2/types.go), so this package needs no access to pkg/luks2's own
// unexported helper.
func stampTokens(t *testing.T, path string, tokens map[string]*luks2.LegacyToken) {
	t.Helper()

	hdr, metadata, err := harness.ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	metadata.Tokens = tokens

	jsonData, area, err := header.EncodeMetadata(hdr, metadata)
	if err != nil {
		t.Fatalf("EncodeMetadata: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := header.WriteEncodedHeader(f, hdr, jsonData, area, (*os.File).Sync); err != nil {
		t.Fatalf("WriteEncodedHeader: %v", err)
	}
}

// tokenIDVolume writes a container whose token map carries the given keys
// VERBATIM, so a non-canonical spelling reaches the disk.
func tokenIDVolume(t *testing.T, name string, keys ...string) string {
	t.Helper()

	path := canonicalImage(t, name)
	if err := Format(FormatOptions{
		Device:        path,
		Passphrase:    []byte("token-id-fixture-passphrase"),
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		KeySize:       512,
		HashAlgo:      "sha512",
		SectorSize:    512,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format: %v", err)
	}

	tokens := make(map[string]*luks2.LegacyToken, len(keys))
	for _, key := range keys {
		tokens[key] = &luks2.LegacyToken{Type: "written-as-" + key, Keyslots: []string{"0"}}
	}
	stampTokens(t, path, tokens)
	return path
}
