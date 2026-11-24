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

// Unlock, Lock, IsUnlocked and GetMappedDevicePath forward to pkg/luks2 and pkg/dmcrypt; volumename_test.go keys on the names Unlock and Lock.
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

// FormatOptions and Format forward to (*luks2.Volume).Format, supporting only the options these fixtures pass.
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

// AddKeyOptions and AddKey forward to (*luks2.Volume).AddKeyslot and return its KeyslotInfo.
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

// requireRoot fails the calling test when not running as uid 0, never skips.
func requireRoot(t *testing.T) {
	t.Helper()

	if uid := os.Getuid(); uid != 0 {
		t.Fatalf("THIS INTEGRATION TEST REQUIRES ROOT -- running as uid %d. "+
			"Use `make integration-test` (Docker, root by default) or "+
			"`make host-integration-test` (re-execs under sudo); do not invoke "+
			"`go test -tags=integration` directly from a non-root shell.", uid)
	}
}

// releaseVolume retries lock until volumeName's mapping is gone and fails the test if it remains; lock is written at the call site for volumename_test.go's audit.
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

// mappingConfirmedGone reports whether dmsetup confirms the mapping absent; unknown counts as present.
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

// stampTokens replaces a container's token map verbatim through internal/header's codec, bypassing ImportToken's canonicalization.
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

// tokenIDVolume writes a container whose token map carries the given keys verbatim.
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
