// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package interop_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
	kdfpkg "github.com/jeremyhahn/go-luks2/internal/kdf"
	"github.com/jeremyhahn/go-luks2/internal/secret"
	"github.com/jeremyhahn/go-luks2/pkg/keyprovider"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// The two-way interoperability matrix (docs/cryptsetup-interop/engineering.md): each
// operation done by one tool and checked by the other, against cryptsetup
// and the real kernel. Rows are data; every row runs in parallel on a
// volume of its own. See compatmatrix_integration_test.go (now moved, from
// pkg/luks2) for the full history.
//
// Checked elsewhere and not repeated here: byte-for-byte header equality
// (canonicalconformance_integration_test.go, which stays in pkg/luks2), the
// FIPS import (fipsimport_test.go in this directory), the header-only
// wipe and detached-header activation (test/integration/header,
// test/integration/dm).

const (
	matrixPassphrase = "matrix-passphrase"
	matrixSecond     = "matrix-second-passphrase"
	matrixNew        = "matrix-new-passphrase"
)

var matrixCheap = []string{"--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"}

var matrixAddKeyOptions = &AddKeyOptions{KDFType: "pbkdf2", PBKDFIterTime: 1}

var matrixNames atomic.Int64

func matrixName(base string) string {
	return base + "-" + strconv.FormatInt(matrixNames.Add(1), 10)
}

func matrixKeyFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func csVolume(t *testing.T, args ...string) string {
	t.Helper()
	loop, _ := activationLoop(t, "matrix.img", 96, nil)
	all := append([]string{"luksFormat", "--type", "luks2", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase))}, matrixCheap...)
	mustCryptsetupPassphrase(t, "", append(append(all, args...), loop)...)
	return loop
}

// FormatOptions and Format are the old FormatOptions/luks2.Format
// free-function shape, forwarded onto (*luks2.Volume).Format the same way
// test/integration/luks2/common_test.go's copy does: B.6 moved Format
// behind the Volume, and the on-disk container it writes is the same
// regardless of which shape chose it.
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

	pass, err := enclave.NewMemoryEnclaveCopy(opts.Passphrase)
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
		kdf.Type = luks2.KDFPBKDF2
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

func libVolume(t *testing.T, opts FormatOptions) string {
	t.Helper()
	loop, _ := activationLoop(t, "matrix.img", 96, nil)
	opts.Device, opts.Passphrase = loop, []byte(matrixPassphrase)
	if opts.KDFType == "" {
		opts.KDFType, opts.PBKDFIterTime = "pbkdf2", 1
	}
	if err := Format(opts); err != nil {
		t.Fatalf("Format: %v", err)
	}
	return loop
}

// verifyRecoveryKeyForTest reports whether key unlocks device, the way the
// pre-redesign library's luks2.VerifyRecoveryKey did before B.6 deleted it
// in favor of (*luks2.Volume).Unlock: a failure to verify (ErrWrongKey) is
// (false, nil) rather than an error.
func verifyRecoveryKeyForTest(device string, key *enclave.MemoryEnclave) (bool, error) {
	ctx := context.Background()
	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		return false, err
	}
	defer func() { _ = v.Close() }()

	unlocked, err := v.Unlock(ctx, key)
	if err != nil {
		if errors.Is(err, luks2.ErrWrongKey) {
			return false, nil
		}
		return false, err
	}
	unlocked.Destroy()
	return true, nil
}

// migrateToFIPSForTest opens device, unlocks it with passphrase and runs
// (*luks2.Volume).MigrateToFIPS at the library's default policy, the way
// the pre-redesign library's luks2.MigrateToFIPS(device, passphrase, nil)
// did before B.6 moved it behind the Volume.
func migrateToFIPSForTest(device string, passphrase []byte) (*luks2.Migration, error) {
	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return nil, err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		return nil, err
	}
	defer func() { _ = pass.Destroy() }()

	return v.MigrateToFIPS(ctx, pass, luks2.MigrateParams{})
}

// AddKeyOptions and AddKey are the old free-function shape, forwarded onto
// (*luks2.Volume).AddKeyslot the same way Format above forwards onto
// (*luks2.Volume).Format. Every caller here discards the slot number, so
// AddKey keeps returning just an error.
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

func AddKey(device string, existing, newPassphrase []byte, opts *AddKeyOptions) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(existing)
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return err
	}
	defer key.Destroy()

	newCred, err := enclave.NewMemoryEnclaveCopy(newPassphrase)
	if err != nil {
		return err
	}
	defer func() { _ = newCred.Destroy() }()

	_, err = v.AddKeyslot(ctx, key, newCred, keyslotParamsForTest(opts))
	return err
}

// changeKeyForTest unlocks slot with oldPass and replaces its credential
// with newPass, the way the pre-redesign library's
// changeKeyForTest(device, oldPass, newPass, slot) did before B.6 moved it
// behind (*luks2.Volume).ChangeKeyslot.
func changeKeyForTest(device string, oldPass, newPass []byte, slot int) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	old, err := enclave.NewMemoryEnclaveCopy(oldPass)
	if err != nil {
		return err
	}
	defer func() { _ = old.Destroy() }()
	key, err := v.UnlockKeyslot(ctx, slot, old)
	if err != nil {
		return err
	}
	defer key.Destroy()

	newCred, err := enclave.NewMemoryEnclaveCopy(newPass)
	if err != nil {
		return err
	}
	defer func() { _ = newCred.Destroy() }()

	_, err = v.ChangeKeyslot(ctx, key, newCred, luks2.KeyslotParams{})
	return err
}

// removeKeyForTest unlocks slot with passphrase and removes it, the way
// the pre-redesign library's removeKeyForTest(device, passphrase, slot) did
// before B.6 deleted it: credential checks are CLI policy now
// (Unlock/UnlockKeyslot, then RemoveKeyslot).
func removeKeyForTest(device string, passphrase []byte, slot int) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
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
// way the pre-redesign library's killSlotForTest(device, passphrase,
// targetSlot) did before B.6 deleted it.
func killSlotForTest(device string, passphrase []byte, targetSlot int) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
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
// AddKey's always-normal-priority behavior.
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

func csAddKey(t *testing.T, device, passphrase string, extra ...string) {
	t.Helper()
	args := append([]string{"luksAddKey", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase))}, matrixCheap...)
	args = append(append(args, extra...), device, matrixKeyFile(t, []byte(passphrase)))
	mustCryptsetupPassphrase(t, "", args...)
}

func csOpens(t *testing.T, device string, passphrase []byte, extra ...string) bool {
	t.Helper()
	args := append([]string{"open", "--test-passphrase", "--key-file", matrixKeyFile(t, passphrase)}, extra...)
	_, ok := cryptsetupWithStdin(t, "", append(args, device)...)
	return ok
}

func assertCryptsetupReadsIt(t *testing.T, device, passphrase string, extra ...string) {
	t.Helper()
	mustCryptsetupPassphrase(t, "", append([]string{"isLuks", "--type", "luks2"}, append(extra, device)...)...)
	mustCryptsetupPassphrase(t, "", append([]string{"luksDump"}, append(extra, device)...)...)
	if !csOpens(t, device, []byte(passphrase), extra...) {
		t.Fatalf("cryptsetup does not open %s with %q", device, passphrase)
	}
}

func csMapping(t *testing.T, device string, passphrase []byte) string {
	t.Helper()
	name := runVolume(t, matrixName("matrix-cs"))
	t.Cleanup(func() {
		if mappingExists(name) {
			_, _ = exec.Command("cryptsetup", "close", name).CombinedOutput() // #nosec G204 -- a run-scoped mapping name
		}
	})
	mustCryptsetupPassphrase(t, "", "open", "--key-file", matrixKeyFile(t, passphrase), device, name)
	return name
}

func mappingExists(name string) bool {
	return exec.Command("dmsetup", "info", name).Run() == nil // #nosec G204 -- a run-scoped mapping name
}

func csClose(t *testing.T, name string) {
	t.Helper()
	mustCryptsetupPassphrase(t, "", "close", name)
}

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

func mappingRegions(t *testing.T, name string, write []byte) []byte {
	t.Helper()
	node := waitForNode(t, name)
	f, err := os.OpenFile(node, os.O_RDWR, 0) // #nosec G304 -- a mapping this test opened
	if err != nil {
		t.Fatalf("open %s: %v", node, err)
	}
	defer func() { _ = f.Close() }()
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatal(err)
	}
	const head, tail = 256 << 10, 64 << 10
	if write != nil {
		if _, err := f.WriteAt(write[:head], 0); err != nil {
			t.Fatalf("write through %s: %v", name, err)
		}
		if _, err := f.WriteAt(write[head:], size-tail); err != nil {
			t.Fatalf("write through %s: %v", name, err)
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	got := make([]byte, head+tail)
	if _, err := f.ReadAt(got[:head], 0); err != nil {
		t.Fatalf("read through %s: %v", name, err)
	}
	if _, err := f.ReadAt(got[head:], size-tail); err != nil {
		t.Fatalf("read through %s: %v", name, err)
	}
	return got
}

func randomPattern(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 320<<10)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func assertDataRoundTrip(t *testing.T, device string, passphrase []byte) {
	t.Helper()
	theirs := randomPattern(t)
	name := csMapping(t, device, passphrase)
	mappingRegions(t, name, theirs)
	csClose(t, name)

	ours := runVolume(t, matrixName("matrix-ours"))
	t.Cleanup(func() { releaseVolume(t, ours) })
	if err := Unlock(device, passphrase, ours); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !bytes.Equal(mappingRegions(t, ours, nil), theirs) {
		releaseVolume(t, ours)
		t.Fatal("go-luks2's mapping reads other bytes than cryptsetup's mapping wrote")
	}
	mine := randomPattern(t)
	mappingRegions(t, ours, mine)
	releaseVolume(t, ours)

	name = csMapping(t, device, passphrase)
	got := mappingRegions(t, name, nil)
	csClose(t, name)
	if !bytes.Equal(got, mine) {
		t.Fatal("cryptsetup's mapping reads other bytes than go-luks2's mapping wrote")
	}
}

func csTokenExport(t *testing.T, device, id string) []byte {
	t.Helper()
	return []byte(mustCryptsetupPassphrase(t, "", "token", "export", "--token-id", id, device))
}

const (
	matrixTPM2Token = `{"type":"systemd-tpm2","keyslots":["0"],"tpm2-blob":"AJ4AIAVxbDnrEKWFKd0=",` +
		`"tpm2-pcrs":[7],"tpm2-pcr-bank":"sha256","tpm2-primary-alg":"ecc","tpm2-policy-hash":"8c4d0e1f",` +
		`"tpm2-pin":false,"tpm2_pcrlock":false,"tpm2_srk":"AAAAAQ=="}`
	matrixFIDO2Token = `{"type":"systemd-fido2","keyslots":["0"],"fido2-credential":"Y3JlZGVudGlhbC1pZA==",` +
		`"fido2-salt":"c2FsdC0zMi1ieXRlcy1vZi1zYWx0LWZvci10ZXN0cyE=","fido2-rp":"io.systemd.cryptsetup",` +
		`"fido2-clientPin-required":false,"fido2-up-required":true,"fido2-uv-required":false}`
	matrixSystemdRecovery = "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv"
)

type matrixRow struct {
	op, dir string
	run     func(t *testing.T)
}

const (
	usToCS = "go-luks2 -> cryptsetup"
	csToUs = "cryptsetup -> go-luks2"
)

var compatMatrix = []matrixRow{
	{"format", usToCS, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		assertCryptsetupReadsIt(t, loop, matrixPassphrase)
	}},
	{"format", csToUs, func(t *testing.T) {
		loop := csVolume(t)
		if ok, err := harness.IsLUKS2(loop); !ok || err != nil {
			t.Fatalf("IsLUKS2 = %v, %v", ok, err)
		}
		if _, err := harness.GetVolumeInfo(loop); err != nil {
			t.Fatalf("GetVolumeInfo: %v", err)
		}
		if err := harness.TestKey(loop, []byte(matrixPassphrase)); err != nil {
			t.Fatalf("TestKey: %v", err)
		}
		if err := harness.TestKey(loop, []byte(matrixNew)); err == nil {
			t.Fatal("TestKey accepted a wrong passphrase")
		}
	}},
	{"open and data", "both", func(t *testing.T) {
		assertDataRoundTrip(t, csVolume(t), []byte(matrixPassphrase))
		assertDataRoundTrip(t, libVolume(t, FormatOptions{}), []byte(matrixPassphrase))
	}},
	{"add key", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		if err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err != nil {
			t.Fatalf("AddKey: %v", err)
		}
		assertCryptsetupReadsIt(t, loop, matrixNew)
	}},
	{"add key", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		csAddKey(t, loop, matrixNew)
		assertDataRoundTrip(t, loop, []byte(matrixNew))
	}},
	{"remove key", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		csAddKey(t, loop, matrixSecond)
		if err := removeKeyForTest(loop, []byte(matrixSecond), 1); err != nil {
			t.Fatalf("RemoveKey: %v", err)
		}
		assertCryptsetupReadsIt(t, loop, matrixPassphrase)
		if csOpens(t, loop, []byte(matrixSecond)) {
			t.Fatal("cryptsetup opens the removed passphrase")
		}
	}},
	{"remove key", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		csAddKey(t, loop, matrixSecond)
		mustCryptsetupPassphrase(t, "", "luksRemoveKey", "--batch-mode", "--key-file", matrixKeyFile(t, []byte(matrixSecond)), loop)
		assertGoOpensOnly(t, loop, matrixPassphrase, matrixSecond)
	}},
	{"kill slot", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		csAddKey(t, loop, matrixSecond)
		if err := killSlotForTest(loop, []byte(matrixPassphrase), 1); err != nil {
			t.Fatalf("KillSlot: %v", err)
		}
		assertCryptsetupReadsIt(t, loop, matrixPassphrase)
		if csOpens(t, loop, []byte(matrixSecond)) {
			t.Fatal("cryptsetup opens the killed slot")
		}
	}},
	{"kill slot", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		csAddKey(t, loop, matrixSecond)
		mustCryptsetupPassphrase(t, "", "luksKillSlot", "--batch-mode", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase)), loop, "1")
		assertGoOpensOnly(t, loop, matrixPassphrase, matrixSecond)
	}},
	{"change key", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		if err := changeKeyForTest(loop, []byte(matrixPassphrase), []byte(matrixNew), 0); err != nil {
			t.Fatalf("ChangeKey: %v", err)
		}
		assertCryptsetupReadsIt(t, loop, matrixNew)
		if csOpens(t, loop, []byte(matrixPassphrase)) {
			t.Fatal("cryptsetup opens the replaced passphrase")
		}
	}},
	{"change key", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		mustCryptsetupPassphrase(t, "", append(append([]string{"luksChangeKey", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase))}, matrixCheap...),
			loop, matrixKeyFile(t, []byte(matrixNew)))...)
		assertGoOpensOnly(t, loop, matrixNew, matrixPassphrase)
	}},
	{"key file", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		key := make([]byte, 4096)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		key[0], key[1], key[4095] = 0, '\n', '\n'
		mustCryptsetupPassphrase(t, "", append(append([]string{"luksAddKey", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase))}, matrixCheap...),
			"--new-keyfile", matrixKeyFile(t, key), loop)...)
		if err := harness.TestKey(loop, key); err != nil {
			t.Fatalf("TestKey with cryptsetup's key file: %v", err)
		}
		if err := harness.TestKey(loop, key[:4095]); err == nil {
			t.Fatal("the key file without its trailing newline opened the volume")
		}
	}},
	{"key file", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		key := make([]byte, luks2.MaxPassphraseLength)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		key[0], key[len(key)-1] = 0, '\n'
		if err := AddKey(loop, []byte(matrixPassphrase), key, matrixAddKeyOptions); err != nil {
			t.Fatalf("AddKey with a binary key: %v", err)
		}
		if !csOpens(t, loop, key) {
			t.Fatal("cryptsetup does not open the binary key go-luks2 enrolled, read from a key file")
		}
		before := deviceDigest(t, loop, 16<<20)
		if err := AddKey(loop, []byte(matrixPassphrase), make([]byte, 4096), matrixAddKeyOptions); !errors.Is(err, luks2.ErrInvalidCredential) {
			t.Fatalf("AddKey with a 4 KiB new key = %v, want ErrPassphraseTooLong", err)
		}
		if deviceDigest(t, loop, 16<<20) != before {
			t.Fatal("a refused AddKey changed the header")
		}
	}},
	{"token import (systemd-tpm2 JSON)", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		var tok luks2.Token
		if err := json.Unmarshal([]byte(matrixTPM2Token), &tok); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		v, err := luks2.Open(context.Background(), loop)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := v.SetToken(context.Background(), 0, tok); err != nil {
			t.Fatalf("SetToken: %v", err)
		}
		if err := v.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !sameJSON(t, csTokenExport(t, loop, "0"), []byte(matrixTPM2Token)) {
			t.Fatalf("cryptsetup exports %s", csTokenExport(t, loop, "0"))
		}
		assertCryptsetupReadsIt(t, loop, matrixPassphrase)
	}},
	{"token import (systemd-fido2)", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		up, pin, uv := true, false, false
		raw, err := json.Marshal(luks2.LegacyToken{Type: "systemd-fido2", Keyslots: []string{"0"},
			FIDO2Credential: "Y3JlZGVudGlhbC1pZA==", FIDO2Salt: "c2FsdC0zMi1ieXRlcy1vZi1zYWx0LWZvci10ZXN0cyE=",
			FIDO2RP: "io.systemd.cryptsetup", FIDO2ClientPinRequired: &pin, FIDO2UPRequired: &up, FIDO2UVRequired: &uv})
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var tok luks2.Token
		if err := json.Unmarshal(raw, &tok); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		v, err := luks2.Open(context.Background(), loop)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := v.SetToken(context.Background(), 1, tok); err != nil {
			t.Fatalf("SetToken: %v", err)
		}
		if err := v.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !sameJSON(t, csTokenExport(t, loop, "1"), []byte(matrixFIDO2Token)) {
			t.Fatalf("cryptsetup exports %s, want %s", csTokenExport(t, loop, "1"), matrixFIDO2Token)
		}
	}},
	{"token import (systemd-fido2, systemd-tpm2 JSON)", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		mustCryptsetupPassphrase(t, "", "token", "import", "--token-id", "1", "--json-file", matrixKeyFile(t, []byte(matrixFIDO2Token)), loop)
		mustCryptsetupPassphrase(t, "", "token", "import", "--token-id", "2", "--json-file", matrixKeyFile(t, []byte(matrixTPM2Token)), loop)
		v, err := luks2.Open(context.Background(), loop)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer func() { _ = v.Close() }()
		hdr, err := v.Header(context.Background())
		if err != nil {
			t.Fatalf("Header: %v", err)
		}
		token, ok := hdr.Tokens()[1]
		if !ok {
			t.Fatal("Tokens()[1] missing")
		}
		if token.Type != keyprovider.TokenTypeFIDO2 || string(token.Members["fido2-rp"]) != `"io.systemd.cryptsetup"` ||
			string(token.Members["fido2-up-required"]) != "true" || string(token.Members["fido2-clientPin-required"]) != "false" {
			t.Fatalf("Tokens()[1] = %+v", token)
		}
		for id, want := range map[int]string{1: matrixFIDO2Token, 2: matrixTPM2Token} {
			tok, ok := hdr.Tokens()[id]
			if !ok {
				t.Fatalf("Tokens()[%d] missing", id)
			}
			raw, err := json.Marshal(tok)
			if err != nil || !sameJSON(t, raw, []byte(want)) {
				t.Fatalf("Tokens()[%d] = %s, %v", id, raw, err)
			}
		}
		if err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err != nil {
			t.Fatalf("AddKey: %v", err)
		}
		if !sameJSON(t, csTokenExport(t, loop, "2"), []byte(matrixTPM2Token)) {
			t.Fatal("the systemd-tpm2 token changed through AddKey")
		}
	}},
	{"token remove", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		mustCryptsetupPassphrase(t, "", "token", "import", "--token-id", "3", "--json-file", matrixKeyFile(t, []byte(matrixTPM2Token)), loop)
		v, err := luks2.Open(context.Background(), loop)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := v.RemoveToken(context.Background(), 3); err != nil {
			t.Fatalf("RemoveToken: %v", err)
		}
		if err := v.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, ok := cryptsetupWithStdin(t, "", "token", "export", "--token-id", "3", loop); ok {
			t.Fatal("cryptsetup still exports the removed token")
		}
		assertCryptsetupReadsIt(t, loop, matrixPassphrase)
	}},
	{"token remove", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		var tok luks2.Token
		if err := json.Unmarshal([]byte(matrixTPM2Token), &tok); err != nil {
			t.Fatal(err)
		}
		v, err := luks2.Open(context.Background(), loop)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.SetToken(context.Background(), 3, tok); err != nil {
			t.Fatal(err)
		}
		if err := v.Close(); err != nil {
			t.Fatal(err)
		}
		mustCryptsetupPassphrase(t, "", "token", "remove", "--token-id", "3", loop)
		v, err = luks2.Open(context.Background(), loop, luks2.WithReadOnly())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = v.Close() }()
		hdr, err := v.Header(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := hdr.Tokens()[3]; ok {
			t.Fatal("Tokens()[3] still present after cryptsetup removed it")
		}
	}},
	{"header backup and restore", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		data := randomPattern(t)
		name := runVolume(t, matrixName("matrix-backup"))
		t.Cleanup(func() { releaseVolume(t, name) })
		if err := Unlock(loop, []byte(matrixPassphrase), name); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
		mappingRegions(t, name, data)
		releaseVolume(t, name)
		backup := filepath.Join(t.TempDir(), "header.backup")
		mustCryptsetupPassphrase(t, "", "luksHeaderBackup", loop, "--header-backup-file", backup)
		if err := func() error {
			v, err := luks2.Open(context.Background(), loop)
			if err != nil {
				return err
			}
			defer func() { _ = v.Close() }()
			return v.Erase(context.Background())
		}(); err != nil {
			t.Fatalf("Wipe: %v", err)
		}
		if ok, _ := harness.IsLUKS(loop); ok {
			t.Fatal("the header survived the wipe")
		}
		mustCryptsetupPassphrase(t, "", "luksHeaderRestore", "--batch-mode", loop, "--header-backup-file", backup)
		restored := runVolume(t, matrixName("matrix-restored"))
		t.Cleanup(func() { releaseVolume(t, restored) })
		if err := Unlock(loop, []byte(matrixPassphrase), restored); err != nil {
			t.Fatalf("Unlock after luksHeaderRestore: %v", err)
		}
		got := mappingRegions(t, restored, nil)
		releaseVolume(t, restored)
		if !bytes.Equal(got, data) {
			t.Fatal("the data does not read back through the restored header")
		}
	}},
	{"header backup and restore (rollback)", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		backup := filepath.Join(t.TempDir(), "header.backup")
		mustCryptsetupPassphrase(t, "", "luksHeaderBackup", loop, "--header-backup-file", backup)
		if err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err != nil {
			t.Fatal(err)
		}
		mustCryptsetupPassphrase(t, "", "luksHeaderRestore", "--batch-mode", loop, "--header-backup-file", backup)
		assertGoOpensOnly(t, loop, matrixPassphrase, matrixNew)
	}},
	{"header restore (primary from secondary)", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		f, err := os.OpenFile(loop, os.O_WRONLY, 0) // #nosec G304 -- a loop device this test made
		if err != nil {
			t.Fatal(err)
		}
		_, werr := f.WriteAt(make([]byte, 4096), 0)
		if cerr := f.Close(); werr != nil || cerr != nil {
			t.Fatalf("damaging the primary: %v %v", werr, cerr)
		}
		v, err := luks2.Open(context.Background(), loop)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := v.RestorePrimaryHeader(context.Background()); err != nil {
			t.Fatalf("RestorePrimaryHeader: %v", err)
		}
		if err := v.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		assertCryptsetupReadsIt(t, loop, matrixPassphrase)
	}},
	{"wipe keyslot", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		csAddKey(t, loop, matrixSecond)
		if err := harness.WipeKeyslot(loop, 1); err != nil {
			t.Fatalf("WipeKeyslot: %v", err)
		}
		assertCryptsetupReadsIt(t, loop, matrixPassphrase)
		if csOpens(t, loop, []byte(matrixSecond)) {
			t.Fatal("cryptsetup opens the wiped keyslot")
		}
	}},
	{"wipe keyslot (luksErase)", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		mustCryptsetupPassphrase(t, "", "luksErase", "--batch-mode", loop)
		if ok, err := harness.IsLUKS2(loop); !ok || err != nil {
			t.Fatalf("IsLUKS2 after luksErase = %v, %v; the header stays", ok, err)
		}
		if err := harness.TestKey(loop, []byte(matrixPassphrase)); err == nil {
			t.Fatal("go-luks2 opens a volume whose keyslots cryptsetup erased")
		}
	}},
	{"recovery key", usToCS, func(t *testing.T) {
		loop := csVolume(t)

		ctx := context.Background()
		v, err := luks2.Open(ctx, loop)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = v.Close() }()

		pass, err := enclave.NewMemoryEnclaveCopy([]byte(matrixPassphrase))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pass.Destroy() }()
		key, err := v.Unlock(ctx, pass)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Destroy()

		rk, err := luks2.NewRecoveryKey()
		if err != nil {
			t.Fatal(err)
		}
		defer rk.Destroy()

		if _, err := v.AddRecoveryKey(ctx, key, rk, luks2.KeyslotParams{
			KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: time.Millisecond},
		}); err != nil {
			t.Fatalf("AddRecoveryKey: %v", err)
		}

		var buf bytes.Buffer
		if _, err := rk.WriteTo(&buf); err != nil {
			t.Fatal(err)
		}
		if !csOpens(t, loop, buf.Bytes()) {
			t.Fatal("cryptsetup does not open the printed recovery key")
		}
		var token map[string]any
		if err := json.Unmarshal(csTokenExport(t, loop, "0"), &token); err != nil || token["type"] != luks2.TokenTypeRecovery {
			t.Fatalf("cryptsetup's export of the recovery token: %v %v", token, err)
		}
	}},
	{"recovery key (systemd-cryptenroll form)", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		csAddKey(t, loop, matrixSystemdRecovery)
		mustCryptsetupPassphrase(t, "", "token", "import", "--token-id", "0", "--json-file",
			matrixKeyFile(t, []byte(`{"type":"systemd-recovery","keyslots":["1"]}`)), loop)
		v, err := luks2.Open(context.Background(), loop, luks2.WithReadOnly())
		if err != nil {
			t.Fatal(err)
		}
		hdr, err := v.Header(context.Background())
		closeErr := v.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		tok, ok := hdr.Tokens()[0]
		if !ok || tok.Type != luks2.TokenTypeRecovery {
			t.Fatalf("Tokens()[0] = %+v, %v", tok, ok)
		}
		typed, err := enclave.NewMemoryEnclaveCopy([]byte(matrixSystemdRecovery + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = typed.Destroy() }()
		credential, err := luks2.ParseRecoveryKey(typed)
		if err != nil {
			t.Fatal(err)
		}
		defer secret.System().Release(credential)
		if ok, err := verifyRecoveryKeyForTest(loop, credential); !ok || err != nil {
			t.Fatalf("VerifyRecoveryKey = %v, %v", ok, err)
		}
	}},
	{"detached header", csToUs, func(t *testing.T) {
		data, _ := activationLoop(t, "matrix-data.img", 32, nil)
		hdrFile := filepath.Join(t.TempDir(), "detached.hdr")
		mustCryptsetupPassphrase(t, "", append(append([]string{"luksFormat", "--type", "luks2", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase))}, matrixCheap...),
			"--header", hdrFile, data)...)
		if err := harness.TestKey(hdrFile, []byte(matrixPassphrase)); err != nil {
			t.Fatalf("TestKey on the header file: %v", err)
		}
		if err := AddKey(hdrFile, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err != nil {
			t.Fatalf("AddKey on the header file: %v", err)
		}
		assertCryptsetupReadsIt(t, hdrFile, matrixNew)
		if !csOpens(t, data, []byte(matrixNew), "--header", hdrFile) {
			t.Fatal("cryptsetup does not open the data with the keyslot go-luks2 added to its detached header")
		}
	}},
}

func assertGoOpensOnly(t *testing.T, device, good, gone string) {
	t.Helper()
	if err := harness.TestKey(device, []byte(good)); err != nil {
		t.Fatalf("TestKey(%q): %v", good, err)
	}
	if err := harness.TestKey(device, []byte(gone)); err == nil {
		t.Fatalf("TestKey(%q) still opens the volume", gone)
	}
}

func TestCompatMatrix(t *testing.T) {
	requireCryptsetupDeclared(t)
	for _, row := range compatMatrix {
		t.Run(row.op+" "+row.dir, func(t *testing.T) {
			defer parallel(t)()
			row.run(t)
		})
	}
}

var cryptsetupFormats = []struct {
	name        string
	args        []string
	unformatted bool
	setup       func(t *testing.T, loop string)
	check       func(t *testing.T, loop string)
}{
	{name: "pbkdf2 sha256", args: []string{"--hash", "sha256"}},
	{name: "pbkdf2 sha512", args: []string{"--hash", "sha512"}},
	{name: "argon2i", args: []string{"--pbkdf", "argon2i", "--pbkdf-memory", "32768", "--pbkdf-force-iterations", "4"}},
	{name: "argon2id", args: []string{"--pbkdf", "argon2id", "--pbkdf-memory", "32768", "--pbkdf-force-iterations", "4"}},
	{name: "key size 256", args: []string{"--key-size", "256"}},
	{name: "key size 512", args: []string{"--key-size", "512"}},
	{name: "sector size 512", args: []string{"--sector-size", "512"}},
	{name: "sector size 4096", args: []string{"--sector-size", "4096"}},
	{name: "label and subsystem", args: []string{"--label", "matrix-label", "--subsystem", "matrix-subsystem"},
		check: func(t *testing.T, loop string) {
			info, err := harness.GetVolumeInfo(loop)
			if err != nil || info.Label != "matrix-label" || info.Metadata == nil {
				t.Fatalf("GetVolumeInfo = %+v, %v", info, err)
			}
			out := mustCryptsetupPassphrase(t, "", "luksDump", loop)
			if !strings.Contains(out, "matrix-label") || !strings.Contains(out, "matrix-subsystem") {
				t.Fatalf("the label or subsystem was lost through go-luks2's write:\n%s", out)
			}
		}},
	{name: "metadata 64k, keyslots 1m", args: []string{"--luks2-metadata-size", "64k", "--luks2-keyslots-size", "1m"}},
	{name: "metadata 1m, keyslots 8m", args: []string{"--luks2-metadata-size", "1m", "--luks2-keyslots-size", "8m"}},
	{name: "keyslot cipher aes-xts-plain", args: []string{"--keyslot-cipher", "aes-xts-plain", "--keyslot-key-size", "512"}},
	{name: "keyslot cipher aes-cbc-essiv:sha256", args: []string{"--keyslot-cipher", "aes-cbc-essiv:sha256", "--keyslot-key-size", "256"}},
	{name: "keyslot cipher aes-cbc-plain64", args: []string{"--keyslot-cipher", "aes-cbc-plain64", "--keyslot-key-size", "128"}},
	{name: "data cipher aes-cbc-essiv:sha256, 128-bit", args: []string{"--cipher", "aes-cbc-essiv:sha256", "--key-size", "128"}},
	{name: "persistent flags", setup: func(t *testing.T, loop string) {
		name := runVolume(t, matrixName("matrix-flags"))
		t.Cleanup(func() {
			if mappingExists(name) {
				_, _ = exec.Command("cryptsetup", "close", name).CombinedOutput() // #nosec G204 -- a run-scoped mapping name
			}
		})
		mustCryptsetupPassphrase(t, "", "open", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase)), "--persistent", "--allow-discards",
			"--perf-same_cpu_crypt", "--perf-submit_from_crypt_cpus", "--perf-no_read_workqueue", "--perf-no_write_workqueue", loop, name)
		csClose(t, name)
	}, check: func(t *testing.T, loop string) {
		_, metadata, err := harness.ReadHeader(loop)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"allow-discards", "same-cpu-crypt", "submit-from-crypt-cpus", "no-read-workqueue", "no-write-workqueue"}
		if !slices.Equal(metadata.Config.Flags, want) {
			t.Fatalf("config.flags after go-luks2's write = %q, want %q", metadata.Config.Flags, want)
		}
		name := runVolume(t, matrixName("matrix-flags-ours"))
		t.Cleanup(func() { releaseVolume(t, name) })
		if err := Unlock(loop, []byte(matrixPassphrase), name); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
		table := dmTable(t, name)
		releaseVolume(t, name)
		if !strings.HasSuffix(table, " 4 same_cpu_crypt submit_from_crypt_cpus no_read_workqueue no_write_workqueue") {
			t.Fatalf("go-luks2's table %q does not carry the persistent performance flags, without allow_discards", table)
		}
		theirs := csMapping(t, loop, []byte(matrixPassphrase))
		table = dmTable(t, theirs)
		csClose(t, theirs)
		if !strings.Contains(table, " 5 allow_discards same_cpu_crypt") {
			t.Fatalf("cryptsetup's table %q", table)
		}
	}},
	{name: "converted from LUKS1 (aes-xts-plain64, sha256)", unformatted: true, setup: func(t *testing.T, loop string) {
		mustCryptsetupPassphrase(t, "", "luksFormat", "--type", "luks1", "--batch-mode", "--pbkdf-force-iterations", "1000", "--hash", "sha256",
			"--key-file", matrixKeyFile(t, []byte(matrixPassphrase)), loop)
		mustCryptsetupPassphrase(t, "", "convert", "--batch-mode", "--type", "luks2", loop)
	}},
	{name: "converted from LUKS1 (aes-cbc-essiv:sha256, sha1)", unformatted: true, setup: func(t *testing.T, loop string) {
		mustCryptsetupPassphrase(t, "", "luksFormat", "--type", "luks1", "--batch-mode", "--pbkdf-force-iterations", "1000", "--hash", "sha1",
			"--cipher", "aes-cbc-essiv:sha256", "--key-size", "256", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase)), loop)
		mustCryptsetupPassphrase(t, "", "convert", "--batch-mode", "--type", "luks2", loop)
	}},
}

func dmTable(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("dmsetup", "table", name).CombinedOutput() // #nosec G204 -- a run-scoped mapping name
	if err != nil {
		t.Fatalf("dmsetup table %s: %v\n%s", name, err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) > 4 {
		fields[4] = "<key>"
	}
	return strings.Join(fields, " ")
}

func TestCompatCryptsetupFormats(t *testing.T) {
	requireCryptsetupDeclared(t)
	for _, tc := range cryptsetupFormats {
		t.Run(tc.name, func(t *testing.T) {
			defer parallel(t)()

			var loop string
			if tc.unformatted {
				loop, _ = activationLoop(t, "matrix.img", 96, nil)
			} else {
				loop = csVolume(t, tc.args...)
			}
			if tc.setup != nil {
				tc.setup(t, loop)
			}

			if ok, err := harness.IsLUKS2(loop); !ok || err != nil {
				t.Fatalf("IsLUKS2 = %v, %v", ok, err)
			}
			if _, err := harness.GetVolumeInfo(loop); err != nil {
				t.Fatalf("GetVolumeInfo: %v", err)
			}
			assertGoOpensOnly(t, loop, matrixPassphrase, matrixNew)
			assertDataRoundTrip(t, loop, []byte(matrixPassphrase))
			if err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err != nil {
				t.Fatalf("AddKey: %v", err)
			}
			assertCryptsetupReadsIt(t, loop, matrixNew)
			assertDataRoundTrip(t, loop, []byte(matrixNew))
			if tc.check != nil {
				tc.check(t, loop)
			}
		})
	}
}

var libraryFormats = []struct {
	name string
	opts FormatOptions
}{
	{"pbkdf2 sha256", FormatOptions{KDFType: "pbkdf2-sha256", PBKDFIterTime: 1}},
	{"pbkdf2 sha512", FormatOptions{KDFType: "pbkdf2-sha512", PBKDFIterTime: 1}},
	{"argon2i", FormatOptions{KDFType: "argon2i", Argon2Time: 1, Argon2Memory: kdfpkg.MinArgon2MemoryKB, Argon2Parallel: 1}},
	{"argon2id", FormatOptions{KDFType: "argon2id", Argon2Time: 1, Argon2Memory: kdfpkg.MinArgon2MemoryKB, Argon2Parallel: 1}},
	{"key size 256", FormatOptions{KeySize: 256}},
	{"sector size 4096", FormatOptions{SectorSize: 4096}},
	{"label and subsystem", FormatOptions{Label: "matrix-label", Subsystem: "matrix-subsystem"}},
	{"metadata 64k", FormatOptions{MetadataSize: 64 << 10}},
	{"data cipher aes-cbc-essiv:sha256", FormatOptions{Cipher: "aes", CipherMode: "cbc-essiv:sha256", KeySize: 256}},
}

func TestCompatLibraryFormats(t *testing.T) {
	requireCryptsetupDeclared(t)
	for _, tc := range libraryFormats {
		t.Run(tc.name, func(t *testing.T) {
			defer parallel(t)()

			loop := libVolume(t, tc.opts)
			assertCryptsetupReadsIt(t, loop, matrixPassphrase)
			assertDataRoundTrip(t, loop, []byte(matrixPassphrase))
			csAddKey(t, loop, matrixNew)
			if err := harness.TestKey(loop, []byte(matrixNew)); err != nil {
				t.Fatalf("TestKey with cryptsetup's keyslot: %v", err)
			}
			if tc.opts.Label != "" && !strings.Contains(mustCryptsetupPassphrase(t, "", "luksDump", loop), "matrix-subsystem") {
				t.Fatal("cryptsetup does not show the subsystem go-luks2 wrote")
			}
		})
	}
}

func TestCompatIntegrityVolumeIsRefusedForActivation(t *testing.T) {
	requireCryptsetupDeclared(t)
	for _, tc := range []struct {
		name    string
		keyBits string
	}{
		{"hmac-sha256 over a 256-bit key: a 64-byte volume key", "256"},
		{"hmac-sha256 over a 512-bit key: a 96-byte volume key", "512"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer parallel(t)()

			loop := csVolume(t, "--integrity", "hmac-sha256", "--integrity-no-wipe", "--key-size", tc.keyBits)
			before := deviceDigest(t, loop, 16<<20)
			name := runVolume(t, matrixName("matrix-integrity"))
			t.Cleanup(func() { releaseVolume(t, name) })
			if err := Unlock(loop, []byte(matrixPassphrase), name); !errors.Is(err, luks2.ErrUnsupported) {
				t.Fatalf("Unlock of an integrity volume = %v, want ErrUnsupported", err)
			}
			if IsUnlocked(name) {
				t.Fatal("a mapping exists after the refused Unlock")
			}
			if deviceDigest(t, loop, 16<<20) != before {
				t.Fatal("the refused Unlock changed the device")
			}

			// Volume.Unlock refuses the integrity segment before it reads a
			// keyslot (integrity is not supported), so key recovery -- TestKey and the
			// existing credential of AddKey -- is refused for either key size.
			if err := harness.TestKey(loop, []byte(matrixPassphrase)); !errors.Is(err, luks2.ErrUnsupported) {
				t.Fatalf("TestKey on an integrity volume = %v, want ErrUnsupported", err)
			}
			if err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); !errors.Is(err, luks2.ErrUnsupported) {
				t.Fatalf("AddKey on an integrity volume = %v, want ErrUnsupported", err)
			}
			if deviceDigest(t, loop, 16<<20) != before {
				t.Fatal("a refused AddKey changed the device")
			}

			theirs := csMapping(t, loop, []byte(matrixPassphrase))
			csClose(t, theirs)
		})
	}
}

func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, a)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}

func TestCompatCryptsetupsMaximumKeyslotsAndCostsAreNotRefused(t *testing.T) {
	requireCryptsetupDeclared(t)
	defer parallel(t)()

	loop := csVolume(t)
	for slot := 1; slot < luks2.MaxKeyslots-1; slot++ {
		csAddKey(t, loop, "matrix-slot-"+strconv.Itoa(slot))
	}
	const last = "matrix-the-last-keyslot"
	csAddKey(t, loop, last, "--pbkdf", "argon2id", "--pbkdf-memory", "1048576", "--pbkdf-parallel", "4", "--pbkdf-force-iterations", "4")

	_, metadata, err := harness.ReadHeader(loop)
	if err != nil {
		t.Fatalf("ReadHeader of a full cryptsetup header: %v", err)
	}
	if len(metadata.Keyslots) != luks2.MaxKeyslots {
		t.Fatalf("the fixture has %d keyslots, want %d", len(metadata.Keyslots), luks2.MaxKeyslots)
	}
	if err := harness.TestKey(loop, []byte(last)); err != nil {
		t.Fatalf("TestKey through all 32 keyslots of a cryptsetup header: %v", err)
	}

	before := deviceDigest(t, loop, 16<<20)
	if _, ok := cryptsetupWithStdin(t, "", append(append([]string{"luksAddKey", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase))}, matrixCheap...),
		loop, matrixKeyFile(t, []byte(matrixNew)))...); ok {
		t.Fatal("cryptsetup added a 33rd keyslot")
	}
	if err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err == nil {
		t.Fatal("AddKey added a 33rd keyslot")
	}
	if deviceDigest(t, loop, 16<<20) != before {
		t.Fatal("a refused 33rd keyslot changed the header")
	}
}

func TestCompatAmplifiedDigestsAreRefusedByBothTools(t *testing.T) {
	requireCryptsetupDeclared(t)
	defer parallel(t)()

	loop := csVolume(t, "--luks2-metadata-size", "256k")
	hdr, metadata, err := harness.ReadHeader(loop)
	if err != nil {
		t.Fatal(err)
	}
	template := metadata.Keyslots["0"]
	start, _ := strconv.ParseInt(template.Area.Offset, 10, 64)
	size, _ := strconv.ParseInt(template.Area.Size, 10, 64)
	ids := make([]string, luks2.MaxKeyslots)
	for i := range ids {
		k := *template
		area := *template.Area
		area.Offset = strconv.FormatInt(start+int64(i)*size, 10)
		k.Area = &area
		ids[i] = strconv.Itoa(i)
		metadata.Keyslots[ids[i]] = &k
	}
	digest := *metadata.Digests["0"]
	for i := range luks2.MaxKeyslots {
		d := digest
		d.Keyslots, d.Iterations = ids, header.MaxKDFIterations
		metadata.Digests[strconv.Itoa(i)] = &d
	}
	hdr.SequenceID++
	writeRawMetadata(t, loop, hdr, metadata)

	if out, ok := cryptsetupWithStdin(t, matrixPassphrase, "open", "--test-passphrase", loop); ok || !strings.Contains(out, "not a valid LUKS device") {
		t.Fatalf("cryptsetup on the amplified header: ok=%v\n%s", ok, out)
	}
	if err := harness.TestKey(loop, []byte(matrixPassphrase)); !errors.Is(err, luks2.ErrInvalidHeader) {
		t.Fatalf("TestKey on the amplified header = %v, want ErrInvalidHeader", err)
	}
	name := runVolume(t, matrixName("matrix-amplified"))
	t.Cleanup(func() { releaseVolume(t, name) })
	if err := Unlock(loop, []byte(matrixPassphrase), name); !errors.Is(err, luks2.ErrInvalidHeader) {
		t.Fatalf("Unlock on the amplified header = %v, want ErrInvalidHeader", err)
	}
}

func writeRawMetadata(t *testing.T, path string, hdr *header.BinaryHeader, metadata *header.Metadata) {
	t.Helper()
	jsonData, err := header.MarshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := header.WriteEncodedHeader(f, hdr, jsonData, int(hdr.HeaderSize), (*os.File).Sync); err != nil { // #nosec G115 -- read back from a header ReadHeader bounded
		t.Fatalf("write: %v", err)
	}
}

func cryptsetupWithStdin(t *testing.T, stdin string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- test constants and devices this test made
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("running cryptsetup: %v", err)
	}
	return string(out), err == nil
}

func mustCryptsetupPassphrase(t *testing.T, passphrase string, args ...string) string {
	t.Helper()
	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- test constants and devices this test made
	cmd.Stdin = strings.NewReader(passphrase)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cryptsetup %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
