// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"bytes"
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
)

// The two-way interoperability matrix (docs/COMPATIBILITY.md): each operation
// done by one tool and checked by the other, against cryptsetup and the real
// kernel. Rows are data; every row runs in parallel on a volume of its own.
//
// Checked elsewhere and not repeated here: byte-for-byte header equality
// (canonicalconformance_integration_test.go), the FIPS import
// (test/integration/pkg/fipsimport_test.go), the header-only wipe
// (TestHeaderOnlyWipeIsACryptoEraseOnTheMedium) and detached-header activation
// (TestADetachedHeaderIsNeverActivated).

const (
	matrixPassphrase = "matrix-passphrase"
	matrixSecond     = "matrix-second-passphrase"
	matrixNew        = "matrix-new-passphrase"
)

// matrixCheap is the KDF cost of every cryptsetup write here: structure is
// under test, not cost.
var matrixCheap = []string{"--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"}

// matrixAddKeyOptions is the cost of every go-luks2 keyslot write here.
var matrixAddKeyOptions = &AddKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterTime: 1}

// matrixNames numbers the matrix's mappings: runVolume scopes a base to the
// run, not to a call, and the rows run in parallel.
var matrixNames atomic.Int64

// matrixName is a mapping base no other row uses.
func matrixName(base string) string {
	return base + "-" + strconv.FormatInt(matrixNames.Add(1), 10)
}

// matrixKeyFile writes content to a key file of its own.
func matrixKeyFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// csVolume is a loop device cryptsetup formatted with matrixPassphrase and
// args, the cheap KDF first so a row's own --pbkdf overrides it.
func csVolume(t *testing.T, args ...string) string {
	t.Helper()
	loop, _ := activationLoop(t, "matrix.img", 96, nil)
	all := append([]string{"luksFormat", "--type", "luks2", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase))}, matrixCheap...)
	mustCryptsetupPassphrase(t, "", append(append(all, args...), loop)...)
	return loop
}

// libVolume is a loop device go-luks2 formatted with matrixPassphrase.
func libVolume(t *testing.T, opts FormatOptions) string {
	t.Helper()
	loop, _ := activationLoop(t, "matrix.img", 96, nil)
	opts.Device, opts.Passphrase = loop, []byte(matrixPassphrase)
	if opts.KDFType == "" {
		opts.KDFType, opts.PBKDFIterTime = KDFTypePBKDF2, 1
	}
	if err := Format(opts); err != nil {
		t.Fatalf("Format: %v", err)
	}
	return loop
}

// csAddKey adds passphrase with cryptsetup, authorized by matrixPassphrase.
func csAddKey(t *testing.T, device, passphrase string, extra ...string) {
	t.Helper()
	args := append([]string{"luksAddKey", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase))}, matrixCheap...)
	args = append(append(args, extra...), device, matrixKeyFile(t, []byte(passphrase)))
	mustCryptsetupPassphrase(t, "", args...)
}

// csOpens reports whether cryptsetup opens device with passphrase.
func csOpens(t *testing.T, device string, passphrase []byte, extra ...string) bool {
	t.Helper()
	args := append([]string{"open", "--test-passphrase", "--key-file", matrixKeyFile(t, passphrase)}, extra...)
	_, ok := cryptsetupWithStdin(t, "", append(args, device)...)
	return ok
}

// assertCryptsetupReadsIt is what every row ends with after a go-luks2 write:
// cryptsetup recognizes the header, dumps it, and opens it.
func assertCryptsetupReadsIt(t *testing.T, device, passphrase string, extra ...string) {
	t.Helper()
	mustCryptsetupPassphrase(t, "", append([]string{"isLuks", "--type", "luks2"}, append(extra, device)...)...)
	mustCryptsetupPassphrase(t, "", append([]string{"luksDump"}, append(extra, device)...)...)
	if !csOpens(t, device, []byte(passphrase), extra...) {
		t.Fatalf("cryptsetup does not open %s with %q", device, passphrase)
	}
}

// csMapping opens device with cryptsetup under a run-scoped name.
func csMapping(t *testing.T, device string, passphrase []byte) string {
	t.Helper()
	name := runVolume(t, matrixName("matrix-cs"))
	// Closed on every path, a failing one included: the mapping is the
	// host's until it is.
	t.Cleanup(func() {
		if mappingExists(name) {
			_, _ = exec.Command("cryptsetup", "close", name).CombinedOutput() // #nosec G204 -- a run-scoped mapping name
		}
	})
	mustCryptsetupPassphrase(t, "", "open", "--key-file", matrixKeyFile(t, passphrase), device, name)
	return name
}

// mappingExists reports whether device-mapper has a mapping called name.
func mappingExists(name string) bool {
	return exec.Command("dmsetup", "info", name).Run() == nil // #nosec G204 -- a run-scoped mapping name
}

// csClose closes a cryptsetup mapping.
func csClose(t *testing.T, name string) {
	t.Helper()
	mustCryptsetupPassphrase(t, "", "close", name)
}

// mappingRegions writes, or reads back, a pattern at the start and at the end
// of the mapping, through the mapping's node.
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

// assertDataRoundTrip is open/activation in both directions: what
// cryptsetup's mapping writes, go-luks2's reads, and the reverse, at the start
// and the end of the data.
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

// csTokenExport returns cryptsetup's export of a token.
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
	// A recovery key as systemd-cryptenroll prints one: 64 modhex characters
	// in eight dash-separated groups.
	matrixSystemdRecovery = "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv"
)

// matrixRow is one cell of the matrix: an operation, the tool that does it,
// and the check the other tool makes.
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
		if ok, err := IsLUKS2(loop); !ok || err != nil {
			t.Fatalf("IsLUKS2 = %v, %v", ok, err)
		}
		if _, err := GetVolumeInfo(loop); err != nil {
			t.Fatalf("GetVolumeInfo: %v", err)
		}
		if err := TestKey(loop, []byte(matrixPassphrase)); err != nil {
			t.Fatalf("TestKey: %v", err)
		}
		if err := TestKey(loop, []byte(matrixNew)); err == nil {
			t.Fatal("TestKey accepted a wrong passphrase")
		}
	}},
	{"open and data", "both", func(t *testing.T) {
		assertDataRoundTrip(t, csVolume(t), []byte(matrixPassphrase))
		assertDataRoundTrip(t, libVolume(t, FormatOptions{}), []byte(matrixPassphrase))
	}},
	{"add key", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		if _, err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err != nil {
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
		if err := RemoveKey(loop, []byte(matrixSecond), 1); err != nil {
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
		if err := KillSlot(loop, []byte(matrixPassphrase), 1); err != nil {
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
		if err := ChangeKey(loop, []byte(matrixPassphrase), []byte(matrixNew), 0); err != nil {
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
		// A 4 KiB binary key file -- NUL bytes and newlines included -- is
		// the passphrase byte for byte, as cryptsetup reads it.
		loop := libVolume(t, FormatOptions{})
		key := make([]byte, 4096)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		key[0], key[1], key[4095] = 0, '\n', '\n'
		mustCryptsetupPassphrase(t, "", append(append([]string{"luksAddKey", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase))}, matrixCheap...),
			"--new-keyfile", matrixKeyFile(t, key), loop)...)
		if err := TestKey(loop, key); err != nil {
			t.Fatalf("TestKey with cryptsetup's key file: %v", err)
		}
		if err := TestKey(loop, key[:4095]); err == nil {
			t.Fatal("the key file without its trailing newline opened the volume")
		}
	}},
	{"key file", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		key := make([]byte, MaxPassphraseLength)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		key[0], key[len(key)-1] = 0, '\n'
		if _, err := AddKey(loop, []byte(matrixPassphrase), key, matrixAddKeyOptions); err != nil {
			t.Fatalf("AddKey with a binary key: %v", err)
		}
		if !csOpens(t, loop, key) {
			t.Fatal("cryptsetup does not open the binary key go-luks2 enrolled, read from a key file")
		}
		// Stricter: a NEW credential is at most MaxPassphraseLength bytes,
		// where cryptsetup enrolls an 8 MiB key file. Refused, typed, before
		// anything is written.
		before := deviceDigest(t, loop, 16<<20)
		if _, err := AddKey(loop, []byte(matrixPassphrase), make([]byte, 4096), matrixAddKeyOptions); !errors.Is(err, ErrPassphraseTooLong) {
			t.Fatalf("AddKey with a 4 KiB new key = %v, want ErrPassphraseTooLong", err)
		}
		if deviceDigest(t, loop, 16<<20) != before {
			t.Fatal("a refused AddKey changed the header")
		}
	}},
	{"token import (systemd-tpm2 JSON)", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		if err := ImportTokenJSON(loop, 0, []byte(matrixTPM2Token)); err != nil {
			t.Fatalf("ImportTokenJSON: %v", err)
		}
		if !sameJSON(t, csTokenExport(t, loop, "0"), []byte(matrixTPM2Token)) {
			t.Fatalf("cryptsetup exports %s", csTokenExport(t, loop, "0"))
		}
		assertCryptsetupReadsIt(t, loop, matrixPassphrase)
	}},
	{"token import (systemd-fido2)", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		up, pin, uv := true, false, false
		if err := ImportToken(loop, 1, &Token{Type: TokenTypeSystemdFIDO2, Keyslots: []string{"0"},
			FIDO2Credential: "Y3JlZGVudGlhbC1pZA==", FIDO2Salt: "c2FsdC0zMi1ieXRlcy1vZi1zYWx0LWZvci10ZXN0cyE=",
			FIDO2RP: "io.systemd.cryptsetup", FIDO2ClientPinRequired: &pin, FIDO2UPRequired: &up, FIDO2UVRequired: &uv}); err != nil {
			t.Fatalf("ImportToken: %v", err)
		}
		if !sameJSON(t, csTokenExport(t, loop, "1"), []byte(matrixFIDO2Token)) {
			t.Fatalf("cryptsetup exports %s, want %s", csTokenExport(t, loop, "1"), matrixFIDO2Token)
		}
	}},
	{"token import (systemd-fido2, systemd-tpm2 JSON)", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		mustCryptsetupPassphrase(t, "", "token", "import", "--token-id", "1", "--json-file", matrixKeyFile(t, []byte(matrixFIDO2Token)), loop)
		mustCryptsetupPassphrase(t, "", "token", "import", "--token-id", "2", "--json-file", matrixKeyFile(t, []byte(matrixTPM2Token)), loop)
		token, err := GetToken(loop, 1)
		if err != nil {
			t.Fatalf("GetToken: %v", err)
		}
		if token.Type != TokenTypeSystemdFIDO2 || token.FIDO2RP != "io.systemd.cryptsetup" ||
			token.FIDO2UPRequired == nil || !*token.FIDO2UPRequired || token.FIDO2ClientPinRequired == nil || *token.FIDO2ClientPinRequired {
			t.Fatalf("GetToken = %+v", token)
		}
		for id, want := range map[int]string{1: matrixFIDO2Token, 2: matrixTPM2Token} {
			raw, err := ExportToken(loop, id)
			if err != nil || !sameJSON(t, raw, []byte(want)) {
				t.Fatalf("ExportToken(%d) = %s, %v", id, raw, err)
			}
		}
		// Kept through an unrelated rewrite, member for member.
		if _, err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err != nil {
			t.Fatalf("AddKey: %v", err)
		}
		if !sameJSON(t, csTokenExport(t, loop, "2"), []byte(matrixTPM2Token)) {
			t.Fatal("the systemd-tpm2 token changed through AddKey")
		}
	}},
	{"token remove", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		mustCryptsetupPassphrase(t, "", "token", "import", "--token-id", "3", "--json-file", matrixKeyFile(t, []byte(matrixTPM2Token)), loop)
		if err := RemoveToken(loop, 3); err != nil {
			t.Fatalf("RemoveToken: %v", err)
		}
		if _, ok := cryptsetupWithStdin(t, "", "token", "export", "--token-id", "3", loop); ok {
			t.Fatal("cryptsetup still exports the removed token")
		}
		assertCryptsetupReadsIt(t, loop, matrixPassphrase)
	}},
	{"token remove", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		if err := ImportTokenJSON(loop, 3, []byte(matrixTPM2Token)); err != nil {
			t.Fatal(err)
		}
		mustCryptsetupPassphrase(t, "", "token", "remove", "--token-id", "3", loop)
		if ok, err := TokenExists(loop, 3); ok || err != nil {
			t.Fatalf("TokenExists = %v, %v after cryptsetup removed it", ok, err)
		}
	}},
	{"header backup and restore", csToUs, func(t *testing.T) {
		// luksHeaderBackup of a go-luks2 volume, the header destroyed, and
		// luksHeaderRestore: go-luks2 opens it and the data is intact.
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
		if err := Wipe(WipeOptions{Device: loop, HeaderOnly: true}); err != nil {
			t.Fatalf("Wipe: %v", err)
		}
		if ok, _ := IsLUKS(loop); ok {
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
		// A backup restored over a later go-luks2 write: go-luks2 reads the
		// restored state, consistently, and the later keyslot is gone.
		loop := libVolume(t, FormatOptions{})
		backup := filepath.Join(t.TempDir(), "header.backup")
		mustCryptsetupPassphrase(t, "", "luksHeaderBackup", loop, "--header-backup-file", backup)
		if _, err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err != nil {
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
		if err := RestorePrimaryHeader(loop); err != nil {
			t.Fatalf("RestorePrimaryHeader: %v", err)
		}
		assertCryptsetupReadsIt(t, loop, matrixPassphrase)
	}},
	{"wipe keyslot", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		csAddKey(t, loop, matrixSecond)
		if err := WipeKeyslot(loop, 1); err != nil {
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
		if ok, err := IsLUKS2(loop); !ok || err != nil {
			t.Fatalf("IsLUKS2 after luksErase = %v, %v; the header stays", ok, err)
		}
		if err := TestKey(loop, []byte(matrixPassphrase)); err == nil {
			t.Fatal("go-luks2 opens a volume whose keyslots cryptsetup erased")
		}
	}},
	{"recovery key", usToCS, func(t *testing.T) {
		loop := csVolume(t)
		key, err := AddRecoveryKey(loop, []byte(matrixPassphrase), &RecoveryKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterTime: 1})
		if err != nil {
			t.Fatalf("AddRecoveryKey: %v", err)
		}
		defer key.Clear()
		text, err := key.FormattedString()
		if err != nil {
			t.Fatal(err)
		}
		if !csOpens(t, loop, []byte(text)) {
			t.Fatal("cryptsetup does not open the printed recovery key")
		}
		var token map[string]any
		if err := json.Unmarshal(csTokenExport(t, loop, "0"), &token); err != nil || token["type"] != TokenTypeSystemdRecovery {
			t.Fatalf("cryptsetup's export of the recovery token: %v %v", token, err)
		}
	}},
	{"recovery key (systemd-cryptenroll form)", csToUs, func(t *testing.T) {
		loop := libVolume(t, FormatOptions{})
		csAddKey(t, loop, matrixSystemdRecovery)
		mustCryptsetupPassphrase(t, "", "token", "import", "--token-id", "0", "--json-file",
			matrixKeyFile(t, []byte(`{"type":"systemd-recovery","keyslots":["1"]}`)), loop)
		tokens, err := ListTokens(loop)
		if err != nil || tokens[0] == nil || tokens[0].Type != TokenTypeSystemdRecovery {
			t.Fatalf("ListTokens = %v, %v", tokens, err)
		}
		credential, err := RecoveryCredential(matrixSystemdRecovery + "\n")
		if err != nil {
			t.Fatal(err)
		}
		defer releaseSecret(credential)
		if ok, err := VerifyRecoveryKey(loop, credential); !ok || err != nil {
			t.Fatalf("VerifyRecoveryKey = %v, %v", ok, err)
		}
	}},
	{"detached header", csToUs, func(t *testing.T) {
		// cryptsetup luksFormat --header: go-luks2 reads and manages the
		// header file's keyslots, cryptsetup opens the data with them, and
		// go-luks2 refuses to activate it (TestADetachedHeaderIsNeverActivated).
		data, _ := activationLoop(t, "matrix-data.img", 32, nil)
		header := filepath.Join(t.TempDir(), "detached.hdr")
		mustCryptsetupPassphrase(t, "", append(append([]string{"luksFormat", "--type", "luks2", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase))}, matrixCheap...),
			"--header", header, data)...)
		if err := TestKey(header, []byte(matrixPassphrase)); err != nil {
			t.Fatalf("TestKey on the header file: %v", err)
		}
		if _, err := AddKey(header, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err != nil {
			t.Fatalf("AddKey on the header file: %v", err)
		}
		assertCryptsetupReadsIt(t, header, matrixNew)
		if !csOpens(t, data, []byte(matrixNew), "--header", header) {
			t.Fatal("cryptsetup does not open the data with the keyslot go-luks2 added to its detached header")
		}
	}},
}

// assertGoOpensOnly: go-luks2 opens device with good and not with gone.
func assertGoOpensOnly(t *testing.T, device, good, gone string) {
	t.Helper()
	if err := TestKey(device, []byte(good)); err != nil {
		t.Fatalf("TestKey(%q): %v", good, err)
	}
	if err := TestKey(device, []byte(gone)); err == nil {
		t.Fatalf("TestKey(%q) still opens the volume", gone)
	}
}

// TestCompatMatrix runs the operation rows of the matrix.
func TestCompatMatrix(t *testing.T) {
	requireCryptsetupDeclared(t)
	for _, row := range compatMatrix {
		t.Run(row.op+" "+row.dir, func(t *testing.T) {
			defer parallel(t)()
			row.run(t)
		})
	}
}

// cryptsetupFormats are volumes cryptsetup made with options other than its
// defaults. Each is held to the same checks: go-luks2 reads it, opens it,
// maps the same bytes as cryptsetup both ways, and adds a keyslot cryptsetup
// opens, after which cryptsetup still reads the header.
var cryptsetupFormats = []struct {
	name string
	args []string
	// unformatted rows format the volume themselves, in setup.
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
			info, err := GetVolumeInfo(loop)
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
	// A 16-byte volume key, and a keyslot cipher cryptsetup takes from it.
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
		_, metadata, err := ReadHeader(loop)
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

// dmTable is a mapping's table with its key field elided.
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

// TestCompatCryptsetupFormats is the matrix's option rows, cryptsetup to
// go-luks2 and back.
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

			if ok, err := IsLUKS2(loop); !ok || err != nil {
				t.Fatalf("IsLUKS2 = %v, %v", ok, err)
			}
			if _, err := GetVolumeInfo(loop); err != nil {
				t.Fatalf("GetVolumeInfo: %v", err)
			}
			assertGoOpensOnly(t, loop, matrixPassphrase, matrixNew)
			assertDataRoundTrip(t, loop, []byte(matrixPassphrase))
			if _, err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err != nil {
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

// libraryFormats are volumes go-luks2 made with options other than its
// defaults, held to cryptsetup: isLuks, luksDump, open, the data both ways,
// and a keyslot cryptsetup adds that go-luks2 then opens.
var libraryFormats = []struct {
	name string
	opts FormatOptions
}{
	{"pbkdf2 sha256", FormatOptions{KDFType: "pbkdf2-sha256", PBKDFIterTime: 1}},
	{"pbkdf2 sha512", FormatOptions{KDFType: "pbkdf2-sha512", PBKDFIterTime: 1}},
	{"argon2i", FormatOptions{KDFType: KDFTypeArgon2i, Argon2Time: 1, Argon2Memory: MinArgon2MemoryKB, Argon2Parallel: 1}},
	{"argon2id", FormatOptions{KDFType: KDFTypeArgon2id, Argon2Time: 1, Argon2Memory: MinArgon2MemoryKB, Argon2Parallel: 1}},
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
			if err := TestKey(loop, []byte(matrixNew)); err != nil {
				t.Fatalf("TestKey with cryptsetup's keyslot: %v", err)
			}
			if tc.opts.Label != "" && !strings.Contains(mustCryptsetupPassphrase(t, "", "luksDump", loop), "matrix-subsystem") {
				t.Fatal("cryptsetup does not show the subsystem go-luks2 wrote")
			}
		})
	}
}

// TestCompatIntegrityVolumeIsRefusedForActivation: cryptsetup --integrity
// volumes. dm-integrity is out of scope, so activation is refused, typed,
// before anything is mapped, and nothing is written; keyslots whose volume
// key an AES data cipher takes stay manageable, and cryptsetup still opens
// the volume. Before the refusal existed, Unlock mapped dm-crypt straight
// over the integrity device -- the 64-byte case below has a volume key that
// passes every keyslot check -- reading garbage and destroying the
// integrity tags on every write.
func TestCompatIntegrityVolumeIsRefusedForActivation(t *testing.T) {
	requireCryptsetupDeclared(t)
	for _, tc := range []struct {
		name       string
		keyBits    string
		manageable bool
	}{
		{"hmac-sha256 over a 256-bit key: a 64-byte volume key", "256", true},
		{"hmac-sha256 over a 512-bit key: a 96-byte volume key", "512", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer parallel(t)()

			loop := csVolume(t, "--integrity", "hmac-sha256", "--integrity-no-wipe", "--key-size", tc.keyBits)
			before := deviceDigest(t, loop, 16<<20)
			name := runVolume(t, matrixName("matrix-integrity"))
			t.Cleanup(func() { releaseVolume(t, name) })
			if err := Unlock(loop, []byte(matrixPassphrase), name); !errors.Is(err, ErrUnsupportedSegmentLayout) {
				t.Fatalf("Unlock of an integrity volume = %v, want ErrUnsupportedSegmentLayout", err)
			}
			if IsUnlocked(name) {
				t.Fatal("a mapping exists after the refused Unlock")
			}
			if deviceDigest(t, loop, 16<<20) != before {
				t.Fatal("the refused Unlock changed the device")
			}

			if tc.manageable {
				if _, err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err != nil {
					t.Fatalf("AddKey on an integrity volume: %v", err)
				}
				assertCryptsetupReadsIt(t, loop, matrixNew)
			} else {
				if err := TestKey(loop, []byte(matrixPassphrase)); !errors.Is(err, ErrInvalidKeyslot) {
					t.Fatalf("TestKey on a 96-byte volume key = %v, want ErrInvalidKeyslot", err)
				}
				if _, err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err == nil {
					t.Fatal("AddKey wrote a keyslot for a volume key it does not read")
				}
				if deviceDigest(t, loop, 16<<20) != before {
					t.Fatal("a refused AddKey changed the device")
				}
			}

			// cryptsetup still activates it, through dm-integrity.
			theirs := csMapping(t, loop, []byte(matrixPassphrase))
			csClose(t, theirs)
		})
	}
}

// The tokens are compared as JSON, not text: both tools re-encode them.
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

// TestCompatCryptsetupsMaximumKeyslotsAndCostsAreNotRefused is #26's
// interoperability half: the aggregate KDF budget and the parse bounds refuse
// no container cryptsetup makes. cryptsetup fills all 32 keyslots -- the last
// with Argon2id at the largest memory cost it chooses by default (1 GiB, four
// lanes) -- and a passphrase that only the last keyslot opens makes go-luks2
// try every one of them. A 33rd keyslot is refused by both tools.
// TestTheMostExpensiveHeaderCryptsetupCanWriteFitsTheBudget prices the same
// count with every derivation at its ceiling.
func TestCompatCryptsetupsMaximumKeyslotsAndCostsAreNotRefused(t *testing.T) {
	requireCryptsetupDeclared(t)
	defer parallel(t)()

	loop := csVolume(t)
	for slot := 1; slot < LUKS2MaxKeyslots-1; slot++ {
		csAddKey(t, loop, "matrix-slot-"+strconv.Itoa(slot))
	}
	const last = "matrix-the-last-keyslot"
	csAddKey(t, loop, last, "--pbkdf", "argon2id", "--pbkdf-memory", "1048576", "--pbkdf-parallel", "4", "--pbkdf-force-iterations", "4")

	_, metadata, err := ReadHeader(loop)
	if err != nil {
		t.Fatalf("ReadHeader of a full cryptsetup header: %v", err)
	}
	if len(metadata.Keyslots) != LUKS2MaxKeyslots {
		t.Fatalf("the fixture has %d keyslots, want %d", len(metadata.Keyslots), LUKS2MaxKeyslots)
	}
	if err := TestKey(loop, []byte(last)); err != nil {
		t.Fatalf("TestKey through all 32 keyslots of a cryptsetup header: %v", err)
	}

	before := deviceDigest(t, loop, 16<<20)
	if _, ok := cryptsetupWithStdin(t, "", append(append([]string{"luksAddKey", "--key-file", matrixKeyFile(t, []byte(matrixPassphrase))}, matrixCheap...),
		loop, matrixKeyFile(t, []byte(matrixNew)))...); ok {
		t.Fatal("cryptsetup added a 33rd keyslot")
	}
	if _, err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixNew), matrixAddKeyOptions); err == nil {
		t.Fatal("AddKey added a 33rd keyslot")
	}
	if deviceDigest(t, loop, 16<<20) != before {
		t.Fatal("a refused 33rd keyslot changed the header")
	}
}

// TestCompatAmplifiedDigestsAreRefusedByBothTools: a header within the
// count bounds whose 32 digests each name all 32 keyslots, at the iteration
// ceiling. cryptsetup refuses it as invalid (a keyslot named by more than one
// digest); go-luks2 refuses the unlock, typed, before deriving anything --
// the scan would otherwise make 1,024 digest derivations at 100,000,000
// iterations.
func TestCompatAmplifiedDigestsAreRefusedByBothTools(t *testing.T) {
	requireCryptsetupDeclared(t)
	defer parallel(t)()

	loop := csVolume(t, "--luks2-metadata-size", "256k")
	hdr, metadata, err := ReadHeader(loop)
	if err != nil {
		t.Fatal(err)
	}
	template := metadata.Keyslots["0"]
	start, _ := parseSize(template.Area.Offset)
	size, _ := parseSize(template.Area.Size)
	ids := make([]string, LUKS2MaxKeyslots)
	for i := range ids {
		k := *template
		area := *template.Area
		area.Offset = formatSize(start + int64(i)*size)
		k.Area = &area
		ids[i] = strconv.Itoa(i)
		metadata.Keyslots[ids[i]] = &k
	}
	digest := *metadata.Digests["0"]
	for i := range LUKS2MaxKeyslots {
		d := digest
		d.Keyslots, d.Iterations = ids, maxKDFIterations
		metadata.Digests[strconv.Itoa(i)] = &d
	}
	hdr.SequenceID++
	writeRawMetadata(t, loop, hdr, metadata)

	if out, ok := cryptsetupWithStdin(t, matrixPassphrase, "open", "--test-passphrase", loop); ok || !strings.Contains(out, "not a valid LUKS device") {
		t.Fatalf("cryptsetup on the amplified header: ok=%v\n%s", ok, out)
	}
	if err := TestKey(loop, []byte(matrixPassphrase)); !errors.Is(err, ErrKDFBudgetExceeded) {
		t.Fatalf("TestKey on the amplified header = %v, want ErrKDFBudgetExceeded", err)
	}
	name := runVolume(t, matrixName("matrix-amplified"))
	t.Cleanup(func() { releaseVolume(t, name) })
	if err := Unlock(loop, []byte(matrixPassphrase), name); !errors.Is(err, ErrKDFBudgetExceeded) {
		t.Fatalf("Unlock on the amplified header = %v, want ErrKDFBudgetExceeded", err)
	}
}
