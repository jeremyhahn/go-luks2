// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/kdf"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// #26: the aggregate budget of one operation.

// cloneKeyslots gives metadata n keyslots, copies of keyslot 0 at disjoint
// areas, and returns their ids.
func cloneKeyslots(t *testing.T, metadata *header.Metadata, n int) []string {
	t.Helper()
	template := metadata.Keyslots["0"]
	start, err := parseSize(template.Area.Offset)
	if err != nil {
		t.Fatal(err)
	}
	size, err := parseSize(template.Area.Size)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, n)
	for i := range n {
		k := *template
		area := *template.Area
		area.Offset = formatSize(start + int64(i)*size)
		k.Area = &area
		kdf := *template.KDF
		k.KDF = &kdf
		ids[i] = strconv.Itoa(i)
		metadata.Keyslots[ids[i]] = &k
	}
	return ids
}

// budgetFixture is a library-formatted image whose JSON area is large enough
// for 32 keyslots and 32 digests.
func budgetFixture(t *testing.T) string {
	t.Helper()
	device := newImage(t, "budget.img")
	if err := formatForTest(formatOptionsForTest{Device: device, Passphrase: []byte(conformancePassphrase),
		KDFType: kdfTypePBKDF2, PBKDFIterTime: 1, MetadataSize: 256 << 10}); err != nil {
		t.Fatalf("Format: %v", err)
	}
	return device
}

// writeRawHeader writes metadata as it is, both copies, with no validation:
// the header a crafted disk carries.
func writeRawHeader(t *testing.T, path string, hdr *header.BinaryHeader, metadata *header.Metadata) {
	t.Helper()
	jsonData, err := header.MarshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	hdr.SequenceID++
	if err := header.WriteEncodedHeader(f, hdr, jsonData, int(hdr.HeaderSize), (*os.File).Sync); err != nil { // #nosec G115 -- a header ReadHeader bounded
		t.Fatal(err)
	}
}

// countKDFCalls counts keyslot derivations, and makes each fail at once so a
// test of the unfixed code ends quickly instead of deriving at the ceiling.
func countKDFCalls(t *testing.T) (*int, volumeSys) {
	t.Helper()
	calls := 0
	sys := testVolumeSys()
	sys.passphraseKDFOverride = func(context.Context, []byte, *header.KDF, int) (*enclave.Memory, error) {
		calls++
		return nil, errors.New("derivation reached")
	}
	return &calls, sys
}

// TestAHeaderAskingForMoreDerivationThanCryptsetupCanIsRefusedBeforeDeriving:
// 32 keyslots and 32 digests -- within the parse bounds -- but every digest
// names every keyslot, each at the iteration ceiling, so one unlock would make
// 32 x 32 digest derivations at 100,000,000 iterations. cryptsetup refuses
// such a header outright (a keyslot named by more than one digest); this
// package refuses the operation, typed, before the first derivation.
func TestAHeaderAskingForMoreDerivationThanCryptsetupCanIsRefusedBeforeDeriving(t *testing.T) {
	device := budgetFixture(t)
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatal(err)
	}
	ids := cloneKeyslots(t, metadata, MaxKeyslots)
	template := metadata.Digests["0"]
	for i := range MaxKeyslots {
		d := *template
		d.Keyslots = ids
		d.Iterations = header.MaxKDFIterations
		metadata.Digests[strconv.Itoa(i)] = &d
	}
	writeRawHeader(t, device, hdr, metadata)
	calls, sys := countKDFCalls(t)

	for name, run := range map[string]func() error{
		"TestKey": func() error { return testKeyForTestWithSys(device, []byte(conformancePassphrase), sys) },
		"AddKey": func() error {
			_, err := addKeyWithPolicy(context.Background(), device, []byte(conformancePassphrase), []byte("a-new-passphrase"),
				&addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: 1}, callerSuppliedCredential, sys)
			return err
		},
		"KillSlot": func() error { return killSlotForTest(device, []byte(conformancePassphrase), 1, withTestSys(sys)) },
	} {
		err := run()
		if !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("%s = %v, want ErrInvalidHeader", name, err)
		}
	}
	if *calls != 0 {
		t.Fatalf("%d keyslot derivation(s) ran for a header refused for its cost", *calls)
	}
}

// TestTheMostExpensiveHeaderCryptsetupCanWriteFitsTheBudget is the other
// half, and the one that must never regress: MaxKeyslots keyslots, one
// digest each, every derivation at its ceiling -- Argon2 at 4 GiB and 10,000
// passes, PBKDF2-SHA1 at 100,000,000 iterations over a 64-byte area key -- is
// within the budget. The real-container half is
// TestCompatCryptsetupsMaximumKeyslotsAndCostsAreNotRefused.
func TestTheMostExpensiveHeaderCryptsetupCanWriteFitsTheBudget(t *testing.T) {
	defer parallel(t)()
	device := budgetFixture(t)
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatal(err)
	}
	ids := cloneKeyslots(t, metadata, MaxKeyslots)
	template := metadata.Digests["0"]
	metadata.Digests = map[string]*header.Digest{}
	// SHA-1 is the costliest PBKDF2 per output byte; a FIPS 140-3 process
	// runs neither it nor Argon2, so there the ceiling is SHA-512's.
	hash, digestLen := "sha1", 20
	if fips.Probe() {
		hash, digestLen = "sha512", 64
	}
	for i, id := range ids {
		k := metadata.Keyslots[id]
		if i%2 == 0 {
			time, memory, cpus := header.MaxArgon2Time, header.MaxArgon2Memory, 4
			k.KDF = &header.KDF{Type: kdfTypeArgon2id, Salt: k.KDF.Salt, Time: &time, Memory: &memory, CPUs: &cpus}
		} else {
			iterations := header.MaxKDFIterations
			k.KDF = &header.KDF{Type: kdfTypePBKDF2, Hash: hash, Salt: k.KDF.Salt, Iterations: &iterations}
		}
		d := *template
		d.Keyslots = []string{id}
		d.Hash, d.Iterations = hash, header.MaxKDFIterations
		d.Digest = encodeBase64(make([]byte, digestLen))
		metadata.Digests[id] = &d
	}
	if err := header.ValidateHeaderStructure(int(hdr.HeaderSize), metadata); err != nil {
		t.Fatalf("the fixture is not a header cryptsetup could have written: %v", err)
	}
	plan := planKeyslotScan(metadata, header.KeyslotIDsInScanOrder(metadata.Keyslots))
	if plan.work.Exceeds(operationKDFBudget) {
		t.Fatalf("the most expensive cryptsetup header needs %+v, over the budget %+v", plan.work, operationKDFBudget)
	}
	if plan.work.PBKDF2Blocks == 0 || (plan.work.Argon2KiBPasses == 0) != fips.Probe() {
		t.Fatalf("the plan priced %+v; every keyslot this process can run should be priced", plan.work)
	}
}

func TestDerivationWork(t *testing.T) {
	iterations, time, memory := 1000, 4, 65536
	for _, tc := range []struct {
		name string
		kdf  *header.KDF
		out  int
		want kdfWork
	}{
		{"pbkdf2-sha256 to 64 bytes: two blocks", &header.KDF{Type: "pbkdf2", Hash: "sha256", Iterations: &iterations}, 64, kdfWork{PBKDF2Blocks: 2000}},
		{"pbkdf2-sha1 to 64 bytes: four blocks", &header.KDF{Type: "pbkdf2", Hash: "sha1", Iterations: &iterations}, 64, kdfWork{PBKDF2Blocks: 4000}},
		{"pbkdf2-sha512 to 32 bytes: one block", &header.KDF{Type: "pbkdf2", Hash: "sha512", Iterations: &iterations}, 32, kdfWork{PBKDF2Blocks: 1000}},
		{"argon2id", &header.KDF{Type: "argon2id", Time: &time, Memory: &memory}, 64, kdfWork{Argon2KiBPasses: 4 * 65536}},
		{"no KDF", nil, 64, kdfWork{}},
		{"no output", &header.KDF{Type: "pbkdf2", Hash: "sha256", Iterations: &iterations}, 0, kdfWork{}},
		{"argon2 missing its cost", &header.KDF{Type: "argon2i"}, 64, kdfWork{}},
		{"pbkdf2 missing its count", &header.KDF{Type: "pbkdf2", Hash: "sha256"}, 64, kdfWork{}},
	} {
		if got := derivationWork(tc.kdf, tc.out); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	huge := kdfWork{PBKDF2Blocks: ^uint64(0), Argon2KiBPasses: ^uint64(0)}
	if got := huge.Add(kdfWork{PBKDF2Blocks: 1, Argon2KiBPasses: 1}); got != huge {
		t.Fatalf("the sum wrapped: %+v", got)
	}
	if kdf.SaturatingMul(1<<40, 1<<40) != ^uint64(0) || kdf.SaturatingMul(0, 5) != 0 {
		t.Fatal("SaturatingMul")
	}
}

// TestHeadersWithMoreKeyslotsOrDigestsThanCryptsetupCreatesAreRefusedOnRead:
// the parse bound. cryptsetup reads such headers (measured: 200 keyslots, 40
// digests) but writes none, and each extra entry is work a crafted header adds
// to every unlock.
func TestHeadersWithMoreKeyslotsOrDigestsThanCryptsetupCreatesAreRefusedOnRead(t *testing.T) {
	defer parallel(t)()
	for _, tc := range []struct {
		name   string
		mutate func(*header.Metadata, []string)
	}{
		{"33 keyslots", func(m *header.Metadata, ids []string) { m.Digests["0"].Keyslots = ids }},
		{"33 digests", func(m *header.Metadata, ids []string) {
			for k := range m.Keyslots {
				if k != "0" {
					delete(m.Keyslots, k)
				}
			}
			for i := 1; i <= MaxKeyslots; i++ {
				d := *m.Digests["0"]
				d.Keyslots = []string{}
				m.Digests[strconv.Itoa(i)] = &d
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			device := budgetFixture(t)
			hdr, metadata, err := readHeaderForTest(device)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(metadata, cloneKeyslots(t, metadata, MaxKeyslots+1))
			writeRawHeader(t, device, hdr, metadata)
			if _, _, err := readHeaderForTest(device); !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("ReadHeader = %v, want ErrInvalidHeader", err)
			}
		})
	}
}

// TestAKeyslotTheAllocatorCanNeverAdmitIsRefusedBeforeDeriving: the memory
// side. Every enclave is admitted against go-enclave's process allocator; a
// scan whose keyslot needs more locked memory than the allocator's whole
// budget is refused up front, typed, rather than after its derivation.
//
// NOT PARALLEL: custody is package state.
func TestAKeyslotTheAllocatorCanNeverAdmitIsRefusedBeforeDeriving(t *testing.T) {
	device := newImage(t, "admission.img")
	formatWithLibrary(t, device)

	small, err := enclave.NewAllocator(enclave.LockedSize(4096))
	if err != nil {
		t.Fatal(err)
	}
	previous := custody
	t.Cleanup(func() { custody = previous })
	custody = secret.Admitted(func() (*enclave.Allocator, error) { return small, nil })
	calls, sys := countKDFCalls(t)

	err = testKeyForTestWithSys(device, []byte(conformancePassphrase), sys)
	if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("TestKey under a one-page budget = %v, want ErrProtectedMemory matching enclave.ErrBudgetExhausted", err)
	}
	if *calls != 0 {
		t.Fatalf("%d derivation(s) ran before a refusal the plan already knew", *calls)
	}
}

// peakRecorder admits every enclave against a fresh, unbounded-enough
// allocator and records the most locked memory live at once. Allocation is
// the only moment the total rises, so sampling after each one sees the peak.
//
// NOT PARALLEL, in every caller: custody is package state.
func peakRecorder(t *testing.T, budget int64) (*enclave.Allocator, *int64) {
	t.Helper()
	a, err := enclave.NewAllocator(budget)
	if err != nil {
		t.Fatal(err)
	}
	var peak int64
	sample := func(e *enclave.Memory, err error) (*enclave.Memory, error) {
		peak = max(peak, a.InUse())
		return e, err
	}
	admitted := secret.Admitted(func() (*enclave.Allocator, error) { return a, nil })
	measuring := admitted
	measuring.Sized = func(n int) (*enclave.Memory, error) { return sample(admitted.Sized(n)) }
	measuring.Moved = func(b []byte) (*enclave.Memory, error) { return sample(admitted.Moved(b)) }
	measuring.Copied = func(b []byte) (*enclave.Memory, error) { return sample(admitted.Copied(b)) }
	previous := custody
	t.Cleanup(func() { custody = previous })
	custody = measuring
	return a, &peak
}

// scanPeak is the planned peak of the scan TestKey makes on device.
func scanPeak(t *testing.T, device string) int64 {
	t.Helper()
	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatal(err)
	}
	plan := planKeyslotScan(header.VolumeKeyDigestsView(metadata), header.KeyslotIDsInScanOrder(metadata.Keyslots))
	if plan.peakLocked <= 0 {
		t.Fatal("the plan priced no locked memory")
	}
	return plan.peakLocked
}

// TestKeyslotOpenPeakIsWhatTheUnlockAllocates measures the locked memory the
// real keyslot path holds at its peak and requires the plan to name exactly
// that, for each keyslot geometry cryptsetup writes: volume keys of 16, 32 and
// 64 bytes, an area key shorter than the volume key, XTS and CBC areas,
// sha256 and sha512 digests. An allocation added to the path without the plan
// learning of it fails here; the AF diffusion state once did.
//
// NOT PARALLEL: peakRecorder.
func TestKeyslotOpenPeakIsWhatTheUnlockAllocates(t *testing.T) {
	requireCryptsetup(t)
	type geometry struct {
		name string
		args []string
	}
	geometries := []geometry{
		{"default, 64-byte key, sha256 digest", nil},
		{"sha512 digest", []string{"--hash", "sha512"}},
		{"32-byte key", []string{"--key-size", "256"}},
		{"64-byte key, 32-byte area key", []string{"--keyslot-cipher", "aes-xts-plain64", "--keyslot-key-size", "256"}},
		{"16-byte key, aes-cbc-essiv area", []string{"--cipher", "aes-cbc-essiv:sha256", "--key-size", "128"}},
	}
	// A FIPS 140-3 process opens no Argon2 keyslot, so it has no Argon2 open
	// to measure.
	if !fips.Probe() {
		geometries = append(geometries, geometry{"argon2id", []string{"--pbkdf", "argon2id", "--pbkdf-memory", "32768", "--pbkdf-force-iterations", "4"}})
	}
	for _, tc := range geometries {
		t.Run(tc.name, func(t *testing.T) {
			device := newImage(t, "peak.img")
			args := append([]string{"luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"}, tc.args...)
			if code, out := runCryptsetup(t, conformancePassphrase, append(args, device)...); code != 0 {
				t.Fatalf("luksFormat exited %d\n%s", code, out)
			}
			want := scanPeak(t, device)
			_, peak := peakRecorder(t, 1<<30)
			if err := testKeyForTest(device, []byte(conformancePassphrase)); err != nil {
				t.Fatalf("TestKey: %v", err)
			}
			if *peak != want {
				t.Fatalf("the keyslot path held %d locked bytes at its peak; the plan says %d", *peak, want)
			}
		})
	}
}

// TestAnAllocatorSizedToThePlannedPeakOpensTheVolume is the review's case: an
// allocator of exactly the planned peak lets the whole unlock through -- the
// preflight's promise that what it admits, the path can allocate -- and one
// page less is refused by the preflight, before any derivation. The plan used
// to leave out the AF diffusion state, so the exact budget passed the
// preflight, ran the KDF and decrypted, and then failed in the AF merge.
//
// NOT PARALLEL: peakRecorder, passphraseKDF.
func TestAnAllocatorSizedToThePlannedPeakOpensTheVolume(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	want := scanPeak(t, device)

	t.Run("exactly the peak", func(t *testing.T) {
		peakRecorder(t, want)
		if err := testKeyForTest(device, passphrase); err != nil {
			t.Fatalf("TestKey under a budget of the planned peak: %v", err)
		}

		v, err := Open(context.Background(), device)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer func() { _ = v.Close() }()
		pass, err := enclave.NewMemoryCopy(passphrase)
		if err != nil {
			t.Fatalf("could not build the test passphrase enclave: %v", err)
		}
		defer func() { _ = pass.Destroy() }()
		key, err := v.Unlock(context.Background(), pass)
		if err != nil {
			t.Fatalf("Unlock under a budget of the planned peak: %v", err)
		}
		key.Destroy()
	})

	t.Run("one page less", func(t *testing.T) {
		peakRecorder(t, want-enclave.LockedSize(1))
		calls := 0
		sys := testVolumeSys()
		real := sys.passphraseKDF
		sys.passphraseKDFOverride = func(ctx context.Context, p []byte, kdf *header.KDF, n int) (*enclave.Memory, error) {
			calls++
			return real(ctx, p, kdf, n)
		}
		err := testKeyForTestWithSys(device, passphrase, sys)
		if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, enclave.ErrBudgetExhausted) {
			t.Fatalf("TestKey one page under the planned peak = %v, want ErrProtectedMemory matching enclave.ErrBudgetExhausted", err)
		}
		if calls != 0 {
			t.Fatalf("%d derivation(s) ran before a refusal the plan could make", calls)
		}
	})
}
