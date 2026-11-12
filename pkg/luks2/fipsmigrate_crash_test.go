// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto/fips140"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// Crash safety of MigrateToFIPS, proved against cryptsetup (#84).
//
// The ordering argument in fipsmigrate.go -- nothing removed before the new
// keyslot is verified, every digest rewrite attests the same key, each header
// copy durable before the other is touched -- is a claim about EVERY state the
// device can be left in if the process dies or the power goes mid-migration.
// These tests enumerate those states instead of trusting the argument.
//
// # How the states are obtained
//
// The migration opens the device once, to lock it, and makes every write
// through that descriptor (#255); each write STEP starts at keyslotWriteStep,
// where the recorder sees it. The recorder
// snapshots the region the migration may write -- everything before the data
// segment -- at each such open, and once more at the end. Between two
// consecutive snapshots exactly one step ran: the keyslot material, a header
// (both copies), or a wipe.
//
// Two kinds of state follow. A BOUNDARY state is the device between two steps
// -- what a failure, or a crash between steps, leaves -- and
// TestMigrateToFIPSFailingAtEachWriteLeavesAnOpenableVolume stops the
// migration at every one of them. A TORN state is a crash inside a step. Each
// step syncs before the next, and writeHeaderInternal syncs the primary copy
// before it touches the secondary, so inside a header write the torn states
// are: primary torn and secondary old, primary new and secondary old, primary
// new and secondary torn; inside a keyslot-area write, a partly written area.
// TestMigrateToFIPSEveryCrashStateStillOpens builds each of those for every
// step.
//
// # What each state must satisfy
//
//   - cryptsetup recovers the ORIGINAL volume key from it with the passphrase
//     (it picks the newest intact copy and repairs the other itself);
//   - this library recovers the original volume key -- reading the primary,
//     or, when the crash tore the primary, after RestorePrimaryHeader rebuilds
//     it from the secondary, which is this library's documented recovery;
//   - a boundary state finishes importing when MigrateToFIPS is run again; a
//     torn state is shown to read as exactly the boundary state before or after
//     its step, and so finishes the same way.

// crashArgon2Args format a cryptsetup Argon2id volume at the lowest cost the
// reader accepts. What is under test is the write sequence; a calibrated cost
// would only spend the package's -race budget (ci.yml) on every state.
var crashArgon2Args = []string{"--pbkdf", "argon2id",
	"--pbkdf-force-iterations", "4", "--pbkdf-memory", "32", "--pbkdf-parallel", "1", "--batch-mode"}

// crashFormatArgs add a 256-bit volume key: every unlock decrypts and merges a
// keyslot area sized by the key, and the smallest key AES-XTS takes halves
// that work on every state.
var crashFormatArgs = append([]string{"--type", "luks2", "--key-size", "256"}, crashArgon2Args...)

// crashFixture is a cryptsetup Argon2id volume with two Argon2id keyslots --
// migrationPassphrase in 0, otherPassphrase in 1. With sha1Digest, digest 0 is
// rewritten as PBKDF2-SHA1 over the real volume key, so the migration takes
// every kind of write step it has: add a keyslot, migrate a digest, remove two
// keyslots. Without it the digest is cryptsetup's own PBKDF2-SHA256, as on a
// default volume, and there is no digest step.
//
// It returns the image's bytes before the data segment (all the migration may
// write), the data segment's offset, and the volume key.
// crashFixtureCache holds, per process, each crashFixture shape and the
// complete migration recorded from it (recordedMigration). Building one runs
// cryptsetup and a migration; every test that needs one only reads it.
var crashFixtureCache struct {
	sync.Mutex
	fixture map[bool]*crashFixtureEntry
}

// crashFixtureEntry is one cached shape.
type crashFixtureEntry struct {
	prefix     []byte
	dataOffset int64
	key        []byte
	// The migration from prefix, recorded once by recordedMigration.
	recorded bool
	steps    []crashStep
	result   *fipsMigrationResultForTest
	final    []byte
}

// crashFixture is buildCrashFixture, built once per shape per process. Its
// digest-cost pin is still applied to every caller, because it is a seam each
// test installs for itself.
func crashFixture(t *testing.T, sha1Digest bool) (prefix []byte, dataOffset int64, key []byte) {
	t.Helper()

	e := crashFixtureFor(t, sha1Digest)
	return e.prefix, e.dataOffset, e.key
}

func crashFixtureFor(t *testing.T, sha1Digest bool) *crashFixtureEntry {
	t.Helper()

	crashFixtureCache.Lock()
	defer crashFixtureCache.Unlock()
	if e, ok := crashFixtureCache.fixture[sha1Digest]; ok {
		return e
	}
	prefix, dataOffset, key := buildCrashFixture(t, sha1Digest)
	if crashFixtureCache.fixture == nil {
		crashFixtureCache.fixture = map[bool]*crashFixtureEntry{}
	}
	e := &crashFixtureEntry{prefix: prefix, dataOffset: dataOffset, key: key}
	crashFixtureCache.fixture[sha1Digest] = e
	return e
}

// recordedMigration is the complete migration of the crashFixture shape,
// recorded once per process: its write steps, its result, and the metadata
// region as it left it. The caller must not modify what it returns.
func recordedMigration(t *testing.T, sha1Digest bool) (*crashFixtureEntry, []crashStep) {
	t.Helper()

	e := crashFixtureFor(t, sha1Digest)
	crashFixtureCache.Lock()
	recorded := e.recorded
	crashFixtureCache.Unlock()
	if !recorded {
		r, result, err, final := migrateRecording(t, e.prefix, 0)
		if err != nil {
			t.Fatalf("MigrateToFIPS failed: %v", err)
		}
		crashFixtureCache.Lock()
		e.steps, e.result, e.final, e.recorded = r.writeSteps(final), result, final, true
		crashFixtureCache.Unlock()
	}
	return e, e.steps
}

// buildCrashFixture builds crashFixture's container.
func buildCrashFixture(t *testing.T, sha1Digest bool) (prefix []byte, dataOffset int64, key []byte) {
	t.Helper()

	// Every resumed import rewrites the digest, through a real (uncalibrated
	// override) calibration: no caller here tests a digest's cost.
	image := filepath.Join(t.TempDir(), "crash-fixture.img")
	placeImage(t, image, cryptsetupArgon2Prefix(t, true))

	key = volumeKey(t, image, migrationPassphrase)
	wantDigests := 0
	if sha1Digest {
		rewriteDigestAsSHA1(t, image, key)
		wantDigests = 1
	}

	_, metadata, err := readHeaderForTest(image)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslots, digests := nonApprovedKDFs(metadata)
	if len(keyslots) != 2 || len(digests) != wantDigests || (sha1Digest && digests[0].Hash != "sha1") {
		t.Fatalf("fixture has non-approved keyslots %v and digests %v, want two argon2id keyslots and %d pbkdf2-sha1 digest(s)",
			keyslots, digests, wantDigests)
	}
	if got := cryptsetupVolumeKey(t, image); got != fmt.Sprintf("%x", key) {
		t.Fatal("cryptsetup does not recover the volume key from the fixture; it is not a valid LUKS2 volume")
	}

	dataOffset, err = parseSize(metadata.Segments["0"].Offset)
	if err != nil {
		t.Fatalf("segment offset: %v", err)
	}
	return readPrefix(t, image, dataOffset), dataOffset, key
}

// rewriteDigestAsSHA1 replaces digest 0 with a PBKDF2-SHA1 digest over key, at
// cryptsetup's floor of 1000 iterations -- what cryptsetup itself writes for a
// volume formatted with --hash sha1.
func rewriteDigestAsSHA1(t *testing.T, image string, key []byte) {
	t.Helper()

	hdr, metadata, err := readHeaderForTest(image)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	iterations := 1000
	digest := metadata.Digests["0"]
	digest.Hash = "sha1"
	digest.Iterations = iterations
	mk, err := custody.Clone("crash fixture volume key", key)
	if err != nil {
		t.Fatalf("custody.Clone: %v", err)
	}
	defer mustDestroy(t, mk)
	derived, err := deriveKeySecret(context.Background(), mk, &header.KDF{Type: kdfTypePBKDF2, Hash: "sha1", Salt: digest.Salt, Iterations: &iterations}, 20, testVolumeSys())
	if err != nil {
		t.Fatalf("deriving the sha1 digest failed: %v", err)
	}
	defer mustDestroy(t, derived)
	if err := secret.Borrow("crash fixture digest", derived, func(b []byte) error {
		digest.Digest = encodeBase64(b)
		return nil
	}); err != nil {
		t.Fatalf("borrow: %v", err)
	}
	hdr.SequenceID++
	if err := writeHeaderInternal(image, hdr, metadata); err != nil {
		t.Fatalf("writing the sha1 digest failed: %v", err)
	}
}

// readPrefix returns the first n bytes of path.
func readPrefix(t *testing.T, path string, n int64) []byte {
	t.Helper()

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, n)
	if _, err := io.ReadFull(f, b); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// placeImage makes path's first len(prefix) bytes equal prefix, creating it
// as a sparse image of the conformance size if it does not exist. Only the
// sectors that differ are written: every state differs from the last in a few
// header and keyslot sectors, and rewriting the whole region each time would
// spend the package's -race budget (ci.yml) on I/O that proves nothing.
func placeImage(t *testing.T, path string, prefix []byte) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Truncate(conformanceImageSize); err != nil {
		t.Fatalf("size %s: %v", path, err)
	}
	current := make([]byte, len(prefix))
	if _, err := io.ReadFull(f, current); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for off := 0; off < len(prefix); off += crashSector {
		end := min(off+crashSector, len(prefix))
		if bytes.Equal(current[off:end], prefix[off:end]) {
			continue
		}
		if _, err := f.WriteAt(prefix[off:end], int64(off)); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

// errInjectedOpen is the fault the recorder injects: the device lock's open,
// or a write step, fails before anything is written.
var errInjectedOpen = errors.New("injected: the device could not be opened, or a write step could not start")

// writeStepRecorder snapshots device's first limit bytes at the open the
// device lock takes and at the start of every write step on the pinned
// descriptor (keyslotWriteStep), and fails the failAt-th of those (1-based;
// 0 never).
//
// The migration opens the device once (#255): the steps are observed on the
// descriptor, not counted as path opens, so a step that wrote through some
// other descriptor would not be a step here -- and is what
// TestMigrateToFIPSWritesOnlyTheDeviceItLocked rules out.
type writeStepRecorder struct {
	device string
	limit  int64
	failAt int
	opens  int
	snaps  [][]byte
	sys    volumeSys
}

// install populates r.sys with openFile and keyslotWriteStep fields that
// record write steps; the caller threads r.sys into the operation under test.
func (r *writeStepRecorder) install(t *testing.T, base volumeSys) {
	t.Helper()

	r.sys = base
	step := func() error {
		r.opens++
		if r.opens == r.failAt {
			return errInjectedOpen
		}
		r.snaps = append(r.snaps, readPrefix(t, r.device, r.limit))
		return nil
	}
	previousOpen, previousStep := r.sys.openFile, r.sys.keyslotWriteStep
	r.sys.openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if name == r.device && flag&(os.O_WRONLY|os.O_RDWR) != 0 {
			if err := step(); err != nil {
				return nil, err
			}
		}
		return previousOpen(name, flag, perm)
	}
	r.sys.keyslotWriteStep = func(ctx context.Context, d *keyslotDevice, op string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.path == r.device {
			if err := step(); err != nil {
				return err
			}
		}
		return previousStep(ctx, d, op)
	}
}

// crashStep is one write step: the region before and after it.
type crashStep struct {
	open          int // which recorded event began it, 1-based
	before, after []byte
}

// writeSteps pairs consecutive snapshots, and the last with final, keeping the
// pairs that changed something. An open that wrote nothing -- the device lock
// -- is not a step.
func (r *writeStepRecorder) writeSteps(final []byte) []crashStep {
	var steps []crashStep
	for i, before := range r.snaps {
		after := final
		if i+1 < len(r.snaps) {
			after = r.snaps[i+1]
		}
		if !bytes.Equal(before, after) {
			steps = append(steps, crashStep{open: i + 1, before: before, after: after})
		}
	}
	return steps
}

// crashSector is the granularity a crash is modeled at: a write reaches the
// medium in whole sectors or not at all.
const crashSector = 512

// tornState is one state a crash inside a step leaves, and the header sequence
// id this library must read from it -- after RestorePrimaryHeader when the
// primary is torn.
type tornState struct {
	class   string
	image   []byte
	wantSeq uint64
}

// headerSeq is the sequence id in the binary header at the start of b.
func headerSeq(b []byte) uint64 { return binary.BigEndian.Uint64(b[16:24]) }

// tornStates returns the states a crash inside step can leave. headerArea is
// the size of one header copy: a step that changes bytes below twice that is a
// header write, and anything else is a keyslot area.
func tornStates(step crashStep, headerArea int) []tornState {
	var primary, secondary, area []int
	for off := 0; off < len(step.before); off += crashSector {
		end := min(off+crashSector, len(step.before))
		if bytes.Equal(step.before[off:end], step.after[off:end]) {
			continue
		}
		switch {
		case off < headerArea:
			primary = append(primary, off)
		case off < 2*headerArea:
			secondary = append(secondary, off)
		default:
			area = append(area, off)
		}
	}
	splice := func(sectors ...[]int) []byte {
		state := bytes.Clone(step.before)
		for _, list := range sectors {
			for _, off := range list {
				end := min(off+crashSector, len(state))
				copy(state[off:end], step.after[off:end])
			}
		}
		return state
	}
	half := func(list []int) []int { return list[:len(list)/2] }

	before, after := headerSeq(step.before), headerSeq(step.after)
	switch {
	case len(primary) == 0 && len(secondary) > 0:
		// A write of the secondary copy alone: repairSecondaryHeader.
		return []tornState{{class: "secondary torn", image: splice(half(secondary)), wantSeq: before}}
	case len(primary) == 0:
		return []tornState{{class: "area half written", image: splice(half(area)), wantSeq: before}}
	}
	return []tornState{
		{class: "primary torn", image: splice(half(primary)), wantSeq: before},
		{class: "primary new, secondary old", image: splice(primary), wantSeq: after},
		{class: "secondary torn", image: splice(primary, half(secondary)), wantSeq: after},
	}
}

// migrateRecording runs MigrateToFIPS on a copy of prefix with the recorder
// installed, and returns the recorder, the result, the error, and the region as
// the migration left it.
func migrateRecording(t *testing.T, prefix []byte, failAt int) (*writeStepRecorder, *fipsMigrationResultForTest, error, []byte) {
	t.Helper()

	image := filepath.Join(t.TempDir(), "migrated.img")
	placeImage(t, image, prefix)
	r := &writeStepRecorder{device: image, limit: int64(len(prefix)), failAt: failAt}
	r.install(t, testVolumeSys())
	result, err := migrateToFIPSAt(context.Background(), image, migrationPassphrase, cheapMigration(), r.sys)
	return r, result, err, readPrefix(t, image, int64(len(prefix)))
}

// assertStateOpens is the per-state contract every state meets: cryptsetup
// and this library both recover the original volume key. It returns whether
// the primary header was torn, whether the secondary was, and the sequence id
// of the header this library opened -- the primary, or, when that was torn,
// the one RestorePrimaryHeader rebuilt it from. The library's image is left
// in dir as library.img.
func assertStateOpens(t *testing.T, dir string, state []byte, key []byte) (primaryTorn, secondaryTorn bool, seq uint64) {
	t.Helper()

	// cryptsetup, on its own copy: it may repair the header it reads.
	theirs := filepath.Join(dir, "cryptsetup.img")
	placeImage(t, theirs, state)
	if got := cryptsetupVolumeKey(t, theirs); got != fmt.Sprintf("%x", key) {
		t.Fatal("cryptsetup recovers a different volume key from this state")
	}

	ours := filepath.Join(dir, "library.img")
	placeImage(t, ours, state)
	shdr, _, err := readSecondaryHeaderForTest(ours)
	if err != nil {
		secondaryTorn = true
	}
	if _, _, err := readHeaderForTest(ours); err != nil {
		primaryTorn = true
		if secondaryTorn {
			t.Fatalf("both header copies are unreadable in this state; primary: %v", err)
		}
		if err := restorePrimaryHeaderForTest(ours); err != nil {
			t.Fatalf("the primary is torn and RestorePrimaryHeader cannot rebuild it from the secondary: %v", err)
		}
	}
	hdr, _, err := readHeaderForTest(ours)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := volumeKey(t, ours, migrationPassphrase); !bytes.Equal(got, key) {
		t.Fatal("this library recovers a different volume key from this state")
	}
	if primaryTorn {
		// The restore writes one past the copy it rebuilt from (#248), so the
		// state it opened is the secondary's.
		if hdr.SequenceID != shdr.SequenceID+1 {
			t.Fatalf("RestorePrimaryHeader wrote sequence %d from a secondary at %d, want one past it", hdr.SequenceID, shdr.SequenceID)
		}
		return primaryTorn, secondaryTorn, shdr.SequenceID
	}
	return primaryTorn, secondaryTorn, hdr.SequenceID
}

// assertImportResumes runs MigrateToFIPS again on image and requires it to
// finish the import with the volume key unchanged.
func assertImportResumes(t *testing.T, image string, key []byte) {
	t.Helper()

	result, err := migrateToFIPSForTest(image, migrationPassphrase, cheapMigration())
	if err != nil {
		t.Fatalf("re-running MigrateToFIPS on this state failed: %v", err)
	}
	if !result.Complete {
		t.Fatalf("re-running MigrateToFIPS on this state left it incomplete: %+v", result)
	}
	assertFIPSReady(t, image)
	if got := volumeKey(t, image, migrationPassphrase); !bytes.Equal(got, key) {
		t.Fatal("the resumed import changed the volume key")
	}
}

// TestMigrateToFIPSEveryCrashStateStillOpens builds every state a crash or
// power loss INSIDE a write step of the migration can leave, and requires each
// to open -- in cryptsetup and in this library -- to the original volume key,
// and to read as exactly the boundary state before or after its step, from
// which TestMigrateToFIPSFailingAtEachWriteLeavesAnOpenableVolume proves the
// import resumes.
func TestMigrateToFIPSEveryCrashStateStillOpens(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	e, steps := recordedMigration(t, true)
	prefix, key, result := e.prefix, e.key, e.result
	if !result.Complete || !result.KeyslotAdded || !slices.Equal(result.MigratedDigests, []string{"0"}) ||
		!slices.Equal(result.RemovedKeyslots, []string{"0", "1"}) {
		t.Fatalf("migration result %+v, want a keyslot added, digest 0 migrated, keyslots 0 and 1 removed", result)
	}

	// The step sequence the ordering argument names, measured: keyslot
	// material, header (keyslot added), header (digest migrated), then a wipe
	// and a header per removed keyslot. A refactor that merges or reorders them
	// changes this and must re-argue the crash states.
	if len(steps) != 7 {
		t.Fatalf("observed %d write steps, want 7 (material, add header, digest header, 2 x (wipe, header))", len(steps))
	}
	headerArea := int(binary.BigEndian.Uint64(prefix[8:16]))

	// Each state is checked in its own subtest, in parallel: the checks
	// read files and run cryptsetup, and write no package-level state.
	classes := map[string]int{}
	for i, step := range steps {
		for _, state := range tornStates(step, headerArea) {
			classes[state.class]++
			t.Run(fmt.Sprintf("step%d/%s", i+1, state.class), func(t *testing.T) {
				defer parallel(t)()
				primaryTorn, secondaryTorn, seq := assertStateOpens(t, t.TempDir(), state.image, key)
				if primaryTorn != (state.class == "primary torn") || secondaryTorn != (state.class == "secondary torn") {
					t.Fatalf("primary torn = %v, secondary torn = %v; the state is not the %q it was built as",
						primaryTorn, secondaryTorn, state.class)
				}
				if seq != state.wantSeq {
					t.Fatalf("this library opened header sequence %d, want %d: the state does not read as the boundary state on that side of its step",
						seq, state.wantSeq)
				}
			})
		}
	}

	// Four header writes and three keyslot-area writes (the new material and
	// two wipes), each with every torn state it can leave.
	want := map[string]int{"primary torn": 4, "primary new, secondary old": 4, "secondary torn": 4, "area half written": 3}
	if !maps.Equal(classes, want) {
		t.Fatalf("torn states built per class %v, want %v", classes, want)
	}
}

// TestMigrateToFIPSFailingAtEachWriteLeavesAnOpenableVolume fails the
// migration at each of its device writes in turn -- an error, not a crash --
// and requires the reported State to match where it stopped, the volume to
// open to the original key in cryptsetup and in this library, and a second
// run to finish the import.
func TestMigrateToFIPSFailingAtEachWriteLeavesAnOpenableVolume(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	prefix, _, key := crashFixture(t, true)

	// Write-opens in the order the migration makes them: the lock, then the
	// write steps of TestMigrateToFIPSEveryCrashStateStillOpens up to the
	// first removal's header. The second removal's wipe and header stop in
	// the same states as the first's, so they are not run again: the -race
	// budget (ci.yml) is spent on states that differ.
	cases := []struct {
		name  string
		stage string
		state string
		// unchanged: the failure precedes every write.
		unchanged bool
	}{
		{"lock", "precondition", fipsStateUntouched, true},
		{"keyslot material", "add keyslot", fipsStateOriginals, true},
		{"add header", "add keyslot", fipsStateOriginals, false},
		{"digest header", "migrate digest", fipsStateOriginals, false},
		{"first wipe", "remove keyslot", fipsStateRemoving, false},
		{"first removal header", "remove keyslot", fipsStateRemoving, false},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err, left := migrateRecording(t, prefix, i+1)
			if !errors.Is(err, errInjectedOpen) {
				t.Fatalf("got %v, want the injected open failure", err)
			}
			var merr *FIPSMigrationError
			if !errors.As(err, &merr) || merr.Stage != tc.stage || merr.State != tc.state {
				t.Fatalf("got %#v, want stage %q reporting %q", err, tc.stage, tc.state)
			}
			if tc.unchanged != bytes.Equal(left, prefix) {
				t.Fatalf("device unchanged = %v, want %v", bytes.Equal(left, prefix), tc.unchanged)
			}
			// migrateRecording has removed the fault: the state must open, and
			// the import must finish, with nothing injected.
			dir := t.TempDir()
			if p, s, _ := assertStateOpens(t, dir, left, key); p || s {
				t.Fatal("a failed write step left a torn header copy; only a crash may")
			}
			// A failure before any write leaves the fixture itself, from
			// which the complete import is TestMigrateToFIPSEveryCrashStateStillOpens's
			// own run; resuming it again would prove nothing new.
			if !tc.unchanged {
				assertImportResumes(t, filepath.Join(dir, "library.img"), key)
			}
		})
	}
}

// TestWriteHeaderMakesThePrimaryDurableBeforeTheSecondary: at the first sync of
// a header write the primary copy is new and the secondary still old, and at
// the second both are new. Without the barrier between them, a power loss
// during writeback could tear both copies.
func TestWriteHeaderMakesThePrimaryDurableBeforeTheSecondary(t *testing.T) {
	device := newImage(t, "header-barrier.img")
	formatWithLibrary(t, device)
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	old := hdr.SequenceID
	hdr.SequenceID++

	type seen struct{ primary, secondary uint64 }
	var syncs []seen
	sys := testVolumeSys()
	real := sys.syncDevice
	sys.syncDevice = func(f *os.File) error {
		p, _, err := readHeaderForTest(device)
		if err != nil {
			t.Fatalf("primary unreadable at a sync point: %v", err)
		}
		s, _, err := readSecondaryHeaderForTest(device)
		if err != nil {
			t.Fatalf("secondary unreadable at a sync point: %v", err)
		}
		syncs = append(syncs, seen{p.SequenceID, s.SequenceID})
		return real(f)
	}

	if err := writeHeaderInternalWithSys(device, hdr, metadata, sys); err != nil {
		t.Fatalf("writeHeaderInternal failed: %v", err)
	}
	want := []seen{{old + 1, old}, {old + 1, old + 1}}
	if !slices.Equal(syncs, want) {
		t.Fatalf("sequence ids (primary, secondary) at each sync = %v, want %v", syncs, want)
	}
}

// TestWriteHeaderStopsBeforeTheSecondaryWhenThePrimarySyncFails: a primary that
// could not be made durable is not followed by a secondary written on top of
// it. The secondary keeps the previous header, complete.
func TestWriteHeaderStopsBeforeTheSecondaryWhenThePrimarySyncFails(t *testing.T) {
	device := newImage(t, "header-barrier-fails.img")
	formatWithLibrary(t, device)
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	old := hdr.SequenceID
	hdr.SequenceID++

	errSync := errors.New("injected sync failure")
	sys := testVolumeSys()
	sys.syncDevice = func(*os.File) error { return errSync }

	if err := writeHeaderInternalWithSys(device, hdr, metadata, sys); !errors.Is(err, errSync) {
		t.Fatalf("got %v, want the injected sync failure", err)
	}
	s, _, err := readSecondaryHeaderForTest(device)
	if err != nil {
		t.Fatalf("the secondary is unreadable after a failed primary sync: %v", err)
	}
	if s.SequenceID != old {
		t.Fatalf("secondary sequence id = %d, want the previous %d: it was written after the primary sync failed", s.SequenceID, old)
	}
}

// TestMigrateToFIPSResumedAfterACrashKeepsAWayIn is the interrupted-retry case:
// a crash during the header write that adds the PBKDF2 keyslot leaves a
// primary naming it beside a secondary that does not (or a torn secondary).
// Running the import again from there must still never reach a state with no
// way in -- in particular, wiping the Argon2 keyslot while the secondary names
// only it, so that tearing the primary next leaves a readable copy naming
// nothing but wiped material. The volume carries cryptsetup's own SHA-256
// digest, as a default volume does, so no digest rewrite happens to reconcile
// the copies by accident.
func TestMigrateToFIPSResumedAfterACrashKeepsAWayIn(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	e, steps := recordedMigration(t, false)
	prefix, key := e.prefix, e.key
	if len(steps) != 6 {
		t.Fatalf("observed %d write steps, want 6 (material, add header, 2 x (wipe, header))", len(steps))
	}
	headerArea := int(binary.BigEndian.Uint64(prefix[8:16]))
	addHeader := steps[1]

	// A torn PRIMARY is not a start state here: the run refuses before
	// writing (ReadHeader fails), and a volume repaired with
	// RestorePrimaryHeader is the "before" header of the step, from which
	// TestMigrateToFIPSReportsADamagedPrimaryAfterAFailedHeaderWrite resumes.
	for _, start := range tornStates(addHeader, headerArea) {
		if start.class == "primary torn" {
			continue
		}
		t.Run(start.class, func(t *testing.T) {
			// Parallel as well, never a sequential middle level: its own
			// subtests take slots, and a sequential level between them and a
			// slot-holding parent is the shape parallel(t) warns deadlocks.
			defer parallel(t)()
			r, result, err, final := migrateRecording(t, start.image, 0)

			if err != nil || !result.Complete {
				t.Fatalf("the resumed import: result %+v, error %v; want complete", result, err)
			}
			resumed := r.writeSteps(final)
			// The first write repairs the secondary copy, and only it.
			first := resumed[0]
			if !bytes.Equal(first.before[:headerArea], first.after[:headerArea]) ||
				!bytes.Equal(first.before[2*headerArea:], first.after[2*headerArea:]) {
				t.Fatal("the resumed run's first write is not a repair of the secondary header copy alone")
			}
			// The window the reconcile closes runs from the first write to the
			// header write after the first wipe: from there both copies agree
			// again, and every later state is one the main crash matrix
			// already proves from agreeing copies.
			if len(resumed) < 3 {
				t.Fatalf("the resumed run made %d write steps, want at least the repair, a wipe and its header", len(resumed))
			}
			for i, step := range resumed[:3] {
				for _, state := range tornStates(step, headerArea) {
					t.Run(fmt.Sprintf("resume step%d/%s", i+1, state.class), func(t *testing.T) {
						defer parallel(t)()
						_, _, seq := assertStateOpens(t, t.TempDir(), state.image, key)
						if seq != state.wantSeq {
							t.Fatalf("this library opened header sequence %d, want %d", seq, state.wantSeq)
						}
					})
				}
			}
		})
	}
}

// damagePrimary overwrites part of device's primary JSON area, as a write that
// failed partway leaves it: the checksum no longer matches.
func damagePrimary(t *testing.T, device string) {
	t.Helper()

	f, err := os.OpenFile(device, os.O_RDWR, 0) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("open %s: %v", device, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xa5}, crashSector), header.HeaderSize); err != nil {
		t.Fatalf("damaging the primary failed: %v", err)
	}
}

// damageSecondary does the same to the secondary copy.
func damageSecondary(t *testing.T, device string) {
	t.Helper()

	hdr, _, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	f, err := os.OpenFile(device, os.O_RDWR, 0) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("open %s: %v", device, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xa5}, crashSector), int64(hdr.HeaderSize)+header.HeaderSize); err != nil {
		t.Fatalf("damaging the secondary failed: %v", err)
	}
}

// onSync substitutes syncDevice: hook runs at the n-th call (1-based) and its
// result is returned instead of syncing.
func onSync(t *testing.T, n int, hook func(f *os.File) error) volumeSys {
	t.Helper()

	sys := testVolumeSys()
	real := sys.syncDevice
	calls := 0
	sys.syncDevice = func(f *os.File) error {
		calls++
		if calls == n {
			return hook(f)
		}
		return real(f)
	}
	return sys
}

// errInjectedSync is the sync failure the tests below inject.
var errInjectedSync = errors.New("injected: the header write could not be made durable")

// TestMigrateToFIPSReportsADamagedPrimaryAfterAFailedHeaderWrite: a header
// write that fails having damaged the primary copy is reported as exactly
// that -- the secondary holds the previous header, and RestorePrimaryHeader
// rebuilds the primary -- never as "opens as before" or "the keyslot opens the
// volume", which the library's own open would contradict. The volume then
// opens in cryptsetup and, after RestorePrimaryHeader, in this library, and a
// second run finishes the import.
func TestMigrateToFIPSReportsADamagedPrimaryAfterAFailedHeaderWrite(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	prefix, _, key := crashFixture(t, true)
	// syncDevice calls in order: the run's durability barrier, then two per
	// header write, the first of each pair the barrier between the copies.
	// Header writes in order: add, digest, two removals.
	// One before the first removal and one after it: the two states the
	// report can be in.
	cases := []struct {
		name    string
		barrier int
		stage   string
		state   string
	}{
		{"add header", 2, "add keyslot", fipsStatePrimaryDamagedOriginals},
		{"first removal header", 6, "remove keyslot", fipsStatePrimaryDamagedRemoving},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			image := filepath.Join(t.TempDir(), "damaged.img")
			placeImage(t, image, prefix)
			sys := onSync(t, tc.barrier, func(*os.File) error {
				damagePrimary(t, image)
				return errInjectedSync
			})
			_, err := migrateToFIPSAt(context.Background(), image, migrationPassphrase, cheapMigration(), sys)

			var merr *FIPSMigrationError
			if !errors.Is(err, errInjectedSync) || !errors.As(err, &merr) || merr.Stage != tc.stage || merr.State != tc.state {
				t.Fatalf("got %#v, want stage %q reporting %q", err, tc.stage, tc.state)
			}
			dir := t.TempDir()
			primaryTorn, secondaryTorn, _ := assertStateOpens(t, dir, readPrefix(t, image, int64(len(prefix))), key)
			if !primaryTorn || secondaryTorn {
				t.Fatalf("primary torn = %v, secondary torn = %v; want only the primary damaged", primaryTorn, secondaryTorn)
			}
			assertImportResumes(t, filepath.Join(dir, "library.img"), key)
		})
	}
}

// TestMigrateToFIPSStopsWhenTheHeaderCopiesDisagreeAfterItsWrites: a secondary
// copy damaged after the keyslot was added -- by anything -- is caught by the
// verification before a single keyslot is removed.
func TestMigrateToFIPSStopsWhenTheHeaderCopiesDisagreeAfterItsWrites(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	prefix, _, _ := crashFixture(t, false)
	image := filepath.Join(t.TempDir(), "secondary-damaged.img")
	placeImage(t, image, prefix)
	// The second sync of the add-header write (the run's durability barrier
	// is the first sync of all), after both copies: the write itself
	// succeeds and the secondary is then damaged.
	sys := onSync(t, 3, func(f *os.File) error {
		if err := f.Sync(); err != nil {
			return err
		}
		damageSecondary(t, image)
		return nil
	})
	_, err := migrateToFIPSAt(context.Background(), image, migrationPassphrase, cheapMigration(), sys)

	var merr *FIPSMigrationError
	if !errors.Is(err, errFIPSMigrationVerification) || !errors.As(err, &merr) ||
		merr.Stage != "verify" || merr.State != fipsStateOriginals {
		t.Fatalf("got %#v, want a verify-stage refusal with no keyslot removed", err)
	}
	_, metadata, err := readHeaderForTest(image)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if keyslots, _ := nonApprovedKDFs(metadata); len(keyslots) != 2 {
		t.Fatalf("non-approved keyslots %v remain, want both originals: nothing may be removed", keyslots)
	}
}

// TestMigrateToFIPSReconcileFailureLeavesThePrimaryAlone: when repairing a
// stale secondary fails at its durability barrier, the run stops before
// writing anything -- the primary, the copy the volume opens through, and the
// secondary are byte for byte what they were.
func TestMigrateToFIPSReconcileFailureLeavesThePrimaryAlone(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	prefix, _, key := crashFixture(t, false)
	image := filepath.Join(t.TempDir(), "stale-secondary.img")
	placeImage(t, image, prefix)
	damageSecondary(t, image)
	before := readPrefix(t, image, int64(len(prefix)))

	// The run's own durability barrier is the first sync; the repair's
	// barrier is the second.
	sys := onSync(t, 2, func(*os.File) error { return errInjectedSync })
	_, err := migrateToFIPSAt(context.Background(), image, migrationPassphrase, cheapMigration(), sys)

	var merr *FIPSMigrationError
	if !errors.Is(err, errInjectedSync) || !errors.As(err, &merr) ||
		merr.Stage != "reconcile header copies" || merr.State != fipsStateOriginals {
		t.Fatalf("got %#v, want a reconcile-stage failure with the originals intact", err)
	}
	// The failed sync is the durability barrier that precedes any secondary
	// write, so nothing at all was written.
	if after := readPrefix(t, image, int64(len(prefix))); !bytes.Equal(before, after) {
		t.Fatal("a reconcile whose durability barrier failed still wrote to the device")
	}
	if got := volumeKey(t, image, migrationPassphrase); !bytes.Equal(got, key) {
		t.Fatal("the volume does not open to its key after a failed reconcile")
	}
}

// TestHeaderCopiesAgree pins every way two header copies can disagree, and
// that repairSecondaryHeader resolves each one a damaged or stale secondary
// causes without touching the primary.
func TestHeaderCopiesAgree(t *testing.T) {
	fresh := func(t *testing.T) string {
		device := newImage(t, "copies.img")
		formatWithLibrary(t, device)
		if err := copiesAgree(t, device); err != nil {
			t.Fatalf("a freshly formatted volume's copies disagree: %v", err)
		}
		return device
	}
	repairs := func(t *testing.T, device string) {
		t.Helper()
		hdr, metadata, err := readHeaderForTest(device)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		primary := readPrefix(t, device, int64(hdr.HeaderSize))
		if err := repairOn(t, device, hdr, metadata, testVolumeSys()); err != nil {
			t.Fatalf("repairSecondaryHeader failed: %v", err)
		}
		if err := copiesAgree(t, device); err != nil {
			t.Fatalf("the copies still disagree after the repair: %v", err)
		}
		if !bytes.Equal(readPrefix(t, device, int64(hdr.HeaderSize)), primary) {
			t.Fatal("repairSecondaryHeader changed the primary copy")
		}
	}

	t.Run("secondary torn", func(t *testing.T) {
		device := fresh(t)
		damageSecondary(t, device)
		if err := copiesAgree(t, device); !errors.Is(err, ErrInvalidHeader) || !strings.Contains(err.Error(), "secondary") {
			t.Fatalf("got %v, want the secondary named unreadable", err)
		}
		repairs(t, device)
	})
	t.Run("secondary stale", func(t *testing.T) {
		device := fresh(t)
		hdr, metadata, err := readHeaderForTest(device)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		hdr.SequenceID++
		sys := onSync(t, 1, func(*os.File) error { return errInjectedSync })
		if err := writeHeaderInternalWithSys(device, hdr, metadata, sys); !errors.Is(err, errInjectedSync) {
			t.Fatalf("got %v, want the injected sync failure", err)
		}
		if err := copiesAgree(t, device); !errors.Is(err, ErrInvalidHeader) || !strings.Contains(err.Error(), "sequence ids") {
			t.Fatalf("got %v, want the differing sequence ids named", err)
		}
		repairs(t, device)
	})
	t.Run("same sequence id, different metadata", func(t *testing.T) {
		device := fresh(t)
		hdr, metadata, err := readHeaderForTest(device)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		other := *metadata
		other.Digests = map[string]*header.Digest{}
		for id, d := range metadata.Digests {
			changed := *d
			changed.Iterations++
			other.Digests[id] = &changed
		}
		if err := repairOn(t, device, hdr, &other, testVolumeSys()); err != nil {
			t.Fatalf("writing a differing secondary failed: %v", err)
		}
		if err := copiesAgree(t, device); !errors.Is(err, ErrInvalidHeader) || !strings.Contains(err.Error(), "different metadata") {
			t.Fatalf("got %v, want differing metadata named", err)
		}
		repairs(t, device)
	})
	t.Run("primary torn", func(t *testing.T) {
		device := fresh(t)
		damagePrimary(t, device)
		if err := copiesAgree(t, device); !errors.Is(err, ErrInvalidHeader) || !strings.Contains(err.Error(), "primary") {
			t.Fatalf("got %v, want the primary named unreadable", err)
		}
	})
	t.Run("the primary is made durable before the secondary is touched", func(t *testing.T) {
		device := fresh(t)
		damageSecondary(t, device)
		hdr, metadata, err := readHeaderForTest(device)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		before := readPrefix(t, device, 2*int64(hdr.HeaderSize))
		// The first sync is the barrier: at it, not one secondary byte may
		// have been written yet. Failing it must leave the secondary as is.
		sys := onSync(t, 1, func(*os.File) error {
			if now := readPrefix(t, device, 2*int64(hdr.HeaderSize)); !bytes.Equal(now, before) {
				t.Fatal("the secondary was written before the primary was made durable")
			}
			return errInjectedSync
		})
		if err := repairOn(t, device, hdr, metadata, sys); !errors.Is(err, errInjectedSync) {
			t.Fatalf("got %v, want the injected sync failure", err)
		}
		if now := readPrefix(t, device, 2*int64(hdr.HeaderSize)); !bytes.Equal(now, before) {
			t.Fatal("a repair whose durability barrier failed still wrote the secondary")
		}
	})
	t.Run("repair cannot sync the secondary", func(t *testing.T) {
		device := fresh(t)
		hdr, metadata, err := readHeaderForTest(device)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		sys := onSync(t, 2, func(*os.File) error { return errInjectedSync })
		if err := repairOn(t, device, hdr, metadata, sys); !errors.Is(err, errInjectedSync) {
			t.Fatalf("got %v, want the injected sync failure", err)
		}
	})
	t.Run("the repair's write step fails", func(t *testing.T) {
		device := fresh(t)
		hdr, metadata, err := readHeaderForTest(device)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		before := readPrefix(t, device, 2*int64(hdr.HeaderSize))
		dev := lockedDevice(t, device)
		r := &writeStepRecorder{device: device, limit: 1, failAt: 1}
		r.install(t, testVolumeSys())
		dev.sys = r.sys
		if err := repairSecondaryHeader(context.Background(), dev, hdr, metadata); !errors.Is(err, errInjectedOpen) {
			t.Fatalf("got %v, want the injected write-step failure", err)
		}
		if !bytes.Equal(readPrefix(t, device, 2*int64(hdr.HeaderSize)), before) {
			t.Fatal("a repair whose write step failed still wrote")
		}
	})
}

// TestStateAfterWriteFailureReadsTheDevice: the reported state follows what
// the device holds, not what the stage assumed.
func TestStateAfterWriteFailureReadsTheDevice(t *testing.T) {
	device := newImage(t, "state.img")
	formatWithLibrary(t, device)
	hdr, _, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	area := int64(hdr.HeaderSize)

	if got := stateAfterWriteFailure(device, area, fipsStateOriginals, testVolumeSys()); got != fipsStateOriginals {
		t.Fatalf("intact header: got %q", got)
	}
	damagePrimary(t, device)
	if got := stateAfterWriteFailure(device, area, fipsStateOriginals, testVolumeSys()); got != fipsStatePrimaryDamagedOriginals {
		t.Fatalf("damaged primary before removal: got %q", got)
	}
	if got := stateAfterWriteFailure(device, area, fipsStateRemoving, testVolumeSys()); got != fipsStatePrimaryDamagedRemoving {
		t.Fatalf("damaged primary during removal: got %q", got)
	}
	if err := restorePrimaryHeaderForTest(device); err != nil {
		t.Fatalf("RestorePrimaryHeader failed: %v", err)
	}
	damageSecondary(t, device)
	damagePrimary(t, device)
	if got := stateAfterWriteFailure(device, area, fipsStateRemoving, testVolumeSys()); got != fipsStateNoHeader {
		t.Fatalf("both copies damaged: got %q", got)
	}
}

// TestStateAfterWriteFailureReadsOnlyTheKnownSecondary: with both header
// copies of a 32 KiB-metadata volume unreadable, the failure report reads the
// secondary where the volume's own geometry puts it and nowhere else. A valid
// header copy is planted at the 4 MiB probe offset, where a reader probing
// every legal offset -- ReadSecondaryHeader with no primary -- finds it; the
// report must not, because on such a layout that offset can be encrypted data.
func TestStateAfterWriteFailureReadsOnlyTheKnownSecondary(t *testing.T) {
	defer parallel(t)()
	small := newImage(t, "small-metadata.img")
	if err := formatForTest(metadataSizeFormatOptions(small, 32<<10)); err != nil {
		t.Fatalf("Format with 32 KiB metadata failed: %v", err)
	}
	large := newImage(t, "large-metadata.img")
	if err := formatForTest(metadataSizeFormatOptions(large, header.HeaderMaxSize)); err != nil {
		t.Fatalf("Format with 4 MiB metadata failed: %v", err)
	}
	planted, err := os.ReadFile(large) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	f, err := os.OpenFile(small, os.O_RDWR, 0) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.WriteAt(planted[header.HeaderMaxSize:2*header.HeaderMaxSize], header.HeaderMaxSize); err != nil {
		t.Fatalf("planting the copy failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	damageSecondary(t, small)
	damagePrimary(t, small)
	// The planted copy is a real probe target: a probing reader finds it.
	if _, _, err := readSecondaryHeaderForTest(small); err != nil {
		t.Fatalf("the planted copy is not one a probing reader finds, so the test measures nothing: %v", err)
	}
	if got := stateAfterWriteFailure(small, 32<<10, fipsStateRemoving, testVolumeSys()); got != fipsStateNoHeader {
		t.Fatalf("got %q; want %q -- the report read past the volume's own secondary", got, fipsStateNoHeader)
	}
}

// TestMigrateToFIPSRefusesATornPrimaryBeforeWriting: the import reads the
// primary copy and does not repair it. With the primary torn it stops before
// any write, says the volume is untouched, and leaves the secondary for
// RestorePrimaryHeader or cryptsetup to rebuild from.
func TestMigrateToFIPSRefusesATornPrimaryBeforeWriting(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := argon2Volume(t, "torn-primary.img", false)
	damagePrimary(t, device)
	before := fileDigest(t, device)

	_, err := migrateToFIPSForTest(device, migrationPassphrase, cheapMigration())
	var merr *FIPSMigrationError
	if !errors.Is(err, ErrInvalidHeader) || !errors.As(err, &merr) || merr.Stage != "unlock" || merr.State != fipsStateUntouched {
		t.Fatalf("got %#v, want an unlock-stage ErrInvalidHeader with the volume untouched", err)
	}
	if fileDigest(t, device) != before {
		t.Fatal("the refused import changed the device")
	}
	if _, _, err := readSecondaryHeaderForTest(device); err != nil {
		t.Fatalf("the secondary copy is not readable after the refusal: %v", err)
	}
}

// TestMigrateToFIPSMakesAgreeingCopiesDurableBeforeWriting is the retry after
// a run that wrote both header copies and was stopped before the secondary
// reached the medium: the copies then read back identical from the page cache,
// so no reconcile happens, and with the PBKDF2 keyslot reused the retry's
// first write is a header write -- over the primary, which until a sync is the
// only copy known to be on the medium. Nothing may be written before the
// run's durability barrier, and if that barrier fails nothing is written at
// all.
func TestMigrateToFIPSMakesAgreeingCopiesDurableBeforeWriting(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	prefix, _, key := crashFixture(t, true)
	image := filepath.Join(t.TempDir(), "unsynced-secondary.img")
	placeImage(t, image, prefix)

	// The first run: the first sync after the secondary copy names the new
	// keyslot -- the add-header write's final sync -- fails, as a run killed
	// there would leave it. Chosen by what the device holds rather than by
	// counting syncs, so the fixture does not depend on the barrier under
	// test.
	sys := testVolumeSys()
	real := sys.syncDevice
	sys.syncDevice = func(f *os.File) error {
		if _, m, err := readSecondaryHeaderForTest(image); err == nil && m.Keyslots["2"] != nil {
			return errInjectedSync
		}
		return real(f)
	}
	_, err := migrateToFIPSAt(context.Background(), image, migrationPassphrase, cheapMigration(), sys)
	var merr *FIPSMigrationError
	if !errors.Is(err, errInjectedSync) || !errors.As(err, &merr) || merr.Stage != "add keyslot" {
		t.Fatalf("got %#v, want the add-keyslot header write to fail at its final sync", err)
	}
	if err := copiesAgree(t, image); err != nil {
		t.Fatalf("the fixture's copies must agree, as both were written: %v", err)
	}
	left := readPrefix(t, image, int64(len(prefix)))

	t.Run("the barrier fails: nothing is written", func(t *testing.T) {
		retry := filepath.Join(t.TempDir(), "retry.img")
		placeImage(t, retry, left)
		sys := onSync(t, 1, func(*os.File) error { return errInjectedSync })
		_, err := migrateToFIPSAt(context.Background(), retry, migrationPassphrase, cheapMigration(), sys)
		var merr *FIPSMigrationError
		if !errors.Is(err, errInjectedSync) || !errors.As(err, &merr) || merr.Stage != "sync" || merr.State != fipsStateUntouched {
			t.Fatalf("got %#v, want a sync-stage failure with the volume untouched", err)
		}
		if !bytes.Equal(readPrefix(t, retry, int64(len(prefix))), left) {
			t.Fatal("a run whose durability barrier failed still wrote to the device")
		}
	})

	t.Run("nothing is written before the barrier", func(t *testing.T) {
		retry := filepath.Join(t.TempDir(), "retry.img")
		placeImage(t, retry, left)
		sys := onSync(t, 1, func(f *os.File) error {
			if !bytes.Equal(readPrefix(t, retry, int64(len(prefix))), left) {
				t.Fatal("the retry wrote to the device before making it durable")
			}
			return f.Sync()
		})
		result, err := migrateToFIPSAt(context.Background(), retry, migrationPassphrase, cheapMigration(), sys)
		if err != nil || !result.Complete || result.KeyslotAdded {
			t.Fatalf("the retry: result %+v, error %v; want complete, reusing the keyslot the first run added", result, err)
		}
		if got := volumeKey(t, retry, migrationPassphrase); !bytes.Equal(got, key) {
			t.Fatal("the retry changed the volume key")
		}
	})
}

// TestMigrateToFIPSReadsTheMediumNotThePageCache models the cache and the
// medium disagreeing, which is what a failed writeback leaves: the earlier
// run's add-keyslot header write reached the medium for the primary only --
// its secondary is torn there -- while the page cache, its failed pages now
// clean, still serves both copies whole and agreeing, and a later fsync
// succeeds without rewriting them. Through the cache the retry would see
// nothing to reconcile and, reusing the PBKDF2 keyslot, would rewrite the
// primary first: the only copy on the medium.
//
// The model: until dropDeviceCache runs, every READ of the device is served
// from a second image holding the cached view; writes, and every read after
// it, reach the device image -- the medium. The retry must repair the
// medium's secondary first, and every state an interruption of its first
// writes can leave on the medium must open. Writes are not mirrored into the
// cached view: the run under test drops it before reading anything, and a run
// that read through it without dropping it fails this test either way.
func TestMigrateToFIPSReadsTheMediumNotThePageCache(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	m := newCacheModel(t, true)

	rec := &writeStepRecorder{device: m.device, limit: int64(len(m.prefix))}
	rec.install(t, m.sys)
	result, err := migrateToFIPSAt(context.Background(), m.device, migrationPassphrase, cheapMigration(), rec.sys)
	if err != nil || !result.Complete {
		t.Fatalf("the retry: result %+v, error %v; want complete", result, err)
	}
	resumed := rec.writeSteps(readPrefix(t, m.device, int64(len(m.prefix))))
	if len(resumed) < 3 {
		t.Fatalf("the retry made %d write steps, want at least the repair and two more", len(resumed))
	}
	first := resumed[0]
	if !bytes.Equal(first.before[:m.headerArea], first.after[:m.headerArea]) ||
		!bytes.Equal(first.before[2*m.headerArea:], first.after[2*m.headerArea:]) {
		t.Fatal("the retry's first write is not a repair of the medium's secondary copy alone")
	}
	for i, step := range resumed[:3] {
		for _, state := range tornStates(step, m.headerArea) {
			t.Run(fmt.Sprintf("retry step%d/%s", i+1, state.class), func(t *testing.T) {
				defer parallel(t)()
				_, _, seq := assertStateOpens(t, t.TempDir(), state.image, m.key)
				if seq != state.wantSeq {
					t.Fatalf("this library opened header sequence %d, want %d", seq, state.wantSeq)
				}
			})
		}
	}
}

// TestMigrateToFIPSRefusesWhenTheCacheOutlivesItsEviction is the same failed
// writeback, but the eviction "succeeds" and the stale pages stay -- as they
// do when another process holds them mapped. Through the cache the copies
// still agree; the run must find that the cache is not the medium, and stop
// having written nothing.
func TestMigrateToFIPSRefusesWhenTheCacheOutlivesItsEviction(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	m := newCacheModel(t, false)
	before := readPrefix(t, m.device, int64(len(m.prefix)))

	_, err := migrateToFIPSAt(context.Background(), m.device, migrationPassphrase, cheapMigration(), m.sys)
	var merr *FIPSMigrationError
	if !errors.Is(err, ErrDeviceCacheStale) || !errors.As(err, &merr) || merr.Stage != "sync" || merr.State != fipsStateUntouched {
		t.Fatalf("got %#v, want a sync-stage ErrDeviceCacheStale with the volume untouched", err)
	}
	if !bytes.Equal(readPrefix(t, m.device, int64(len(m.prefix))), before) {
		t.Fatal("a run that found the cache stale still wrote to the medium")
	}
}

// cacheModel is a device whose page cache disagrees with its medium, as a
// failed writeback of the add-keyslot header leaves it: the medium -- the
// device image, which every write and every direct read reaches -- holds a
// durable new primary and a torn secondary, while every buffered READ is
// served from a second image holding both copies whole and agreeing, until
// the cache is evicted. With evicts false the eviction succeeds and changes
// nothing, as it does for pages another process holds mapped. Writes are not
// mirrored into the cached view: a run under test either reads past it or
// is refused, and one that read through it fails these tests either way.
type cacheModel struct {
	device     string
	prefix     []byte
	headerArea int
	key        []byte
	sys        volumeSys
}

func newCacheModel(t *testing.T, evicts bool) *cacheModel {
	t.Helper()

	e, steps := recordedMigration(t, true)
	prefix, key := e.prefix, e.key
	headerArea := int(binary.BigEndian.Uint64(prefix[8:16]))
	addHeader := steps[1]
	var medium []byte
	for _, state := range tornStates(addHeader, headerArea) {
		if state.class == "secondary torn" {
			medium = state.image
		}
	}
	if medium == nil {
		t.Fatal("the add-keyslot header write has no secondary-torn state to model")
	}

	dir := t.TempDir()
	device := filepath.Join(dir, "medium.img")
	cache := filepath.Join(dir, "cache.img")
	placeImage(t, device, medium)
	placeImage(t, cache, addHeader.after)

	// Every read the run makes goes through its pinned descriptor (#255), so
	// the cached view is modeled THERE: until the cache is dropped, a read of
	// the device's descriptor is served from the cache image.
	dropped := false
	cached, err := os.Open(cache) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("open the cache image: %v", err)
	}
	t.Cleanup(func() { _ = cached.Close() })
	sys := testVolumeSys()
	sys.pinnedDeviceReader = func(f *os.File) io.ReaderAt {
		if !sameFile(t, f.Name(), device) {
			return f
		}
		return readerFunc(func(p []byte, off int64) (int, error) {
			if !dropped {
				return cached.ReadAt(p, off)
			}
			return f.ReadAt(p, off)
		})
	}
	sys.dropDeviceCache = func(*os.File) error {
		dropped = evicts
		return nil
	}
	previousDirect := sys.readDeviceDirect
	sys.readDeviceDirect = func(ctx context.Context, path string, off int64, n int) ([]byte, error) {
		if !sameFile(t, path, device) {
			return previousDirect(ctx, path, off, n)
		}
		medium := readPrefix(t, device, off+int64(n))
		return medium[off:], nil
	}

	// The model is what it claims: through the cache the copies agree, on
	// the medium the secondary is torn.
	if err := copiesAgree(t, cache); err != nil {
		t.Fatalf("through the modeled cache the copies must agree: %v", err)
	}
	if _, _, err := readHeaderCopy(cache, int64(headerArea)); err != nil {
		t.Fatalf("the modeled cache's secondary must be whole: %v", err)
	}
	if !bytes.Equal(readPrefix(t, device, int64(len(prefix))), medium) {
		t.Fatal("the modeled medium is not the torn state")
	}
	return &cacheModel{device: device, prefix: prefix, headerArea: headerArea, key: key, sys: sys}
}

// TestMigrateToFIPSStopsWhenTheCacheCannotBeDropped: if what the run reads
// cannot be shown to come from the medium, it reads nothing and writes
// nothing.
func TestMigrateToFIPSStopsWhenTheCacheCannotBeDropped(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := argon2Volume(t, "no-drop.img", false)
	before := fileDigest(t, device)
	errDrop := errors.New("injected: the cache could not be dropped")
	sys := testVolumeSys()
	sys.dropDeviceCache = func(*os.File) error { return errDrop }

	_, err := migrateToFIPSAt(context.Background(), device, migrationPassphrase, cheapMigration(), sys)
	var merr *FIPSMigrationError
	if !errors.Is(err, errDrop) || !errors.As(err, &merr) || merr.Stage != "sync" || merr.State != fipsStateUntouched {
		t.Fatalf("got %#v, want a sync-stage failure with the volume untouched", err)
	}
	if fileDigest(t, device) != before {
		t.Fatal("a run that could not drop the cache changed the device")
	}
}

// TestDropDeviceCache: the real eviction succeeds on an open device image and
// reports a descriptor it cannot advise on.
func TestDropDeviceCache(t *testing.T) {
	image := newImage(t, "drop.img")
	f, err := os.Open(image) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := testVolumeSys().dropDeviceCache(f); err != nil {
		t.Fatalf("dropDeviceCache on an open image: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := testVolumeSys().dropDeviceCache(f); err == nil {
		t.Fatal("dropDeviceCache on a closed descriptor reported success")
	}
}

// TestMigrateToFIPSReportsTheStateOnTheMediumNotInTheCache: a header write
// whose primary writeback fails can leave the cache's primary whole while the
// medium's is torn. The reported state must describe the MEDIUM -- what a
// reboot, or cryptsetup, will find -- and say so when the medium cannot be
// read at all.
func TestMigrateToFIPSReportsTheStateOnTheMediumNotInTheCache(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	prefix, _, _ := crashFixture(t, true)
	errDirect := errors.New("injected: the medium cannot be read")
	// syncDevice calls: the run's durability barrier, then two per header
	// write (add, digest, two removals), the first of each the barrier
	// between the copies.
	cases := []struct {
		name    string
		barrier int
		medium  string // "torn primary" or "unreadable"
		stage   string
		state   string
	}{
		{"add header, primary torn on the medium", 2, "torn primary", "add keyslot", fipsStatePrimaryDamagedOriginals},
		{"first removal header, primary torn on the medium", 6, "torn primary", "remove keyslot", fipsStatePrimaryDamagedRemoving},
		{"add header, medium unreadable", 2, "unreadable", "add keyslot", fipsStateUnconfirmed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			image := filepath.Join(t.TempDir(), "writeback.img")
			placeImage(t, image, prefix)

			failed := false
			sys := onSync(t, tc.barrier, func(*os.File) error {
				failed = true
				return errInjectedSync
			})
			previousDirect := sys.readDeviceDirect
			sys.readDeviceDirect = func(ctx context.Context, path string, off int64, n int) ([]byte, error) {
				if !failed {
					return previousDirect(ctx, path, off, n)
				}
				if tc.medium == "unreadable" {
					return nil, errDirect
				}
				medium, err := previousDirect(ctx, path, off, n)
				if err == nil {
					for i := header.HeaderSize; i < header.HeaderSize+crashSector; i++ {
						if int64(i) >= off && int64(i) < off+int64(len(medium)) {
							medium[int64(i)-off] ^= 0xa5
						}
					}
				}
				return medium, err
			}

			_, err := migrateToFIPSAt(context.Background(), image, migrationPassphrase, cheapMigration(), sys)
			var merr *FIPSMigrationError
			if !errors.Is(err, errInjectedSync) || !errors.As(err, &merr) || merr.Stage != tc.stage || merr.State != tc.state {
				t.Fatalf("got %#v, want stage %q reporting %q", err, tc.stage, tc.state)
			}
			// The cache still reads the primary whole: the report did not
			// come from it.
			if _, _, err := readHeaderForTest(image); err != nil {
				t.Fatalf("the cached view's primary must still read whole: %v", err)
			}
		})
	}
}

// TestReadHeaderCopyFromClassifiesEveryRejection: each check of the header
// reader fails with a typed error a caller can test for -- damage as
// ErrInvalidHeader, a LUKS1 (or later) header as ErrUnsupportedLUKSVersion and
// not as damage, a short read with its cause -- and an intact copy of either
// kind reads.
func TestReadHeaderCopyFromClassifiesEveryRejection(t *testing.T) {
	device := newImage(t, "reader.img")
	formatWithLibrary(t, device)
	hdr, _, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	area := int64(hdr.HeaderSize)
	intact := readPrefix(t, device, 2*area)

	// Offsets within the binary header (LUKS2 on-disk layout).
	const versionAt, sizeAt, recordedOffsetAt = 6, 8, 256
	mutate := func(at int64, f func([]byte)) []byte {
		b := bytes.Clone(intact)
		f(b[at:])
		return b
	}

	if _, _, err := readHeaderCopyFrom(bytes.NewReader(intact), 0); err != nil {
		t.Fatalf("the intact primary: %v", err)
	}
	if _, _, err := readHeaderCopyFrom(bytes.NewReader(intact), area); err != nil {
		t.Fatalf("the intact secondary: %v", err)
	}

	cases := []struct {
		name    string
		image   []byte
		offset  int64
		want    error
		notWant error
	}{
		{"short read", intact[:100], 0, io.EOF, nil},
		{"bad magic", mutate(0, func(b []byte) { b[0] ^= 0xff }), 0, ErrInvalidHeader, nil},
		{"LUKS1", mutate(0, func(b []byte) { binary.BigEndian.PutUint16(b[versionAt:], 1) }), 0, ErrNotLUKS2, ErrInvalidHeader},
		{"recorded offset disagrees", mutate(0, func(b []byte) { binary.BigEndian.PutUint64(b[recordedOffsetAt:], uint64(area)) }), 0, ErrInvalidHeader, nil},
		{"secondary size disagrees", mutate(area, func(b []byte) { binary.BigEndian.PutUint64(b[sizeAt:], uint64(2*area)) }), area, ErrInvalidHeader, nil},
		{"checksum", mutate(header.HeaderSize, func(b []byte) { b[0] ^= 0xff }), 0, ErrInvalidHeader, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := readHeaderCopyFrom(bytes.NewReader(tc.image), tc.offset)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if tc.notWant != nil && errors.Is(err, tc.notWant) {
				t.Fatalf("got %v, which must not match %v", err, tc.notWant)
			}
		})
	}
}

// lockedDevice locks path and pins it, as a keyslot operation does, for a test
// that drives a pinned helper directly. The lock is released when the test
// ends.
func lockedDevice(t *testing.T, path string) *keyslotDevice {
	t.Helper()

	lock, dev, err := lockKeyslotDevice(context.Background(), path, testVolumeSys())
	if err != nil {
		t.Fatalf("lockKeyslotDevice(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	return dev
}

// repairOn runs repairSecondaryHeader on path under its own lock, released
// before it returns.
func repairOn(t *testing.T, path string, hdr *header.BinaryHeader, metadata *header.Metadata, sys volumeSys) error {
	t.Helper()

	lock, dev, err := lockKeyslotDevice(context.Background(), path, sys)
	if err != nil {
		t.Fatalf("lockKeyslotDevice(%s): %v", path, err)
	}
	defer func() { _ = lock.Release() }()
	return repairSecondaryHeader(context.Background(), dev, hdr, metadata)
}

// copiesAgree is header.HeaderCopiesAgree on path, read through a descriptor of its
// own.
func copiesAgree(t *testing.T, path string) error {
	t.Helper()

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	return header.HeaderCopiesAgree(f)
}

// readerFunc adapts a function to io.ReaderAt.
type readerFunc func(p []byte, off int64) (int, error)

func (f readerFunc) ReadAt(p []byte, off int64) (int, error) { return f(p, off) }

// sameFile reports whether two paths name the same file -- a pinned
// descriptor's /proc/self/fd entry and the image it was opened from among
// them.
func sameFile(t *testing.T, a, b string) bool {
	t.Helper()

	sa, errA := os.Stat(a)
	sb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(sa, sb)
}
