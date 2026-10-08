// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// Importing a foreign Argon2 volume into a FIPS 140-3 deployment (#84).
//
// # This is a keyslot migration, not a re-encryption
//
// In LUKS2 the VOLUME KEY encrypts the data and each keyslot stores that key
// wrapped under a passphrase-derived key. The KDF is a property of the keyslot,
// not of the volume, and the data cipher -- aes-xts-plain64 -- is already
// approved. So nothing in the data area has to change: the migration rewrites a
// few KB of header metadata and keyslot material and never reads or writes a
// byte of data. Re-encrypting would rewrite every byte, with a window in which
// an interruption destroys the volume, to fix something that is not in the data.
//
// # Why it must run OUTSIDE FIPS mode
//
// Recovering the volume key means deriving through the existing Argon2 keyslot,
// and a FIPS process cannot execute Argon2 (fips.Mode.RequireKDF). So this is
// a non-FIPS import step that produces a FIPS-ready volume: the FIPS-activated
// process that later opens it never executes the unapproved primitive, which is
// what the owner ruling of 2026-08-31 requires. MigrateToFIPS refuses to start
// in a FIPS process instead of failing obscurely inside the derivation.
//
// # The order, and why no state along it is unopenable
//
//	0  sync          whatever an earlier process left in the page cache is
//	                 made durable, then the cache is dropped, so everything
//	                 below reads what is on the medium
//	1  unlock        through the caller's passphrase -> the key a digest
//	                 binds to every data segment, never an unbound key
//	2  plan          every non-approved digest must attest THAT key, or stop
//	   reconcile     a stale or torn secondary header copy is rewritten from
//	                 the primary, and only the secondary is written
//	3  add keyslot   PBKDF2 keyslot wrapping the same key (AddKey's own code)
//	4  migrate       each non-approved digest rewritten as PBKDF2 over the key
//	5  verify        real open through the new keyslot and approved digests
//	                 only, then the ordinary unlock scan over approved keyslots
//	                 and digests must recover the same volume key -- the key
//	                 Unlock would hand dm-crypt, not merely one that opens --
//	                 and both header copies must agree
//	6  remove        the non-approved keyslots, each through the removal gate
//	7  final check   static: nothing non-approved remains that was not kept;
//	                 real open again against the header as finally written
//
// Nothing is removed until 5 has passed, so a failure at or before 5 leaves
// every original keyslot in place. The digest rewrite in 4 replaces a digest
// with another over the SAME key, so either header copy opens the volume. Each
// removal in 6 goes through checkKeyslotRemovable, the gate every removal in
// this package takes, and the keyslot verified in 5 is approved and therefore
// never a removal target. Every step runs under one device lock.
//
// # Both header copies, and an interrupted earlier run
//
// Every header write syncs the primary copy before it touches the secondary
// (writeHeaderTo), so an interruption tears at most one copy, and the
// survivor is the header before or after that write -- each of which opens.
// That argument needs both copies to describe the same volume when a
// destructive step begins. A run that starts from what an INTERRUPTED earlier
// run left can find them apart: a primary naming the PBKDF2 keyslot that run
// added, beside a secondary that still names only the Argon2 one, or a torn
// secondary. Wiping the Argon2 keyslot from there and then tearing the primary
// would leave, as the only readable copy, one naming nothing but wiped
// material. So before the first write the secondary is reconciled to the
// primary -- making the primary durable first, then writing the secondary
// alone, so the copy the volume opens through is never at risk -- and before
// the first removal the two are required to agree.
//
// Agreeing in the page cache is not agreeing on the medium. A run killed
// after writing the secondary copy and before syncing it leaves two copies
// that read back identical while the secondary on the medium may be torn; and
// after a writeback ERROR the kernel may keep the unwritten bytes in the cache
// as clean pages, which a later fsync succeeds without rewriting. A retry
// trusting either would skip the reconcile and -- the PBKDF2 keyslot reused --
// make a header write over the primary its first write, putting the only
// copy on the medium at risk. So every run, under the lock and before its
// first READ, syncs the device and evicts its cached pages -- and, because
// eviction is advisory (a page another process holds mapped survives it),
// then reads the header region both through the cache and past it (O_DIRECT)
// and requires the two to be identical. Everything the run reads, the header
// copies above all, is then what is on the medium, and the reconcile repairs
// what the medium actually holds. If any of it fails, or the cache disagrees
// with the medium (ErrDeviceCacheStale), the run stops before reading on. A torn PRIMARY is not repaired here: the run refuses before writing,
// and RestorePrimaryHeader (or cryptsetup, which repairs on its own) rebuilds
// it from the secondary.
//
// # The digest is migrated too, and is easy to forget
//
// verifyMasterKey derives through the DIGEST's KDF on every unlock, separately
// from the keyslot's. A volume whose keyslots are all PBKDF2 but whose digest is
// not stays unopenable in FIPS mode, and the failure looks identical. This
// package's own digests are PBKDF2 by construction (createDigest), but a foreign
// volume's need not be -- a LUKS1 volume converted by cryptsetup carries a
// PBKDF2-SHA1 digest, and a foreign writer may use Argon2 there too (see
// screenDigestStructure) -- so the digest is checked rather than assumed.
//
// # What may be read or wiped
//
// An unlock reads a keyslot's whole declared area, and removing a keyslot
// randomizes it; both areas come off the device. A non-approved keyslot the
// migration removes need not be able to open anything, so nothing about it
// has been proved by the unlock, and a keyslot the unlock tries has not been
// proved before it is read. checkKeyslotAreaConfined requires EVERY luks2
// keyslot's area to be keyslot space -- inside config.keyslots_size and clear
// of every data segment -- before the first keyslot is read, and each removed
// area again at its wipe. The import neither reads nor writes a byte of data.
//
// # "Approved" is what strict FIPS mode RUNS
//
// Every approval decision here -- which keyslot may be reused, which digest
// must be rewritten, what the static check accepts -- goes through
// keyslotFIPSRefusal and digestFIPSRefusal, which add to the algorithm the
// parameter floors crypto/pbkdf2 enforces under GODEBUG=fips140=only. A
// foreign PBKDF2-SHA256 KDF over an eight-byte salt has an approved name and
// is refused there, so a name check alone would certify a volume the FIPS
// process cannot open.
//
// # Verification, per the owner ruling of 2026-09-25
//
// A process cannot switch into FIPS mode, so "confirm it opens under fips140"
// cannot be done in the migrating process. It is done in three layers: the
// static check (every remaining keyslot and digest approved, via
// IsFIPSCompliantKDF), a real open through the new keyslot and approved digests
// with Argon2 structurally absent from the path, and a test in the nightly FIPS
// lane that migrates a real cryptsetup volume and opens it under
// GODEBUG=fips140=only in a separate process.

// fipsMigrationOptionsForTest tunes MigrateToFIPS. The zero value -- or nil -- is the
// complete import: a PBKDF2-SHA256 keyslot at a calibrated cost, and every
// non-approved keyslot removed.
type fipsMigrationOptionsForTest struct {
	// KeepNonApprovedKeyslots keeps the original Argon2 (or PBKDF2-SHA1)
	// keyslots instead of removing them. The default is to remove them.
	//
	// Keeping them is a HALF-MIGRATION: the volume then still opens in a
	// non-FIPS process through a KDF FIPS mode cannot execute, which is not
	// "imported" in any meaningful sense. It is offered for a staged rollout
	// -- migrate each credential in turn, then remove the originals -- and the
	// result says so: FIPSMigrationResult.Complete is false and
	// RetainedNonApprovedKeyslots names what was kept.
	KeepNonApprovedKeyslots bool

	// Hash is the PBKDF2 hash for the new keyslot and for any digest that is
	// migrated: "sha256" (the default), "sha384" or "sha512". Anything FIPS
	// mode cannot run is refused before the device is touched.
	Hash string

	// PBKDFIterTime and PBKDFIterations cost the new keyslot exactly as the
	// AddKeyOptions fields of the same names do.
	PBKDFIterTime   int
	PBKDFIterations int
}

// fipsMigrationResultForTest is what MigrateToFIPS did, reported from the point of
// decision rather than left to be inferred from the header afterwards.
type fipsMigrationResultForTest struct {
	// Keyslot is the FIPS-approved keyslot the passphrase now opens.
	Keyslot int

	// KeyslotAdded is false when the passphrase already opened an approved
	// keyslot, which was then used as it stands -- re-running a completed
	// import does not stack up duplicate keyslots.
	KeyslotAdded bool

	// MigratedDigests are the digests whose KDF was rewritten to PBKDF2.
	MigratedDigests []string

	// RemovedKeyslots are the non-approved keyslots that were removed. Any
	// credential they held -- another passphrase, a token-bound secret -- no
	// longer opens the volume.
	RemovedKeyslots []string

	// RetainedNonApprovedKeyslots are the non-approved keyslots kept because
	// the caller set KeepNonApprovedKeyslots. Non-empty means the import is
	// incomplete.
	RetainedNonApprovedKeyslots []string

	// Complete is true when no keyslot or digest the volume carries uses a KDF
	// FIPS mode cannot execute.
	Complete bool
}

// Volume states a FIPSMigrationError reports. Each is a statement the ordering
// above makes true, not a hope.
const (
	fipsStateUntouched = "nothing was written and the volume is unchanged"
	fipsStateOriginals = "no keyslot was removed, so the volume still opens exactly as it did before"
	fipsStateRemoving  = "the verified FIPS-approved keyslot is in place and opens the volume; " +
		"non-approved keyslots not listed as removed may remain"
	fipsStateFinal = "the removals are complete; the header as written did not pass the final check, " +
		"so do not rely on it opening under FIPS until the cause is resolved"

	// The failed write left the PRIMARY header copy unreadable. Each says what
	// the secondary -- the previous header, complete -- still opens through.
	fipsStatePrimaryDamagedOriginals = "the primary header copy did not finish writing; the secondary copy holds the previous header, " +
		"in which no keyslot was removed -- RestorePrimaryHeader rebuilds the primary from it, and cryptsetup repairs it on its own"
	fipsStatePrimaryDamagedRemoving = "the primary header copy did not finish writing; the secondary copy holds the previous header, " +
		"in which the verified FIPS-approved keyslot opens the volume -- RestorePrimaryHeader rebuilds the primary from it, " +
		"and cryptsetup repairs it on its own"
	fipsStateNoHeader = "neither header copy is readable after the failed write; restore the header from a backup"

	// What is on the medium could not be read past the page cache, so which
	// header copy survived the failed write is not known.
	fipsStateUnconfirmed = "a header or keyslot write failed and the header copies on the medium could not be read past the page cache " +
		"to say which survived; check the device before relying on it -- RestorePrimaryHeader rebuilds a damaged primary from the " +
		"secondary, and cryptsetup repairs it on its own"
)

// stateAfterWriteFailure is state, checked against the MEDIUM: a failed header
// write can leave the primary copy unreadable, and then "opens as before" is
// true only through the secondary, which the state must say.
//
// A failed write is exactly when the page cache may hold bytes the medium does
// not -- a writeback error can leave the cache's copy whole and the medium's
// torn -- so the header copies are read past the cache, at the deepest medium
// source (mediumSources: a buffered loop device's backing file), and judged by
// the header reader's own checks (readHeaderCopyFrom). If that read cannot be
// made, the state says what is not known rather than guessing.
//
// area is the header area size the run read and validated before writing:
// the secondary is read THERE and nowhere else. A reader probing every legal
// offset up to 4 MiB would, on a small layout, read the encrypted data, which
// the import never reads.
func stateAfterWriteFailure(device string, area int64, state string, sys volumeSys) string {
	sources, err := mediumSources(device, sys.nodeRdev)
	if err != nil {
		return fipsStateUnconfirmed
	}
	deepest := sources[len(sources)-1]
	medium, err := sys.readDeviceDirect(context.Background(), deepest.path, deepest.offset, int(2*area))
	if err != nil {
		return fipsStateUnconfirmed
	}
	view := bytes.NewReader(medium)
	if _, _, err := readHeaderCopyFrom(view, 0); err == nil {
		return state
	}
	if _, _, err := readHeaderCopyFrom(view, area); err != nil {
		return fipsStateNoHeader
	}
	if state == fipsStateRemoving {
		return fipsStatePrimaryDamagedRemoving
	}
	return fipsStatePrimaryDamagedOriginals
}

// migrateToFIPS is (*Volume).MigrateToFIPS's implementation, with ctx
// threaded through.
//
// lockDevice takes the device's exclusive lock and returns it pinned, with
// the release the run defers. It is called once, after the preconditions:
// (*Volume).MigrateToFIPS locks the descriptor Open pinned, through the
// Volume's own lock wait, clock and lock directory.
func migrateToFIPS(ctx context.Context, device string, passphrase []byte, opts *fipsMigrationOptionsForTest, sys volumeSys, lockDevice func() (*keyslotDevice, func(), error)) (*fipsMigrationResultForTest, error) {
	// The header area size, once the run has read and validated one: what a
	// failure report reads the secondary at (stateAfterWriteFailure).
	var area int64
	// What a failure report reads the medium through: the pinned descriptor's
	// own file once the device is locked (#255). Only states reached after the
	// lock consult it.
	mediumPath := device
	fail := func(stage, state string, err error) (*fipsMigrationResultForTest, error) {
		if state == fipsStateOriginals || state == fipsStateRemoving {
			state = stateAfterWriteFailure(mediumPath, area, state, sys)
		}
		return nil, &FIPSMigrationError{Device: device, Stage: stage, State: state, Err: err}
	}

	if sys.fipsMode() {
		return fail("precondition", fipsStateUntouched, fipsRefusal(errFIPSMigrationUnderFIPS, "", nil))
	}
	// The passphrase is an EXISTING credential -- the one the import
	// re-wraps, not a new one chosen here -- so it is judged by what can open a
	// keyslot (#249, A7): a volume opened by a cryptsetup keyfile is migrated
	// like any other.
	if err := validateExistingCredential(passphrase); err != nil {
		return fail("precondition", fipsStateUntouched, err)
	}

	o := fipsMigrationOptionsForTest{}
	if opts != nil {
		o = *opts
	}
	if o.Hash == "" {
		o.Hash = defaultHashAlgo
	}
	o.Hash = strings.ToLower(o.Hash)
	if !fipsApprovedKDF(kdfTypePBKDF2, o.Hash) {
		return fail("precondition", fipsStateUntouched, &errs.Error{
			Kind:   ErrUnsupported,
			Detail: "PBKDF2 hash " + strconv.Quote(o.Hash) + " is not one FIPS mode can run (sha256, sha384, sha512)",
		})
	}
	// The new keyslot's cost is judged where AddKey judges it, in createKDF,
	// which runs before anything is written.
	addOpts := &addKeyOptionsForTest{
		KDFType:         kdfTypePBKDF2,
		Hash:            o.Hash,
		PBKDFIterTime:   o.PBKDFIterTime,
		PBKDFIterations: o.PBKDFIterations,
	}

	// ONE DESCRIPTOR FOR THE WHOLE IMPORT (#255). The lock is taken on it and
	// every read, write, sync, wipe and medium check below goes through it --
	// the medium checks by reopening the same inode through /proc/self/fd --
	// so a path re-pointed mid-import cannot send a write, or a read the
	// import acts on, to a device that was never locked. This used to resolve
	// the path at every step, like the keyslot operations before #249 (A10).
	dev, release, err := lockDevice()
	if err != nil {
		return fail("precondition", fipsStateUntouched, err)
	}
	defer release()
	mediumPath = dev.mediumPath()
	// The header copies are this run's to reconcile, as "Both header copies"
	// above says; the keyslot code it reuses must not repair them for it.
	dev.leveled = true

	// SYNC, then READ FROM THE MEDIUM: see "Both header copies" above. The
	// lock's descriptor is the device's own; fsync flushes every dirty page
	// of it whoever wrote them, and evicting the clean pages after it means
	// every byte this run reads -- headers above all -- comes off the medium,
	// not out of a cache that may hold what never reached it.
	if err := sys.syncDevice(dev.file); err != nil {
		return fail("sync", fipsStateUntouched, &errs.Error{
			Kind: errs.ErrIO, Detail: "failed to make what an earlier write left in the page cache durable before reading", Err: err})
	}
	if err := sys.dropDeviceCache(dev.file); err != nil {
		return fail("sync", fipsStateUntouched, &errs.Error{
			Kind: errs.ErrIO, Detail: "failed to evict the device's cached pages, so what is read could not be shown to be on the medium", Err: err})
	}
	// Eviction is advisory -- a page another process holds mapped stays
	// cached and the call still succeeds -- so it is not the proof. This is:
	// the header region read through the cache must equal the same bytes read
	// past it.
	if err := requireCacheMatchesMediumOf(ctx, dev.reader(), mediumPath, sys); err != nil {
		return fail("sync", fipsStateUntouched, err)
	}

	hdr, metadata, err := dev.readPrimaryHeader()
	if err != nil {
		return fail("unlock", fipsStateUntouched, err)
	}
	headerArea, err := header.HeaderAreaSize(hdr)
	if err != nil {
		return fail("unlock", fipsStateUntouched, err)
	}
	area = int64(headerArea)

	// Every keyslot area this run could READ -- unlocking tries keyslots,
	// verification scans them -- or WIPE must be keyslot space: inside the
	// container's reserved keyslots area and clear of every data segment.
	// Checked before the first keyslot is touched, because an unlock reads a
	// keyslot's whole declared area: a foreign header declaring one that
	// reaches into the data would have the import read ciphertext, which it
	// never does, before any later check could refuse.
	for _, id := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		if keyslot := metadata.Keyslots[id]; keyslot == nil || keyslot.Type != "luks2" {
			continue
		}
		if err := checkKeyslotAreaConfined(hdr, metadata, id); err != nil {
			return fail("precondition", fipsStateUntouched, err)
		}
	}

	// 1. UNLOCK. Approved keyslots are tried first, so a credential that
	// already has one is found there without running Argon2 at all.
	//
	// Only keyslots whose digests bind every data segment are tried. A LUKS2
	// header may carry unbound keys beside the volume key, and one the same
	// passphrase opens would otherwise be found first, carried across, and
	// verified -- verification proves the migrated keyslot opens to the key it
	// was written with, not that the key decrypts anything -- while the
	// removal below wiped the only keyslot holding the key the data needs.
	var order []string
	for _, id := range fipsFirstScanOrder(metadata) {
		// The strict predicate the removal guard and getVolumeKey use (#249):
		// a keyslot attested by an unbound digest beside a bound one, or by
		// per-segment digests that only together cover the volume, is not a
		// migration source.
		if keyslotBoundToDataSegments(metadata, id) {
			order = append(order, id)
		}
	}
	if len(order) == 0 {
		return fail("unlock", fipsStateUntouched, fipsRefusal(errFIPSMigrationUnboundKey, "no keyslot is attested by digests binding every data segment ("+strings.Join(dataSegmentIDs(metadata), ", ")+")", nil))
	}
	masterKey, openedID, err := getMasterKeySlot(ctx, dev.reader(), device, passphrase, header.VolumeKeyDigestsView(metadata), order, sys)
	if err != nil {
		return fail("unlock", fipsStateUntouched, err)
	}
	defer custody.Release(masterKey)

	// The prefilter above is what the header DECLARES; this is what the key
	// recovered actually satisfies, through the same digest evaluation the
	// unlock uses.
	if missing := unboundSegments(metadata, metadata.Digests, openedID, masterKey); len(missing) > 0 {
		return fail("unlock", fipsStateUntouched, fipsRefusal(errFIPSMigrationUnboundKey, "the key keyslot "+openedID+" holds is not bound to data segment(s) "+
			strings.Join(missing, ", ")+" by any digest it matches", nil))
	}

	// 2. PLAN. Every non-approved digest must attest the key just recovered.
	// Checked before anything is written, so a digest that cannot be migrated
	// costs a refusal and not a half-done import.
	var digestsToMigrate []string
	for _, id := range sortedDigestIDs(metadata.Digests) {
		digest := metadata.Digests[id]
		if digest == nil {
			continue
		}
		refusal, approved := digestFIPSRefusal(id, digest)
		if approved {
			continue
		}
		evaluated, matched := evaluateDigest(masterKey, digest, fips.Probe)
		if !evaluated || !matched {
			return fail("plan", fipsStateUntouched, fipsRefusal(errFIPSMigrationDigest, "digest "+id+" ("+refusal.String()+")", nil))
		}
		digestsToMigrate = append(digestsToMigrate, id)
	}

	// RECONCILE the two header copies before the first write, writing only the
	// secondary: see "Both header copies" above. Nothing else is written if
	// they already agree, which is every run that does not follow an
	// interrupted one.
	if header.HeaderCopiesAgree(dev.reader()) != nil {
		if err := repairSecondaryHeader(ctx, dev, hdr, metadata); err != nil {
			return fail("reconcile header copies", fipsStateOriginals, err)
		}
		if err := header.HeaderCopiesAgree(dev.reader()); err != nil {
			return fail("reconcile header copies", fipsStateOriginals, err)
		}
	}

	result := &fipsMigrationResultForTest{}

	// 3. ADD KEYSLOT -- through AddKey's own code, under the lock held here.
	// If it fails, nothing has been removed and nothing will be.
	slot, reusable := header.CanonicalKeyslotID(openedID)
	reusable = reusable && keyslotFIPSApproved(metadata.Keyslots[openedID])
	if !reusable {
		added, err := addKeyslotWithMasterKey(ctx, dev, hdr, metadata, masterKey, passphrase, addOpts, callerSuppliedCredential)
		if err != nil {
			return fail("add keyslot", fipsStateOriginals, err)
		}
		slot = added
		result.KeyslotAdded = true
	}
	result.Keyslot = slot
	slotID := strconv.Itoa(slot)

	// 4. MIGRATE DIGESTS. Each is replaced by a PBKDF2 digest over the same
	// volume key, keeping the keyslots and segments it attests. Every header
	// either copy of the write can leave behind attests the same key.
	if len(digestsToMigrate) > 0 {
		hdr, metadata, err = dev.readPrimaryHeader()
		if err != nil {
			return fail("migrate digest", fipsStateOriginals, err)
		}
		for _, id := range digestsToMigrate {
			kdf, value, err := createDigest(masterKey, o.Hash, sys)
			if err != nil {
				return fail("migrate digest", fipsStateOriginals, err)
			}
			digest := metadata.Digests[id]
			digest.Type = kdf.Type
			digest.Hash = kdf.Hash
			digest.Salt = kdf.Salt
			digest.Iterations = *kdf.Iterations
			// An Argon2 digest's cost members describe a KDF the digest no
			// longer uses; left in place they would declare Argon2 cost on a
			// PBKDF2 digest.
			digest.Time, digest.Memory, digest.CPUs = nil, nil, nil
			digest.Digest = value
		}
		hdr.SequenceID++
		if err := dev.writeHeader(ctx, hdr, metadata); err != nil {
			return fail("migrate digest", fipsStateOriginals, err)
		}
		result.MigratedDigests = digestsToMigrate
	}

	// 5. VERIFY, before anything is removed -- including that BOTH header
	// copies describe the volume just verified, so a removal interrupted later
	// leaves either one opening it.
	if err := verifyFIPSOpen(ctx, dev, passphrase, slotID, masterKey, sys); err != nil {
		return fail("verify", fipsStateOriginals, err)
	}
	if err := header.HeaderCopiesAgree(dev.reader()); err != nil {
		return fail("verify", fipsStateOriginals, fipsRefusal(errFIPSMigrationVerification, "the header copies do not agree after the writes", err))
	}

	// 6. REMOVE the non-approved keyslots, or record that they were kept.
	hdr, metadata, err = dev.readPrimaryHeader()
	if err != nil {
		return fail("remove keyslot", fipsStateOriginals, err)
	}
	for _, id := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		keyslot := metadata.Keyslots[id]
		if keyslot == nil || keyslot.Type != "luks2" || keyslotFIPSApproved(keyslot) {
			continue
		}
		if id == slotID {
			// Unreachable: slotID is approved by construction and verified in
			// step 5. Stated so the invariant the removal rests on is a
			// refusal rather than an assumption.
			return fail("remove keyslot", fipsStateOriginals, fipsRefusal(errFIPSMigrationVerification, "keyslot "+id+" is both the migrated keyslot and not approved", nil))
		}
		if o.KeepNonApprovedKeyslots {
			result.RetainedNonApprovedKeyslots = append(result.RetainedNonApprovedKeyslots, id)
			continue
		}
		if destroyed, err := removeKeyslotOn(ctx, dev, hdr, metadata, id); err != nil {
			// A refusal before the wipe, with nothing removed yet, leaves the
			// originals intact; anything else leaves the verified keyslot.
			state := fipsStateRemoving
			if !destroyed && len(result.RemovedKeyslots) == 0 {
				state = fipsStateOriginals
			}
			return fail("remove keyslot", state, err)
		}
		result.RemovedKeyslots = append(result.RemovedKeyslots, id)
	}

	// 7. FINAL CHECK, against the header as written. Static first -- nothing
	// non-approved may remain except what the caller asked to keep -- and then
	// a real open again, because the outcome being reported is THIS header.
	_, metadata, err = dev.readPrimaryHeader()
	if err != nil {
		return fail("final check", fipsStateFinal, err)
	}
	keyslots, digests := nonApprovedKDFs(metadata)
	var unexpected []string
	for _, k := range keyslots {
		if !slices.Contains(result.RetainedNonApprovedKeyslots, strconv.Itoa(k.ID)) {
			unexpected = append(unexpected, fmt.Sprintf("keyslot %d (%s)", k.ID, k))
		}
	}
	for _, d := range digests {
		unexpected = append(unexpected, fmt.Sprintf("digest %d (%s)", d.ID, d))
	}
	if len(unexpected) > 0 {
		return fail("final check", fipsStateFinal, fipsRefusal(errFIPSMigrationVerification, "still not approved: "+strings.Join(unexpected, ", "), nil))
	}
	if err := verifyFIPSOpen(ctx, dev, passphrase, slotID, masterKey, sys); err != nil {
		return fail("final check", fipsStateFinal, err)
	}

	result.Complete = len(result.RetainedNonApprovedKeyslots) == 0
	return result, nil
}

// verifyFIPSOpen is the real-open half of the verification: it re-reads the
// header from the device, unlocks keyslot id with passphrase through
// FIPS-approved digests only, and requires the key recovered to be want.
//
// Argon2 is not on this path by construction rather than by luck: the keyslot
// is refused unless its own KDF is approved, and the digest set handed to the
// unlock is filtered to approved ones before it gets there. It is therefore the
// path a FIPS process would take, run in a process that cannot BE one.
// fipsRefusal is one of the migration's own refusals, classified at its
// source (DESIGN.md §C.1): Kind is the public ErrFIPSMigration, and the
// refusal's sentinel -- with the failure that led to it, when there is one --
// stays reachable through Err. A bare sentinel, or one used as the Kind,
// left errAt nothing it recognized, and a policy refusal read as ErrIO.
func fipsRefusal(refusal error, detail string, cause error) *errs.Error {
	err := refusal
	if cause != nil {
		err = &fipsRefusalCause{refusal: refusal, err: cause}
	}
	return &errs.Error{Kind: ErrFIPSMigration, Detail: detail, Err: err}
}

// fipsRefusalCause is the cause of a refusal that follows from another
// failure: errors.Is and errors.As reach both the refusal and the failure.
type fipsRefusalCause struct{ refusal, err error }

func (c *fipsRefusalCause) Error() string   { return c.refusal.Error() + ": " + c.err.Error() }
func (c *fipsRefusalCause) Unwrap() []error { return []error{c.refusal, c.err} }

func verifyFIPSOpen(ctx context.Context, dev *keyslotDevice, passphrase []byte, id string, want *enclave.MemoryEnclave, sys volumeSys) error {
	_, metadata, err := dev.readPrimaryHeader()
	if err != nil {
		return err
	}
	keyslot := metadata.Keyslots[id]
	if keyslot == nil || !keyslotFIPSApproved(keyslot) {
		return fipsRefusal(errFIPSMigrationVerification, "keyslot "+id+" is missing or does not use a FIPS-approved KDF", nil)
	}

	approved := make(map[string]*header.Digest, len(metadata.Digests))
	for digestID, digest := range metadata.Digests {
		if digestFIPSApproved(digest) {
			approved[digestID] = digest
		}
	}

	got, err := unlockKeyslotFrom(ctx, dev.reader(), id, passphrase, keyslot, approved, sys)
	if err != nil {
		return fipsRefusal(errFIPSMigrationVerification, "keyslot "+id+" does not open through FIPS-approved KDFs", err)
	}
	defer custody.Release(got)

	same := false
	if err := secret.Borrow("compare the migrated volume key", got, func(b []byte) error {
		var err error
		same, err = want.EqualTo(b)
		return err
	}); err != nil {
		return err
	}
	if !same {
		return fipsRefusal(errFIPSMigrationVerification, "keyslot "+id+" opened to a key other than the volume key it was written with", nil)
	}

	// Opening to the right key is not yet opening the DATA: the approved
	// digests the key matches must bind every data segment, or a FIPS
	// process reaches the key and still cannot use it on the volume.
	if missing := unboundSegments(metadata, approved, id, got); len(missing) > 0 {
		return fipsRefusal(errFIPSMigrationVerification, "no FIPS-approved digest binds the key keyslot "+id+" holds to data segment(s) "+strings.Join(missing, ", "), nil)
	}

	// header.Keyslot id opening to the volume key is still not what a FIPS process
	// DOES: Unlock runs the keyslot scan and maps whatever it finds first. A
	// retained approved keyslot holding an unbound key under the same
	// passphrase would be found by a scan that ignored segment binding, and
	// dm-crypt would be handed the wrong key. So the scan itself is run, over
	// exactly what a FIPS process can execute, and must recover the volume key.
	view := fipsApprovedView(metadata)
	scanned, _, err := getMasterKeySlot(ctx, dev.reader(), dev.path, passphrase, view, header.VolumeKeyScanOrder(view), sys)
	if err != nil {
		return fipsRefusal(errFIPSMigrationVerification, "the unlock scan over FIPS-approved keyslots and digests does not open the volume", err)
	}
	defer custody.Release(scanned)
	if err := secret.Borrow("compare the scanned volume key", scanned, func(b []byte) error {
		var err error
		same, err = want.EqualTo(b)
		return err
	}); err != nil {
		return err
	}
	if !same {
		return fipsRefusal(errFIPSMigrationVerification, "the unlock scan over FIPS-approved keyslots and digests recovers a key other than the volume key", nil)
	}
	return nil
}

// fipsApprovedView returns a shallow copy of metadata holding only what a FIPS
// process can execute: luks2 keyslots whose KDF is approved and digests whose
// KDF is approved. Running the ordinary unlock scan over it is running the scan
// a FIPS process runs, without Argon2 ever being reachable.
func fipsApprovedView(metadata *header.Metadata) *header.Metadata {
	view := *metadata
	view.Keyslots = make(map[string]*header.Keyslot, len(metadata.Keyslots))
	for id, keyslot := range metadata.Keyslots {
		if keyslot != nil && keyslot.Type == "luks2" && keyslotFIPSApproved(keyslot) {
			view.Keyslots[id] = keyslot
		}
	}
	view.Digests = make(map[string]*header.Digest, len(metadata.Digests))
	for id, digest := range metadata.Digests {
		if digestFIPSApproved(digest) {
			view.Digests[id] = digest
		}
	}
	return &view
}

// removeKeyslotOn removes one keyslot for a caller that already holds the
// device lock, in the order every removal in this package takes: the removal
// gate, then the header proved writable, then the wipe, then the header.
// destroyed reports whether the keyslot's material may already have been wiped
// when an error is returned, so the caller never reports a keyslot intact that
// is not.
//
// removeKeyslotOn is the name the rollback paths use (#246); every caller holds
// the locked descriptor and removes through it.
func removeKeyslotOn(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, id string) (destroyed bool, err error) {
	target := metadata.Keyslots[id]

	// THE GATE -- the same one RemoveKey, KillSlot and KillKeyslot take:
	// are the bytes about to be randomized keyslot bytes, can anything still
	// open the volume after this removal, and do the bytes about to be wiped
	// belong to anything that can?
	if err := checkKeyslotRemovable(dev, hdr, metadata, id); err != nil {
		return false, err
	}

	removeKeyslotFromMetadata(metadata, id)
	hdr.SequenceID++
	if err := checkHeaderWritable(hdr, metadata); err != nil {
		return false, err
	}

	// From here the operation is destructive.
	if err := wipeKeyslotArea(ctx, dev, hdr, metadata, id, target); err != nil {
		return true, err
	}
	return true, dev.writeHeader(ctx, hdr, metadata)
}

// fipsApprovedKDF reports whether a KDF, as a header declares it, is one a FIPS
// 140-3 process can execute. It is IsFIPSCompliantKDF plus the hash: on disk a
// PBKDF2 KDF is type "pbkdf2" with a separate hash member, and "pbkdf2" over
// SHA-1 is refused in FIPS mode (getPBKDF2HashFunc) even though the type alone
// is approved.
func fipsApprovedKDF(kdfType, hash string) bool {
	if !isFIPSCompliantKDF(kdfType) {
		return false
	}
	if normalizeKDFType(kdfType) != kdfTypePBKDF2 {
		return true
	}
	switch strings.ToLower(hash) {
	case "sha256", "sha384", "sha512":
		return true
	default:
		return false
	}
}

// The parameter floors crypto/pbkdf2.Key enforces under GODEBUG=fips140=only,
// on top of the hash: a salt of at least 128 bits and an output of at least 112
// bits. A PBKDF2-SHA256 KDF below either is refused there with an error, so an
// approved NAME is not enough to call a keyslot or digest openable in strict
// FIPS mode -- a foreign writer is free to choose an eight-byte salt.
const (
	fipsMinSaltLen   = 128 / 8
	fipsMinOutputLen = 112 / 8
)

// fipsParameterRefusal returns why strict FIPS mode would refuse a PBKDF2
// derivation over salt to outputLen bytes, or "" if it would not. A salt that
// does not decode is refused too: no FIPS process derives through it.
func fipsParameterRefusal(salt string, outputLen int) string {
	decoded, err := decodeBase64(salt)
	if err != nil {
		return "salt is not base64"
	}
	if len(decoded) < fipsMinSaltLen {
		return "salt shorter than 128 bits"
	}
	if outputLen < fipsMinOutputLen {
		return "output shorter than 112 bits"
	}
	return ""
}

// keyslotFIPSRefusal describes why a luks2 keyslot's own KDF could not run in
// a strict FIPS process, as a NonApprovedKDF with its ID set, or reports ok when
// it could: the algorithm approved (fipsApprovedKDF) and its parameters above
// the floors crypto/pbkdf2 enforces, the output being the keyslot's key size.
func keyslotFIPSRefusal(id string, keyslot *header.Keyslot) (refusal NonApprovedKDF, ok bool) {
	refusal.ID, _ = strconv.Atoi(id) // id is always a canonical keyslot ID (a small decimal integer)
	if keyslot == nil || keyslot.KDF == nil {
		refusal.Reason = "no KDF object"
		return refusal, false
	}
	refusal.Type, refusal.Hash = keyslot.KDF.Type, keyslot.KDF.Hash
	// The anti-forensic hash runs on every unlock too, and SHA-1 -- what a
	// converted LUKS1 keyslot carries -- is not approved there (#236). Named
	// even when the KDF is refused as well, so an operator is told every
	// reason the keyslot cannot be opened in FIPS mode.
	afRefused := keyslot.AF != nil && keyslot.AF.Hash == "sha1"
	if afRefused {
		refusal.Reason = "anti-forensic hash sha1"
	}
	if !fipsApprovedKDF(keyslot.KDF.Type, keyslot.KDF.Hash) || afRefused {
		return refusal, false
	}
	// The KDF's output is the key that wraps the AREA, whose length is
	// area.key_size (#249, A6); the volume key's is what it was taken from
	// only while the two agree.
	outputLen := keyslot.KeySize
	if keyslot.Area != nil {
		outputLen = keyslot.Area.KeySize
	}
	refusal.Reason = fipsParameterRefusal(keyslot.KDF.Salt, outputLen)
	return refusal, refusal.Reason == ""
}

// digestFIPSRefusal is keyslotFIPSRefusal for a digest, whose output length is
// the length of its stored value.
func digestFIPSRefusal(id string, digest *header.Digest) (refusal NonApprovedKDF, ok bool) {
	refusal.ID, _ = strconv.Atoi(id) // id is always a canonical digest ID (a small decimal integer)
	if digest == nil {
		refusal.Reason = "digest is null"
		return refusal, false
	}
	refusal.Type, refusal.Hash = digest.Type, digest.Hash
	if !fipsApprovedKDF(digest.Type, digest.Hash) {
		return refusal, false
	}
	value, err := decodeBase64(digest.Digest)
	if err != nil {
		refusal.Reason = "digest value is not base64"
		return refusal, false
	}
	refusal.Reason = fipsParameterRefusal(digest.Salt, len(value))
	return refusal, refusal.Reason == ""
}

// keyslotFIPSApproved reports whether a strict FIPS process could run a
// keyslot's own KDF: algorithm and parameters both.
func keyslotFIPSApproved(keyslot *header.Keyslot) bool {
	_, ok := keyslotFIPSRefusal("", keyslot)
	return ok
}

// digestFIPSApproved reports whether a strict FIPS process could run a
// digest's KDF: algorithm and parameters both.
func digestFIPSApproved(digest *header.Digest) bool {
	_, ok := digestFIPSRefusal("", digest)
	return ok
}

// dataSegmentIDs returns every segment id the header declares, sorted. A
// volume's data is reachable only through a key some digest binds to each of
// them.
func dataSegmentIDs(metadata *header.Metadata) []string {
	ids := make([]string, 0, len(metadata.Segments))
	for id, segment := range metadata.Segments {
		if segment != nil {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

// keyslotDeclaredForAllSegments reports whether the digests attesting keyslot
// id, taken together, name every data segment. It is the static half of "does
// this keyslot hold the volume key": a keyslot failing it holds, at best, an
// unbound key, and is never the one the migration carries across.
func keyslotDeclaredForAllSegments(metadata *header.Metadata, id string) bool {
	var bound []string
	for _, digest := range metadata.Digests {
		if digestCovers(digest, id) {
			bound = append(bound, digest.Segments...)
		}
	}
	for _, segment := range dataSegmentIDs(metadata) {
		if !slices.Contains(bound, segment) {
			return false
		}
	}
	return true
}

// unboundSegments returns the data segments no digest in digests binds to key
// through keyslot id: each digest must attest the keyslot AND be evaluated to
// match key, so what is checked is the key actually recovered, not what the
// header declares about the keyslot. Empty means key opens every segment.
func unboundSegments(metadata *header.Metadata, digests map[string]*header.Digest, id string, key *enclave.MemoryEnclave) []string {
	var bound []string
	for _, digestID := range sortedDigestIDs(digests) {
		digest := digests[digestID]
		if !digestCovers(digest, id) {
			continue
		}
		if _, matched := evaluateDigest(key, digest, fips.Probe); matched {
			bound = append(bound, digest.Segments...)
		}
	}
	var missing []string
	for _, segment := range dataSegmentIDs(metadata) {
		if !slices.Contains(bound, segment) {
			missing = append(missing, segment)
		}
	}
	return missing
}

// nonApprovedKDFs is the STATIC half of the verification: every luks2 keyslot
// and every digest whose KDF a FIPS process cannot execute, in scan order and
// digest-id order respectively.
//
// Keyslots of any other type are not listed. A "reencrypt" keyslot carries no
// passphrase-wrapped key and no KDF a FIPS process would run to open the
// volume.
func nonApprovedKDFs(metadata *header.Metadata) (keyslots, digests []NonApprovedKDF) {
	for _, id := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		keyslot := metadata.Keyslots[id]
		if keyslot == nil || keyslot.Type != "luks2" {
			continue
		}
		if refusal, ok := keyslotFIPSRefusal(id, keyslot); !ok {
			keyslots = append(keyslots, refusal)
		}
	}
	for _, id := range sortedDigestIDs(metadata.Digests) {
		if metadata.Digests[id] == nil {
			continue
		}
		if refusal, ok := digestFIPSRefusal(id, metadata.Digests[id]); !ok {
			digests = append(digests, refusal)
		}
	}
	return keyslots, digests
}

// fipsFirstScanOrder is header.KeyslotIDsInScanOrder with the FIPS-approved keyslots
// moved to the front, each group keeping its own order.
func fipsFirstScanOrder(metadata *header.Metadata) []string {
	all := header.KeyslotIDsInScanOrder(metadata.Keyslots)
	order := make([]string, 0, len(all))
	for _, id := range all {
		if keyslotFIPSApproved(metadata.Keyslots[id]) {
			order = append(order, id)
		}
	}
	for _, id := range all {
		if !keyslotFIPSApproved(metadata.Keyslots[id]) {
			order = append(order, id)
		}
	}
	return order
}

// sortedDigestIDs returns the digest ids in a fixed order, so what is migrated
// and what is reported do not depend on map iteration.
func sortedDigestIDs(digests map[string]*header.Digest) []string {
	ids := make([]string, 0, len(digests))
	for id := range digests {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// keyslotRefusedByFIPS reports whether a keyslot that could not be tried was
// refused ONLY because this process runs in FIPS 140-3 mode -- so that it is
// reported as a volume needing import rather than as a damaged one, and, just
// as importantly, so that a damaged one is never reported as needing import.
//
// "Only" is COMPUTED, not inferred from which algorithms the header names. The
// keyslot is screened again with every KDF the FIPS gates refused -- its own,
// and those of the digests attesting it -- replaced by an approved stand-in,
// and each replaced KDF must first pass the structural half of the screen
// (screenKDFStructure, screenDigestStructure) that the gates would otherwise
// have cut short. If that screen passes, the gates were the whole of the
// refusal. If it fails, something else is wrong with the keyslot or its
// digests, and the caller reports that instead: a SHA-1 digest whose value is
// not base64 is a damaged header whatever mode reads it.
func keyslotRefusedByFIPS(id string, keyslot *header.Keyslot, digests map[string]*header.Digest, fipsMode func() fips.Mode) bool {
	if !fipsMode() || keyslot == nil || keyslot.Type != "luks2" {
		return false
	}

	// A keyslot the screen passes was refused later -- reading or decrypting
	// its area -- and no FIPS gate runs there.
	if _, err := screenKeyslot(id, keyslot, digests, fipsMode); err == nil {
		return false
	}

	standIn, substituted, ok := fipsStandInKeyslot(keyslot)
	if !ok {
		return false
	}
	standInDigests := make(map[string]*header.Digest, len(digests))
	for digestID, digest := range digests {
		standInDigests[digestID] = digest
		if !digestCovers(digest, id) || digestFIPSApproved(digest) {
			continue
		}
		if replaced, ok := fipsStandInDigest(digest); ok {
			standInDigests[digestID] = replaced
			substituted = true
		}
	}
	if !substituted {
		return false
	}

	_, err := screenKeyslot(id, standIn, standInDigests, fipsMode)
	return err == nil
}

// fipsStandInKeyslot returns keyslot with its KDF replaced by an approved
// PBKDF2 stand-in, when its own KDF is not approved but is well formed.
// substituted reports whether a replacement was made; ok is false when the KDF
// is malformed, which no FIPS policy explains.
func fipsStandInKeyslot(keyslot *header.Keyslot) (standIn *header.Keyslot, substituted, ok bool) {
	if keyslotFIPSApproved(keyslot) {
		return keyslot, false, true
	}
	if keyslot.KDF == nil || header.ValidateKDFCost(keyslot.KDF) != nil || screenKDFStructure(keyslot.KDF) != nil {
		return nil, false, false
	}
	replaced := *keyslot
	replaced.KDF = fipsStandInKDF(keyslot.KDF.Salt)
	// A SHA-1 anti-forensic hash is refused by policy alone (#236): stand an
	// approved one in for it. Any other unreadable name is left, so the
	// screen still reports it as the damage it is.
	if keyslot.AF != nil && keyslot.AF.Hash == "sha1" {
		af := *keyslot.AF
		af.Hash = defaultHashAlgo
		replaced.AF = &af
	}
	return &replaced, true, true
}

// fipsStandInDigest returns digest with its KDF replaced by an approved PBKDF2
// stand-in, when it is well formed apart from its KDF's approval.
func fipsStandInDigest(digest *header.Digest) (*header.Digest, bool) {
	expected, _, err := screenDigestStructure(digest)
	clearBytes(expected)
	if err != nil {
		return nil, false
	}
	kdf := fipsStandInKDF(digest.Salt)
	replaced := *digest
	replaced.Type, replaced.Hash, replaced.Iterations = kdf.Type, kdf.Hash, *kdf.Iterations
	replaced.Time, replaced.Memory, replaced.CPUs = nil, nil, nil
	replaced.Digest = encodeBase64(make([]byte, sha256DigestLen))
	return &replaced, true
}

// sha256DigestLen is the length of a PBKDF2-SHA256 digest, the stand-in's.
const sha256DigestLen = 32

// fipsStandInKDF is an approved KDF over salt, which the caller has already
// checked decodes. It is screened, never run.
func fipsStandInKDF(salt string) *header.KDF {
	iterations := header.MinKDFIterations
	return &header.KDF{Type: kdfTypePBKDF2, Hash: "sha256", Salt: salt, Iterations: &iterations}
}

// newFIPSImportRequiredError names what a FIPS process refused on the keyslots
// in blocked: each one's own KDF if that is not approved, and every
// non-approved digest attesting any of them.
func newFIPSImportRequiredError(device string, metadata *header.Metadata, blocked []string) error {
	e := &FIPSImportRequiredError{Device: device}
	for _, id := range blocked {
		keyslot := metadata.Keyslots[id]
		if keyslot == nil || keyslot.KDF == nil {
			continue
		}
		if refusal, ok := keyslotFIPSRefusal(id, keyslot); !ok {
			e.Keyslots = append(e.Keyslots, refusal)
		}
	}
	for _, id := range sortedDigestIDs(metadata.Digests) {
		digest := metadata.Digests[id]
		if digest == nil {
			continue
		}
		refusal, ok := digestFIPSRefusal(id, digest)
		if ok {
			continue
		}
		if slices.ContainsFunc(blocked, func(k string) bool { return digestCovers(digest, k) }) {
			e.Digests = append(e.Digests, refusal)
		}
	}
	return e
}
