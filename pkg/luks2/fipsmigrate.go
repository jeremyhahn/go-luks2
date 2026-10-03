// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-enclave"
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
// and a FIPS process cannot execute Argon2 (requireFIPSApprovedKDF). So this is
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
// (writeHeaderInternal), so an interruption tears at most one copy, and the
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

// FIPSMigrationOptions tunes MigrateToFIPS. The zero value -- or nil -- is the
// complete import: a PBKDF2-SHA256 keyslot at a calibrated cost, and every
// non-approved keyslot removed.
type FIPSMigrationOptions struct {
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

// FIPSMigrationResult is what MigrateToFIPS did, reported from the point of
// decision rather than left to be inferred from the header afterwards.
type FIPSMigrationResult struct {
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
func stateAfterWriteFailure(device string, area int64, state string) string {
	sources, err := mediumSources(device)
	if err != nil {
		return fipsStateUnconfirmed
	}
	deepest := sources[len(sources)-1]
	medium, err := readDeviceDirect(deepest.path, deepest.offset, int(2*area))
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

// MigrateToFIPS imports a volume into a FIPS 140-3 deployment by rewrapping its
// existing volume key under PBKDF2: it adds a PBKDF2 keyslot for passphrase
// holding the same volume key, migrates every digest whose KDF is not approved,
// verifies the volume opens through approved KDFs alone, and then removes the
// keyslots FIPS mode cannot execute. No data is re-encrypted.
//
// It must run in a process that is NOT in FIPS mode, because unlocking the
// volume executes its Argon2 keyslot; in a FIPS process it returns
// ErrFIPSMigrationUnderFIPS without touching the device.
//
// Only passphrase's credential is carried across. Other credentials held only
// in non-approved keyslots are removed with them unless
// KeepNonApprovedKeyslots is set; migrate each with that option and remove the
// originals with a final call without it.
//
// On failure the error is a *FIPSMigrationError whose State says what the
// volume was left as.
func MigrateToFIPS(device string, passphrase []byte, opts *FIPSMigrationOptions) (*FIPSMigrationResult, error) {
	// The header area size, once the run has read and validated one: what a
	// failure report reads the secondary at (stateAfterWriteFailure).
	var area int64
	fail := func(stage, state string, err error) (*FIPSMigrationResult, error) {
		if state == fipsStateOriginals || state == fipsStateRemoving {
			state = stateAfterWriteFailure(device, area, state)
		}
		return nil, &FIPSMigrationError{Device: device, Stage: stage, State: state, Err: err}
	}

	if fipsMode() {
		return fail("precondition", fipsStateUntouched, ErrFIPSMigrationUnderFIPS)
	}
	if err := ValidateDevicePath(device); err != nil {
		return fail("precondition", fipsStateUntouched, err)
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return fail("precondition", fipsStateUntouched, err)
	}

	o := FIPSMigrationOptions{}
	if opts != nil {
		o = *opts
	}
	if o.Hash == "" {
		o.Hash = DefaultHashAlgo
	}
	o.Hash = strings.ToLower(o.Hash)
	if !fipsApprovedKDF(KDFTypePBKDF2, o.Hash) {
		return fail("precondition", fipsStateUntouched, &detailError{
			Kind:   ErrUnsupportedHash,
			Detail: "PBKDF2 hash " + strconv.Quote(o.Hash) + " is not one FIPS mode can run (sha256, sha384, sha512)",
		})
	}
	// The new keyslot's cost is judged where AddKey judges it, in createKDF,
	// which runs before anything is written.
	addOpts := &AddKeyOptions{
		KDFType:         KDFTypePBKDF2,
		Hash:            o.Hash,
		PBKDFIterTime:   o.PBKDFIterTime,
		PBKDFIterations: o.PBKDFIterations,
	}

	lock, err := AcquireFileLock(device)
	if err != nil {
		return fail("precondition", fipsStateUntouched, err)
	}
	defer func() { _ = lock.Release() }()

	// SYNC, then READ FROM THE MEDIUM: see "Both header copies" above. The
	// lock's descriptor is the device's own; fsync flushes every dirty page
	// of it whoever wrote them, and evicting the clean pages after it means
	// every byte this run reads -- headers above all -- comes off the medium,
	// not out of a cache that may hold what never reached it.
	if err := syncDevice(lock.file); err != nil {
		return fail("sync", fipsStateUntouched, &detailError{
			Detail: "failed to make what an earlier write left in the page cache durable before reading", Err: err})
	}
	if err := dropDeviceCache(lock.file); err != nil {
		return fail("sync", fipsStateUntouched, &detailError{
			Detail: "failed to evict the device's cached pages, so what is read could not be shown to be on the medium", Err: err})
	}
	// Eviction is advisory -- a page another process holds mapped stays
	// cached and the call still succeeds -- so it is not the proof. This is:
	// the header region read through the cache must equal the same bytes read
	// past it.
	if err := requireCacheMatchesMedium(device); err != nil {
		return fail("sync", fipsStateUntouched, err)
	}

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return fail("unlock", fipsStateUntouched, err)
	}
	headerArea, err := headerAreaSize(hdr)
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
	for _, id := range keyslotIDsInScanOrder(metadata.Keyslots) {
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
		if keyslotDeclaredForAllSegments(metadata, id) {
			order = append(order, id)
		}
	}
	if len(order) == 0 {
		return fail("unlock", fipsStateUntouched, &detailError{
			Kind:   ErrFIPSMigrationUnboundKey,
			Detail: "no keyslot is attested by digests binding every data segment (" + strings.Join(dataSegmentIDs(metadata), ", ") + ")",
		})
	}
	masterKey, openedID, err := getMasterKeySlot(device, passphrase, metadata, order)
	if err != nil {
		return fail("unlock", fipsStateUntouched, err)
	}
	defer releaseSecret(masterKey)

	// The prefilter above is what the header DECLARES; this is what the key
	// recovered actually satisfies, through the same digest evaluation the
	// unlock uses.
	if missing := unboundSegments(metadata, metadata.Digests, openedID, masterKey); len(missing) > 0 {
		return fail("unlock", fipsStateUntouched, &detailError{
			Kind: ErrFIPSMigrationUnboundKey,
			Detail: "the key keyslot " + openedID + " holds is not bound to data segment(s) " +
				strings.Join(missing, ", ") + " by any digest it matches",
		})
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
		evaluated, matched := evaluateDigest(masterKey, digest)
		if !evaluated || !matched {
			return fail("plan", fipsStateUntouched, &detailError{
				Kind:   ErrFIPSMigrationDigest,
				Detail: "digest " + id + " (" + refusal.String() + ")",
			})
		}
		digestsToMigrate = append(digestsToMigrate, id)
	}

	// RECONCILE the two header copies before the first write, writing only the
	// secondary: see "Both header copies" above. Nothing else is written if
	// they already agree, which is every run that does not follow an
	// interrupted one.
	if headerCopiesAgree(device) != nil {
		if err := repairSecondaryHeader(device, hdr, metadata); err != nil {
			return fail("reconcile header copies", fipsStateOriginals, err)
		}
		if err := headerCopiesAgree(device); err != nil {
			return fail("reconcile header copies", fipsStateOriginals, err)
		}
	}

	result := &FIPSMigrationResult{}

	// 3. ADD KEYSLOT -- through AddKey's own code, under the lock held here.
	// If it fails, nothing has been removed and nothing will be.
	slot, reusable := canonicalKeyslotID(openedID)
	reusable = reusable && keyslotFIPSApproved(metadata.Keyslots[openedID])
	if !reusable {
		added, err := addKeyslotWithMasterKey(device, hdr, metadata, masterKey, passphrase, addOpts, callerSuppliedCredential)
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
		hdr, metadata, err = ReadHeader(device)
		if err != nil {
			return fail("migrate digest", fipsStateOriginals, err)
		}
		for _, id := range digestsToMigrate {
			kdf, value, err := createDigest(masterKey, o.Hash)
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
		if err := writeHeaderInternal(device, hdr, metadata); err != nil {
			return fail("migrate digest", fipsStateOriginals, err)
		}
		result.MigratedDigests = digestsToMigrate
	}

	// 5. VERIFY, before anything is removed -- including that BOTH header
	// copies describe the volume just verified, so a removal interrupted later
	// leaves either one opening it.
	if err := verifyFIPSOpen(device, passphrase, slotID, masterKey); err != nil {
		return fail("verify", fipsStateOriginals, err)
	}
	if err := headerCopiesAgree(device); err != nil {
		return fail("verify", fipsStateOriginals, &detailError{Kind: ErrFIPSMigrationVerification,
			Detail: "the header copies do not agree after the writes", Err: err})
	}

	// 6. REMOVE the non-approved keyslots, or record that they were kept.
	hdr, metadata, err = ReadHeader(device)
	if err != nil {
		return fail("remove keyslot", fipsStateOriginals, err)
	}
	for _, id := range keyslotIDsInScanOrder(metadata.Keyslots) {
		keyslot := metadata.Keyslots[id]
		if keyslot == nil || keyslot.Type != "luks2" || keyslotFIPSApproved(keyslot) {
			continue
		}
		if id == slotID {
			// Unreachable: slotID is approved by construction and verified in
			// step 5. Stated so the invariant the removal rests on is a
			// refusal rather than an assumption.
			return fail("remove keyslot", fipsStateOriginals, &detailError{
				Kind: ErrFIPSMigrationVerification, Detail: "keyslot " + id + " is both the migrated keyslot and not approved",
			})
		}
		if o.KeepNonApprovedKeyslots {
			result.RetainedNonApprovedKeyslots = append(result.RetainedNonApprovedKeyslots, id)
			continue
		}
		if destroyed, err := removeKeyslotLocked(device, hdr, metadata, id); err != nil {
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
	_, metadata, err = ReadHeader(device)
	if err != nil {
		return fail("final check", fipsStateFinal, err)
	}
	keyslots, digests := nonApprovedKDFs(metadata)
	var unexpected []string
	for _, k := range keyslots {
		if !slices.Contains(result.RetainedNonApprovedKeyslots, k.ID) {
			unexpected = append(unexpected, "keyslot "+k.ID+" ("+k.String()+")")
		}
	}
	for _, d := range digests {
		unexpected = append(unexpected, "digest "+d.ID+" ("+d.String()+")")
	}
	if len(unexpected) > 0 {
		return fail("final check", fipsStateFinal, &detailError{
			Kind:   ErrFIPSMigrationVerification,
			Detail: "still not approved: " + strings.Join(unexpected, ", "),
		})
	}
	if err := verifyFIPSOpen(device, passphrase, slotID, masterKey); err != nil {
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
func verifyFIPSOpen(device string, passphrase []byte, id string, want *enclave.MemoryEnclave) error {
	_, metadata, err := ReadHeader(device)
	if err != nil {
		return err
	}
	keyslot := metadata.Keyslots[id]
	if keyslot == nil || !keyslotFIPSApproved(keyslot) {
		return &detailError{Kind: ErrFIPSMigrationVerification,
			Detail: "keyslot " + id + " is missing or does not use a FIPS-approved KDF"}
	}

	approved := make(map[string]*Digest, len(metadata.Digests))
	for digestID, digest := range metadata.Digests {
		if digestFIPSApproved(digest) {
			approved[digestID] = digest
		}
	}

	got, err := unlockKeyslot(device, id, passphrase, keyslot, approved)
	if err != nil {
		return &detailError{Kind: ErrFIPSMigrationVerification,
			Detail: "keyslot " + id + " does not open through FIPS-approved KDFs", Err: err}
	}
	defer releaseSecret(got)

	same := false
	if err := borrowSecret("compare the migrated volume key", got, func(b []byte) error {
		same = want.EqualTo(b)
		return nil
	}); err != nil {
		return err
	}
	if !same {
		return &detailError{Kind: ErrFIPSMigrationVerification,
			Detail: "keyslot " + id + " opened to a key other than the volume key it was written with"}
	}

	// Opening to the right key is not yet opening the DATA: the approved
	// digests the key matches must bind every data segment, or a FIPS
	// process reaches the key and still cannot use it on the volume.
	if missing := unboundSegments(metadata, approved, id, got); len(missing) > 0 {
		return &detailError{Kind: ErrFIPSMigrationVerification,
			Detail: "no FIPS-approved digest binds the key keyslot " + id + " holds to data segment(s) " + strings.Join(missing, ", ")}
	}

	// Keyslot id opening to the volume key is still not what a FIPS process
	// DOES: Unlock runs the keyslot scan and maps whatever it finds first. A
	// retained approved keyslot holding an unbound key under the same
	// passphrase would be found by a scan that ignored segment binding, and
	// dm-crypt would be handed the wrong key. So the scan itself is run, over
	// exactly what a FIPS process can execute, and must recover the volume key.
	scanned, err := getMasterKey(device, passphrase, fipsApprovedView(metadata))
	if err != nil {
		return &detailError{Kind: ErrFIPSMigrationVerification,
			Detail: "the unlock scan over FIPS-approved keyslots and digests does not open the volume", Err: err}
	}
	defer releaseSecret(scanned)
	if err := borrowSecret("compare the scanned volume key", scanned, func(b []byte) error {
		same = want.EqualTo(b)
		return nil
	}); err != nil {
		return err
	}
	if !same {
		return &detailError{Kind: ErrFIPSMigrationVerification,
			Detail: "the unlock scan over FIPS-approved keyslots and digests recovers a key other than the volume key"}
	}
	return nil
}

// fipsApprovedView returns a shallow copy of metadata holding only what a FIPS
// process can execute: luks2 keyslots whose KDF is approved and digests whose
// KDF is approved. Running the ordinary unlock scan over it is running the scan
// a FIPS process runs, without Argon2 ever being reachable.
func fipsApprovedView(metadata *LUKS2Metadata) *LUKS2Metadata {
	view := *metadata
	view.Keyslots = make(map[string]*Keyslot, len(metadata.Keyslots))
	for id, keyslot := range metadata.Keyslots {
		if keyslot != nil && keyslot.Type == "luks2" && keyslotFIPSApproved(keyslot) {
			view.Keyslots[id] = keyslot
		}
	}
	view.Digests = make(map[string]*Digest, len(metadata.Digests))
	for id, digest := range metadata.Digests {
		if digestFIPSApproved(digest) {
			view.Digests[id] = digest
		}
	}
	return &view
}

// removeKeyslotLocked removes one keyslot for a caller that already holds the
// device lock, in the order every removal in this package takes: the removal
// gate, then the header proved writable, then the wipe, then the header.
// destroyed reports whether the keyslot's material may already have been wiped
// when an error is returned, so the caller never reports a keyslot intact that
// is not.
func removeKeyslotLocked(device string, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata, id string) (destroyed bool, err error) {
	target := metadata.Keyslots[id]

	// The bytes about to be randomized must be keyslot bytes. The gate below
	// protects the SURVIVING keyslots' areas; this protects the header and
	// the data from an area that points at them.
	if err := checkKeyslotAreaConfined(hdr, metadata, id); err != nil {
		return false, err
	}

	// THE GATE -- the same one RemoveKey, KillSlot and KillKeyslot take:
	// after this removal, can anything still open the volume, and do the bytes
	// about to be wiped belong to anything that can?
	if err := checkKeyslotRemovable(device, metadata, id); err != nil {
		return false, err
	}

	removeKeyslotFromMetadata(metadata, id)
	hdr.SequenceID++
	if err := checkHeaderWritable(hdr, metadata); err != nil {
		return false, err
	}

	// From here the operation is destructive.
	if err := wipeKeyslotArea(device, target); err != nil {
		return true, err
	}
	return true, writeHeaderInternal(device, hdr, metadata)
}

// checkKeyslotAreaConfined refuses a keyslot whose area is not wholly inside
// the container's reserved keyslots area (keyslotsAreaBounds), or that reaches
// into any data segment -- an area the migration would therefore read outside
// keyslot space when it unlocks or scans the keyslot, or overwrite when it
// removes it.
//
// checkKeyslotRemovable already refuses a wipe that would reach a SURVIVING
// keyslot's area, and wipeKeyslotArea refuses one past the end of the device.
// Neither asks whether the area is keyslot space at all, so a keyslot that
// cannot open anything -- and is therefore exactly what the migration removes
// -- could point its area into the header or the encrypted data and have it
// overwritten with random bytes, with the final verification still passing
// because it reads only the header and the new keyslot; and one that CAN open
// the volume could declare an area running into the data, of which the
// unlock reads every byte. Both boundaries are read from the container, never
// assumed.
func checkKeyslotAreaConfined(hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata, id string) error {
	keyslot := metadata.Keyslots[id]
	if keyslot == nil || keyslot.Area == nil {
		return &detailError{Kind: ErrInvalidKeyslot, Detail: "keyslot " + id + " declares no area, so what removing it would wipe is unknown"}
	}
	offset, offErr := parseSize(keyslot.Area.Offset)
	size, sizeErr := parseSize(keyslot.Area.Size)
	if offErr != nil || sizeErr != nil || offset < 0 || size <= 0 || offset > math.MaxInt64-size {
		return &detailError{Kind: ErrInvalidKeyslot, Detail: fmt.Sprintf(
			"keyslot %s declares an area at offset %q of size %q, which is not a byte range", id, keyslot.Area.Offset, keyslot.Area.Size)}
	}
	end := offset + size

	start, limit, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		return err
	}
	if offset < start || end > limit {
		return &detailError{Kind: ErrKeyslotAreaOverlap, Detail: fmt.Sprintf(
			"keyslot %s declares its area at [%d,%d), outside the container's keyslots area [%d,%d); "+
				"reading or wiping it would touch bytes that are not keyslot material", id, offset, end, start, limit)}
	}

	segmentIDs := make([]string, 0, len(metadata.Segments))
	for segmentID := range metadata.Segments {
		segmentIDs = append(segmentIDs, segmentID)
	}
	slices.Sort(segmentIDs)
	for _, segmentID := range segmentIDs {
		segment := metadata.Segments[segmentID]
		if segment == nil {
			continue
		}
		segmentStart, err := parseSize(segment.Offset)
		if err != nil || segmentStart < 0 {
			return &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
				"data segment %s declares an offset of %q, so whether removing keyslot %s would overwrite it cannot be decided",
				segmentID, segment.Offset, id)}
		}
		segmentEnd := int64(math.MaxInt64)
		if segment.Size != "dynamic" {
			segmentSize, err := parseSize(segment.Size)
			if err != nil || segmentSize < 0 || segmentStart > math.MaxInt64-segmentSize {
				return &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
					"data segment %s declares a size of %q, so whether removing keyslot %s would overwrite it cannot be decided",
					segmentID, segment.Size, id)}
			}
			segmentEnd = segmentStart + segmentSize
		}
		if offset < segmentEnd && segmentStart < end {
			return &detailError{Kind: ErrKeyslotAreaOverlap, Detail: fmt.Sprintf(
				"keyslot %s declares its area at [%d,%d), which overlaps data segment %s starting at %d; "+
					"reading or wiping it would touch the encrypted data", id, offset, end, segmentID, segmentStart)}
		}
	}
	return nil
}

// fipsApprovedKDF reports whether a KDF, as a header declares it, is one a FIPS
// 140-3 process can execute. It is IsFIPSCompliantKDF plus the hash: on disk a
// PBKDF2 KDF is type "pbkdf2" with a separate hash member, and "pbkdf2" over
// SHA-1 is refused in FIPS mode (getPBKDF2HashFunc) even though the type alone
// is approved.
func fipsApprovedKDF(kdfType, hash string) bool {
	if !IsFIPSCompliantKDF(kdfType) {
		return false
	}
	if normalizeKDFType(kdfType) != KDFTypePBKDF2 {
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
func keyslotFIPSRefusal(id string, keyslot *Keyslot) (refusal NonApprovedKDF, ok bool) {
	refusal.ID = id
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
	refusal.Reason = fipsParameterRefusal(keyslot.KDF.Salt, keyslot.KeySize)
	return refusal, refusal.Reason == ""
}

// digestFIPSRefusal is keyslotFIPSRefusal for a digest, whose output length is
// the length of its stored value.
func digestFIPSRefusal(id string, digest *Digest) (refusal NonApprovedKDF, ok bool) {
	refusal.ID = id
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
func keyslotFIPSApproved(keyslot *Keyslot) bool {
	_, ok := keyslotFIPSRefusal("", keyslot)
	return ok
}

// digestFIPSApproved reports whether a strict FIPS process could run a
// digest's KDF: algorithm and parameters both.
func digestFIPSApproved(digest *Digest) bool {
	_, ok := digestFIPSRefusal("", digest)
	return ok
}

// dataSegmentIDs returns every segment id the header declares, sorted. A
// volume's data is reachable only through a key some digest binds to each of
// them.
func dataSegmentIDs(metadata *LUKS2Metadata) []string {
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
func keyslotDeclaredForAllSegments(metadata *LUKS2Metadata, id string) bool {
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
func unboundSegments(metadata *LUKS2Metadata, digests map[string]*Digest, id string, key *enclave.MemoryEnclave) []string {
	var bound []string
	for _, digestID := range sortedDigestIDs(digests) {
		digest := digests[digestID]
		if !digestCovers(digest, id) {
			continue
		}
		if _, matched := evaluateDigest(key, digest); matched {
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
func nonApprovedKDFs(metadata *LUKS2Metadata) (keyslots, digests []NonApprovedKDF) {
	for _, id := range keyslotIDsInScanOrder(metadata.Keyslots) {
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

// fipsFirstScanOrder is keyslotIDsInScanOrder with the FIPS-approved keyslots
// moved to the front, each group keeping its own order.
func fipsFirstScanOrder(metadata *LUKS2Metadata) []string {
	all := keyslotIDsInScanOrder(metadata.Keyslots)
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
func sortedDigestIDs(digests map[string]*Digest) []string {
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
func keyslotRefusedByFIPS(id string, keyslot *Keyslot, digests map[string]*Digest) bool {
	if !fipsMode() || keyslot == nil || keyslot.Type != "luks2" {
		return false
	}

	// A keyslot the screen passes was refused later -- reading or decrypting
	// its area -- and no FIPS gate runs there.
	if _, err := screenKeyslot(id, keyslot, digests); err == nil {
		return false
	}

	standIn, substituted, ok := fipsStandInKeyslot(keyslot)
	if !ok {
		return false
	}
	standInDigests := make(map[string]*Digest, len(digests))
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

	_, err := screenKeyslot(id, standIn, standInDigests)
	return err == nil
}

// fipsStandInKeyslot returns keyslot with its KDF replaced by an approved
// PBKDF2 stand-in, when its own KDF is not approved but is well formed.
// substituted reports whether a replacement was made; ok is false when the KDF
// is malformed, which no FIPS policy explains.
func fipsStandInKeyslot(keyslot *Keyslot) (standIn *Keyslot, substituted, ok bool) {
	if keyslotFIPSApproved(keyslot) {
		return keyslot, false, true
	}
	if keyslot.KDF == nil || validateKDFCost(keyslot.KDF) != nil || screenKDFStructure(keyslot.KDF) != nil {
		return nil, false, false
	}
	replaced := *keyslot
	replaced.KDF = fipsStandInKDF(keyslot.KDF.Salt)
	// A SHA-1 anti-forensic hash is refused by policy alone (#236): stand an
	// approved one in for it. Any other unreadable name is left, so the
	// screen still reports it as the damage it is.
	if keyslot.AF != nil && keyslot.AF.Hash == "sha1" {
		af := *keyslot.AF
		af.Hash = DefaultHashAlgo
		replaced.AF = &af
	}
	return &replaced, true, true
}

// fipsStandInDigest returns digest with its KDF replaced by an approved PBKDF2
// stand-in, when it is well formed apart from its KDF's approval.
func fipsStandInDigest(digest *Digest) (*Digest, bool) {
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
func fipsStandInKDF(salt string) *KDF {
	iterations := minKDFIterations
	return &KDF{Type: KDFTypePBKDF2, Hash: "sha256", Salt: salt, Iterations: &iterations}
}

// newFIPSImportRequiredError names what a FIPS process refused on the keyslots
// in blocked: each one's own KDF if that is not approved, and every
// non-approved digest attesting any of them.
func newFIPSImportRequiredError(device string, metadata *LUKS2Metadata, blocked []string) error {
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
