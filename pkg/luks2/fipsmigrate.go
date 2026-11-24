// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"context"
	"errors"
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

// Importing a foreign Argon2 volume into FIPS 140-3 is a keyslot migration run outside FIPS mode, ordered so every interrupted state still opens.

// fipsMigrationOptionsForTest tunes migrateToFIPS; nil or zero is the complete import.
type fipsMigrationOptionsForTest struct {
	// KeepNonApprovedKeyslots keeps the original Argon2 (or PBKDF2-SHA1)
	// keyslots instead of removing them. The default is to remove them.
	//
	// Keeping them is a HALF-MIGRATION: the volume then still opens in a
	// non-FIPS process through a KDF FIPS mode cannot execute, which is not
	// "imported" in any meaningful sense. It is offered for a staged rollout
	// -- migrate each credential in turn, then remove the originals -- and the
	// result says so: Migration.Complete is false and
	// Migration.RetainedNonApproved names what was kept.
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

	// The failed write left the primary unreadable; each says what the secondary still opens through.
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

// stateAfterWriteFailure reports state as read from the medium at the validated area size, or says what is not known.
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

// migrateToFIPS is (*Volume).MigrateToFIPS's implementation; lockDevice locks and pins the device once, after the preconditions.
func migrateToFIPS(ctx context.Context, device string, passphrase []byte, opts *fipsMigrationOptionsForTest, sys volumeSys, lockDevice func() (*keyslotDevice, func(), error)) (*fipsMigrationResultForTest, error) {
	// The header area size, once the run has read and validated one: what a
	// failure report reads the secondary at (stateAfterWriteFailure).
	var area int64
	// What a failure report reads the medium through once the device is locked.
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
	// The passphrase is an existing credential, judged by what can open a keyslot.
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

	// One descriptor for the whole import, so a re-pointed path cannot redirect any read or write.
	dev, release, err := lockDevice()
	if err != nil {
		return fail("precondition", fipsStateUntouched, err)
	}
	defer release()
	mediumPath = dev.mediumPath()
	// The header copies are this run's to reconcile, as "Both header copies"
	// above says; the keyslot code it reuses must not repair them for it.
	dev.leveled = true

	// Sync, then evict, so every byte this run reads comes off the medium.
	if err := sys.syncDevice(dev.file); err != nil {
		return fail("sync", fipsStateUntouched, &errs.Error{
			Kind: errs.ErrIO, Detail: "failed to make what an earlier write left in the page cache durable before reading", Err: err})
	}
	if err := sys.dropDeviceCache(dev.file); err != nil {
		return fail("sync", fipsStateUntouched, &errs.Error{
			Kind: errs.ErrIO, Detail: "failed to evict the device's cached pages, so what is read could not be shown to be on the medium", Err: err})
	}
	// Eviction is advisory; the proof is the header region read through and past the cache comparing equal.
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

	// Every keyslot area this run could read or wipe must lie in the keyslots area, clear of data, checked before any keyslot is touched.
	for _, id := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		if keyslot := metadata.Keyslots[id]; keyslot == nil || keyslot.Type != "luks2" {
			continue
		}
		if err := checkKeyslotAreaConfined(hdr, metadata, id); err != nil {
			return fail("precondition", fipsStateUntouched, err)
		}
	}

	// 1. Unlock: approved keyslots first, and only keyslots whose digests bind every data segment.
	var order []string
	for _, id := range fipsFirstScanOrder(metadata) {
		// The strict predicate the removal guard and getVolumeKey use.
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

	// Check the recovered key against the digests, as unlock does.
	if missing := unboundSegments(metadata, metadata.Digests, openedID, masterKey); len(missing) > 0 {
		return fail("unlock", fipsStateUntouched, fipsRefusal(errFIPSMigrationUnboundKey, "the key keyslot "+openedID+" holds is not bound to data segment(s) "+
			strings.Join(missing, ", ")+" by any digest it matches", nil))
	}

	// 2. Plan: every digest must pass the header screen and every non-approved one must attest the recovered key, before anything is written.
	if err := malformedDigestError(metadata.Digests); err != nil {
		return fail("plan", fipsStateUntouched, err)
	}
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

	// Reconcile the header copies before the first write, writing only the secondary.
	if header.HeaderCopiesAgree(dev.reader()) != nil {
		if err := repairSecondaryHeader(ctx, dev, hdr, metadata); err != nil {
			return fail("reconcile header copies", fipsStateOriginals, err)
		}
		if err := header.HeaderCopiesAgree(dev.reader()); err != nil {
			return fail("reconcile header copies", fipsStateOriginals, err)
		}
	}

	result := &fipsMigrationResultForTest{}

	// 3. Add keyslot through AddKey's code, under the lock held here.
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

	// 4. Migrate digests: each becomes a PBKDF2 digest over the same volume key.
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

	// 5. Verify before anything is removed, including that both header copies agree.
	if err := verifyFIPSOpen(ctx, dev, passphrase, slotID, masterKey, sys); err != nil {
		return fail("verify", fipsStateOriginals, err)
	}
	if err := header.HeaderCopiesAgree(dev.reader()); err != nil {
		return fail("verify", fipsStateOriginals, fipsRefusal(errFIPSMigrationVerification, "the header copies do not agree after the writes", err))
	}

	// 6. Remove the non-approved keyslots, or record that they were kept.
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

	// 7. Final check against the header as written: static, then a real open.
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

// fipsRefusal is one of the migration's own refusals, classified at its source and returned only through fail.
func fipsRefusal(refusal error, detail string, cause error) *errs.Error {
	return &errs.Error{Kind: refusal, Detail: detail, Err: cause}
}

// verifyFIPSOpen re-reads the header and unlocks keyslot id through approved digests only, requiring the key to be want.
func verifyFIPSOpen(ctx context.Context, dev *keyslotDevice, passphrase []byte, id string, want enclave.ByteAccess, sys volumeSys) error {
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

	// The approved digests the key matches must bind every data segment.
	if missing := unboundSegments(metadata, approved, id, got); len(missing) > 0 {
		return fipsRefusal(errFIPSMigrationVerification, "no FIPS-approved digest binds the key keyslot "+id+" holds to data segment(s) "+strings.Join(missing, ", "), nil)
	}

	// Run the keyslot scan over what a FIPS process can execute; it must recover the volume key.
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

// fipsApprovedView returns a shallow copy of metadata holding only approved luks2 keyslots and digests.
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

// removeKeyslotOn removes one keyslot under a held lock (gate, writable header, wipe, header); destroyed reports whether material may be wiped.
func removeKeyslotOn(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, id string) (destroyed bool, err error) {
	target := metadata.Keyslots[id]

	// The removal gate RemoveKey, KillSlot and KillKeyslot take.
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

// fipsApprovedKDF reports whether a declared KDF can run in a FIPS 140-3 process, including its PBKDF2 hash.
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

// The salt (128-bit) and output (112-bit) floors crypto/pbkdf2 enforces under fips140=only.
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

// keyslotFIPSRefusal describes why a luks2 keyslot's KDF could not run in strict FIPS, or reports ok.
func keyslotFIPSRefusal(id string, keyslot *header.Keyslot) (refusal NonApprovedKDF, ok bool) {
	refusal.ID, _ = strconv.Atoi(id) // id is always a canonical keyslot ID (a small decimal integer)
	if keyslot == nil || keyslot.KDF == nil {
		refusal.Reason = "no KDF object"
		return refusal, false
	}
	refusal.Type, refusal.Hash = keyslot.KDF.Type, keyslot.KDF.Hash
	// A SHA-1 anti-forensic hash is not approved either; name it even when the KDF is refused too.
	afRefused := keyslot.AF != nil && keyslot.AF.Hash == "sha1"
	if afRefused {
		refusal.Reason = "anti-forensic hash sha1"
	}
	if !fipsApprovedKDF(keyslot.KDF.Type, keyslot.KDF.Hash) || afRefused {
		return refusal, false
	}
	// The KDF output wraps the area, so its length is area.key_size.
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

// keyslotDeclaredForAllSegments reports whether keyslot id's digests together name every data segment.
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

// unboundSegments returns the data segments no digest binds to key through keyslot id; empty means key opens every segment.
func unboundSegments(metadata *header.Metadata, digests map[string]*header.Digest, id string, key enclave.ByteAccess) []string {
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

// nonApprovedKDFs lists every luks2 keyslot and digest whose KDF a FIPS process cannot execute, in scan and id order.
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

// keyslotRefusedByFIPS reports whether a keyslot was refused only by FIPS mode, by re-screening it with approved stand-ins for the refused KDFs.
func keyslotRefusedByFIPS(id string, keyslot *header.Keyslot, digests map[string]*header.Digest, fipsMode func() fips.Mode, failure error) bool {
	if !fipsMode() || keyslot == nil || keyslot.Type != "luks2" {
		return false
	}
	// A malformed covering digest is damage an import cannot repair.
	if !coveringDigestsWellFormed(id, digests) {
		return false
	}

	// A later failure with all-approved names counts as FIPS only when it is strict mode's derivation error.
	if _, err := screenKeyslot(id, keyslot, digests, fipsMode); err == nil {
		switch {
		case !keyslotFIPSApproved(keyslot):
			// The passphrase derivation runs first and is what strict mode
			// refuses; it fails as an invalid argument.
			if !errors.Is(failure, errs.ErrInvalidArgument) {
				return false
			}
		case !coveringDigestsFIPSApproved(id, digests):
			// The digest derivations run last, after the area was read,
			// decrypted and merged; strict mode refusing every one of them
			// leaves no digest evaluated.
			if !coveringDigestsUnusable(id, digests, failure) {
				return false
			}
		default:
			return false
		}
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

// coveringDigestsFIPSApproved reports whether every digest that covers keyslot
// id is one strict FIPS mode will evaluate.
func coveringDigestsFIPSApproved(id string, digests map[string]*header.Digest) bool {
	for _, digest := range digests {
		if digestCovers(digest, id) && !digestFIPSApproved(digest) {
			return false
		}
	}
	return true
}

// coveringDigestsUnusable reports whether failure is the verdict the digest
// check gives keyslot id when not one of its covering digests could be
// evaluated: the outcome of strict mode refusing all of their derivations.
func coveringDigestsUnusable(id string, digests map[string]*header.Digest, failure error) bool {
	applicable := 0
	for _, digest := range digests {
		if digestCovers(digest, id) {
			applicable++
		}
	}
	var got *errs.Error
	if applicable == 0 || !errors.As(failure, &got) {
		return false
	}
	want, ok := unverifiableKeyslotError(id, applicable).(*errs.Error)
	return ok && got.Kind == want.Kind && got.Detail == want.Detail && got.Err == nil
}

// coveringDigestsWellFormed reports whether every digest covering keyslot id
// passes the structural digest screen, which runs no FIPS gate: what is left
// to refuse it is policy, never damage.
func coveringDigestsWellFormed(id string, digests map[string]*header.Digest) bool {
	return coveringDigestStructureError(id, digests) == nil
}

// coveringDigestStructureError returns ErrInvalidHeader for the lowest-numbered malformed digest attesting keyslot id, or nil.
func coveringDigestStructureError(id string, digests map[string]*header.Digest) error {
	for _, digestID := range sortedDigestIDs(digests) {
		digest := digests[digestID]
		if !digestCovers(digest, id) {
			continue
		}
		expected, _, err := screenDigestStructure(digest)
		clearBytes(expected)
		if err != nil {
			return &errs.Error{Kind: ErrInvalidHeader, Detail: "digest " + digestID + " attesting keyslot " + id + " is malformed", Err: err}
		}
	}
	return nil
}

// malformedDigestError returns ErrInvalidHeader naming the first digest the structural screen rejects, or nil.
func malformedDigestError(digests map[string]*header.Digest) error {
	for _, id := range sortedDigestIDs(digests) {
		digest := digests[id]
		if digest == nil {
			continue
		}
		expected, _, err := screenDigestStructure(digest)
		clearBytes(expected)
		if err != nil {
			return &errs.Error{Kind: ErrInvalidHeader, Detail: "digest " + id + " is malformed", Err: err}
		}
	}
	return nil
}

// fipsStandInKeyslot replaces a well-formed non-approved KDF with an approved PBKDF2 stand-in; ok is false for a malformed KDF.
func fipsStandInKeyslot(keyslot *header.Keyslot) (standIn *header.Keyslot, substituted, ok bool) {
	if keyslotFIPSApproved(keyslot) {
		return keyslot, false, true
	}
	if keyslot.KDF == nil || header.ValidateKDFCost(keyslot.KDF) != nil || screenKDFStructure(keyslot.KDF) != nil {
		return nil, false, false
	}
	replaced := *keyslot
	replaced.KDF = fipsStandInKDF(keyslot.KDF.Salt)
	// Stand in an approved hash for SHA-1; other unreadable names stay, so the screen reports them.
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
