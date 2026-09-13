// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// RecoveryKeyLength is the default length for recovery keys (32 bytes = 256 bits)
const RecoveryKeyLength = 32

// RecoveryKeyFormat specifies the output format for recovery keys
type RecoveryKeyFormat string

const (
	// RecoveryKeyFormatHex outputs the key as hexadecimal
	RecoveryKeyFormatHex RecoveryKeyFormat = "hex"

	// RecoveryKeyFormatBase64 outputs the key as base64
	RecoveryKeyFormatBase64 RecoveryKeyFormat = "base64"

	// RecoveryKeyFormatDashed outputs as dash-separated hex groups (like Windows BitLocker)
	RecoveryKeyFormatDashed RecoveryKeyFormat = "dashed"
)

// RecoveryKey is a generated credential for a volume.
//
// # THE PRINTED TEXT IS THE PASSPHRASE
//
// The keyslot holds the FORMATTED TEXT -- "9F3A2C-4B81DE-..." -- byte for byte.
// It is not an encoding of the credential, it IS the credential, so a printed
// page opens the volume from any rescue system with stock cryptsetup and
// nothing else:
//
//	cryptsetup open /dev/sdb1 vault      # paste the printed string
//
// That is the whole point of a recovery key, and it is why this changed. What
// this package used to enroll was the raw 32 bytes BEHIND the rendering, so the
// printed page only opened the volume after being decoded by the very library
// that might be the thing that is unavailable. A recovery path with a software
// dependency is not a recovery path.
//
// # NO ENTROPY IS LOST BY THIS, AND NONE IS GAINED BY REVERTING IT
//
// The credential is the same 32 bytes from the same CSPRNG, written down in a
// different alphabet. Rendering 256 bits as 64 hex characters spreads the same
// 256 bits over more characters; it does not create or destroy any of them. The
// per-character density falls, the total does not move.
//
// Anyone reading "the keyslot holds text rather than key bytes" as a weakening
// and reverting it would silently reintroduce the failure above, so: it is not
// a weakening, it is the same secret in a form a human can carry.
//
// # Custody
//
// The credential is held in protected memory and is the caller's to release
// with Clear. Materializing it as a Go string costs a deliberate call
// (FormattedString) because a string holding a credential can never be wiped.
type RecoveryKey struct {
	// Credential is THE PASSPHRASE the keyslot was enrolled with: the
	// formatted text, byte for byte, in protected memory.
	//
	// This member replaces the previous pair -- a raw Key that WAS the
	// credential and a Formatted rendering that was not -- and the rename is
	// deliberate. Under the new model the raw bytes open nothing, so leaving a
	// field called Key would have left the old code compiling and quietly
	// verifying against bytes no keyslot holds. Borrow it with
	// MemoryEnclave.WithBytes; never copy it out.
	Credential *enclave.MemoryEnclave

	// Format is the rendering the credential is written in.
	Format RecoveryKeyFormat

	// CredentialHash is a SHA-256 of the credential text, hex-encoded. It is a
	// one-way function of the credential and is not itself secret: it is
	// written into the saved file in the clear so a transcription can be
	// checked without going near the volume.
	CredentialHash string

	// CreatedAt is when the key was generated.
	CreatedAt time.Time

	// VolumeUUID is the UUID of the volume this key is for.
	VolumeUUID string

	// Keyslot is the keyslot the credential was added to, as reported by the
	// code that CHOSE it. It is -1 for a key that has not been added to a
	// volume.
	Keyslot int

	// TokenID is the token slot naming that keyslot, or -1 when no token was
	// written. The token is what tells cryptsetup and systemd that the slot is
	// a recovery key rather than someone's passphrase.
	TokenID int

	// SaveError contains any error that occurred while saving the key to file.
	// The key was still successfully added to the volume even if this is set.
	SaveError error
}

// RecoveryKeyOptions contains options for recovery key generation
type RecoveryKeyOptions struct {
	// Length is the key length in bytes (default: 32)
	Length int

	// Format is the output format (default: dashed)
	Format RecoveryKeyFormat

	// Keyslot specifies which keyslot to use (nil = auto-select)
	Keyslot *int

	// OutputPath is where to save the recovery key (optional)
	OutputPath string

	// KDFType specifies the KDF type (default: argon2id).
	//
	// # What systemd writes, MEASURED
	//
	// From `cryptsetup luksDump` on a volume enrolled with systemd-cryptenroll
	// (systemd 255, cryptsetup 2.7.0) holding a passphrase, a recovery key and
	// three FIDO2 credentials:
	//
	//	slot 0  human passphrase   argon2id  t=24  m=512000  p=4
	//	slot 1  recovery key       pbkdf2    sha512  iterations=1000
	//	slot 2  FIDO2 credential   pbkdf2    sha512  iterations=1000
	//	slot 3  FIDO2 credential   pbkdf2    sha512  iterations=1000
	//	slot 4  FIDO2 credential   pbkdf2    sha512  iterations=1000
	//
	// A flat minimum, identically, for every credential that is not a human
	// passphrase, and no calibration at all. That is the correct shape and this
	// package should match it.
	//
	// # 1000 IS NOT A GENERALLY SAFE ITERATION COUNT
	//
	// It is correct for these keyslots for exactly one reason: the credential is
	// 256 bits from a CSPRNG, so there is nothing to enumerate and stretching it
	// defends against nothing. The same number under a HUMAN-CHOSEN passphrase
	// would be catastrophic -- which is precisely why systemd puts argon2id at
	// t=24 on slot 0 and 1000 pbkdf2 iterations on the rest. Anyone copying the
	// number somewhere else, or "fixing" it upward here, has misread which of
	// those two cases they are in.
	//
	// (Unrelatedly, 1000 is also what `cryptsetup --pbkdf-force-iterations 1000`
	// produces, which is how the test fixtures in this repository stay fast. Same
	// number, two unconnected reasons. They have been confounded once already.)
	//
	// # Why the default is still argon2id: it CANNOT BE EXPRESSED YET
	//
	// This package's pbkdf2 path takes a TIME BUDGET and calibrates against it;
	// there is no way through the public API to write a fixed iteration count.
	// The floor at minPBKDF2Iterations does not rescue it, because on real
	// hardware even a 1 ms budget extrapolates well past 1000 before the floor
	// is consulted. Measured on one developer machine, BenchmarkPBKDF2:
	//
	//	sha512, 1 ms budget    -> 3253 iterations
	//	sha512, 10 ms budget   -> 31824 iterations
	//	sha256, 2000 ms (the default) -> ~9.9M iterations
	//
	// So the smallest thing this API can currently write is a few thousand
	// iterations that DIFFER PER MACHINE -- neither systemd's number nor a
	// reproducible one, and still paying for a calibration probe to get there.
	// Switching the default to that would produce headers that match nothing and
	// vary between two nodes enrolled from the same script, which is worse than
	// either endpoint.
	//
	// # THE COMPARISON ABOVE HAS AN EXPIRY DATE
	//
	// Read the 0.88 s / 2.08 s figures as an argument against pbkdf2 and you
	// will reach the wrong conclusion the moment the gap above closes. Nearly
	// all of that 2.08 s IS THE BENCHMARK -- the calibration probe, not the key
	// derivation -- and an explicit iteration count does not run one. At 1000
	// iterations there is nothing to calibrate and nothing to stretch, so the
	// choice stops being "a gigabyte or two seconds" and becomes neither: the
	// memory comes back AND the wall time with it.
	//
	// What survives the change is the reasoning, which is why it is written out
	// rather than summarized as a verdict: a heavy KDF defends a guessable
	// secret, this credential is not guessable, and the cost was never buying
	// anything. The 2.4x figure is an artifact of an API that could only
	// calibrate.
	//
	// # Closing it takes TWO things, and the second one is easy to miss
	//
	// The first is an explicit iteration count -- PBKDFIterations on
	// FormatOptions and AddKeyOptions, resolved in createPBKDF2KDF instead of
	// the benchmark. That exists on the issue/144-canonical-json-conformance
	// branch and is not on main yet.
	//
	// IT IS NOT SUFFICIENT ON ITS OWN. An explicit count is still bounded by
	// this package's OWASP-derived floor, which refuses systemd's number
	// outright -- measured against forcedPBKDF2Iterations:
	//
	//	sha1    1000 REFUSED: permitted range 1300000..100000000
	//	sha256  1000 REFUSED: permitted range  600000..100000000
	//	sha512  1000 REFUSED: permitted range  210000..100000000
	//
	// So the floor rejects 1000 by a factor of 210 on sha512, and anyone who
	// adds the field and expects this default to follow will hit that and be
	// puzzled. The floor is not wrong: it exists because a calibrated count
	// measures the DEFENDER's hardware and says nothing about the attacker's,
	// which is the right instinct for a passphrase.
	//
	// It is wrong only for a credential with no brute-force surface, and the
	// second thing needed is therefore an exemption scoped to exactly that: to
	// credentials THIS LIBRARY GENERATED, on the unexported addKey path, with
	// AddRecoveryKey and EnrollKeyProvider as the only callers permitted to
	// claim it -- because they are the only two that know the bytes came from a
	// CSPRNG rather than from a person. Exempt means the OWASP floor does not
	// apply; minPBKDF2Iterations still does, and it is 1000, which is systemd's
	// value exactly. That work is queued behind the field.
	//
	// If a future change makes that exemption reachable from an exported option,
	// something has gone wrong: a caller-supplied credential may be a human
	// passphrase, and the floor is the only thing standing between one and a
	// keyslot stretched a thousand times too little.
	//
	// When both land, this default becomes pbkdf2 / SHA512 / 1000 with no
	// calibration, and the luksDump table above is the artifact to check it
	// against. The hash is part of the target and is the easiest part to lose:
	// systemd writes sha512, while this package's own default is sha256.
	//
	// # None of this is an interoperability question
	//
	// A keyslot records its own KDF parameters and every implementation reads
	// them from the header, so cryptsetup and systemd-cryptsetup open an
	// argon2id keyslot and a pbkdf2 one alike. The type, hash and count are a
	// COST decision, not a compatibility constraint, and treating the iteration
	// count as something that has to match for interop would be a
	// misunderstanding. It is also forward-only: volumes keep whatever their
	// keyslots already hold.
	//
	// Callers who want pbkdf2 today set KDFType to KDFTypePBKDF2 explicitly.
	KDFType string

	// Argon2 parameters
	Argon2Time     int
	Argon2Memory   int
	Argon2Parallel int

	// Hash selects the PBKDF2 hash when KDFType is pbkdf2 (default: sha256).
	Hash string

	// PBKDFIterations is an exact PBKDF2 iteration count. Zero calibrates, as
	// before.
	//
	// This is the ONLY place the library-generated exemption becomes visible.
	// The relaxed floor is consulted only for an explicit count -- a calibrated
	// one is bounded by the benchmark instead -- so without this field the
	// exemption is selected and never binds. The point of it is to be able to
	// reproduce a systemd-enrolled header: systemd writes pbkdf2/sha512/1000,
	// and the sha512 floor of 210000 makes that unwritable for a credential a
	// CALLER supplied.
	//
	// It is safe HERE and nowhere else: the credential this enrolls is drawn by
	// GenerateRecoveryKey from randomSecret, 256 bits with no candidate list, so
	// the iteration count has no search to multiply. The same field on
	// AddKeyOptions is held to the full hash-dependent floor, because the bytes
	// arriving there came from outside. The exemption still keeps
	// minPBKDF2Iterations, so zero, negative and absurd counts are refused.
	//
	// See keyslotCostPolicy (kdf.go) for the full argument.
	PBKDFIterations int
}

// GenerateRecoveryKey generates a cryptographically secure recovery key.
//
// length is the number of RANDOM BYTES drawn, not the length of the credential:
// the credential is those bytes rendered in format, which is longer. 32 bytes
// is 71 characters dashed, 64 hex, 44 base64.
//
// The random bytes are drawn directly into locked memory and the rendering is
// built directly into locked memory, so neither ever exists on the ordinary
// heap. The raw bytes are DESTROYED before this returns -- once the rendering
// exists they are not the credential and there is nothing left to do with
// them, so holding them would be holding a second copy of the secret for no
// reason. The caller owns the result and must Clear it.
func GenerateRecoveryKey(length int, format RecoveryKeyFormat) (*RecoveryKey, error) {
	if length <= 0 {
		length = RecoveryKeyLength
	}

	if format == "" {
		format = RecoveryKeyFormatDashed
	}

	key, err := randomSecret("recovery key", length)
	if err != nil {
		return nil, err
	}
	defer key.Destroy()

	credential, err := newSecretEnclave("recovery key", formattedLen(length, format))
	if err != nil {
		return nil, err
	}

	if err := borrowSecret("recovery key", key, func(raw []byte) error {
		return borrowSecret("recovery key", credential, func(dst []byte) error {
			formatRecoveryKeyInto(dst, raw, format)
			return nil
		})
	}); err != nil {
		credential.Destroy()
		return nil, err
	}

	// The hash is of the CREDENTIAL, not of the bytes behind it -- the
	// credential is the thing an operator transcribes and the thing a keyslot
	// holds, so it is the thing worth being able to check. It is a one-way
	// function of it and is written to the recovery file in the clear, so it is
	// not protected; it is computed inside the borrow only because that is
	// where the credential is readable.
	var credentialHash string
	if err := borrowSecret("recovery key", credential, func(b []byte) error {
		sum := sha256.Sum256(b)
		credentialHash = hex.EncodeToString(sum[:])
		return nil
	}); err != nil {
		credential.Destroy()
		return nil, err
	}

	return &RecoveryKey{
		Credential:     credential,
		Format:         format,
		CredentialHash: credentialHash,
		CreatedAt:      time.Now(),
		Keyslot:        -1,
		TokenID:        -1,
	}, nil
}

// AddRecoveryKey generates a recovery key, adds it to a LUKS volume and records
// a token saying what the keyslot is.
//
// existingPassphrase is a credential that already opens the volume; it is needed
// because adding a keyslot means unwrapping the volume key.
//
// # What lands on the device
//
// A keyslot holding the FORMATTED TEXT as its passphrase -- see RecoveryKey for
// why -- and a `systemd-recovery` token naming that keyslot. The token carries
// nothing else: there is no material to record, because the credential is the
// text an operator is holding. Its purpose is to tell cryptsetup, systemd and
// the next person that the slot is a recovery key rather than somebody's
// passphrase, which is a distinction that otherwise exists only in a filing
// cabinet.
//
// If the token cannot be written the KEYSLOT IS ROLLED BACK, for the same
// reason EnrollKeyProvider does it: a keyslot nothing describes is a live
// credential that cannot be told apart from one still in use.
func AddRecoveryKey(device string, existingPassphrase []byte, opts *RecoveryKeyOptions) (*RecoveryKey, error) {
	if opts == nil {
		opts = &RecoveryKeyOptions{}
	}

	// Set defaults
	if opts.Length <= 0 {
		opts.Length = RecoveryKeyLength
	}
	if opts.Format == "" {
		opts.Format = RecoveryKeyFormatDashed
	}

	// Generate recovery key
	recoveryKey, err := GenerateRecoveryKey(opts.Length, opts.Format)
	if err != nil {
		return nil, err
	}

	addOpts := &AddKeyOptions{
		Keyslot:         opts.Keyslot,
		KDFType:         opts.KDFType,
		Argon2Time:      opts.Argon2Time,
		Argon2Memory:    opts.Argon2Memory,
		Argon2Parallel:  opts.Argon2Parallel,
		Hash:            opts.Hash,
		PBKDFIterations: opts.PBKDFIterations,
	}

	// The credential is borrowed for the length of the enrollment and no
	// longer. enrollWithToken writes the keyslot, reads the slot number from
	// where addKey CHOSE it rather than inferring it afterwards (#42), writes
	// the token naming that slot, and rolls the keyslot back if the token write
	// fails.
	//
	// libraryGeneratedCredential, because THIS function drew the bytes it is
	// enrolling: the credential is randomSecret output, 256 bits with no
	// candidate list behind it. A PBKDF2 iteration count multiplies the cost of
	// each guess in an offline search, and there is no search to multiply here,
	// so the hash-dependent floor buys nothing while making systemd's own
	// parameters unwritable. The exemption KEEPS minPBKDF2Iterations -- LUKS2's
	// minimum, and exactly what systemd enrolls -- so zero, negative and absurd
	// counts are still refused. See keyslotCostPolicy (kdf.go) for the full
	// argument, including why the same reasoning is invalid for a credential a
	// caller hands in and why no exported API can select this.
	var keyslot, tokenID int
	if err := borrowSecret("recovery key", recoveryKey.Credential, func(credential []byte) error {
		var err error
		keyslot, tokenID, err = enrollWithToken(device, existingPassphrase, credential, addOpts,
			recoveryToken(), libraryGeneratedCredential)
		return err
	}); err != nil {
		recoveryKey.Clear()
		return nil, fmt.Errorf("failed to add recovery key: %w", err)
	}

	recoveryKey.Keyslot = keyslot
	recoveryKey.TokenID = tokenID

	// Get volume info for UUID
	info, err := GetVolumeInfo(device)
	if err == nil {
		recoveryKey.VolumeUUID = info.UUID
	}

	// Save to file if path specified
	if opts.OutputPath != "" {
		if err := SaveRecoveryKey(recoveryKey, opts.OutputPath); err != nil {
			// Non-fatal - key was still added, but caller should be aware
			recoveryKey.SaveError = fmt.Errorf("failed to save recovery key to %s: %w", opts.OutputPath, err)
		}
	}

	return recoveryKey, nil
}

// recoveryToken builds the token that identifies a recovery keyslot.
//
// It is systemd's, and it is the WHOLE token: type and keyslots, nothing else.
// systemd-cryptenroll --recovery-key writes no format member and no algorithm
// member, because there is no material to describe -- the credential is the
// printed text. Adding fields of our own here would produce a token systemd
// reads differently from the way we wrote it.
//
// Keyslots is filled in by enrollWithToken, which is the only place that knows
// the answer.
func recoveryToken() *Token {
	return &Token{Type: recoveryTokenType}
}

// removeFile is os.Remove, reached through a variable so the staging-cleanup
// paths can be exercised. Same seam as dm, devDir and nodeRdev elsewhere in this
// package: the failure being guarded against is a filesystem refusal, and a test
// cannot arrange one at exactly one call without it.
var removeFile = os.Remove

// maxRecoveryKeyFileSize bounds how much of a caller-supplied path this package
// will read into LOCKED memory.
//
// The file this package writes is a few hundred bytes. 64 KiB leaves room for
// an operator's own notes around the key while keeping an untrusted path from
// sizing a locked allocation, which is a process-wide rlimited resource: an
// unbounded read here would fail every concurrent operation, not just its own.
const maxRecoveryKeyFileSize = 64 << 10

// SaveRecoveryKey saves a recovery key to a file, ATOMICALLY.
//
// # Why the whole file is staged before anything is published
//
// The key itself is streamed from its enclave rather than assembled in a
// strings.Builder, which the original form did -- and which put three
// unwipeable copies of the credential on the heap to write one file.
//
// But streaming straight at the destination is how a save DESTROYS a recovery
// key. Opening it truncating empties it before the replacement exists, so a
// destroyed rendering, a refused borrow, a short write, a failed Sync or the
// process simply exiting leaves an empty or partial file where a working
// credential used to be -- at the exact moment somebody is reaching for the
// last-resort credential because everything else has failed. The original
// os.WriteFile form had this property by accident, by building the content
// first; staging it deliberately is what keeps it.
//
// So the complete file is written to a temporary file in the SAME DIRECTORY
// (a rename is only atomic within a filesystem), synced, closed, and then
// published. The directory is synced afterwards, because a rename that is not
// itself durable can be lost by a crash even though the data it points at was
// flushed.
//
// # Publication REFUSES to replace an existing file
//
// os.Link rather than os.Rename: link fails with EEXIST if the destination
// exists, and does so atomically, which rename cannot express.
//
// That is a deliberate tightening of what the original did. Opening the
// destination for writing meant a mode-0400 file was refused and a 0600 one was
// silently overwritten -- so whether a recovery key could be clobbered depended
// on the mode of whatever was already there, which is not a rule anybody chose.
// The rule is now the same either way. For a last-resort credential, refusing is
// the safe direction, and a caller that means to replace one removes it first.
//
// Writing the key to disk is of course an exposure in its own right -- it is
// what the caller asked for -- and the file is created 0400.
func SaveRecoveryKey(key *RecoveryKey, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Staged in the destination directory so the publish below is a
	// within-filesystem link, and created 0400 from the start so the key is
	// never briefly readable through a wider mode.
	tmp, err := os.CreateTemp(dir, ".recovery-key-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to write recovery key: %w", err)
	}
	tmpPath := tmp.Name()

	// The staging name is unlinked on EVERY path, published or not.
	//
	// It used to be gated on a `published` flag, which disabled this exactly
	// when the risk appeared. Publication is os.Link, so from the moment it
	// succeeds there are TWO names for one inode -- two complete copies of the
	// recovery credential as far as anything walking the filesystem is
	// concerned -- and gating the cleanup on publication meant that if the
	// explicit removal below then failed, the staging name survived at a path
	// nobody expects, for backup or scanning tooling to collect. The comment
	// there claimed removal "on every failure path" and was not true on that one.
	//
	// Unconditional is safe because a hard link cannot damage what it names: the
	// inode survives while any name refers to it, so unlinking the staging name
	// after a successful link removes a duplicate and nothing else. Dropping the
	// flag removes the wrong invariant along with the bug.
	defer func() {
		_ = tmp.Close() // no-op once closed below
		_ = removeFile(tmpPath)
	}()

	if err := tmp.Chmod(0400); err != nil {
		return fmt.Errorf("failed to write recovery key: %w", err)
	}

	if err := writeRecoveryKeyContent(tmp, key); err != nil {
		return err
	}

	// The DATA is durable before the name that points at it exists.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("failed to write recovery key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to write recovery key: %w", err)
	}

	// Publish. EEXIST here means an existing recovery key was left untouched.
	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to replace the existing recovery key file %s: remove it first if that is intended", path)
		}
		return fmt.Errorf("failed to write recovery key: %w", err)
	}
	// Explicit as well as deferred, so a failure is REPORTED rather than
	// retried in silence. The deferred attempt above is the backstop; between
	// them the staging name goes away unless the filesystem refuses twice.
	//
	// The message names the published path first: the key WAS saved, and an
	// operator reading a bare "failed to remove" would reasonably conclude the
	// credential had been lost when what actually happened is that a duplicate
	// of it may remain.
	if err := removeFile(tmpPath); err != nil {
		return fmt.Errorf("the recovery key was written to %s, but its staging copy %s could not be removed and may still hold the credential: %w",
			path, tmpPath, err)
	}

	return syncDir(dir)
}

// writeRecoveryKeyContent writes the whole file into w. The key is borrowed from
// its enclave for the one write that carries it and is never materialized
// alongside the preamble.
func writeRecoveryKeyContent(w io.Writer, key *RecoveryKey) error {
	// The preamble carries no key material.
	var preamble strings.Builder
	preamble.WriteString("# LUKS Recovery Key\n")
	preamble.WriteString("# IMPORTANT: Store this key in a safe location!\n")
	preamble.WriteString("# This key can be used to unlock the encrypted volume if the primary\n")
	preamble.WriteString("# passphrase is lost or the TPM becomes unavailable.\n")
	preamble.WriteString("#\n")
	fmt.Fprintf(&preamble, "# Volume UUID: %s\n", key.VolumeUUID)
	fmt.Fprintf(&preamble, "# Keyslot: %d\n", key.Keyslot)
	fmt.Fprintf(&preamble, "# Token: %d\n", key.TokenID)
	fmt.Fprintf(&preamble, "# Created: %s\n", key.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(&preamble, "# Key Hash (SHA-256): %s\n", key.CredentialHash)
	preamble.WriteString("#\n")
	preamble.WriteString("# The line below IS the passphrase. Type or paste it exactly as it\n")
	preamble.WriteString("# appears, including the dashes and the letter case:\n")
	preamble.WriteString("#\n")
	preamble.WriteString("#   cryptsetup open <device> <name>\n")
	preamble.WriteString("#\n")
	preamble.WriteString("# Recovery Key:\n")

	if _, err := io.WriteString(w, preamble.String()); err != nil {
		return fmt.Errorf("failed to write recovery key: %w", err)
	}

	if err := borrowSecret("recovery key", key.Credential, func(b []byte) error {
		_, err := w.Write(b)
		return err
	}); err != nil {
		return fmt.Errorf("failed to write recovery key: %w", err)
	}

	if _, err := io.WriteString(w, "\n"); err != nil {
		return fmt.Errorf("failed to write recovery key: %w", err)
	}

	return nil
}

// syncDir flushes a directory entry so that a rename or link into it survives a
// crash. Without it the file's data is durable and the name pointing at it may
// not be, which for a recovery key means the key exists on disk and nothing can
// find it.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the directory the caller asked to write into
	if err != nil {
		return fmt.Errorf("failed to sync the recovery key directory: %w", err)
	}
	defer func() { _ = d.Close() }()

	if err := d.Sync(); err != nil {
		return fmt.Errorf("failed to sync the recovery key directory: %w", err)
	}
	return nil
}

// LoadRecoveryKey loads a recovery key file and returns the KEY MATERIAL BEHIND
// the rendering -- the bytes the text decodes to, in protected memory.
//
// # This is probably not the function you want
//
// It is unchanged, and that is deliberate rather than an oversight: it is how a
// volume enrolled BEFORE the recovery key became the printed text is opened,
// because those keyslots hold the decoded bytes. For a volume enrolled by the
// current code, the credential is the line itself and
// LoadRecoveryCredential returns it.
//
// The two are kept apart rather than merged behind a guess. Deciding which one
// a container wants by trying both would be a fallback, and a fallback here
// means that on the day a recovery key is needed the tool reports success after
// silently testing something other than what was asked.
//
// The file is read DIRECTLY into locked memory and parsed in place. It used to
// go through os.ReadFile into a plain []byte, then string(data), then
// strings.Split -- so the credential existed in at least three places, two of
// them immutable and therefore unwipeable no matter what the byte slice was
// cleared to. Measured on a 512 KiB file, that cost 1.18 MB of ordinary heap.
//
// Nothing about those copies was forced. They were this package's own choice of
// how to read a file, not a validated primitive's internals, so the
// protected-memory mandate does not yield to them the way it does inside
// PBKDF2 -- see exposure 2 in enclave.go for the case where it does.
func LoadRecoveryKey(path string) (*enclave.MemoryEnclave, error) {
	line, err := readRecoveryKeyLine(path)
	if err != nil {
		return nil, err
	}
	defer line.Destroy()

	return parseRecoveryKeySecret(line)
}

// LoadRecoveryCredential reads a saved recovery key file and returns THE
// CREDENTIAL -- the line verbatim, which is what the keyslot holds.
//
// This is the one to use for a volume this package enrolled. LoadRecoveryKey
// decodes the same line into the bytes behind it, which is the credential only
// for a volume enrolled before the recovery key became the printed text; see
// RecoveryKey.
//
// The line is taken EXACTLY as written apart from surrounding whitespace, which
// a text editor may have added and which no keyslot holds. Nothing else is
// normalized: case and dashes are part of the credential, and a "helpful"
// canonicalization here would produce bytes the volume has never seen.
func LoadRecoveryCredential(path string) (*enclave.MemoryEnclave, error) {
	return readRecoveryKeyLine(path)
}

// readRecoveryKeyLine reads the first non-comment line of a recovery key file
// into locked memory.
//
// The file is read DIRECTLY into locked memory and parsed in place. It used to
// go through os.ReadFile into a plain []byte, then string(data), then
// strings.Split -- so the credential existed in at least three places, two of
// them immutable and therefore unwipeable no matter what the byte slice was
// cleared to. Measured on a 512 KiB file, that cost 1.18 MB of ordinary heap.
//
// Nothing about those copies was forced. They were this package's own choice of
// how to read a file, not a validated primitive's internals, so the
// protected-memory mandate does not yield to them the way it does inside
// PBKDF2 -- see exposure 2 in enclave.go for the case where it does.
func readRecoveryKeyLine(path string) (*enclave.MemoryEnclave, error) {
	f, err := os.Open(path) // #nosec G304 -- user-provided path for recovery key file
	if err != nil {
		return nil, fmt.Errorf("failed to read recovery key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to read recovery key file: %w", err)
	}

	// The size decides a LOCKED allocation, so it is bounded before anything is
	// mapped rather than after.
	size := info.Size()
	if size <= 0 || size > maxRecoveryKeyFileSize {
		return nil, fmt.Errorf("%w: %s is %d bytes; a recovery key file must be between 1 and %d",
			ErrInvalidSize, path, size, maxRecoveryKeyFileSize)
	}

	contents, err := newSecretEnclave("recovery key file", int(size))
	if err != nil {
		return nil, err
	}
	defer contents.Destroy()

	var keyLine *enclave.MemoryEnclave
	err = borrowSecret("recovery key file", contents, func(b []byte) error {
		if _, err := io.ReadFull(f, b); err != nil {
			return fmt.Errorf("failed to read recovery key file: %w", err)
		}

		// A sub-slice of the locked pages: the line is located by index, never
		// copied out.
		line := firstRecoveryKeyLine(b)
		if len(line) == 0 {
			return fmt.Errorf("no recovery key found in file")
		}

		keyLine, err = copySecret("recovery key", line)
		return err
	})
	if err != nil {
		return nil, err
	}

	return keyLine, nil
}

// RecoveryCredential returns the credential a typed or pasted recovery key
// names: the text itself, in protected memory.
//
// It is the counterpart to ParseRecoveryKey under the current model. There is
// no decoding to do -- the keyslot holds these characters -- so all this does is
// move them into locked memory and refuse what cannot be a recovery key.
//
// # What is NOT normalized, and why
//
// Surrounding whitespace is trimmed, because a paste carries it and no keyslot
// holds it. NOTHING ELSE IS TOUCHED. Case is significant, the dashes are
// significant, and a credential that has been "canonicalized" on the way in is
// a credential the volume has never seen. This is the same contract cryptsetup
// offers when the same string is pasted at its own prompt, which is the point:
// the two must agree, because the whole reason the credential is text is so
// that stock cryptsetup can open the volume without this package.
//
// # What is exposed, precisely
//
// formatted is a Go string and Go strings are immutable, so the CALLER'S copy
// cannot be wiped by anyone. That is unavoidable at this boundary: a recovery
// key reaches a program by being typed, pasted or read out of a file, all of
// which are string-shaped. What this function avoids is making more of them --
// the string is copied ONCE, into locked memory. Callers that already hold the
// key in an enclave, as LoadRecoveryCredential does, should not come through
// here at all.
func RecoveryCredential(formatted string) (*enclave.MemoryEnclave, error) {
	// One copy, into locked memory. []byte(formatted) is the last ordinary
	// allocation the credential sees, and adoptSecret's enclave takes ownership
	// of it and wipes it -- including on the failure path.
	held, err := adoptSecret("recovery key", []byte(formatted))
	if err != nil {
		return nil, err
	}

	var credential *enclave.MemoryEnclave
	if err := borrowSecret("recovery key", held, func(b []byte) error {
		body := trimASCIISpace(b)
		if len(body) == 0 {
			return fmt.Errorf("recovery key is empty")
		}
		// A newline inside the body means more than one line was handed in --
		// the whole file, most likely. Refused rather than silently taking the
		// first line, because guessing which line somebody meant is how the
		// wrong string gets enrolled or tested.
		if bytes.IndexByte(body, '\n') >= 0 {
			return fmt.Errorf("a recovery key is a single line; use LoadRecoveryCredential to read a saved file")
		}

		var err error
		credential, err = copySecret("recovery key", body)
		return err
	}); err != nil {
		held.Destroy()
		return nil, err
	}
	held.Destroy()

	return credential, nil
}

// firstRecoveryKeyLine returns the first line of the file that is neither blank
// nor a comment, as a SUB-SLICE of the input rather than a copy.
//
// It walks bytes rather than using strings.Split, which would allocate an
// unwipeable string per line of a file whose whole point is to hold a
// credential.
func firstRecoveryKeyLine(contents []byte) []byte {
	for len(contents) > 0 {
		line := contents
		if i := bytes.IndexByte(contents, '\n'); i >= 0 {
			line, contents = contents[:i], contents[i+1:]
		} else {
			contents = nil
		}

		line = trimASCIISpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		return line
	}
	return nil
}

// trimASCIISpace returns b without leading or trailing ASCII whitespace, as a
// sub-slice. strings.TrimSpace's byte equivalent that does not copy.
func trimASCIISpace(b []byte) []byte {
	start := 0
	for start < len(b) && isASCIISpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isASCIISpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isASCIISpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// ParseRecoveryKey decodes a formatted recovery key into the KEY MATERIAL
// BEHIND it and returns that in protected memory.
//
// # This is probably not the function you want
//
// Its behavior is unchanged, and so is its meaning: it turns "9F3A2C-4B81DE-..."
// into the bytes that rendering encodes. What changed around it is which of the
// two is the credential. A keyslot enrolled by the current code holds the TEXT,
// so RecoveryCredential is what produces something that opens such a volume;
// this function is for a volume enrolled before that change, whose keyslot holds
// the decoded bytes.
//
// It is tolerant in a way RecoveryCredential is deliberately not -- it accepts
// either case, with or without dashes, hex or base64 -- because it is decoding a
// rendering rather than reproducing a credential.
//
// # What is exposed, precisely
//
// formatted is a Go string and Go strings are immutable, so the CALLER'S copy
// of the key cannot be wiped by anyone. That is unavoidable at this boundary: a
// recovery key reaches a program by being typed, pasted or read out of a file,
// all of which are string-shaped.
//
// What is avoidable is this package making more of them, and it used to make
// about four -- ReplaceAll and ToLower each yield a new string when they change
// anything, and both decoders took []byte(s) of the result. An earlier version
// of this comment described only the caller's copy, which understated the
// exposure by that factor. The string is now copied ONCE, into locked memory,
// and every normalisation and decode happens there.
//
// Callers that already hold the key in an enclave -- LoadRecoveryKey does --
// should not come through here at all.
func ParseRecoveryKey(formatted string) (*enclave.MemoryEnclave, error) {
	if len(formatted) == 0 {
		return nil, fmt.Errorf("recovery key is empty")
	}

	// One copy, into locked memory. []byte(formatted) is the last ordinary
	// allocation the key sees, and copySecret's enclave takes ownership of it
	// and wipes it.
	held, err := adoptSecret("recovery key", []byte(formatted))
	if err != nil {
		return nil, err
	}
	defer held.Destroy()

	return parseRecoveryKeySecret(held)
}

// parseRecoveryKeySecret decodes a formatted recovery key that is already in
// protected memory, normalising in place and decoding into a new enclave.
//
// The format detection is byte-for-byte the same decision tree the string
// version made: dashes mean dashed-hex, an all-hex even-length body is tried as
// hex first, a trailing '=' or any non-hex character admits base64, and hex is
// the fallback.
func parseRecoveryKeySecret(formatted *enclave.MemoryEnclave) (*enclave.MemoryEnclave, error) {
	var key *enclave.MemoryEnclave

	err := borrowSecret("recovery key", formatted, func(raw []byte) error {
		body := trimASCIISpace(raw)
		if len(body) == 0 {
			return fmt.Errorf("recovery key is empty")
		}

		// Dashed: strip the separators and lower-case, into locked scratch.
		if bytes.IndexByte(body, '-') >= 0 {
			stripped, err := copySecretFiltered("recovery key", body, func(c byte) bool { return c != '-' })
			if err != nil {
				return err
			}
			defer stripped.Destroy()

			return borrowSecret("recovery key", stripped, func(hexBody []byte) error {
				lowerASCII(hexBody)
				key, err = decodeHexSecret(hexBody)
				return err
			})
		}

		// Not dashed. The hex test is on the lower-cased body, so a copy is
		// taken to lower-case in -- the borrowed pages of an enclave built from
		// existing material are frozen read-only.
		normalized, err := copySecret("recovery key", body)
		if err != nil {
			return err
		}
		defer normalized.Destroy()

		return borrowSecret("recovery key", normalized, func(b []byte) error {
			lowerASCII(b)
			isHex := isAllHex(b)

			if isHex && len(b)%2 == 0 {
				if k, err := decodeHexSecret(b); err == nil {
					key = k
					return nil
				}
			}

			// base64 is case-sensitive, so it decodes the ORIGINAL body rather
			// than the lower-cased copy.
			if body[len(body)-1] == '=' || !isHex {
				if k, err := decodeBase64Secret(body); err == nil {
					key = k
					return nil
				}
			}

			key, err = decodeHexSecret(b)
			return err
		})
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

// lowerASCII lower-cases ASCII letters in place. strings.ToLower is not usable:
// it returns a new string, and that string would be the recovery key on the
// unprotected heap.
func lowerASCII(b []byte) {
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
}

// isAllHex reports whether every byte is a lower-case hex digit.
func isAllHex(b []byte) bool {
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// VerifyRecoveryKey reports whether a recovery key unlocks the volume.
//
// The key stays in its enclave and is borrowed for the unlock attempt only.
//
// # What to pass
//
// Whatever the keyslot actually holds. For a volume enrolled by the current
// code that is the CREDENTIAL -- RecoveryKey.Credential, or the result of
// RecoveryCredential or LoadRecoveryCredential. For one enrolled before the
// recovery key became the printed text it is the decoded material, from
// ParseRecoveryKey or LoadRecoveryKey. This function tests the bytes it is
// given and does not guess between the two.
//
// # (false, nil) means "no keyslot verified this key", NOT "the key is wrong"
//
// The distinction is the whole point of this function's error return. Every
// failure used to collapse into (false, nil): an unreadable device, a malformed
// header, a keyslot too damaged to try, a FIPS-refused KDF and a failure to
// obtain locked memory all reported "this recovery key does not work". The harm
// is specific and is why #72 exists -- somebody checking a recovery key against
// a CORRUPTED volume was told the key was wrong, and would discard a key that
// works. It also contradicted the fail-closed contract: an operator-fixable
// RLIMIT_MEMLOCK condition surfaced as a bad credential.
//
// Now only a failure to VERIFY produces (false, nil). Everything else is
// returned, so a caller that cares can tell "not this key" from "this volume
// cannot answer the question".
//
// Even (false, nil) stops short of saying the key is wrong, and this comment
// will not say it either: three causes reach the digest comparison
// indistinguishably -- a wrong credential, the RIGHT credential over damaged
// key material, and a semantically wrong digest. Which of them it was is an
// open design question (#68). A caller acting on a false here should read it as
// "this volume did not open with this key", not as grounds to destroy the key.
func VerifyRecoveryKey(device string, key *enclave.MemoryEnclave) (bool, error) {
	if err := ValidateDevicePath(device); err != nil {
		return false, err
	}

	_, metadata, err := ReadHeader(device)
	if err != nil {
		return false, err
	}

	// Try to unlock with the key
	var unlocked bool
	if err := borrowSecret("recovery key", key, func(raw []byte) error {
		masterKey, err := getMasterKey(device, raw, metadata)
		if err != nil {
			if errors.Is(err, ErrMasterKeyVerification) {
				// The keyslots were tried and none verified. That is an answer
				// to the question this function asks, not a failure of it.
				return nil
			}
			// Anything else means the question could not be answered. Saying
			// "no" here would be a statement about the key that the volume
			// never actually made.
			return err
		}
		masterKey.Destroy()
		unlocked = true
		return nil
	}); err != nil {
		return false, err
	}

	return unlocked, nil
}

// formattedLen returns the exact number of bytes a key of n bytes occupies in
// the given rendering, so the destination can be allocated in locked memory up
// front rather than grown on the heap.
func formattedLen(n int, format RecoveryKeyFormat) int {
	switch format {
	case RecoveryKeyFormatBase64:
		return base64.StdEncoding.EncodedLen(n)
	case RecoveryKeyFormatHex:
		return hex.EncodedLen(n)
	default: // dashed, and the default for anything unrecognized
		hexLen := hex.EncodedLen(n)
		if hexLen == 0 {
			return 0
		}
		groups := (hexLen + dashedGroupSize - 1) / dashedGroupSize
		return hexLen + groups - 1
	}
}

// dashedGroupSize is the number of hex characters between dashes in the
// BitLocker-style rendering.
const dashedGroupSize = 6

// formatRecoveryKeyInto renders key into dst, which must be exactly
// formattedLen(len(key), format) bytes.
//
// It encodes in place rather than returning a string because a string holding a
// recovery key can never be wiped. The dashed form is built by encoding the hex
// RIGHT-ALIGNED in dst and then walking left to right inserting separators: the
// read cursor stays ahead of the write cursor for every group, so the expansion
// needs no second buffer.
func formatRecoveryKeyInto(dst, key []byte, format RecoveryKeyFormat) {
	switch format {
	case RecoveryKeyFormatBase64:
		base64.StdEncoding.Encode(dst, key)
	case RecoveryKeyFormatHex:
		hex.Encode(dst, key)
	default:
		hexLen := hex.EncodedLen(len(key))
		if hexLen == 0 {
			return
		}

		src := dst[len(dst)-hexLen:]
		hex.Encode(src, key)

		w, r := 0, len(dst)-hexLen
		for remaining := hexLen; remaining > 0; {
			n := dashedGroupSize
			if remaining < n {
				n = remaining
			}
			copy(dst[w:w+n], dst[r:r+n])
			w += n
			r += n
			remaining -= n
			if remaining > 0 {
				dst[w] = '-'
				w++
			}
		}

		toUpperASCII(dst)
	}
}

// toUpperASCII uppercases hex digits in place. strings.ToUpper is not usable
// here: it returns a new string, and that string would be the recovery key on
// the unprotected heap.
func toUpperASCII(b []byte) {
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
}

// decodeHexSecret decodes hex bytes DIRECTLY into locked memory.
//
// It takes a []byte rather than a string, and the caller has already trimmed
// and lower-cased in place: doing either here would mean strings.TrimSpace and
// strings.ToLower, each yielding an unwipeable copy of the credential.
func decodeHexSecret(src []byte) (*enclave.MemoryEnclave, error) {
	n := hex.DecodedLen(len(src))
	if n == 0 {
		return nil, hex.ErrLength
	}

	return decodeSecret("recovery key", n, func(dst []byte) (int, error) {
		return hex.Decode(dst, src)
	})
}

// decodeBase64Secret decodes base64 bytes DIRECTLY into locked memory.
func decodeBase64Secret(src []byte) (*enclave.MemoryEnclave, error) {
	n := base64.StdEncoding.DecodedLen(len(src))
	if n == 0 {
		return nil, base64.CorruptInputError(0)
	}

	return decodeSecret("recovery key", n, func(dst []byte) (int, error) {
		return base64.StdEncoding.Decode(dst, src)
	})
}

// decodeSecret allocates maxLen bytes of locked memory, lets decode fill it,
// and returns an enclave holding exactly the bytes decode reported.
//
// The two-step exists because base64's DecodedLen is an upper bound -- padding
// makes the real length shorter -- and an enclave sized from the bound would
// hand back trailing zeros as part of the key. The oversized region is
// destroyed once the exact-sized one has been filled, so the surplus is wiped
// rather than merely ignored.
func decodeSecret(op string, maxLen int, decode func(dst []byte) (int, error)) (*enclave.MemoryEnclave, error) {
	scratch, err := newSecretEnclave(op, maxLen)
	if err != nil {
		return nil, err
	}
	defer scratch.Destroy()

	var exact *enclave.MemoryEnclave
	err = borrowSecret(op, scratch, func(dst []byte) error {
		n, err := decode(dst)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("recovery key is empty")
		}
		// The exact-sized enclave is allocated even when n == maxLen, so that
		// the caller's handle never aliases scratch, which is destroyed here.
		exact, err = newSecretEnclave(op, n)
		if err != nil {
			return err
		}
		return borrowSecret(op, exact, func(out []byte) error {
			copy(out, dst[:n])
			return nil
		})
	})
	if err != nil {
		exact.Destroy()
		return nil, err
	}

	return exact, nil
}

// FormattedString materializes the credential as a Go string, for display.
//
// It deliberately produces an UNPROTECTED, unwipeable copy, because displaying
// a recovery key is the entire purpose of one and every display path in Go goes
// through a string. Call it as late as possible, at the point of output, and do
// not store the result. Callers that write the key somewhere should prefer
// SaveRecoveryKey or a borrow of Credential, both of which never materialize it.
//
// The name is kept from when this returned a rendering that was not the
// credential. What it returns has not changed -- the same characters, in the
// same order -- so display code needs no revision; what changed is that those
// characters now open the volume by themselves.
func (r *RecoveryKey) FormattedString() (string, error) {
	s, err := r.Credential.OpenString()
	if err != nil {
		return "", &ProtectedMemoryError{Op: "recovery key", Err: err}
	}
	return s, nil
}

// Clear releases the key material from protected memory. It is idempotent and
// safe on a zero-valued RecoveryKey, so it can always be deferred.
func (r *RecoveryKey) Clear() {
	destroySecrets(r.Credential)
	r.Credential = nil
}
