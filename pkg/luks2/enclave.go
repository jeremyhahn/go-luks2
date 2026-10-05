// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"errors"
	"io"

	"github.com/jeremyhahn/go-enclave"
)

// Key custody in this package.
//
// # Why this exists
//
// This library performs LUKS2 operations IN PROCESS. Every other LUKS2 consumer
// in the portfolio used to shell out to cryptsetup, and that got the protected-
// memory guarantee for free: the master key was derived, held and handed to the
// kernel inside a SEPARATE process whose address space this one could not read,
// and which exited. Doing the work in process removes that boundary, so this
// library has to provide the guarantee itself.
//
// The rule this library is held to (owner ruling 2026-08-17) is that every key,
// password, secret or token read into memory lives in protected storage for its
// whole lifetime and is zeroized on release -- never a plain []byte or string.
// go-luks2 sits at the bottom of that stack: the low-level libraries that
// handle raw key bytes all share one locked-memory package,
// github.com/jeremyhahn/go-enclave, rather than each rolling its own.
//
// # The ownership model
//
// Key material is OWNED by a *enclave.MemoryEnclave for its whole lifetime and
// only ever BORROWED, through the narrowest WithBytes window that the consuming
// call permits. Nothing in this package returns raw key bytes across a function
// boundary where an enclave handle can be returned instead.
//
// # What is deliberately NOT enclaved
//
// Three classes of bytes are held plainly, on purpose, and each is a decision
// rather than an omission:
//
//   - ENCRYPTED keyslot material. Those bytes are the AF-split master key under
//     the passphrase-derived key, and they are stored on the device in exactly
//     that form. An attacker who can read this process's heap can read the
//     device, so locking them buys no confidentiality while doubling the
//     RLIMIT_MEMLOCK a caller needs (a keyslot area is keySize*4000 bytes --
//     256 KiB for a 512-bit key). Their PLAINTEXT -- the AF stripes -- is
//     enclaved, because that is the master key spread wide.
//   - KDF salts and the stored digest. Both are cleartext fields of the LUKS2
//     header. They are not secret and locking them protects nothing.
//   - Passphrases arriving as []byte from a caller. See below.
//
// # The residual exposures
//
// These are recorded here rather than only in a review comment, because the
// guarantee this file provides is narrower than "the key is never in ordinary
// memory" and an overclaim is worse than the current state.
//
//  1. CALLER-SUPPLIED CREDENTIALS. The exported API takes passphrases as plain
//     []byte (Format, Unlock, AddKey, ...) and a recovery key as a string
//     (ParseRecoveryKey). Those bytes are the caller's, in the caller's memory,
//     before this package is entered; it cannot lock them retroactively and must
//     not wipe a buffer it does not own. It borrows them and, for the string,
//     copies once into locked memory -- a Go string cannot be borrowed without
//     copying and cannot be wiped at all.
//
//     What this does NOT cover is copies this package makes for its own
//     convenience afterwards. LoadRecoveryKey used to read the file into a
//     []byte, stringify it and split it, and ParseRecoveryKey used to normalise
//     through ReplaceAll and ToLower -- four unwipeable copies between them, all
//     avoidable, none of them forced by a boundary. They are gone rather than
//     listed here. This entry is for material that arrives already exposed, not
//     a place to record exposure this package chose.
//
//  2. VALIDATED-MODULE KDF INPUT -- and on two paths the input is THE MASTER
//     KEY. This one is a RULED position, not an oversight; see below.
//
//     crypto/pbkdf2.Key takes its password as a string:
//
//     func Key[Hash hash.Hash](h func() Hash, password string, salt []byte,
//     iter, keyLength int) ([]byte, error)
//
//     so derivePBKDF2 must write string(passphrase) at the call. A Go string is
//     immutable: it cannot be wiped by anybody and survives until the collector
//     reclaims it. Inside the Go Cryptographic Module,
//     crypto/internal/fips140/pbkdf2 then does hmac.New(h, []byte(password)),
//     a second copy, and derives the ipad/opad pair held for the whole
//     derivation; recovering either recovers the input exactly.
//
//     For a passphrase that only widens exposure 1. What matters is
//     deriveKeySecret, which borrows an enclave and hands the borrowed slice
//     straight down this path -- so the "password" is the VOLUME MASTER KEY.
//     Its two callers are verifyMasterKey, on every unlock, once per digest
//     tried, and createDigest, on every format.
//
//     "Every unlock" includes UnlockWithVolumeKey (#79). That path takes the
//     key from the caller and skips the keyslot derivation entirely, so the
//     passphrase side of this entry does not apply to it. It still verifies
//     the key against the segment's digests through the same loop, so the
//     master-key side does, once per digest tried. Skipping that check would
//     let a wrong key map garbage as the plaintext device.
//
//     # Why this is accepted rather than fixed
//
//     The obvious remedy -- a PBKDF2 whose password and HMAC state stay in
//     wipeable storage -- means implementing PBKDF2 over crypto/hmac, and that
//     is prohibited. This project's security policy forbids hand-rolled
//     cryptography outright (owner ruling 2026-08-25):
//
//     "No agent implements a cryptographic primitive or construction by hand --
//     ever. ... Hand-rolling a KDF, cipher mode, MAC, or any construction --
//     even 'over validated sub-primitives,' even to satisfy another mandate --
//     is prohibited."
//
//     And this exact case was resolved by name: "crypto/pbkdf2 copies the
//     password inside the validated module, so a secret cannot be kept wipeable
//     through a validated PBKDF2 call. Ruling: use crypto/pbkdf2; accept the
//     bounded transient copy; document it; do NOT hand-roll PBKDF2 over
//     crypto/hmac to keep it wipeable. The protected-memory mandate yields at
//     that boundary. This is the general rule, not a one-off."
//
//     So this entry is the compliance artifact the ruling requires, not an
//     excuse for a gap. Reopening it needs the owner to revisit that ruling,
//     not a code change here.
//
//     Note what switching from golang.org/x/crypto/pbkdf2 to the stdlib did and
//     did not do. It did remove a panic: the x/crypto shim calls the same
//     validated implementation and then panic(err)s on anything it returns. It
//     did NOT reduce the copies -- the string conversion moved from the shim
//     into this package's own call, and the module's copy is unchanged. Saying
//     the exposure narrowed would be the kind of overclaim the preamble warns
//     about.
//
//     This is the exposure that most contradicts a casual reading of this
//     package. Three comments elsewhere used to assert the opposite in as many
//     words; they have been corrected rather than the claim quietly narrowed.
//
//  3. KDF OUTPUT. crypto/pbkdf2.Key and argon2.IDKey allocate and RETURN their
//     result on the ordinary Go heap; neither can be asked to write into a
//     caller-provided buffer. DeriveKeyEnclave moves that result into an enclave
//     immediately -- enclave.NewMemoryEnclave takes ownership and wipes the
//     source -- so the window is the return statement plus one copy, but it is
//     not zero, and the KDF's own internal scratch is beyond reach entirely.
//
//  4. EXPANDED CIPHER KEYS. xts.NewCipher(aes.NewCipher, key) holds the AES key
//     schedule for both halves of the key on the ordinary heap for the life of
//     the cipher, and neither x/crypto/xts nor crypto/aes offers a way to place
//     it elsewhere or wipe it. A round-key schedule is a deterministic expansion
//     of the key, so recovering it recovers the key. This is on every keyslot
//     encrypt and decrypt. A CBC keyslot area (keyslotarea.go) is read through
//     crypto/aes the same way, with a second schedule for ESSIV keyed by
//     SHA-256 of the area key; the hash itself is cleared once that schedule
//     exists.
//
//     go-enclave v0.7.0-alpha erases AES key schedules under runtime/secret
//     (enclave.KeyScheduleErasure), and that does NOT reach this entry. It
//     covers the AES operations inside go-enclave's own sealing, which this
//     package does not use; the XTS ciphers here are built by this package
//     through x/crypto/xts, outside any runtime/secret.Do, so their schedules
//     persist on the heap exactly as described whichever build is running.
//
//  5. THE KERNEL KEYRING. This entry used to be THE DEVICE-MAPPER TABLE, and
//     it was the largest hole in this list: dm-crypt was handed the volume key
//     INSIDE its table, and devmapper.go hex-encodes a table key into two
//     immutable Go strings plus an uncleared ioctl buffer, all three inside a
//     third-party package this library cannot reach into and all three
//     outliving the call by however long the collector takes.
//
//     That is gone (#78). The key is handed to dm-crypt as a kernel-keyring
//     reference, which is what cryptsetup does, so it goes from its enclave
//     into the kernel through add_key and no userspace string ever holds it.
//     Nothing in this package assigns CryptTable.Key and there is no fallback
//     that would -- owner ruling 2026-08-31, fail closed -- so the hex encoding
//     is structurally unreachable rather than conditionally avoided.
//
//     What replaces it is smaller but real, and it is recorded here rather
//     than presented as a clean win. The key spends the duration of one
//     activation ioctl in the KERNEL's keyring, and KERNEL KEYRINGS ARE NOT
//     NAMESPACED BY CONTAINER: keys live in the host's key subsystem scoped by
//     uid and by session. Three things bound it:
//
//       - the type is "logon", whose payload is write-only. KEYCTL_READ
//         returns EOPNOTSUPP, so no process -- not another container's, not
//         root's -- can read the bytes back out. What a same-uid neighbor
//         could do is SEE that an entry exists and USE it by reference, not
//         learn the key.
//       - the ring is the SESSION keyring, never the uid-wide user keyring,
//         and container runtimes give each container its own (measured: runc
//         creates `_ses.<hash>` per container).
//       - the entry exists for one ioctl and is then revoked, unlinked and
//         VERIFIED gone. It never outlives its mapping.
//
//     This is much better than an unwipeable userspace string, and it is not
//     nothing. On a host where several containers share a uid AND a session
//     keyring, the window is one ioctl wide and confers use-by-reference, not
//     disclosure.
//
// That list is FIVE, and it is meant to be exhaustive. It was three, and the
// missing two were the input side of the KDF -- documented only as an output
// problem -- and the cipher schedule, which was noted locally in format.go and
// never brought here. If a sixth is found, it belongs in this list on the same
// commit that finds it: the preamble above says an overclaim is worse than the
// current state, and a list that is quietly short IS the overclaim.
//
// Entry 5 was REWRITTEN rather than struck out, and that distinction is the
// preamble's rule in action. The exposure it named is genuinely closed, but
// closing it moved the key somewhere else, and a list that had simply deleted
// the entry would have claimed the volume key now touches nothing outside an
// enclave -- which is not true for the duration of the ioctl. Where an exposure
// is traded rather than removed, this list records the trade.
//
// # Fail closed
//
// Every helper here fails the operation when protected memory cannot be
// obtained. There is no degradation to heap. See ProtectedMemoryError.
//
// # Release
//
// Every enclave this package creates is released through releaseSecret, the
// single site that receives go-enclave's release report. "Zeroized on release"
// has one qualification there, and it is not a sixth entry above because no
// key byte reaches ordinary memory through it: where a sandbox denies the
// mprotect a frozen region needs before it can be overwritten, go-enclave
// unmaps the pages WITHOUT the in-process wipe (enclave.ErrReleasedWithoutWipe)
// and the kernel's zeroing of an anonymous page before reuse is what clears
// them. The pages were mlock'd throughout, so nothing reached swap. Why that
// report, and a refused unmap, are dropped there rather than returned is
// recorded on releaseSecret.

// newSecretEnclave returns an enclave over n bytes of locked, zeroed memory for
// the caller to fill IN PLACE, through a borrow.
//
// It is the constructor to reach for whenever the material does not exist yet,
// because material produced inside the borrow is never anywhere else. Use
// adoptSecret only for material that already exists outside an enclave and
// cannot be produced inside one.
//
// The three go-enclave constructors are reached through the variables below
// rather than called directly. That is the same seam as dm and nodeRdev
// elsewhere in this package, and it exists for one reason: the fail-closed
// paths cannot otherwise be tested. RLIMIT_MEMLOCK is process-wide, so
// exhausting it for real inside a test binary takes the rest of the suite with
// it, and a refusal that only ever runs on a machine already out of locked
// memory is a refusal nothing checks on the way in.
//
// All three ADMIT through go-enclave's process Allocator before anything is
// mapped (#26): the library allocates against the one budget the binary sized
// (enclave.SetAllocator), or against RLIMIT_MEMLOCK by default, and never
// installs or builds an allocator of its own. A refusal is the allocator's
// typed enclave.ErrBudgetExhausted rather than an mlock failure partway through.
var (
	newLockedRegion      = admittedSized
	moveIntoLockedRegion = admittedMove
	copyIntoLockedRegion = admittedCopy

	// lockedMemoryAllocator is the allocator every enclave is admitted
	// against. A variable only so a test can stand in a small budget.
	lockedMemoryAllocator = enclave.ProcessAllocator
)

// admittedSized is enclave.NewMemoryEnclaveSized, admitted.
func admittedSized(n int) (*enclave.MemoryEnclave, error) {
	a, err := lockedMemoryAllocator()
	if err != nil {
		return nil, err
	}
	return a.NewSized(n)
}

// admittedMove is enclave.NewMemoryEnclave, admitted. It owns b on every
// path, as NewMemoryEnclave does: b is wiped even when nothing is admitted.
func admittedMove(b []byte) (*enclave.MemoryEnclave, error) {
	a, err := lockedMemoryAllocator()
	if err != nil {
		enclave.Wipe(b)
		return nil, err
	}
	return a.New(b)
}

// admittedCopy is enclave.NewMemoryEnclaveCopy, admitted: the copy is made
// into the admitted pages, which are then frozen read-only as that
// constructor's are. src is left alone.
func admittedCopy(src []byte) (*enclave.MemoryEnclave, error) {
	if len(src) == 0 {
		return nil, enclave.ErrEmptyEnclave
	}
	e, err := admittedSized(len(src))
	if err != nil {
		return nil, err
	}
	if err := e.WithBytes(func(dst []byte) error {
		copy(dst, src)
		return nil
	}); err != nil {
		_ = e.Destroy()
		return nil, err
	}
	if err := e.Freeze(); err != nil {
		_ = e.Destroy()
		return nil, err
	}
	return e, nil
}

func newSecretEnclave(op string, n int) (*enclave.MemoryEnclave, error) {
	e, err := newLockedRegion(n)
	if err != nil {
		return nil, &ProtectedMemoryError{Op: op, Err: err}
	}
	return e, nil
}

// adoptSecret moves already-materialized key material into an enclave.
//
// It TAKES OWNERSHIP of b: go-enclave wipes the caller's slice on every return
// path, including the failure path, so the material does not survive in
// ordinary memory even when the lock is refused. The caller must not read b
// afterwards.
//
// This is the second-best constructor and exists only for the stdlib boundary
// where a value is handed back to us already on the heap -- a KDF return, an
// AF-merge result. Prefer newSecretEnclave.
func adoptSecret(op string, b []byte) (*enclave.MemoryEnclave, error) {
	e, err := moveIntoLockedRegion(b)
	if err != nil {
		return nil, &ProtectedMemoryError{Op: op, Err: err}
	}
	return e, nil
}

// randomSecret draws n cryptographically secure random bytes DIRECTLY into
// locked memory.
//
// The read happens inside the borrow, so the bytes are written into the locked
// pages themselves and never exist on the Go heap -- which is the whole point.
// A master key produced with randomBytes and then moved would have spent its
// first moments on swappable, core-dumpable memory that a later wipe cannot
// reliably reach.
func randomSecret(op string, n int) (*enclave.MemoryEnclave, error) {
	e, err := newSecretEnclave(op, n)
	if err != nil {
		return nil, err
	}

	if err := e.WithBytes(func(b []byte) error {
		_, err := io.ReadFull(cryptoRand, b)
		return err
	}); err != nil {
		releaseSecret(e)
		return nil, &CryptoError{Op: op, Err: err}
	}

	return e, nil
}

// borrowSecret runs fn against the material inside e, translating a dead or
// destroyed enclave into a ProtectedMemoryError so that callers get one error
// vocabulary rather than go-enclave's.
//
// fn must not retain the slice and must not call back into the same enclave;
// both are go-enclave contracts, not local conventions. fn MAY borrow other
// enclaves, which is what makes the crypto helpers here composable.
func borrowSecret(op string, e *enclave.MemoryEnclave, fn func([]byte) error) error {
	err := e.WithBytes(fn)
	if err == nil {
		return nil
	}
	if errors.Is(err, enclave.ErrEnclaveDestroyed) {
		return &ProtectedMemoryError{Op: op, Err: err}
	}
	// fn's own error passes through unwrapped; only the custody failure is
	// reclassified.
	return err
}

// copySecret returns a FROZEN enclave holding a copy of b.
//
// It is for material that is ALREADY in protected memory and must be narrowed
// -- a line located inside a locked file buffer, a body trimmed of its
// surrounding whitespace -- where adoptSecret cannot be used because the source
// is not the caller's to wipe. b must itself be protected; copying unprotected
// bytes with this only moves them, it does not un-expose them.
//
// The result is read-only, exactly as adoptSecret's is: the material is
// complete when this returns, so a write through a slice retained past its
// borrow faults the process instead of silently corrupting a credential. Since
// go-enclave v0.5.0-alpha that is one constructor call rather than a sized
// region, a borrow to fill it and a Destroy on the error path -- the
// composition copySecretWritable below still carries, for the one case that
// needs the pages to stay writable.
func copySecret(op string, b []byte) (*enclave.MemoryEnclave, error) {
	e, err := copyIntoLockedRegion(b)
	if err != nil {
		return nil, &ProtectedMemoryError{Op: op, Err: err}
	}
	return e, nil
}

// copySecretWritable is copySecret whose result a borrow may WRITE to.
//
// It exists for a copy that is normalised in place after it is taken -- a
// candidate body lower-cased before the hex test -- which the frozen result of
// copySecret cannot be. The pages are writable for the enclave's whole life,
// so the copy should be short-lived scratch, destroyed as soon as the
// normalised bytes have been consumed; material that is returned to a caller
// belongs in copySecret.
func copySecretWritable(op string, b []byte) (*enclave.MemoryEnclave, error) {
	if len(b) == 0 {
		return nil, &ProtectedMemoryError{Op: op, Err: enclave.ErrEmptyEnclave}
	}

	e, err := newSecretEnclave(op, len(b))
	if err != nil {
		return nil, err
	}

	if err := borrowSecret(op, e, func(dst []byte) error {
		copy(dst, b)
		return nil
	}); err != nil {
		releaseSecret(e)
		return nil, err
	}

	return e, nil
}

// copySecretFiltered is copySecretWritable keeping only the bytes keep reports
// true for, sized exactly to what survives.
//
// It exists so that stripping separators out of a formatted secret happens
// inside locked memory rather than through strings.ReplaceAll, which would
// yield an unwipeable copy of the whole thing. The result is writable for the
// same reason copySecretWritable's is: the stripped body is lower-cased in
// place before it is decoded.
func copySecretFiltered(op string, b []byte, keep func(byte) bool) (*enclave.MemoryEnclave, error) {
	n := 0
	for _, c := range b {
		if keep(c) {
			n++
		}
	}
	if n == 0 {
		return nil, &ProtectedMemoryError{Op: op, Err: enclave.ErrEmptyEnclave}
	}

	e, err := newSecretEnclave(op, n)
	if err != nil {
		return nil, err
	}

	if err := borrowSecret(op, e, func(dst []byte) error {
		i := 0
		for _, c := range b {
			if keep(c) {
				dst[i] = c
				i++
			}
		}
		return nil
	}); err != nil {
		releaseSecret(e)
		return nil, err
	}

	return e, nil
}

// destroyEnclave is go-enclave's release, reached through a variable for the
// same reason the constructors above are: the refusals it reports cannot be
// produced on demand. A refused munlock or munmap needs the kernel to be out of
// map slots, and a denied mprotect needs a seccomp filter, neither of which a
// test binary can impose on itself without taking the rest of the suite with
// it.
var destroyEnclave = (*enclave.MemoryEnclave).Destroy

// releaseSecret destroys e -- zeroizing the material and returning its pages --
// and is the ONE place this package receives go-enclave's release report. Every
// enclave this package creates is released through it (or through
// destroySecrets, which calls it), so the decision below is made once rather
// than re-made, or silently not made, at each of the call sites.
//
// # What the report can say, and why it is not an operation failure
//
// Since go-enclave v0.7.0-alpha Destroy returns the release report directly.
// Apart from nil it is one of two things, and neither means key material
// escaped locked memory:
//
//   - enclave.ErrReleasedWithoutWipe: the mprotect that makes a frozen region
//     writable was denied (a seccomp filter or sandbox), so the pages were
//     unmapped without the in-process overwrite. They were mlock'd for their
//     whole life, so nothing reached swap, and the kernel zeroes an anonymous
//     page before any reuse. What it reports is the ENVIRONMENT: the same
//     denial reaches every frozen enclave in the process.
//   - enclave.ErrLockedMemoryUnavailable: the release itself was refused
//     (ENOMEM at vm.max_map_count is the realistic cause), so the pages are
//     still MAPPED and stay on go-enclave's WipeAll ledger. Whether they are
//     still LOCKED depends on how far the release got, and what matters is
//     that it never leaves material both unwiped and unlocked: go-enclave
//     wipes before it unlocks. If the wipe ran -- a refused munlock, or a
//     refused munmap after a successful munlock -- the pages hold zeroes,
//     locked or not. If it could not run -- the wipe-enabling mprotect AND the
//     bare-unmap fallback were both refused -- the material is still there and
//     the pages are still mlock'd, as they have been all along. Only the
//     process's WipeAll, or the process's exit, takes them back.
//
// Under go-enclave v0.5.0-alpha, which this package used before, the second
// case did not reach a caller as a report at all: a refused munlock or munmap
// PANICKED out of Destroy, contrary to go-enclave's own contract, and go-enclave
// v0.6.2-alpha fixed that (its #83). So adopting v0.7 changes this package's
// behavior there, from a crash at the release to the operation completing with
// the pages left on the ledger. That is the intended direction: the crash
// protected no key byte, and it could abort an operation midway -- between
// writing a keyslot and releasing the stripes that wrote it -- for a condition
// that only costs address space. The first case was already dropped then,
// implicitly, by the void Destroy every call site used.
//
// This package can do nothing with either. It cannot remedy the environment,
// retrying at once with nothing changed is refused again (go-enclave's own
// guidance), and WipeAll belongs to the binary that owns the process, never to
// a library. Nor may it turn either into the operation's error: every release
// here happens after the operation's outcome is already decided -- a volume
// formatted, a keyslot written, a mapping created -- or while an earlier error
// is already being returned. Reporting a completed Format or Unlock as failed
// because an unmap was refused afterwards would invite the caller to repeat it,
// and a repeated Format destroys a volume. And it may not log: a logger, or a
// write to log/slog's process-global default, in a layer-0 primitive imposes a
// logging decision on every embedding application (see forgetKeyslotID in
// header.go).
//
// So the report is dropped HERE, deliberately and for those reasons. An
// application that wants to see these conditions has them where it can act: its
// own Destroy calls on the enclaves this package hands it (recovery
// credentials, KeyProvider output) report the same environment, and its
// shutdown WipeAll counts any pages still held -- these included -- and
// reports, as a *enclave.SweepError, the unwiped releases and corruption the
// sweep itself meets.
//
// Detected CORRUPTION is not a report and is not dropped: go-enclave panics
// with enclave.ErrEnclaveCorrupted, after wiping, and releaseSecret does not
// recover it. A process whose locked memory was written by something that did
// not own it must not carry on.
func releaseSecret(e *enclave.MemoryEnclave) {
	// Dropped on purpose; see the doc comment above for every outcome and why
	// none of them is this package's to act on or to return.
	_ = destroyEnclave(e)
}

// destroySecrets releases every enclave given through releaseSecret, skipping
// nils. It exists so a function holding several pieces of key material can
// release all of them in a single deferred call rather than accumulating defers
// that are easy to forget on an error path.
func destroySecrets(secrets ...*enclave.MemoryEnclave) {
	for _, s := range secrets {
		releaseSecret(s)
	}
}
