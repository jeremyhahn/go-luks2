// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/rand"
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
// The company mandate (software/CLAUDE.md, owner 2026-08-17) is that every key,
// password, secret or token read into memory lives in protected storage for its
// whole lifetime and is zeroized on release -- never a plain []byte or string --
// and that Layer 0-3 library code touching raw key bytes uses the portfolio
// locked-memory primitive, github.com/jeremyhahn/go-enclave. go-luks2 is Layer 0.
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
//     # Why this is accepted rather than fixed
//
//     The obvious remedy -- a PBKDF2 whose password and HMAC state stay in
//     wipeable storage -- means implementing PBKDF2 over crypto/hmac, and that
//     is prohibited. From the company conventions, security-review.md, "NEVER
//     hand-roll cryptography" (owner ruling 2026-08-25):
//
//     "No agent implements a cryptographic primitive or construction by hand --
//     ever. ... Hand-rolling a KDF, cipher mode, MAC, or any construction --
//     even 'over validated sub-primitives,' even to satisfy another mandate --
//     is prohibited."
//
//     And the case is resolved by name (#155): "crypto/pbkdf2 copies the
//     password inside the validated module, so a secret cannot be kept wipeable
//     through a validated PBKDF2 call. Ruling: use crypto/pbkdf2; accept the
//     bounded transient copy; document it; do NOT hand-roll PBKDF2 over
//     crypto/hmac to keep it wipeable. The protected-memory mandate yields at
//     that boundary. This is the general rule, not a one-off."
//
//     So this entry is the compliance artifact the ruling requires, not an
//     excuse for a gap. Reopening it needs the owner to revisit ruling #155,
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
//     encrypt and decrypt.
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

// newSecretEnclave returns an enclave over n bytes of locked, zeroed memory for
// the caller to fill IN PLACE, through a borrow.
//
// It is the constructor to reach for whenever the material does not exist yet,
// because material produced inside the borrow is never anywhere else. Use
// adoptSecret only for material that already exists outside an enclave and
// cannot be produced inside one.
//
// The two go-enclave constructors are reached through the variables below
// rather than called directly. That is the same seam as dm and nodeRdev
// elsewhere in this package, and it exists for one reason: the fail-closed
// paths cannot otherwise be tested. RLIMIT_MEMLOCK is process-wide, so
// exhausting it for real inside a test binary takes the rest of the suite with
// it, and a refusal that only ever runs on a machine already out of locked
// memory is a refusal nothing checks on the way in.
var (
	newLockedRegion      = enclave.NewMemoryEnclaveSized
	moveIntoLockedRegion = enclave.NewMemoryEnclave
)

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
		_, err := io.ReadFull(rand.Reader, b)
		return err
	}); err != nil {
		e.Destroy()
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

// copySecret returns an enclave holding a copy of b.
//
// It is for material that is ALREADY in protected memory and must be narrowed
// or normalised -- a line located inside a locked file buffer, a body to be
// lower-cased -- where adoptSecret cannot be used because the source is not the
// caller's to wipe. b must itself be protected; copying unprotected bytes with
// this only moves them, it does not un-expose them.
func copySecret(op string, b []byte) (*enclave.MemoryEnclave, error) {
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
		e.Destroy()
		return nil, err
	}

	return e, nil
}

// copySecretFiltered is copySecret keeping only the bytes keep reports true
// for, sized exactly to what survives.
//
// It exists so that stripping separators out of a formatted secret happens
// inside locked memory rather than through strings.ReplaceAll, which would
// yield an unwipeable copy of the whole thing.
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
		e.Destroy()
		return nil, err
	}

	return e, nil
}

// destroySecrets destroys every enclave given, skipping nils. It exists so a
// function holding several pieces of key material can release all of them in a
// single deferred call rather than accumulating defers that are easy to forget
// on an error path.
func destroySecrets(secrets ...*enclave.MemoryEnclave) {
	for _, s := range secrets {
		s.Destroy() // nil-safe by go-enclave contract
	}
}
