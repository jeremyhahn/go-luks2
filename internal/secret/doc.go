// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package secret is this module's custody of key material.
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
// The rule this library is held to is that every key,
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
// call permits. Nothing in this module returns raw key bytes across a function
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
//   - The few credentials that reach this module as plain bytes from outside
//     it. See exposure 1.
//
// # The residual exposures
//
// These are recorded here rather than only in a review comment, because the
// guarantee this file provides is narrower than "the key is never in ordinary
// memory" and an overclaim is worse than the current state.
//
//  1. CREDENTIALS THAT ARRIVE AS PLAIN BYTES. The library API does not have this
//     problem: Format, Unlock, UnlockKeyslot, AddKeyslot, ChangeKeyslot and
//     ParseRecoveryKey all take a *enclave.MemoryEnclave, which the caller owns
//     and this module only borrows. What is left is the places a credential is
//     first read from outside the process, before any enclave exists:
//
//     - The CLI's terminal prompt. term.ReadPassword returns a plain []byte; it
//     is moved into an enclave (and the source wiped) immediately, but the
//     bytes exist on the heap until then and in whatever the terminal driver
//     buffered. --key-file is read straight into locked memory a byte at a
//     time, so no plain copy is made in this process; the file or pipe it
//     comes from is outside this module's reach.
//     - keyprovider.WithStdin takes a []byte. It is for NON-SECRET helper
//     input only (the FIDO2 protocols pass a salt and a relying-party id
//     through it). Passing a credential through it would put the credential
//     in an unwipeable buffer, so do not.
//     - keyprovider.NewFIDO2Credential returns the credential id as a []byte.
//     The id is not secret: it is written into the LUKS2 header in the clear.
//
//     This module cannot lock those bytes retroactively and must not wipe a
//     buffer it does not own. What it does NOT do is make copies of its own
//     afterwards: normalising or parsing a recovery key works on enclave
//     contents in place and never goes through a Go string. This entry is for
//     material that arrives already exposed, not a place to record exposure
//     this module chose.
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
//     This applies to EVERY credential an enclave holds, not only the master
//     key: derivePBKDF2 is reached by borrowing the enclave (the passphrase, a
//     recovery key, a key-provider secret) and handing the borrowed slice to
//     pbkdf2.Key(string(...)). The enclave stays the owner; the string copy is
//     the exposure.
//
//     On two paths the "password" is the VOLUME MASTER KEY, because
//     deriveKeySecret borrows an enclave and hands the slice straight down
//     this path. Its two callers are verifyMasterKey, on every unlock, once per
//     digest tried, and createDigest, on every format. "Every unlock" includes
//     Volume.UnlockWithVolumeKey: that path takes the key from the
//     caller and skips the keyslot derivation, but it still verifies the key
//     against the segment's digests through the same loop, once per digest
//     tried. Skipping that check would let a wrong key map garbage as the
//     plaintext device.
//
//     The Argon2 types have the same shape. golang.org/x/crypto/argon2
//     copies its password input into BLAKE2b state that is never wiped, and
//     returns its result on the heap (exposure 3), so an enclave-held
//     credential is exposed there too, for as long as that memory survives.
//
//     # Why this is accepted rather than fixed
//
//     The obvious remedy -- a PBKDF2 whose password and HMAC state stay in
//     wipeable storage -- means implementing PBKDF2 over crypto/hmac, and that
//     is prohibited. This project's security policy forbids hand-rolled
//     cryptography outright, and it is a requirement here:
//
//     No cryptographic primitive or construction is implemented by hand: not a
//     KDF, cipher mode, MAC or any other construction, not even over validated
//     sub-primitives, not even to satisfy another mandate.
//
//     PBKDF2 is therefore crypto/pbkdf2. It copies the password inside the
//     validated module, so the secret cannot stay wipeable through that call;
//     that bounded transient copy is accepted and documented here, and the
//     protected-memory mandate yields at that boundary. The same holds for
//     every validated primitive with that shape, not only this one.
//
//     So this entry is the documentation that requirement demands, not an
//     excuse for a gap. Closing it would mean changing the security policy,
//     not a code change here.
//
//     Note what switching from golang.org/x/crypto/pbkdf2 to the stdlib did and
//     did not do. It did remove a panic: the x/crypto shim calls the same
//     validated implementation and then panic(err)s on anything it returns. It
//     did NOT reduce the copies -- the string conversion moved from the shim
//     into this module's own call, and the Go Cryptographic Module's copy is
//     unchanged. Saying the exposure narrowed would be the kind of overclaim
//     the preamble warns about.
//
//     This is the exposure that most contradicts a casual reading of this
//     package. Three comments elsewhere used to assert the opposite in as many
//     words; they have been corrected rather than the claim quietly narrowed.
//
//  3. KDF OUTPUT. crypto/pbkdf2.Key and argon2.IDKey allocate and RETURN their
//     result on the ordinary Go heap; neither can be asked to write into a
//     caller-provided buffer. The derivation moves that result into an enclave
//     immediately -- Custody.Adopt takes ownership and wipes the source -- so the window is the return statement plus one copy, but it is
//     not zero, and the KDF's own internal scratch is beyond reach entirely.
//
//  4. EXPANDED CIPHER KEYS. xts.NewCipher(aes.NewCipher, key) holds the AES key
//     schedule for both halves of the key on the ordinary heap for the life of
//     the cipher, and neither x/crypto/xts nor crypto/aes offers a way to place
//     it elsewhere or wipe it. A round-key schedule is a deterministic expansion
//     of the key, so recovering it recovers the key. This is on every keyslot
//     encrypt and decrypt. A CBC keyslot area (internal/areacipher) is read through
//     crypto/aes the same way, with a second schedule for ESSIV keyed by
//     SHA-256 of the area key; the hash itself is cleared once that schedule
//     exists.
//
//     go-enclave v0.7.0-alpha erases AES key schedules under runtime/secret
//     (enclave.KeyScheduleErasure), and that does NOT reach this entry. It
//     covers the AES operations inside go-enclave's own sealing, which this
//     package does not use; the XTS ciphers here are built by this module
//     through x/crypto/xts, outside any runtime/secret.Do, so their schedules
//     persist on the heap exactly as described whichever build is running.
//
//     FIPS: the keyslot wrap uses golang.org/x/crypto/xts, which is NOT part of
//     the Go Cryptographic Module. Only the AES block cipher underneath it is.
//     The XTS mode itself therefore runs outside the validated boundary; see
//     docs/fips for what that means for a FIPS deployment.
//
//  5. THE KERNEL KEYRING. This entry used to be THE DEVICE-MAPPER TABLE, and
//     it was the largest hole in this list: dm-crypt was handed the volume key
//     INSIDE its table, and the devmapper.go library hex-encodes a table key into two
//     immutable Go strings plus an uncleared ioctl buffer, all three inside a
//     third-party package this library cannot reach into and all three
//     outliving the call by however long the collector takes.
//
//     That is gone. The key is handed to dm-crypt as a kernel-keyring
//     reference, which is what cryptsetup does, so it goes from its enclave
//     into the kernel through add_key and no userspace string ever holds it.
//     Nothing in this module assigns CryptTable.Key and there is no fallback
//     that would -- a failed keyring hand-off fails the activation closed --
//     so the hex encoding is structurally unreachable rather than
//     conditionally avoided.
//
//     What replaces it is smaller but real, and it is recorded here rather
//     than presented as a clean win. The key spends the activation's table
//     load, the re-check that the name still names the target this call
//     created, and the resume (pkg/dmcrypt activateCreated) in the KERNEL's
//     keyring, and KERNEL KEYRINGS ARE NOT
//     NAMESPACED BY CONTAINER: keys live in the host's key subsystem scoped by
//     uid and by session. Three things bound it. The type is "logon", whose
//     payload is write-only: KEYCTL_READ returns EOPNOTSUPP, so no process --
//     not another container's, not root's -- can read the bytes back out; what
//     a same-uid neighbor could do is SEE that an entry exists and USE it by
//     reference, not learn the key. The ring is the SESSION keyring, never the
//     uid-wide user keyring, and container runtimes give each container its own
//     (measured: runc creates `_ses.<hash>` per container). And the entry exists
//     only from the load to the resume and is then revoked, unlinked and
//     VERIFIED gone; it never outlives the activation call.
//
//     This is much better than an unwipeable userspace string, and it is not
//     nothing. On a host where several containers share a uid AND a session
//     keyring, the window spans the load, a re-check and the resume, and
//     confers use-by-reference, not disclosure.
//
//  6. HASH STATE. sha256.Sum256 leaves its input in the hash's internal state,
//     which is on the stack or heap and cannot be wiped. Two calls hash secret
//     material: areacipher's cbcSectors derives the ESSIV salt as
//     sha256.Sum256(area key), and recoverykey.Hash digests the credential.
//     The ESSIV salt array is cleared after use and the
//     recovery-key digest is public by design, but the hash's internal state,
//     which held the key or credential, is out of reach: the stdlib offers no
//     way to wipe it.
//
// That list is SIX, and it is meant to be exhaustive. If a seventh is found,
// it belongs in this list on the same commit that finds it: the preamble above
// says an overclaim is worse than the current state, and a list that is quietly
// short IS the overclaim.
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
// obtained. There is no degradation to heap. See ErrProtectedMemory.
//
// # Release
//
// Every enclave this module creates is released through Custody.Release, the
// one place that destroys an enclave and reports a failed release. Code that
// owns an enclave defers it; code that only borrows one never releases it.
package secret
