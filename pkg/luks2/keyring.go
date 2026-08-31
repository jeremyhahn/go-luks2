// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// The volume key reaches dm-crypt through the KERNEL KEYRING, not through the
// device-mapper table.
//
// # What this closes
//
// A dm-crypt table carries its key inline, and github.com/anatol/devmapper.go
// builds that table with hex.EncodeToString plus strings.Join -- so handing it
// a Key produces two immutable Go strings holding the volume key in hex, and
// then an ordinary heap buffer for the ioctl that is never cleared. Go strings
// cannot be wiped by anybody, and all three live inside a third-party package
// this library cannot reach into, so the key sits in unprotected, unwipeable
// memory for an unbounded time after the mapping is created. In a long-lived
// storage daemon -- which is how go-blockstore consumes this library -- that
// is one process holding every volume key it has ever opened until the
// collector happens to reclaim the pages.
//
// dm-crypt's other key form is a REFERENCE: a table field of the shape
//
//	:<key size in bytes>:<key type>:<key description>
//
// which makes the kernel resolve the key out of the calling task's keyrings
// with request_key(). devmapper.CryptTable exposes it as KeyID and short-
// circuits the hex path entirely when it is set (crypt.go: `key := c.KeyID; if
// key == "" { key = hex.EncodeToString(c.Key) }`), so no upstream change is
// needed and no userspace string ever holds the key. This is what cryptsetup
// itself does, so the format is proven rather than novel.
//
// There is NO in-table fallback. Owner ruling 2026-08-31: fail closed, we do
// not support legacy kernels that are insecure. Nothing in this package assigns
// CryptTable.Key, which is what makes the guarantee structural rather than
// conditional -- there is no path, no option and no environment in which the
// hex encoding above can be reached.
//
// # Why the "logon" key type
//
// A logon key's payload is WRITE-ONLY from userspace: KEYCTL_READ returns
// EOPNOTSUPP for it, unlike a "user" key whose payload any possessor can read
// back. So once the bytes cross into the kernel they cannot be retrieved by
// this process, by another process of the same user, or by root. That is a
// strictly stronger custody position than the enclave the key came from, which
// is why the borrow can be handed straight to add_key.
//
// # Why the SESSION keyring, and why the goroutine is pinned
//
// Kernel keyrings are NOT namespaced by container. Keys live in the host's key
// subsystem scoped by uid and by session, so the choice of ring is a blast
// radius decision and not a detail:
//
//   - the USER keyring (_uid) is shared by every process of that uid on the
//     host, across containers. It is not used here.
//   - the SESSION keyring is per-session. A container runtime gives each
//     container its own -- measured: runc creates `_ses.<hash>` per container
//     -- so in the deployments this library targets the ring is already
//     container-scoped, and where it is not it is still narrower than the uid.
//
// The ring is RESOLVED to a concrete serial with KEYCTL_GET_KEYRING_ID before
// anything is added, rather than passing KEY_SPEC_SESSION_KEYRING to each call.
// That is deliberate and it is a correctness guard, not tidiness: when a task
// has no session keyring, a lookup WITHOUT the create flag installs the
// uid-shared _uid_ses ring into its credentials, while a lookup WITH it creates
// a fresh anonymous one. Letting the ring be decided implicitly by whichever
// call happened to run first would make the blast radius depend on call order.
// Resolving once, with create, pins it to the narrow answer.
//
// The goroutine is pinned across the whole sequence because dm-crypt resolves
// the reference with request_key() from inside the DM_TABLE_LOAD ioctl, which
// runs in the context of the calling TASK -- so the search covers that task's
// thread, process and session keyrings and nothing else. Linux credentials are
// per-task even for threads: installing or joining a keyring goes through
// prepare_creds/commit_creds, which diverges the calling thread's credentials
// from its siblings'. A Go goroutine may be rescheduled onto a different OS
// thread between two syscalls, so without the pin a key added on one thread
// would occasionally be invisible to the ioctl issued from another, and the
// unlock would fail with ENOKEY at random.
//
// # Lifetime: the activation call, and not one instant longer
//
// The entry is removed as soon as CreateAndLoad returns, on the success path
// as well as every failure path. This is deliberately NARROWER than "for the
// lifetime of the mapping":
//
//   - dm-crypt copies the payload into its own crypt_config and programs the
//     crypto transforms during crypt_ctr, then does key_put() on the keyring
//     reference. Nothing in normal operation -- reads, writes, suspend, resume,
//     removal -- consults the keyring again; only an explicit `dmsetup message
//     ... key set` would, which this library never issues.
//   - cryptsetup's effective behavior is the same. It adds to a keyring of a
//     process that then exits, so the entry is gone the moment the command
//     finishes while the mapping stays live.
//
// A shorter lifetime is strictly better custody and it also removes a whole
// class of leak: there is no keyring entry that can outlive its mapping, so
// Lock and the unlock rollback have nothing keyring-shaped to clean up and
// cannot forget to. The integration suite proves the assumption rather than
// asserting it -- it drives I/O through the mapping, across a suspend/resume
// cycle, after the entry is gone.
//
// # Nothing here may fail silently
//
// Three failures in this file would otherwise be invisible, and each is
// refused by a check rather than warned about in a comment:
//
//  1. A stale or colliding entry. add_key UPDATES a key of the same type and
//     description in place instead of failing, so a leftover from a crashed
//     process -- or an entry planted by another process of the same uid, which
//     the session keyring does not prevent -- would be silently overwritten or
//     silently adopted. The description is deterministic per volume (see
//     keyringDescription) and the ring is SEARCHED before anything is added:
//     an entry that is already there is an anomaly and fails the unlock with
//     ErrKeyringEntryExists.
//  2. A release that did not take. Trusting the revoke and unlink return values
//     would leave the volume key in the kernel keyring whenever the kernel said
//     one thing and did another. release VERIFIES absence by searching again,
//     and reports ErrKeyringKeyNotReleased when the key is still resolvable or
//     when its absence cannot be confirmed.
//     The search and the add are not atomic, and that is a KNOWN, accepted
//     residual rather than an oversight. Two concurrent unlocks of the same
//     volume can both observe absence; the loser's add updates the winner's
//     entry. There is no key confusion in that race -- both are adding the
//     same volume master key, recovered from the same header -- so the worst
//     outcome is one of them seeing ENOKEY and failing, an availability flake.
//     Closing it needs an atomic test-and-add the keyctl interface does not
//     offer. It is the same shape as the IsUnlocked check this package already
//     documents, and it is recorded rather than restructured for.
//  3. Fail-closed arriving at first unlock. A container configured without the
//     keyring syscalls is a boot-time defect, but Unlock is the first thing
//     that would notice -- turning a config error into an outage in the middle
//     of service. CheckKeyringAvailable is the preflight that moves it to
//     startup.

const (
	// keyringKeyType is the kernel key type the volume key is stored under.
	// See above for why it is "logon" and not "user".
	keyringKeyType = "logon"

	// keyringDescriptionPrefix is the "subsystem" qualifier the kernel's
	// logon_vet_description REQUIRES: a logon key description must contain a
	// colon that is not its first character. A description without one is
	// rejected with EINVAL, which is why this is a constant rather than
	// something a caller could omit.
	keyringDescriptionPrefix = "luks2"
)

// kernelKeyring is the seam between this package and the kernel's key
// management syscalls, in the same shape and for the same reason as the
// deviceMapper seam in devicemapper.go: the failures that matter here -- a
// seccomp profile denying the syscalls, a release that does not take, a
// pre-existing entry -- cannot all be produced for real in a test. The happy
// path IS exercised against the real kernel (these syscalls work unprivileged
// for logon keys), so the seam exists for the refusals.
type kernelKeyring struct {
	sessionRing func() (int, error)
	add         func(keyType, description string, payload []byte, ringID int) (int, error)
	search      func(ringID int, keyType, description string) (int, error)
	revoke      func(keyID int) error
	unlink      func(keyID, ringID int) error
}

// keyring is the live kernel keyring, a package-level value for the same
// reason dm is: every consumer wants the real kernel and only the tests want
// anything else.
var keyring = liveKeyring()

// liveKeyring returns the real implementation.
//
// unix.AddKey passes &payload[0] straight to the add_key syscall without
// copying, which is what makes it safe to hand it a slice borrowed from an
// enclave: the bytes go from locked memory into the kernel with nothing in
// between. Adding a keyring hop that staged the key on the heap first would
// defeat the entire point of this change.
func liveKeyring() kernelKeyring {
	return kernelKeyring{
		sessionRing: func() (int, error) {
			// create=true. See the file comment: without it, a task with no
			// session keyring gets the uid-shared one installed instead of a
			// fresh anonymous one.
			return unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, true)
		},
		add: unix.AddKey,
		search: func(ringID int, keyType, description string) (int, error) {
			return unix.KeyctlSearch(ringID, keyType, description, 0)
		},
		revoke: func(keyID int) error {
			_, err := unix.KeyctlInt(unix.KEYCTL_REVOKE, keyID, 0, 0, 0)
			return err
		},
		unlink: func(keyID, ringID int) error {
			_, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, ringID, 0, 0)
			return err
		},
	}
}

// keyringVolumeKey is a live keyring entry holding a volume key, and the
// dm-crypt reference that names it.
type keyringVolumeKey struct {
	id          int
	ring        int
	description string
	keySize     int
}

// tableKeyID returns the dm-crypt key_string for this entry -- the value that
// goes in CryptTable.KeyID instead of the key itself.
//
// The size is in BYTES and the kernel CHECKS it: crypt_ctr parses it out of the
// reference and crypt_set_keyring_key refuses the load with EINVAL if the
// keyring payload is a different length. It is therefore taken from the
// borrowed slice rather than from anything the header claims.
func (k *keyringVolumeKey) tableKeyID() string {
	return fmt.Sprintf(":%d:%s:%s", k.keySize, keyringKeyType, k.description)
}

// release revokes the entry, unlinks it, and then VERIFIES that it is gone.
//
// The verification is the point. Revoking runs the key type's revoke method
// immediately, which for a logon key frees the payload through kfree_sensitive
// -- so the bytes are zeroed at once rather than whenever the last reference
// happens to be dropped -- and the unlink then removes the last link. But a
// return value of nil from either is a claim, not evidence, and the thing being
// claimed is that a volume master key is no longer in kernel memory. So the
// ring is searched again and the answer has to be "not there".
//
// A key that was ALREADY gone, or already revoked, is not a failure: ENOKEY and
// ENOENT mean the entry no longer exists, and EKEYREVOKED means its payload has
// already been freed. All three are the outcome this call wanted.
//
// Anything else -- the key still resolving, or a search that cannot say --
// means the volume key may still be sitting in the kernel keyring, and that is
// reported rather than swallowed. Unconfirmed is treated as still-present, the
// same conservative direction removeCreatedMapping takes for a plaintext
// mapping it cannot inspect.
func (k *keyringVolumeKey) release() error {
	revokeErr := ignoreAbsentKey(keyring.revoke(k.id))
	unlinkErr := ignoreAbsentKey(keyring.unlink(k.id, k.ring))

	joined := errors.Join(revokeErr, unlinkErr, k.verifyGone())
	if joined == nil {
		return nil
	}

	// The cause is classified here too, not only on the way in. This is the
	// path that reports A MASTER KEY MAY STILL BE RESIDENT, so it is the last
	// place that should hand an operator a bare errno: whatever refused a
	// revoke on a key this process just created is the same kind of condition
	// -- a policy, a quota, a kernel -- that refuses an add, and it deserves
	// the same remedy.
	return fmt.Errorf("%w: the volume key may still be present in the kernel keyring as %s %q; inspect it with `keyctl show %d` and remove it with `keyctl unlink %d %d`: %w. %s",
		ErrKeyringKeyNotReleased, keyringKeyType, k.description, k.ring, k.id, k.ring,
		joined, keyringRemedy(classifyKeyringErrno(joined)))
}

// verifyGone reports an error unless the kernel confirms the entry is no longer
// resolvable. See release for why a successful unlink is not accepted as proof.
func (k *keyringVolumeKey) verifyGone() error {
	id, err := keyring.search(k.ring, keyringKeyType, k.description)
	switch {
	case err == nil:
		return fmt.Errorf("the entry is still resolvable as key %d after being revoked and unlinked", id)
	case isAbsentKey(err):
		return nil
	default:
		return fmt.Errorf("the keyring could not be searched to confirm the entry is gone: %w", err)
	}
}

// ignoreAbsentKey maps "the key is not there" onto success and passes
// everything else through. See release.
func ignoreAbsentKey(err error) error {
	if err == nil || isAbsentKey(err) || errors.Is(err, unix.EKEYREVOKED) {
		return nil
	}
	return err
}

// isAbsentKey reports whether err is the kernel saying no such key, as opposed
// to any other reason a lookup can fail. The distinction decides whether a
// volume key is reported as possibly-still-present, so it is drawn on the errno
// rather than on message text.
func isAbsentKey(err error) bool {
	return errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.ENOENT)
}

// addVolumeKeyToKeyring places key in the kernel keyring under a description
// that identifies this volume and mapping, and returns the handle that names
// it.
//
// key is a slice BORROWED from an enclave for the duration of this call. It is
// handed to add_key and to nothing else: no copy, no staging buffer, no string.
// The caller must release the returned entry.
//
// An entry that already exists under this description FAILS the operation. See
// the file comment: add_key would otherwise update it in place, so overwriting
// somebody else's key material or adopting a stale entry would both be silent.
func addVolumeKeyToKeyring(dmUUID string, key []byte) (*keyringVolumeKey, error) {
	ring, err := keyring.sessionRing()
	if err != nil {
		return nil, keyringFailure("resolve the session keyring", err)
	}

	description := keyringDescription(dmUUID)

	switch id, searchErr := keyring.search(ring, keyringKeyType, description); {
	case searchErr == nil:
		return nil, fmt.Errorf("%w: %s key %q (the digest of device-mapper UUID %q) is already present as key %d, so this unlock would silently overwrite or adopt key material it did not create; a leftover from a crashed process can be removed with `keyctl unlink %d %d`",
			ErrKeyringEntryExists, keyringKeyType, description, dmUUID, id, id, ring)
	case isAbsentKey(searchErr):
		// The expected case: nothing is there.
	default:
		return nil, keyringFailure("search the session keyring", searchErr)
	}

	id, err := keyring.add(keyringKeyType, description, key, ring)
	if err != nil {
		return nil, keyringFailure("add the volume key to the session keyring", err)
	}

	return &keyringVolumeKey{
		id:          id,
		ring:        ring,
		description: description,
		keySize:     len(key),
	}, nil
}

// keyringDescription builds the key description for a mapping: the subsystem
// qualifier the kernel requires, and a SHA-256 digest of the volume's dm UUID.
//
// # Why a digest and not the UUID itself
//
// The description ends up inside CryptTable.KeyID, and devmapper.go joins the
// target specification with strings.Join(args, " ") -- so the reference is ONE
// SPACE-DELIMITED TOKEN in a positional grammar the kernel parses as
// `<cipher> <key> <iv_offset> <device> <start>`. A space, a newline or a NUL
// anywhere in that token shifts every field after it.
//
// The dm UUID is built from the LUKS2 header's uuid field -- 40 bytes read
// straight off the device, whose charset the header reader does not constrain
// and whose checksum a hostile header author also controls -- and from the
// caller's mapping name. Before #78 those bytes only reached the fixed-width
// DmIoctl name and uuid fields, which are not grammar-parsed. Making them
// reach a parsed grammar is what created the exposure, so it is closed HERE.
//
// Hashing closes it BY CONSTRUCTION rather than by validation: the output is 64
// characters of [0-9a-f] whatever the input was, so there is no charset to get
// wrong, no escaping to forget, and no "one character short" whitelist. It is
// the same move as leaving CryptTable.Key unassigned instead of defaulting it
// off -- the bad state is unrepresentable rather than merely avoided.
// ValidateMappingName still bounds the name, because the name reaches
// /dev/mapper and the dm UUID by other routes that no hash covers.
//
// Determinism is preserved, which is what the pre-add collision guard in
// addVolumeKeyToKeyring depends on: the same volume and mapping always hash to
// the same description, so a leftover entry is still detected. A random nonce
// would have made collisions impossible and that guard vacuous.
//
// The digest is not a secret and is not derived from anything secret -- the
// header UUID and the mapping name are both public, printed by `dmsetup info`.
// It is used for its closed alphabet, not for any cryptographic property; the
// entry it names is only meaningful for the duration of one ioctl.
//
// The cost is that `keyctl show` no longer names the volume, so the errors in
// this file carry both the digest and the dm UUID it came from.
func keyringDescription(dmUUID string) string {
	digest := sha256.Sum256([]byte(dmUUID))
	return keyringDescriptionPrefix + ":" + hex.EncodeToString(digest[:])
}

// CheckKeyringAvailable verifies that this process can actually place a volume
// key in the kernel keyring, and returns the same typed, actionable error
// Unlock would return if it cannot.
//
// # Why a preflight exists
//
// Unlock fails closed when the keyring is unavailable, which is the right
// answer to the wrong question if it is asked for the first time halfway
// through a shift. The condition it detects -- a container started without the
// keyring syscalls -- is fixed at boot and cannot change afterwards, so
// discovering it at the first unlock of a customer volume converts a
// configuration error into an outage. Calling this at startup converts it back:
// the process refuses to come up, and the error names the syscalls and the
// remedy.
//
// Long-lived consumers (a storage daemon, a node agent) should call it during
// initialization. It is cheap -- one add and one release of a 32-byte probe --
// and it exercises the same syscalls, key type and ring resolution that an
// unlock does, including the release path, so a kernel that can add but not
// revoke is caught here too rather than at teardown.
//
// A nil return is not a promise that a later unlock will succeed; the quota can
// still be exhausted between the two. It is a promise that the syscalls are
// reachable, which is the failure this exists to move earlier.
func CheckKeyringAvailable() error {
	// The probe description is randomized precisely because volume
	// descriptions are not: a preflight must not fail because a previous probe
	// left something behind, and it must never collide with a real volume's
	// entry.
	nonce := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return keyringFailure("draw randomness for the keyring preflight", err)
	}
	probe := fmt.Sprintf("preflight-%d-%s", os.Getpid(), hex.EncodeToString(nonce))

	// A throwaway value of the length a LUKS2 aes-xts-plain64 volume key has,
	// so the preflight also exercises the size the real path uses against any
	// payload-length limit the kernel imposes.
	material, err := randomSecret("keyring preflight", 64)
	if err != nil {
		return err
	}
	defer material.Destroy()

	// Pinned for the same reason unlockLoadTable pins: the ring belongs to the
	// task, so the add and the release have to happen on the same one.
	unpin := pinToOSThread()
	defer unpin()

	var entry *keyringVolumeKey
	if err := borrowSecret("keyring preflight", material, func(b []byte) error {
		var addErr error
		entry, addErr = addVolumeKeyToKeyring(probe, b)
		return addErr
	}); err != nil {
		return err
	}

	return entry.release()
}

// pinToOSThread pins the calling goroutine to the OS thread it is running on
// and returns the function that releases it.
//
// Every keyring sequence in this package runs inside one of these windows. The
// reason is in the file comment: keyrings belong to the TASK, so an add on one
// OS thread and a use on another are not guaranteed to see the same ring, and
// Go is free to move a goroutine between the two syscalls. Lock/Unlock nest by
// count, so a caller that has already pinned stays pinned.
func pinToOSThread() func() {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}

// keyringFailure classifies an errno from a keyring syscall and attaches the
// remedy for that specific cause.
//
// The classification is not cosmetic. A blocked syscall, a kernel without key
// support, an exhausted quota and a genuine kernel refusal are four different
// problems with four different fixes, and a single "keyring unavailable" would
// be technically true and operationally useless -- it would send an operator
// looking at their kernel config when the answer is a seccomp profile.
func keyringFailure(op string, err error) error {
	return &KeyringUnavailableError{Op: op, Kind: classifyKeyringErrno(err), Err: err}
}

// classifyKeyringErrno maps an errno onto the sentinel that names its cause.
func classifyKeyringErrno(err error) error {
	switch {
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		// MEASURED 2026-08-31 across container configurations: Docker's default
		// seccomp profile denies add_key, keyctl and request_key, and
		// --cap-add SYS_ADMIN does NOT lift it -- only relaxing seccomp does.
		// EPERM here is therefore a policy refusal far more often than a
		// permission one, which is why the remedy talks about seccomp first.
		return ErrKeyringBlocked
	case errors.Is(err, unix.ENOSYS):
		return ErrKeyringUnsupported
	case errors.Is(err, unix.EDQUOT), errors.Is(err, unix.EKEYREJECTED):
		return ErrKeyringQuotaExhausted
	default:
		return ErrKeyringFailed
	}
}
