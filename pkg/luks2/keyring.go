// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"encoding/hex"
	"fmt"
	"os"

	keyringpkg "github.com/jeremyhahn/go-luks2/internal/keyring"
	"github.com/jeremyhahn/go-luks2/internal/secret"
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
// A logon key's payload is WRITE-ONLY from userspace (KEYCTL_READ returns
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
// The pinned thread is then THROWN AWAY rather than unpinned, because the same
// commit_creds that makes the pin necessary may have installed a session
// keyring on it alone; see internal/keyring.RunOnDiscardedThread.
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
//     internal/keyring.Description) and the ring is SEARCHED before anything is
//     added: an entry that is already there is an anomaly and fails the unlock
//     with ErrKeyringEntryExists.
//  2. A release that did not take. Trusting the revoke and unlink return values
//     would leave the volume key in the kernel keyring whenever the kernel said
//     one thing and did another. Release VERIFIES absence by searching again,
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
//
// The syscall mechanism, the keyring entry type and the add/release/classify
// logic live in internal/keyring (#265, H7); this file keeps the seam pkg/luks2
// tests substitute and the entry points that need the custody/FIPS seams
// internal/keyring cannot import.

// keyringKeyType and keyringDescriptionPrefix mirror internal/keyring's
// constants, kept under their original names so this package's own tests and
// messages do not have to spell out the qualified name.
const (
	keyringKeyType           = keyringpkg.KeyType
	keyringDescriptionPrefix = keyringpkg.DescriptionPrefix
)

// keyring is the live kernel keyring syscalls, a package-level value for the
// same reason dm is: every consumer wants the real kernel and only the tests
// want anything else.
var keyring = keyringpkg.Live()

// keyringVolumeKey is a live keyring entry holding a volume key, and the
// dm-crypt reference that names it. It wraps internal/keyring.VolumeKey so
// this package's existing method names (release, tableKeyID) and callers need
// no change.
type keyringVolumeKey struct {
	keyringpkg.VolumeKey
}

// tableKeyID returns the dm-crypt key_string for this entry -- the value that
// goes in CryptTable.KeyID instead of the key itself.
func (k *keyringVolumeKey) tableKeyID() string {
	return k.TableKeyID()
}

// release revokes the entry, unlinks it, and then VERIFIES that it is gone.
// See internal/keyring.VolumeKey.Release.
func (k *keyringVolumeKey) release() error {
	return k.Release(keyring)
}

// addVolumeKeyToKeyring places key in the kernel keyring under a description
// that identifies this volume and mapping, and returns the handle that names
// it. See internal/keyring.AddVolumeKey.
//
// key is a slice BORROWED from an enclave for the duration of this call. It is
// handed to add_key and to nothing else: no copy, no staging buffer, no
// string. The caller must release the returned entry.
func addVolumeKeyToKeyring(dmUUID string, key []byte) (*keyringVolumeKey, error) {
	vk, err := keyringpkg.AddVolumeKey(keyring, dmUUID, key)
	if err != nil {
		return nil, err
	}
	return &keyringVolumeKey{VolumeKey: *vk}, nil
}

// keyringDescription builds the key description for a mapping. See
// internal/keyring.Description.
func keyringDescription(dmUUID string) string {
	return keyringpkg.Description(dmUUID)
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
	nonce, err := randomBytes(8)
	if err != nil {
		return keyringFailure("draw randomness for the keyring preflight", err)
	}
	probe := fmt.Sprintf("preflight-%d-%s", os.Getpid(), hex.EncodeToString(nonce))

	// A throwaway value of the length a LUKS2 aes-xts-plain64 volume key has,
	// so the preflight also exercises the size the real path uses against any
	// payload-length limit the kernel imposes.
	material, err := custody.Random("keyring preflight", 64, cryptoRand)
	if err != nil {
		return err
	}
	defer custody.Release(material)

	// On a discarded thread for the same reason unlockLoadTable is: the ring
	// belongs to the task, so the add and the release have to happen on the
	// same one, and resolving the ring may change that thread's credentials.
	return runOnDiscardedThread(func() error {
		var entry *keyringVolumeKey
		if err := secret.Borrow("keyring preflight", material, func(b []byte) error {
			var addErr error
			entry, addErr = addVolumeKeyToKeyring(probe, b)
			return addErr
		}); err != nil {
			return err
		}
		return entry.release()
	})
}

// pinToOSThread pins the calling goroutine to the OS thread it is running on
// and returns the function that releases it. Lock/Unlock nest by count, so a
// caller that has already pinned stays pinned.
//
// The library's own keyring sequences do NOT use it any more; they run on
// runOnDiscardedThread, because releasing the pin hands a thread whose
// credentials the sequence may have changed back to the scheduler. Only the
// tests use it, to search a ring that already exists.
func pinToOSThread() func() {
	return keyringpkg.PinOSThread()
}

// runOnDiscardedThread runs fn on a new goroutine locked to its OS thread, and
// lets that thread EXIT with the goroutine instead of returning it to the
// scheduler. See internal/keyring.RunOnDiscardedThread.
func runOnDiscardedThread(fn func() error) error {
	return keyringpkg.RunOnDiscardedThread(fn)
}

// keyringFailure classifies an errno from a keyring syscall and attaches the
// remedy for that specific cause. See internal/keyring.Failure.
func keyringFailure(op string, err error) error {
	return keyringpkg.Failure(op, err)
}
