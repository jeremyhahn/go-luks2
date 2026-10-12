# dm-crypt activation — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (f871541)
> Conflicts with this document are defects. Fix them here first.

Activation turns an unlocked volume key into a plaintext block device,
`/dev/mapper/<name>`, by creating a dm-crypt target in device-mapper. It is
`pkg/dmcrypt`, and it is the only package in this module that does it.

## The problem and the shape chosen

Opening a LUKS2 volume has two halves. The first, reading the header and
turning a credential into the volume key, needs no privilege and no
subprocess. The second, loading a key into the kernel and creating a mapping,
needs root, the kernel keyring and device-mapper ioctls.

The two are separate packages so that `pkg/luks2` stays rootless and
exec-free (DESIGN.md §A.4): `pkg/luks2` derives the key and describes the
target (`(*luks2.Volume).Target`), and `pkg/dmcrypt` consumes that
description. A consumer that only inspects, edits or tests volumes never
links the privileged half.

Rejected alternatives:

- **One package that does both.** It would make every header edit a
  root-capable operation to audit, and would put the keyring and ioctl code
  where the pure-Go header code lives.
- **Shelling out to `cryptsetup open`.** The library must interface correctly
  with the cryptsetup tools, not depend on them at run time; a subprocess also
  puts the key on a command line or pipe outside protected memory.
- **Putting the key in the dm-crypt table.** The table is a string the kernel
  and device-mapper tooling echo back (`dmsetup table --showkeys`). See the
  trust boundary below.

## Component boundaries

| Package | Role |
|---|---|
| `pkg/dmcrypt` | The public surface: `Activate`, `Deactivate`, `Lookup`, `CheckKeyring`, `ValidateName`, `Mapping`, the error sentinels and `KeyringError` |
| `pkg/luks2` | Supplies `*Volume` and `*Key`; `(*Volume).Target` re-reads the header and re-verifies the key |
| `internal/keyring` | The kernel-keyring calls (`add_key`, revoke, unlink, verify gone) and their error classification; `pkg/luks2` cannot import it |
| `internal/dm` | The device-mapper ioctl layer: create, load, resume, remove, info, with the retry budget for a transient hold |
| `internal/secret`, `internal/volkey` | Protected-memory custody of the key; `volkey.Borrow` is the one window at which raw bytes are visible to this package |

`pkg/dmcrypt` imports `pkg/luks2`, never the reverse. Its error sentinels for
the keyring and for shared device conditions are re-exported by value from the
internal packages that own them, so `errors.Is` holds whichever package's name
a caller matches.

The CLI reaches the package through a small activator seam
(`internal/cli`), so `luks2 open` and `luks2 close` exercise the same calls a
library consumer makes. See [cli.md](cli.md).

## Data flow

`Activate(ctx, v, key, name)`:

1. Refuse a cancelled context and an invalid name (`ValidateName`).
2. Look the name up in device-mapper. If it is in use, fail with
   `ErrActive` before any key material is touched. This check is a cheap early
   refusal, not the guard: the check and the create are not atomic, and the
   create is what the kernel refuses for a taken name.
3. Call `(*luks2.Volume).Target`. It re-reads the header under the volume's
   shared lock, re-verifies the key against the header digest for the mapped
   segment, and returns the backing device's major:minor, the data offset and
   length, the cipher, IV offset, sector size and flags. A key the re-read
   header does not verify is `luks2.ErrWrongKey`.
4. Build the dm UUID `CRYPT-LUKS2-<header uuid without dashes>-<name>`,
   cryptsetup's form, cut to the 128 bytes the kernel stores.
5. Create the device-mapper device. From the moment this succeeds the mapping
   is a transaction.
6. Borrow the key from its enclave. Add it to the session keyring as a `logon`
   key, build the table that names it by reference, then release the entry
   when the borrow closes.
7. Load the table and resume, confirming before each step that the name still
   names the target this call created (same dm UUID, same device number).
8. Make the `/dev/dm-N` node exist and wait until `/dev/mapper/<name>` is
   verifiably this device (`ErrNodeUnverified` otherwise).
9. Return a `Mapping`.

Every failure after step 5 rolls the target back, under
`context.WithoutCancel(ctx)` and its own time budget, so a cancelled caller
never leaves a plaintext device behind. The rollback removes only a target
whose dm UUID and device number match the ones this call created; anything
else under that name belongs to someone else and is left alone. If the
rollback cannot confirm the removal, the error is `ErrStillLive` and names the
`Deactivate` call that closes it.

`Deactivate(ctx, name)` establishes the target's identity from device-mapper
first, then removes it, re-confirming the identity before every attempt. It
retries a busy target for a fixed budget (a udev rule can hold a device
briefly) and then fails with `ErrBusy`. It touches no keyring state: the entry
is already gone by the time a mapping exists.

`Lookup(ctx, name)` reads device-mapper and returns a `Mapping` or
`ErrNotActive`.

Nothing is persisted by this package. The mapping lives in the kernel until
`Deactivate` or a reboot; the key entry lives in the kernel keyring only for
the duration of the load and resume.

## The dm-crypt table

The table is a single crypt target, built from `luks2.Target`:

| Field | Source |
|---|---|
| start | 0 |
| length | the segment length in bytes, rounded down to a sector multiple (dm-crypt refuses a length that is not one) |
| cipher | the segment's encryption string from the header |
| key | a keyring reference, never key bytes |
| IV offset | the segment's IV tweak |
| backend device | `<major>:<minor>` of the pinned descriptor, never a path |
| backend offset | the segment's data offset |
| flags | the header's activation flags |
| sector size | the segment's sector size; zero or negative is refused |

The backing device is addressed by major:minor taken from the descriptor
`Target` pinned, never by a path, so a path swapped between unlock and
activation cannot redirect the mapping.

## Trust boundary: the kernel-keyring handoff

The volume key lives in go-enclave protected memory for its whole lifetime
(see the project rule and the canonical list of raw-bytes boundaries in the
package documentation of `internal/secret`). The handoff to dm-crypt is the
one place the key leaves this process, and it is by reference:

- The key goes from its enclave into the kernel through `add_key`, borrowed
  through `volkey.Borrow` for that one call. No userspace string holds it.
- The table carries only the keyring reference. This package never sets the
  device-mapper library's inline `Key` field, so the hex encoding of the key
  is structurally unreachable, not merely unused.
- There is no fallback. If the keyring cannot hold the key, activation fails
  with an error matching `ErrKeyringUnavailable`. It never degrades to an
  inline key.
- The entry is a `logon` key in the session keyring. Its payload is
  write-only: no process, root included, can read the bytes back. It exists
  from the load to the resume, then is revoked, unlinked and verified gone. If
  that cannot be confirmed, the activation fails with
  `ErrKeyringKeyNotReleased` and rolls the mapping back, because a custody
  failure is not hidden by a successful open.
- The keyring is not namespaced by container. A neighbour sharing both uid and
  session keyring can see that the entry exists and use it by reference during
  that window; it cannot learn the key. The residual exposure is enumerated in
  the package documentation of `internal/secret`, which is canonical; this
  document does not restate it.

The keyring call runs on a goroutine locked to an OS thread that is discarded
afterwards, because the ring belongs to the task and resolving it can change
that thread's credentials.

## What this feature deliberately does not do

- No LUKS header parsing, keyslot or credential handling: that is
  [volumes](../volumes/architecture.md) and [keyslots](../keyslots/architecture.md).
- No loop devices, filesystems or mounting.
- No inline-key fallback, and no activation without root.
- No multi-segment layouts: `Target` maps the one segment the header
  describes.
- No dm-integrity, and no online reencryption.
- No logging. Failures are typed errors returned to the caller.

The same kernel-keyring behaviour is described from the volume side in
[volumes/architecture.md](../volumes/architecture.md#kernel-keyring).
