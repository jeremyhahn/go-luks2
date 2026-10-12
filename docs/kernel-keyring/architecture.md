# Kernel keyring — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8
> Conflicts with this document are defects. Fix them here first.

How a LUKS2 volume key gets from locked memory into dm-crypt without ever
appearing in the device-mapper table, what the startup preflight proves, and
why a keyring that cannot hold the key fails the operation instead of degrading.

Related: [dm-crypt-activation](../dm-crypt-activation/architecture.md) covers
the rest of activation (the dm target, the table, rollback);
[volumes](../volumes/architecture.md#kernel-keyring) summarizes this feature
inside the volume lifecycle.

## The problem and the shape chosen

dm-crypt accepts its volume key in one of two forms in the table it is loaded
with: inline, as hex, or as a reference to a key held in the calling task's
kernel keyrings. An inline key travels through user-space buffers the library
cannot wipe, through the device-mapper ioctl, and into table dumps
(`dmsetup table --showkeys`). A reference travels as a short description and
the kernel reads the payload itself.

go-luks2 uses only the reference form, as cryptsetup does. The table carries
`:<size>:logon:luks2:<sha256 of the dm UUID>` and never the key.

The flow for one activation:

1. **Create the dm target** (named, with no table yet). If a later step
   fails, `Activate` rolls it back; see
   [dm-crypt-activation](../dm-crypt-activation/architecture.md).
2. **Resolve the session keyring** of the calling task, creating one if the
   task has none.
3. **Refuse if an entry already exists** under the description this mapping
   would use (`ErrKeyringEntryExists`).
4. **`add_key`** the volume key as a `logon` key. The payload is borrowed from
   its locked-memory enclave for exactly this call and handed to the syscall
   with no copy. A `logon` key's payload cannot be read back from user space.
5. **Load the table** naming that key.
6. **Revoke, unlink, and search again.** The entry is released before the
   activation step returns, on every path including a failed load, and the release is
   verified: a successful unlink is not accepted as proof the key is gone. If
   the kernel still resolves the entry, activation fails with
   `ErrKeyringKeyNotReleased` and the error names the `keyctl` commands that
   remove it.

The whole sequence runs on a goroutine locked to an OS thread that is allowed
to exit afterwards. Keyrings belong to the task, and resolving the session
keyring can install new credentials on the calling thread; returning such a
thread to the Go scheduler would leak that keyring to whatever goroutine ran
there next.

### Rejected alternatives

- **Fall back to an inline key when the keyring is unavailable.** Rejected: the
  fallback puts the master key in memory the library cannot
  wipe, for an unbounded time, and a caller that got a successful return would
  believe a guarantee that did not hold. Unavailability is fatal.
- **A `user` key instead of `logon`.** Rejected: any possessor of a `user`
  key can read the payload back. A `logon` key is write-only from user space.
- **The dm UUID as the key description.** Rejected: the description sits inside
  one space-delimited token of the table, and the UUID is built from a header
  field and a caller-chosen name whose character set this library does not
  control. Hashing makes the description 64 hex characters whatever the input,
  by construction rather than by validation, and stays deterministic, which the
  pre-add collision check depends on.
- **Overwrite or adopt an existing entry.** `add_key` would update it in
  place. Either would be silent, so the operation fails instead.
- **A preflight that only checks the syscall number exists.** Rejected: the
  failure that matters is a policy block (a container seccomp profile), which a
  presence check cannot see. The preflight runs the real add and release.

## The preflight

`CheckKeyring` exists because the usual cause of unavailability, a container
started without the keyring syscalls, is fixed at boot. Discovering it at the
first activation turns a configuration error into an outage. A long-lived
consumer calls it at startup, refuses to come up on error, and the error names
the syscalls and the remedy.

It adds and releases a throwaway 64-byte key (the size of an `aes-xts-plain64`
volume key) under a randomized description, so it neither collides with a
real volume's entry nor fails because an earlier probe left one behind. The
probe is generated inside a locked-memory enclave, so it never exists in an
ordinary Go buffer. It exercises the same syscalls, key type, ring resolution
and release path as an activation, so a kernel that can add but not revoke is
caught at startup rather than at teardown.

A nil return is a promise that the syscalls are reachable, not that a later
activation will succeed: the quota can fill in between.

## Component boundaries

| Path | Role |
|---|---|
| `internal/keyring` | Owns the sentinels, `Classify`, `Remedy`, the `logon` key add, the verified release, the description digest and the discarded-thread runner. A leaf package. |
| `pkg/dmcrypt` | Re-exports the sentinels by value, owns the public `KeyringError`, and exposes `CheckKeyring`. Calls `internal/keyring` from `Activate`. |
| `pkg/luks2` | Cannot import `internal/keyring`. `Unlock` derives and verifies the key and never touches the keyring. |

The sentinels live below `pkg/dmcrypt` because the keyring package sits below
it and below `pkg/keyprovider`. `pkg/dmcrypt` re-exports them by value, so
`errors.Is` holds whichever package's name a caller matches against.

## Trust boundaries

- The key leaves locked memory at exactly one point: the `add_key` syscall.
  The kernel keyring entry that hands the key to dm-crypt is one of the
  enumerated raw-bytes boundaries in the package documentation of
  [`internal/secret`](../../internal/secret/doc.go), which is the canonical
  list; [volumes/engineering.md](../volumes/engineering.md#key-custody-detail)
  summarizes it. This document adds nothing to that list.
- Keyrings are not namespaced by container, so a container needs a seccomp
  profile that allows the three keyring syscalls. The `logon` type keeps the
  payload unreadable from user space.
- The entry lives only for the duration of the activation ioctl.
- Error text carries the step that failed and the errno, never key content.

## What this feature does not do

- It does not keep the key in the keyring for the life of the mapping; dm-crypt
  has its own copy once the table is loaded.
- It does not fall back to an inline key under any condition.
- It does not clean up entries it did not create, and it does not adopt them.
  A leftover from a crashed process is removed by the operator with `keyctl`.
- It does not change the host's key quota or seccomp policy; it reports the
  remedy.
