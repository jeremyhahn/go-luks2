# dm-crypt activation — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (f871541)
> Conflicts with this document are defects. Fix them here first.

Design and boundaries: [architecture.md](architecture.md).

## Exported surface

Every name below was checked against `go doc -all ./pkg/dmcrypt`.

```go
func Activate(ctx context.Context, v *luks2.Volume, key *luks2.Key, name string) (*Mapping, error)
func Deactivate(ctx context.Context, name string) error
func Lookup(ctx context.Context, name string) (*Mapping, error) // ErrNotActive
func CheckKeyring(ctx context.Context) error
func ValidateName(name string) error

const MaxNameLength = 127

type Mapping struct { Name, UUID string; Major, Minor uint32 }
func (m *Mapping) Path() string // "/dev/mapper/" + Name

type Error = errs.Error // alias of internal/errs.Error

type KeyringError struct { Op string; Kind, Err error }
func (e *KeyringError) Error() string
func (e *KeyringError) Remedy() string
func (e *KeyringError) Unwrap() []error
```

`Mapping` is obtained only from `Lookup` or a successful `Activate`. `Path`
does not re-verify against the kernel; `Lookup` is what confirms identity.

`KeyringError` is a type of this package rather than an alias of the internal
one, because `Remedy` is a method this package's callers need and a method
cannot be added to an alias of a foreign type. `Kind` is one of
`ErrKeyringBlocked`, `ErrKeyringUnsupported`, `ErrKeyringQuotaExhausted` or
`ErrKeyringFailed`. `Unwrap` reports the specific cause, the underlying errno,
and also `ErrKeyringUnavailable` and `ErrKeyring`, so a caller can branch on a
cause it can act on and fall back to either umbrella.

## Invariants

- Every entry point (`Activate`, `Deactivate`, `Lookup`, `CheckKeyring`)
  refuses a cancelled context first. `Activate`, `Deactivate` and `Lookup`
  then run `ValidateName`; an invalid name never reaches device-mapper.
- `Activate` never writes key bytes into the dm-crypt table, and never holds
  them in a plain `[]byte` or string. The key is borrowed from its enclave at
  the one call that must see it.
- `Activate` re-verifies the key against the header as it is now, every time.
  It does not trust a key that was verified at unlock.
- Once `Activate`'s create succeeds, the outcome is one of: a verified mapping
  is returned, or the target this call created is removed. The rollback never
  removes a target it did not create (matching dm UUID and device number).
- The rollback is not cancellable. A cancelled caller still gets it.
- The keyring entry is released before the key borrow closes, on every path
  including a panic. A failed release fails the activation, even when the load
  and resume succeeded, and the mapping is rolled back.
- `Deactivate` identifies the target before removing it and re-checks the
  identity before every attempt. If the name was removed or replaced during the
  wait, it returns nil without removing the replacement.
- `Deactivate` on a name with no target is `ErrNotActive`, not success.
  Removal itself is not idempotent.
- Two concurrent `Activate` calls for one name: the kernel's refusal of the
  second create is `ErrActive`, and the loser does not roll back (it created
  nothing).
- A dm UUID is `CRYPT-LUKS2-<header uuid, dashes removed>-<name>`, cut to 128
  bytes. It is cut once, at creation, because the kernel cuts it and every
  later identity check compares against the stored value.

## Name rules

`ValidateName` is one whitelist for four consumers: the fixed-width ioctl
field, the `/dev/mapper/<name>` path, the dm UUID, and the keyring description
derived from the UUID. A name is accepted if and only if all hold:

- non-empty and at most `MaxNameLength` (127) bytes, so the kernel's 128-byte
  `DM_NAME_LEN` is never silently truncated;
- not `.`, `..` or `control` (the device-mapper control node);
- starts with `A-Z a-z 0-9`;
- every byte is one of `A-Z a-z 0-9 _ . + -`.

Anything else is `ErrInvalidName`, with the offending byte or rule in the
detail.

## Error semantics

Every error is an `*Error` (`errs.Error`): `Op`, `Path`, a `Kind` sentinel
that is never nil, a `Detail` in words, and an optional typed `Err`. `Unwrap`
returns `{Kind, Err}`, so `errors.Is` matches either. Cancellation is the
`Kind`, so `errors.Is(err, context.DeadlineExceeded)` holds. Errors are
returned once, at the exported entry point; nothing is reclassified on the way
out.

| Sentinel | Returned when | Caller can |
|---|---|---|
| `ErrInvalidName` | `ValidateName` refuses the name | Fix the name |
| `ErrActive` | `Activate` found the name in use, or lost the create race | Pick another name, or `Lookup` and reuse |
| `ErrNotActive` | `Deactivate` or `Lookup` found no target under the name | Treat as already closed |
| `ErrBusy` | `Deactivate` could not remove a target something holds open, after the retry budget | Find and release the holder; `dmsetup remove --deferred` |
| `ErrStillLive` | `Activate` failed after its create and could not confirm the removal | Close the name with `Deactivate`; a plaintext mapping may exist |
| `ErrNodeUnverified` | No `/dev` node could be made or confirmed to name the new target | Treat as a failed activation (it was rolled back) |
| `ErrDeviceChanged` | The target was replaced or removed between create and load/resume | Retry the whole activation |
| `ErrPermissionDenied` | The process lacks the privilege for device-mapper or keyring access | Run as root |
| `ErrIntegerOverflow` | A negative size or offset reached a narrowing conversion | Treat as a corrupt descriptor |
| `ErrKeyring` | Root of every keyring failure | Branch only if no finer cause applies |
| `ErrKeyringUnavailable` | Umbrella: the keyring cannot hold the key | Call `Remedy()` on the `*KeyringError` |
| `ErrKeyringBlocked` | The keyring syscalls are refused by policy, almost always a container seccomp profile | Allow the keyring syscalls in the profile |
| `ErrKeyringUnsupported` | The kernel does not implement the keyring syscalls (built without `CONFIG_KEYS`) | Use a kernel that has them |
| `ErrKeyringQuotaExhausted` | The per-user key quota is full | Free keys or raise the quota |
| `ErrKeyringFailed` | The syscalls are reachable and the kernel refused anyway, for none of the reasons above | Read the wrapped errno |
| `ErrKeyringEntryExists` | A key was already present under the description about to be used: an anomaly, refused rather than resolved. Not under `ErrKeyringUnavailable` | Investigate the stale entry |
| `ErrKeyringKeyNotReleased` | An entry holding the volume key could not be revoked and unlinked, and may still be present. Not under `ErrKeyringUnavailable` | Activation is rolled back; investigate the keyring |

`Activate` also returns `luks2.ErrWrongKey` when the re-read header does not
verify the key, and the `pkg/luks2` errors from reading the header and
describing the target. They pass through unchanged.

When a rollback also fails, the returned error joins the cause with the
rollback's, so `errors.Is` matches both (for instance `ErrKeyringFailed` and
`ErrStillLive`).

Fail-closed paths: an unavailable keyring, a failed keyring release, an
unverifiable node, an inspection error during rollback (reported as
`ErrStillLive`, not as success), and an identity the caller cannot establish
before a `Deactivate` removal.

`ErrDeviceInUse`, `ErrDeviceCacheStale` and the other shared device kinds are
not raised by this package.

## Configuration

None. There are no options, environment variables or files. The retry budget
for a transient device-mapper hold is a constant of `internal/dm` (3 seconds,
20 ms initial delay, backing off).

## Persistence

None. The mapping lives in the kernel; the keyring entry lives from table load
to resume.

## Test strategy

- Unit tests drive `Activate`, `Deactivate` and `Lookup` through two seams in
  the package (`sys`): a fake device-mapper and a fake keyring. These cover the
  create race, the replaced-target cases, the rollback, the release failure and
  cancellation during rollback, without root.
- `errorshape_test.go` pins that `Error` is the module error shape and that
  the sentinels carry the package prefix.
- `activate_integration_test.go` runs against the real kernel and needs root.
  `make integration-test-dmcrypt` runs it in the devcontainer, and
  `make integration-test-cli` drives `luks2 open` and `luks2 close` end to
  end. A container needs the keyring seccomp profile.
- Fault injection never relies on permission bits (CI runs as root).

## Observability

None. This package does not log. Failures are typed errors; the detail text
names the target and the remedy.
