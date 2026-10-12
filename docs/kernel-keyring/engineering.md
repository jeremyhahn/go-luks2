# Kernel keyring — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8
> Conflicts with this document are defects. Fix them here first.

The implementation contract for the keyring path. Design and rejected
alternatives: [architecture.md](architecture.md).

## Exported surface

All in `pkg/dmcrypt` (`keyring.go`, `errors.go`).

| Name | Kind | Declared in |
|---|---|---|
| `CheckKeyring(ctx context.Context) error` | func | `pkg/dmcrypt/keyring.go` |
| `KeyringError` | struct `{Op string; Kind error; Err error}` | `pkg/dmcrypt/errors.go` |
| `(*KeyringError).Error() string` | method | `pkg/dmcrypt/errors.go` |
| `(*KeyringError).Unwrap() []error` | method | `pkg/dmcrypt/errors.go` |
| `(*KeyringError).Remedy() string` | method | `pkg/dmcrypt/errors.go` |
| `ErrKeyring`, `ErrKeyringUnavailable`, `ErrKeyringBlocked`, `ErrKeyringUnsupported`, `ErrKeyringQuotaExhausted`, `ErrKeyringFailed`, `ErrKeyringEntryExists`, `ErrKeyringKeyNotReleased` | `error` vars | `pkg/dmcrypt/errors.go`, each `= keyringpkg.Err…` |

The sentinels are declared in `internal/keyring/errors.go` (as `ErrKeyring`,
`ErrUnavailable`, `ErrBlocked`, `ErrUnsupported`, `ErrQuotaExhausted`,
`ErrFailed`, `ErrEntryExists`, `ErrKeyNotReleased`) and re-exported by value.
`pkg/luks2` does not re-export them; its error documentation points here.

`KeyringError` is a new type, not an alias of
`internal/keyring.UnavailableError`: a method cannot be added to an alias of a
foreign type, and `Remedy` is a method callers need. `Activate` and
`CheckKeyring` convert one into the other at the boundary
(`classifyKeyringErr`), so a caller branches on a type `pkg/dmcrypt` owns.

## Invariants

- **Fail closed.** If the key cannot be placed in the keyring, the operation is
  refused. There is no inline-key fallback and no degraded mode.
- **The key is borrowed, never copied.** The `[]byte` handed to `add_key` is a
  `WithBytes` window over the enclave. Raw-bytes boundaries are enumerated in
  [`internal/secret`'s package documentation](../../internal/secret/doc.go);
  this feature adds none.
- **One thread for add and release.** Both run in `RunOnDiscardedThread`: a
  goroutine locked to its OS thread that never unlocks, so the thread exits with
  it and any credentials installed by resolving the session keyring die with
  it. A panic inside is re-raised on the caller's goroutine.
- **Description.** `luks2:` followed by the SHA-256 of the dm UUID in hex.
  Key type is `logon`. The table reference is `:<size>:logon:<description>`,
  where size is the key length in bytes and the kernel checks it against the
  payload.
- **Collision guard.** Before the add, the ring is searched for the description.
  An existing entry returns `ErrKeyringEntryExists` and nothing is added.
- **Verified release.** `Release` revokes, unlinks, and searches again; the
  search must answer "not there". `ENOKEY`/`ENOENT` (already gone) and
  `EKEYREVOKED` (payload already freed) are success. Any other outcome returns
  `ErrKeyringKeyNotReleased`, with the `keyctl show` and `keyctl unlink`
  commands that remove the entry.
- **Release always completes.** It runs regardless of context cancellation: a
  key already in the kernel must not stay there because its caller was
  cancelled.
- **Cancellation.** `CheckKeyring` returns early with the context's error if
  the context is already done.
- **Idempotence.** `CheckKeyring` leaves nothing behind and may be called any
  number of times; its probe description is randomized per call.

## Error semantics

`KeyringError.Unwrap` returns `[ErrKeyring, ErrKeyringUnavailable, Kind, Err]`,
so `errors.Is` matches the root, the unavailability umbrella, the specific cause
and the underlying errno (`unix.EPERM`, `unix.EDQUOT`, `unix.ENOSYS`).

| Sentinel | Raised when | Matches `ErrKeyringUnavailable` | Matches `ErrKeyring` |
|---|---|---|---|
| `ErrKeyring` | Never raised alone. The root: every other sentinel matches it. The only safe catch-all. | no | yes |
| `ErrKeyringUnavailable` | Umbrella for every case where the key could not be placed. Always accompanies exactly one of the four causes below. | yes | yes |
| `ErrKeyringBlocked` | `EPERM` or `EACCES`: the syscalls are refused by policy, almost always a container seccomp profile. | yes | yes |
| `ErrKeyringUnsupported` | `ENOSYS`: the kernel was built without `CONFIG_KEYS`. | yes | yes |
| `ErrKeyringQuotaExhausted` | `EDQUOT` or `EKEYREJECTED`: the per-user key quota is full. | yes | yes |
| `ErrKeyringFailed` | Any other errno: the syscalls are reachable and the kernel refused anyway. | yes | yes |
| `ErrKeyringEntryExists` | An entry is already present under this mapping's description. An anomaly, refused and not resolved. | **no** | yes |
| `ErrKeyringKeyNotReleased` | The entry could not be confirmed gone after revoke and unlink. The key may still be in the kernel. | **no** | yes |

`ErrKeyringEntryExists` and `ErrKeyringKeyNotReleased` are not unavailability.
They surface as `*errs.Error` values, not as `*KeyringError`, so
`errors.As(err, &keyringErr)` does not match them; match the sentinel.

`Kind` on a `*KeyringError` is always one of the four causes
(`ErrKeyringBlocked`, `ErrKeyringUnsupported`, `ErrKeyringQuotaExhausted`,
`ErrKeyringFailed`).

### `Remedy`

`Remedy()` returns operator guidance chosen by `Kind`, and `Error()` appends
it: `could not <Op>: <errno>. <Remedy>`. `Op` names the step and never carries
key content.

| Kind | Guidance |
|---|---|
| `ErrKeyringBlocked` | A container seccomp profile. Docker's default denies `add_key`, `keyctl` and `request_key`, and adding `SYS_ADMIN` does not lift that. Allow those three in a narrow custom profile; prefer that to `seccomp=unconfined`. Under Kubernetes, a localhost seccomp profile. |
| `ErrKeyringUnsupported` | The kernel lacks `CONFIG_KEYS`. No runtime change helps, and there is no fallback. |
| `ErrKeyringQuotaExhausted` | Raise `/proc/sys/kernel/keys/maxkeys` and `maxbytes` (`root_maxkeys` and `root_maxbytes` for uid 0), or find the leak with `keyctl show`. The library releases every entry it creates. |
| anything else | The syscalls are reachable and the kernel refused; the reported cause is its answer. |

The Remedy text is the authority for operators; this table summarizes it.

### Fail-closed paths

When the add fails, no table is loaded and `Activate` removes the target it
created. A failed table load releases the entry. A release that cannot be confirmed is an error even
though the activation itself otherwise finished.

## Configuration

None in this library. The environment decides: the kernel's key quota
(`/proc/sys/kernel/keys/*`) and the process's seccomp policy.

## Persistence

None. Entries live in the kernel session keyring only for the duration of the
activation ioctl. Nothing is written to the volume or to disk.

## Test strategy

- **Unit, `pkg/dmcrypt/keyring_test.go`:** `CheckKeyring` leaves nothing
  behind, reports the same typed failure an `Activate` would, and catches a
  broken release path; `KeyringError` formats with the remedy and its
  `Is`/`Unwrap` match the sentinel family; `classifyKeyringErr` translates
  `UnavailableError`.
- **Unit, `pkg/dmcrypt/activate_test.go`:** the table carries a reference and no
  key; the keyring being unavailable fails closed; an existing entry is refused;
  the entry is released when the load fails; an unreleasable entry is reported;
  a cancelled context is honoured.
- **Fault injection:** `internal/keyring.Syscalls` is a value of five function
  fields (`SessionRing`, `Add`, `Search`, `Revoke`, `Unlink`) that tests
  substitute. A seccomp block, a release that does not take and a pre-existing
  entry cannot be produced for real, so they are injected here; `Live()` is the
  real implementation.
- **Integration:** `TestCheckKeyringPassesOnARealKernel`
  (`pkg/dmcrypt/activate_integration_test.go`), the keyring suite under
  `test/integration/keyring` and the activation tests under
  `test/integration/dmcrypt` run against a real kernel, in a container with `test/integration/seccomp.json` (Docker's default profile plus
  an allow block for the three syscalls). See
  [volumes/engineering.md](../volumes/engineering.md).

## Observability

None. The library does not log. Failures return typed errors; the caller
decides what to record.
