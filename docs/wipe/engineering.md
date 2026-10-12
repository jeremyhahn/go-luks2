# Wipe — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-12 against a9c840c
> Conflicts with this document are defects. Fix them here first.

## Exported surface

### `*Volume` and `pkg/wipe`

```go
func (v *Volume) Erase(ctx context.Context) error // header-only crypto-erase

// pkg/wipe
func Sanitize(ctx context.Context, path string, p Params) error
type Params struct { Standard Standard; Patterns []Pattern; Verify VerifyMode; Discard bool; Progress func(Progress) }
type Progress struct { Pass, Passes int; Written, Total int64; Pattern Pattern; Verifying bool }
func (p Pattern) String() string
func (s Standard) String() string
func (s Standard) Patterns() []Pattern
```

`Progress.Written`/`Total` give the completed fraction; `Standard.Patterns()`
returns a standard's pass sequence. Single-keyslot zeroing is `(*Volume).RemoveKeyslot(ctx, slot)`, documented in
[keyslots/engineering.md](../keyslots/engineering.md#persistence).

## Invariants

- The device is opened with `O_EXCL` for the whole operation; a device the
  kernel reports in use is refused before anything is written.
- The `O_EXCL` claim reopens the locked descriptor's own inode (its
  `/proc/self/fd` entry), never the path again, so a symlink re-pointed after
  the lock cannot redirect the wipe — the same
  claim-targets-the-locked-descriptor invariant as the rest of the write path ([volumes/architecture.md](../volumes/architecture.md#volume-target-and-activation)).
- Header-only wipe never touches at or past the start of the data segment.
- Full-device wipe syncs after every pass, the last included, whether or not
  verification is requested.
- Cancellation is observed every 1 MiB. Each write pass (`writePass`,
  `pkg/wipe/sanitize.go`) and the verification read (`verifyWrite`,
  `pkg/wipe/verify.go`) check `ctx` before every 1 MiB chunk. A cancelled
  `Sanitize` returns an error whose kind is the context's error, so
  `errors.Is(err, context.Canceled)` holds, and whose detail states how many
  bytes were written or verified. Bytes already written stay written.
- `pkg/wipe` has no package-level seam variables. `Sanitize` calls the
  unexported `sanitize` with a `sys` struct of filesystem, clock and
  lock-protocol seams built by `defaultSys`; the package's tests pass their
  own `sys`. `TestNoNewSeamVars` (`test/makefile`) fails on a new
  package-level func or interface variable.
- Removing a keyslot via `(*Volume).RemoveKeyslot` is guarded by the same
  last-keyslot and area-overlap checks as any other removal path
  ([keyslots/engineering.md](../keyslots/engineering.md#exported-surface)).

## Configuration

`wipe.Params{Standard, Patterns, Verify VerifyMode, Discard, Progress}`.
Header-only wipe is `(*Volume).Erase`; a full-device wipe is `Sanitize`.

| Field | Effect |
|---|---|
| `Patterns` | The pass sequence (`Zeros`, `Ones`, `Random`); empty is one `Zeros` pass |
| `Standard` | A fixed pattern sequence and default verification; overrides `Patterns` |
| `Verify` | `VerifyDefault` follows the standard; `VerifyAlways` reads the last pass back and compares it; `VerifyNever` skips that |
| `Discard` | Issue `BLKDISCARD` over the device afterwards |
| `Progress` | Called after every chunk written or read |

| Standard | Passes |
|---|---|
| `nist` | random |
| `dod3` | zeros, ones, random |
| `dod7` | zeros, ones, random, random, zeros, ones, random |

A random pass is AES-256-CTR under a fresh key, so it is checked like any
other during verification. If the device cannot be read past the page cache,
verification fails instead of reading the cache. A `Discard` the device
refuses, or a regular file, is ignored silently.

## Error semantics

| Error | Meaning |
|---|---|
| `ErrDeviceInUse` | The device is mounted, mapped, or otherwise held; refused before any write |
| `ErrDeviceChanged` | Declared by `pkg/wipe` for consistency with `luks2` and `dmcrypt`; never returned by a wipe, whose claim reopens the locked inode rather than the path |
| `ErrLockContended` | Another holder kept the device's lock for the whole wait budget (`LockTimeoutError`) |
| `wipe.ErrVerification` | A verification pass found a byte that did not match |
| `ErrLastKeyslot`, `ErrKeyslotAreaOverlap` | `RemoveKeyslot`'s removal guards ([keyslots](../keyslots/engineering.md#error-semantics)) |

## Persistence

A header-only wipe zeroes exactly the layout `header/architecture.md`
describes (both header copies, the keyslots area, every keyslot area the
header lists, and any other recognisable header copy at a legal offset). See
[header/architecture.md#layout](../header/architecture.md#layout) for the
byte ranges. Nothing on the device recovers from either wipe mode. A
header-only wipe leaves the data segment in place, so a header backup taken
before it that holds the keyslots area (`cryptsetup luksHeaderBackup` does)
opens the data again once restored; only a full wipe removes that route.

## Test strategy

Covered by `pkg/wipe`'s unit suite against real temp files (pattern
sequencing, verification, the `O_EXCL` claim), `pkg/luks2`'s (the header-only
wipe plan) and the cryptsetup compatibility matrix's `wipe_keyslot*` row and
header-only-wipe row, `TestHeaderOnlyWipeIsACryptoEraseOnTheMedium` in
`test/integration/device`
([cryptsetup-interop/engineering.md](../cryptsetup-interop/engineering.md)).
Full-device sanitize with `--trim`/verification needs a real block device and
is part of the integration tier.

## Observability

No logging. `Progress` is a caller-supplied callback, not a log or metric
emitted by the library itself.
