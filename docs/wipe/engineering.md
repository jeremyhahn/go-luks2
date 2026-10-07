# Wipe — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
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
- A path that resolves to a different file at open time than at lock time
  (a symlink re-pointed in between) is refused before anything is written —
  the same claim-targets-the-locked-descriptor invariant as the rest of the
  write path ([volumes/architecture.md](../volumes/architecture.md#volume-target-and-activation)).
- Header-only wipe never touches at or past the start of the data segment.
- Full-device wipe syncs after the last pass, always, whether or not
  verification is requested.
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
| `ErrDeviceChanged` | The path named a different file at open time than at lock time |
| `wipe.ErrVerification` | A verification pass found a byte that did not match |
| `ErrLastKeyslot`, `ErrKeyslotAreaOverlap` | `RemoveKeyslot`'s removal guards ([keyslots](../keyslots/engineering.md#error-semantics)) |

## Persistence

A header-only wipe zeroes exactly the layout `header/architecture.md`
describes (both header copies, the keyslots area, every keyslot area the
header lists, and any other recognisable header copy at a legal offset). See
[header/architecture.md#layout](../header/architecture.md#layout) for the
byte ranges. There is no recovery from either wipe mode; a header backup
taken before a header-only wipe no longer opens the volume, because the
keyslot material it needs is gone.

## Test strategy

Covered by `pkg/luks2`'s unit suite against real temp files (pattern
sequencing, verification, the EXCL/retarget guards) and the cryptsetup
compatibility matrix's `wipe_keyslot*` row and
`TestHeaderOnlyWipeIsACryptoEraseOnTheMedium`
([cryptsetup-interop/engineering.md](../cryptsetup-interop/engineering.md)).
Full-device sanitize with `--trim`/verification needs a real block device and
is part of the integration tier.

## Observability

No logging. `Progress` is a caller-supplied callback, not a log or metric
emitted by the library itself.
