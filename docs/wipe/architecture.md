# Wipe — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (623da94)
> Conflicts with this document are defects. Fix them here first.

Destroying a volume, two ways: a crypto-erase that destroys only the header
copies and keyslots (fast, leaves ciphertext in place but unopenable), and a
full-device overwrite (slow, destroys the ciphertext itself). Keyslot-level
destruction (removing one credential without touching the others) is
[keyslots](../keyslots/architecture.md)'s contract, not this one's.

## The problem and the shape chosen

A crypto-erase is sufficient when the goal is "this device can no longer be
opened" — overwriting the data segment buys nothing once the keys that
protect it are gone. A full overwrite is for when the goal is "no bytes on
this medium should be recoverable", including by someone who already has
every header backup ever taken. The two are genuinely different operations
with different costs, so this library keeps them as two call sites
(`(*luks2.Volume).Erase` vs. `wipe.Sanitize`) rather than one call with a mode flag that
callers could set by habit.

## Rejected alternatives

- **One `Wipe` call with a header-only flag.** Rejected: no boolean
  arguments, and the crypto-erase needs the LUKS2 header and the volume's
  lock to decide what to zero, so it is `(*Volume).Erase` and the full
  overwrite is `wipe.Sanitize` (DESIGN.md §B.1, §B.6; DECISIONS.md, H10e).
- **A `Verify`/`NoVerify` boolean pair.** Rejected for the same rule: one
  three-valued `VerifyMode` (DESIGN.md §B.5).
- **A separate keyslot wipe.** Rejected: it is the same operation as
  `RemoveKeyslot`, which always destroys the area (DESIGN.md §B.6).
- **Whole-device destruction inside a single `host` package.** Rejected: it
  would mix the exec trust boundary with ioctl code and drag `exec` into every
  importer (DESIGN.md §A.4).
- **Taking the lock and claim through `pkg/luks2`.** Rejected: `pkg/luks2`
  imports `pkg/wipe`, so the reverse import would cycle; `Sanitize` uses
  `internal/device`'s lock-and-claim sequence directly (DECISIONS.md, H10e).
- **A dedicated `O_DIRECT` reader for verification.** Rejected: verification
  runs once per `Sanitize`, not on a hot path, so it reuses the already-tested
  `internal/device` read-past-cache primitive at the cost of more syscalls
  (DECISIONS.md, H10e).

## Component boundaries

`pkg/wipe` is its own public package (DESIGN.md §A.4): "LUKS-independent,
consumed directly by go-trusted-platform, with its own trust boundary
(whole-device destruction)." The header-only crypto-erase is
`(*luks2.Volume).Erase(ctx)` instead, since it needs the volume handle's
lock, not device-level sanitization:

```go
// pkg/luks2
func (v *Volume) Erase(ctx context.Context) error // header-only crypto-erase under the volume's exclusive lock

// pkg/wipe
type Pattern uint8
const (Zeros Pattern = iota; Ones; Random)
type Standard uint8
const (NoStandard Standard = iota; DoD3Pass; DoD7Pass; NIST)
func (s Standard) Patterns() []Pattern
type VerifyMode uint8
const (VerifyDefault VerifyMode = iota; VerifyAlways; VerifyNever)
type Params struct { Standard Standard; Patterns []Pattern; Verify VerifyMode; Discard bool; Progress func(Progress) }
func Sanitize(ctx context.Context, path string, p Params) error
```

`VerifyMode` is one three-valued field rather than a boolean pair (no boolean
arguments, DESIGN.md §B.1). Single-keyslot zeroing is
`(*Volume).RemoveKeyslot`, documented with
[keyslots](../keyslots/engineering.md#persistence).

## Data flow

**Header-only (default, crypto-erase).** Zeroes both header copies and the
whole keyslots area, plus every keyslot area the header lists, using the
geometry of a header copy whose checksum is valid. Any other header copy
found at a legal offset is zeroed too: its binary header and its JSON.
Nothing at or past the start of the data segment is touched. If no header
copy has a valid checksum, the keyslots area cannot be located: the first
32 KiB and every recognizable copy are zeroed, and a full wipe is the only
remaining option.

**Full device.** Overwrites the whole device, then syncs. A standard
(`nist`/`dod3`/`dod7`) is a fixed pattern sequence overriding passes/random;
verification reads the device back with `O_DIRECT`, past the page cache (for
a loop device, its backing file too), and compares every byte with the final
pass. `dod3` and `dod7` turn verification on by default.

Both modes open the device with `O_EXCL`: a mounted, mapped or otherwise held
device is refused before anything is written. The exclusive open reopens the
locked descriptor's own inode (its `/proc/self/fd` entry), never the path
again, so a symlink re-pointed after the lock cannot redirect the wipe to
another device.

## What this feature deliberately does not do

No partial-pattern recovery claims: a header-only wipe makes no promise about
the data segment's recoverability, and a full wipe with `--trim` makes no
promise beyond what `BLKDISCARD` guarantees on the underlying medium. There
is no undo for a full wipe.
