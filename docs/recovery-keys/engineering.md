# Recovery keys — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

## Exported surface

### `*Volume` (`pkg/luks2`)

```go
type RecoveryKeyFormat uint8
const (RecoveryDashed RecoveryKeyFormat = iota; RecoveryHex; RecoveryBase64)
func (f RecoveryKeyFormat) String() string
func ParseRecoveryKeyFormat(name string) (RecoveryKeyFormat, error)
const DefaultRecoveryKeyLength = 32
type RecoveryKey struct{ /* unexported */ }
type RecoveryKeyOption func(*recoveryOptions)
func WithRecoveryFormat(f RecoveryKeyFormat) RecoveryKeyOption
func WithRecoveryLength(n int) RecoveryKeyOption
func NewRecoveryKey(opts ...RecoveryKeyOption) (*RecoveryKey, error)
func (r *RecoveryKey) Format() RecoveryKeyFormat
func (r *RecoveryKey) Hash() string                       // SHA-256 of the text, hex
func (r *RecoveryKey) WriteTo(w io.Writer) (int64, error)  // the text; never a Go string
func (r *RecoveryKey) Destroy()
func ParseRecoveryKey(text *enclave.MemoryEnclave) (*enclave.MemoryEnclave, error)
func (v *Volume) AddRecoveryKey(ctx context.Context, key *Key, rk *RecoveryKey, p KeyslotParams) (Enrollment, error)
type Enrollment struct { Keyslot KeyslotInfo; Token int }
```

`WriteTo(io.Writer)` is the only way to get the text out: a credential never
becomes a Go string in this API (it cannot be wiped). `internal/cli`
(`recoveryfile.go`) does its own file reads/writes against `WriteTo`/
`ParseRecoveryKey`; the library itself has no file I/O in this path.

`make api-diff` holds this surface to DESIGN.md §B.6: the old generate, save,
load and verify free functions are not exported.

## Invariants

- The printed/written text, not the decoded bytes, is what the keyslot
  holds, so the same recovery key opens the volume through stock cryptsetup.
  `ParseRecoveryKey` only trims surrounding whitespace and refuses anything
  that is not one line; it does not decode, so a key enrolled before this was
  the case (its keyslot holds the decoded bytes) has no exported path.
- Two-phase enrollment: the caller shows or persists the key **before**
  `AddRecoveryKey` is called. If the CLI's `recovery add` cannot print the
  key (the write to standard output fails), the keyslot and token are removed
  again and the command fails; `--output` is written only after a successful
  print, so an unprinted key was never saved. If a removal fails, the message
  names the command that finishes it (`killslot` or `token remove`) (CLI
  behavior, [cli.md](cli.md)).
- A credential presented to `(*Volume).Unlock` is subject
  to the same untrusted-keyslot bounds as any other credential
  ([keyslots/architecture.md](../keyslots/architecture.md#untrusted-keyslots)).

## Generated credentials

Recovery keys are random bytes drawn by the library, so there is no offline
search for an iteration count to slow down. For keyslots written by
`AddRecoveryKey` the floor is 1000, which is what systemd writes (`pbkdf2`,
`sha512`, 1000). `WithRecoveryLength` is bounded below by 32 bytes (`ErrInvalidArgument`
otherwise). `Enroll` ([tokens/engineering.md](../tokens/engineering.md)) keeps
the full passphrase floor. The exemption is an unexported policy type; no
exported option selects it.

`--length` is the number of random bytes, default 32; zero means 32. It must
be at least 32 (256 bits), and the rendered key at most 512 characters. Keep
the default.

| `--format` | Example | Characters for 32 bytes |
|---|---|---|
| `dashed` (default) | `56D3DF-C65CED-…` (uppercase hex, groups of 6) | 74 |
| `hex` | `6920392130c6…` (lowercase) | 64 |
| `base64` | `nzosS4HeB8Wm…=` | 44 |

Any other format value, an empty one included, is a usage error (exit 1)
raised before the passphrase is read.

## Error semantics

| Error | Meaning |
|---|---|
| `ErrInvalidArgument` | Format name is not `dashed`/`hex`/`base64`, a length below 32 bytes or a rendering over 512 characters, or the recovery floor's own iteration count overflowed the shared ceiling (`*KDFCostError`; should not occur with library defaults); the original message is in `Detail` |
| `*OrphanedKeyslotError` (`ErrOrphanedKeyslot`) | The keyslot was added but the token write failed and the keyslot could not be removed again; names the slot to kill by hand |

A keyslot or token written as JSON `null` (from any source, not specific to
recovery keys) is dropped on read; see
[header/engineering.md](../header/engineering.md).

## Persistence

The recovery keyslot is an ordinary LUKS2 keyslot (schema:
[header/engineering.md](../header/engineering.md)); what is specific to a
recovery key is the `systemd-recovery` token naming its slot
([tokens/engineering.md](../tokens/engineering.md#token-types)) and the lower KDF
floor above. `--output` writes a file with mode 0400: comment lines with the
volume UUID, keyslot, token and checksum, then the key.

## Test strategy

Covered by `pkg/luks2`'s unit suite (generation, rendering, parsing, the
lower floor, the two-phase rollback on a token-write failure) and the
cryptsetup compatibility matrix's `recovery key*` rows and
`TestCLI_FIPSModeCreateAndRecoveryAddOpenWithCryptsetup`
([cryptsetup-interop/engineering.md](../cryptsetup-interop/engineering.md)).

## Observability

No logging. Neither the CLI nor the library reports a problem releasing a
recovery credential's enclave; the release outcome is dropped
([volumes/engineering.md](../volumes/engineering.md#key-custody-detail)).
