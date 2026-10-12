# Header — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-12 against base/331 (a9c840c)
> Conflicts with this document are defects. Fix them here first.

## Exported surface

### `*Volume`/`*Header` (`pkg/luks2`)

```go
type Header struct{ /* unexported */ }
func (v *Volume) Header(ctx context.Context) (*Header, error)
func (v *Volume) SecondaryHeader(ctx context.Context) (*Header, error)
func (v *Volume) RestorePrimaryHeader(ctx context.Context) error
func (v *Volume) ReplacePrimaryHeader(ctx context.Context) error // unconditional
func (h *Header) UUID() string
func (h *Header) Label() string
func (h *Header) Subsystem() string
func (h *Header) SequenceID() uint64
func (h *Header) Size() int64
func (h *Header) Offset() int64 // 0 for the primary copy, the header area size for the secondary
func (h *Header) Keyslots() []KeyslotInfo
func (h *Header) Segments() []Segment
func (h *Header) Tokens() map[int]Token
func (h *Header) Requirements() []string
func (h *Header) Dropped() []DroppedEntry
func (h *Header) MarshalJSON() ([]byte, error)
type Segment struct { ID int; Type string; Offset, Size int64; Encryption string; SectorSize int; IVTweak uint64 }
const SizeDynamic int64 = -1
type DroppedEntry struct{ Kind, ID string }
func (e DroppedEntry) String() string
```

`(*Volume).Header(ctx)` returns the current copy (the primary, or the
secondary when the primary is damaged or older), `ErrNotLUKS2` when the
device is LUKS1 and `ErrInvalidHeader` when neither copy is a valid header;
the accessors above are the header summary. The on-disk model and codec
this is built on, `internal/header`, is unchanged by this layer
([architecture.md](architecture.md#component-boundaries)).

No free function reads or writes a header by device path. `make api-diff`
holds this surface to its disposition baseline
(`test/tools/apidump/baseline/disposition-luks2.tsv`), where the path-taking
`ReadHeader`, `ReadSecondaryHeader` and `RestorePrimaryHeader` are renamed to
the `*Volume` methods above and `WriteHeader`/`CreateBinaryHeader` are
unexported into `internal/header`.

## Invariants

- A header write syncs the primary, then writes and syncs the
  secondary, so a crash tears at most one copy. `sequence_id` advances on
  every keyslot or token change.
- Every write applies the full structural validator first, so this library
  never writes a header cryptsetup would refuse. `RestorePrimaryHeader` is
  the one exception, applying only the header-wide rules.
- `(*Volume).SecondaryHeader`/`RestorePrimaryHeader` never read or derive
  against the data segment; the import/migration code that shares this
  invariant is [fips/engineering.md](../fips/engineering.md).
- Unknown JSON members round-trip exactly (byte-identical values, including
  non-canonical number spellings) through every nested object in every
  rewrite; see [architecture.md](architecture.md#encoding).

## Error semantics

| Error | Meaning |
|---|---|
| `ErrInvalidHeader` | A rule about the header as a whole failed (magic, checksum, structure, a member named twice) |
| `ErrInvalidArgument` | `FormatParams.MetadataSize` is not a power of two from 16 KiB to 4 MiB |
| `ErrNotLUKS2` | The device is LUKS1, not LUKS2 |
| `ErrUnsupported` | The checksum algorithm field names anything but `sha256`; on unlock, more than one segment or a segment with an `integrity` member |
| `ErrUnsupportedRequirement` | A write or unlock met a mandatory requirement this library does not implement |
| `ErrPrimaryHeaderCurrent` | `RestorePrimaryHeader` would roll the volume back; use `ReplacePrimaryHeader` deliberately |
| `ErrDeviceChanged` | An in-use claim's re-opened path no longer names the locked file |
| `LockTimeoutError` | The device's lock was held in a conflicting mode (a writer against a read, or anyone against a write) for the lock wait, `DefaultLockWait` unless `WithLockWait` sets another |

`ErrInvalidHeader`, `ErrInvalidArgument`, `ErrInvalidCredential` and `ErrIO`
are module-wide kinds (`internal/errs`, re-exported by value), and
`ErrUnsupported` is `internal/device`'s, re-exported the same way. The
specific sentinels that were folded into them are listed in
[volumes/engineering.md](../volumes/engineering.md#error-semantics).

## Configuration

`FormatParams.MetadataSize` is the only header-shape knob: 16 KiB to 4 MiB,
power of two. Everything else about the binary/JSON layout is fixed by the
specification and not configurable.

## Persistence

This file *is* the persistence contract: layout, binary header fields, JSON
object shapes and the encoding rules in
[architecture.md](architecture.md#layout) through
[architecture.md](architecture.md#encoding). There is no separate migration
rule beyond "a header this library writes must open in cryptsetup and the
reverse" ([cryptsetup-interop](../cryptsetup-interop/engineering.md)).

## Test strategy

`internal/header` has its own unit suite (structural validator table, JSON
passthrough/unknown-members, requirements, canonical JSON; `validation_test.go`,
`unknownfields_test.go`, `requirements_test.go`, `canonicaljson_test.go`),
with a 90% floor
(`coverage-floors.txt`). Device-level and cryptsetup-conformance tests
(`TestCanonicalJSONReencodesCryptsetupsHeaderByteForByte`,
`TestFormattedBinaryHeaderMatchesCryptsetup`) live in `pkg/luks2`, and are also exercised by the compatibility matrix's `format*` and
`header*` rows
([cryptsetup-interop/engineering.md](../cryptsetup-interop/engineering.md)).

## Observability

No logging; every failure above is a typed, returned error.
