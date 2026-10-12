# Header — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163);
> "Rejected alternatives" and "What this feature deliberately does not do"
> verified 2026-10-11 against main (623da94)
> Conflicts with this document are defects. Fix them here first.

A LUKS2 header is two copies of a 4096-byte binary header plus a JSON area,
followed by the keyslots area and the data segment. This folder covers the
on-disk layout, the binary/JSON codec, and how a header that was not written
by this library (or that is damaged, or hostile) is still read safely.
Keyslot and token *content* inside the JSON is documented where the
credential is: [keyslots](../keyslots/architecture.md),
[tokens](../tokens/architecture.md).

## The problem and the shape chosen

The on-disk format is cryptsetup's, unchanged: a header go-luks2 writes must
open in cryptsetup and the reverse, and breaking that is a defect, not a
design choice to revisit
([cryptsetup-interop/engineering.md](../cryptsetup-interop/engineering.md)).
The one place this library's judgment differs from cryptsetup's is how much
it trusts the header before spending CPU and locked memory on it — see
"Untrusted headers", below, which is a deliberate, documented divergence, not
an accident of a stricter parser.

## Rejected alternatives

- **Requiring a valid header to open a volume.** Rejected: `Open` pins the
  descriptor and nothing else, because `RestorePrimaryHeader` and `Erase` must
  work on a damaged header (DESIGN.md §B.1).
- **A force flag on the primary-header restore.** Rejected: no boolean
  arguments, so the unconditional restore is its own method,
  `ReplacePrimaryHeader` (DESIGN.md §B.1, §B.6).
- **Indented JSON, and Go's default HTML escaping.** Rejected: the JSON area
  cannot grow after format, and indented output filled it at far fewer
  keyslots than cryptsetup's compact json-c output does; json-c does not
  escape `<`, `>` or `&` (commit 3082e41, "canonical JSON, calibrated digest,
  and cost rules that match cryptsetup").
- **A fixed digest iteration count.** Rejected: cryptsetup calibrates the
  digest to a time target, and a hardcoded count does not. A proposal to
  hardcode 1000 rested on a measurement taken with
  `--pbkdf-force-iterations`, which pins the digest as well as the keyslot;
  it was reverted (same commit).
- **Zero-filling the unused keyslots area at format.** Rejected: zeros
  disclose which slots are in use and which were destroyed, so `Format`
  fills it with random bytes (same commit).
- **Exporting internals across the `internal/header` boundary for small
  helpers.** Rejected: duplicating a helper of a few lines is cheaper and less
  coupled than exporting `pkg/luks2` internals or threading parameters
  through the call chain (DECISIONS.md, H5).

## Component boundaries

The on-disk model, JSON codec, structural validator, checksum/binary-header
codec and keyslot scan order live in `internal/header` (H5, DECISIONS.md).
`pkg/luks2` does not re-export that model: its `Header`, `Segment`, `Token`
and `KeyslotInfo` are its own types built from it, and `DroppedEntry` and
`LegacyToken` are the only aliases of `internal/header`'s. `internal/header`
sits above `internal/kdf` and `internal/fips` in the import DAG (it may import
them) and must not import `pkg/luks2` (DESIGN.md §A.2); a handful of small pure helpers
(`parseSize`, the overflow conversions, the segment/digest/keyslot-coverage
helpers) are duplicated rather than threaded across that boundary — each is a
few lines, and duplicating them is cheaper than exporting `pkg/luks2`
internals or exporting `internal/header` internals the other way (DECISIONS.md
H5).

`pkg/luks2`'s public read model is a `*Header` type returned from
`(*Volume).Header(ctx)`/`SecondaryHeader(ctx)`, backed by the same
`internal/header` model, with `Keyslots()`, `Segments()`, `Tokens()`,
`Requirements()`, `Dropped()` and `MarshalJSON()` accessors. No free function
reads or writes a header by device path.

## Data flow

- `(*Volume).Header` reads each copy's area once and checks magic, version,
  area size, checksum and the JSON, then cryptsetup's structural rules, and
  returns the current copy: the one with the higher sequence ID, the primary
  at a tie, the other copy when one fails those checks. Every write runs the full structural validator first, except
  `RestorePrimaryHeader`, which copies an existing secondary and applies only
  the header-wide rules.
- Keyslots are screened one at a time before use: geometry, key size and KDF
  cost are bounded before any derivation or allocation, and one bad keyslot
  does not block the others (see "Untrusted headers", below).
- A header write encodes canonical JSON, writes and syncs the primary, then
  writes and syncs the secondary, so a crash tears at most one copy. Keyslot
  and token changes advance `sequence_id`.
- Members the structs do not model survive a read-modify-write in every
  nested metadata object; see "Encoding", below, for the limits.
- Every operation that writes the container takes an exclusive `flock` on the
  device, waiting up to 30 s (`DefaultLockWait`) before `LockTimeoutError`
  ([volumes/architecture.md](../volumes/architecture.md#volume-target-and-activation) covers the
  lock order itself; this is the header-write side of it). Its reads and
  writes go through the descriptor it locked, or through an `O_EXCL`
  descriptor proven to be the same file: the path is opened again only for
  that in-use claim, and the open is refused with `ErrDeviceChanged` unless
  its device, inode and rdev match the locked one.

## Layout

`area` is the size of one header copy (binary header plus JSON). It is 16 KiB
by default, leaving 12288 bytes of JSON.

| Region | Offset | Size |
|---|---|---|
| Primary header and JSON | `0` | `area` |
| Secondary header and JSON | `area` | `area` |
| Keyslots area | `2 × area` | `16 MiB − 2 × area` |
| Data segment | `16 MiB` | rest of the device |

`FormatParams.MetadataSize` sets `area` to a power of two from 16 KiB to
4 MiB, as cryptsetup's `--luks2-metadata-size` does; other values fail with
`ErrInvalidArgument`. It cannot change after format. Containers
cryptsetup wrote with any legal size are read from their headers.

`Format` fills the unused keyslots area with random bytes, so the first 16 MiB
of a new container is allocated and does not show which slots were ever used.
The data area is left as it was.

## Binary header

Integers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0x000 | 6 | Magic: `LUKS\xba\xbe` (primary), `SKUL\xba\xbe` (secondary) |
| 0x006 | 2 | Version, `2` |
| 0x008 | 8 | Header size (`area`) |
| 0x010 | 8 | Sequence ID |
| 0x018 | 48 | Label |
| 0x048 | 32 | Checksum algorithm, e.g. `sha256` |
| 0x068 | 64 | Salt |
| 0x0A8 | 40 | UUID |
| 0x0D0 | 48 | Subsystem label |
| 0x100 | 8 | Header offset (0 or `area`) |
| 0x108 | 184 | Padding |
| 0x1C0 | 64 | Checksum |
| 0x200 | 3584 | Padding |

The checksum covers the binary header (checksum field zeroed) followed by the
whole JSON area. This library writes `sha256` in the algorithm field, as
cryptsetup does, and refuses a header naming any other algorithm
(`ErrUnsupported`). cryptsetup verifies with whatever hash the
field names, so a header re-checksummed with `sha1` or `sha512` opens there and
not here. The two copies differ in magic and header offset.

The specification has `sequence_id` increase on each update and readers prefer
the copy with the higher value. This library writes 1 on format and advances it
on keyslot and token changes. `(*Volume).Header` follows that rule (the primary
at a tie); `SecondaryHeader` reads the secondary alone, and the CLI's
`header show` and `header secondary` print each copy's sequence ID.
cryptsetup writes 3 on format because it does three header writes.

## JSON metadata

Pretty-printed here; values are illustrative.

```json
{
  "keyslots": {
    "0": {
      "type": "luks2",
      "key_size": 64,
      "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
      "area": { "type": "raw", "offset": "32768", "size": "258048",
                "encryption": "aes-xts-plain64", "key_size": 64 },
      "kdf": { "type": "argon2id", "salt": "...", "time": 4,
               "memory": 1048576, "cpus": 4 }
    }
  },
  "tokens": {},
  "segments": {
    "0": { "type": "crypt", "offset": "16777216", "size": "dynamic",
           "iv_tweak": "0", "encryption": "aes-xts-plain64", "sector_size": 512 }
  },
  "digests": {
    "0": { "type": "pbkdf2", "keyslots": ["0"], "segments": ["0"],
           "hash": "sha256", "iterations": 500000, "salt": "...", "digest": "..." }
  },
  "config": { "json_size": "12288", "keyslots_size": "16744448" }
}
```

| Object | Holds |
|---|---|
| `keyslots` | Wrapped copies of the volume key; see [keyslots](../keyslots/architecture.md) |
| `segments` | The encrypted data area: offset, size (`dynamic` = to the end), cipher, sector size |
| `digests` | PBKDF2 digests that verify a recovered volume key, and which keyslots and segments each binds |
| `tokens` | Metadata about external credentials; see [tokens](../tokens/architecture.md) |
| `config` | JSON area size, keyslots area size, optional `requirements` |

A container whose `config.requirements.mandatory` lists anything is refused
for writing, unlocking and activation (`ErrUnsupportedRequirement`): this library
implements none of those features, online reencryption included. It can still
be read.

## Encoding

What goes to disk is compact JSON, one NUL, then zero padding to the end of the
JSON area. Three properties matter for conformance:

- Compact. The JSON area cannot grow after format. Compact, all 32 keyslots
  fit in the default area; indented, only 22 do.
- No HTML escaping. Go escapes `<`, `>` and `&` by default; json-c, which
  cryptsetup uses, does not.
- No trailing newline between the closing brace and the NUL.

Byte offsets and sizes are JSON strings (`offset`, `size`, `iv_tweak`,
`json_size`, `keyslots_size`) because they can exceed 2^53; small counts
(`key_size`, `iterations`, `stripes`, `sector_size`) are numbers. This matches
the specification and cryptsetup.

Output matches cryptsetup byte for byte while each object has at most ten
entries. Go sorts object keys as strings and json-c keeps insertion order, so
at eleven keyslots this library writes `0,1,10,2,…`. Both parse the same.
`TestCanonicalJSONReencodesCryptsetupsHeaderByteForByte` and
`TestFormattedBinaryHeaderMatchesCryptsetup` check this against cryptsetup.

Members a struct does not model are kept through a rewrite in every nested
object: keyslots and their `area`, `kdf` and `af`, tokens, segments, digests,
`config` and `requirements`. Their values are kept exactly (large integers and
number spellings such as `1e3` included); whitespace inside them is compacted.
Unknown members at the top level of the metadata are dropped.

## Untrusted headers

Anyone with the disk can write the header, and keyslot fields decide how much
work an unlock does before any passphrase is checked.

- The header area is read once; the checksum and the JSON come from the same
  bytes. An object that names a member twice, or a modeled member in another
  case (`"Keyslots"`), fails with `ErrInvalidHeader`: cryptsetup's JSON
  parser is case-sensitive and Go's is not.
- The header is checked against cryptsetup's structural rules
  (`LUKS2_hdr_validate`): segment offsets and sizes on the 512-byte grid, the
  keyslots area between the header copies and the data, digests and tokens
  naming keyslots and segments that exist. On read, a rule about the header
  as a whole fails with `ErrInvalidHeader`; a damaged keyslot or token does
  not. Every write applies all the rules, so this library never writes a
  header cryptsetup would refuse. The one exception is `RestorePrimaryHeader`,
  which copies an existing secondary back and applies only the header-wide
  rules, so a damaged keyslot or token cannot block the repair.
- Segment fields that go straight into the dm-crypt table are also
  whitelisted: cipher characters, `sector_size` (512, 1024, 2048 or 4096) and
  `iv_tweak`. Activation (`Target`) refuses a segment that starts inside the
  header or keyslots area, including a detached header's offset 0
  (`ErrInvalidHeader`); unlocking refuses a segment with an `integrity` member
  (`ErrUnsupported`). A detached header's
  keyslots are still read and managed: its data, at offset 0 of another
  device, overlaps no keyslot area, as cryptsetup also holds.
- A digest is derived to the length its hash implies, or to 32 bytes (older
  go-luks2) or 20 bytes (every LUKS1 digest, kept by `cryptsetup convert`).
- Keyslot field bounds and the aggregate per-operation KDF budget are
  [keyslots/architecture.md#untrusted-keyslots](../keyslots/architecture.md#untrusted-keyslots).

## API

```go
v, err := luks2.Open(ctx, device)
hdr, err := v.Header(ctx)             // current copy
hdr, err = v.SecondaryHeader(ctx)
err = v.RestorePrimaryHeader(ctx)     // rebuild primary from secondary
err = v.ReplacePrimaryHeader(ctx)     // unconditional
```

`SecondaryHeader` finds the secondary copy at the area size the primary
states, or by probing the legal area sizes when the primary is unreadable. `RestorePrimaryHeader` reads and
validates the secondary copy (magic, checksum, header-wide structure; a
damaged keyslot or token does not block it) before writing, and refuses with
`ErrPrimaryHeaderCurrent` when the primary is intact and not older (restoring
would roll the volume back); `ReplacePrimaryHeader` overrides that guard
unconditionally. Both write a sequence ID one above both copies.

## What this feature deliberately does not do

No online reencryption, no dm-integrity segments, no mandatory requirement
this library does not name explicitly — a mandatory requirement is
`ErrUnsupportedRequirement` and a dm-integrity segment is refused for
unlocking with `ErrUnsupported`; neither is silently accepted.

Nor does it provide these header operations, which a volume's owner runs with
cryptsetup itself on the same container:

| Not provided | Reason |
|---|---|
| LUKS1-to-LUKS2 convert (`cryptsetup convert --type luks2`) | This library reads and writes LUKS2 only. A LUKS1 header is refused with `ErrNotLUKS2`, and this library has no LUKS1 writer to convert from |
| Changing the UUID or label (`luksUUID`, `cryptsetup config --label`) | The UUID, label and subsystem are written once, by `Format`. `*Header` only reads them, and there is no call that rewrites them on an existing volume |
| Header backup to a file (`luksHeaderBackup`/`luksHeaderRestore`) | `RestorePrimaryHeader` and `ReplacePrimaryHeader` repair the primary copy from the secondary copy on the same device. No exported function reads or writes a header through a file path |
