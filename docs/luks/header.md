# LUKS2 header

> **Status: REFERENCE** · Last verified: 2026-10-05 against v0.3.1-alpha

A LUKS2 header is two copies of a 4096-byte binary header plus a JSON area,
followed by the keyslots area and the data segment.

## Layout

`area` is the size of one header copy (binary header plus JSON). It is 16 KiB
by default, leaving 12288 bytes of JSON.

| Region | Offset | Size |
|---|---|---|
| Primary header and JSON | `0` | `area` |
| Secondary header and JSON | `area` | `area` |
| Keyslots area | `2 × area` | `16 MiB − 2 × area` |
| Data segment | `16 MiB` | rest of the device |

`FormatOptions.MetadataSize` sets `area` to a power of two from 16 KiB to
4 MiB, as cryptsetup's `--luks2-metadata-size` does; other values fail with
`ErrInvalidMetadataSize`. It cannot change after format. Containers
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
(`ErrUnsupportedHeaderChecksum`). cryptsetup verifies with whatever hash the
field names, so a header re-checksummed with `sha1` or `sha512` opens there and
not here. The
two copies differ in magic and header offset.

The specification has `sequence_id` increase on each update and readers prefer
the copy with the higher value. This library writes 1 on format and advances it
on keyslot and token changes. `WriteHeader` writes the value the caller passes.
`ReadHeader` reads the primary copy only and does not compare sequence IDs; the
CLI's `header show` and `header secondary` show both so you can.
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
| `keyslots` | Wrapped copies of the volume key; see [keyslots.md](keyslots.md) |
| `segments` | The encrypted data area: offset, size (`dynamic` = to the end), cipher, sector size |
| `digests` | PBKDF2 digests that verify a recovered volume key, and which keyslots and segments each binds |
| `tokens` | Metadata about external credentials; see [tokens.md](tokens.md) |
| `config` | JSON area size, keyslots area size, optional `requirements` |

A container whose `config.requirements.mandatory` lists anything is refused
for writing and for activation (`UnsupportedRequirementError`): this library
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
  case (`"Keyslots"`), fails with `ErrAmbiguousJSONMember`: cryptsetup's JSON
  parser is case-sensitive and Go's is not.
- The header is checked against cryptsetup's structural rules
  (`LUKS2_hdr_validate`, in `headervalidation.go`): segment offsets and sizes
  on the 512-byte grid, the keyslots area between the header copies and the
  data, digests and tokens naming keyslots and segments that exist. On read, a
  rule about the header as a whole fails with `ErrInvalidHeader`; a damaged
  keyslot or token does not. Every write applies all the rules, so this library
  never writes a header cryptsetup would refuse. The one exception is
  `RestorePrimaryHeader`, which copies an existing secondary back and applies
  only the header-wide rules, so a damaged keyslot or token cannot block the
  repair.
- Segment fields that go straight into the dm-crypt table are also
  whitelisted: cipher characters, `sector_size` (512, 1024, 2048 or 4096) and
  `iv_tweak`. Unlock refuses a segment that starts inside the header or
  keyslots area, including a detached header's offset 0.
- Keyslots are validated one at a time, before each is used, so one damaged
  keyslot does not hide the others and the header can still be inspected. A
  keyslot outside the bounds below fails with an error matching
  `ErrInvalidKeyslot` before any derivation or allocation.

| Field | Bound |
|---|---|
| `key_size` | declared 1–1024 bytes; only 32, 48 or 64 is tried (AES-XTS) |
| `af.stripes` | 1–4000 |
| `area.size` | 1 byte – 128 MiB (cryptsetup's `LUKS2_MAX_KEYSLOTS_SIZE`) |
| `key_size × stripes` | at most `area.size` |
| PBKDF2 iterations | 1 – 100,000,000 |
| Argon2 time / memory / cpus | 1–10,000 / 8 KiB – 4 GiB / 1–255 |

Keyslots of a type this library does not implement, such as `reencrypt`, are
never tried. The bounds are per derivation: nothing caps the total work of an
unlock that tries many keyslots.

## API

```go
hdr, metadata, err := luks2.ReadHeader(device)     // primary copy
hdr, metadata, err = luks2.ReadSecondaryHeader(device)
err = luks2.RestorePrimaryHeader(device)           // rebuild primary from secondary
err = luks2.WriteHeader(device, hdr, metadata)     // writes both copies
```

`ReadSecondaryHeader` finds the secondary copy by probing the legal area sizes,
so it works when the primary is unreadable. `RestorePrimaryHeader` reads and validates
the secondary copy (magic, checksum, header-wide structure; a damaged keyslot or
token does not block it) before writing, refuses with `ErrPrimaryHeaderCurrent` when
the primary is intact and not older (restoring would roll the volume back;
`RestorePrimaryHeaderWithOptions` with `Force` overrides), and writes a sequence
ID one above both copies. `WriteHeader` stamps the correct magic and
offset on each copy, whatever the caller's header carried.
