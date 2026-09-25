# LUKS2 Header Format

The LUKS2 header consists of a binary header followed by a JSON metadata area. Both primary and backup copies are stored.

## Binary Header Structure

The binary header is 4096 bytes (4 KB) and contains:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x0000 | 6 | Magic | `LUKS\xba\xbe` (primary) or `SKUL\xba\xbe` (secondary) |
| 0x0006 | 2 | Version | `0x0002` for LUKS2 |
| 0x0008 | 8 | Header Size | Total header size including JSON |
| 0x0010 | 8 | Sequence ID | Monotonic counter for updates |
| 0x0018 | 48 | Label | Volume label (null-padded) |
| 0x0048 | 32 | Checksum Algorithm | e.g., "sha256" |
| 0x0068 | 64 | Salt | Random salt for checksum |
| 0x00A8 | 40 | UUID | Volume UUID string |
| 0x00D0 | 48 | Subsystem | Optional subsystem label |
| 0x0100 | 8 | Header Offset | Offset of this header |
| 0x0108 | 184 | Padding | Reserved (zeros) |
| 0x01C0 | 64 | Checksum | SHA-256 of header + JSON |
| 0x0200 | 3584 | Padding | Reserved to 4 KB |

## Metadata Area Size

Each header copy (binary header plus JSON area) occupies one metadata area,
and the two copies tile the front of the device:

| Region | Offset | Size |
|--------|--------|------|
| Primary header + JSON | `0` | `area` |
| Secondary header + JSON | `area` | `area` |
| Keyslots area | `2 × area` | `16 MiB − 2 × area` |
| Data segment | `16 MiB` | rest of device |

`area` is 16 KiB by default, leaving `json_size` = 12288. Set
`FormatOptions.MetadataSize` to a power of two from 16 KiB to 4 MiB for more
JSON space. This is the equivalent of cryptsetup's `--luks2-metadata-size`,
with the same accepted set and the same layout; other values are refused with
`ErrInvalidMetadataSize`. The size is recorded in the header and cannot change
after format. Containers cryptsetup wrote with any legal size are read
from their headers.

## Header Checksum

The checksum is computed over:
1. The binary header (with checksum field zeroed)
2. The entire JSON metadata area

```
checksum = SHA256(binary_header || json_area)
```

## JSON Metadata

The JSON area follows the binary header and contains structured metadata:

```json
{
  "keyslots": {
    "0": {
      "type": "luks2",
      "key_size": 64,
      "af": {
        "type": "luks1",
        "stripes": 4000,
        "hash": "sha256"
      },
      "area": {
        "type": "raw",
        "offset": "32768",
        "size": "258048",
        "encryption": "aes-xts-plain64",
        "key_size": 64
      },
      "kdf": {
        "type": "argon2id",
        "salt": "base64...",
        "time": 4,
        "memory": 1048576,
        "cpus": 4
      }
    }
  },
  "tokens": {},
  "segments": {
    "0": {
      "type": "crypt",
      "offset": "16777216",
      "size": "dynamic",
      "iv_tweak": "0",
      "encryption": "aes-xts-plain64",
      "sector_size": 512
    }
  },
  "digests": {
    "0": {
      "type": "pbkdf2",
      "keyslots": ["0"],
      "segments": ["0"],
      "hash": "sha256",
      "iterations": 100000,
      "salt": "base64...",
      "digest": "base64..."
    }
  },
  "config": {
    "json_size": "12288",
    "keyslots_size": "16744448"
  }
}
```

### On-disk encoding

The example above is pretty-printed for reading. **What is written to disk is
compact**: no newlines, no indentation, one NUL terminator after the closing
brace, and zero padding to the end of the JSON area.

Three properties of the encoding are conformance requirements, not style:

| Property | Why |
|---|---|
| Compact | The JSON area is fixed when the container is formatted (12288 bytes by default) and cannot grow (the keyslots and the data segment are already placed), so indentation is charged against the keyslot budget. Indented, only 22 of the 32 keyslots LUKS2 defines fit; compact, all 32 fit in 10676 bytes. |
| No HTML escaping | Go's `encoding/json` escapes `<`, `>` and `&` as `\u003c`, `\u003e` and `\u0026` by default. json-c, which cryptsetup uses, does not. |
| No trailing newline | `json.Encoder.Encode` appends one; it would land between the closing brace and the NUL terminator. |

Byte values that exceed 2^53 are written as JSON **strings** (`"offset"`,
`"size"`, `"iv_tweak"`, `"json_size"`, `"keyslots_size"`) because JSON numbers
are doubles; counts and sizes that do not (`"key_size"`, `"iterations"`,
`"stripes"`, `"sector_size"`) are written bare. This matches the LUKS2
specification and cryptsetup exactly.

Conformance is asserted rather than assumed. `TestCanonicalJSONReencodes-
CryptsetupsHeaderByteForByte` parses a container cryptsetup wrote and re-encodes
it, requiring identical bytes; `TestFormattedBinaryHeaderMatchesCryptsetup`
compares two independently formatted containers and requires the whole 4096-byte
binary header to match outside the header salt, the derived checksum, and
`sequence_id`.

Byte-identity with cryptsetup's json-c encoder holds **up to ten entries** in
any of `keyslots`, `tokens`, `segments` or `digests`. Go's `encoding/json` sorts
object keys as strings while json-c preserves insertion order, so at eleven
keyslots cryptsetup writes `0,1,...,9,10` and this library writes
`0,1,10,2,...,9`. Both are conformant — JSON objects are unordered — and both
parse identically; only a byte comparison sees it.

### sequence_id

`sequence_id` is a monotonic counter, not a format constant: the LUKS2
specification defines it as increased on update, and a reader takes the header
copy with the higher value. cryptsetup writes 3 after `luksFormat` because its
format performs three header writes; this library writes 1. Both are valid, and
the value records a container's write history rather than describing its layout.

## JSON Sections

### keyslots

Defines encryption keyslots:
- `type`: Always "luks2"
- `key_size`: Master key size (bytes)
- `af`: Anti-forensic parameters
- `area`: Encrypted key material location
- `kdf`: Key derivation function parameters

### segments

Defines encrypted data segments:
- `type`: "crypt" for encrypted segments
- `offset`: Start of encrypted data
- `size`: "dynamic" for full device
- `encryption`: Cipher specification
- `sector_size`: Encryption sector size

### digests

Master key verification:
- `type`: "pbkdf2" (always)
- `keyslots`: Which keyslots use this digest
- `segments`: Which segments use this key
- `digest`: Expected key hash

### tokens

Hardware token references:
- FIDO2 tokens
- TPM2 tokens
- Custom token types

### config

Volume configuration:
- `json_size`: Size of JSON area
- `keyslots_size`: Total keyslot area size

## Header Locations

| Header | Offset | Purpose |
|--------|--------|---------|
| Primary | 0x0000 | Main header |
| Secondary | 0x4000 | Backup header |

Both headers should be identical (except magic bytes). The secondary header uses `SKUL` magic to distinguish it.

## Implementation in go-luks2

### Reading Headers

```go
// Read and validate header
header, err := luks2.ReadHeader(device)
if err != nil {
    // Handle invalid/corrupted header
}

// Access metadata
fmt.Println(header.UUID)
fmt.Println(header.Label)
```

### Header Validation

1. Check magic bytes
2. Verify version is 2
3. Validate checksum
4. Parse JSON metadata
5. Verify JSON structure

### Checksum Verification

```go
// Computed internally during ReadHeader
// Returns error if checksum doesn't match:
// "header checksum mismatch"
```

## Security Considerations

1. **Checksum Protection**: Headers are integrity-protected
2. **Redundancy**: Backup header survives corruption
3. **Secure Wipe**: Both headers must be destroyed
4. **No Encryption**: Headers are not encrypted (by design)
