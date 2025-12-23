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
