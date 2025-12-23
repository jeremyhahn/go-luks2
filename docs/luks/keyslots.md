# LUKS2 Keyslots

Keyslots store encrypted copies of the master key, each protected by a different passphrase.

## Overview

LUKS2 supports up to 32 keyslots (0-31). Each keyslot:

- Contains an independently encrypted copy of the master key
- Uses its own passphrase and KDF parameters
- Can be added, changed, or removed without affecting others

## Keyslot Structure

```json
{
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
      "salt": "base64-encoded-salt",
      "time": 4,
      "memory": 1048576,
      "cpus": 4
    }
  }
}
```

## Fields

### type

Always `"luks2"` for standard keyslots.

### key_size

Master key size in bytes:
- 32 bytes (256 bits) for AES-128-XTS
- 64 bytes (512 bits) for AES-256-XTS (default)

### af (Anti-Forensic)

Protects against forensic key recovery:

| Field | Description |
|-------|-------------|
| type | Always "luks1" (LUKS1-compatible algorithm) |
| stripes | Number of stripes (default: 4000) |
| hash | Hash for diffusion function |

### area

Encrypted key material storage:

| Field | Description |
|-------|-------------|
| type | "raw" for standard storage |
| offset | Byte offset on device |
| size | Total size (key_size × stripes) |
| encryption | Cipher for key encryption |
| key_size | Size of encryption key |

### kdf

Key derivation function parameters. See [Key Derivation](kdf.md).

## Key Material Layout

Each keyslot's encrypted area contains:

```
┌─────────────────────────────────────────┐
│          Encrypted Key Material          │
├─────────────────────────────────────────┤
│  Stripe 0: 64 bytes (encrypted)         │
│  Stripe 1: 64 bytes (encrypted)         │
│  Stripe 2: 64 bytes (encrypted)         │
│  ...                                     │
│  Stripe 3999: 64 bytes (encrypted)      │
├─────────────────────────────────────────┤
│  Total: 64 × 4000 = 256,000 bytes       │
│  Padded to sector boundary              │
└─────────────────────────────────────────┘
```

## Keyslot Unlock Process

```
1. Read keyslot metadata from JSON
2. Get KDF parameters (salt, iterations, etc.)
3. Derive key from passphrase using KDF
4. Read encrypted key material from disk
5. Decrypt with derived key (AES-XTS)
6. Anti-forensic merge (combine 4000 stripes)
7. Verify against digest
8. If valid, use as master key
```

## Code Example

### Unlocking a Keyslot

```go
// Attempt unlock with passphrase
err := luks2.Unlock(device, passphrase, volumeName)
if err != nil {
    if errors.Is(err, luks2.ErrInvalidPassphrase) {
        // Wrong passphrase for all keyslots
    }
}
```

### Checking Active Keyslots

```go
info, err := luks2.GetVolumeInfo(device)
if err != nil {
    return err
}

fmt.Printf("Active keyslots: %v\n", info.ActiveKeyslots)
// Output: Active keyslots: [0 1 3]
```

## Multiple Keyslots

### Use Cases

1. **Multiple Users**: Different passphrase per user
2. **Recovery Key**: Separate recovery passphrase
3. **Automation**: Keyfile in addition to passphrase
4. **Key Rotation**: Add new key, then remove old

### Adding a Keyslot

```go
// Add a new keyslot (requires existing passphrase)
err := luks2.AddKey(device, existingPass, newPass, luks2.AddKeyOptions{
    Slot: 1,  // Use slot 1, or -1 for auto
})
```

### Removing a Keyslot

```go
// Remove keyslot (wipes encrypted key material)
err := luks2.WipeKeyslot(device, 1)
```

## Security Considerations

### Keyslot Independence

- Each keyslot is cryptographically independent
- Compromising one passphrase doesn't reveal others
- Master key is the same, but protected differently

### Keyslot Wiping

Wiping a keyslot:
1. Overwrites the encrypted key area
2. Removes JSON metadata
3. Makes that passphrase unusable
4. Does not affect other keyslots

### Attack Resistance

- Strong KDF prevents brute-force attacks
- Anti-forensic split prevents partial recovery
- Multiple keyslots don't weaken security
