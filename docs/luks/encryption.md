# LUKS2 Encryption

LUKS2 uses symmetric encryption for both data and key material protection.

## Cipher Specification

The default cipher specification is:

```
aes-xts-plain64
```

Components:
- **aes**: AES (Advanced Encryption Standard) block cipher
- **xts**: XEX-based Tweaked-codebook mode with ciphertext Stealing
- **plain64**: 64-bit sector number as IV tweak

## AES-XTS Mode

XTS mode is designed specifically for disk encryption:

### Properties

- **Tweakable**: Each sector has a unique tweak (IV)
- **Length-preserving**: Ciphertext same size as plaintext
- **No authentication**: Does not detect tampering
- **Parallel**: Sectors can be encrypted independently

### Key Size

XTS uses two keys (for encryption and tweak):

| Setting | Key Size | Effective Security |
|---------|----------|-------------------|
| AES-128-XTS | 256 bits (2×128) | 128-bit |
| AES-256-XTS | 512 bits (2×256) | 256-bit |

go-luks2 uses AES-256-XTS (512-bit key) by default.

## Sector Encryption

Data is encrypted sector-by-sector:

```
┌─────────────────────────────────────────┐
│              Sector N                    │
├─────────────────────────────────────────┤
│  Plaintext (512 or 4096 bytes)          │
│            │                             │
│            ▼                             │
│  ┌────────────────┐                      │
│  │   AES-XTS      │ ◄── Key + Tweak(N)  │
│  └────────────────┘                      │
│            │                             │
│            ▼                             │
│  Ciphertext (same size)                  │
└─────────────────────────────────────────┘
```

### Sector Size

| Size | Use Case |
|------|----------|
| 512 bytes | Traditional, maximum compatibility |
| 4096 bytes | Modern drives, better performance |

## Anti-Forensic Splitting

Master key is protected with anti-forensic information splitting (AFsplit).

### Purpose

Prevents recovery of the master key from:
- Partial disk reads
- Disk imaging artifacts
- Forensic recovery tools

### Algorithm

```
Master Key (64 bytes)
      │
      ▼
┌─────────────────────┐
│   AFSplit           │
│   4000 stripes      │
│   SHA-256 diffuse   │
└─────────────────────┘
      │
      ▼
Split Material (256,000 bytes)
      │
      ▼
┌─────────────────────┐
│   AES-XTS Encrypt   │
│   with derived key  │
└─────────────────────┘
      │
      ▼
Encrypted Keyslot Material
```

### Recovery (Unlock)

```
Encrypted Material
      │
      ▼
┌─────────────────────┐
│   AES-XTS Decrypt   │
│   with derived key  │
└─────────────────────┘
      │
      ▼
Split Material (256,000 bytes)
      │
      ▼
┌─────────────────────┐
│   AFMerge           │
│   Combine stripes   │
└─────────────────────┘
      │
      ▼
Master Key (64 bytes)
```

### Security Property

If any single stripe is wiped or corrupted, the master key cannot be recovered. This means:

1. Wiping 64 bytes anywhere in the keyslot destroys it
2. Forensic tools cannot recover partial key data
3. Physical damage to keyslot area is fatal

## Device-Mapper Integration

go-luks2 uses Linux device-mapper for encryption:

```
User Space              Kernel Space
    │                       │
    ▼                       │
/dev/sdb1 ──────────────────┤
(encrypted)                 │
    │                       ▼
    │            ┌─────────────────────┐
    │            │   device-mapper     │
    │            │   dm-crypt target   │
    │            └─────────────────────┘
    │                       │
    ▼                       ▼
           /dev/mapper/myvolume
               (decrypted)
```

### dm-crypt Table

```
0 <size> crypt aes-xts-plain64 <key> 0 /dev/sdb1 <offset>
```

Components:
- `0`: Start sector
- `<size>`: Number of sectors
- `crypt`: dm-crypt target
- `aes-xts-plain64`: Cipher specification
- `<key>`: Master key (hex)
- `0`: IV offset
- `/dev/sdb1`: Underlying device
- `<offset>`: Data start offset

## Implementation Details

### Key Generation

```go
// Master key is generated using crypto/rand
masterKey := make([]byte, 64)
_, err := rand.Read(masterKey)
```

### Memory Protection

```go
// Keys are cleared after use
defer func() {
    for i := range masterKey {
        masterKey[i] = 0
    }
}()
```

### Encryption Operations

```go
// Encrypt key material
encrypted, err := encryptKeyMaterial(data, derivedKey, "aes")

// Decrypt key material
decrypted, err := decryptKeyMaterial(encrypted, derivedKey, "aes", 512)
```

## Security Considerations

### XTS Limitations

1. **No Authentication**: Cannot detect tampering
2. **Malleability**: Specific bit flips have predictable effects
3. **Sector Boundaries**: Changes in one sector don't affect others

### Mitigations

1. **Header Checksums**: Detect header tampering
2. **Key Verification**: Digest verifies correct decryption
3. **dm-integrity**: Optional integrity protection (not in go-luks2)

### Best Practices

1. Use full disk encryption
2. Keep headers backed up securely
3. Use strong passphrases
4. Wipe headers before device disposal
