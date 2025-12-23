# LUKS2 Technical Documentation

This directory contains technical documentation about the LUKS2 (Linux Unified Key Setup version 2) disk encryption format as implemented by go-luks2.

## Contents

| Document | Description |
|----------|-------------|
| [Header Format](header.md) | Binary header structure and JSON metadata |
| [Keyslots](keyslots.md) | Key slot management and encryption |
| [Key Derivation](kdf.md) | PBKDF2 and Argon2 key derivation functions |
| [Encryption](encryption.md) | AES-XTS encryption and anti-forensic splitting |
| [Tokens](tokens.md) | Token management for FIDO2/TPM2 |

## LUKS2 Overview

LUKS2 is the second version of the Linux Unified Key Setup specification, providing:

- **Authenticated encryption metadata** with checksums
- **JSON-based configuration** for flexibility
- **Multiple keyslots** (up to 32) for different passphrases
- **Token support** for hardware security modules
- **Integrity protection** options (dm-integrity)

## On-Disk Layout

```
┌─────────────────────────────────────────────────────────────┐
│                    LUKS2 Device Layout                       │
├─────────────────────────────────────────────────────────────┤
│  Offset 0x0000: Primary Binary Header (4 KB)                │
├─────────────────────────────────────────────────────────────┤
│  Offset 0x1000: Primary JSON Area (typically 12 KB)          │
├─────────────────────────────────────────────────────────────┤
│  Offset 0x4000: Secondary Binary Header (4 KB) [backup]      │
├─────────────────────────────────────────────────────────────┤
│  Offset 0x5000: Secondary JSON Area [backup]                 │
├─────────────────────────────────────────────────────────────┤
│  Keyslot Area (size varies, typically starts at 32 KB)       │
│  - Contains encrypted key material for each keyslot          │
├─────────────────────────────────────────────────────────────┤
│  Data Segment (encrypted user data)                          │
│  - Encrypted with AES-XTS using the master key               │
└─────────────────────────────────────────────────────────────┘
```

## Cryptographic Components

### Master Key

- Generated randomly during volume creation
- 256 or 512 bits (typically 512 for AES-XTS)
- Never stored directly on disk
- Encrypted in each keyslot with a passphrase-derived key

### Key Hierarchy

```
Passphrase
    │
    ▼
┌──────────────────┐
│ Key Derivation   │  PBKDF2 or Argon2
│ Function (KDF)   │
└────────┬─────────┘
         │
         ▼
    Derived Key
         │
         ▼
┌──────────────────┐
│ Decrypt Keyslot  │  AES-XTS
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Anti-Forensic    │  AFMerge (4000 stripes)
│ Merge            │
└────────┬─────────┘
         │
         ▼
    Master Key
         │
         ▼
┌──────────────────┐
│ Verify Digest    │  PBKDF2-SHA256
└────────┬─────────┘
         │
         ▼
    Data Encryption
```

## Security Properties

### Passphrase Protection

- Strong KDFs resist brute-force attacks
- Argon2id provides memory-hard protection
- PBKDF2 with high iterations for compatibility

### Anti-Forensic Protection

- Master key split into 4000 stripes
- All stripes required for reconstruction
- Single stripe wipe makes key unrecoverable

### Header Redundancy

- Primary and backup headers
- Survives partial corruption
- Both must be wiped to destroy volume

## Implementation Notes

### go-luks2 Specifics

- Pure Go implementation
- Uses device-mapper for dm-crypt integration
- Supports file-based volumes via loop devices
- No dependency on cryptsetup binary

### Compatibility

- Fully interoperable with cryptsetup
- Volumes can be opened by either tool
- Follows LUKS2 on-disk specification

## References

- [LUKS2 On-Disk Format Specification](https://gitlab.com/cryptsetup/LUKS2-docs)
- [cryptsetup Documentation](https://gitlab.com/cryptsetup/cryptsetup)
- [dm-crypt Kernel Documentation](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/dm-crypt.html)
