# Architecture

## Overview

go-luks2 is a pure Go implementation of LUKS2 (Linux Unified Key Setup) disk encryption. It provides both a command-line tool and a library for creating, unlocking, and managing encrypted volumes without external dependencies on cryptsetup.

## Core Components

### 1. Header Management (`header.go`)

**Purpose**: Read/write LUKS2 headers

**Structure**:
```
┌─────────────────────────────┐
│  Binary Header (4096 bytes) │  ← Magic, UUID, checksums
├─────────────────────────────┤
│  JSON Metadata (16KB)       │  ← Keyslots, segments, config
├─────────────────────────────┤
│  Backup Binary Header       │  ← Redundancy at offset 0x4000
├─────────────────────────────┤
│  Backup JSON Metadata       │
└─────────────────────────────┘
```

**Key Functions**:
- `ReadHeader()` - Parse binary + JSON metadata
- `WriteHeader()` - Write primary + backup headers
- Checksum validation (SHA-256)

### 2. Format Operations (`format.go`)

**Purpose**: Create new LUKS2 volumes

**Process**:
1. Generate master key (random)
2. Create keyslot with KDF (PBKDF2/Argon2)
3. Encrypt master key with passphrase-derived key
4. Apply anti-forensic split (4000 stripes)
5. Write encrypted key material to keyslot area
6. Create segment metadata (encryption params)
7. Write headers (primary + backup)

**Security**:
- Master key cleared from memory after use
- Passphrase-derived keys cleared after encryption
- Supports AES-XTS-256, Argon2id, PBKDF2

### 3. Unlock Operations (`unlock.go`)

**Purpose**: Unlock LUKS volumes using device-mapper

**Process**:
1. Read header and keyslot metadata
2. Derive key from passphrase using stored KDF
3. Decrypt keyslot material
4. Anti-forensic merge (reconstruct master key)
5. Verify master key against digest
6. Create device-mapper target
7. Load encryption table

**Device Mapper Integration**:
- Creates `/dev/mapper/<name>` device
- Uses dm-crypt target
- Handles sector-by-sector encryption

### 4. Key Derivation (`kdf.go`)

**Purpose**: Derive cryptographic keys from passphrases

**Supported KDFs**:
- **PBKDF2** (SHA-256/SHA-512)
  - Iterations calibrated for time target
  - Used for digest (100k iterations)

- **Argon2i** (memory-hard, side-channel resistant)
  - Time cost, memory cost, parallelism

- **Argon2id** (hybrid, recommended)
  - Default: 4 iterations, 1GB memory, 4 threads

**Functions**:
- `CreateKDF()` - Generate KDF with calibrated parameters
- `DeriveKey()` - Derive key from passphrase + salt
- `BenchmarkPBKDF2()` - Calibrate iterations for target time

### 5. Anti-Forensic Split (`antiforensic.go`)

**Purpose**: Protect against forensic key recovery

**Algorithm** (LUKS standard):
- Split key into 4000 stripes
- Each stripe encrypted with diffusion function
- All stripes required to recover key
- Partial data cannot reveal key material

**Process**:
```
Key (32 bytes) → AFSplit → 128,000 bytes (4000 * 32)
                          ↓
                    Encrypted Material
                          ↓
                     AFMerge → Key (32 bytes)
```

**Security**: Ensures wiping single stripe makes key unrecoverable

### 6. Filesystem Operations (`filesystem.go`, `mount.go`)

**Purpose**: Manage filesystems on unlocked volumes

**Operations**:
- `MakeFilesystem()` - Create ext4/xfs/etc on device
- `Mount()` - Mount encrypted filesystem
- `Unmount()` - Unmount filesystem
- `IsMounted()` - Check mount status

### 7. Wipe Operations (`wipe.go`)

**Purpose**: Securely destroy LUKS volumes

**Modes**:
- **Header Only**: Wipe LUKS headers (fast)
- **Full Wipe**: Overwrite entire device (slow)
- **Keyslot Wipe**: Destroy single keyslot

**Options**:
- Multiple passes (1-7 recommended)
- Random or zero patterns
- DOD 5220.22-M compliance available

## Data Flow

### Volume Creation
```
Passphrase → KDF → Passphrase Key
                         ↓
Master Key ← Random  →  Encrypted with Passphrase Key
    ↓                        ↓
AF Split (4000 stripes) → Keyslot Material
    ↓
Write to Device
```

### Volume Unlock
```
Passphrase → KDF → Passphrase Key
                         ↓
Keyslot Material → Decrypt → AF-Split Material
                                  ↓
                              AF Merge
                                  ↓
                             Master Key
                                  ↓
                       Verify against Digest
                                  ↓
                          Device-Mapper Setup
```

## Security Model

### Defense in Depth

1. **Passphrase Protection**: Strong KDFs (Argon2id default)
2. **Key Protection**: AES-256-XTS encryption
3. **Anti-Forensic**: 4000-stripe split
4. **Header Redundancy**: Primary + backup headers
5. **Memory Safety**: Sensitive data cleared after use

### Threat Model

**Protects Against**:
- ✓ Offline attacks (strong KDF)
- ✓ Forensic key recovery (AF split)
- ✓ Brute force (high iteration counts)
- ✓ Header corruption (backups)

**Does NOT Protect Against**:
- ✗ Online attacks while unlocked
- ✗ Memory dumps of running system
- ✗ Hardware keyloggers
- ✗ Physical coercion

## File Layout

```
pkg/luks/
├── errors.go          # Typed errors
├── types.go           # Data structures
├── header.go          # Header management
├── format.go          # Volume creation
├── unlock.go          # Volume unlocking
├── kdf.go             # Key derivation
├── antiforensic.go    # AF split/merge
├── filesystem.go      # Filesystem creation
├── mount.go           # Mount operations
├── wipe.go            # Secure wipe
└── util.go            # Utilities

cmd/luks/              # CLI tool
docs/                  # Documentation
```

## Performance Characteristics

| Operation | Time (typical) | I/O Pattern |
|-----------|---------------|-------------|
| Format (50GB) | 2-5s | Sequential write (headers only) |
| Unlock | 1-3s | Random read (keyslot) |
| Lock | <100ms | None |
| Wipe (headers) | <1s | Sequential write (32KB) |
| Wipe (full, 50GB) | ~5min | Sequential write (entire device) |

**KDF Times** (defaults):
- PBKDF2: 2000ms target
- Argon2id: 1-4s (depending on memory)

## Compatibility

**LUKS2 Specification**: Fully compliant
**Interoperability**:
- ✓ Volumes created with go-luks2 can be unlocked with cryptsetup
- ✓ Volumes created with cryptsetup can be unlocked with go-luks2

**Tested With**:
- cryptsetup 2.3+
- Linux kernel 5.x+
- device-mapper 1.02+

## Limitations

1. **Linux Only**: Requires device-mapper kernel module
2. **No LUKS1**: Only LUKS2 supported
3. **Single Keyslot**: Format creates only keyslot 0
4. **AES-XTS Only**: Other ciphers planned but not implemented
5. **Root Required**: Device-mapper operations need privileges
