# Architecture

## Overview

go-luks2 is a pure Go implementation of LUKS2 (Linux Unified Key Setup) disk encryption. It provides both a command-line tool and a library for creating, unlocking, and managing encrypted volumes without external dependencies on cryptsetup.

## Project Structure

```
go-luks2/
├── cmd/luks2/              # CLI application
│   ├── main.go             # Entry point, version, usage text
│   ├── cli.go              # CLI logic with dependency injection
│   ├── cli_test.go         # CLI unit tests
│   └── terminal.go         # Terminal interface for password input
│
├── pkg/luks2/              # Core library
│   ├── types.go            # Data structures and options
│   ├── errors.go           # Typed errors and sentinels
│   ├── header.go           # Header read/write operations
│   ├── format.go           # Volume creation
│   ├── unlock.go           # Volume unlock/lock operations
│   ├── kdf.go              # Key derivation functions
│   ├── antiforensic.go     # AF split/merge operations
│   ├── filesystem.go       # Filesystem creation
│   ├── mount.go            # Mount/unmount operations
│   ├── wipe.go             # Secure wipe operations
│   ├── loopdev.go          # Loop device management
│   ├── token.go            # Token management API
│   └── *_test.go           # Unit tests
│
├── test/integration/       # Integration tests
│   ├── Dockerfile          # Docker environment for tests
│   ├── pkg/                # Package integration tests
│   └── cli/                # CLI integration tests
│
├── docs/                   # Documentation
│   ├── ARCHITECTURE.md     # This file
│   ├── cli/                # CLI command documentation
│   └── luks/               # LUKS2 technical documentation
│
└── .devcontainer/          # VS Code dev container
    ├── Dockerfile
    └── devcontainer.json
```

## Core Components

### 1. CLI Layer (`cmd/luks2/`)

The CLI is designed for testability using dependency injection:

```go
type CLI struct {
    Args      []string
    Stdin     io.Reader
    Stdout    io.Writer
    Stderr    io.Writer
    Luks      LuksOperations    // Interface for LUKS operations
    Terminal  Terminal          // Interface for password input
    FS        FileSystem        // Interface for file operations
    ExitFunc  func(code int)
}
```

This allows complete testing without actual disk operations.

### 2. Header Management (`header.go`)

Handles LUKS2 binary header and JSON metadata:

```
┌─────────────────────────────┐
│  Binary Header (4096 bytes) │  ← Magic, UUID, checksums
├─────────────────────────────┤
│  JSON Metadata (12-16 KB)   │  ← Keyslots, segments, config
├─────────────────────────────┤
│  Backup Binary Header       │  ← Redundancy at offset 0x4000
├─────────────────────────────┤
│  Backup JSON Metadata       │
└─────────────────────────────┘
```

### 3. Format Operations (`format.go`)

Creates new LUKS2 volumes:

1. Generate master key (random)
2. Create keyslot with KDF (PBKDF2/Argon2)
3. Encrypt master key with passphrase-derived key
4. Apply anti-forensic split (4000 stripes)
5. Write encrypted key material
6. Create segment metadata
7. Write headers (primary + backup)

### 4. Unlock Operations (`unlock.go`)

Unlocks LUKS volumes using device-mapper:

1. Read header and keyslot metadata
2. Derive key from passphrase using stored KDF
3. Decrypt keyslot material
4. Anti-forensic merge (reconstruct master key)
5. Verify master key against digest
6. Create device-mapper target
7. Load encryption table

### 5. Key Derivation (`kdf.go`)

Supports multiple KDFs:

| KDF | Type | Use Case |
|-----|------|----------|
| Argon2id | Memory-hard | Default, recommended |
| Argon2i | Memory-hard | Side-channel resistant |
| PBKDF2 | Iterative | FIPS compliance |

### 6. Anti-Forensic Split (`antiforensic.go`)

Protects master key from forensic recovery:

```
Key (64 bytes) → AFSplit → 256,000 bytes (4000 × 64)
                           ↓
                     Encrypted Material
                           ↓
                      AFMerge → Key (64 bytes)
```

### 7. Token Management (`token.go`)

Manages LUKS2 tokens for external key sources:

- FIDO2 hardware keys
- TPM2 modules
- Custom token types

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

## Testing Architecture

### Unit Tests

Located alongside source files (`*_test.go`):
- No I/O operations
- No root privileges required
- Mock-based testing for CLI

### Integration Tests

Located in `test/integration/`:
- Require Docker with privileged mode
- Test actual device operations
- Use loop devices for isolation

```bash
# Run unit tests
make test-unit

# Run integration tests in Docker
make integration-test
```

## Build System

### Version Injection

Version is read from `VERSION` file and injected at build time:

```makefile
VERSION=$(shell cat VERSION | tr -d 'v')
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"
```

### Key Targets

| Target | Description |
|--------|-------------|
| `build` | Build CLI with version |
| `test-unit` | Run unit tests |
| `integration-test` | Run integration tests in Docker |
| `ci` | Full CI pipeline |

## Compatibility

### LUKS2 Specification

- Fully compliant with LUKS2 on-disk format
- Interoperable with cryptsetup

### System Requirements

- Linux with device-mapper support
- Kernel 5.x+ recommended
- Root privileges for device operations

## Limitations

1. **Linux Only**: Requires device-mapper kernel module
2. **LUKS2 Only**: LUKS1 not supported
3. **AES-XTS Only**: Other ciphers planned
4. **Root Required**: Device-mapper needs privileges
