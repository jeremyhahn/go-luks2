# go-luks2

Pure Go implementation of LUKS2 (Linux Unified Key Setup) disk encryption.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Features

- **LUKS2** - Full specification compliance
- **Pure Go** - No external dependencies on cryptsetup
- **Compatible** - Interoperable with cryptsetup
- **Secure** - Argon2id, AES-XTS-256, anti-forensic split
- **Complete** - Format, unlock, mount, wipe operations
- **Typed Errors** - Proper error handling with `errors.Is()` / `errors.As()`

## Quick Start

### CLI Tool

```bash
# Install
go install github.com/jeremyhahn/go-luks2/cmd/luks@latest

# Create encrypted volume
dd if=/dev/zero of=secret.img bs=1M count=100
sudo luks format secret.img

# Unlock and mount
sudo luks open secret.img my-disk
sudo mkfs.ext4 /dev/mapper/my-disk
sudo luks mount my-disk /mnt/secret

# Use it
echo "confidential" | sudo tee /mnt/secret/data.txt

# Cleanup
sudo luks unmount /mnt/secret
sudo luks close my-disk
```

### Go Library

```bash
go get github.com/jeremyhahn/go-luks2/pkg/luks
```

**Format and unlock:**

```go
package main

import (
    "fmt"
    "github.com/jeremyhahn/go-luks2/pkg/luks"
)

func main() {
    // Format volume
    err := luks.Format(luks.FormatOptions{
        Device:     "/dev/loop0",
        Passphrase: []byte("my-secure-passphrase"),
        Label:      "MyData",
        KDFType:    "argon2id",  // Most secure
    })
    if err != nil {
        panic(err)
    }

    // Unlock volume
    err = luks.Unlock("/dev/loop0", []byte("my-secure-passphrase"), "my-volume")
    if err != nil {
        panic(err)
    }
    defer luks.Lock("my-volume")

    fmt.Println("✓ Volume unlocked at /dev/mapper/my-volume")
}
```

**With typed error handling:**

```go
import (
    "errors"
    "fmt"
    "github.com/jeremyhahn/go-luks2/pkg/luks"
)

err := luks.Unlock(device, passphrase, "my-volume")
if err != nil {
    // Check for specific errors
    if errors.Is(err, luks.ErrInvalidPassphrase) {
        fmt.Println("Wrong passphrase")
        return
    }

    if errors.Is(err, luks.ErrVolumeAlreadyUnlocked) {
        fmt.Println("Already unlocked")
        return
    }

    // Check typed errors
    var devErr *luks.DeviceError
    if errors.As(err, &devErr) {
        fmt.Printf("Device error: %s\n", devErr.Device)
        return
    }

    panic(err)
}
```

**Mount filesystem:**

```go
// Create filesystem (first time only)
luks.MakeFilesystem("my-volume", "ext4", "DataDisk")

// Mount
err := luks.Mount(luks.MountOptions{
    Device:     "my-volume",
    MountPoint: "/mnt/encrypted",
    FSType:     "ext4",
})
if err != nil {
    panic(err)
}
defer luks.Unmount("/mnt/encrypted", 0)
```

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** - System design and components
- **[Usage Guide](docs/USAGE.md)** - Detailed CLI and API documentation
- **[Security Audit](docs/SECURITY-AUDIT.md)** - Security analysis and recommendations

## API Overview

### Core Functions

```go
// Format a new LUKS2 volume
Format(opts FormatOptions) error

// Unlock volume (creates /dev/mapper/<name>)
Unlock(device string, passphrase []byte, name string) error

// Lock volume (removes from device-mapper)
Lock(name string) error

// Check if volume is unlocked
IsUnlocked(name string) bool

// Get volume information
GetVolumeInfo(device string) (*VolumeInfo, error)
```

### Filesystem Operations

```go
// Create filesystem on unlocked volume
MakeFilesystem(device, fstype, label string) error

// Mount encrypted volume
Mount(opts MountOptions) error

// Unmount
Unmount(mountPoint string, flags int) error

// Check mount status
IsMounted(mountPoint string) (bool, error)
```

### Secure Wipe

```go
// Wipe LUKS headers or full device
Wipe(opts WipeOptions) error

// Wipe specific keyslot
WipeKeyslot(device string, keyslot int) error
```

### Typed Errors

```go
// Sentinel errors (use with errors.Is())
ErrInvalidPassphrase
ErrDeviceNotFound
ErrVolumeNotUnlocked
ErrVolumeAlreadyUnlocked
ErrInvalidHeader
// ... and more

// Typed errors (use with errors.As())
*DeviceError
*VolumeError
*KeyslotError
*CryptoError
```

## Security

### Cryptographic Defaults

- **Cipher**: AES-256-XTS
- **KDF**: Argon2id (recommended) / PBKDF2 / Argon2i
- **Hash**: SHA-256
- **Anti-Forensic**: 4000-stripe split
- **Key Size**: 512 bits

### Security Features

- Strong KDFs (Argon2id with 1GB memory default)
- Anti-forensic information splitting
- Secure random number generation (`crypto/rand`)
- Memory clearing of sensitive data
- Header checksums and redundancy
- Compatible with cryptsetup

### Security Audit

A comprehensive security audit has been performed. See [docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md) for:
- Identified issues and severity ratings
- Security recommendations
- Cryptographic analysis
- Memory safety review

**Status**: GOOD with room for improvement. Primary concerns relate to incomplete memory clearing of intermediate buffers and input validation. See audit report for details.

## Requirements

- Linux kernel with device-mapper support
- Root/sudo privileges for device-mapper operations
- Go 1.24+ (for building)

## Compatibility

**LUKS2 Specification**: Fully compliant

**Interoperability**:
- Volumes created with go-luks2 can be unlocked with `cryptsetup`
- Volumes created with `cryptsetup` can be unlocked with go-luks2

**Tested With**:
- cryptsetup 2.3+
- Linux kernel 5.x+
- device-mapper 1.02+

## Examples

### CLI

```bash
# Format with custom KDF
sudo luks format --kdf argon2id --label "Backup" /dev/sdb1

# Unlock
sudo luks open /dev/sdb1 backup-disk

# Mount
sudo luks mount backup-disk /mnt/backup

# Wipe (makes data unrecoverable)
sudo luks wipe /dev/sdb1
```

### Library

```go
// Advanced format options
opts := luks.FormatOptions{
    Device:         "/dev/sdb1",
    Passphrase:     []byte("strong-passphrase"),
    KDFType:        "argon2id",
    Argon2Memory:   2097152,  // 2GB
    Argon2Time:     4,
    Argon2Parallel: 8,
    KeySize:        512,
}
luks.Format(opts)

// Loop device support
loopDev, _ := luks.SetupLoopDevice("encrypted.img")
defer luks.DetachLoopDevice(loopDev)
luks.Unlock(loopDev, passphrase, "my-volume")
```

## Testing

```bash
# Unit tests (fast, no root required)
make test-unit

# Integration tests (requires root)
sudo make test

# All tests in Docker (isolated, recommended)
make docker-integration-test
```

**Coverage**: 85%+ (unit + integration)

## Project Structure

```
go-luks2/
├── pkg/luks/              # Core library
│   ├── errors.go          # Typed errors
│   ├── format.go          # Volume creation
│   ├── unlock.go          # Volume unlocking
│   ├── kdf.go             # Key derivation
│   ├── mount.go           # Filesystem mounting
│   └── ...
├── cmd/luks/              # CLI tool
├── docs/                  # Documentation
│   ├── ARCHITECTURE.md    # System design
│   ├── USAGE.md           # Detailed guide
│   └── SECURITY-AUDIT.md  # Security analysis
└── README.md              # This file
```

## Performance

| Operation | Time (typical) |
|-----------|----------------|
| Format (50GB) | 2-5s |
| Unlock | 1-3s |
| Lock | <100ms |
| Wipe (headers) | <1s |
| Wipe (full, 50GB) | ~5min |

## Contributing

Contributions welcome! Please:
1. Read the [Architecture](docs/ARCHITECTURE.md) docs
2. Follow existing code style
3. Add tests for new features
4. Update documentation

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details

## Author

Jeremy Hahn

## Acknowledgments

- LUKS2 specification by Milan Broz
- cryptsetup project for reference implementation
- Go crypto libraries for solid foundations
