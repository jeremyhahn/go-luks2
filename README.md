# go-luks2

Pure Go implementation of LUKS2 disk encryption. No external dependencies on cryptsetup.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Installation

```bash
# CLI tool
go install github.com/jeremyhahn/go-luks2/cmd/luks2@latest

# Library
go get github.com/jeremyhahn/go-luks2/pkg/luks2
```

## CLI Usage

All commands require root privileges.

### Commands

| Command | Description |
|---------|-------------|
| `create <path> [size] [fs]` | Create LUKS2 volume (block device or file) |
| `open <device> <name>` | Unlock volume to /dev/mapper/\<name\> |
| `close <name>` | Lock volume |
| `mount <name> <mountpoint>` | Mount unlocked volume |
| `unmount <mountpoint>` | Unmount volume |
| `info <device>` | Show volume information |
| `wipe [opts] <device>` | Securely wipe volume (`--full`, `--passes N`, `--random`, `--trim`) |
| `help` | Show help |
| `version` | Show version |

### Examples

**Block device:**
```bash
sudo luks2 create /dev/sdb1
sudo luks2 open /dev/sdb1 mydisk
sudo mkfs.ext4 /dev/mapper/mydisk
sudo luks2 mount mydisk /mnt/encrypted
# ... use /mnt/encrypted ...
sudo luks2 unmount /mnt/encrypted
sudo luks2 close mydisk
```

**File-based volume (auto-configures loop device and filesystem):**
```bash
sudo luks2 create secret.luks 500M ext4
sudo luks2 mount luks-auto /mnt/encrypted
# ... use /mnt/encrypted ...
sudo luks2 unmount /mnt/encrypted
sudo luks2 close luks-auto
```

## Library API

### Core Operations

```go
import "github.com/jeremyhahn/go-luks2/pkg/luks2"

// Format new volume
luks2.Format(luks2.FormatOptions{
    Device:     "/dev/sdb1",
    Passphrase: []byte("secret"),
    Label:      "MyVolume",
    KDFType:    "argon2id",  // or "pbkdf2", "argon2i"
})

// Unlock/Lock
luks2.Unlock("/dev/sdb1", []byte("secret"), "myvolume")
luks2.Lock("myvolume")

// Status
luks2.IsUnlocked("myvolume")                    // bool
luks2.GetVolumeInfo("/dev/sdb1")                // *VolumeInfo, error
luks2.GetMappedDevicePath("myvolume")           // string, error
```

### Keyslot Management

```go
// Add passphrase to new keyslot
luks2.AddKey(device, existingPass, newPass, &luks2.AddKeyOptions{
    KDFType: "argon2id",
    Hash:    "sha256",  // for pbkdf2
})

// Change passphrase in specific keyslot
luks2.ChangeKey(device, oldPass, newPass, keyslotNumber)

// Remove passphrase (requires matching passphrase)
luks2.RemoveKey(device, passphrase, keyslotNumber)

// Kill keyslot (authenticate with any valid passphrase)
luks2.KillSlot(device, authPassphrase, targetSlot)

// Kill keyslot without authentication (dangerous)
luks2.KillKeyslot(device, keyslotNumber)

// Verify passphrase without unlocking
luks2.TestKey(device, passphrase)

// List active keyslots
luks2.ListKeyslots(device)  // []KeyslotInfo, error
```

### Token Management

Tokens store metadata for external key sources (FIDO2, TPM2, etc.):

```go
luks2.ListTokens(device)                        // map[int]*Token, error
luks2.GetToken(device, tokenID)                 // *Token, error
luks2.ImportToken(device, tokenID, token)       // error
luks2.ImportTokenJSON(device, tokenID, json)    // error
luks2.ExportToken(device, tokenID)              // []byte, error
luks2.RemoveToken(device, tokenID)              // error
luks2.FindFreeTokenSlot(device)                 // int, error
luks2.TokenExists(device, tokenID)              // bool, error
luks2.CountTokens(device)                       // int, error
```

### Recovery Keys

Generate and manage recovery keys for emergency access:

```go
// Generate and add recovery key
key, _ := luks2.AddRecoveryKey(device, existingPass, &luks2.RecoveryKeyOptions{
    Format:     luks2.RecoveryKeyFormatDashed,  // "XXXX-XXXX-XXXX-..."
    OutputPath: "/secure/recovery.key",
})
fmt.Println(key.Formatted)  // Human-readable key

// Generate key only (without adding to volume)
key, _ := luks2.GenerateRecoveryKey(32, luks2.RecoveryKeyFormatHex)

// Save/Load recovery keys
luks2.SaveRecoveryKey(key, "/path/to/key")
keyBytes, _ := luks2.LoadRecoveryKey("/path/to/key")

// Verify and parse
luks2.VerifyRecoveryKey(device, keyBytes)      // bool, error
luks2.ParseRecoveryKey("XXXX-XXXX-...")        // []byte, error
```

### Filesystem & Mount

```go
luks2.MakeFilesystem("myvolume", "ext4", "label")

// Advanced filesystem options
luks2.MakeFilesystemWithOptions(device, luks2.FilesystemExt4, &luks2.FilesystemOptions{
    Label:     "MyVolume",
    BlockSize: 4096,
})

luks2.Mount(luks2.MountOptions{
    Device:     "myvolume",
    MountPoint: "/mnt/encrypted",
    FSType:     "ext4",
})

luks2.Unmount("/mnt/encrypted", 0)
luks2.IsMounted("/mnt/encrypted")              // bool, error
luks2.CheckFilesystem(device, fstype, repair)  // error
luks2.GetFilesystemInfo(device)                // *FilesystemInfo, error
luks2.SupportedFilesystems()                   // []FilesystemType
```

Supported filesystems: ext2, ext3, ext4, xfs, zfs, vfat

### Loop Devices

```go
loopDev, _ := luks2.SetupLoopDevice("encrypted.img")
defer luks2.DetachLoopDevice(loopDev)
luks2.Unlock(loopDev, passphrase, "myvolume")

luks2.FindLoopDevice("encrypted.img")  // Find existing loop device
```

### Secure Wipe

```go
// Wipe entire device
luks2.Wipe(luks2.WipeOptions{
    Device:     "/dev/sdb1",
    Passes:     3,      // overwrite passes
    Random:     true,   // random data vs zeros
    HeaderOnly: false,  // true = headers only (fast)
    Trim:       true,   // TRIM/DISCARD for SSDs
})

// Wipe specific keyslot
luks2.WipeKeyslot(device, keyslotNumber)
```

### Header Access

```go
hdr, metadata, err := luks2.ReadHeader(device)
luks2.WriteHeader(device, hdr, metadata)         // error
luks2.CreateBinaryHeader(opts)                   // *LUKS2BinaryHeader, error

// Validation
luks2.IsLUKS(device)                             // bool, error
luks2.IsLUKS2(device)                            // bool, error
```

### FIPS Compliance

For FIPS 140-2/3 environments, use PBKDF2:

```go
luks2.IsFIPSCompliantKDF("pbkdf2-sha256")  // true
luks2.IsFIPSCompliantKDF("argon2id")       // false

luks2.Format(luks2.FormatOptions{
    Device:     device,
    Passphrase: pass,
    KDFType:    "pbkdf2-sha256",  // FIPS-approved
})
```

FIPS-approved KDFs: `pbkdf2-sha1`, `pbkdf2-sha256`, `pbkdf2-sha384`, `pbkdf2-sha512`

## Cryptographic Defaults

| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-XTS |
| KDF | Argon2id (1GB memory, 4 iterations, 4 threads) |
| Hash | SHA-256 |
| Key Size | 512 bits |
| Anti-Forensic | 4000-stripe split |

## Requirements

- Linux with device-mapper support
- Root privileges for device-mapper operations
- Go 1.25.5 (for building)

## Compatibility

- Fully compliant with LUKS2 specification
- Interoperable with cryptsetup 2.3+
- Volumes created with go-luks2 work with cryptsetup and vice versa

## Limitations

- Linux only (requires device-mapper)
- LUKS2 only (LUKS1 not supported)
- AES-XTS only (other ciphers not implemented)

## Testing

```bash
make test              # Unit tests
sudo make integration  # Integration tests (requires root)
make ci-full           # Full test suite in Docker
```

## License

Apache License 2.0

## Author

Jeremy Hahn
