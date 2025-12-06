# Usage Guide

## Installation

### Install CLI Tool

```bash
go install github.com/jeremyhahn/go-luks2/cmd/luks@latest
```

### Use as Library

```bash
go get github.com/jeremyhahn/go-luks2/pkg/luks2
```

## CLI Tool

### Create Encrypted Volume

```bash
# On a block device
sudo luks2 format /dev/sdb1

# On a file (for testing)
dd if=/dev/zero of=encrypted.img bs=1M count=100
sudo luks2 format encrypted.img
```

**Options**:
```bash
--kdf string         # KDF type: pbkdf2, argon2i, argon2id (default)
--key-size int       # Key size in bits: 256, 512 (default)
--label string       # Volume label
--sector-size int    # Sector size: 512 (default), 4096
```

### Unlock Volume

```bash
# Unlock (creates /dev/mapper/my-disk)
sudo luks2 open /dev/sdb1 my-disk

# Verify it's unlocked
ls -l /dev/mapper/my-disk
```

### Create Filesystem

```bash
# First time only - create filesystem
sudo mkfs.ext4 /dev/mapper/my-disk

# Or use XFS
sudo mkfs.xfs /dev/mapper/my-disk
```

### Mount Volume

```bash
# Create mount point
sudo mkdir -p /mnt/encrypted

# Mount
sudo luks2 mount my-disk /mnt/encrypted

# Use it
echo "secret data" | sudo tee /mnt/encrypted/file.txt

# Verify
cat /mnt/encrypted/file.txt
```

### Unmount Volume

```bash
# Unmount
sudo luks2 unmount /mnt/encrypted

# Lock (remove from device-mapper)
sudo luks2 close my-disk
```

### Complete Workflow Example

```bash
# 1. Create image file
dd if=/dev/zero of=/tmp/secret.img bs=1M count=100

# 2. Format with LUKS
sudo luks2 format /tmp/secret.img

# 3. Open (enter passphrase)
sudo luks2 open /tmp/secret.img secret-disk

# 4. Create filesystem
sudo mkfs.ext4 /dev/mapper/secret-disk

# 5. Mount
sudo mkdir -p /mnt/secret
sudo luks2 mount secret-disk /mnt/secret

# 6. Use
sudo touch /mnt/secret/important.txt
sudo chown $USER:$USER /mnt/secret/important.txt
echo "confidential" > /mnt/secret/important.txt

# 7. Cleanup
sudo luks2 unmount /mnt/secret
sudo luks2 close secret-disk
```

### Wipe Volume

```bash
# Wipe headers only (fast, makes data unrecoverable)
sudo luks2 wipe /dev/sdb1

# Full wipe with 3 passes (slow, DOD standard)
sudo luks2 wipe --passes 3 --full /dev/sdb1
```

## Library API

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func main() {
    // Format a volume
    err := luks2.Format(luks2.FormatOptions{
        Device:     "/dev/loop0",
        Passphrase: []byte("my-secure-passphrase"),
        Label:      "MyData",
        KDFType:    "argon2id", // Most secure
    })
    if err != nil {
        panic(err)
    }

    // Unlock the volume
    err = luks2.Unlock("/dev/loop0", []byte("my-secure-passphrase"), "my-volume")
    if err != nil {
        panic(err)
    }
    defer luks2.Lock("my-volume")

    fmt.Println("Volume unlocked at /dev/mapper/my-volume")
}
```

### Advanced Format Options

```go
opts := luks2.FormatOptions{
    Device:     "/dev/sdb1",
    Passphrase: []byte("strong-passphrase"),
    Label:      "BackupDisk",

    // Encryption
    Cipher:     "aes",           // Default
    CipherMode: "xts-plain64",   // Default
    KeySize:    512,              // 512-bit (default)

    // KDF Selection
    KDFType: "argon2id",  // pbkdf2, argon2i, or argon2id

    // PBKDF2 Options (if KDFType = "pbkdf2")
    PBKDFIterTime: 2000,  // Target milliseconds
    HashAlgo:      "sha256",

    // Argon2 Options (if KDFType = "argon2i" or "argon2id")
    Argon2Time:     4,        // Time cost (iterations)
    Argon2Memory:   1048576,  // Memory in KB (1GB)
    Argon2Parallel: 4,        // Parallelism (threads)

    // Disk Layout
    SectorSize: 512,  // 512 or 4096
}

err := luks2.Format(opts)
```

### Error Handling with Typed Errors

```go
import (
    "errors"
    "github.com/jeremyhahn/go-luks2/pkg/luks2"
)

err := luks2.Unlock(device, passphrase, volumeName)
if err != nil {
    // Check for specific error types
    if errors.Is(err, luks2.ErrInvalidPassphrase) {
        fmt.Println("Wrong passphrase, try again")
        return
    }

    if errors.Is(err, luks2.ErrDeviceNotFound) {
        fmt.Println("Device doesn't exist")
        return
    }

    if errors.Is(err, luks2.ErrVolumeAlreadyUnlocked) {
        fmt.Println("Volume is already unlocked")
        return
    }

    // Check for typed errors
    var devErr *luks2.DeviceError
    if errors.As(err, &devErr) {
        fmt.Printf("Device error on %s: %v\n", devErr.Device, devErr.Err)
        return
    }

    // Generic error
    fmt.Printf("Unlock failed: %v\n", err)
}
```

### Available Typed Errors

```go
// Sentinel errors (use errors.Is())
luks2.ErrInvalidHeader
luks2.ErrInvalidPassphrase
luks2.ErrDeviceNotFound
luks2.ErrVolumeNotUnlocked
luks2.ErrVolumeAlreadyUnlocked
luks2.ErrNotMounted
luks2.ErrAlreadyMounted
luks2.ErrUnsupportedKDF
luks2.ErrUnsupportedHash
luks2.ErrInvalidKeyslot
luks2.ErrNoKeyslots
luks2.ErrInvalidSize
luks2.ErrPermissionDenied

// Typed errors (use errors.As())
*luks2.DeviceError      // Errors related to devices
*luks2.VolumeError      // Errors related to volumes
*luks2.KeyslotError     // Errors related to keyslots
*luks2.CryptoError      // Cryptographic operation errors
```

### Volume Information

```go
info, err := luks2.GetVolumeInfo("/dev/sdb1")
if err != nil {
    panic(err)
}

fmt.Printf("UUID: %s\n", info.UUID)
fmt.Printf("Label: %s\n", info.Label)
fmt.Printf("Cipher: %s\n", info.Cipher)
fmt.Printf("Keyslots: %v\n", info.ActiveKeyslots)
```

### Mount/Unmount Operations

```go
// Create filesystem (first time only)
err := luks2.MakeFilesystem("my-volume", "ext4", "DataDisk")
if err != nil {
    panic(err)
}

// Mount
err = luks2.Mount(luks2.MountOptions{
    Device:     "my-volume",      // Volume name (not /dev/mapper/...)
    MountPoint: "/mnt/encrypted",
    FSType:     "ext4",
    Options:    []string{"noatime"},  // Mount options (optional)
    ReadOnly:   false,
})
if err != nil {
    panic(err)
}

// Check if mounted
mounted, err := luks2.IsMounted("/mnt/encrypted")
if err != nil {
    panic(err)
}
fmt.Printf("Mounted: %v\n", mounted)

// Unmount
err = luks2.Unmount("/mnt/encrypted", 0)  // 0 = normal unmount
if err != nil {
    panic(err)
}
```

### Secure Wipe

```go
// Wipe headers only (fast)
err := luks2.Wipe(luks2.WipeOptions{
    Device:     "/dev/sdb1",
    Passes:     1,
    HeaderOnly: true,
})

// Full device wipe (slow)
err = luks2.Wipe(luks2.WipeOptions{
    Device:     "/dev/sdb1",
    Passes:     3,      // DOD standard
    Random:     true,   // Use random data
    HeaderOnly: false,
})

// Wipe specific keyslot
err = luks2.WipeKeyslot("/dev/sdb1", 0)
```

### Loop Device Management

```go
// Setup loop device for file-based volumes
loopDev, err := luks2.SetupLoopDevice("/path/to/encrypted.img")
if err != nil {
    panic(err)
}
defer luks2.DetachLoopDevice(loopDev)

fmt.Printf("Loop device: %s\n", loopDev)

// Use with LUKS
err = luks2.Unlock(loopDev, passphrase, "my-volume")
```

## Best Practices

### Security

1. **Strong Passphrases**: Use at least 12 characters with mixed case, numbers, symbols
2. **KDF Selection**: Use Argon2id for new volumes (best security)
3. **Memory**: Set Argon2 memory high (1GB+) on systems with available RAM
4. **Backup**: Keep encrypted backups on separate media
5. **Wipe**: Always wipe headers before disposing of devices

### Performance

1. **Sector Size**: Use 4096 for large files/modern drives
2. **PBKDF2**: Faster unlock than Argon2, use for frequently-accessed volumes
3. **Argon2**: Better security, use for infrequently-accessed volumes
4. **Alignment**: Ensure volume starts on 1MB boundary for performance

### Error Handling

```go
// Always check errors
if err := luks2.Format(opts); err != nil {
    log.Fatalf("Format failed: %v", err)
}

// Use typed errors for graceful handling
if errors.Is(err, luks2.ErrInvalidPassphrase) {
    // Retry with new passphrase
}

// Clean up on errors
volume := "temp-volume"
if err := luks2.Unlock(device, pass, volume); err != nil {
    return err
}
defer func() {
    if err := luks2.Lock(volume); err != nil {
        log.Printf("Warning: failed to lock volume: %v", err)
    }
}()
```

### Memory Safety

```go
// Clear sensitive data
passphrase := []byte("secret")
defer clearBytes(passphrase)  // Internal function

// Use defer for cleanup
err := luks2.Unlock(device, passphrase, volume)
if err != nil {
    return err
}
defer luks2.Lock(volume)

// Don't log sensitive data
// ❌ log.Printf("Passphrase: %s", passphrase)
// ✓ log.Printf("Unlocked volume: %s", volume)
```

## Troubleshooting

### Common Issues

**"permission denied"**
```bash
# Need root for device-mapper operations
sudo your-command
```

**"device not found"**
```bash
# Check device exists
ls -l /dev/sdb1

# For loop devices, setup first
sudo losetup -f encrypted.img
```

**"volume already unlocked"**
```bash
# Check device-mapper
sudo dmsetup ls

# Close existing mapping
sudo luks2 close volume-name
```

**"invalid passphrase"**
- Check caps lock
- Try different keyslot (if multiple exist)
- Verify volume isn't corrupted

**"no space left on device"**
```bash
# Ensure device is large enough
# Minimum: ~20MB for LUKS headers + data
```

### Debug Mode

```go
// Enable verbose error messages (in development)
import "log"

err := luks2.Format(opts)
if err != nil {
    log.Printf("Format error: %+v", err)  // Detailed error
}
```

### Logs

```bash
# Check system logs for device-mapper errors
sudo journalctl -xe | grep dm-crypt

# Check kernel messages
sudo dmesg | grep -i crypt
```

