# luks2 create

Create a new LUKS2 encrypted volume.

## Synopsis

```
luks2 create <path> [size] [filesystem]
```

## Description

The `create` command initializes a new LUKS2 encrypted volume. It supports two modes:

1. **Block device mode**: Format an existing block device (partition)
2. **File volume mode**: Create an encrypted file with automatic loop device setup

For file volumes, the command automatically:
- Creates the file with the specified size
- Formats it with LUKS2 encryption
- Sets up a loop device
- Unlocks the volume
- Creates the specified filesystem

## Arguments

| Argument | Description |
|----------|-------------|
| `path` | Block device (e.g., `/dev/sdb1`) or file path |
| `size` | Size for file volumes (required for files, ignored for devices) |
| `filesystem` | Filesystem type: `ext4`, `ext3`, `ext2` (default: `ext4`) |

### Size Suffixes

| Suffix | Unit |
|--------|------|
| `K` | Kilobytes |
| `M` | Megabytes |
| `G` | Gigabytes |
| `T` | Terabytes |

## Examples

### Create on a block device

```bash
# Format a partition with LUKS2
sudo luks2 create /dev/sdb1

# You will be prompted for:
# - Passphrase (entered twice for confirmation)
# - Volume label (optional)
```

### Create a file-based volume

```bash
# Create a 100MB encrypted file with ext4
sudo luks2 create myvolume.luks 100M

# Create a 1GB encrypted file with ext4
sudo luks2 create backup.luks 1G ext4

# Create with ext3 filesystem
sudo luks2 create legacy.luks 500M ext3
```

### Automated workflow

When creating a file volume, the command automatically performs:

```
1. Create sparse file
2. Format with LUKS2 (Argon2id KDF)
3. Setup loop device
4. Unlock volume
5. Create filesystem
```

After completion, the volume is ready to mount:

```bash
sudo luks2 mount luks-auto /mnt/encrypted
```

## Encryption Settings

The `create` command uses these default settings:

| Setting | Value |
|---------|-------|
| Cipher | AES-XTS-256 |
| Key Size | 512 bits |
| KDF | Argon2id |
| Sector Size | 512 bytes |

## Passphrase Requirements

- Minimum length: 8 characters
- Maximum length: 512 characters
- Confirmation required for new volumes

## Output

On success, displays:
- Volume file/device path
- Loop device (for file volumes)
- Device mapper path
- Next steps for mounting

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (file exists, invalid size, format failed) |

## See Also

- [open](open.md) - Unlock an existing volume
- [mount](mount.md) - Mount an unlocked volume
- [info](info.md) - Display volume information
