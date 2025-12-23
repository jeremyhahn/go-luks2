# luks2 info

Display LUKS2 volume information.

## Synopsis

```
luks2 info <device>
```

## Description

The `info` command reads and displays detailed information about a LUKS2 encrypted volume, including:

- Volume UUID
- Label
- LUKS version
- Cipher and mode
- Sector size
- Active keyslots and their KDF parameters

## Arguments

| Argument | Description |
|----------|-------------|
| `device` | Path to the LUKS2 device or file |

## Examples

### View block device info

```bash
sudo luks2 info /dev/sdb1
```

### View file volume info

```bash
sudo luks2 info myvolume.luks
```

### View loop device info

```bash
sudo luks2 info /dev/loop0
```

## Output

The command displays:

```
Volume Information: /dev/sdb1
===========================================================

UUID:           12345678-1234-1234-1234-123456789abc
Label:          MySecureVolume
Version:        LUKS2
Cipher:         aes-xts-plain64
Sector Size:    512 bytes
Active Keyslots: [0]

Keyslot Details:
  Slot 0: argon2id (key size: 64 bytes)

Volume is valid and accessible
```

## Fields Explained

| Field | Description |
|-------|-------------|
| UUID | Unique identifier for the volume |
| Label | User-assigned volume name |
| Version | LUKS format version (always LUKS2) |
| Cipher | Encryption algorithm and mode |
| Sector Size | Encryption sector size in bytes |
| Active Keyslots | List of configured keyslot numbers |

## Keyslot Information

Each keyslot shows:
- Slot number (0-31)
- KDF type (argon2id, argon2i, or pbkdf2)
- Key size in bytes

## Use Cases

### Verify volume before opening

```bash
# Check if device is LUKS formatted
sudo luks2 info /dev/sdb1 && echo "Valid LUKS volume"
```

### Check encryption settings

```bash
# Verify cipher strength
sudo luks2 info /dev/sdb1 | grep Cipher
```

### Identify volume by UUID

```bash
# Get UUID for fstab or scripts
sudo luks2 info /dev/sdb1 | grep UUID
```

## Error Handling

### "Failed to read volume"

The device is not a valid LUKS2 volume:

```bash
# Check if device exists
ls -l /dev/sdb1

# Verify it's LUKS formatted
file /dev/sdb1
# or
sudo hexdump -C /dev/sdb1 | head -1
# Should show "LUKS" magic bytes
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success (valid LUKS2 volume) |
| 1 | Error (not LUKS, corrupted, not found) |

## See Also

- [create](create.md) - Create new volumes
- [open](open.md) - Unlock the volume
