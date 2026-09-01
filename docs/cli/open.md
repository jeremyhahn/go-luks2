# luks2 open

Unlock a LUKS2 encrypted volume.

## Synopsis

```
luks2 open <device> <name>
```

## Description

The `open` command unlocks a LUKS2 encrypted volume and creates a device-mapper entry at `/dev/mapper/<name>`. This allows the encrypted data to be accessed through the decrypted device.

## Arguments

| Argument | Description |
|----------|-------------|
| `device` | Path to the encrypted device or loop device |
| `name` | Name for the device-mapper entry |

## Examples

### Open a block device

```bash
# Unlock partition
sudo luks2 open /dev/sdb1 my-encrypted-disk

# The decrypted device is available at:
# /dev/mapper/my-encrypted-disk
```

### Open a file-based volume

```bash
# First, setup the loop device
sudo losetup -f --show myvolume.luks
# Returns: /dev/loop0

# Then unlock
sudo luks2 open /dev/loop0 myvolume

# Or use the library's loop device:
# If created with 'luks2 create', it may already be on a loop device
```

### After opening

```bash
# First-time setup: create filesystem
sudo mkfs.ext4 /dev/mapper/myvolume

# Mount the volume
sudo luks2 mount myvolume /mnt/encrypted

# Use the encrypted storage
ls /mnt/encrypted
```

## Workflow

```
Encrypted Device ──> Unlock ──> /dev/mapper/<name>
     │                  │              │
  /dev/sdb1        Passphrase    Decrypted Access
```

## Passphrase

- Prompts for passphrase with hidden input
- Passphrase is cleared from memory after use
- Failed attempts return an error

## Device Mapper

When unlocked, the volume appears as:

```
/dev/mapper/<name>
```

This device can be:
- Formatted with a filesystem (first time only)
- Mounted to a directory
- Used as a raw block device

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (wrong passphrase, device not found, already unlocked) |

## Troubleshooting

### "device not found"

```bash
# Verify device exists
ls -l /dev/sdb1

# For files, setup loop device first
sudo losetup -f --show myvolume.luks
```

### "master key verification failed"

- Verify caps lock is off
- Try typing passphrase in a text editor first
- `luks2 open` takes only a device and a name; it scans every keyslot itself,
  so there is no keyslot to choose

This message does **not** prove the passphrase is wrong, and the command does
not claim it does. A LUKS2 keyslot is unwrapped with an unauthenticated cipher,
so the same failure arises from key material the *correct* passphrase can no
longer decrypt. If the volume was working recently, suspect corruption before
concluding the credential was mistyped.

### "no valid keyslots"

The header carries no keyslot this implementation can try — either none at all,
or only ones of a type it does not open, such as a container left partway
through a reencryption. **No passphrase will open it.** This is a header
problem, not a credential problem, and retyping the passphrase cannot help.

### "invalid keyslot" / "invalid LUKS header"

A keyslot, or the header itself, is malformed: a keyslot with no KDF object, an
area that does not parse, a keyslot no digest authenticates. The passphrase may
well be correct; the container cannot evaluate it.

### "volume already unlocked"

```bash
# Check existing mappings
sudo dmsetup ls

# Close existing mapping first
sudo luks2 close <name>
```

## See Also

- [close](close.md) - Lock the volume
- [mount](mount.md) - Mount after opening
- [create](create.md) - Create new volumes
