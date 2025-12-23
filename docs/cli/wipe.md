# luks2 wipe

Securely wipe a LUKS2 volume.

## Synopsis

```
luks2 wipe <device>
```

## Description

The `wipe` command securely destroys a LUKS2 volume by overwriting the header area. This makes the encrypted data permanently inaccessible, even if the passphrase is known.

**WARNING**: This operation is irreversible. All data will be permanently lost.

## Arguments

| Argument | Description |
|----------|-------------|
| `device` | Path to the LUKS2 device or file to wipe |

## Examples

### Wipe a block device

```bash
# Wipe LUKS headers (makes data unrecoverable)
sudo luks2 wipe /dev/sdb1

# You will be prompted to type 'YES' to confirm
```

### Wipe a file volume

```bash
sudo luks2 wipe myvolume.luks
```

## Confirmation

The command requires explicit confirmation:

```
*** WARNING: DESTRUCTIVE OPERATION ***

This will PERMANENTLY DESTROY all data on: /dev/sdb1
This action CANNOT be undone!

Type 'YES' to confirm wipe: YES

Wiping LUKS headers...

Volume wiped successfully!

The device is no longer encrypted and cannot be unlocked.
```

## What Gets Wiped

The default wipe operation destroys:
- Primary LUKS2 header (first 16KB)
- Backup LUKS2 header
- All keyslot areas

This is sufficient to make the encrypted data unrecoverable because the master encryption key can no longer be derived.

## Security Considerations

### Header-only wipe (default)

- Fast operation (< 1 second)
- Destroys encryption keys
- Encrypted data remains on disk but is cryptographically inaccessible
- Suitable for most security requirements

### When to use full device wipe

For higher security requirements (not implemented in CLI, use library):

```go
// Full device wipe with multiple passes
luks2.Wipe(luks2.WipeOptions{
    Device:     "/dev/sdb1",
    Passes:     3,      // DOD standard
    Random:     true,   // Random data
    HeaderOnly: false,  // Wipe entire device
})
```

## Pre-requisites

Before wiping:
1. **Unmount** the volume
2. **Close** (lock) the volume
3. **Back up** any needed data
4. **Verify** the correct device

```bash
# Safety check - verify you're wiping the right device
sudo luks2 info /dev/sdb1

# Ensure it's not mounted
mount | grep sdb1

# Ensure it's not open
sudo dmsetup ls | grep sdb1
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success (or cancelled) |
| 1 | Error (wipe failed) |

## Recovery

**There is no recovery from a wipe operation.**

Once the headers are wiped:
- The volume cannot be unlocked
- The passphrase is useless
- The data is cryptographically destroyed

## See Also

- [info](info.md) - Verify device before wiping
- [close](close.md) - Close volume before wiping
