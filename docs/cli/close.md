# luks2 close

Lock a LUKS2 encrypted volume.

## Synopsis

```
luks2 close <name>
```

## Description

The `close` command locks a previously unlocked LUKS2 volume by removing its device-mapper entry. After closing, the encrypted data is no longer accessible until the volume is opened again.

**Important**: The volume must be unmounted before closing.

## Arguments

| Argument | Description |
|----------|-------------|
| `name` | Name of the device-mapper entry (from `open` command) |

## Examples

### Close a volume

```bash
# Close the volume
sudo luks2 close my-encrypted-disk

# Verify it's closed
ls /dev/mapper/my-encrypted-disk
# Should return: No such file or directory
```

### Complete cleanup workflow

```bash
# 1. Unmount first
sudo luks2 unmount /mnt/encrypted

# 2. Close the volume
sudo luks2 close myvolume

# 3. (Optional) Detach loop device for file volumes
sudo losetup -d /dev/loop0
```

## Pre-requisites

Before closing, ensure:
1. Volume is not mounted
2. No processes are using the device
3. All file handles are closed

## Error Handling

### "Volume is still mounted"

```bash
# Unmount first
sudo luks2 unmount /mnt/encrypted

# Or check mount points
mount | grep myvolume

# Force unmount if necessary (use with caution)
sudo umount -l /mnt/encrypted
```

### "Device is busy"

```bash
# Find processes using the device
sudo lsof /dev/mapper/myvolume

# Or use fuser
sudo fuser -m /dev/mapper/myvolume
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (still mounted, device busy, not found) |

## See Also

- [open](open.md) - Unlock the volume
- [unmount](unmount.md) - Unmount before closing
