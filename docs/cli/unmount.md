# luks2 unmount

Unmount a LUKS2 volume.

## Synopsis

```
luks2 unmount <mountpoint>
```

## Description

The `unmount` command unmounts a previously mounted LUKS2 volume. After unmounting, the volume can be closed (locked) safely.

## Arguments

| Argument | Description |
|----------|-------------|
| `mountpoint` | Directory where the volume is mounted |

## Examples

### Basic unmount

```bash
# Unmount the volume
sudo luks2 unmount /mnt/encrypted
```

### Complete cleanup

```bash
# 1. Unmount
sudo luks2 unmount /mnt/encrypted

# 2. Close (lock) the volume
sudo luks2 close myvolume

# 3. (Optional) Detach loop device
sudo losetup -d /dev/loop0
```

## Pre-requisites

Before unmounting, ensure:
1. No processes are accessing files in the mountpoint
2. Current directory is not within the mountpoint
3. No open file handles

## Error Handling

### "Device is busy"

Some process is using files in the mounted volume:

```bash
# Find processes using the mount
sudo lsof +D /mnt/encrypted

# Or use fuser
sudo fuser -m /mnt/encrypted

# Show which processes
sudo fuser -mv /mnt/encrypted
```

### "Not mounted"

The path is not a mount point:

```bash
# Check current mounts
mount | grep encrypted

# Verify correct path
df -h /mnt/encrypted
```

### Force unmount (use with caution)

If the normal unmount fails:

```bash
# Lazy unmount - detaches immediately, cleans up when not busy
sudo umount -l /mnt/encrypted

# Force unmount - may cause data loss
sudo umount -f /mnt/encrypted
```

## Best Practices

1. **Save all files** before unmounting
2. **Close applications** that access the volume
3. **Change directory** out of the mountpoint
4. **Sync filesystems** before unmounting:
   ```bash
   sync
   sudo luks2 unmount /mnt/encrypted
   ```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (not mounted, device busy) |

## See Also

- [mount](mount.md) - Mount the volume
- [close](close.md) - Lock after unmounting
