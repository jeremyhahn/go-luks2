# luks2 mount

Mount an unlocked LUKS2 volume.

## Synopsis

```
luks2 mount <name> <mountpoint>
```

## Description

The `mount` command mounts an unlocked LUKS2 volume to a directory, making the encrypted filesystem accessible. The volume must be opened (unlocked) first.

If the mountpoint directory doesn't exist, it will be created automatically.

## Arguments

| Argument | Description |
|----------|-------------|
| `name` | Name of the unlocked volume (device-mapper name) |
| `mountpoint` | Directory to mount the volume to |

## Examples

### Basic mount

```bash
# Mount to /mnt/encrypted
sudo luks2 mount myvolume /mnt/encrypted

# Access files
ls /mnt/encrypted
```

### Mount to custom location

```bash
# Create and mount to home directory
sudo luks2 mount myvolume ~/secure-data
```

### Complete workflow

```bash
# 1. Open the volume
sudo luks2 open /dev/sdb1 myvolume

# 2. Mount (creates mountpoint if needed)
sudo luks2 mount myvolume /mnt/encrypted

# 3. Use the encrypted storage
cp important-files/* /mnt/encrypted/

# 4. Cleanup
sudo luks2 unmount /mnt/encrypted
sudo luks2 close myvolume
```

## Filesystem Type

The `mount` command defaults to `ext4`. If your volume uses a different filesystem, you may need to use the system `mount` command directly:

```bash
# For XFS
sudo mount -t xfs /dev/mapper/myvolume /mnt/encrypted

# For ext3
sudo mount -t ext3 /dev/mapper/myvolume /mnt/encrypted
```

## Auto-created Mountpoints

If the mountpoint doesn't exist, it's created with:
- Permissions: 0750 (rwxr-x---)
- Owner: root

## Error Handling

### "Mountpoint already in use"

```bash
# Check what's mounted
mount | grep /mnt/encrypted

# Unmount existing
sudo luks2 unmount /mnt/encrypted
```

### "No filesystem found"

The volume needs a filesystem. Create one first:

```bash
# Create ext4 filesystem
sudo mkfs.ext4 /dev/mapper/myvolume

# Then mount
sudo luks2 mount myvolume /mnt/encrypted
```

### "Volume not unlocked"

```bash
# Open the volume first
sudo luks2 open /dev/sdb1 myvolume

# Then mount
sudo luks2 mount myvolume /mnt/encrypted
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (already mounted, no filesystem, volume not open) |

## See Also

- [unmount](unmount.md) - Unmount the volume
- [open](open.md) - Open volume before mounting
- [create](create.md) - Create with automatic filesystem
