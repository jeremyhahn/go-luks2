# Filesystems — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8
> Conflicts with this document are defects. Fix them here first.

How to put a filesystem on an unlocked volume, mount it and take it down again.
The commands are in [cli.md](cli.md).

## Requirements

- Root.
- The tools for the filesystem you use, installed in a standard system
  directory (`/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`, `/usr/local/sbin` or
  `/usr/local/bin`) and not writable by anyone but root:

| For | Install |
|---|---|
| ext4 | `mkfs.ext4`, `e2fsck` (e2fsprogs) |
| xfs | `mkfs.xfs`, `xfs_repair` (xfsprogs) |
| vfat | `mkfs.fat`, `fsck.fat` (dosfstools) |
| zfs | `zpool`, `zfs` (zfs-utils) |
| Any `mount` without `-t` | `blkid` (util-linux) |

A tool somewhere else, or one that another user could have replaced, is refused
rather than run, and the tool search path is not taken from your environment.

## First run

```bash
sudo luks2 create /srv/data.luks 1G          # LUKS2 volume with ext4, opened and left open as luks-auto
sudo luks2 mount luks-auto /mnt/data
sudo luks2 unmount /mnt/data
sudo luks2 close luks-auto
```

`create` on a file picks `ext4`, `xfs` or `vfat`; `zfs` is not offered. On a
block device it formats LUKS2 only; open it and run `mkfs.<type>` on
`/dev/mapper/<name>` yourself.

## Common tasks

| Task | How |
|---|---|
| Mount a volume | `sudo luks2 mount <name> <mountpoint>`. The type is detected; pass `-t <type>` to name it. |
| Allow setuid files or device nodes | `--allow-suid`, `--allow-dev`. Both are off by default. |
| Unmount | `sudo luks2 unmount <mountpoint>`, before `luks2 close`. |
| Check or repair a filesystem | No verb. Unmount, then run `e2fsck`, `xfs_repair` or `fsck.fat` on `/dev/mapper/<name>`. |
| Look up a type, label or UUID | `blkid /dev/mapper/<name>` |

## Troubleshooting

| You see | Cause | Do |
|---|---|---|
| `carries no signature blkid recognizes` | No filesystem on the mapping | Make one with `mkfs.<type>` |
| `carries more than one filesystem signature` | Old signatures remain from an earlier format | Pass `-t <type>` |
| `which is not a mountable filesystem`, naming LUKS, swap, RAID or LVM | The mapping holds something else | Check you opened the right device |
| `was not found in any of ...`, or `... so it could have been replaced` (owned by another user, or writable by group or others) | A tool is missing, or in a place or with permissions the library does not trust | Install the package; fix ownership and mode so only root can write the tool and its directories |
| `mount point ... does not exist` from the library | Target directory missing (the CLI creates it for you) | Create it |
| `Not mounted: <mountpoint>` on unmount | Nothing is mounted there | Check the path with `findmnt` |
| Unmount fails as busy | A process holds the filesystem | Find it with `fuser -mv <mountpoint>`; `umount -l` is the last resort |
