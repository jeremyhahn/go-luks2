# Filesystems — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8
> Conflicts with this document are defects. Fix them here first.

The `luks2` CLI reaches `pkg/filesystem` in three places. The verbs are defined
in [volumes/cli.md](../volumes/cli.md); this page states what each does with the
filesystem package.

| Verb | Calls | Detail |
|---|---|---|
| `luks2 create <path> <size> [ext4\|xfs\|vfat]` (file volume) | `Make` | Runs `mkfs.ext4`, `mkfs.xfs` or `mkfs.fat` on the new mapping, with the label if one was given. Only `Label` is set, so every other `MakeParams` field takes its default. `zfs` is not offered: it needs a pool name. |
| `luks2 mount [-t <fstype>] [--allow-suid] [--allow-dev] <name> <mountpoint>` | `Mount`, `IsMounted`, `Detect` | Without `-t`, the type is what `blkid -p` finds on the mapping. Nothing found, more than one signature or a non-filesystem is refused with exit 1. Mounts with `nosuid,nodev`. A mountpoint that is already a mount point is refused by the CLI. |
| `luks2 unmount <mountpoint>` | `Unmount`, `IsMounted` | No flags, so no `Force`, `Detach` or `Expire`. A path `/proc/mounts` does not list as a mount point is refused. |
| `luks2 close <name>` | `DeviceMounted` | Refuses while a filesystem on the mapping is mounted. |

```bash
sudo luks2 create /srv/data.luks 1G xfs
sudo luks2 mount data /mnt/data
sudo luks2 unmount /mnt/data
```

A block-device `create` formats LUKS2 only and makes no filesystem; run
`mkfs.<type>` on `/dev/mapper/<name>` yourself after `open`.

## No CLI

These operations have no verb. Reach them from the Go API, or run the
underlying tool yourself:

| Operation | Library call | By hand |
|---|---|---|
| Check | `filesystem.Check` | `e2fsck -n`, `xfs_repair -n`, `fsck.fat -n`, `zpool scrub` |
| Repair | `filesystem.Repair` | `e2fsck -p`, `xfs_repair`, `fsck.fat -a` |
| Inspect | `filesystem.Inspect` | `blkid -o export <device>` |
| Make with options (journal size, ZFS pool, ...) | `filesystem.Make` with `MakeParams` | `mkfs.*`, `zpool create` |
| Detect on its own | `filesystem.Detect` | `blkid -p <device>` |

Every verb above needs root, and needs the tools it runs to be installed: see
[user.md](user.md#requirements). The CLI is embedded only; there is no server
and no transport selection.
