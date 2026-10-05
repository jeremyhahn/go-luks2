# luks2 mount

> **Status: REFERENCE** · Last verified: 2026-10-05 against v0.3.1-alpha

```
luks2 mount [--type | -t <fstype>] <name> <mountpoint>
```

Mounts `/dev/mapper/<name>` on `<mountpoint>`, with no options. The type is
`--type` (or `-t`) if given, otherwise what `blkid -p` finds on the mapping.
Nothing found, more than one signature, or something that is not a filesystem
(another LUKS container, swap) is refused with exit 1 rather than guessed. For
mount options, use `mount(8)`:

```bash
sudo luks2 mount backup /mnt/backup          # detects ext4, xfs, vfat, ...
sudo luks2 mount -t xfs data /mnt/data
```

A missing mountpoint is created with mode 0750. The command refuses a
mountpoint that is already a mount point, and fails if no mapping named
`<name>` exists. An empty `--type`, or `--type` and `-t` naming different
types, is a usage error.
