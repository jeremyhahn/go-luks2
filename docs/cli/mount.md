# luks2 mount

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

```
luks2 mount <name> <mountpoint>
```

Mounts `/dev/mapper/<name>` on `<mountpoint>` **as ext4**, with no options.
For any other filesystem, or for mount options, use `mount(8)`:

```bash
sudo luks2 mount backup /mnt/backup
sudo mount -t xfs /dev/mapper/data /mnt/data
```

A missing mountpoint is created with mode 0750. The command refuses a
mountpoint that is already a mount point, and fails if no mapping named
`<name>` exists. If the mount fails it suggests running `mkfs.ext4` on the
mapping, which is only right for a new, empty volume.
