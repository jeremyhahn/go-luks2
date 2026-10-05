# luks2 unmount

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

```
luks2 unmount <mountpoint>
```

Unmounts `<mountpoint>` with no flags. It refuses a path that `/proc/mounts`
does not list as a mount point. If the kernel says the mount is busy, find the
holder with `fuser -mv <mountpoint>`; the command suggests `umount -l` as a
last resort.

```bash
sudo luks2 unmount /mnt/backup
sudo luks2 close backup
```
