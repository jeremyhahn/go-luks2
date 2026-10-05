# luks2 close

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

```
luks2 close <name>
```

Removes `/dev/mapper/<name>`. It does not detach a loop device; use
`losetup -d` for that.

```bash
sudo luks2 unmount /mnt/backup
sudo luks2 close backup
```

Unmount first. Before closing, the command asks whether `/dev/mapper/<name>`
is listed as a mount point in `/proc/mounts`. A device path never is, so this
check does not catch a mounted volume. Closing a mounted volume reaches
device-mapper, which reports the target busy; `close` retries for 3 seconds and
then fails with `device-mapper target is held open` and hints for finding the
holder. If `/proc/mounts` cannot be read, it refuses to close.

A name with no mapping fails with `volume not unlocked`.
