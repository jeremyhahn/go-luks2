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

Unmount first. `close` refuses while a filesystem on the mapping is mounted,
whatever path it was mounted through: it compares the mapping's device number
with the mounts in `/proc/self/mountinfo`. If that cannot be read, it refuses
to close. A holder it cannot see, such as a ZFS pool, makes device-mapper
report the target busy; `close` retries for 3 seconds and then fails with
`device-mapper target is held open` and hints for finding the holder.

A name with no mapping fails with `volume not unlocked`.
