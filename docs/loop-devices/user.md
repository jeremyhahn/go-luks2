# Loop devices — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (3da0ff2)
> Conflicts with this document are defects. Fix them here first.

A loop device makes a file look like a disk. You need one to open a LUKS2
volume kept in an image file, because the kernel's encryption layer works on
disks only.

Prerequisites: root, and a kernel with loop support (`/dev/loop-control`
exists). In a container, the container also needs access to
`/dev/loop-control` and to the loop devices themselves.

## Create an encrypted file and use it

```bash
sudo luks2 create /srv/data.luks 1G     # formats, attaches, opens as luks-auto, makes ext4
sudo luks2 mount luks-auto /mnt/encrypted
```

The loop device is attached for you and stays attached while the volume is
open.

## Close it and release the loop device

```bash
sudo luks2 unmount /mnt/encrypted
sudo luks2 close luks-auto
sudo losetup -j /srv/data.luks          # e.g. /dev/loop0: ... (/srv/data.luks)
sudo losetup -d /dev/loop0
```

`luks2 close` does not detach the loop device; `losetup -d` does.

## Open an existing encrypted file

```bash
sudo losetup -f --show /srv/data.luks   # prints e.g. /dev/loop0
sudo luks2 open /dev/loop0 data
sudo luks2 mount data /mnt/data
```

`luks2 open` on the file itself is refused with `not a block device`.

## Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| `create` prints `Failed to set up a loop device` | No free loop device, no access to `/dev/loop-control`, or not root | Fix the cause, then `losetup -f --show <file>` and `luks2 open` it; the formatted file is kept |
| The error says the allocated device's node did not appear under `/dev` | The kernel gave out a loop device but nothing created its `/dev` entry; common in containers past the first few devices | Make sure devtmpfs or udev creates device nodes where `luks2` runs, or detach loop devices you no longer use |
| `open` says `not a block device` | You passed the image file | Attach it with `losetup -f --show` and open the loop device |
| A detach error says the detach did not become observable, and something else still holds the device open | A mount, a mapping or another process still uses the loop device | Unmount and close what is on it, then `losetup -d` |
| A detach error says the device's state was unreadable | `/sys/block` could not be read | Check that sysfs is mounted and readable |
| A detach error says the device is now attached to a different file | The loop device was released and reused by someone else | Nothing to do: your file is no longer attached. Do not detach the other file's device |
| `losetup -d` returns but the device is still listed | Something still holds it; the kernel detaches it when the last user goes | Find and close the holder (`lsblk`, `dmsetup ls`) |
