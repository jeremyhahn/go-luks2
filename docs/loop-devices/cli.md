# Loop devices — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (3da0ff2)
> Conflicts with this document are defects. Fix them here first.

No verb of its own: there is no `luks2 loop` command group, and no flag
selects or configures a loop device. One verb reaches this feature, and two
more are documented here for how they treat a loop device.

| Verb | Uses a loop device | Documented in |
|---|---|---|
| `create <path> <size> [filesystem]` (file volume) | Attaches one, and detaches it again on a failure | [volumes/cli.md](../volumes/cli.md#file-volume) |
| `open <device> <name>` | Takes one, never attaches it; an image file is refused | [volumes/cli.md](../volumes/cli.md#open) |
| `close <name>` | Never detaches one | [volumes/cli.md](../volumes/cli.md#close) |

Exit statuses follow [volumes/cli.md](../volumes/cli.md#exit-status). No
loop-device error has a row of its own, so each exits 1. Root is required.

## create (file volume)

```
luks2 create [--key-file <path>] [KDF options] <path> <size> [filesystem]
```

After formatting `<path>`, `create` attaches it to a free loop device, opens
the device as `/dev/mapper/luks-auto` and makes the filesystem on the mapping.
On success the loop device stays attached, holding the open volume.

```bash
sudo luks2 create /srv/data.luks 1G
sudo luks2 mount luks-auto /mnt/encrypted
# later
sudo luks2 unmount /mnt/encrypted
sudo luks2 close luks-auto
sudo losetup -j /srv/data.luks          # shows the device, e.g. /dev/loop0
sudo losetup -d /dev/loop0
```

| Failure | What is printed | Status |
|---|---|---|
| The attach fails | `Failed to set up a loop device for <path>: …`, then the `losetup -f --show <path>` to finish by hand. The formatted file is kept. | 1 |
| Opening, unlocking or activating on the loop device fails | `Failed to open /dev/loopN: …`, then `Detached loop device /dev/loopN.` or, if that detach failed, the error and `Detach it with: losetup -d /dev/loopN` | The open failure's own status |
| `mkfs` fails | The mkfs error. `luks-auto` is closed and then the loop device detached (not attempted if the close failed); a failed step prints its error and the `luks2 close` or `losetup -d` command to finish | The mkfs failure's status |

A detach the kernel deferred because something still holds the device counts
as detached: the kernel releases it when the last user goes away.

## open

```
luks2 open [--key-file <path>] <device> <name>
```

`<device>` may be a loop device. An image file is refused with `not a block
device`; attach it first:

```bash
sudo losetup -f --show /srv/data.luks   # prints e.g. /dev/loop0
sudo luks2 open /dev/loop0 data
```

## close

`luks2 close <name>` removes the mapping only. A loop device under it, whether
`create` attached it or you did, stays attached until `losetup -d`.
