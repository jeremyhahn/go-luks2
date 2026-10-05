# luks2 CLI reference

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

`luks2` creates, opens and manages LUKS2 volumes. It is a thin layer over
[`pkg/luks2`](../luks/README.md).

```bash
go install github.com/jeremyhahn/go-luks2/cmd/luks2@latest
# or, from a checkout
make build && sudo cp build/luks2 /usr/local/bin/
```

## Commands

| Command | Does |
|---|---|
| [create](create.md) | Format a block device, or create, format, open and mkfs a file volume |
| [open](open.md) | Unlock a volume to `/dev/mapper/<name>` |
| [close](close.md) | Remove the mapping |
| [mount](mount.md), [unmount](unmount.md) | Mount an open volume as ext4; unmount it |
| [info](info.md) | Show the volume summary |
| [wipe](wipe.md) | Destroy the header copies, or overwrite the whole device |
| [keyslots, testkey, addkey, changekey, removekey, killslot](keyslots.md) | Manage passphrases |
| [recovery generate, add, verify](recovery.md) | Recovery keys |
| [token ...](token.md) | Read and edit header tokens |
| [header show, secondary, restore; isluks](header.md) | Inspect and repair the header copies |
| `help`, `--help`, `-h` | Print usage (exit 0) |
| `version`, `--version`, `-v` | Print the version (exit 0) |

## Rules for every command

- Paths must be absolute. The library refuses a relative device or file
  path with `invalid device path`. Key files and output files may be relative.
- Root is needed to create a mapping, a loop device or a mount, and to
  write a block device. `info`, `keyslots`, `testkey`, the keyslot and token
  edits, and `header` work on a file you own without root.
- Passphrases are 8 to 512 bytes. Without a terminal, use `--key-file`;
  see [key input](key-input.md).
- Options take `--name value` or `--name=value`, before or after the
  positional arguments. An unknown option is refused rather than read as a
  path. `close`, `mount`, `unmount`, `info` and `wipe` parse their own
  arguments; see each page.
- The exit status is 0 on success and 1 on any failure, including bad
  arguments and missing arguments (which also print the command's usage). The
  exceptions, where 1 is an answer rather than a failure, are `isluks`,
  `token exists` and `recovery verify`. A canceled `wipe` or `header restore`
  exits 0.
- The destructive commands, `wipe` and `header restore`, read `YES` from
  standard input. Anything else cancels.

## Typical session

```bash
sudo luks2 create /srv/secret.luks 1G          # opens as luks-auto, runs mkfs.ext4
sudo luks2 mount luks-auto /mnt/secret
sudo luks2 unmount /mnt/secret
sudo luks2 close luks-auto
sudo losetup -d /dev/loop0                      # the loop device create attached

# Later
sudo losetup -f --show /srv/secret.luks         # prints e.g. /dev/loop0
sudo luks2 open /dev/loop0 secret
sudo luks2 mount secret /mnt/secret
```
