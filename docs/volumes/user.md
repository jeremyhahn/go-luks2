# Volumes — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

## Prerequisites

- Linux, with device-mapper and the kernel keyring available. Root is needed
  to create a mapping, a loop device or a mount; reading a header or managing
  keyslots on a file you own is not.
- Inside a container, the keyring syscalls (`add_key`, `keyctl`,
  `request_key`) must be allowed by seccomp; Docker's default profile denies
  them.
- `go install github.com/jeremyhahn/go-luks2/cmd/luks2@latest`, or build from
  a checkout with `make build`.

## First run: encrypt a file as a volume

```bash
sudo luks2 create /srv/secret.luks 1G
# prompts for a passphrase (twice), formats, attaches a loop device,
# opens it as luks-auto, and runs mkfs.ext4
sudo luks2 mount luks-auto /mnt/secret
```

Write to `/mnt/secret`, then tear down in reverse order:

```bash
sudo luks2 unmount /mnt/secret
sudo luks2 close luks-auto
sudo losetup -d /dev/loop0   # the loop device create attached
```

## Common tasks

### Reopen an existing volume

```bash
sudo losetup -f --show /srv/secret.luks   # prints e.g. /dev/loop0
sudo luks2 open /dev/loop0 secret
sudo luks2 mount secret /mnt/secret
```

### Format a block device directly, without a loop device

```bash
sudo luks2 create /dev/sdb1
sudo luks2 open /dev/sdb1 backup
sudo mkfs.ext4 /dev/mapper/backup
```

### Run unattended, from a script or systemd unit

Use `--key-file` instead of a terminal prompt:

```bash
#!/bin/sh
set -eu
KEY=/etc/luks/backup.key   # mode 0400, root-owned

luks2 open --key-file "$KEY" /dev/sdb1 backup
trap 'luks2 unmount /mnt/backup; luks2 close backup' EXIT
luks2 mount backup /mnt/backup
rsync -a --delete /srv/ /mnt/backup/srv/
```

There is no `--passphrase` option: command-line arguments and the environment
are readable by other processes. See [cli.md](cli.md#key-input) for every
other way to supply a passphrase without a terminal.

### Check whether a passphrase still works, without unlocking

```bash
sudo luks2 testkey --key-file /etc/luks/backup.key /dev/sdb1
```

Detail: [keyslots/cli.md](../keyslots/cli.md#testkey).

## Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| `open` fails with `master key verification failed` | Wrong passphrase, or damaged key material (the two look the same) | Try the passphrase again; if certain it is right, check with another keyslot or a recovery key ([recovery-keys](../recovery-keys/user.md)) |
| `open` fails with `kernel keyring` | Keyring syscalls blocked or unsupported | Inside a container, allow `add_key`/`keyctl`/`request_key` in seccomp |
| `close` fails with `device-mapper target is held open` | Something still has the mapping open (a mount, a ZFS pool) | Find the holder; `fuser -mv <mountpoint>` if it was mounted |
| `mount` refuses with "carries no signature blkid recognizes" or "carries more than one filesystem signature" | `blkid` could not pick one filesystem type | With no signature, make a filesystem first; otherwise pass `--type`/`-t` explicitly |
| A key file "does not work" though the text looks right | The trailing newline from `echo` is part of the passphrase | Use `printf %s` instead of `echo` when writing the key file, or know that `create` wrote the passphrase with the newline it was given — see [cli.md](cli.md#the-trailing-newline) |
| `create` on a block device refuses, naming a filesystem or LUKS signature | The device already holds data | Confirm it is the right device, then `--force` |

For a failure not in this table, [cli.md](cli.md#failures) under `open` lists
every message `luks2 open` can print and what it means.
