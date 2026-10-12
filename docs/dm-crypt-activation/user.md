# dm-crypt activation — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8
> Conflicts with this document are defects. Fix them here first.

Opening a LUKS2 volume gives you a plaintext device at `/dev/mapper/<name>`;
closing it removes that device. The volume's data stays encrypted on disk
throughout.

## Prerequisites

- Root. Creating a mapping is a kernel device-mapper operation.
- A block device or loop device holding a LUKS2 volume. For a plain file, attach
  a loop device first: `sudo losetup -f --show /srv/data.luks`.
- A kernel with the keyring syscalls. Inside a container, a seccomp profile that
  allows them: Docker's default denies them.
- The passphrase, from a terminal prompt, a pipe or `--key-file`.

## First run

```bash
sudo luks2 open /dev/sdb1 backup      # asks for the passphrase
ls -l /dev/mapper/backup
sudo luks2 close backup
```

Names start with a letter or digit and may then use letters, digits and
`_ . + -`, up to 127 characters.

## Common tasks

**Open without a terminal.** Use a key file or a pipe; see
[key input](../volumes/cli.md#key-input).

```bash
sudo luks2 open --key-file /etc/luks/backup.key /dev/sdb1 backup
```

**Use the mapping.** Make a filesystem on it or mount one that is already
there; see [volumes/user.md](../volumes/user.md).

**Close it.** Unmount first, then close:

```bash
sudo luks2 unmount /mnt/backup
sudo luks2 close backup
```

**Check at startup that a service can open volumes.** A program built on the
library can run the keyring preflight once during start-up, so a container
without the keyring syscalls fails when it starts rather than at the first
open. See [api.md](api.md).

## Troubleshooting

| What you see | Cause and fix |
|---|---|
| `invalid device-mapper mapping name` | The name has a character outside letters, digits and `_ . + -`, starts with something else, is `.`, `..` or `control`, or is over 127 bytes. Choose another. |
| `mapping is already active` | The name is in use. `luks2 close` it, or pick another name. |
| `could not … keyring` error naming syscalls or a quota | The keyring is blocked (container seccomp profile), unsupported by the kernel, or out of quota. The message names the remedy; allow the syscalls in the container profile, or free keys. |
| `master key verification failed` | Wrong passphrase, or the header changed since the key was checked. Try again. |
| `mapping is not active` on close | Nothing is open under that name. It may already be closed. |
| `device-mapper target is held open` on close | Something is using the mapping. Unmount it and stop programs using it; the message names `lsof`, `mount` and `dmsetup info -c` to find the holder. `dmsetup remove --deferred <name>` removes it when it frees. |
| `may still be live` on open | The open failed and the cleanup could not confirm the plaintext mapping is gone. Run `sudo luks2 close <name>` and check `dmsetup info <name>`. |

For header, keyslot and passphrase problems, see
[volumes/user.md](../volumes/user.md).
