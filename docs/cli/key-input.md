# Key input

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

Every command that needs a passphrase can run without a terminal, so `luks2`
works from scripts, systemd units and timers.

```
luks2 <command> [--key-file <path>] ...       # the existing passphrase
luks2 <command> [--new-key-file <path>] ...   # addkey, changekey: the new one
```

| Invocation | Passphrase |
|---|---|
| `--key-file <path>` | The whole file, trailing newline included |
| `--key-file -` | All of standard input, trailing newline included |
| no flag, stdin is a pipe | The first line of stdin, without its newline |
| no flag, stdin is a terminal | Prompt, input hidden |

`--key-file` wins even when a terminal is attached. An empty path
(`--key-file ""`, or a variable that expanded to nothing) is refused rather
than falling back to stdin or the terminal. `recovery verify` takes no
`--key-file`; see [recovery](recovery.md#verify).

## The trailing newline

A key file's newline is part of the passphrase, as in cryptsetup. This is the
usual reason a key file "does not work":

```bash
echo secret > /etc/luks/backup.key       # passphrase is "secret\n"
printf %s secret > /etc/luks/backup.key  # passphrase is "secret"
```

A piped passphrase without `--key-file` stands in for typing, so the newline
ends it:

```bash
printf %s 'my passphrase' | luks2 open --key-file - /dev/sdb1 backup
echo 'my passphrase'      | luks2 open /dev/sdb1 backup
```

Every other byte is content, spaces and NUL included.

## Limits

A credential that opens an existing keyslot may be 1 byte to 8 MiB, as with
cryptsetup, so a 4 KiB key file or a short legacy passphrase works. A new
passphrase (`create`, and the new credential of `addkey` and `changekey`) must
be 8 to 512 bytes. A key file over 8 MiB is refused while it is read, with
`key file is too large`.

## Confirmation

A new passphrase typed at a terminal is asked for twice and compared in
constant time. One from a file or pipe is not confirmed, as with
`cryptsetup --batch-mode`. For `addkey` and `changekey`, a missing
`--new-key-file` means the new passphrase comes from stdin or the terminal by
the table above.

## Unattended backup

```bash
#!/bin/sh
set -eu
KEY=/etc/luks/backup.key   # mode 0400, root-owned

luks2 open --key-file "$KEY" /dev/sdb1 backup
trap 'luks2 unmount /mnt/backup; luks2 close backup' EXIT
luks2 mount backup /mnt/backup
rsync -a --delete /srv/ /mnt/backup/srv/
```

There is no `--passphrase` option, because command-line arguments and the
environment are readable by other processes.
