# Non-interactive key input

Every `luks2` command that needs a passphrase can take one without a terminal.
This is what makes the tool usable from a script, a systemd unit or a timer —
an unattended backup that unlocks a target, writes to it and locks it again.

## Synopsis

```
luks2 <command> [--key-file <path>] ...
luks2 <command> [--new-key-file <path>] ...   # commands that set a new passphrase
```

## The three sources

| How it is invoked | Where the passphrase comes from |
|---|---|
| `--key-file <path>` | **The whole file**, trailing newline included |
| `--key-file -` | **The whole of standard input**, trailing newline included |
| No flag, standard input is a pipe | **The first line** of standard input, without its newline |
| No flag, standard input is a terminal | The interactive prompt |

`--key-file` wins over a terminal. An operator who names a key file has said
where the credential is, and prompting anyway would hang a unit that happens to
have a terminal attached.

## The trailing newline

**A key file's newline is part of the passphrase.** This is cryptsetup's rule
and this tool matches it exactly, so a key file works the same way with both
tools.

It is the most common way a key file "does not work":

```bash
# WRONG -- echo appends a newline, so the passphrase is "secret\n"
echo secret > /etc/luks/backup.key

# RIGHT -- printf writes exactly what you asked for
printf %s secret > /etc/luks/backup.key
```

If the volume was created interactively with the passphrase `secret`, only the
second file opens it.

A piped passphrase with **no** `--key-file` follows the opposite rule, because
it is standing in for typing: the first line is the passphrase, the newline
ends it, and anything after it is ignored.

```bash
# Both of these unlock a volume whose passphrase is "secret"
printf %s secret | luks2 open --key-file - /dev/sdb1 backup
echo secret      | luks2 open              /dev/sdb1 backup
```

Other content is passed through untouched. Spaces are content. A NUL byte is
content: a key file holding `abc\0def` is a seven-byte passphrase, the same as
it is for cryptsetup.

## Limits

* A key file may be at most **8 MiB**, which is cryptsetup's own bound.
* An **empty** key file is refused. cryptsetup accepts one and fails later with
  the same message a wrong passphrase produces; an empty key file is almost
  always a path that does not hold what the operator thinks it holds.

## Two credentials

`addkey` and `changekey` need two passphrases: one to authenticate with and one
to install. They are separate options, and a script must give both — being
prompted for the second one is what hangs a unit.

```bash
luks2 addkey --key-file /etc/luks/current.key \
             --new-key-file /etc/luks/next.key /dev/sdb1
```

## Confirmation

A new passphrase typed at a terminal is asked for twice and the two are
compared in constant time. A passphrase from a key file or a pipe is **not**
confirmed: re-reading the same bytes proves nothing, and a pipe has no second
line. `cryptsetup --batch-mode` makes the same choice.

## Example: an unattended backup

```bash
#!/bin/sh
set -eu

KEY=/etc/luks/backup.key   # mode 0400, root-owned

luks2 open --key-file "$KEY" /dev/sdb1 backup
trap 'luks2 unmount /mnt/backup; luks2 close backup' EXIT

luks2 mount backup /mnt/backup
rsync -a --delete /srv/ /mnt/backup/srv/
```

Nothing in it needs a terminal, and the passphrase never appears in a process
argument or in the environment — both of which are readable by other processes
on the machine, which is why there is no `--passphrase` option and will not be
one.

## See Also

- [open](open.md) — unlocking a volume
- [keyslots](keyslots.md) — adding, changing and revoking credentials
- [recovery](recovery.md) — recovery keys
