# Volumes — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-12 against base/331 (a9c840c)
> Conflicts with this document are defects. Fix them here first.

`luks2` creates, opens, mounts and closes LUKS2 volumes. It is a thin layer
over `pkg/luks2` (library contract: [engineering.md](engineering.md)).

```bash
go install github.com/jeremyhahn/go-luks2/cmd/luks2@latest
# or, from a checkout
make build && sudo cp build/luks2 /usr/local/bin/
```

## Command index

Every `luks2` verb, by the feature folder that documents it:

| Command | Documented in |
|---|---|
| `create`, `open`, `close`, `mount`, `unmount`, `info` | here |
| `keyslots`, `testkey`, `addkey`, `changekey`, `removekey`, `killslot` | [keyslots/cli.md](../keyslots/cli.md) |
| `recovery generate`, `recovery add`, `recovery verify` | [recovery-keys/cli.md](../recovery-keys/cli.md) |
| `token list`, `show`, `export`, `import`, `remove`, `free`, `exists`, `count` | [tokens/cli.md](../tokens/cli.md) |
| `header show`, `header secondary`, `header restore`, `isluks` | [header/cli.md](../header/cli.md) |
| `wipe` | [wipe/cli.md](../wipe/cli.md) |
| `help`, `--help`, `-h` | Print usage (exit 0) |
| `version`, `--version`, `-v` | Print the version (exit 0) |

Every verb above has a `CommandDefinition` in the CLI parity suite
(`test/integration/cli/commands/`). A verb in one and not the
other is a defect in whichever is behind.

## Rules for every command

- A relative device or file path is resolved against the working directory
  before it reaches the library, which takes absolute paths only.
- Root is needed to create a mapping, a loop device or a mount, and to
  write a block device. `info`, `keyslots`, `testkey`, the keyslot and token
  edits, and `header` work on a file you own without root.
- New passphrases are 8 to 512 bytes; an existing one may be 1 byte to 8 MiB.
  Without a terminal, use `--key-file`; see [key input](#key-input), below.
- Options take `--name value` or `--name=value`, before or after the
  positional arguments. An unknown option is refused rather than read as a
  path. `close`, `unmount`, `info`, `keyslots`, the `token` verbs that take
  only a device and an id, and `header show` and `header secondary` take
  positional arguments only and do no option parsing; `mount` and every other
  verb use the shared option parser.
- The exit status is 0 on success and, on failure, one of the codes in
  [Exit status](#exit-status).
- The destructive commands, `wipe`, `header restore` and `create` on a block
  device, read `YES` from standard input. Any other answer, end of input or a
  read error cancels. `--batch-mode` (or `--yes`) skips the question.

## Exit status

The status follows cryptsetup(8) where the failures correspond. This is the
one table; the other command documents link here.

| Status | Meaning | Errors that give it |
|---|---|---|
| 0 | Success | |
| 1 | Wrong parameters, or any failure not listed below | Usage errors (bad, missing or unknown arguments, which also print the command's usage), a canceled confirmation (`wipe`, `header restore`, block-device `create`), invalid KDF options, and every error with no row of its own |
| 2 | No permission, or a bad passphrase | `ErrWrongKey`, `ErrInvalidCredential`, `ErrPermissionDenied`, and a new passphrase whose confirmation did not match |
| 3 | Out of memory | `ErrProtectedMemory`: locked memory could not be obtained |
| 4 | Wrong device | `ErrDeviceNotFound`, `ErrNotLUKS2`, `ErrInvalidHeader` |
| 5 | Exists or busy | `ErrDeviceInUse`, `ErrLockContended`, `dmcrypt.ErrActive` (`open` on a mapping name already in use), `dmcrypt.ErrBusy` (`close` on a mapping something still holds open) |

An error is matched through whatever wraps it, and the first row that matches
wins, in the order 2, 3, 4, 5. `dmcrypt.ErrStillLive` and `dmcrypt.ErrNotActive`
have no row and exit 1. Running `luks2` with no command, or with an
unknown command or group verb, prints the usage and exits 1. The table is
`exitTable` in `internal/cli/exit.go`, and `exitCode` applies it.

`SIGINT` and `SIGTERM` cancel the running command (`cmd/luks2/main.go` runs it
under `signal.NotifyContext`). A write in progress stops at its next consistent
step boundary ([engineering.md](engineering.md#cancellation)), and the command
exits with the resulting error's status, 1 for a cancellation.

Three verbs answer in their status:

- `isluks` exits 0 for yes and 1 for no, whatever the reason for the no. It
  never uses 2 to 5, so a device that cannot be opened or read is 1, not 4.
- `token exists` exits 0 if the token is present and 1 if it is absent. A
  device that cannot be opened or is not LUKS2 gives that error's own status
  from the table.
- `recovery verify` exits 0 if the key opens the volume and 2 if it does not
  (`ErrWrongKey`, the same as a wrong passphrase). Any other failure gives its
  own status.

## Transport

Embedded only (library calls and this CLI). No server mode, no `--local`
flag: there is no transport selection, because there is no transport other
than the Go API and this process. See [api.md](api.md).

## create

```
luks2 create [--key-file <path>] [KDF options] [--batch-mode | --yes] [--force]
             <path> [size] [filesystem]
```

A block device is formatted in place; a path that does not exist yet is a new
file volume. A relative path is resolved against the working directory. A path
under `/dev/` (other than `/dev/shm/`) that is not a block device is refused.

### Block device

Formats the device as LUKS2 and stops. `size` and `filesystem` are ignored.
Before anything is asked:

- A device the kernel reports in use (mounted, open as a mapping, held) is
  refused. The device stays claimed with `O_EXCL` through the questions and is
  released just before formatting.
- A device holding a LUKS header (either copy) or a filesystem, RAID, LVM or
  partition-table signature is refused, naming what was found. `--force`
  formats over it.

Then it asks you to type `YES`. Any other answer, end of input or a read error
exits 1. `--batch-mode` (or `--yes`) skips the question. `--key-file -` reads
standard input for the key, so it needs `--batch-mode`.

```bash
sudo luks2 create /dev/sdb1
sudo luks2 open /dev/sdb1 backup
sudo mkfs.ext4 /dev/mapper/backup
```

### File volume

```bash
sudo luks2 create /srv/data.luks 1G          # ext4
sudo luks2 create /srv/data.luks 500M xfs
```

`size` is required: a positive whole number with an optional `K`, `M`, `G` or
`T` suffix (powers of 1024, either case); no suffix means bytes. Anything else
(`1.5G`, `10x`, an overflowing value) is refused. `filesystem` is
`ext4` (default), `xfs` or `vfat`. `zfs` needs a pool name and is not offered.

Steps, in order:

1. Refuse an unsupported filesystem or an unparsable size.
2. Create the file at `size` (sparse), with `O_EXCL` and `O_NOFOLLOW`, mode
   0600. An existing file, or a symlink at the path, is refused.
3. Read the passphrase and, from a terminal only, an optional label.
4. Format. The rest of the 16 MiB header region is filled with random bytes,
   so that much is allocated.
5. Attach a loop device.
6. Open it as `/dev/mapper/luks-auto`.
7. Run `mkfs.<filesystem>` on the mapping with the label.

If reading the passphrase or formatting fails, the file is deleted (only if it
is still the file this run created) and the command exits with the failure's
status.

If step 5 or 6 fails, the command prints the error on stderr, detaches the
loop device from step 5 (after a failed step 6), keeps the formatted container
with the commands to finish by hand, and exits with the failure's status. A failed step 6 normally
leaves no mapping, but if the error says the mapping may still be live, close
`luks-auto` yourself. The name is always `luks-auto`, so creating a second file
volume while one is open stops here.

If step 7 fails, the command tries to close the mapping and detach the loop
device, keeps the container file and exits with the failure's status. If either cleanup step fails it
says so and prints the `luks2 close` or `losetup -d` command to finish. Whatever
mkfs wrote may be partial.

### KDF options

Named as cryptsetup names them. Also accepted by
[`recovery add`](../recovery-keys/cli.md#add),
[`addkey` and `changekey`](../keyslots/cli.md#addkey).

| Option | Applies to | Meaning |
|---|---|---|
| `--pbkdf <name>` | | `argon2id`, `argon2i` or `pbkdf2`, the three values cryptsetup's `--pbkdf` takes. Default: `pbkdf2` (SHA-512) in FIPS 140-3 mode, `argon2id` otherwise. |
| `--hash <name>` | pbkdf2 | `sha256`, `sha384` or `sha512` (default `sha512`) |
| `--iter-time <ms>` | pbkdf2 | Calibration budget (default 2000). The count never falls below the hash's floor. |
| `--pbkdf-force-iterations <n>` | both | PBKDF2 iteration count (no calibration, floor still applies), or Argon2 time cost |
| `--pbkdf-memory <KiB>` | argon2id, argon2i | Argon2 memory, at least 65536 |
| `--pbkdf-parallel <n>` | argon2id, argon2i | Argon2 threads |

These are checked before the passphrase prompt and before any file is made: an
option that does not apply to the chosen KDF, an empty value, a value that is
not a whole number above zero, and `--pbkdf argon2id` or `argon2i` in FIPS mode
(`ErrFIPSNotApproved`) all exit 1. The Argon2 cost bounds (memory under 65536,
and the time and thread limits) are part of the same pre-prompt check
(`KDFParams.Validate`), so they fail before the prompt too. The PBKDF2 bounds (a
count under the hash's floor, `--iter-time` over 600000) are the library's and
are only enforced when the keyslot is written, after the prompt.

Defaults without options: AES-XTS with a 512-bit key, 512-byte sectors,
Argon2id at time 4, 1 GiB, 4 threads. The output names the KDF used. See
[keyslots/engineering.md](../keyslots/engineering.md) and
[fips/architecture.md](../fips/architecture.md).

```bash
sudo luks2 create --pbkdf pbkdf2 --hash sha256 --iter-time 3000 /dev/sdb1
sudo luks2 create --pbkdf argon2id --pbkdf-memory 524288 /srv/data.luks 1G
printf %s 'my passphrase' > /root/new.key
sudo luks2 create --key-file /root/new.key /srv/data.luks 100M
```

A new passphrase typed at a terminal is asked for twice. One from `--key-file`
or a pipe is not, and no label is asked for.

## open

```
luks2 open [--key-file <path>] <device> <name>
```

Unlocks `<device>` and creates `/dev/mapper/<name>`. `<device>` is a block
device or a loop device; for a file, attach one first with
`losetup -f --show <file>`. Every keyslot is tried; there is no slot option.

`<name>` starts with a letter or digit, continues with letters, digits and
`_ . + -`, and is at most 127 bytes.

```bash
sudo luks2 open /dev/sdb1 backup
sudo luks2 open --key-file /etc/luks/backup.key /dev/sdb1 backup
echo 'my passphrase' | sudo luks2 open /dev/sdb1 backup
```

The volume key goes to dm-crypt through the kernel keyring. Inside a container
that needs a seccomp profile allowing the keyring syscalls; see
[Kernel keyring](architecture.md#kernel-keyring).

### Failures

| Message contains | Meaning |
|---|---|
| `master key verification failed` | A keyslot was tried and the key did not match, or the passphrase opens only an unbound keyslot. Usually a wrong passphrase, but damaged key material looks the same. |
| `no valid keyslots` | Nothing in the header can be tried. No passphrase will help. |
| `mandatory requirement` | The header declares a feature this tool does not implement, such as `online-reencrypt-v2` from an interrupted `cryptsetup reencrypt`. Finish it with `cryptsetup reencrypt --resume-only <device>`. |
| `segment layout cannot be activated` | The header has more than one segment. |
| `not a block device` | `<device>` is a file; attach a loop device first. |
| `invalid keyslot`, `invalid LUKS header` | The header or a keyslot is malformed. The passphrase may be correct. |
| `mapping is already active` | `<name>` is in use; close it or pick another. |
| `kernel keyring` | The keyring syscalls are blocked or unsupported. |
| `may still be live` | The open failed and its cleanup did not finish; run `luks2 close <name>`. |

## close

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

A name with no mapping fails with `mapping is not active` (`dmcrypt.ErrNotActive`).

## mount

```
luks2 mount [--type | -t <fstype>] [--allow-suid] [--allow-dev] <name> <mountpoint>
```

Mounts `/dev/mapper/<name>` on `<mountpoint>` (made absolute first) with
`nosuid,nodev`: the filesystem is untrusted content, so setuid files and device
nodes on it are inert. `--allow-suid` and `--allow-dev` each lift one of the
two. The type is
`--type` (or `-t`) if given, otherwise what `blkid -p` finds on the mapping.
Nothing found, more than one signature, or something that is not a filesystem
(another LUKS container, swap) is refused with exit 1 rather than guessed. For
mount options, use `mount(8)`:

```bash
sudo luks2 mount backup /mnt/backup          # detects ext4, xfs, vfat, ...
sudo luks2 mount -t xfs data /mnt/data
```

A missing mountpoint is created with mode 0750. The command refuses a
mountpoint that is already a mount point, and fails if no mapping named
`<name>` exists. An empty `--type`, or `--type` and `-t` naming different
types, is a usage error.

## unmount

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

## info

```
luks2 info <device>
```

Prints a summary from the primary header. Works on a block device, a loop
device or a container file.

```
$ luks2 info /srv/data.luks

LUKS2 Volume Manager
Pure Go LUKS2 Implementation
Volume Information: /srv/data.luks
===========================================================

UUID:           856e75eb-57d5-488e-984b-29344ad7a7d7
Label:          backup
Version:        LUKS2
Cipher:         aes-xts-plain64
Sector Size:    512 bytes
Active Keyslots: [0 1]

Keyslot Details:
  Slot 0: argon2id (key size: 64 bytes)
  Slot 1: pbkdf2 (key size: 64 bytes)

Volume is valid and accessible
```

"Valid" means the primary header parsed; it says nothing about whether a
passphrase opens the volume. Use [testkey](../keyslots/cli.md#testkey) for
that, and [keyslots](../keyslots/cli.md#keyslots) for KDF details.

If the header holds keyslot or token entries written as JSON `null`, they are
listed on stderr: they are ignored, and the next header write removes them.

If the primary header cannot be read, the exit status is the error's own (4 for
a missing device or one that is not LUKS2). To ask only "is this LUKS", use
[isluks](../header/cli.md#isluks).

## Key input

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
`--key-file`; see [recovery-keys/cli.md](../recovery-keys/cli.md#verify).

### The trailing newline

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

### Limits

A credential that opens an existing keyslot may be 1 byte to 8 MiB, as with
cryptsetup, so a 4 KiB key file or a short legacy passphrase works. A new
passphrase (`create`, and the new credential of `addkey` and `changekey`) must
be 8 to 512 bytes. A key file over 8 MiB is refused while it is read, with
`key file is too large`.

### Confirmation

A new passphrase typed at a terminal is asked for twice and compared in
constant time. One from a file or pipe is not confirmed, as with
`cryptsetup --batch-mode`. For `addkey` and `changekey`, a missing
`--new-key-file` means the new passphrase comes from stdin or the terminal by
the table above.

### Unattended backup

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
