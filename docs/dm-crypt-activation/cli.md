# dm-crypt activation — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (f871541)
> Conflicts with this document are defects. Fix them here first.

Two `luks2` verbs reach `pkg/dmcrypt`: `open` calls `dmcrypt.Activate` and
`close` calls `dmcrypt.Deactivate`. The command syntax, key input and the rest
of the verb set are documented once, in [volumes/cli.md](../volumes/cli.md);
this file states what those two verbs add from the activation side and does
not repeat the flag tables. `luks2 mount` also calls `dmcrypt.Lookup` to find
the mapping it mounts; it is documented in volumes/cli.md.

There is no verb for `Lookup`, `CheckKeyring` or `ValidateName`. A name is
validated by `open` and `close` before anything else happens.

Transport: embedded only. There is no server mode and no `--local` flag.

## open

```
luks2 open [--key-file <path>] <device> <name>
```

Unlocks `<device>` and creates `/dev/mapper/<name>`.

| Argument or flag | Type | Required | Meaning |
|---|---|---|---|
| `<device>` | path | yes | A block device or loop device; a file must be attached to a loop device first |
| `<name>` | string | yes | The mapping name; the rules are below |
| `--key-file <path>` | path | no | Read the passphrase from a file, or `-` for standard input; see [key input](../volumes/cli.md#key-input) |

`<name>` starts with a letter or digit, continues with letters, digits and
`_ . + -`, and is at most 127 bytes. `.`, `..` and `control` are refused. A
bad name exits 1 with `invalid device-mapper mapping name`, before the
passphrase is asked for.

Needs root: creating a mapping is a device-mapper operation. The volume key
reaches dm-crypt through the kernel keyring and never through the command line
or the table; a container needs a seccomp profile allowing the keyring
syscalls.

Exit status per [the exit-status table](../volumes/cli.md#exit-status), with
the error on stderr. From activation: a name already in use (`ErrActive`)
exits 5; `ErrInvalidName`, `ErrStillLive`, `ErrNodeUnverified` and the
keyring errors exit 1; a wrong key exits 2.

```bash
sudo luks2 open /dev/sdb1 backup
sudo luks2 open --key-file /etc/luks/backup.key /dev/sdb1 backup
```

### Failures that come from activation

| Message contains | Error | Exit | Meaning |
|---|---|---|---|
| `invalid device-mapper mapping name` | `ErrInvalidName` | 1 | The name breaks the rules above |
| `mapping is already active` | `ErrActive` | 5 | `<name>` is in use; close it or pick another |
| `kernel keyring` | `ErrKeyringUnavailable` family | 1 | The keyring syscalls are blocked, unsupported or out of quota; the message names the remedy |
| `may still be live` | `ErrStillLive` | 1 | The open failed and the cleanup could not confirm the removal; run `luks2 close <name>` |
| `no device node verifiably names` | `ErrNodeUnverified` | 1 | The device node could not be confirmed; the mapping was rolled back |
| `master key verification failed` | `luks2.ErrWrongKey` | 2 | The key does not verify against the header |

The messages for failures that come from reading the header or trying
keyslots (`no valid keyslots`, `mandatory requirement`, `segment layout cannot
be activated` and the others) are in
[volumes/cli.md](../volumes/cli.md#failures).

## close

```
luks2 close <name>
```

Removes `/dev/mapper/<name>`. It does not detach a loop device.

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `<name>` | string | yes | The mapping to close |

Exit status per [the exit-status table](../volumes/cli.md#exit-status). A
mapping that is held open (`ErrBusy`) exits 5; `ErrNotActive` and
`ErrInvalidName` exit 1.

```bash
sudo luks2 unmount /mnt/backup
sudo luks2 close backup
```

Behaviour that comes from `Deactivate`:

- A name with no mapping fails with `mapping is not active`
  (`dmcrypt.ErrNotActive`) and exits 1. Closing twice exits 1 the second time.
- A target something holds open is retried for 3 seconds, then fails with
  `device-mapper target is held open` (`dmcrypt.ErrBusy`, exit 5) and hints for finding the holder
  (`lsof`, `mount`, `dmsetup info -c`) and for deferring the removal
  (`dmsetup remove --deferred`).
- If the mapping was removed or replaced during the retries, `close` does not
  touch the replacement.

`close` itself also refuses while a filesystem on the mapping is mounted; that
check is the CLI's and is described in volumes/cli.md.
