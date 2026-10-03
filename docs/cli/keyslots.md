# luks2 keyslot commands

The credentials a container can be opened with. A LUKS2 volume holds up to 32
keyslots, each wrapping the same volume key under a different passphrase, so a
credential can be added or revoked without re-encrypting anything.

Every command here accepts `--key-file`; see [key-input](key-input.md).

## Synopsis

```
luks2 keyslots  <device>
luks2 testkey   [--key-file <path>] <device>
luks2 addkey    [--key-file <path>] [--new-key-file <path>] [--slot <n>] [--kdf <name>] <device>
luks2 changekey [--key-file <path>] [--new-key-file <path>] <device> <keyslot>
luks2 removekey [--key-file <path>] <device> <keyslot>
luks2 killslot  [--key-file <path>] <device> <keyslot>
```

## keyslots

Lists the keyslots on a volume, **in the order an unlock attempts them** —
ascending slot number. The order is the real one, not a presentation choice: it
is what decides how long an unlock takes.

```bash
$ sudo luks2 keyslots /dev/sdb1
Slot  Type     Key size  KDF        Encryption
0     luks2    64        argon2id   aes-xts-plain64
4     luks2    64        pbkdf2     aes-xts-plain64
```

Slot numbers are reported as they are on the device. A volume whose credentials
have been revoked has gaps, and the gaps matter: `removekey` and `killslot` take
the number shown here.

A container with **no** keyslots is reported on stderr and exits 1. Nothing can
open such a volume, and an empty table would read as "everything is fine".

## testkey

Checks that a passphrase opens a volume. Nothing is changed.

```bash
sudo luks2 testkey /dev/sdb1
sudo luks2 testkey --key-file /etc/luks/backup.key /dev/sdb1
```

A failure is **not** necessarily a wrong passphrase. The library distinguishes a
keyslot that judged the credential and rejected it from one that could not be
tried at all, and the reason it gives is passed through unchanged — see the
troubleshooting section of [open](open.md).

## addkey

Adds another passphrase. The existing one is needed to unwrap the volume key;
the new one goes into a free keyslot.

```bash
sudo luks2 addkey /dev/sdb1
sudo luks2 addkey --key-file current.key --new-key-file next.key /dev/sdb1
sudo luks2 addkey --slot 5 --kdf pbkdf2 /dev/sdb1
```

| Option | Meaning |
|---|---|
| `--slot <n>` | Use this keyslot instead of the first free one |
| `--kdf <name>` | `argon2id`, `argon2i`, `pbkdf2` (SHA-256), `pbkdf2-sha384` or `pbkdf2-sha512`. Default: `pbkdf2-sha512` in FIPS 140-3 mode, `argon2id` otherwise. `pbkdf2-sha1` is refused before any passphrase is asked for: no keyslot is created with SHA-1 |
| `--new-key-file <path>` | Read the **new** passphrase from a file |

**`addkey` does not report which keyslot it used.** Run
`luks2 keyslots <device>` to see. The library's `AddKey` returns the slot it
chose, so a correct number is available to the command; what it must never do
is reconstruct one from the header afterwards, which gives the wrong answer on
any container whose active slots are not contiguous from zero — every container
that has ever had a credential revoked — and a wrong number here is acted on
months later by an operator deciding what to destroy.

## changekey

Replaces the passphrase in one keyslot, in place. The old passphrase must be the
one in that slot.

```bash
sudo luks2 changekey /dev/sdb1 0
sudo luks2 changekey --key-file old.key --new-key-file new.key /dev/sdb1 0
```

## removekey

Removes a keyslot, using **that slot's own** passphrase.

```bash
sudo luks2 removekey /dev/sdb1 2
```

## killslot

Removes a keyslot, authenticating with **any** valid passphrase. This is how a
lost or compromised credential is revoked by someone who still holds a working
one — the equivalent of `cryptsetup luksKillSlot`.

```bash
sudo luks2 killslot /dev/sdb1 3
```

The slot number is echoed back before anything happens. It is irreversible, and
the operator named it by number.

## Exit codes

| Code | Description |
|---|---|
| 0 | Success |
| 1 | The operation failed, the arguments were unusable, or the credential could not be read |

## Removing the last keyslot

The library refuses to remove the only usable keyslot on a container: a volume
with none cannot be opened by anything, ever. Wipe it deliberately with
[wipe](wipe.md) instead.

## See Also

- [key-input](key-input.md) — where passphrases come from
- [recovery](recovery.md) — recovery keys, which are keyslots too
- [token](token.md) — the header record of *what* opens a keyslot
- [LUKS2 keyslots](../luks/keyslots.md) — the on-disk structure
