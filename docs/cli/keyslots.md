# luks2 keyslot commands

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

```
luks2 keyslots  <device>
luks2 testkey   [--key-file <path>] <device>
luks2 addkey    [--key-file <path>] [--new-key-file <path>] [--slot <n>] [--kdf <name>] <device>
luks2 changekey [--key-file <path>] [--new-key-file <path>] <device> <slot>
luks2 removekey [--key-file <path>] <device> <slot>
luks2 killslot  [--key-file <path>] <device> <slot>
```

A volume has keyslots 0–31, each wrapping the same volume key under a different
passphrase. A `<slot>` argument outside 0–31 is refused before anything is read.
`--key-file` is the existing passphrase and `--new-key-file` the new one; see
[key input](key-input.md).

## keyslots

```
$ luks2 keyslots /srv/data.luks
Slot  Type     Key size  KDF        Encryption
0     luks2    64        argon2id   aes-xts-plain64
4     luks2    64        pbkdf2     aes-xts-plain64
```

Listed by ascending slot number, with gaps where slots were removed. Unlock
tries slots bound to the data segment first, then the rest, each in that order;
keyslot priority is not used. A header with no keyslots prints a message on
stderr and exits 1.

## testkey

Checks that a passphrase opens the volume. Changes nothing. A failure prints
the library's reason, which may be damage rather than a wrong passphrase (see
[open](open.md#failures)).

```bash
sudo luks2 testkey --key-file /etc/luks/backup.key /dev/sdb1
```

## addkey

Adds a passphrase. The existing one unwraps the volume key; the new one goes
into the first free slot, or `--slot <n>`.

`--kdf` is `argon2id`, `argon2i`, `pbkdf2` (SHA-256), `pbkdf2-sha256`,
`pbkdf2-sha384` or `pbkdf2-sha512`. Default: `pbkdf2-sha512` in FIPS 140-3
mode, `argon2id` otherwise. A new Argon2 keyslot takes the cost of the
volume's first Argon2 keyslot. `pbkdf2-sha1` is refused before any prompt.

```bash
sudo luks2 addkey --key-file current.key --new-key-file next.key /dev/sdb1
sudo luks2 addkey --slot 5 --kdf pbkdf2-sha512 /dev/sdb1
```

It does not print the slot it used; run `luks2 keyslots`.

## changekey

Replaces the passphrase in `<slot>` in place. The old passphrase must be the
one in that slot. The slot keeps its KDF type and Argon2 cost; a PBKDF2-SHA1
slot is rewritten as PBKDF2-SHA256.

```bash
sudo luks2 changekey --key-file old.key --new-key-file new.key /dev/sdb1 0
```

## removekey and killslot

`removekey` needs the passphrase of the slot being removed. `killslot` accepts
any valid passphrase, which is how a lost or compromised credential is revoked
(cryptsetup's `luksKillSlot`). `killslot` prints the slot number before it acts.

```bash
sudo luks2 removekey /dev/sdb1 2
sudo luks2 killslot --key-file current.key /dev/sdb1 3
```

The freed area is overwritten with random bytes. The slot's number is removed
from every token; a token left naming no slot stays until
[`token remove`](token.md). Removing the last slot that can open the volume is
refused.
