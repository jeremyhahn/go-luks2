# Keyslots — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

```
luks2 keyslots  <device>
luks2 testkey   [--key-file <path>] <device>
luks2 addkey    [--key-file <path>] [--new-key-file <path>] [--slot <n>] [KDF options] <device>
luks2 changekey [--key-file <path>] [--new-key-file <path>] [KDF options] <device> <slot>
luks2 removekey [--key-file <path>] <device> <slot>
luks2 killslot  [--key-file <path>] <device> <slot>
```

A volume has keyslots 0–31, each wrapping the same volume key under a different
passphrase. A `<slot>` argument outside 0–31 is refused before anything is read.
`--key-file` is the existing passphrase and `--new-key-file` the new one; see
[volumes/cli.md](../volumes/cli.md#key-input). General rules (path resolution,
root requirements, exit codes): [volumes/cli.md](../volumes/cli.md#rules-for-every-command).

## keyslots

```
$ luks2 keyslots /srv/data.luks
Slot  Type     Key size  KDF        Encryption
0     luks2    64        argon2id   aes-xts-plain64
4     luks2    64        pbkdf2     aes-xts-plain64
```

Listed by ascending slot number, with gaps where slots were removed. `open`
tries only slots bound to the data segment: `prefer` slots first, then `normal`
ones, each in that order, and never an `ignore` slot, as `cryptsetup open`
without `--key-slot` does. A header with no keyslots prints a message on stderr and exits 1.

## testkey

Checks that a passphrase opens the volume. Changes nothing. A failure prints
the library's reason, which may be damage rather than a wrong passphrase (see
[volumes/cli.md](../volumes/cli.md#failures)).

```bash
sudo luks2 testkey --key-file /etc/luks/backup.key /dev/sdb1
```

## addkey

Adds a passphrase. The existing one unwraps the volume key; the new one goes
into the first free slot, or `--slot <n>`.

The KDF options are the ones `create` takes (`--pbkdf`, `--hash`,
`--iter-time`, `--pbkdf-force-iterations`, `--pbkdf-memory`, `--pbkdf-parallel`;
[volumes/cli.md](../volumes/cli.md#kdf-options)). With none given, the new
keyslot is `pbkdf2` (SHA-512) in FIPS 140-3 mode and `argon2id` otherwise, and
an Argon2 keyslot takes the cost of the volume's first Argon2 keyslot. SHA-1
is refused, as is any option that does not apply to the chosen KDF, before any
prompt.

```bash
sudo luks2 addkey --key-file current.key --new-key-file next.key /dev/sdb1
sudo luks2 addkey --slot 5 --pbkdf pbkdf2 --hash sha512 --iter-time 1000 /dev/sdb1
```

It does not print the slot it used; run `luks2 keyslots`.

## changekey

Replaces the passphrase in `<slot>` in place. The old passphrase must be the
one in that slot. With no KDF option the slot keeps its KDF type and Argon2
cost; a PBKDF2-SHA1 slot is rewritten as PBKDF2-SHA256. The same KDF options as
`addkey` set a new cost instead.

```bash
sudo luks2 changekey --key-file old.key --new-key-file new.key /dev/sdb1 0
sudo luks2 changekey --pbkdf pbkdf2 --iter-time 1000 /dev/sdb1 0
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
from every token in the same header write; a token left naming no slot stays
until [`token remove`](../tokens/cli.md), as with `cryptsetup
luksKillSlot`. Removing the last slot that can open the volume is refused; a
slot created with `cryptsetup luksAddKey --unbound` does not count, and its
passphrase cannot authorize `addkey` or `killslot`.
