# FIPS 140-3 — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

There is no `luks2 fips` verb. FIPS mode is a process property
(`GODEBUG=fips140=on` or `fips140=only`), not something a command selects,
and `MigrateToFIPS` has **no CLI verb: it is library-only** today. A consumer
that needs to drive it from a script calls
`go doc github.com/jeremyhahn/go-luks2/pkg/luks2 MigrateToFIPS` directly.

What the existing commands do differently in FIPS mode:

## `--pbkdf` behaviour

`create`, `addkey` and `recovery add` work in FIPS mode with no options and
write PBKDF2-SHA512 keyslots. `--pbkdf argon2id` is refused before the
passphrase prompt, with `ErrFIPSNotApproved`; see
[volumes/cli.md](../volumes/cli.md#kdf-options).

```bash
# Works in FIPS mode: writes a PBKDF2-SHA512 keyslot (the default)
sudo luks2 create /dev/sdb1

# Refused in FIPS mode, before any prompt
sudo luks2 create --pbkdf argon2id /dev/sdb1
```

`addkey --kdf` and `recovery add`'s KDF options are checked the same way:
an Argon2 request in FIPS mode is refused before the passphrase prompt, not
after.

## `isluks`, `header show`, `keyslots`, `testkey`

Unaffected by FIPS mode: these only read, and reading a non-approved keyslot
(to list it, or to report that a passphrase for it does not open the volume)
is not a derivation.

## `open`

Unaffected by `--pbkdf`-style flags (there are none for `open`), but a
volume that only opens through Argon2 or SHA-1 keyslots fails in FIPS mode
with the FIPS-import message; see
[volumes/cli.md](../volumes/cli.md#failures). There is no CLI path to run
`MigrateToFIPS` and then retry in one command.
