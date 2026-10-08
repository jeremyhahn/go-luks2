# FIPS 140-3 — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

There is no `luks2 fips` verb. FIPS mode is a process property
(`GODEBUG=fips140=on` or `fips140=only`), not something a command selects,
and `MigrateToFIPS` has **no CLI verb: it is library-only** today. A consumer
that needs to drive it from a script calls
`go doc github.com/jeremyhahn/go-luks2/pkg/luks2 MigrateToFIPS` directly.

What the existing commands do differently in FIPS mode:

## `--pbkdf` behaviour

`create`, `addkey` and `recovery add` work in FIPS mode with no options and
write PBKDF2-SHA512 keyslots. `--pbkdf argon2id` and `--pbkdf argon2i` are
refused before the passphrase prompt, with `ErrFIPSNotApproved`; see
[volumes/cli.md](../volumes/cli.md#kdf-options).

```bash
# Works in FIPS mode: writes a PBKDF2-SHA512 keyslot (the default)
sudo luks2 create /dev/sdb1

# Refused in FIPS mode, before any prompt
sudo luks2 create --pbkdf argon2id /dev/sdb1
```

The KDF options of `addkey`, `changekey` and `recovery add` are checked the same way:
an Argon2 request in FIPS mode is refused before the passphrase prompt, not
after.

## `isluks`, `header show`, `keyslots`

Unaffected by FIPS mode: these only read, and listing a non-approved keyslot
is not a derivation.

## `open` and `testkey`

Neither has `--pbkdf`-style flags, but both unlock the volume
(`Volume.Unlock`), which derives a key from each keyslot it tries, so both are
held to the FIPS restrictions. A volume that only opens through Argon2 or SHA-1
keyslots fails in FIPS mode with the FIPS-import message
(`ErrFIPSImportRequired`) for `open` and for `testkey` alike; `testkey` does
not report "opens" for it. See [volumes/cli.md](../volumes/cli.md#failures).
There is no CLI path to run `MigrateToFIPS` and then retry in one command.
