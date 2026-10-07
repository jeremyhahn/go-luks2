# FIPS 140-3 — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

Prerequisites: a build running under `GODEBUG=fips140=on` or
`fips140=only`. There is no separate installation step; FIPS mode is a Go
runtime setting.

## Create a volume that is FIPS-compliant from the start

```bash
GODEBUG=fips140=only sudo luks2 create /dev/sdb1
```

No options are needed: the default KDF in FIPS mode is already
PBKDF2-SHA512. Requesting Argon2 explicitly is refused before any prompt.

## Bring an existing (non-FIPS) volume into compliance

`MigrateToFIPS` has no CLI verb today; call it from Go:

```go
res, err := luks2.MigrateToFIPS("/dev/sdb1", passphrase, nil)
// res.Complete: no keyslot or digest FIPS mode cannot run remains
```

Run it in a process that is **not** in FIPS mode — the migration itself
needs to read the non-approved keyslots it is replacing. Keep the
passphrase you migrated with; it is the one credential that survives the
import unchanged.

## Recognize when a migration is needed

Opening a volume in a FIPS process that only has Argon2 or SHA-1 keyslots
fails with a message naming `MigrateToFIPS` and listing the affected
keyslots/digests ([volumes/cli.md](../volumes/cli.md#failures)). That is the
signal to run the migration above, not a sign of a damaged volume.

## Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| `create --pbkdf argon2id` is refused in FIPS mode | Argon2 is never approved, by design | Omit `--pbkdf` to get the FIPS default, or run outside FIPS mode |
| `open` fails naming `MigrateToFIPS` | The volume only has non-approved keyslots | Run `MigrateToFIPS` from a non-FIPS process, once |
| `MigrateToFIPS` fails partway through | Interrupted by a crash or a cancelled call | Re-run it; every intermediate state still opens with the original passphrase |
| A SHA-1 keyslot (from an old `cryptsetup convert`) cannot be read | SHA-1 is refused in FIPS mode before any hashing | Migrate it, or open with a non-FIPS process |
