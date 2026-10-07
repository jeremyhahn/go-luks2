# Recovery keys — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

Prerequisites: an existing LUKS2 volume and a passphrase that already opens
it ([volumes/user.md](../volumes/user.md)).

## Create a recovery key and keep it somewhere safe

```bash
sudo luks2 recovery add --key-file current.key --output /root/recovery.txt /dev/sdb1
```

The key is printed once and, with `--output`, also saved to a file (mode
0400). Copy it somewhere away from the machine: a password manager, a printed
backup, a safe. There is no way to retrieve it again later — if it is lost,
generate and add a new one while the old passphrase still works.

## Check a saved recovery key still works

```bash
sudo luks2 recovery verify --recovery-file /root/recovery.txt /dev/sdb1
```

This is read-only and safe to run periodically to confirm a backup is still
good.

## Use a recovery key to open a volume

Type it exactly as printed, dashes and case included:

```bash
sudo luks2 open /dev/sdb1 backup
# at the passphrase prompt, paste the recovery key text
```

It also works with stock cryptsetup (`cryptsetup open /dev/sdb1 backup`),
because the keyslot holds the printed text itself.

## Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| `recovery verify` rejects a key that looks right | The key was enrolled by an older version and the keyslot holds decoded bytes, not the text | Use the library's `LoadRecoveryKey`/`ParseRecoveryKey` tolerant path, or re-enroll a fresh key |
| `recovery add` printed the key but then exited 1 | Writing to `--output` failed after the key was already added | The key is already live in the keyslot; copy it from the terminal output before it scrolls away |
| `recovery add` exited 1 and the keyslot is gone | The key could not be printed (output write failed) and no `--output` was given, so the keyslot and token were rolled back | Re-run with `--output <path>`, or ensure standard output is not redirected somewhere that fails |
