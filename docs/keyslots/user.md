# Keyslots — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

Prerequisites: an existing LUKS2 volume ([volumes/user.md](../volumes/user.md)).
Managing keyslots on a file you own needs no root.

## Add a second passphrase

```bash
sudo luks2 addkey --key-file current.key --new-key-file next.key /dev/sdb1
sudo luks2 keyslots /dev/sdb1   # confirm the new slot
```

## Revoke a lost or compromised passphrase

Use `killslot` with a different, still-valid passphrase — you do not need the
compromised one to remove it:

```bash
sudo luks2 killslot --key-file current.key /dev/sdb1 3
```

If you cannot name a slot number, list them first with `luks2 keyslots`.

## Rotate a passphrase without changing its slot

```bash
sudo luks2 changekey --key-file old.key --new-key-file new.key /dev/sdb1 0
```

## Check a passphrase still works, before relying on it

```bash
sudo luks2 testkey --key-file /etc/luks/backup.key /dev/sdb1
```

This changes nothing on disk; use it to verify a key file was written
correctly before trusting it for unattended unlock.

## Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| `addkey`/`changekey` fails with the master-key-verification message | The existing passphrase given is wrong | Re-check which slot it belongs to with `luks2 keyslots` and `testkey` |
| `removekey`/`killslot` refuses to remove a slot | It is the last keyslot that can open the volume | Add another keyslot or recovery key first |
| A credential from `cryptsetup luksAddKey --unbound` cannot authorize anything | Unbound keyslots are never tried by unlock and do not count toward the last-keyslot guard | Use a bound keyslot's credential instead |
