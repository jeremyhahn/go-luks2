# Header — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

Prerequisites: a LUKS2 device or container file. Inspecting the header and
restoring it needs no root on a file you own.

## Check whether a device is a LUKS2 container

```bash
if sudo luks2 isluks --luks2 /dev/sdb1; then sudo luks2 open /dev/sdb1 backup; fi
```

## Look at what a header says, without unlocking

```bash
sudo luks2 header show /srv/data.luks
```

This parses the header only; it does not try any passphrase. For a passphrase
check, use [testkey](../keyslots/cli.md#testkey).

## Recover from a damaged primary header

Always keep a backup before attempting a repair:

```bash
cryptsetup luksHeaderBackup /dev/sdb1 --header-backup-file /root/sdb1.header
sudo luks2 header restore /dev/sdb1
```

`restore` refuses if the primary is already current, to avoid rolling the
volume back to a state where a since-removed passphrase would work again. If
you are certain you want that anyway, add `--force`.

## Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| `header show` fails to read the primary | Primary header copy is damaged or missing | `header secondary` to check the other copy, then `header restore` |
| `header restore` refuses without `--force` | The primary header's sequence ID is not lower than the secondary's | Confirm you actually want a rollback before adding `--force` |
| `isluks` exits 1 on a device you believe is LUKS2 | Either it genuinely is not, or it cannot be read (permissions, wrong path) | Check stderr for the reason; `isluks` without `--luks2` also accepts LUKS1 |
