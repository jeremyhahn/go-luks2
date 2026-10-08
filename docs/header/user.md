# Header — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
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
| cryptsetup reports a damaged primary, yet `header show` prints a header | The primary copy is damaged or missing; `header show` prints the current valid copy, here the secondary, still labeled `Primary` | `header secondary` to check the other copy, then `header restore` |
| `header restore` refuses without `--force` | The primary header's sequence ID is not lower than the secondary's | Confirm you actually want a rollback before adding `--force` |
| `isluks` exits 1 on a device you believe is LUKS2 | Either it genuinely is not, its header fails validation, or it cannot be read (permissions, wrong path, lock) | `isluks` does not report the reason; `header show` on the same device does. `isluks` without `--luks2` also accepts LUKS1 |
