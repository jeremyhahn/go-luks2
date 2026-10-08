# Wipe — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

Prerequisites: the volume must be closed first
([volumes/cli.md](../volumes/cli.md#close)). Both wipe modes need root on a
block device.

## Make a volume permanently unopenable, quickly

```bash
sudo luks2 wipe /dev/sdb1
```

This destroys the header copies and keyslots only; it is fast because it does
not touch the (still-encrypted) data segment. A header backup taken before
it (`cryptsetup luksHeaderBackup`) still holds the keyslots, so restoring it
opens the data again: if such a backup exists and is not destroyed too, use
the full wipe below. Use this when the goal is "nobody can open this again,"
not "nobody can recover any bytes from this medium."

## Destroy the data itself before disposing of a device

```bash
sudo luks2 wipe --full --verify /dev/sdb1
```

This is slow: it overwrites the whole device and reads it back to confirm.
For a device you are about to discard entirely, add `--trim`.

## Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| `wipe` refuses with a device-in-use error | The volume is still open or mounted | `luks2 unmount` then `luks2 close` first |
| A header-only `wipe` of a volume whose header was already damaged reports success | No header copy had a valid checksum, so only the first 32 KiB and every recognizable copy were zeroed; keyslot material further out may remain | Use `--full`; a header-only wipe cannot target an area it cannot find |
| `wipe --full --verify` fails verification | A byte did not match the final pass — possibly a flaky device | Re-run; if it fails consistently, suspect the medium itself |
