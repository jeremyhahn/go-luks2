# Wipe — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

Prerequisites: the volume must be closed first
([volumes/cli.md](../volumes/cli.md#close)). Both wipe modes need root on a
block device.

## Make a volume permanently unopenable, quickly

```bash
sudo luks2 wipe /dev/sdb1
```

This destroys the header copies and keyslots only; it is fast because it does
not touch the (still-encrypted) data segment. Any existing header backup
becomes useless at the same moment. Use this when the goal is "nobody can
open this again," not "nobody can recover any bytes from this medium."

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
| `wipe` says the keyslots area could not be located | No header copy had a valid checksum | Use `--full`; a header-only wipe cannot target an area it cannot find |
| `wipe --full --verify` fails verification | A byte did not match the final pass — possibly a flaky device | Re-run; if it fails consistently, suspect the medium itself |
