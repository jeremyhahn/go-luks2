# cryptsetup interop — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163) and cryptsetup 2.7.5
> Conflicts with this document are defects. Fix them here first.

## Move a volume between go-luks2 and cryptsetup

Nothing special is required: a volume formatted with `luks2 create` opens
with `cryptsetup open`, and vice versa. The two tools write and read the same
on-disk format, measured by the matrix in
[engineering.md](engineering.md#the-interop-matrix).

```bash
sudo luks2 create /dev/sdb1
sudo cryptsetup open /dev/sdb1 backup   # opens the same volume
```

```bash
sudo cryptsetup luksFormat /dev/sdc1
sudo luks2 open /dev/sdc1 data           # opens the same volume
```

## Know what go-luks2 refuses that cryptsetup allows

Before relying on a volume or header shape that cryptsetup accepts, check
[architecture.md](architecture.md#stricter-than-cryptsetup) — every row there
is a deliberate refusal (a short passphrase, a detached-header activation),
not a bug to work around — and the out-of-scope containers (dm-integrity,
mid-reencryption, LUKS1) in [engineering.md](engineering.md#the-interop-matrix).

## Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| A volume `cryptsetup` opens refuses with `luks2 open` | It is one of the out-of-scope shapes (dm-integrity, mid-reencryption, LUKS1, a non-AES keyslot cipher) | The "out of scope" table in [engineering.md](engineering.md#the-interop-matrix) names the exact refusal |
| A write (`addkey`, `token import`, ...) fails with a lock error while cryptsetup seems to be waiting forever on the same device | go-luks2's lock wait times out at 30 s where cryptsetup waits indefinitely | Retry once the other process releases the lock, or investigate what is holding it |
| `luks2` and `cryptsetup` disagree about a header's validity | Confirm both are reading the same copy (primary vs. secondary) — see [header/cli.md](../header/cli.md#show-and-secondary) | If they still disagree on the same copy, this is a defect: file it |
