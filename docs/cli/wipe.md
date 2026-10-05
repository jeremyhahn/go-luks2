# luks2 wipe

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

```
luks2 wipe [--full] [--passes <n>] [--random] [--standard nist|dod3|dod7]
           [--verify | --no-verify] [--trim] <device>
```

Options may come before or after `<device>`; `--name=value` is not accepted
here. The command shows what it will do and reads `YES` from standard input.
Anything else prints `Wipe canceled` and exits 0. Close the volume first.

## Header-only (default)

```bash
sudo luks2 wipe /dev/sdb1
```

Zeroes both header copies: twice the header area from the start of the device
(32 KiB by default; the size is read from a valid header copy). It also zeroes
the 4 KiB binary header of any other header copy it finds at a legal offset.

**Keyslot areas and data are not touched.** The volume no longer opens, and
neither this tool nor cryptsetup recognises it as LUKS. But anyone who kept a
header backup (`cryptsetup luksHeaderBackup`, or a copy of the first 32 KiB) can
write it back and open the volume with any passphrase that was valid. To
destroy the key material, use `--full`.

Without `--full` the other options have no effect, but they are still parsed:
an invalid `--passes` or `--standard` value exits 1.

## Full device (`--full`)

Overwrites the whole device, then syncs.

| Option | Effect |
|---|---|
| `--passes <n>` | Number of passes (default 1) |
| `--random` | Random data instead of zeros |
| `--standard <name>` | A fixed pattern sequence; overrides `--passes` and `--random` |
| `--verify` | Read the device back and compare it with the final pass |
| `--no-verify` | Turn verification off |
| `--trim` | Issue `BLKDISCARD` over the device afterwards |

| Standard | Passes |
|---|---|
| `nist` | random |
| `dod3` | zeros, ones, random |
| `dod7` | zeros, ones, random, random, zeros, ones, random |

`dod3` and `dod7` turn verification on, and the command prints
`Verify: Enabled (100%)`. **Verification only checks the final pass and is
skipped when that pass is random,** so it does nothing for any of the three
standards. It has an effect only on a zero-filled custom wipe:
`--full --verify`.

A `--trim` that the device refuses, or a regular file, is ignored silently.

```bash
sudo luks2 wipe --full /dev/sdb1                  # one pass of zeros
sudo luks2 wipe --full --verify /dev/sdb1         # zeros, read back
sudo luks2 wipe --full --standard nist --trim /dev/nvme0n1p3
```

There is no recovery from a full wipe.
