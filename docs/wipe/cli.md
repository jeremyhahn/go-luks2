# Wipe — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

```
luks2 wipe [--full] [--passes <n>] [--random] [--standard nist|dod3|dod7]
           [--verify | --no-verify] [--trim] [--batch-mode | --yes] <device>
```

Options may come before or after `<device>`. A relative path is resolved
against the working directory. The command shows what it will do and reads
`YES` from standard input. Any other answer, end of input or a read error
prints `Wipe canceled` and exits 1. `--batch-mode` (or `--yes`) skips the
question.

The device is opened with `O_EXCL`, so a device that is mounted, open as a
mapping, or otherwise held is refused. Close the volume first
([volumes/cli.md](../volumes/cli.md#close)). If the path names a different
file when it is opened than when it was locked (a symlink re-pointed in
between), the wipe is refused before anything is written.

## Header-only (default)

```bash
sudo luks2 wipe /dev/sdb1
```

Zeroes both header copies and the whole keyslots area, plus every keyslot area
the header lists, using the geometry of a header copy whose checksum is valid.
Any other header copy found at a legal offset is zeroed too: its binary header
and its JSON. Nothing at or past the start of the data segment is touched.

This is a crypto-erase. A header backup taken before the wipe
(`cryptsetup luksHeaderBackup`, or a copy of the first megabytes) no longer
opens the volume, because the keyslot material it needs is gone. If no header
copy has a valid checksum, the keyslots area cannot be located: the first
32 KiB and every recognisable copy are zeroed, and you should use `--full`.

`--passes`, `--random`, `--standard`, `--verify`, `--no-verify` and `--trim`
shape the full overwrite, so without `--full` they are a usage error (exit 1)
rather than being silently ignored.

## Full device (`--full`)

Overwrites the whole device, then syncs.

| Option | Effect |
|---|---|
| `--passes <n>` | Number of passes, 1 to 100 (default 1). The whole value must be a number. |
| `--random` | Random data instead of zeros |
| `--standard <name>` | A fixed pattern sequence; overrides `--passes` and `--random` |
| `--verify` | Read the device back and compare it with the final pass |
| `--no-verify` | Turn verification off, including a standard's |
| `--trim` | Issue `BLKDISCARD` over the device afterwards |

| Standard | Passes |
|---|---|
| `nist` | random |
| `dod3` | zeros, ones, random |
| `dod7` | zeros, ones, random, random, zeros, ones, random |

`dod3` and `dod7` turn verification on. Verification reads the device back with
`O_DIRECT`, past the page cache (for a loop device, its backing file too), and
compares every byte with the final pass. A random pass is AES-256-CTR under a
fresh key, so it is checked like any other. If the device cannot be read past
the page cache, verification fails instead of reading the cache.

A `--trim` that the device refuses, or a regular file, is ignored silently.

```bash
sudo luks2 wipe --full /dev/sdb1                  # one pass of zeros
sudo luks2 wipe --full --verify /dev/sdb1         # zeros, read back
sudo luks2 wipe --full --standard nist --trim /dev/nvme0n1p3
```

There is no recovery from a full wipe.
