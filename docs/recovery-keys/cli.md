# Recovery keys — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (f871541)
> Conflicts with this document are defects. Fix them here first.

```
luks2 recovery generate [--format <name>] [--length <n>] [--output <path>]
luks2 recovery add      [--key-file <path>] [--format <name>] [--length <n>]
                        [--slot <n>] [--output <path>] [KDF options] <device>
luks2 recovery verify   [--recovery-file <path>] <device>
```

A recovery key is a random credential in an ordinary keyslot, meant to be
written down and kept away from the volume.

## The printed line is the passphrase

The key is printed once, on standard output:

```
=================== RECOVERY KEY ===================
56D3DF-C65CED-8A2EB2-DC6791-5E6837-655CC1-594860-39979D-423839-A4EF18-6182
====================================================
```

The keyslot holds that text exactly, so it opens the volume anywhere, including
with stock cryptsetup: `cryptsetup open /dev/sdb1 vault` and paste. Type it
exactly as shown; dashes and case are part of it. The `Checksum (not secret)`
line is a SHA-256 of the key for checking a transcription; it opens nothing.

If `add` cannot print the key (the write to standard output fails), the
keyslot and token are removed again and the command fails; `--output` is
written only after the key is printed, so it was not saved either. If a
removal fails, stderr names the command that finishes it (`luks2 killslot`
or `luks2 token remove`).

| `--format` | Example | Characters for 32 bytes |
|---|---|---|
| `dashed` (default) | `56D3DF-C65CED-…` (uppercase hex, groups of 6) | 74 |
| `hex` | `6920392130c6…` (lowercase) | 64 |
| `base64` | `nzosS4HeB8Wm…=` | 44 |

Any other `--format` value, an empty one included, is a usage error (exit 1)
raised before the passphrase is read.

`--length` is the number of random bytes, default 32; zero means 32. It must be
at least 32 (256 bits), and the rendered key at most 512 characters.
Keep the default.

## generate

Prints a key without touching any volume.

```bash
luks2 recovery generate --format hex --output /root/recovery.txt
```

## add

Generates a key, adds it to a keyslot using an existing passphrase, and writes
a `systemd-recovery` token naming the slot, so `cryptsetup luksDump` and
`luks2 token list` show what the slot is. If the token cannot be written, the
keyslot is removed again. The output names the keyslot and token.

```bash
sudo luks2 recovery add --key-file current.key --output /root/recovery.txt /dev/sdb1
```

`add` takes the [create KDF options](../volumes/cli.md#kdf-options), checked
before the passphrase prompt. Without them the keyslot gets `DefaultKDFType()`:
PBKDF2-SHA512 in FIPS 140-3 mode, otherwise Argon2id with the cost of the
volume's first Argon2 keyslot, if it has one. Because the key is generated,
`--pbkdf-force-iterations` may go as low as 1000 here, which is what
`systemd-cryptenroll` writes; it is safe only because the key is at least 256
random bits.

```bash
sudo luks2 recovery add --pbkdf pbkdf2 --hash sha512 --pbkdf-force-iterations 1000 /dev/sdb1
```

`--output` writes a file with mode 0400: comment lines with the volume UUID,
keyslot, token and checksum, then the key. The file is created exclusively,
so an existing path is refused rather than overwritten. If the file cannot
be written the command fails, but the key is already in the keyslot and on
screen; copy it then.

## verify

Checks that a key still opens the volume. Read-only.

```bash
sudo luks2 recovery verify --recovery-file /root/recovery.txt /dev/sdb1
echo '56D3DF-C65CED-...' | sudo luks2 recovery verify /dev/sdb1
```

`--recovery-file` takes the first line that is not blank or a `#` comment.
Without it, the key is read from the terminal or the first line of a pipe.
Surrounding whitespace is stripped; nothing else is changed. Exit 0 if the key
opens the volume. A key that does not open it exits 2 (`ErrWrongKey`, the
same status as a wrong passphrase) after `That recovery key does NOT open
<device>` on stderr; any other failure exits with its own
[status](../volumes/cli.md#exit-status).

Keys enrolled by older versions hold the decoded bytes rather than the text, so
`verify` rejects them. No exported library function decodes those any more
(`ParseRecoveryKey` only trims and checks the text); re-enroll a fresh key
while a passphrase still opens the volume.
