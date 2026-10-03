# luks2 recovery

Recovery keys: a full-strength credential, generated rather than chosen, for the
case where the passphrase is gone.

A recovery key is an ordinary keyslot. Nothing about it is weaker or stronger
than a passphrase — what differs is that it is drawn from a cryptographic random
source rather than remembered, so it is written down instead.

## Synopsis

```
luks2 recovery generate [--format <name>] [--length <n>] [--output <path>]
luks2 recovery add      [--key-file <path>] [--format <name>] [--length <n>]
                        [--slot <n>] [--output <path>] [KDF options] <device>
luks2 recovery verify   [--recovery-file <path>] <device>
```

## It is shown once

The key is printed to standard output **exactly once** and is never written
anywhere else unless `--output` asks for it. It cannot be recovered from the
volume afterwards — that is the whole point of it. Copy it at that moment.

```
=================== RECOVERY KEY ===================
9f3a2c-4b81de-07c5a6-...
====================================================
```

## The printed string IS the passphrase

What is on the screen is the credential itself. Paste it at any prompt that asks
for one — including a rescue system that has never heard of this tool:

```bash
cryptsetup open /dev/sdb1 vault      # paste the printed string
```

That is the point of a printed page in a safe. A recovery key that only works
after being decoded by a particular piece of software is not a recovery path,
because the software is one of the things that can be unavailable on the day it
is needed.

Type or paste it **exactly as shown**: the dashes are part of it and so is the
letter case. Nothing normalizes it on the way back in, because the volume holds
those exact characters and cryptsetup will not normalize them either.

The line labeled `Checksum (not secret)` is a SHA-256 of the credential, for
checking a transcription without going near the volume. It is not the key and it
will not open anything.

### No entropy is lost by this

The credential is the same 32 bytes from the same CSPRNG, written down in a
different alphabet. Rendering 256 bits as 64 hex characters spreads the same 256
bits over more characters; it does not create or destroy any of them. Anyone
reading "the keyslot holds text rather than key bytes" as a weakening and
reverting it would reintroduce exactly the failure above.

## Formats

| `--format` | Looks like | Length for a 32-byte key |
|---|---|---|
| `dashed` (default) | `9f3a2c-4b81de-...` | 71 characters |
| `hex` | `9f3a2c4b81de...` | 64 characters |
| `base64` | `nzosS4HeB8Wm...=` | 44 characters |

`dashed` is the default because it is the one a human transcribes without
losing their place.

## generate

Produces a recovery key without touching a volume — useful when provisioning,
where the key is wanted before the container exists.

```bash
luks2 recovery generate
luks2 recovery generate --format hex --output /root/recovery.txt
```

## add

Generates a recovery key and puts it in a keyslot.

```bash
sudo luks2 recovery add /dev/sdb1
sudo luks2 recovery add --key-file current.key --output /root/recovery.txt /dev/sdb1
```

The keyslot it went into **is** reported, unlike `addkey`: `AddRecoveryKey`
reads the number from where the library chose it rather than inferring it
afterwards, so it is the real one. It is written into the saved file and
outlives the process — an operator retiring the key months later destroys the
right credential.

A `systemd-recovery` **token** is written alongside it, naming that keyslot.
Without it the header shows a keyslot and nothing says what it is, which is
indistinguishable from somebody's forgotten second passphrase — and that
difference decides whether an operator revokes it. `cryptsetup luksDump` and
`luks2 token list` both show it.

If the token cannot be written, **the keyslot is rolled back**: a credential
nothing describes is worse than no credential. In the one case where the
rollback itself fails, the error names the slot, because at that point that
number is the only record of it.

If `--output` is given and the file cannot be written, the command exits 1 and
says so loudly on stderr — **but the key is already live in a keyslot**, and it
is still on the screen. That is the moment to copy it.

### Key derivation

`add` takes the same KDF options as [`create`](create.md#key-derivation-kdf-options):
`--pbkdf argon2id|pbkdf2`, `--hash`, `--iter-time`, `--pbkdf-force-iterations`,
`--pbkdf-memory` and `--pbkdf-parallel`, checked the same way and before the
passphrase prompt; cost bounds are the library's and are checked when the
keyslot is written, with nothing written if one is refused.

With none of them the keyslot gets the library's policy for the mode:
PBKDF2-SHA512 in FIPS 140-3 mode, Argon2id otherwise — and an Argon2id
recovery keyslot inherits the Argon2 cost of the volume's existing keyslots.
In FIPS 140-3 mode `--pbkdf argon2id` is refused with `ErrFIPSNotApproved`.

```bash
# FIPS 140-3 mode: no option needed
sudo GODEBUG=fips140=only luks2 recovery add /dev/sdb1

# PBKDF2 explicitly, as systemd-cryptenroll writes a recovery keyslot
sudo luks2 recovery add --pbkdf pbkdf2 --hash sha512 --pbkdf-force-iterations 1000 /dev/sdb1
```

A recovery key is 256 random bits, so its keyslot may take an explicit
iteration count as low as 1000 — the count multiplies the cost of a search,
and there is no search over 256 random bits. A passphrase keyslot is held to
the hash's full floor.

## verify

Checks that a recovery key still opens a volume. This is a read-only operation,
and it is the only way to find out that a key written down a year ago was
transcribed correctly.

```bash
# Type it back, or pipe it
sudo luks2 recovery verify /dev/sdb1
echo '9f3a2c-4b81de-...' | sudo luks2 recovery verify /dev/sdb1

# Or read the file 'recovery add --output' wrote
sudo luks2 recovery verify --recovery-file /root/recovery.txt /dev/sdb1
```

`--recovery-file` reads the file this tool wrote, with its header and checksum
line. Without it, the key is read from the terminal or a pipe. Either way it is
taken verbatim — only surrounding whitespace is stripped.

### A recovery key made before the credential became the printed text

Those keyslots hold the **decoded** bytes, so `verify` will refuse them. This
command does not try both: a check that quietly tests something other than what
it was asked about is worse than one that says no. The library keeps
`ParseRecoveryKey` and `LoadRecoveryKey` for that case; pass either result to
`VerifyRecoveryKey`.

## Exit codes

| Code | Description |
|---|---|
| 0 | Success — for `verify`, the key opens the volume |
| 1 | The key does not open the volume, or the operation failed |

## Key derivation

The keyslot is written with this package's default KDF, argon2id. systemd would
write pbkdf2 here, and it is right — but the shape it writes cannot be expressed
by this package yet, so the default is unchanged for now.

### What systemd does

From `cryptsetup luksDump` on a volume enrolled with `systemd-cryptenroll`
(systemd 255, cryptsetup 2.7.0):

| slot | credential | KDF |
|---|---|---|
| 0 | human passphrase | argon2id, t=24, m=512000, p=4 |
| 1 | recovery key | pbkdf2, sha512, **1000 iterations** |
| 2–4 | FIDO2 credentials | pbkdf2, sha512, **1000 iterations** |

A flat minimum for every credential that is not a human passphrase, with no
calibration. The reason is that a recovery key is 256 bits from a CSPRNG: there
is nothing to enumerate, so stretching it defends against nothing while costing
about a second and a gigabyte of locked memory on a node that may have neither.

> **1000 is not a generally safe iteration count.** It is right here only
> because the credential is random and full-length. Under a human-chosen
> passphrase the same number would be catastrophic — which is exactly why
> systemd puts argon2id at t=24 on slot 0 and 1000 on the rest.

### Why the default has not changed yet

This package's pbkdf2 path takes a *time budget* and calibrates against it;
there is no way to ask it for a fixed iteration count. Even the smallest budget
overshoots, and the result depends on the machine:

| request | result on one developer machine |
|---|---|
| sha512, 1 ms budget | 3253 iterations |
| sha512, 10 ms budget | 31824 iterations |
| sha256, 2000 ms (the default) | ~9.9M iterations |

Switching to that would write headers matching neither systemd nor each other —
two nodes enrolled from the same script would differ — while still paying for a
calibration probe. That is why "just ask for a low budget" is not a workaround.

Two things have to change first, and the second is easy to miss. An explicit
iteration count is one. The other is that this package's OWASP-derived floor
refuses systemd's number outright — the permitted range for sha512 starts at
210,000, so 1000 is rejected by a factor of 210. That floor is right for a
passphrase, whose strength is unknown; it is wrong only for a credential the
library generated itself and knows to be 256 random bits.

Measured on the same machine, the two paths as they stand today:

| | wall | memory |
|---|---|---|
| argon2id, t=4 m=1GiB p=4 (current default) | 0.88 s | 1 GiB |
| pbkdf2, 2000 ms budget | 2.08 s | none |

**Do not read that as an argument against pbkdf2.** Nearly all of the 2.08 s is
the calibration benchmark, not the derivation, and an explicit iteration count
does not run one. At 1000 iterations there is nothing to calibrate and nothing
to stretch, so the choice stops being "a gigabyte or two seconds" and becomes
neither. The 2.4× is an artifact of an API that could only calibrate.

### It is not an interoperability question

A keyslot records its own KDF parameters and every implementation reads them
from the header, so `cryptsetup` and `systemd-cryptsetup` open an argon2id
keyslot and a pbkdf2 one alike. The type, hash and count are a **cost** decision,
not a compatibility constraint. It is also forward-only: existing volumes keep
whatever their keyslots already hold.

Library callers who want pbkdf2 today set `RecoveryKeyOptions.KDFType`; see
[keyslots](keyslots.md) for the same option on `addkey`. Note that matching
systemd means the **hash** too — it writes sha512, while this package defaults
to sha256.

## Storing one

The saved file is written `0400` and holds the credential in the clear — it has
to, that is what it is for. Keep it somewhere the volume is not: a safe, a
password manager, a different machine. On the volume itself it is worthless.

Printing it is a legitimate way to store it, and the reason the credential is
text: a page in a safe needs no reader, no battery and no software.

## See Also

- [keyslots](keyslots.md) — a recovery key occupies one
- [key-input](key-input.md) — where the existing passphrase comes from
