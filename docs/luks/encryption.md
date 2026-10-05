# Encryption

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

## Ciphers

`Format` writes `aes-xts-plain64` with a 512-bit key (AES-256-XTS) and
512-byte sectors. `FormatOptions.KeySize` may be 256 (AES-128-XTS) and
`SectorSize` may be 4096.

| Where | Cipher | Done by |
|---|---|---|
| Keyslot areas | `aes-xts-plain64` written; `aes-xts-plain64` or `aes-xts-plain` read; anything else fails with `ErrUnsupportedKeyslotCipher` | This library, `golang.org/x/crypto/xts` |
| Data segment | Whatever the header declares, after a character whitelist | The kernel, dm-crypt |

XTS encrypts each sector independently with the sector number as tweak. It does
not authenticate: changed ciphertext decrypts to garbage rather than failing.
The header checksum detects corruption, not tampering, since anyone who can
write the disk can recompute it.

## Anti-forensic split

The volume key is never stored directly. Each keyslot holds it split into
stripes with a hash-based diffuser, encrypted with AES-XTS under the key
derived from the credential. This library writes 4000 stripes
(`key_size × 4000` bytes, 256,000 for a 64-byte key) and reads 1 to 4000.

```
volume key ──AF split (4000 stripes)──> stripes ──AES-XTS, derived key──> keyslot area
keyslot area ──AES-XTS decrypt──> stripes ──AF merge──> candidate key ──digest check
```

Every stripe feeds the merge, so overwriting any part of the stripe material
destroys that keyslot. The area is rounded up to 4 KiB; the padding after the
stripes is not read. New keyslots use SHA-256 or SHA-512 for the diffuser; SHA-1 keyslots
from older cryptsetup are read outside FIPS mode only. Stripes, derived keys and
the merged key are held in locked memory; see
[Key custody](../ARCHITECTURE.md#key-custody).

## The dm-crypt table

`Unlock` creates a `crypt` target whose key field is a kernel keyring
reference, not the key. The optional-parameter count `<n>` is 0 for 512-byte
sectors; for 1024, 2048 or 4096 it is 1, followed by `sector_size:<size>`:

```
0 <sectors> crypt aes-xts-plain64 :64:logon:luks2:<sha256 of dm UUID> <iv_tweak> <device> <offset sectors> <n> [sector_size:<size>]
```

The key sits in the session keyring only while the target is created, then is
revoked. See [Kernel keyring](../ARCHITECTURE.md#kernel-keyring).
