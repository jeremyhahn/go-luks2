# Reference standards

> **Status: NORMATIVE** · Scope: go-luks2 · Last verified: 2026-10-16
> The code implements these documents precisely. A divergence between the code and a document listed here is a defect.

Where an industry standard exists, go-luks2 implements it and designs nothing in its place. This directory holds a copy of each standard the code implements, fetched from its publisher, where the licence permits redistribution. A standard whose licence does not permit a copy is listed with where to obtain it.

A draft is adopted at one pinned revision. A new revision, or the final text, updates both the copy here and the code. `ROADMAP.md` Dependencies carries a standards-watch line for each pinned draft.

## Index

| File | Standard and revision | Final or draft | Licence | Implementing package |
|---|---|---|---|---|
| [luks2-on-disk-format-1.1.3.pdf](luks2-on-disk-format-1.1.3.pdf) | LUKS2 On-Disk Format Specification, version 1.1.3 (2024-02-17) | Draft: the publisher calls the document work in progress. **Pinned: version 1.1.3, LUKS2-docs commit `55f31ae5`** | CC BY-SA 4.0 ([luks2-on-disk-format-LICENSE](luks2-on-disk-format-LICENSE)) | `internal/header` (binary header, JSON metadata), `pkg/luks2` (keyslots, segments, digests, tokens), `internal/areacipher` (keyslot area encryption) |
| not copied: licence | LUKS1 On-Disk Format Specification, version 1.2.3 (2018-01-20). The document states no licence. It defines the anti-forensic splitter that LUKS2 keyslots of AF type `luks1` use. Obtain it from the cryptsetup project: <https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf> | Final | None stated | `internal/af` |
| [rfc8018.txt](rfc8018.txt) | RFC 8018, PKCS #5: Password-Based Cryptography Specification, Version 2.1 (January 2017); PBKDF2 is section 5.2 | Final | IETF Trust Legal Provisions | `internal/kdf`, `pkg/luks2` (`sha1kdf.go`) |
| [rfc9106.txt](rfc9106.txt) | RFC 9106, Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications (September 2021); Argon2 version 0x13 | Final | IETF Trust Legal Provisions | `internal/kdf` (argon2i, argon2id) |
| [NIST.FIPS.197-upd1.pdf](NIST.FIPS.197-upd1.pdf) | FIPS 197, Advanced Encryption Standard (AES), updated 2023-05-09 | Final | US government work, not subject to copyright in the United States | `internal/areacipher`, `pkg/wipe` |
| [NIST.SP.800-38A.pdf](NIST.SP.800-38A.pdf) | NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation: Methods and Techniques (December 2001); CBC mode | Final | US government work | `internal/areacipher` (`aes-cbc-plain`, `aes-cbc-plain64`, `aes-cbc-essiv:sha256`) |
| [NIST.SP.800-38E.pdf](NIST.SP.800-38E.pdf) | NIST SP 800-38E, Recommendation for Block Cipher Modes of Operation: The XTS-AES Mode for Confidentiality on Storage Devices (January 2010) | Final | US government work | `internal/areacipher` (`aes-xts-plain64`, `aes-xts-plain`) |
| not copied: licence | IEEE Std 1619-2018, IEEE Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices; defines XTS-AES, which SP 800-38E approves by reference. IEEE copyright; the text is not redistributable. Obtain it from IEEE: <https://standards.ieee.org/ieee/1619/5880/> | Final | IEEE copyright | `internal/areacipher` |
| [NIST.FIPS.180-4.pdf](NIST.FIPS.180-4.pdf) | FIPS 180-4, Secure Hash Standard (SHS) (August 2015); SHA-1, SHA-256, SHA-384, SHA-512 | Final | US government work | `internal/kdf`, `internal/af`, `internal/header` (header checksum), `pkg/luks2` (digests) |
| [NIST.FIPS.198-1.pdf](NIST.FIPS.198-1.pdf) | FIPS 198-1, The Keyed-Hash Message Authentication Code (HMAC) (July 2008); the PBKDF2 pseudorandom function | Final | US government work | `internal/kdf`, `pkg/luks2` (`sha1kdf.go`) |
| [NIST.FIPS.140-3.pdf](NIST.FIPS.140-3.pdf) | FIPS 140-3, Security Requirements for Cryptographic Modules (March 2019) | Final | US government work | `internal/fips`, `pkg/luks2` (`fips.go`, `fipsmigrate.go`) |
| [NIST.FIPS.140-3-IG.pdf](NIST.FIPS.140-3-IG.pdf) | Implementation Guidance for FIPS 140-3 and the Cryptographic Module Validation Program, last updated 2026-08-19; IG C.I, the XTS-AES key check | Final; revised in place by its publisher | US government work | `internal/areacipher` (`WithFIPS`), `internal/fips` |
| [NIST.SP.800-88r1.pdf](NIST.SP.800-88r1.pdf) | NIST SP 800-88 Revision 1, Guidelines for Media Sanitization (December 2014). The publisher has withdrawn it, superseded by Revision 2. The code implements Revision 1's single pass of random data | Final, withdrawn | US government work | `pkg/wipe` (`NIST`) |
| not copied: not fetched | DoD 5220.22-M, National Industrial Security Program Operating Manual; the source of the `DoD3Pass` and `DoD7Pass` sequences. A US government work, but the publisher's server refused the download. Obtain it from the DoD issuances site: <https://www.esd.whs.mil/Directives/issuances/dodm/> | Final, cancelled | US government work | `pkg/wipe` (`DoD3Pass`, `DoD7Pass`) |
| [rfc4648.txt](rfc4648.txt) | RFC 4648, The Base16, Base32, and Base64 Data Encodings (October 2006) | Final | IETF Trust Legal Provisions | `internal/recoverykey` (hex, base64), `internal/header` (base64 JSON fields) |
| [rfc9562.txt](rfc9562.txt) | RFC 9562, Universally Unique IDentifiers (UUIDs) (May 2024) | Final | IETF Trust Legal Provisions | `internal/header`, `pkg/luks2` (volume UUID) |
| [linux-v6.12-dm-crypt.rst](linux-v6.12-dm-crypt.rst) | Linux kernel documentation, dm-crypt target: the table format, IV generators, the keyring key reference; tag `v6.12` | Final (kernel ABI) | GPL-2.0 | `pkg/dmcrypt`, `internal/dm` |
| [linux-v6.12-dm-ioctl.h](linux-v6.12-dm-ioctl.h) | Linux kernel UAPI header `include/uapi/linux/dm-ioctl.h`, the device-mapper ioctl interface; tag `v6.12` | Final (kernel ABI) | LGPL-2.0+ WITH Linux-syscall-note | `pkg/dmcrypt`, `internal/dm` |
| [linux-v6.12-keys-core.rst](linux-v6.12-keys-core.rst) | Linux kernel documentation, Kernel Key Retention Service: the `logon` key type and `add_key`/`keyctl`; tag `v6.12` | Final (kernel ABI) | GPL-2.0 | `internal/keyring`, `pkg/dmcrypt` |
| [linux-v6.12-loop.h](linux-v6.12-loop.h) | Linux kernel UAPI header `include/uapi/linux/loop.h`, the loop device ioctl interface; tag `v6.12` | Final (kernel ABI) | GPL-1.0+ WITH Linux-syscall-note | `pkg/loop` |
| not copied: licence | FIDO Alliance, Client to Authenticator Protocol (CTAP), version 2.1. Not implemented here: `pkg/keyprovider` delegates every authenticator exchange to the libfido2 helper binaries (`fido2-cred`, `fido2-assert`). FIDO Alliance copyright; the text is not redistributable. Obtain it from <https://fidoalliance.org/specifications/> | Final | FIDO Alliance copyright | `pkg/keyprovider` (through libfido2) |

## Formats with no published standard

- The `systemd-fido2`, `systemd-recovery` and `systemd-tpm2` token JSON schemas are defined by systemd's source, not by a standard. `internal/header` and `pkg/luks2` carry them field for field, as systemd 255 and cryptsetup 2.7.0 write them.
- TPM: the code implements no TPM protocol. A `systemd-tpm2` token is preserved unchanged through a header rewrite.
- `pkg/filesystem` drives each filesystem's own tools (`mkfs.*`, `fsck.*`, `blkid`) and implements no on-disk filesystem format.

## Sources

| Publisher | Where the copies came from |
|---|---|
| cryptsetup project | <https://gitlab.com/cryptsetup/LUKS2-docs> at commit `55f31ae5413f9e0edd04f3836bbb66070ea81e5d` |
| RFC Editor | <https://www.rfc-editor.org/rfc/> |
| NIST | <https://nvlpubs.nist.gov/> and <https://csrc.nist.gov/> |
| Linux kernel | <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/>, tag `v6.12` |
