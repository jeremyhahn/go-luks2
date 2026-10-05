# luks2 info

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

```
luks2 info <device>
```

Prints a summary from the primary header. Works on a block device, a loop
device or a container file.

```
$ luks2 info /srv/data.luks

LUKS2 Volume Manager
Pure Go LUKS2 Implementation
Volume Information: /srv/data.luks
===========================================================

UUID:           856e75eb-57d5-488e-984b-29344ad7a7d7
Label:          backup
Version:        LUKS2
Cipher:         aes-xts-plain64
Sector Size:    512 bytes
Active Keyslots: [0 1]

Keyslot Details:
  Slot 0: argon2id (key size: 64 bytes)
  Slot 1: pbkdf2 (key size: 64 bytes)

Volume is valid and accessible
```

"Valid" means the primary header parsed; it says nothing about whether a
passphrase opens the volume. Use [testkey](keyslots.md#testkey) for that, and
[keyslots](keyslots.md#keyslots) for KDF details.

If the header holds keyslot or token entries written as JSON `null`, they are
listed on stderr: they are ignored, and the next header write removes them.

Exit 1 if the primary header cannot be read. To ask only "is this LUKS", use
[isluks](header.md#isluks).
