# luks2 header, luks2 isluks

> **Status: REFERENCE** · Last verified: 2026-10-05 against v0.3.1-alpha

```
luks2 header show      <device>
luks2 header secondary <device>
luks2 header restore   [--batch-mode | --yes] [--force] <device>
luks2 isluks [--luks2] <device>
```

A LUKS2 container has two header copies, written together on every change.
Layout: [header.md](../luks/header.md).

## show and secondary

```
$ luks2 header show /srv/data.luks
Primary header: /srv/data.luks
===========================================================
Version:        LUKS2
UUID:           856e75eb-57d5-488e-984b-29344ad7a7d7
Label:          backup
Subsystem:
Header size:    16384 bytes
Header offset:  0
Checksum algo:  sha256
Sequence ID:    7

Keyslots:       2
Tokens:         1
Segments:       1
Digests:        1
```

`secondary` prints the same for the second copy, whose header offset equals the
header size. The copy with the higher sequence ID was written last; if the
secondary is ahead, the primary is stale.

## restore

Rebuilds the primary copy from the secondary, after you type `YES`
(`--batch-mode` or `--yes` skips the question; any other answer, end of input
or a read error exits 1). The secondary is validated first. Restore is refused
when the primary is intact and its sequence ID is not lower than the
secondary's, since that would roll the volume back: a passphrase removed since
may open it again. `--force` restores anyway; it still asks for `YES` unless
`--batch-mode` is given. Keep a backup:

```bash
cryptsetup luksHeaderBackup /dev/sdb1 --header-backup-file /root/sdb1.header
sudo luks2 header restore /dev/sdb1
```

## isluks

Exit 0 if the device starts with the LUKS magic, 1 otherwise, like
`cryptsetup isLuks`. `--luks2` also requires version 2. A device that cannot be
read is also 1, with the reason on stderr.

```bash
if sudo luks2 isluks --luks2 /dev/sdb1; then sudo luks2 open /dev/sdb1 backup; fi
```
