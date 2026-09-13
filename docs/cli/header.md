# luks2 header, luks2 isluks

Header inspection and repair.

A LUKS2 container carries **two copies** of its header, and the second is not a
backup anyone has to remember to take — it is written every time the first one
is. These commands are how the second copy becomes useful.

## Synopsis

```
luks2 header show      <device>
luks2 header secondary <device>
luks2 header restore   <device>
luks2 isluks [--luks2] <device>
```

## show and secondary

```bash
$ sudo luks2 header show /dev/sdb1
Primary header: /dev/sdb1
===========================================================
Version:        LUKS2
UUID:           12345678-1234-1234-1234-123456789abc
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

`secondary` prints the same report for the copy at offset `0x4000`.

**The sequence id is the reason to look at both.** Whichever copy carries the
higher one was written last. A secondary that is *ahead* of the primary means
the primary is stale, which is what a restore is for.

If the header carries entries written as JSON `null`, they are reported on
stderr along with the warning that the next write removes them permanently.

## restore

Overwrites the primary header with the secondary copy. Requires typing `YES`.

```bash
sudo luks2 header restore /dev/sdb1
```

If the secondary copy is **older**, changes recorded only in the primary — a
keyslot added since, a token written since — are lost. Compare the two sequence
ids first:

```bash
sudo luks2 header show /dev/sdb1      | grep Sequence
sudo luks2 header secondary /dev/sdb1 | grep Sequence
```

Back the header up before repairing anything:

```bash
cryptsetup luksHeaderBackup /dev/sdb1 --header-backup-file /root/sdb1.header
```

## isluks

Answers whether a device holds a LUKS container, **in its exit code** — 0 for
yes, 1 for no, as `cryptsetup isLuks` does it. `--luks2` narrows the question to
LUKS2 specifically.

```bash
if sudo luks2 isluks --luks2 /dev/sdb1; then
    sudo luks2 open /dev/sdb1 backup
fi
```

A device that could not be read is also "no", but the reason is reported on
stderr so a person can tell "there is no container here" from "this device could
not be read".

## Exit codes

| Code | Description |
|---|---|
| 0 | Success — for `isluks`, the device holds a LUKS container |
| 1 | Not a LUKS container, or the operation failed |

## See Also

- [info](info.md) — the volume report, from the primary header
- [LUKS2 header](../luks/header.md) — the on-disk structure
