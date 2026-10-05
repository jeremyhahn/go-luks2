# luks2 open

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

```
luks2 open [--key-file <path>] <device> <name>
```

Unlocks `<device>` and creates `/dev/mapper/<name>`. `<device>` is a block
device or a loop device; for a file, attach one first with
`losetup -f --show <file>`. Every keyslot is tried; there is no slot option.

`<name>` starts with a letter or digit, continues with letters, digits and
`_ . + -`, and is at most 127 bytes.

```bash
sudo luks2 open /dev/sdb1 backup
sudo luks2 open --key-file /etc/luks/backup.key /dev/sdb1 backup
echo 'my passphrase' | sudo luks2 open /dev/sdb1 backup
```

The volume key goes to dm-crypt through the kernel keyring. Inside a container
that needs a seccomp profile allowing the keyring syscalls; see
[Kernel keyring](../ARCHITECTURE.md#kernel-keyring).

## Failures

| Message contains | Meaning |
|---|---|
| `master key verification failed` | A keyslot was tried and the key did not match, or the passphrase opens only an unbound keyslot. Usually a wrong passphrase, but damaged key material looks the same. |
| `no valid keyslots` | Nothing in the header can be tried. No passphrase will help. |
| `mandatory requirement` | The header declares a feature this tool does not implement, such as `online-reencrypt-v2` from an interrupted `cryptsetup reencrypt`. Finish it with `cryptsetup reencrypt --resume-only <device>`. |
| `segment layout cannot be activated` | The header has more than one segment. |
| `not a block device` | `<device>` is a file; attach a loop device first. |
| `invalid keyslot`, `invalid LUKS header` | The header or a keyslot is malformed. The passphrase may be correct. |
| `volume already unlocked` | `<name>` is in use; close it or pick another. |
| `kernel keyring` | The keyring syscalls are blocked or unsupported. |
| `may still be live` | The open failed and its cleanup did not finish; run `luks2 close <name>`. |
