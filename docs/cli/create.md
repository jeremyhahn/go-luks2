# luks2 create

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

```
luks2 create [--key-file <path>] [KDF options] <path> [size] [filesystem]
```

A `<path>` under `/dev/` is a block device; anything else is a file volume.
Either way the path must be absolute.

## Block device

Formats the device as LUKS2 and stops. `size` and `filesystem` are ignored.

```bash
sudo luks2 create /dev/sdb1
sudo luks2 open /dev/sdb1 backup
sudo mkfs.ext4 /dev/mapper/backup
```

## File volume

```bash
sudo luks2 create /srv/data.luks 1G          # ext4
sudo luks2 create /srv/data.luks 500M xfs
```

`size` is required: a whole number with an optional `K`, `M`, `G` or `T`
suffix (powers of 1024, either case); no suffix means bytes. `filesystem` is
`ext4` (default), `xfs` or `vfat`. `zfs` needs a pool name and is not offered.

Steps, in order:

1. Refuse an unsupported filesystem, an unparsable size or an existing file.
2. Create the file at `size` (sparse).
3. Read the passphrase and, from a terminal only, an optional label.
4. Format. The rest of the 16 MiB header region is filled with random bytes,
   so that much is allocated.
5. Attach a loop device.
6. Open it as `/dev/mapper/luks-auto`.
7. Run `mkfs.<filesystem>` on the mapping with the label.

If reading the passphrase or formatting fails, the file is deleted and the
command exits 1.

If step 5 or 6 fails, the command prints a warning and the manual command, and
**exits 0** with the formatted container kept. A failed step 6 normally leaves
no mapping, but if the error says the mapping may still be live, close
`luks-auto` yourself. The loop device from step 5 stays attached. The name is
always `luks-auto`, so creating a second file volume while one is open stops
here.

If step 7 fails, the command tries to close the mapping and detach the loop
device, keeps the container file and exits 1. If either cleanup step fails it
says so and prints the `luks2 close` or `losetup -d` command to finish. Whatever
mkfs wrote may be partial.

## KDF options

Named as cryptsetup names them. Also accepted by
[`recovery add`](recovery.md).

| Option | Applies to | Meaning |
|---|---|---|
| `--pbkdf <name>` | | `argon2id` or `pbkdf2`. Default: `pbkdf2` (SHA-512) in FIPS 140-3 mode, `argon2id` otherwise. |
| `--hash <name>` | pbkdf2 | `sha256`, `sha384` or `sha512` (default `sha512`) |
| `--iter-time <ms>` | pbkdf2 | Calibration budget (default 2000). The count never falls below the hash's floor. |
| `--pbkdf-force-iterations <n>` | both | PBKDF2 iteration count (no calibration, floor still applies), or Argon2 time cost |
| `--pbkdf-memory <KiB>` | argon2id | Argon2 memory, at least 65536 |
| `--pbkdf-parallel <n>` | argon2id | Argon2 threads |

These are checked before the passphrase prompt and before any file is made: an
option that does not apply to the chosen KDF, an empty value, a value that is
not a whole number above zero, and `--pbkdf argon2id` in FIPS mode
(`ErrFIPSNotApproved`) all exit 1. The cost bounds themselves (Argon2 memory
under 65536, a PBKDF2 count under the floor, `--iter-time` over 600000) are the
library's and fail at format time, after the prompt.

Defaults without options: AES-XTS with a 512-bit key, 512-byte sectors,
Argon2id at time 4, 1 GiB, 4 threads. The output names the KDF used. See
[kdf.md](../luks/kdf.md) and [FIPS.md](../FIPS.md).

```bash
sudo luks2 create --pbkdf pbkdf2 --hash sha256 --iter-time 3000 /dev/sdb1
sudo luks2 create --pbkdf argon2id --pbkdf-memory 524288 /srv/data.luks 1G
printf %s 'my passphrase' > /root/new.key
sudo luks2 create --key-file /root/new.key /srv/data.luks 100M
```

A new passphrase typed at a terminal is asked for twice. One from `--key-file`
or a pipe is not, and no label is asked for.
