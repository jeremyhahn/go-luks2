# luks2 create

Create a new LUKS2 encrypted volume.

## Synopsis

```
luks2 create [--key-file <path>] [KDF options] <path> [size] [filesystem]
```

## Non-interactive use

`--key-file <path>` supplies the new volume's passphrase without a terminal, and
the volume label prompt is skipped when there is nobody to answer it. See
[key-input](key-input.md).

```bash
printf %s 'my passphrase' > /root/new.key
sudo luks2 create --key-file /root/new.key encrypted.luks 100M ext4
```

## Key derivation (KDF options)

The passphrase's keyslot is created with the KDF the process's mode allows, as
cryptsetup does:

| Mode | Default KDF |
|------|-------------|
| FIPS 140-3 (`GODEBUG=fips140=only` or `on`) | PBKDF2-SHA512, calibrated to the time budget and never below the SHA-512 iteration floor (210,000 at the default 2000 ms) |
| Otherwise | Argon2id (time 4, memory 1 GiB, parallelism 4) |

These options choose otherwise. They are named as cryptsetup names them.

| Option | Applies to | Description |
|--------|------------|-------------|
| `--pbkdf <name>` | | `argon2id` or `pbkdf2`. `argon2id` is refused in FIPS 140-3 mode. |
| `--hash <name>` | pbkdf2 | `sha256`, `sha384` or `sha512` (default `sha512`). The volume digest keeps its own default (`sha256`). |
| `--iter-time <ms>` | pbkdf2 | Time budget the iteration count is calibrated to (default 2000). The count never falls below the hash's floor for that budget. |
| `--pbkdf-force-iterations <n>` | both | The PBKDF2 iteration count, which skips calibration and is held to the hash's floor; or the Argon2 time cost. |
| `--pbkdf-memory <KiB>` | argon2id | Argon2 memory cost, at least 65536. |
| `--pbkdf-parallel <n>` | argon2id | Argon2 parallelism. |

An option that does not apply to the chosen KDF is refused, not ignored, and
so is an empty value or one that is not a whole number above zero. These
checks, and the FIPS check, run **before anything else happens**: a refused
choice exits 1 before the passphrase prompt and before a file is created. In
FIPS 140-3 mode, `--pbkdf argon2id` exits 1 with the library's
`ErrFIPSNotApproved` ("algorithm not approved in FIPS 140-3 mode") and says
what to use instead.

The cost bounds themselves are the library's and are checked when the volume
is formatted: an Argon2 memory below 65536 KiB, a PBKDF2 count below the
hash's floor, or an `--iter-time` above 600000 is refused then, after the
passphrase prompt. For a file volume, `create` removes the file it made.

```bash
# The mode's default
sudo luks2 create /dev/sdb1

# PBKDF2-SHA256 at a 3-second budget
sudo luks2 create --pbkdf pbkdf2 --hash sha256 --iter-time 3000 /dev/sdb1

# Argon2id at 512 MiB (not in FIPS 140-3 mode)
sudo luks2 create --pbkdf argon2id --pbkdf-memory 524288 data.luks 1G
```

The output names the KDF used (`KDF: PBKDF2-SHA512`, `KDF: Argon2id`).
See [FIPS 140-3](../FIPS.md).

## Description

The `create` command initializes a new LUKS2 encrypted volume. It supports two modes:

1. **Block device mode**: Format an existing block device (partition)
2. **File volume mode**: Create an encrypted file with automatic loop device setup

For file volumes, the command automatically:
- Creates the file with the specified size
- Formats it with LUKS2 encryption
- Sets up a loop device
- Unlocks the volume
- Creates the specified filesystem

## Arguments

| Argument | Description |
|----------|-------------|
| `path` | Block device (e.g., `/dev/sdb1`) or file path |
| `size` | Size for file volumes (required for files, ignored for devices) |
| `filesystem` | Filesystem type: `ext4`, `xfs`, `vfat` (default: `ext4`). `ext2` and `ext3` are not supported. `zfs` is supported by the library but not by this command, because it needs a pool name (`ZFSOptions`) that `create` does not take. |

### Size Suffixes

| Suffix | Unit |
|--------|------|
| `K` | Kilobytes |
| `M` | Megabytes |
| `G` | Gigabytes |
| `T` | Terabytes |

## Examples

### Create on a block device

```bash
# Format a partition with LUKS2
sudo luks2 create /dev/sdb1

# You will be prompted for:
# - Passphrase (entered twice for confirmation)
# - Volume label (optional)
```

### Create a file-based volume

```bash
# Create a 100MB encrypted file with ext4
sudo luks2 create myvolume.luks 100M

# Create a 1GB encrypted file with ext4
sudo luks2 create backup.luks 1G ext4

# Create with XFS filesystem
sudo luks2 create data.luks 500M xfs
```

### Automated workflow

When creating a file volume, the command automatically performs:

```
1. Create sparse file
2. Format with LUKS2 (the KDF above)
3. Setup loop device
4. Unlock volume
5. Create filesystem
```

After completion, the volume is ready to mount:

```bash
sudo luks2 mount luks-auto /mnt/encrypted
```

If step 5 fails, `create` exits 1 and prints the cause. It closes the
`luks-auto` mapping and detaches the loop device it attached, so nothing is
left unlocked. The LUKS2 container file is valid and is kept, but filesystem
creation did not complete, so anything the formatter wrote before failing
may be partial: delete it, or attach and open it yourself and run `mkfs`
on the mapping. If the mapping cannot be closed, `create` says so and prints
the `luks2 close` and `losetup -d` commands to finish the cleanup.

## Encryption Settings

The `create` command uses these default settings:

| Setting | Value |
|---------|-------|
| Cipher | AES-XTS-256 |
| Key Size | 512 bits |
| KDF | Argon2id; PBKDF2-SHA512 in FIPS 140-3 mode (see [KDF options](#key-derivation-kdf-options)) |
| Sector Size | 512 bytes |

## Passphrase Requirements

- Minimum length: 8 characters
- Maximum length: 512 characters
- Confirmation required for new volumes

## Output

On success, displays:
- Volume file/device path
- Loop device (for file volumes)
- Device mapper path
- Next steps for mounting

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (file exists, invalid size, a KDF option refused, format failed) |

## See Also

- [open](open.md) - Unlock an existing volume
- [mount](mount.md) - Mount an unlocked volume
- [info](info.md) - Display volume information
