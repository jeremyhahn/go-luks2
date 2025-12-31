# luks2 wipe

Securely wipe a LUKS2 volume.

## Synopsis

```
luks2 wipe [options] <device>
```

## Description

The `wipe` command securely destroys a LUKS2 volume. By default, it wipes only the LUKS2 headers (fast). Use `--full` to wipe the entire device.

**WARNING**: This operation is irreversible. All data will be permanently lost.

## Arguments

| Argument | Description |
|----------|-------------|
| `device` | Path to the LUKS2 device or file to wipe |

## Options

| Option | Description |
|--------|-------------|
| `--full` | Wipe entire device (default: headers only) |
| `--passes N` | Number of overwrite passes (default: 1) |
| `--random` | Use random data instead of zeros |
| `--trim` | Issue TRIM/DISCARD after wipe (for SSDs) |

## Examples

### Wipe headers only (fast)

```bash
sudo luks2 wipe /dev/sdb1
```

Makes data unrecoverable by destroying encryption keys. Fast (< 1 second).

### Full device wipe

```bash
sudo luks2 wipe --full /dev/sdb1
```

Overwrites entire device with zeros.

### DoD-style 3-pass wipe

```bash
sudo luks2 wipe --full --passes 3 /dev/sdb1
```

Overwrites device 3 times for higher security.

### Random data wipe

```bash
sudo luks2 wipe --full --random /dev/sdb1
```

Uses cryptographically random data instead of zeros.

### SSD with TRIM

```bash
sudo luks2 wipe --full --trim /dev/ssd1
```

Full wipe followed by TRIM/DISCARD command for SSDs.

### All options

```bash
sudo luks2 wipe --full --passes 3 --random --trim /dev/sdb1
```

## Confirmation

All wipe operations require explicit confirmation:

```
*** WARNING: DESTRUCTIVE OPERATION ***

This will PERMANENTLY DESTROY all data on: /dev/sdb1
This action CANNOT be undone!

Mode: Full device wipe (3 passes)
Data: Random
TRIM: Enabled (SSD)

Type 'YES' to confirm wipe: YES

Wiping entire device (this may take a while)...

Volume wiped successfully!
```

## What Gets Wiped

### Header-only wipe (default)
- Primary LUKS2 header (first 16KB)
- Backup LUKS2 header
- All keyslot areas (32KB total)

This destroys encryption keys, making data cryptographically inaccessible.

### Full device wipe (`--full`)
- Entire device contents
- Time depends on device size and passes

## Security Considerations

| Mode | Speed | Security | Use Case |
|------|-------|----------|----------|
| Header-only | Fast | High | Most scenarios |
| Full (1 pass) | Medium | Higher | Paranoid |
| Full (3+ passes) | Slow | Highest | Compliance/disposal |
| With TRIM | N/A | SSD-specific | SSD disposal |

## Pre-requisites

Before wiping:
1. **Unmount** the volume
2. **Close** (lock) the volume
3. **Back up** any needed data
4. **Verify** the correct device

```bash
# Verify correct device
sudo luks2 info /dev/sdb1

# Ensure not mounted
mount | grep sdb1

# Ensure not open
sudo dmsetup ls | grep sdb1
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success (or cancelled) |
| 1 | Error |

## Recovery

**There is no recovery from a wipe operation.**

## See Also

- [info](info.md) - Verify device before wiping
- [close](close.md) - Close volume before wiping
