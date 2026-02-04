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
| `--standard <name>` | Use named wipe standard: `nist`, `dod3`, `dod7` |
| `--verify` | Enable verification pass |
| `--no-verify` | Disable verification (override standard) |

## Wipe Standards

The `--standard` option enables compliance with official secure erasure methodologies:

| Standard | Name | Passes | Pattern Sequence | Verification |
|----------|------|--------|------------------|--------------|
| `nist` | NIST SP 800-88 Rev 1 | 1 | Random | No |
| `dod3` | DoD 5220.22-M (3-pass) | 3 | Zeros -> Ones -> Random | Yes (100%) |
| `dod7` | DoD 5220.22-M ECE (7-pass) | 7 | (Z->O->R) + R + (Z->O->R) | Yes (100%) |

### NIST SP 800-88

The NIST standard is recommended for modern storage media. It uses a single pass of cryptographically random data, which is sufficient for modern drives with high-density storage.

### DoD 5220.22-M (3-pass)

The DoD 3-pass standard overwrites data three times with different patterns:
1. Pass 1: All zeros (0x00)
2. Pass 2: All ones (0xFF)
3. Pass 3: Random data

After the three passes, the device is read back to verify the final pattern was written correctly.

### DoD 5220.22-M ECE (7-pass)

The extended 7-pass standard provides additional assurance:
1. Pass 1-3: Zeros -> Ones -> Random
2. Pass 4: Random (additional)
3. Pass 5-7: Zeros -> Ones -> Random (repeat)

This is followed by 100% verification of the final pattern.

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

### NIST SP 800-88 standard

```bash
sudo luks2 wipe --full --standard nist /dev/sdb1
```

Single pass of random data. Recommended for most modern storage media.

### DoD 5220.22-M 3-pass standard

```bash
sudo luks2 wipe --full --standard dod3 /dev/sdb1
```

Three-pass wipe (zeros, ones, random) with 100% verification.

### DoD 5220.22-M ECE 7-pass standard

```bash
sudo luks2 wipe --full --standard dod7 /dev/sdb1
```

Seven-pass wipe with full verification. Most thorough option.

### Custom multi-pass wipe

```bash
sudo luks2 wipe --full --passes 3 --random /dev/sdb1
```

Three passes of random data (custom configuration).

### Enable verification on custom wipe

```bash
sudo luks2 wipe --full --passes 1 --verify /dev/sdb1
```

Single zero pass with verification.

### Disable verification on standard

```bash
sudo luks2 wipe --full --standard dod3 --no-verify /dev/sdb1
```

DoD 3-pass without verification step.

### SSD with TRIM

```bash
sudo luks2 wipe --full --standard nist --trim /dev/ssd1
```

NIST standard followed by TRIM/DISCARD command for SSDs.

### All options

```bash
sudo luks2 wipe --full --standard dod3 --trim /dev/sdb1
```

## Confirmation

All wipe operations require explicit confirmation:

```
*** WARNING: DESTRUCTIVE OPERATION ***

This will PERMANENTLY DESTROY all data on: /dev/sdb1
This action CANNOT be undone!

Mode: dod3 standard (3 passes)
Sequence: zeros -> ones -> random
Verify: Enabled (100%)
TRIM: Enabled (SSD)

Type 'YES' to confirm wipe: YES

Wiping entire device (this may take a while)...

Volume wiped successfully!
```

## Verification

When verification is enabled (either by standard or `--verify` flag):

1. After all wipe passes complete, the device is read back
2. Every byte is compared against the expected final pattern
3. If any mismatch is found, the operation fails with an error
4. Random patterns skip verification (cannot verify random data)

Verification ensures the wipe patterns were actually written to the physical media and not just cached.

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
| NIST (1 random) | Medium | Very High | Modern storage |
| DoD 3-pass | Slow | Higher | Compliance |
| DoD 7-pass | Very Slow | Highest | Maximum assurance |
| With TRIM | N/A | SSD-specific | SSD disposal |

### Choosing a Standard

- **Header-only**: Fastest option. Destroys encryption keys, making data cryptographically unrecoverable.
- **NIST**: Recommended for most use cases. Single random pass is sufficient for modern high-density storage.
- **DoD 3-pass**: Required by some compliance frameworks. Provides multiple pattern verification.
- **DoD 7-pass**: Maximum assurance. For highly sensitive data or regulatory requirements.

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
| 1 | Error (including verification failure) |

## Recovery

**There is no recovery from a wipe operation.**

## See Also

- [info](info.md) - Verify device before wiping
- [close](close.md) - Close volume before wiping
