# luks2 CLI Reference

The `luks2` command-line tool provides a complete interface for creating, managing, and securing LUKS2 encrypted volumes.

## Installation

```bash
go install github.com/jeremyhahn/go-luks2/cmd/luks2@latest
```

Or build from source:

```bash
git clone https://github.com/jeremyhahn/go-luks2.git
cd go-luks2
make build
sudo cp build/luks2 /usr/local/bin/
```

## Requirements

- Linux operating system
- Root privileges (sudo) for device-mapper operations
- Kernel with dm-crypt support

## Usage

```
luks2 <command> [arguments]
```

## Commands

| Command | Description |
|---------|-------------|
| [create](create.md) | Create a new LUKS2 encrypted volume |
| [open](open.md) | Unlock an encrypted volume |
| [close](close.md) | Lock an encrypted volume |
| [mount](mount.md) | Mount an unlocked volume |
| [unmount](unmount.md) | Unmount a volume |
| [info](info.md) | Display volume information |
| [wipe](wipe.md) | Securely wipe a volume (headers or full device) |
| help | Show usage information |
| version | Show version information |

## Quick Start

### Create an encrypted file volume

```bash
# Create a 100MB encrypted file with ext4 filesystem
sudo luks2 create myvolume.luks 100M ext4

# The volume is automatically:
# - Formatted with LUKS2
# - Attached to a loop device
# - Unlocked as /dev/mapper/luks-auto
# - Formatted with ext4 filesystem
```

### Create on a block device

```bash
# Format an existing partition
sudo luks2 create /dev/sdb1
```

### Complete workflow

```bash
# 1. Create encrypted volume
sudo luks2 create secret.luks 1G

# 2. Mount it
sudo luks2 mount luks-auto /mnt/secret

# 3. Use it
echo "confidential data" | sudo tee /mnt/secret/data.txt

# 4. Cleanup when done
sudo luks2 unmount /mnt/secret
sudo luks2 close luks-auto
```

### Re-open an existing volume

```bash
# Open (unlock) the volume
sudo luks2 open /dev/loop0 myvolume

# Mount
sudo luks2 mount myvolume /mnt/encrypted

# ... use the volume ...

# Cleanup
sudo luks2 unmount /mnt/encrypted
sudo luks2 close myvolume
```

## Global Options

| Option | Description |
|--------|-------------|
| `--help`, `-h` | Show help message |
| `--version`, `-v` | Show version information |

## Security Considerations

1. **Passphrase Strength**: Use at least 12 characters with mixed case, numbers, and symbols
2. **Memory**: Passphrases are cleared from memory after use
3. **Root Access**: All operations require root privileges
4. **Secure Wipe**: Use `wipe` command before disposing of devices

## See Also

- [create](create.md) - Detailed create command documentation
- [open](open.md) - Detailed open command documentation
- [wipe](wipe.md) - Secure wipe documentation
- [LUKS2 Header Format](../luks/header.md) - Technical header documentation
