// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

// Version is set at build time via -ldflags
var Version = "dev"

const banner = `
LUKS2 Volume Manager
Pure Go LUKS2 Implementation
`

const usage = `
USAGE:
    luks2 <command> [options]

COMMANDS:
    create <path> [size]         Create a new LUKS2 volume
                                 - Block device: luks2 create /dev/sdb1
                                 - File volume:  luks2 create /srv/encrypted.luks 100M
                                 Options: --pbkdf argon2id|pbkdf2 and its cost
                                 options (default: pbkdf2 in FIPS 140-3 mode);
                                 on a block device: asks for YES unless
                                 --batch-mode, refuses existing data unless --force
    open <device> <name>         Unlock and open a LUKS volume
    close <name>                 Lock and close a LUKS volume
    mount <name> <mountpoint>    Mount an unlocked volume (type detected, or --type)
    unmount <mountpoint>         Unmount a volume
    info <device>                Show volume information
    wipe [options] <device>      Securely wipe a volume (asks for YES)
                                 Options: --full, --passes N, --random, --trim,
                                 --batch-mode

KEYSLOTS:
    keyslots <device>            List the keyslots on a volume
    testkey <device>             Check that a passphrase opens a volume
    addkey <device>              Add another passphrase
    changekey <device> <slot>    Replace the passphrase in a keyslot
    removekey <device> <slot>    Remove a keyslot, using its own passphrase
    killslot <device> <slot>     Remove a keyslot, using any valid passphrase

RECOVERY KEYS:
    recovery generate            Generate a recovery key
    recovery add <device>        Generate one and add it to a keyslot
    recovery verify <device>     Check that a recovery key still opens a volume

TOKENS:
    token list <device>          Show the tokens on a volume
    token show <device> <id>     Show one token
    token export <device> <id>   Write a token as JSON
    token import <device> <id>   Store a token from JSON
    token remove <device> <id>   Delete a token (the keyslot is NOT touched)
    token free <device>          Report the first free token slot
    token exists <device> <id>   Exit 0 if the token is there, 1 if not
    token count <device>         Report how many tokens there are

HEADER:
    header show <device>         Show the primary header
    header secondary <device>    Show the secondary header copy
    header restore <device>      Overwrite the primary header from the secondary
                                 (asks for YES unless --batch-mode)
    isluks [--luks2] <device>    Exit 0 if the device holds a LUKS container

    help                         Show this help message
    version                      Show version information

NON-INTERACTIVE USE:
    Commands that read a passphrase accept --key-file (recovery verify uses
    --recovery-file); addkey and changekey also accept --new-key-file:

    # From a key file. THE WHOLE FILE IS THE PASSPHRASE, trailing newline
    # included -- this is cryptsetup's rule, so use printf, not echo:
    printf %s 'my passphrase' > /etc/luks/backup.key
    luks2 open --key-file /etc/luks/backup.key /dev/sdb1 backup

    # From standard input, whole:
    printf %s 'my passphrase' | luks2 open --key-file - /dev/sdb1 backup

    # From standard input, one line (the newline is NOT part of it):
    echo 'my passphrase' | luks2 open /dev/sdb1 backup

EXAMPLES:
    # Create a new LUKS2 encrypted volume on a block device
    sudo luks2 create /dev/sdb1

    # Create a LUKS2 encrypted volume in a file (auto-configured)
    sudo luks2 create /srv/encrypted.luks 100M

    # Open (unlock) the volume
    sudo luks2 open /dev/sdb1 my-encrypted-disk

    # First use of a block device: make a filesystem
    sudo mkfs.ext4 /dev/mapper/my-encrypted-disk

    # Mount the unlocked volume (the filesystem type is detected)
    sudo luks2 mount my-encrypted-disk /mnt/encrypted

    # Use your encrypted storage
    ls /mnt/encrypted

    # Unmount when done
    sudo luks2 unmount /mnt/encrypted

    # Close (lock) the volume
    sudo luks2 close my-encrypted-disk

    # View volume information
    sudo luks2 info /dev/sdb1

    # Wipe the header copies so the volume no longer opens (keyslot areas and
    # data remain; add --full to overwrite the whole device)
    sudo luks2 wipe /dev/sdb1

WORKFLOW (Block Device):
    1. Create:  luks2 create /dev/sdb1
    2. Open:    luks2 open /dev/sdb1 myvolume
    3. Mkfs:    mkfs.ext4 /dev/mapper/myvolume  (first use only)
    4. Mount:   luks2 mount myvolume /mnt/encrypted
    5. Use:     cp files /mnt/encrypted/
    6. Unmount: luks2 unmount /mnt/encrypted
    7. Close:   luks2 close myvolume

WORKFLOW (File Volume):
    1. Create:  luks2 create /srv/encrypted.luks 100M  (auto-configured!)
    2. Mount:   luks2 mount luks-auto /mnt/encrypted
    3. Use:     cp files /mnt/encrypted/
    4. Unmount: luks2 unmount /mnt/encrypted
    5. Close:   luks2 close luks-auto

NOTE:
    - Requires root privileges for most operations
    - Passphrases are never logged or displayed
    - Device and volume-file paths must be absolute (key files may be relative)
    - LUKS2 work is pure Go; create runs mkfs.<type> for a file volume's filesystem
    - File volumes are automatically configured (loop device + filesystem)
`

func main() {
	cli := NewCLI()
	code := cli.Run()
	if code != 0 {
		cli.ExitFunc(code)
	}
}
