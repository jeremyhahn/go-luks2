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
                                 - File volume:  luks2 create encrypted.luks 100M
    open <device> <name>         Unlock and open a LUKS volume
    close <name>                 Lock and close a LUKS volume
    mount <name> <mountpoint>    Mount an unlocked volume
    unmount <mountpoint>         Unmount a volume
    info <device>                Show volume information
    wipe [options] <device>      Securely wipe a volume
                                 Options: --full, --passes N, --random, --trim
    help                         Show this help message
    version                      Show version information

EXAMPLES:
    # Create a new LUKS2 encrypted volume on a block device
    sudo luks2 create /dev/sdb1

    # Create a LUKS2 encrypted volume in a file (auto-configured)
    sudo luks2 create encrypted.luks 100M

    # Open (unlock) the volume
    sudo luks2 open /dev/sdb1 my-encrypted-disk

    # Mount the unlocked volume
    sudo luks2 mount my-encrypted-disk /mnt/encrypted

    # Use your encrypted storage
    ls /mnt/encrypted

    # Unmount when done
    sudo luks2 unmount /mnt/encrypted

    # Close (lock) the volume
    sudo luks2 close my-encrypted-disk

    # View volume information
    sudo luks2 info /dev/sdb1

    # Securely wipe (CAUTION: destroys data!)
    sudo luks2 wipe /dev/sdb1

WORKFLOW (Block Device):
    1. Create:  luks2 create /dev/sdb1
    2. Open:    luks2 open /dev/sdb1 myvolume
    3. Mount:   luks2 mount myvolume /mnt/encrypted
    4. Use:     cp files /mnt/encrypted/
    5. Unmount: luks2 unmount /mnt/encrypted
    6. Close:   luks2 close myvolume

WORKFLOW (File Volume):
    1. Create:  luks2 create encrypted.luks 100M  (auto-configured!)
    2. Mount:   luks2 mount luks-auto /mnt/encrypted
    3. Use:     cp files /mnt/encrypted/
    4. Unmount: luks2 unmount /mnt/encrypted
    5. Close:   luks2 close luks-auto

NOTE:
    - Requires root privileges for most operations
    - Passphrases are never logged or displayed
    - All operations use pure Go (no external tools)
    - File volumes are automatically configured (loop device + filesystem)
`

func main() {
	cli := NewCLI()
	code := cli.Run()
	if code != 0 {
		cli.ExitFunc(code)
	}
}
