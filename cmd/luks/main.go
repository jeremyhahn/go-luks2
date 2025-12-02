// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/jeremyhahn/go-luks2/pkg/luks"
	"golang.org/x/term"
)

// Version information
const Version = "1.0.0"

const banner = `
╔══════════════════════════════════════════════════════════════╗
║                   LUKS2 Volume Manager                       ║
║              Pure Go LUKS2 Implementation                    ║
╚══════════════════════════════════════════════════════════════╝
`

const usage = `
USAGE:
    luks <command> [options]

COMMANDS:
    create <path> [size]         Create a new LUKS2 volume
                                 - Block device: luks create /dev/sdb1
                                 - File volume:  luks create encrypted.luks 100M
    open <device> <name>         Unlock and open a LUKS volume
    close <name>                 Lock and close a LUKS volume
    mount <name> <mountpoint>    Mount an unlocked volume
    unmount <mountpoint>         Unmount a volume
    info <device>                Show volume information
    wipe <device>                Securely wipe a volume
    help                         Show this help message
    version                      Show version information

EXAMPLES:
    # Create a new LUKS2 encrypted volume on a block device
    sudo luks create /dev/sdb1

    # Create a LUKS2 encrypted volume in a file (auto-configured)
    sudo luks create encrypted.luks 100M

    # Open (unlock) the volume
    sudo luks open /dev/sdb1 my-encrypted-disk

    # Mount the unlocked volume
    sudo luks mount my-encrypted-disk /mnt/encrypted

    # Use your encrypted storage
    ls /mnt/encrypted

    # Unmount when done
    sudo luks unmount /mnt/encrypted

    # Close (lock) the volume
    sudo luks close my-encrypted-disk

    # View volume information
    sudo luks info /dev/sdb1

    # Securely wipe (CAUTION: destroys data!)
    sudo luks wipe /dev/sdb1

WORKFLOW (Block Device):
    1. Create:  luks create /dev/sdb1
    2. Open:    luks open /dev/sdb1 myvolume
    3. Mount:   luks mount myvolume /mnt/encrypted
    4. Use:     cp files /mnt/encrypted/
    5. Unmount: luks unmount /mnt/encrypted
    6. Close:   luks close myvolume

WORKFLOW (File Volume):
    1. Create:  luks create encrypted.luks 100M  (auto-configured!)
    2. Mount:   luks mount luks-auto /mnt/encrypted
    3. Use:     cp files /mnt/encrypted/
    4. Unmount: luks unmount /mnt/encrypted
    5. Close:   luks close luks-auto

NOTE:
    - Requires root privileges for most operations
    - Passphrases are never logged or displayed
    - All operations use pure Go (no external tools)
    - File volumes are automatically configured (loop device + filesystem)
`

func main() {
	if len(os.Args) < 2 {
		showBanner()
		fmt.Print(usage)
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "create":
		cmdCreate()
	case "open":
		cmdOpen()
	case "close":
		cmdClose()
	case "mount":
		cmdMount()
	case "unmount":
		cmdUnmount()
	case "info":
		cmdInfo()
	case "wipe":
		cmdWipe()
	case "help", "--help", "-h":
		showBanner()
		fmt.Print(usage)
	case "version", "--version", "-v":
		fmt.Printf("luks version %s\n", Version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		fmt.Print(usage)
		os.Exit(1)
	}
}

func showBanner() {
	fmt.Print(banner)
}

// cmdCreateFile creates a LUKS2 volume in a file with full automation
func cmdCreateFile(filename string) {
	if len(os.Args) < 4 {
		fmt.Println("Error: Size required for file volumes")
		fmt.Println("Usage: luks create <file> <size> [filesystem]")
		fmt.Println("Example: luks create encrypted.luks 100M ext4")
		fmt.Println("\nSize suffixes: K, M, G, T")
		fmt.Println("Filesystem types: ext4, ext3, ext2 (default: ext4)")
		os.Exit(1)
	}

	sizeStr := os.Args[3]

	fstype := "ext4"
	if len(os.Args) > 4 {
		fstype = os.Args[4]
	}

	showBanner()
	fmt.Printf("Creating LUKS2 encrypted file: %s (%s)\n\n", filename, sizeStr)

	// Parse size
	size, err := parseSize(sizeStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid size: %v\n", err)
		os.Exit(1)
	}

	// Check if file exists
	if _, err := os.Stat(filename); err == nil {
		fmt.Fprintf(os.Stderr, "Error: File already exists: %s\n", filename)
		fmt.Fprintf(os.Stderr, "Remove it first if you want to recreate it.\n")
		os.Exit(1)
	}

	// Create file
	fmt.Printf("Creating %s file...\n", sizeStr)
	f, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create file: %v\n", err)
		os.Exit(1)
	}

	// Truncate to desired size
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		_ = os.Remove(filename)
		fmt.Fprintf(os.Stderr, "Failed to set file size: %v\n", err)
		os.Exit(1)
	}
	_ = f.Close()

	fmt.Println("✓ File created")

	// Now format it as LUKS
	fmt.Println("\nFormatting as LUKS2 volume...")

	// Prompt for passphrase
	passphrase, err := promptPassphrase("Enter passphrase for new volume: ", true)
	if err != nil {
		_ = os.Remove(filename)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer clearBytes(passphrase)

	// Prompt for label
	fmt.Print("Enter volume label (optional, press Enter to skip): ")
	var label string
	_, _ = fmt.Scanln(&label)

	// Create format options
	opts := luks.FormatOptions{
		Device:     filename,
		Passphrase: passphrase,
		Label:      label,
		KDFType:    "argon2id",
	}

	fmt.Println("\n  Cipher: AES-XTS-256")
	fmt.Println("  KDF: Argon2id")
	fmt.Println("  Key Size: 512 bits")
	fmt.Println("\nThis may take a few seconds...")

	if err := luks.Format(opts); err != nil {
		_ = os.Remove(filename)
		fmt.Fprintf(os.Stderr, "\n✗ Failed to format volume: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✓ LUKS2 encrypted file created successfully!")
	fmt.Printf("\nFile: %s\n", filename)
	fmt.Printf("Size: %s\n", sizeStr)

	// Auto-setup loop device
	fmt.Println("\nSetting up loop device...")
	loopDev, err := luks.SetupLoopDevice(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to setup loop device: %v\n", err)
		fmt.Printf("\nManual setup: sudo losetup -f %s\n", filename)
		return
	}
	fmt.Printf("✓ Loop device created: %s\n", loopDev)

	// Auto-unlock
	fmt.Println("\nUnlocking volume...")
	volumeName := "luks-auto"
	if err := luks.Unlock(loopDev, passphrase, volumeName); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to unlock: %v\n", err)
		fmt.Printf("\nManual unlock: sudo luks open %s myvolume\n", loopDev)
		return
	}
	fmt.Printf("✓ Volume unlocked as: /dev/mapper/%s\n", volumeName)

	// Auto-format filesystem
	fmt.Printf("\nCreating %s filesystem...\n", fstype)
	if err := luks.MakeFilesystem(volumeName, fstype, label); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Filesystem creation failed: %v\n", err)
		fmt.Printf("Manual format: sudo mkfs.%s /dev/mapper/%s\n", fstype, volumeName)
		fmt.Printf("\nVolume is ready at: /dev/mapper/%s\n", volumeName)
		fmt.Printf("Mount with: sudo luks mount %s /mnt/encrypted\n", volumeName)
		return
	}
	fmt.Printf("✓ Filesystem created\n")

	fmt.Println("\n════════════════════════════════════════")
	fmt.Println("✓ Volume ready to use!")
	fmt.Println("════════════════════════════════════════")
	fmt.Printf("\nMount: sudo luks mount %s /mnt/encrypted\n", volumeName)
	fmt.Printf("Use:   ls /mnt/encrypted\n")
	fmt.Printf("\nCleanup:\n")
	fmt.Printf("  sudo luks unmount /mnt/encrypted\n")
	fmt.Printf("  sudo luks close %s\n", volumeName)
}

// parseSize parses a size string like "100M" into bytes
func parseSize(s string) (int64, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("empty size")
	}

	// Get suffix
	suffix := s[len(s)-1]
	var multiplier int64 = 1

	valueStr := s
	switch suffix {
	case 'K', 'k':
		multiplier = 1024
		valueStr = s[:len(s)-1]
	case 'M', 'm':
		multiplier = 1024 * 1024
		valueStr = s[:len(s)-1]
	case 'G', 'g':
		multiplier = 1024 * 1024 * 1024
		valueStr = s[:len(s)-1]
	case 'T', 't':
		multiplier = 1024 * 1024 * 1024 * 1024
		valueStr = s[:len(s)-1]
	}

	var value int64
	_, err := fmt.Sscanf(valueStr, "%d", &value)
	if err != nil {
		return 0, fmt.Errorf("invalid size value: %s", s)
	}

	return value * multiplier, nil
}

// cmdCreate creates a new LUKS2 volume (block device or file)
func cmdCreate() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: luks create <path> [size] [filesystem]")
		fmt.Println("\nFor block devices:")
		fmt.Println("  luks create /dev/sdb1")
		fmt.Println("\nFor file volumes:")
		fmt.Println("  luks create encrypted.luks 100M")
		fmt.Println("  luks create encrypted.luks 1G ext4")
		fmt.Println("\nSize suffixes: K, M, G, T")
		fmt.Println("Filesystem types: ext4, ext3, ext2 (default: ext4)")
		os.Exit(1)
	}

	path := os.Args[2]
	isBlockDevice := len(path) >= 5 && path[:5] == "/dev/"

	if isBlockDevice {
		cmdCreateBlockDevice(path)
	} else {
		cmdCreateFile(path)
	}
}

// cmdCreateBlockDevice creates a LUKS2 volume on a block device
func cmdCreateBlockDevice(device string) {
	showBanner()
	fmt.Printf("Creating LUKS2 volume on block device: %s\n\n", device)

	// Prompt for passphrase
	passphrase, err := promptPassphrase("Enter passphrase for new volume: ", true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer clearBytes(passphrase)

	// Prompt for label
	fmt.Print("Enter volume label (optional, press Enter to skip): ")
	var label string
	_, _ = fmt.Scanln(&label)

	// Create format options
	opts := luks.FormatOptions{
		Device:     device,
		Passphrase: passphrase,
		Label:      label,
		KDFType:    "argon2id",
	}

	fmt.Println("\nCreating LUKS2 volume...")
	fmt.Println("  Cipher: AES-XTS-256")
	fmt.Println("  KDF: Argon2id")
	fmt.Println("  Key Size: 512 bits")
	fmt.Println("\nThis may take a few seconds...")

	if err := luks.Format(opts); err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ Failed to create volume: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✓ LUKS2 volume created successfully!")
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  1. Open:  sudo luks open %s myvolume\n", device)
	fmt.Printf("  2. Mount: sudo luks mount myvolume /mnt/encrypted\n")
}

// cmdOpen unlocks a LUKS2 volume
func cmdOpen() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: luks open <device> <name>")
		fmt.Println("Example: luks open /dev/sdb1 my-encrypted-disk")
		os.Exit(1)
	}

	device := os.Args[2]
	name := os.Args[3]

	showBanner()
	fmt.Printf("Opening LUKS2 volume: %s → %s\n\n", device, name)

	// Prompt for passphrase
	passphrase, err := promptPassphrase("Enter passphrase: ", false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer clearBytes(passphrase)

	fmt.Println("\nUnlocking volume...")

	if err := luks.Unlock(device, passphrase, name); err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ Failed to unlock volume: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✓ Volume unlocked successfully!")
	fmt.Printf("\nDevice mapper created: /dev/mapper/%s\n", name)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  Format (first time): sudo mkfs.ext4 /dev/mapper/%s\n", name)
	fmt.Printf("  Mount: sudo luks mount %s /mnt/encrypted\n", name)
}

// cmdClose locks a LUKS2 volume
func cmdClose() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: luks close <name>")
		fmt.Println("Example: luks close my-encrypted-disk")
		os.Exit(1)
	}

	name := os.Args[2]

	showBanner()
	fmt.Printf("Closing LUKS2 volume: %s\n\n", name)

	// Check if mounted
	mounted, err := luks.IsMounted("/dev/mapper/" + name)
	if err == nil && mounted {
		fmt.Fprintf(os.Stderr, "✗ Volume is still mounted!\n")
		fmt.Fprintf(os.Stderr, "Please unmount first: sudo luks unmount <mountpoint>\n")
		os.Exit(1)
	}

	fmt.Println("Locking volume...")

	if err := luks.Lock(name); err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ Failed to lock volume: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✓ Volume locked successfully!")
	fmt.Printf("\nDevice mapper removed: /dev/mapper/%s\n", name)
}

// cmdMount mounts an unlocked LUKS2 volume
func cmdMount() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: luks mount <name> <mountpoint>")
		fmt.Println("Example: luks mount my-encrypted-disk /mnt/encrypted")
		os.Exit(1)
	}

	name := os.Args[2]
	mountpoint := os.Args[3]

	showBanner()
	fmt.Printf("Mounting volume: %s → %s\n\n", name, mountpoint)

	// Check if already mounted
	mounted, _ := luks.IsMounted(mountpoint)
	if mounted {
		fmt.Fprintf(os.Stderr, "✗ Mountpoint already in use: %s\n", mountpoint)
		os.Exit(1)
	}

	// Create mountpoint if it doesn't exist
	if _, err := os.Stat(mountpoint); os.IsNotExist(err) {
		fmt.Printf("Creating mountpoint: %s\n", mountpoint)
		if err := os.MkdirAll(mountpoint, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "✗ Failed to create mountpoint: %v\n", err)
			os.Exit(1)
		}
	}

	opts := luks.MountOptions{
		Device:     name,
		MountPoint: mountpoint,
		FSType:     "ext4", // Default, will auto-detect
		Flags:      0,
		Data:       "",
	}

	fmt.Println("Mounting...")

	if err := luks.Mount(opts); err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ Failed to mount: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nHave you created a filesystem? Try:\n")
		fmt.Fprintf(os.Stderr, "  sudo mkfs.ext4 /dev/mapper/%s\n", name)
		os.Exit(1)
	}

	fmt.Println("\n✓ Volume mounted successfully!")
	fmt.Printf("\nYou can now use: %s\n", mountpoint)
}

// cmdUnmount unmounts a LUKS2 volume
func cmdUnmount() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: luks unmount <mountpoint>")
		fmt.Println("Example: luks unmount /mnt/encrypted")
		os.Exit(1)
	}

	mountpoint := os.Args[2]

	showBanner()
	fmt.Printf("Unmounting: %s\n\n", mountpoint)

	// Check if mounted
	mounted, _ := luks.IsMounted(mountpoint)
	if !mounted {
		fmt.Fprintf(os.Stderr, "✗ Not mounted: %s\n", mountpoint)
		os.Exit(1)
	}

	fmt.Println("Unmounting...")

	if err := luks.Unmount(mountpoint, 0); err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ Failed to unmount: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nTry forcing unmount with: umount -l %s\n", mountpoint)
		os.Exit(1)
	}

	fmt.Println("\n✓ Volume unmounted successfully!")
}

// cmdInfo displays volume information
func cmdInfo() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: luks info <device>")
		fmt.Println("Example: luks info /dev/sdb1")
		os.Exit(1)
	}

	device := os.Args[2]

	showBanner()
	fmt.Printf("Volume Information: %s\n", device)
	fmt.Println("═══════════════════════════════════════════════════════════")

	info, err := luks.GetVolumeInfo(device)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ Failed to read volume: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nUUID:           %s\n", info.UUID)
	fmt.Printf("Label:          %s\n", info.Label)
	fmt.Printf("Version:        LUKS%d\n", info.Version)
	fmt.Printf("Cipher:         %s\n", info.Cipher)
	fmt.Printf("Sector Size:    %d bytes\n", info.SectorSize)
	fmt.Printf("Active Keyslots: %v\n", info.ActiveKeyslots)

	if len(info.ActiveKeyslots) > 0 {
		fmt.Printf("\nKeyslot Details:\n")
		for _, slot := range info.ActiveKeyslots {
			ks := info.Metadata.Keyslots[fmt.Sprintf("%d", slot)]
			if ks != nil {
				fmt.Printf("  Slot %d: %s (key size: %d bytes)\n", slot, ks.KDF.Type, ks.KeySize)
			}
		}
	}

	fmt.Println("\n✓ Volume is valid and accessible")
}

// cmdWipe securely wipes a LUKS2 volume
func cmdWipe() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: luks wipe <device>")
		fmt.Println("Example: luks wipe /dev/sdb1")
		os.Exit(1)
	}

	device := os.Args[2]

	showBanner()
	fmt.Printf("*** WARNING: DESTRUCTIVE OPERATION ***\n")
	fmt.Printf("\nThis will PERMANENTLY DESTROY all data on: %s\n", device)
	fmt.Printf("This action CANNOT be undone!\n\n")

	// Confirmation
	fmt.Print("Type 'YES' to confirm wipe: ")
	var confirm string
	_, _ = fmt.Scanln(&confirm)

	if confirm != "YES" {
		fmt.Println("\n✓ Wipe cancelled")
		os.Exit(0)
	}

	fmt.Println("\nWiping LUKS headers...")

	opts := luks.WipeOptions{
		Device:     device,
		Passes:     1,
		Random:     false,
		HeaderOnly: true, // Only wipe headers by default
	}

	if err := luks.Wipe(opts); err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ Failed to wipe: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✓ Volume wiped successfully!")
	fmt.Printf("\nThe device is no longer encrypted and cannot be unlocked.\n")
}

// promptPassphrase prompts for passphrase with hidden input
func promptPassphrase(prompt string, confirm bool) ([]byte, error) {
	fmt.Print(prompt)
	passphrase, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}

	if confirm {
		fmt.Print("Confirm passphrase: ")
		confirmation, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return nil, fmt.Errorf("failed to read confirmation: %w", err)
		}

		if string(passphrase) != string(confirmation) {
			return nil, fmt.Errorf("passphrases do not match")
		}
	}

	return passphrase, nil
}

// clearBytes securely clears a byte slice
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
