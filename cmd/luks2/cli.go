// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// LuksOperations defines the interface for LUKS2 operations
type LuksOperations interface {
	Format(opts luks2.FormatOptions) error
	Unlock(device string, passphrase []byte, name string) error
	Lock(name string) error
	Mount(opts luks2.MountOptions) error
	Unmount(mountPoint string, flags int) error
	GetVolumeInfo(device string) (*luks2.VolumeInfo, error)
	Wipe(opts luks2.WipeOptions) error
	SetupLoopDevice(filename string) (string, error)
	DetachLoopDevice(loopDev string) error
	MakeFilesystem(volumeName, fstype, label string) error
	IsMounted(mountPoint string) (bool, error)
	IsUnlocked(name string) bool
}

// Terminal defines the interface for terminal operations
type Terminal interface {
	ReadPassword(fd int) ([]byte, error)
}

// FileSystem defines the interface for file system operations
type FileSystem interface {
	Create(name string) (*os.File, error)
	Stat(name string) (os.FileInfo, error)
	Remove(name string) error
	MkdirAll(path string, perm os.FileMode) error
}

// CLI represents the command-line interface application
type CLI struct {
	Args       []string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	Luks       LuksOperations
	Terminal   Terminal
	FS         FileSystem
	ExitFunc   func(code int)
	stdinFd    int
	getStdinFd func() int
}

// DefaultLuksOperations implements LuksOperations using the actual luks2 package
type DefaultLuksOperations struct{}

func (d *DefaultLuksOperations) Format(opts luks2.FormatOptions) error {
	return luks2.Format(opts)
}

func (d *DefaultLuksOperations) Unlock(device string, passphrase []byte, name string) error {
	return luks2.Unlock(device, passphrase, name)
}

func (d *DefaultLuksOperations) Lock(name string) error {
	return luks2.Lock(name)
}

func (d *DefaultLuksOperations) Mount(opts luks2.MountOptions) error {
	return luks2.Mount(opts)
}

func (d *DefaultLuksOperations) Unmount(mountPoint string, flags int) error {
	return luks2.Unmount(mountPoint, flags)
}

func (d *DefaultLuksOperations) GetVolumeInfo(device string) (*luks2.VolumeInfo, error) {
	return luks2.GetVolumeInfo(device)
}

func (d *DefaultLuksOperations) Wipe(opts luks2.WipeOptions) error {
	return luks2.Wipe(opts)
}

func (d *DefaultLuksOperations) SetupLoopDevice(filename string) (string, error) {
	return luks2.SetupLoopDevice(filename)
}

func (d *DefaultLuksOperations) DetachLoopDevice(loopDev string) error {
	return luks2.DetachLoopDevice(loopDev)
}

func (d *DefaultLuksOperations) MakeFilesystem(volumeName, fstype, label string) error {
	return luks2.MakeFilesystem(volumeName, fstype, label)
}

func (d *DefaultLuksOperations) IsMounted(mountPoint string) (bool, error) {
	return luks2.IsMounted(mountPoint)
}

func (d *DefaultLuksOperations) IsUnlocked(name string) bool {
	return luks2.IsUnlocked(name)
}

// DefaultFileSystem implements FileSystem using the actual os package
type DefaultFileSystem struct{}

func (d *DefaultFileSystem) Create(name string) (*os.File, error) {
	return os.Create(name) // #nosec G304 -- CLI tool intentionally creates files at user-specified paths
}

func (d *DefaultFileSystem) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (d *DefaultFileSystem) Remove(name string) error {
	return os.Remove(name)
}

func (d *DefaultFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// NewCLI creates a new CLI instance with default dependencies
func NewCLI() *CLI {
	return &CLI{
		Args:       os.Args,
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Luks:       &DefaultLuksOperations{},
		Terminal:   &DefaultTerminal{},
		FS:         &DefaultFileSystem{},
		ExitFunc:   os.Exit,
		getStdinFd: func() int { return int(os.Stdin.Fd()) },
	}
}

// Run executes the CLI with the given arguments
func (c *CLI) Run() int {
	if len(c.Args) < 2 {
		c.showBanner()
		_, _ = fmt.Fprint(c.Stdout, usage)
		return 1
	}

	command := c.Args[1]

	switch command {
	case "create":
		return c.cmdCreate()
	case "open":
		return c.cmdOpen()
	case "close":
		return c.cmdClose()
	case "mount":
		return c.cmdMount()
	case "unmount":
		return c.cmdUnmount()
	case "info":
		return c.cmdInfo()
	case "wipe":
		return c.cmdWipe()
	case "help", "--help", "-h":
		c.showBanner()
		_, _ = fmt.Fprint(c.Stdout, usage)
		return 0
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(c.Stdout, "luks2 version %s\n", Version)
		return 0
	default:
		_, _ = fmt.Fprintf(c.Stderr, "Unknown command: %s\n\n", command)
		_, _ = fmt.Fprint(c.Stdout, usage)
		return 1
	}
}

func (c *CLI) showBanner() {
	_, _ = fmt.Fprint(c.Stdout, banner)
}

// cmdCreate handles the create command
func (c *CLI) cmdCreate() int {
	if len(c.Args) < 3 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 create <path> [size] [filesystem]")
		_, _ = fmt.Fprintln(c.Stdout, "\nFor block devices:")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 create /dev/sdb1")
		_, _ = fmt.Fprintln(c.Stdout, "\nFor file volumes:")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 create encrypted.luks 100M")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 create encrypted.luks 1G ext4")
		_, _ = fmt.Fprintln(c.Stdout, "\nSize suffixes: K, M, G, T")
		_, _ = fmt.Fprintln(c.Stdout, "Filesystem types: ext4, ext3, ext2 (default: ext4)")
		return 1
	}

	path := c.Args[2]
	isBlockDevice := len(path) >= 5 && path[:5] == "/dev/"

	if isBlockDevice {
		return c.cmdCreateBlockDevice(path)
	}
	return c.cmdCreateFile(path)
}

// cmdCreateFile creates a LUKS2 volume in a file with full automation
func (c *CLI) cmdCreateFile(filename string) int {
	if len(c.Args) < 4 {
		_, _ = fmt.Fprintln(c.Stdout, "Error: Size required for file volumes")
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 create <file> <size> [filesystem]")
		_, _ = fmt.Fprintln(c.Stdout, "Example: luks2 create encrypted.luks 100M ext4")
		_, _ = fmt.Fprintln(c.Stdout, "\nSize suffixes: K, M, G, T")
		_, _ = fmt.Fprintln(c.Stdout, "Filesystem types: ext4, ext3, ext2 (default: ext4)")
		return 1
	}

	sizeStr := c.Args[3]

	fstype := "ext4"
	if len(c.Args) > 4 {
		fstype = c.Args[4]
	}

	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Creating LUKS2 encrypted file: %s (%s)\n\n", filename, sizeStr)

	// Parse size
	size, err := ParseSize(sizeStr)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Invalid size: %v\n", err)
		return 1
	}

	// Check if file exists
	if _, err := c.FS.Stat(filename); err == nil {
		_, _ = fmt.Fprintf(c.Stderr, "Error: File already exists: %s\n", filename)
		_, _ = fmt.Fprintln(c.Stderr, "Remove it first if you want to recreate it.")
		return 1
	}

	// Create file
	_, _ = fmt.Fprintf(c.Stdout, "Creating %s file...\n", sizeStr)
	f, err := c.FS.Create(filename)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Failed to create file: %v\n", err)
		return 1
	}

	// Truncate to desired size
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		_ = c.FS.Remove(filename)
		_, _ = fmt.Fprintf(c.Stderr, "Failed to set file size: %v\n", err)
		return 1
	}
	_ = f.Close()

	_, _ = fmt.Fprintln(c.Stdout, "File created")

	// Now format it as LUKS
	_, _ = fmt.Fprintln(c.Stdout, "\nFormatting as LUKS2 volume...")

	// Prompt for passphrase
	passphrase, err := c.promptPassphrase("Enter passphrase for new volume: ", true)
	if err != nil {
		_ = c.FS.Remove(filename)
		_, _ = fmt.Fprintf(c.Stderr, "Error: %v\n", err)
		return 1
	}
	defer ClearBytes(passphrase)

	// Prompt for label
	_, _ = fmt.Fprint(c.Stdout, "Enter volume label (optional, press Enter to skip): ")
	var label string
	_, _ = fmt.Fscanln(c.Stdin, &label)

	// Create format options
	opts := luks2.FormatOptions{
		Device:     filename,
		Passphrase: passphrase,
		Label:      label,
		KDFType:    "argon2id",
	}

	_, _ = fmt.Fprintln(c.Stdout, "\n  Cipher: AES-XTS-256")
	_, _ = fmt.Fprintln(c.Stdout, "  KDF: Argon2id")
	_, _ = fmt.Fprintln(c.Stdout, "  Key Size: 512 bits")
	_, _ = fmt.Fprintln(c.Stdout, "\nThis may take a few seconds...")

	if err := c.Luks.Format(opts); err != nil {
		_ = c.FS.Remove(filename)
		_, _ = fmt.Fprintf(c.Stderr, "\nFailed to format volume: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "\nLUKS2 encrypted file created successfully!")
	_, _ = fmt.Fprintf(c.Stdout, "\nFile: %s\n", filename)
	_, _ = fmt.Fprintf(c.Stdout, "Size: %s\n", sizeStr)

	// Auto-setup loop device
	_, _ = fmt.Fprintln(c.Stdout, "\nSetting up loop device...")
	loopDev, err := c.Luks.SetupLoopDevice(filename)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Warning: Failed to setup loop device: %v\n", err)
		_, _ = fmt.Fprintf(c.Stdout, "\nManual setup: sudo losetup -f %s\n", filename)
		return 0
	}
	_, _ = fmt.Fprintf(c.Stdout, "Loop device created: %s\n", loopDev)

	// Auto-unlock
	_, _ = fmt.Fprintln(c.Stdout, "\nUnlocking volume...")
	volumeName := "luks-auto"
	if err := c.Luks.Unlock(loopDev, passphrase, volumeName); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Warning: Failed to unlock: %v\n", err)
		_, _ = fmt.Fprintf(c.Stdout, "\nManual unlock: sudo luks2 open %s myvolume\n", loopDev)
		return 0
	}
	_, _ = fmt.Fprintf(c.Stdout, "Volume unlocked as: /dev/mapper/%s\n", volumeName)

	// Auto-format filesystem
	_, _ = fmt.Fprintf(c.Stdout, "\nCreating %s filesystem...\n", fstype)
	if err := c.Luks.MakeFilesystem(volumeName, fstype, label); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Warning: Filesystem creation failed: %v\n", err)
		_, _ = fmt.Fprintf(c.Stdout, "Manual format: sudo mkfs.%s /dev/mapper/%s\n", fstype, volumeName)
		_, _ = fmt.Fprintf(c.Stdout, "\nVolume is ready at: /dev/mapper/%s\n", volumeName)
		_, _ = fmt.Fprintf(c.Stdout, "Mount with: sudo luks2 mount %s /mnt/encrypted\n", volumeName)
		return 0
	}
	_, _ = fmt.Fprintln(c.Stdout, "Filesystem created")

	_, _ = fmt.Fprintln(c.Stdout, "\n========================================")
	_, _ = fmt.Fprintln(c.Stdout, "Volume ready to use!")
	_, _ = fmt.Fprintln(c.Stdout, "========================================")
	_, _ = fmt.Fprintf(c.Stdout, "\nMount: sudo luks2 mount %s /mnt/encrypted\n", volumeName)
	_, _ = fmt.Fprintln(c.Stdout, "Use:   ls /mnt/encrypted")
	_, _ = fmt.Fprintln(c.Stdout, "\nCleanup:")
	_, _ = fmt.Fprintln(c.Stdout, "  sudo luks2 unmount /mnt/encrypted")
	_, _ = fmt.Fprintf(c.Stdout, "  sudo luks2 close %s\n", volumeName)

	return 0
}

// cmdCreateBlockDevice creates a LUKS2 volume on a block device
func (c *CLI) cmdCreateBlockDevice(device string) int {
	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Creating LUKS2 volume on block device: %s\n\n", device)

	// Prompt for passphrase
	passphrase, err := c.promptPassphrase("Enter passphrase for new volume: ", true)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Error: %v\n", err)
		return 1
	}
	defer ClearBytes(passphrase)

	// Prompt for label
	_, _ = fmt.Fprint(c.Stdout, "Enter volume label (optional, press Enter to skip): ")
	var label string
	_, _ = fmt.Fscanln(c.Stdin, &label)

	// Create format options
	opts := luks2.FormatOptions{
		Device:     device,
		Passphrase: passphrase,
		Label:      label,
		KDFType:    "argon2id",
	}

	_, _ = fmt.Fprintln(c.Stdout, "\nCreating LUKS2 volume...")
	_, _ = fmt.Fprintln(c.Stdout, "  Cipher: AES-XTS-256")
	_, _ = fmt.Fprintln(c.Stdout, "  KDF: Argon2id")
	_, _ = fmt.Fprintln(c.Stdout, "  Key Size: 512 bits")
	_, _ = fmt.Fprintln(c.Stdout, "\nThis may take a few seconds...")

	if err := c.Luks.Format(opts); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "\nFailed to create volume: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "\nLUKS2 volume created successfully!")
	_, _ = fmt.Fprintln(c.Stdout, "\nNext steps:")
	_, _ = fmt.Fprintf(c.Stdout, "  1. Open:  sudo luks2 open %s myvolume\n", device)
	_, _ = fmt.Fprintln(c.Stdout, "  2. Mount: sudo luks2 mount myvolume /mnt/encrypted")

	return 0
}

// cmdOpen unlocks a LUKS2 volume
func (c *CLI) cmdOpen() int {
	if len(c.Args) < 4 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 open <device> <name>")
		_, _ = fmt.Fprintln(c.Stdout, "Example: luks2 open /dev/sdb1 my-encrypted-disk")
		return 1
	}

	device := c.Args[2]
	name := c.Args[3]

	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Opening LUKS2 volume: %s -> %s\n\n", device, name)

	// Prompt for passphrase
	passphrase, err := c.promptPassphrase("Enter passphrase: ", false)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Error: %v\n", err)
		return 1
	}
	defer ClearBytes(passphrase)

	_, _ = fmt.Fprintln(c.Stdout, "\nUnlocking volume...")

	if err := c.Luks.Unlock(device, passphrase, name); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "\nFailed to unlock volume: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "\nVolume unlocked successfully!")
	_, _ = fmt.Fprintf(c.Stdout, "\nDevice mapper created: /dev/mapper/%s\n", name)
	_, _ = fmt.Fprintln(c.Stdout, "\nNext steps:")
	_, _ = fmt.Fprintf(c.Stdout, "  Format (first time): sudo mkfs.ext4 /dev/mapper/%s\n", name)
	_, _ = fmt.Fprintf(c.Stdout, "  Mount: sudo luks2 mount %s /mnt/encrypted\n", name)

	return 0
}

// cmdClose locks a LUKS2 volume
func (c *CLI) cmdClose() int {
	if len(c.Args) < 3 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 close <name>")
		_, _ = fmt.Fprintln(c.Stdout, "Example: luks2 close my-encrypted-disk")
		return 1
	}

	name := c.Args[2]

	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Closing LUKS2 volume: %s\n\n", name)

	// Check if mounted
	mounted, err := c.Luks.IsMounted("/dev/mapper/" + name)
	if err == nil && mounted {
		_, _ = fmt.Fprintln(c.Stderr, "Volume is still mounted!")
		_, _ = fmt.Fprintln(c.Stderr, "Please unmount first: sudo luks2 unmount <mountpoint>")
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "Locking volume...")

	if err := c.Luks.Lock(name); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "\nFailed to lock volume: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "\nVolume locked successfully!")
	_, _ = fmt.Fprintf(c.Stdout, "\nDevice mapper removed: /dev/mapper/%s\n", name)

	return 0
}

// cmdMount mounts an unlocked LUKS2 volume
func (c *CLI) cmdMount() int {
	if len(c.Args) < 4 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 mount <name> <mountpoint>")
		_, _ = fmt.Fprintln(c.Stdout, "Example: luks2 mount my-encrypted-disk /mnt/encrypted")
		return 1
	}

	name := c.Args[2]
	mountpoint := c.Args[3]

	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Mounting volume: %s -> %s\n\n", name, mountpoint)

	// Check if already mounted
	mounted, _ := c.Luks.IsMounted(mountpoint)
	if mounted {
		_, _ = fmt.Fprintf(c.Stderr, "Mountpoint already in use: %s\n", mountpoint)
		return 1
	}

	// Create mountpoint if it doesn't exist
	if _, err := c.FS.Stat(mountpoint); os.IsNotExist(err) {
		_, _ = fmt.Fprintf(c.Stdout, "Creating mountpoint: %s\n", mountpoint)
		if err := c.FS.MkdirAll(mountpoint, 0750); err != nil {
			_, _ = fmt.Fprintf(c.Stderr, "Failed to create mountpoint: %v\n", err)
			return 1
		}
	}

	opts := luks2.MountOptions{
		Device:     name,
		MountPoint: mountpoint,
		FSType:     "ext4",
		Flags:      0,
		Data:       "",
	}

	_, _ = fmt.Fprintln(c.Stdout, "Mounting...")

	if err := c.Luks.Mount(opts); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "\nFailed to mount: %v\n", err)
		_, _ = fmt.Fprintln(c.Stderr, "\nHave you created a filesystem? Try:")
		_, _ = fmt.Fprintf(c.Stderr, "  sudo mkfs.ext4 /dev/mapper/%s\n", name)
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "\nVolume mounted successfully!")
	_, _ = fmt.Fprintf(c.Stdout, "\nYou can now use: %s\n", mountpoint)

	return 0
}

// cmdUnmount unmounts a LUKS2 volume
func (c *CLI) cmdUnmount() int {
	if len(c.Args) < 3 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 unmount <mountpoint>")
		_, _ = fmt.Fprintln(c.Stdout, "Example: luks2 unmount /mnt/encrypted")
		return 1
	}

	mountpoint := c.Args[2]

	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Unmounting: %s\n\n", mountpoint)

	// Check if mounted
	mounted, _ := c.Luks.IsMounted(mountpoint)
	if !mounted {
		_, _ = fmt.Fprintf(c.Stderr, "Not mounted: %s\n", mountpoint)
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "Unmounting...")

	if err := c.Luks.Unmount(mountpoint, 0); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "\nFailed to unmount: %v\n", err)
		_, _ = fmt.Fprintf(c.Stderr, "\nTry forcing unmount with: umount -l %s\n", mountpoint)
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "\nVolume unmounted successfully!")

	return 0
}

// cmdInfo displays volume information
func (c *CLI) cmdInfo() int {
	if len(c.Args) < 3 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 info <device>")
		_, _ = fmt.Fprintln(c.Stdout, "Example: luks2 info /dev/sdb1")
		return 1
	}

	device := c.Args[2]

	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Volume Information: %s\n", device)
	_, _ = fmt.Fprintln(c.Stdout, "===========================================================")

	info, err := c.Luks.GetVolumeInfo(device)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "\nFailed to read volume: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintf(c.Stdout, "\nUUID:           %s\n", info.UUID)
	_, _ = fmt.Fprintf(c.Stdout, "Label:          %s\n", info.Label)
	_, _ = fmt.Fprintf(c.Stdout, "Version:        LUKS%d\n", info.Version)
	_, _ = fmt.Fprintf(c.Stdout, "Cipher:         %s\n", info.Cipher)
	_, _ = fmt.Fprintf(c.Stdout, "Sector Size:    %d bytes\n", info.SectorSize)
	_, _ = fmt.Fprintf(c.Stdout, "Active Keyslots: %v\n", info.ActiveKeyslots)

	if len(info.ActiveKeyslots) > 0 {
		_, _ = fmt.Fprintln(c.Stdout, "\nKeyslot Details:")
		for _, slot := range info.ActiveKeyslots {
			ks := info.Metadata.Keyslots[fmt.Sprintf("%d", slot)]
			if ks != nil {
				_, _ = fmt.Fprintf(c.Stdout, "  Slot %d: %s (key size: %d bytes)\n", slot, ks.KDF.Type, ks.KeySize)
			}
		}
	}

	_, _ = fmt.Fprintln(c.Stdout, "\nVolume is valid and accessible")

	return 0
}

// cmdWipe securely wipes a LUKS2 volume
func (c *CLI) cmdWipe() int {
	if len(c.Args) < 3 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 wipe [options] <device>")
		_, _ = fmt.Fprintln(c.Stdout, "")
		_, _ = fmt.Fprintln(c.Stdout, "Options:")
		_, _ = fmt.Fprintln(c.Stdout, "  --full           Wipe entire device (default: headers only)")
		_, _ = fmt.Fprintln(c.Stdout, "  --passes N       Number of overwrite passes (default: 1)")
		_, _ = fmt.Fprintln(c.Stdout, "  --random         Use random data instead of zeros")
		_, _ = fmt.Fprintln(c.Stdout, "  --trim           Issue TRIM/DISCARD after wipe (for SSDs)")
		_, _ = fmt.Fprintln(c.Stdout, "")
		_, _ = fmt.Fprintln(c.Stdout, "Examples:")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe /dev/sdb1                    # Wipe headers only (fast)")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe --full /dev/sdb1             # Wipe entire device")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe --full --passes 3 /dev/sdb1  # DoD-style 3-pass wipe")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe --full --random /dev/sdb1    # Random data wipe")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe --full --trim /dev/ssd1      # Full wipe + TRIM for SSD")
		return 1
	}

	// Parse options
	opts := luks2.WipeOptions{
		Passes:     1,
		Random:     false,
		HeaderOnly: true,
		Trim:       false,
	}

	var device string
	for i := 2; i < len(c.Args); i++ {
		switch c.Args[i] {
		case "--full":
			opts.HeaderOnly = false
		case "--random":
			opts.Random = true
		case "--trim":
			opts.Trim = true
		case "--passes":
			if i+1 < len(c.Args) {
				i++
				var passes int
				_, err := fmt.Sscanf(c.Args[i], "%d", &passes)
				if err != nil || passes < 1 {
					_, _ = fmt.Fprintf(c.Stderr, "Invalid passes value: %s (must be >= 1)\n", c.Args[i])
					return 1
				}
				opts.Passes = passes
			} else {
				_, _ = fmt.Fprintln(c.Stderr, "--passes requires a value")
				return 1
			}
		default:
			if c.Args[i][0] == '-' {
				_, _ = fmt.Fprintf(c.Stderr, "Unknown option: %s\n", c.Args[i])
				return 1
			}
			device = c.Args[i]
		}
	}

	if device == "" {
		_, _ = fmt.Fprintln(c.Stderr, "Error: device path required")
		return 1
	}

	opts.Device = device

	c.showBanner()
	_, _ = fmt.Fprintln(c.Stdout, "*** WARNING: DESTRUCTIVE OPERATION ***")
	_, _ = fmt.Fprintf(c.Stdout, "\nThis will PERMANENTLY DESTROY all data on: %s\n", device)
	_, _ = fmt.Fprintln(c.Stdout, "This action CANNOT be undone!")

	// Show wipe configuration
	_, _ = fmt.Fprintln(c.Stdout, "")
	if opts.HeaderOnly {
		_, _ = fmt.Fprintln(c.Stdout, "Mode: Header wipe only (fast)")
	} else {
		_, _ = fmt.Fprintf(c.Stdout, "Mode: Full device wipe (%d pass", opts.Passes)
		if opts.Passes > 1 {
			_, _ = fmt.Fprint(c.Stdout, "es")
		}
		_, _ = fmt.Fprintln(c.Stdout, ")")
		if opts.Random {
			_, _ = fmt.Fprintln(c.Stdout, "Data: Random")
		} else {
			_, _ = fmt.Fprintln(c.Stdout, "Data: Zeros")
		}
		if opts.Trim {
			_, _ = fmt.Fprintln(c.Stdout, "TRIM: Enabled (SSD)")
		}
	}

	// Confirmation
	_, _ = fmt.Fprint(c.Stdout, "\nType 'YES' to confirm wipe: ")
	var confirm string
	_, _ = fmt.Fscanln(c.Stdin, &confirm)

	if confirm != "YES" {
		_, _ = fmt.Fprintln(c.Stdout, "\nWipe cancelled")
		return 0
	}

	if opts.HeaderOnly {
		_, _ = fmt.Fprintln(c.Stdout, "\nWiping LUKS headers...")
	} else {
		_, _ = fmt.Fprintln(c.Stdout, "\nWiping entire device (this may take a while)...")
	}

	if err := c.Luks.Wipe(opts); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "\nFailed to wipe: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "\nVolume wiped successfully!")
	_, _ = fmt.Fprintln(c.Stdout, "\nThe device is no longer encrypted and cannot be unlocked.")

	return 0
}

// promptPassphrase prompts for passphrase with hidden input
func (c *CLI) promptPassphrase(prompt string, confirm bool) ([]byte, error) {
	_, _ = fmt.Fprint(c.Stdout, prompt)

	fd := c.stdinFd
	if c.getStdinFd != nil {
		fd = c.getStdinFd()
	}

	passphrase, err := c.Terminal.ReadPassword(fd)
	_, _ = fmt.Fprintln(c.Stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}

	if confirm {
		_, _ = fmt.Fprint(c.Stdout, "Confirm passphrase: ")
		confirmation, err := c.Terminal.ReadPassword(fd)
		_, _ = fmt.Fprintln(c.Stdout)
		if err != nil {
			return nil, fmt.Errorf("failed to read confirmation: %w", err)
		}

		if string(passphrase) != string(confirmation) {
			return nil, fmt.Errorf("passphrases do not match")
		}
	}

	return passphrase, nil
}

// ParseSize parses a size string like "100M" into bytes (exported for testing)
func ParseSize(s string) (int64, error) {
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

// ClearBytes securely clears a byte slice (exported for testing)
func ClearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
