// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// LuksOperations defines the interface for LUKS2 operations
type LuksOperations interface {
	Format(opts luks2.FormatOptions) error
	Unlock(device string, passphrase []byte, name string) error
	Lock(name string) error
	Mount(opts luks2.MountOptions) error
	DetectFilesystem(name string) (luks2.FilesystemType, error)
	Unmount(mountPoint string, flags int) error
	GetVolumeInfo(device string) (*luks2.VolumeInfo, error)
	Wipe(opts luks2.WipeOptions) error
	SetupLoopDevice(filename string) (string, error)
	DetachLoopDevice(loopDev string) error
	MakeFilesystem(volumeName, fstype, label string) error
	IsMounted(mountPoint string) (bool, error)
	IsMappingMounted(name string) (bool, error)
	IsUnlocked(name string) bool

	// Keyslots
	TestKey(device string, passphrase []byte) error
	AddKey(device string, existing, newPassphrase []byte, opts *luks2.AddKeyOptions) (int, error)
	RemoveKey(device string, passphrase []byte, keyslot int) error
	KillSlot(device string, authPassphrase []byte, targetSlot int) error
	ChangeKey(device string, oldPassphrase, newPassphrase []byte, keyslot int) error
	ListKeyslots(device string) ([]luks2.KeyslotInfo, error)

	// Recovery keys
	GenerateRecoveryKey(length int, format luks2.RecoveryKeyFormat) (*luks2.RecoveryKey, error)
	AddRecoveryKey(device string, existing []byte, opts *luks2.RecoveryKeyOptions) (*luks2.RecoveryKey, error)
	SaveRecoveryKey(key *luks2.RecoveryKey, path string) error
	LoadRecoveryCredential(path string) (*enclave.MemoryEnclave, error)
	RecoveryCredential(formatted string) (*enclave.MemoryEnclave, error)
	VerifyRecoveryKey(device string, key *enclave.MemoryEnclave) (bool, error)

	// Tokens
	GetToken(device string, tokenID int) (*luks2.Token, error)
	ListTokens(device string) (map[int]*luks2.Token, error)
	ExportToken(device string, tokenID int) ([]byte, error)
	ImportToken(device string, tokenID int, token *luks2.Token) error
	ImportTokenJSON(device string, tokenID int, tokenJSON []byte) error
	RemoveToken(device string, tokenID int) error
	FindFreeTokenSlot(device string) (int, error)
	TokenExists(device string, tokenID int) (bool, error)
	CountTokens(device string) (int, error)

	// Header
	ReadHeader(device string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error)
	ReadSecondaryHeader(device string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error)
	RestorePrimaryHeader(device string, opts luks2.RestoreHeaderOptions) error
	IsLUKS(device string) (bool, error)
	IsLUKS2(device string) (bool, error)
}

// Terminal defines the interface for terminal operations
type Terminal interface {
	ReadPassword(fd int) ([]byte, error)

	// IsTerminal reports whether fd is a terminal. It is what decides between
	// prompting for a passphrase and reading one from a pipe, so it belongs on
	// the same seam as the reading itself -- a test that says "there is no
	// terminal here" must be able to say it in one place.
	IsTerminal(fd int) bool
}

// FileSystem defines the interface for file system operations
type FileSystem interface {
	// CreateExclusive creates a file that must not exist yet: O_EXCL, a
	// symlink refused rather than followed (O_NOFOLLOW), mode 0600.
	CreateExclusive(name string) (*os.File, error)

	// RemoveCreated removes name only if it is still the file this run
	// created and holds open as created.
	RemoveCreated(name string, created *os.File) error

	Create(name string) (*os.File, error)
	Open(name string) (*os.File, error)
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

	// Devices is how create inspects a path before formatting it. nil means
	// DefaultDeviceProber.
	Devices DeviceProber

	// destroyEnclave releases a credential the library handed this command.
	// nil means go-enclave's own Destroy; a test sets it to produce the
	// release reports a healthy host never does. See releaseCredential.
	destroyEnclave func(*enclave.MemoryEnclave) error
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

func (d *DefaultLuksOperations) DetectFilesystem(name string) (luks2.FilesystemType, error) {
	return luks2.DetectFilesystem(name)
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

func (d *DefaultLuksOperations) IsMappingMounted(name string) (bool, error) {
	return luks2.IsMappingMounted(name)
}

func (d *DefaultLuksOperations) IsUnlocked(name string) bool {
	return luks2.IsUnlocked(name)
}

// DefaultFileSystem implements FileSystem using the actual os package
type DefaultFileSystem struct{}

func (d *DefaultFileSystem) CreateExclusive(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600) // #nosec G304 -- the operator's path; O_EXCL|O_NOFOLLOW is the point
}

func (d *DefaultFileSystem) RemoveCreated(name string, created *os.File) error {
	return removeCreated(name, created)
}

func (d *DefaultFileSystem) Create(name string) (*os.File, error) {
	return os.Create(name) // #nosec G304 -- CLI tool intentionally creates files at user-specified paths
}

func (d *DefaultFileSystem) Open(name string) (*os.File, error) {
	return os.Open(name) // #nosec G304 -- CLI tool intentionally reads files at user-specified paths
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
		Devices:    DefaultDeviceProber{},
	}
}

// looksLikeADeviceName reports whether an absent path names where a block
// device would be: under /dev, except /dev/shm, which is an ordinary place to
// keep a file. A typo for a device is refused rather than created as a file
// in devtmpfs.
func looksLikeADeviceName(path string) bool {
	return strings.HasPrefix(path, "/dev/") && path != "/dev/shm" && !strings.HasPrefix(path, "/dev/shm/")
}

// devices returns the DeviceProber, defaulting to the real one.
func (c *CLI) devices() DeviceProber {
	if c.Devices == nil {
		return DefaultDeviceProber{}
	}
	return c.Devices
}

// Run executes the CLI with the given arguments
func (c *CLI) Run() int {
	if len(c.Args) < 2 {
		c.showBanner()
		_, _ = fmt.Fprintf(c.Stdout, "%s", usage)
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
	case "testkey":
		return c.cmdTestKey()
	case "addkey":
		return c.cmdAddKey()
	case "removekey":
		return c.cmdRemoveKey()
	case "killslot":
		return c.cmdKillSlot()
	case "changekey":
		return c.cmdChangeKey()
	case "keyslots":
		return c.cmdKeyslots()
	case "recovery":
		return c.cmdRecovery()
	case "token":
		return c.cmdToken()
	case "header":
		return c.cmdHeader()
	case "isluks":
		return c.cmdIsLUKS()
	case "help", "--help", "-h":
		c.showBanner()
		_, _ = fmt.Fprintf(c.Stdout, "%s", usage)
		return 0
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(c.Stdout, "luks2 version %s\n", Version)
		return 0
	default:
		_, _ = fmt.Fprintf(c.Stderr, "Unknown command: %s\n\n", command)
		_, _ = fmt.Fprintf(c.Stdout, "%s", usage)
		return 1
	}
}

func (c *CLI) showBanner() {
	_, _ = fmt.Fprint(c.Stdout, banner)
}

// cmdCreate handles the create command
func (c *CLI) cmdCreate() int {
	o := newOptions("create")
	key := keyFileFlag(o, "key-file")
	kdf := declareKDFFlags(o)
	batch := batchFlags(o)
	force := o.Bool("force")
	args, err := o.parse(c.Args[2:])
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "%v\n", err)
		return 1
	}

	if len(args) < 1 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 create <path> [size] [filesystem]")
		_, _ = fmt.Fprintln(c.Stdout, "\nFor block devices:")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 create /dev/sdb1")
		_, _ = fmt.Fprintln(c.Stdout, "\nFor file volumes:")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 create /srv/encrypted.luks 100M")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 create /srv/encrypted.luks 1G ext4")
		_, _ = fmt.Fprintln(c.Stdout, "\nSize suffixes: K, M, G, T")
		_, _ = fmt.Fprintln(c.Stdout, filesystemTypesHelp())
		_, _ = fmt.Fprintln(c.Stdout, "\nOptions:")
		_, _ = fmt.Fprintf(c.Stdout, "%s", keyFileHelp)
		_, _ = fmt.Fprintf(c.Stdout, "%s", kdfFlagsHelp)
		_, _ = fmt.Fprintf(c.Stdout, "%s", batchFlagsHelp)
		_, _ = fmt.Fprintln(c.Stdout, "  --force              Format a block device that already holds a LUKS header or a filesystem")
		return 1
	}

	// The KDF is settled before anything else happens: a choice this mode
	// refuses must stop the command before it prompts for a passphrase or
	// creates a file (#237).
	choice, err := kdf.resolve()
	if err != nil {
		return c.kdfRefused(err)
	}

	path, err := absPath("create", args[0])
	if err != nil {
		return c.usageError(err)
	}

	// What is at the path decides the flow, not its spelling: a /dev name
	// that is not a block device is refused rather than created as a file.
	kind, err := c.devices().Kind(path)
	if err != nil {
		return c.fail(&DevicePathError{Path: path, Op: "inspect", Err: err})
	}
	switch {
	case kind == pathBlockDevice:
		return c.cmdCreateBlockDevice(path, *key, choice, batch(), *force)
	case kind == pathAbsent && !looksLikeADeviceName(path):
		return c.cmdCreateFile(path, args[1:], *key, choice)
	case kind == pathAbsent:
		_, _ = fmt.Fprintf(c.Stderr, "Error: no such block device: %s\n", path)
		return 1
	default:
		_, _ = fmt.Fprintf(c.Stderr, "Error: File already exists: %s\n", path)
		_, _ = fmt.Fprintln(c.Stderr, "Remove it first if you want to recreate it.")
		return 1
	}
}

// formatOptions returns the FormatOptions for a new volume on device, with
// the KDF the options chose.
func (k kdfChoice) formatOptions(device string, passphrase []byte, label string) luks2.FormatOptions {
	return luks2.FormatOptions{
		Device:          device,
		Passphrase:      passphrase,
		Label:           label,
		KDFType:         k.KDFType,
		PBKDFIterTime:   k.PBKDFIterTime,
		PBKDFIterations: k.PBKDFIterations,
		Argon2Time:      k.Argon2Time,
		Argon2Memory:    k.Argon2Memory,
		Argon2Parallel:  k.Argon2Parallel,
	}
}

// cliExcludedFilesystems are library-supported filesystems that create cannot
// build. create calls MakeFilesystem, which passes only a label; ZFS needs
// ZFSOptions with a pool name, so offering it would advertise a volume the
// command cannot finish formatting.
var cliExcludedFilesystems = map[luks2.FilesystemType]bool{
	luks2.FilesystemZFS: true,
}

// cliFilesystems returns the filesystems create can build: the library's
// SupportedFilesystems() less cliExcludedFilesystems, so the help can never
// offer a type the library refuses (#195).
func cliFilesystems() []luks2.FilesystemType {
	var out []luks2.FilesystemType
	for _, fs := range luks2.SupportedFilesystems() {
		if !cliExcludedFilesystems[fs] {
			out = append(out, fs)
		}
	}
	return out
}

// isCLIFilesystem reports whether create can build fstype.
func isCLIFilesystem(fstype string) bool {
	for _, fs := range cliFilesystems() {
		if string(fs) == fstype {
			return true
		}
	}
	return false
}

// filesystemTypesHelp lists the filesystems create accepts.
func filesystemTypesHelp() string {
	fss := cliFilesystems()
	names := make([]string, 0, len(fss))
	for _, fs := range fss {
		names = append(names, string(fs))
	}
	return "Filesystem types: " + strings.Join(names, ", ") + " (default: ext4)"
}

// cmdCreateFile creates a LUKS2 volume in a file with full automation.
//
// args are the positional arguments after the filename: the size, then
// optionally the filesystem type.
func (c *CLI) cmdCreateFile(filename string, args []string, key KeySource, kdf kdfChoice) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(c.Stdout, "Error: Size required for file volumes")
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 create <file> <size> [filesystem]")
		_, _ = fmt.Fprintln(c.Stdout, "Example: luks2 create /srv/encrypted.luks 100M ext4")
		_, _ = fmt.Fprintln(c.Stdout, "\nSize suffixes: K, M, G, T")
		_, _ = fmt.Fprintln(c.Stdout, filesystemTypesHelp())
		return 1
	}

	sizeStr := args[0]

	fstype := "ext4"
	if len(args) > 1 {
		fstype = args[1]
	}

	// Refuse a filesystem create cannot build before anything is created,
	// formatted or unlocked: failing at the MakeFilesystem step would leave
	// an unlocked, unformatted volume behind (#195).
	if !isCLIFilesystem(fstype) {
		_, _ = fmt.Fprintf(c.Stderr, "Error: Unsupported filesystem: %s\n", fstype)
		_, _ = fmt.Fprintln(c.Stderr, filesystemTypesHelp())
		return 1
	}

	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Creating LUKS2 encrypted file: %s (%s)\n\n", filename, sizeStr)

	// Parse size
	size, err := ParseSize(sizeStr)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Invalid size: %v\n", err)
		return 1
	}

	// Created EXCLUSIVELY, in one step: there is no window between asking
	// whether the file exists and creating it, a symlink planted at the path
	// is refused rather than followed, and only the owner can read it. What
	// was created is remembered, so a cleanup removes this run's file and
	// never one that took its place.
	_, _ = fmt.Fprintf(c.Stdout, "Creating %s file...\n", sizeStr)
	f, err := c.FS.CreateExclusive(filename)
	if errors.Is(err, os.ErrExist) {
		_, _ = fmt.Fprintf(c.Stderr, "Error: File already exists: %s\n", filename)
		_, _ = fmt.Fprintln(c.Stderr, "Remove it first if you want to recreate it.")
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Failed to create file: %v\n", err)
		return 1
	}
	// Held open until the command ends: the descriptor is what lets the
	// cleanup tell this file from one that replaced it.
	defer func() { _ = f.Close() }()
	cleanup := func() { _ = c.FS.RemoveCreated(filename, f) }

	// Truncate to desired size
	if err := f.Truncate(size); err != nil {
		cleanup()
		_, _ = fmt.Fprintf(c.Stderr, "Failed to set file size: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "File created")

	// Now format it as LUKS
	_, _ = fmt.Fprintln(c.Stdout, "\nFormatting as LUKS2 volume...")

	// Obtain the passphrase, from a key file when one was given and from the
	// terminal otherwise.
	passphrase, err := c.readPassphrase("Enter passphrase for new volume: ", true, key)
	if err != nil {
		cleanup()
		_, _ = fmt.Fprintf(c.Stderr, "Error: %v\n", err)
		return 1
	}
	defer ClearBytes(passphrase)

	// The label prompt is skipped when the credential did not come from a
	// terminal: there is nobody there to answer it, and Fscanln would consume
	// whatever the script piped next.
	label := c.promptLabel(key)

	opts := kdf.formatOptions(filename, passphrase, label)

	_, _ = fmt.Fprintln(c.Stdout, "\n  Cipher: AES-XTS-256")
	_, _ = fmt.Fprintf(c.Stdout, "  KDF: %s\n", kdf.Label)
	_, _ = fmt.Fprintln(c.Stdout, "  Key Size: 512 bits")
	_, _ = fmt.Fprintln(c.Stdout, "\nThis may take a few seconds...")

	if err := c.Luks.Format(opts); err != nil {
		cleanup()
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
		_, _ = fmt.Fprintf(c.Stderr, "\nError: Failed to set up a loop device for %s: %v\n", filename, err)
		return c.abandonUnopenedVolume(filename, fstype)
	}
	_, _ = fmt.Fprintf(c.Stdout, "Loop device created: %s\n", loopDev)

	// Auto-unlock
	_, _ = fmt.Fprintln(c.Stdout, "\nUnlocking volume...")
	volumeName := "luks-auto"
	if err := c.Luks.Unlock(loopDev, passphrase, volumeName); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "\nError: Failed to unlock %s: %v\n", loopDev, err)
		if err := c.Luks.DetachLoopDevice(loopDev); err != nil {
			_, _ = fmt.Fprintf(c.Stderr, "Warning: Failed to detach loop device %s: %v\n", loopDev, err)
			_, _ = fmt.Fprintf(c.Stderr, "Detach it with: sudo losetup -d %s\n", loopDev)
		} else {
			_, _ = fmt.Fprintf(c.Stderr, "Detached loop device %s.\n", loopDev)
		}
		return c.abandonUnopenedVolume(filename, fstype)
	}
	_, _ = fmt.Fprintf(c.Stdout, "Volume unlocked as: /dev/mapper/%s\n", volumeName)

	// Auto-format filesystem
	_, _ = fmt.Fprintf(c.Stdout, "\nCreating %s filesystem...\n", fstype)
	if err := c.Luks.MakeFilesystem(volumeName, fstype, label); err != nil {
		return c.abandonUnformattedVolume(filename, loopDev, volumeName, fstype, err)
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

// abandonUnformattedVolume handles a MakeFilesystem failure in create (#229).
// The volume is not usable, so the command fails: it prints the cause, closes
// the mapping it opened so nothing is left unlocked, detaches the loop device
// it attached, and says that the LUKS2 container itself -- which is valid --
// was kept. It always returns exit status 1. Before #229 this path printed
// "Volume is ready" and exited 0, leaving an unlocked mapping with no
// filesystem on it that a script checking the exit status took as usable.
//
// The loop device is detached only once the mapping is closed: while the
// mapping is open it holds the loop device, and the detach would fail.
func (c *CLI) abandonUnformattedVolume(filename, loopDev, volumeName, fstype string, cause error) int {
	_, _ = fmt.Fprintf(c.Stderr, "\nError: Filesystem creation failed: %v\n", cause)

	if err := c.Luks.Lock(volumeName); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Error: Failed to close /dev/mapper/%s: %v\n", volumeName, err)
		_, _ = fmt.Fprintf(c.Stderr, "The volume is still UNLOCKED. Close it with: sudo luks2 close %s\n", volumeName)
		_, _ = fmt.Fprintf(c.Stderr, "Then detach the loop device with: sudo losetup -d %s\n", loopDev)
		return 1
	}
	_, _ = fmt.Fprintf(c.Stderr, "Closed /dev/mapper/%s: the volume is locked.\n", volumeName)

	if err := c.Luks.DetachLoopDevice(loopDev); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Warning: Failed to detach loop device %s: %v\n", loopDev, err)
		_, _ = fmt.Fprintf(c.Stderr, "Detach it with: sudo losetup -d %s\n", loopDev)
	} else {
		_, _ = fmt.Fprintf(c.Stderr, "Detached loop device %s.\n", loopDev)
	}

	_, _ = fmt.Fprintf(c.Stderr, "\nThe LUKS2 container %s is valid and was kept, but filesystem creation did not complete:\n", filename)
	_, _ = fmt.Fprintln(c.Stderr, "whatever the formatter wrote before it failed may be partial.")
	return c.finishByHand(filename, fstype)
}

// finishByHand tells the operator how to finish a create that stopped after
// the container was written, and returns exit status 1.
func (c *CLI) finishByHand(filename, fstype string) int {
	_, _ = fmt.Fprintf(c.Stderr, "Delete it, or attach it (sudo losetup -f --show %s), open it (sudo luks2 open <loop-device> <name>)\n", filename)
	_, _ = fmt.Fprintf(c.Stderr, "and create the filesystem yourself (sudo mkfs.%s /dev/mapper/<name>).\n", fstype)
	return 1
}

// abandonUnopenedVolume ends a create whose container was written but could
// not be attached or opened, so it has no filesystem. The command FAILS: it
// used to print a warning and exit 0, and a script checking the exit status
// took a volume nothing could mount as ready. The container itself is valid
// and is kept, and the operator is told how to finish by hand. It always
// returns exit status 1.
func (c *CLI) abandonUnopenedVolume(filename, fstype string) int {
	_, _ = fmt.Fprintf(c.Stderr, "\nThe LUKS2 container %s is valid and was kept, but it is not open and has no filesystem.\n", filename)
	return c.finishByHand(filename, fstype)
}

// cmdCreateBlockDevice creates a LUKS2 volume on a block device
func (c *CLI) cmdCreateBlockDevice(device string, key KeySource, kdf kdfChoice, batch, force bool) int {
	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Creating LUKS2 volume on block device: %s\n\n", device)

	// Probed before anything is asked: a device that is in use is refused
	// whatever the flags say, and one that holds data is refused without
	// --force.
	found, release, err := c.devices().Claim(device)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Error: cannot use %s: %v\n", device, err)
		return 1
	}
	// The exclusive claim is held through the confirmation and the
	// passphrase prompt, and given up just before Format, which opens the
	// device again itself.
	claimed := true
	unclaim := func() {
		if claimed {
			release()
			claimed = false
		}
	}
	defer unclaim()
	if found != "" {
		if !force {
			_, _ = fmt.Fprintf(c.Stderr, "Error: %s: %s holds %s.\n", ErrDeviceHasData, device, found)
			_, _ = fmt.Fprintln(c.Stderr, "Refusing to format over it. Pass --force to destroy it.")
			return 1
		}
		_, _ = fmt.Fprintf(c.Stdout, "WARNING: %s holds %s, which formatting destroys.\n", device, found)
	}

	// Whole-stdin key input and a confirmation cannot share one stream.
	if key.Path == stdinKeyFile && !batch {
		return c.usageError(&UsageError{Command: "create", Detail: "--key-file - reads standard input, so the confirmation cannot; pass --batch-mode"})
	}
	_, _ = fmt.Fprintf(c.Stdout, "WARNING: This will overwrite data on %s irrevocably.\n", device)
	if err := c.confirmDestructive("Type 'YES' to confirm: ", batch); err != nil {
		return c.refuseUnconfirmed("Create", err)
	}

	// Obtain the passphrase, from a key file when one was given and from the
	// terminal otherwise.
	passphrase, err := c.readPassphrase("Enter passphrase for new volume: ", true, key)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Error: %v\n", err)
		return 1
	}
	defer ClearBytes(passphrase)

	label := c.promptLabel(key)

	opts := kdf.formatOptions(device, passphrase, label)

	_, _ = fmt.Fprintln(c.Stdout, "\nCreating LUKS2 volume...")
	_, _ = fmt.Fprintln(c.Stdout, "  Cipher: AES-XTS-256")
	_, _ = fmt.Fprintf(c.Stdout, "  KDF: %s\n", kdf.Label)
	_, _ = fmt.Fprintln(c.Stdout, "  Key Size: 512 bits")
	_, _ = fmt.Fprintln(c.Stdout, "\nThis may take a few seconds...")

	unclaim()
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
	o := newOptions("open")
	key := keyFileFlag(o, "key-file")
	args, err := o.parse(c.Args[2:])
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "%v\n", err)
		return 1
	}

	if len(args) < 2 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 open [options] <device> <name>")
		_, _ = fmt.Fprintln(c.Stdout, "Example: luks2 open /dev/sdb1 my-encrypted-disk")
		_, _ = fmt.Fprintln(c.Stdout, "\nOptions:")
		_, _ = fmt.Fprintf(c.Stdout, "%s", keyFileHelp)
		return 1
	}

	device, err := absPath("open", args[0])
	if err != nil {
		return c.usageError(err)
	}
	name := args[1]

	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Opening LUKS2 volume: %s -> %s\n\n", device, name)

	// The credential: a key file, a pipe, or the terminal.
	passphrase, err := c.readPassphrase("Enter passphrase: ", false, *key)
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

	// Check if mounted.
	//
	// By the mapping's DEVICE, not a path: this used to ask IsMounted whether
	// "/dev/mapper/<name>" was a mount point, which it never is, so the refusal
	// below could not fire (#250, C10). IsMappingMounted matches the mounted
	// device number against the mapping's.
	//
	// An ERROR here is not "not mounted": the mount state is UNKNOWN, and
	// closing a volume whose filesystem is still mounted tears it out from
	// under its writers. Only a known "not mounted" may act.
	mounted, err := c.Luks.IsMappingMounted(name)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Cannot determine whether %s is mounted: %v\n", name, err)
		_, _ = fmt.Fprintln(c.Stderr, "Refusing to close a volume that may still be mounted.")
		return 1
	}
	if mounted {
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

// cmdMount mounts an unlocked LUKS2 volume.
//
// The filesystem type is the one --type names, or else the one on the device
// as blkid identifies it. It is never assumed: this used to mount everything
// as ext4, so the xfs and vfat volumes create makes could not be mounted with
// the command create tells the operator to run. When nothing can be detected
// the mount is refused, with a pointer to --type.
func (c *CLI) cmdMount() int {
	o := newOptions("mount")
	longType := o.String("type", "")
	shortType := o.String("t", "")
	args, err := o.parse(c.Args[2:])
	if err != nil {
		return c.usageError(err)
	}

	if len(args) != 2 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 mount [--type <fstype>] <name> <mountpoint>")
		_, _ = fmt.Fprintln(c.Stdout, "Example: luks2 mount my-encrypted-disk /mnt/encrypted")
		_, _ = fmt.Fprintln(c.Stdout, "\nOptions:")
		_, _ = fmt.Fprintln(c.Stdout, "  --type, -t <fstype>  Filesystem type to mount as (default: detected with blkid)")
		return 1
	}

	fstype, err := mountTypeOption(o, *longType, *shortType)
	if err != nil {
		return c.usageError(err)
	}

	name := args[0]
	mountpoint := args[1]

	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Mounting volume: %s -> %s\n\n", name, mountpoint)

	// Check if already mounted.
	//
	// The error is not discarded into "not mounted". IsMounted fails only when
	// /proc/mounts cannot be read, so a failure means the answer is UNKNOWN --
	// and mounting over a mountpoint already in use hides whatever was there.
	mounted, err := c.Luks.IsMounted(mountpoint)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Cannot determine whether %s is already mounted: %v\n", mountpoint, err)
		_, _ = fmt.Fprintln(c.Stderr, "Refusing to mount over a mountpoint that may be in use.")
		return 1
	}
	if mounted {
		_, _ = fmt.Fprintf(c.Stderr, "Mountpoint already in use: %s\n", mountpoint)
		return 1
	}

	if fstype == "" {
		detected, err := c.Luks.DetectFilesystem(name)
		if err != nil {
			_, _ = fmt.Fprintf(c.Stderr, "Cannot determine the filesystem on /dev/mapper/%s: %v\n", name, err)
			_, _ = fmt.Fprintln(c.Stderr, "Refusing to guess. Make a filesystem on it first, or name the type with --type.")
			return 1
		}
		fstype = string(detected)
		_, _ = fmt.Fprintf(c.Stdout, "Detected filesystem: %s\n", fstype)
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
		FSType:     fstype,
	}

	_, _ = fmt.Fprintf(c.Stdout, "Mounting as %s...\n", fstype)

	if err := c.Luks.Mount(opts); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "\nFailed to mount as %s: %v\n", fstype, err)
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "\nVolume mounted successfully!")
	_, _ = fmt.Fprintf(c.Stdout, "\nYou can now use: %s\n", mountpoint)

	return 0
}

// mountTypeOption is the filesystem type --type or -t named, or "" when
// neither was given. Naming two different types, or an empty one, is a usage
// error: an empty --type would otherwise read as "detect it", which is not
// what anyone typing the option asked for.
func mountTypeOption(o *options, long, short string) (string, error) {
	switch {
	case o.Given("type") && o.Given("t") && long != short:
		return "", &UsageError{Command: "mount", Detail: fmt.Sprintf("--type %q and -t %q name different filesystems", long, short)}
	case o.Given("type") && long == "", o.Given("t") && short == "":
		return "", &UsageError{Command: "mount", Detail: "--type and -t need a filesystem name"}
	case o.Given("type"):
		return long, nil
	default:
		return short, nil
	}
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

	// Check if mounted.
	//
	// A failure to read /proc/mounts is not "not mounted". Reporting it as one
	// is SAFE -- this path refuses either way -- but it tells the operator
	// something false about their system, and "not mounted" sends them looking
	// in the wrong place.
	mounted, err := c.Luks.IsMounted(mountpoint)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Cannot determine whether %s is mounted: %v\n", mountpoint, err)
		return 1
	}
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

	device, err := absPath("info", c.Args[2])
	if err != nil {
		return c.usageError(err)
	}

	c.showBanner()
	_, _ = fmt.Fprintf(c.Stdout, "Volume Information: %s\n", device)
	_, _ = fmt.Fprintln(c.Stdout, "===========================================================")

	info, err := c.Luks.GetVolumeInfo(device)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "\nFailed to read volume: %v\n", err)
		return 1
	}

	c.warnAboutDroppedEntries(device, info.Metadata)

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

// warnAboutDroppedEntries tells the operator when the header on disk carried
// keyslot or token entries written as JSON null, which the library removed
// while reading it.
//
// The library cannot do this itself: it is a Layer-0 primitive, and taking a
// logging dependency -- or writing to log/slog's process-global default --
// would impose a logging decision on every application that embeds it (#27).
// It reports the ids instead, and deciding that an operator running `luks2
// info` should see them on stderr is exactly the kind of decision an
// application is allowed to make.
//
// It goes to STDERR rather than stdout because the volume report on stdout is
// something people pipe, and a warning that a container is damaged does not
// belong in the middle of it.
func (c *CLI) warnAboutDroppedEntries(device string, metadata *luks2.LUKS2Metadata) {
	if metadata == nil || len(metadata.DroppedNullEntries) == 0 {
		return
	}

	_, _ = fmt.Fprintf(c.Stderr, "\nWARNING: the header on %s carries %d entr%s written as JSON null:\n",
		device, len(metadata.DroppedNullEntries), plural(len(metadata.DroppedNullEntries), "y", "ies"))
	for _, entry := range metadata.DroppedNullEntries {
		_, _ = fmt.Fprintf(c.Stderr, "  %s\n", entry)
	}
	_, _ = fmt.Fprintln(c.Stderr, "They are not usable and are ignored. Any command that writes this header")
	_, _ = fmt.Fprintln(c.Stderr, "will remove them from the device permanently. Back the header up first:")
	_, _ = fmt.Fprintf(c.Stderr, "  cryptsetup luksHeaderBackup %s --header-backup-file <file>\n", device)
}

// plural picks between two suffixes for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// maxWipePasses bounds --passes. Seven is the most any named standard uses;
// the bound only stops a typo from becoming weeks of writing.
const maxWipePasses = 100

// cmdWipe securely wipes a LUKS2 volume
func (c *CLI) cmdWipe() int {
	if len(c.Args) < 3 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 wipe [options] <device>")
		_, _ = fmt.Fprintln(c.Stdout, "")
		_, _ = fmt.Fprintln(c.Stdout, "Options:")
		_, _ = fmt.Fprintln(c.Stdout, "  --full             Wipe entire device (default: headers and keyslots only)")
		_, _ = fmt.Fprintln(c.Stdout, "  --passes N         Number of overwrite passes (default: 1)")
		_, _ = fmt.Fprintln(c.Stdout, "  --random           Use random data instead of zeros")
		_, _ = fmt.Fprintln(c.Stdout, "  --trim             Issue TRIM/DISCARD after wipe (for SSDs)")
		_, _ = fmt.Fprintln(c.Stdout, "  --standard <name>  Use named wipe standard: nist, dod3, dod7")
		_, _ = fmt.Fprintln(c.Stdout, "  --verify           Enable verification pass")
		_, _ = fmt.Fprintln(c.Stdout, "  --no-verify        Disable verification (override standard)")
		_, _ = fmt.Fprintln(c.Stdout, "  --batch-mode, --yes  Do not ask for confirmation (for scripts)")
		_, _ = fmt.Fprintln(c.Stdout, "")
		_, _ = fmt.Fprintln(c.Stdout, "Standards:")
		_, _ = fmt.Fprintln(c.Stdout, "  nist   NIST SP 800-88: 1 random pass (no verification)")
		_, _ = fmt.Fprintln(c.Stdout, "  dod3   DoD 5220.22-M: 3 passes (zeros->ones->random) + verify")
		_, _ = fmt.Fprintln(c.Stdout, "  dod7   DoD 5220.22-M ECE: 7 passes + verify")
		_, _ = fmt.Fprintln(c.Stdout, "")
		_, _ = fmt.Fprintln(c.Stdout, "Examples:")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe /dev/sdb1                      # Wipe headers only (fast)")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe --full /dev/sdb1               # Wipe entire device")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe --full --standard nist /dev/sdb1   # NIST standard")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe --full --standard dod3 /dev/sdb1   # DoD 3-pass")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe --full --standard dod7 /dev/sdb1   # DoD 7-pass")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe --full --passes 3 --random /dev/sdb1  # Custom 3-pass")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 wipe --full --trim /dev/ssd1        # Full wipe + TRIM for SSD")
		return 1
	}

	o := newOptions("wipe")
	full := o.Bool("full")
	random := o.Bool("random")
	trim := o.Bool("trim")
	verify := o.Bool("verify")
	noVerify := o.Bool("no-verify")
	passes := o.String("passes", "1")
	standard := o.String("standard", "")
	batch := batchFlags(o)
	args, err := o.parse(c.Args[2:])
	if err != nil {
		return c.usageError(err)
	}

	opts := luks2.WipeOptions{
		HeaderOnly: !*full,
		Random:     *random,
		Trim:       *trim,
		Verify:     *verify && !*noVerify,
		NoVerify:   *noVerify,
		Standard:   luks2.StandardCustom,
	}
	explicitNoVerify := *noVerify

	// The whole argument must be a number, and a sane one: Sscanf stopped at
	// the first non-digit, so "3x" was three passes.
	n, err := strconv.Atoi(*passes)
	if err != nil || n < 1 || n > maxWipePasses {
		_, _ = fmt.Fprintf(c.Stderr, "Invalid passes value: %s (must be 1-%d)\n", *passes, maxWipePasses)
		return 1
	}
	opts.Passes = n

	switch *standard {
	case "":
	case "nist":
		opts.Standard = luks2.StandardNIST
	case "dod3":
		opts.Standard = luks2.StandardDoD3Pass
	case "dod7":
		opts.Standard = luks2.StandardDoD7Pass
	default:
		_, _ = fmt.Fprintf(c.Stderr, "Unknown standard: %s (valid: nist, dod3, dod7)\n", *standard)
		return 1
	}

	if len(args) != 1 {
		_, _ = fmt.Fprintln(c.Stderr, "Error: exactly one device path required")
		return 1
	}
	device, err := absPath("wipe", args[0])
	if err != nil {
		return c.usageError(err)
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
		// Determine what to show based on standard vs legacy
		if opts.Standard != luks2.StandardCustom {
			patterns := opts.Standard.GetPatternSequence()
			_, _ = fmt.Fprintf(c.Stdout, "Mode: %s standard (%d pass", opts.Standard.String(), len(patterns))
			if len(patterns) > 1 {
				_, _ = fmt.Fprint(c.Stdout, "es")
			}
			_, _ = fmt.Fprintln(c.Stdout, ")")
			_, _ = fmt.Fprint(c.Stdout, "Sequence: ")
			for i, p := range patterns {
				if i > 0 {
					_, _ = fmt.Fprint(c.Stdout, " -> ")
				}
				_, _ = fmt.Fprint(c.Stdout, p.String())
			}
			_, _ = fmt.Fprintln(c.Stdout, "")
			// Show verification status
			verifyEnabled := opts.Standard.RequiresVerification() || opts.Verify
			if explicitNoVerify {
				verifyEnabled = false
			}
			if verifyEnabled {
				_, _ = fmt.Fprintln(c.Stdout, "Verify: Enabled (100%)")
			}
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
			if opts.Verify {
				_, _ = fmt.Fprintln(c.Stdout, "Verify: Enabled")
			}
		}
		if opts.Trim {
			_, _ = fmt.Fprintln(c.Stdout, "TRIM: Enabled (SSD)")
		}
	}

	// Confirmation. Anything but YES -- end of input included -- cancels,
	// and a canceled wipe exits non-zero: a script must not read it as done.
	if err := c.confirmDestructive("\nType 'YES' to confirm wipe: ", batch()); err != nil {
		return c.refuseUnconfirmed("Wipe", err)
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
		return nil, &KeyInputError{Op: "failed to read passphrase", Source: "terminal", Err: err}
	}

	if confirm {
		_, _ = fmt.Fprint(c.Stdout, "Confirm passphrase: ")
		confirmation, err := c.Terminal.ReadPassword(fd)
		// Cleared unconditionally, including on the read-error path: the
		// confirmation is a second full copy of the passphrase and it was
		// previously left on the heap for the collector to release unzeroed
		// while the passphrase it duplicated was carefully wiped.
		defer ClearBytes(confirmation)
		_, _ = fmt.Fprintln(c.Stdout)
		if err != nil {
			// The first passphrase is wiped here too: it is not returned,
			// so nothing else ever will (#246 D13).
			ClearBytes(passphrase)
			return nil, &KeyInputError{Op: "failed to read confirmation", Source: "terminal", Err: err}
		}

		// Compare in CONSTANT TIME, and as bytes. Bytes because converting a
		// passphrase to a string copies the secret into immutable memory that
		// can never be zeroed; constant time because bytes.Equal returns as
		// soon as it finds a differing byte, and the caller controls both
		// inputs only in the case where they are supposed to match.
		if subtle.ConstantTimeCompare(passphrase, confirmation) != 1 {
			ClearBytes(passphrase)
			return nil, &KeyInputError{Op: "confirm passphrase", Source: "terminal", Err: ErrPassphraseMismatch}
		}
	}

	return passphrase, nil
}

// ParseSize parses a size string like "100M" into bytes (exported for testing).
//
// The WHOLE string must be a positive decimal number with an optional K, M, G
// or T suffix (powers of 1024), and the result must fit an int64. Sscanf used
// to stop at the first character it could not use, so "10x" and "1.5G" were
// accepted as 10 bytes and 1 GiB, and a large value wrapped negative.
func ParseSize(s string) (int64, error) {
	if len(s) == 0 {
		return 0, &UsageError{Command: "create", Detail: "empty size"}
	}

	multiplier := int64(1)
	valueStr := s
	switch s[len(s)-1] {
	case 'K', 'k':
		multiplier = 1 << 10
	case 'M', 'm':
		multiplier = 1 << 20
	case 'G', 'g':
		multiplier = 1 << 30
	case 'T', 't':
		multiplier = 1 << 40
	}
	if multiplier != 1 {
		valueStr = s[:len(s)-1]
	}

	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil || value <= 0 || strings.HasPrefix(valueStr, "+") {
		return 0, &UsageError{Command: "create", Detail: fmt.Sprintf("invalid size %q: want a positive whole number with an optional K, M, G or T suffix", s)}
	}
	if value > math.MaxInt64/multiplier {
		return 0, &UsageError{Command: "create", Detail: fmt.Sprintf("size %q is too large", s)}
	}

	return value * multiplier, nil
}

// ClearBytes securely clears a byte slice (exported for testing)
func ClearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
