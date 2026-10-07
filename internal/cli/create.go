// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// create formats a new LUKS2 volume: a block device in place, or a new
// sparse file that is then attached, unlocked and given a filesystem
// (docs/volumes/cli.md#create). What is at the path decides the flow, not
// its spelling.

// createUsage is also printed directly to stdout by runCreate when <path>
// is missing, matching the pre-rewrite CLI (docs/volumes/cli.md#create).
const createUsage = "Usage: luks2 create [options] <path> [size] [filesystem]\n\n" +
	"A block device is formatted in place; size and filesystem are ignored.\n" +
	"A path that does not exist yet is a new file volume and needs <size>\n" +
	"(a number with an optional K, M, G or T suffix). filesystem is ext4\n" +
	"(default), xfs or vfat.\n\n" +
	"Options:\n" + keyFileHelp + kdfFlagsHelp +
	"  --batch-mode, --yes  Do not ask for confirmation\n" +
	"  --force              Format a block device that already holds a LUKS header or a filesystem\n"

func createCommand() *command {
	return &command{
		name:     "create",
		synopsis: "Create a new LUKS2 volume",
		usage:    createUsage,
		run:      runCreate,
	}
}

func runCreate(ctx context.Context, e *env, args []string) error {
	f := newFlags("create")
	key := keyFileFlag(f, "key-file")
	kdfFlags := declareKDFFlags(f)
	batch := batchFlags(f)
	force := f.Bool("force")
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		_, _ = fmt.Fprint(e.stdout, createUsage)
		return &UsageError{Command: "create", Detail: "want <path> [size] [filesystem]"}
	}

	// Settled before anything is created, claimed or asked: a KDF this
	// mode refuses must stop the command before any of that happens.
	kdf, kdfLabel, err := kdfFlags.resolve()
	if err != nil {
		reportKDFRefusal(e, err)
		return err
	}

	path, err := absPath("create", positional[0])
	if err != nil {
		return err
	}

	// What is at the path decides the flow, not its spelling: a /dev name
	// that is not a block device is refused rather than created as a file.
	kind, err := createPathKind(path)
	if err != nil {
		return err
	}
	switch {
	case kind == pathBlockDevice:
		return createBlockDevice(ctx, e, path, *key, kdf, kdfLabel, batch(), *force)
	case kind == pathAbsent && !looksLikeADeviceName(path):
		return createFile(ctx, e, path, positional[1:], *key, kdf, kdfLabel)
	case kind == pathAbsent:
		return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("no such block device: %s", path)}
	default:
		return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("file already exists: %s (remove it first if you want to recreate it)", path)}
	}
}

func createBlockDevice(ctx context.Context, e *env, device string, key keySource, kdf luks2.KDFParams, kdfLabel string, batch, force bool) error {
	_, _ = fmt.Fprintf(e.stdout, "Creating a LUKS2 volume on %s\n", device)

	// Probed before anything is asked: a device that is in use is refused
	// whatever the flags say, and one that holds data is refused without
	// --force.
	found, release, err := claimDevice(device)
	if err != nil {
		return err
	}
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
			return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("%s holds %s; pass --force to destroy it", device, found)}
		}
		_, _ = fmt.Fprintf(e.stdout, "WARNING: %s holds %s, which formatting destroys.\n", device, found)
	}

	// Whole-stdin key input and a confirmation cannot share one stream.
	if key.path == stdinKeyFile && !batch {
		return &UsageError{Command: "create", Detail: "--key-file - reads standard input, so the confirmation cannot; pass --batch-mode"}
	}
	_, _ = fmt.Fprintf(e.stdout, "WARNING: this will overwrite data on %s irrevocably.\n", device)
	if err := confirmDestructive(e, "Type 'YES' to confirm: ", batch); err != nil {
		return refuseUnconfirmed(e, "Create", err)
	}

	pass, err := readPassphrase(e, "Enter passphrase for new volume: ", true, key)
	if err != nil {
		return err
	}
	defer e.custody.Release(pass)
	label := promptLabel(e, key)

	// The exclusive claim is held through the confirmation and the
	// passphrase prompt, and given up just before Format, which opens the
	// device again itself.
	unclaim()

	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	if err := v.Format(ctx, pass, luks2.FormatParams{Label: label, KDF: kdf}); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(e.stdout, "LUKS2 volume created successfully.")
	_, _ = fmt.Fprintf(e.stdout, "  KDF: %s\n", kdfLabel)
	_, _ = fmt.Fprintln(e.stdout, "\nNext steps:")
	_, _ = fmt.Fprintf(e.stdout, "  1. Open:  sudo luks2 open %s myvolume\n", device)
	_, _ = fmt.Fprintln(e.stdout, "  2. Mount: sudo luks2 mount myvolume /mnt/encrypted")
	return nil
}

func createFile(ctx context.Context, e *env, path string, rest []string, key keySource, kdf luks2.KDFParams, kdfLabel string) error {
	if len(rest) < 1 {
		_, _ = fmt.Fprintln(e.stdout, "Error: Size required for file volumes")
		_, _ = fmt.Fprintln(e.stdout, "Usage: luks2 create <path> <size> [filesystem]")
		return &UsageError{Command: "create", Detail: "file volumes need <size>; want <path> <size> [filesystem]"}
	}
	size, err := parseSize("create", rest[0])
	if err != nil {
		return err
	}
	fstype := "ext4"
	if len(rest) > 1 {
		fstype = rest[1]
	}
	if !isCreateFilesystem(fstype) {
		return &UsageError{Command: "create", Detail: fmt.Sprintf("unsupported filesystem %q (want ext4, xfs or vfat)", fstype)}
	}

	_, _ = fmt.Fprintf(e.stdout, "Creating a LUKS2 encrypted file: %s (%s)\n", path, rest[0])

	// Created EXCLUSIVELY, in one step: a symlink planted at the path is
	// refused rather than followed, and only the owner can read it. What
	// was created is remembered, so a cleanup removes this run's file and
	// never one that took its place.
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600) // #nosec G304 -- the operator's own <path> argument
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("file already exists: %s (remove it first if you want to recreate it)", path)}
		}
		return err
	}
	defer func() { _ = fh.Close() }()
	cleanup := func() { _ = removeCreatedFile(path, fh) }

	if err := fh.Truncate(size); err != nil {
		cleanup()
		return err
	}

	pass, err := readPassphrase(e, "Enter passphrase for new volume: ", true, key)
	if err != nil {
		cleanup()
		return err
	}
	defer e.custody.Release(pass)
	label := promptLabel(e, key)

	v, err := luks2.Open(ctx, path)
	if err != nil {
		cleanup()
		return err
	}
	if err := v.Format(ctx, pass, luks2.FormatParams{Label: label, KDF: kdf}); err != nil {
		_ = v.Close()
		cleanup()
		return err
	}
	_ = v.Close()

	_, _ = fmt.Fprintln(e.stdout, "LUKS2 volume created successfully.")
	_, _ = fmt.Fprintf(e.stdout, "  KDF: %s\n", kdfLabel)

	loopDev, err := e.host.looper.attach(ctx, path)
	if err != nil {
		_, _ = fmt.Fprintf(e.stderr, "Failed to set up a loop device for %s: %v\n", path, err)
		_, _ = fmt.Fprintln(e.stderr, "The container was formatted but is not open. Attach a loop device by hand:")
		_, _ = fmt.Fprintf(e.stderr, "  losetup -f --show %s\n", path)
		return err
	}

	const volumeName = "luks-auto"
	v2, err := luks2.Open(ctx, loopDev.path())
	if err != nil {
		return detachAndReport(ctx, e, loopDev, path, err)
	}
	volumeKey, err := v2.Unlock(ctx, pass)
	if err != nil {
		_ = v2.Close()
		return detachAndReport(ctx, e, loopDev, path, err)
	}
	m, err := e.host.activator.activate(ctx, v2, volumeKey, volumeName)
	volumeKey.Destroy()
	_ = v2.Close()
	if err != nil {
		return detachAndReport(ctx, e, loopDev, path, err)
	}

	_, _ = fmt.Fprintf(e.stdout, "Volume unlocked as: %s\n", m.path())

	if err := e.host.mounter.make(ctx, m.path(), filesystem.Type(fstype), filesystem.MakeParams{Label: label}); err != nil {
		_, _ = fmt.Fprintf(e.stderr, "Failed to create the %s filesystem: %v\n", fstype, err)
		cctx, stop := cleanupContext(ctx)
		defer stop()
		if derr := e.host.activator.deactivate(cctx, volumeName); derr != nil {
			_, _ = fmt.Fprintf(e.stderr, "Failed to close %s: %v; run: luks2 close %s\n", volumeName, derr, volumeName)
		} else if _, derr := e.host.looper.detach(cctx, loopDev); derr != nil {
			_, _ = fmt.Fprintf(e.stderr, "Failed to detach %s: %v; run: losetup -d %s\n", loopDev.path(), derr, loopDev.path())
		}
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "Created a %s filesystem.\n", fstype)
	_, _ = fmt.Fprintln(e.stdout, "\nReady to use:")
	_, _ = fmt.Fprintf(e.stdout, "  sudo luks2 mount %s /mnt/encrypted\n", volumeName)
	_, _ = fmt.Fprintln(e.stdout, "Cleanup:")
	_, _ = fmt.Fprintln(e.stdout, "  sudo luks2 unmount /mnt/encrypted")
	_, _ = fmt.Fprintf(e.stdout, "  sudo luks2 close %s\n", volumeName)
	return nil
}

// detachAndReport reports that the file volume could not be unlocked or
// activated, detaches the loop device create's own attach step left
// behind, and leaves the formatted container in place for the operator to
// finish by hand.
// cleanupTimeout bounds the teardown create runs after a failure.
const cleanupTimeout = 30 * time.Second

// cleanupContext returns the context create's teardown runs under: ctx's
// values without its cancellation, so an interrupt does not leave the mapping
// and loop device behind, bounded so a stuck device cannot hang the command.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

func detachAndReport(ctx context.Context, e *env, d loopDevice, path string, cause error) error {
	_, _ = fmt.Fprintf(e.stderr, "Failed to open %s: %v\n", d.path(), cause)
	cctx, stop := cleanupContext(ctx)
	defer stop()
	if _, err := e.host.looper.detach(cctx, d); err != nil {
		_, _ = fmt.Fprintf(e.stderr, "Failed to detach loop device %s: %v\n", d.path(), err)
		_, _ = fmt.Fprintf(e.stderr, "Detach it with: losetup -d %s\n", d.path())
	} else {
		_, _ = fmt.Fprintf(e.stderr, "Detached loop device %s.\n", d.path())
	}
	_, _ = fmt.Fprintf(e.stderr, "The container at %s was formatted but is not open.\n", path)
	return cause
}

// promptLabel asks for an optional volume label, only when the credential
// came from a terminal: there is nobody to answer it otherwise, and
// reading a line would consume whatever a script piped next.
func promptLabel(e *env, key keySource) string {
	if key.path != "" || !stdinIsTerminal(e) {
		return ""
	}
	_, _ = fmt.Fprint(e.stdout, "Enter volume label (optional, press Enter to skip): ")
	var label string
	_, _ = fmt.Fscanln(e.stdin, &label)
	return label
}

// isCreateFilesystem reports whether create will build name's filesystem.
// zfs is excluded: it needs a pool name create has no option for.
func isCreateFilesystem(name string) bool {
	switch filesystem.Type(name) {
	case filesystem.Ext4, filesystem.XFS, filesystem.FAT32:
		return true
	}
	return false
}

// looksLikeADeviceName reports whether path names something under /dev
// other than /dev/shm, so an absent path there is refused as "no such
// block device" rather than created as a file.
func looksLikeADeviceName(path string) bool {
	return strings.HasPrefix(path, "/dev/") && path != "/dev/shm" && !strings.HasPrefix(path, "/dev/shm/")
}
