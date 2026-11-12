// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
)

// mountUsage is also printed directly to stdout by runMount when <name> or
// <mountpoint> is missing, matching the pre-rewrite CLI
// (docs/volumes/cli.md#mount).
const mountUsage = "Usage: luks2 mount [--type <fstype>] [--allow-suid] [--allow-dev] <name> <mountpoint>\n" +
	"Example: luks2 mount my-encrypted-disk /mnt/encrypted\n\n" +
	"Options:\n" +
	"  --type, -t <fstype>  Filesystem type to mount as (default: detected)\n" +
	"  --allow-suid         Honor setuid/setgid bits (default: mounted nosuid)\n" +
	"  --allow-dev          Interpret device nodes (default: mounted nodev)\n"

func mountCommand() *command {
	return &command{
		name:     "mount",
		synopsis: "Mount an unlocked volume",
		usage:    mountUsage,
		run:      runMount,
	}
}

func runMount(ctx context.Context, e *env, args []string) error {
	f := newFlags("mount")
	longType := f.String("type", "")
	shortType := f.String("t", "")
	allowSuid := f.Bool("allow-suid")
	allowDev := f.Bool("allow-dev")
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) != 2 {
		_, _ = fmt.Fprint(e.stdout, mountUsage)
		return &UsageError{Command: "mount", Detail: "want <name> <mountpoint>"}
	}
	if (f.Given("type") && *longType == "") || (f.Given("t") && *shortType == "") {
		_, _ = fmt.Fprint(e.stdout, mountUsage)
		return &UsageError{Command: "mount", Detail: "--type needs a filesystem type"}
	}
	if f.Given("type") && f.Given("t") && *longType != *shortType {
		_, _ = fmt.Fprint(e.stdout, mountUsage)
		return &UsageError{Command: "mount", Detail: "--type and -t name different types"}
	}
	fstype := *longType
	if fstype == "" {
		fstype = *shortType
	}

	name := positional[0]
	target, err := absPath("mount", positional[1])
	if err != nil {
		return err
	}

	// The filesystem is untrusted content: setuid files and device nodes on
	// it are inert unless the operator opts in.
	var flags uintptr = unix.MS_NOSUID | unix.MS_NODEV
	if *allowSuid {
		flags &^= unix.MS_NOSUID
	}
	if *allowDev {
		flags &^= unix.MS_NODEV
	}

	m, err := e.host.activator.lookup(ctx, name)
	if err != nil {
		return err
	}
	source := m.path()

	mounted, err := e.host.mounter.isMounted(ctx, target)
	if err != nil {
		return err
	}
	if mounted {
		return &UsageError{Command: "mount", Detail: fmt.Sprintf("%s is already mounted", target)}
	}

	if fstype == "" {
		detected, err := e.host.mounter.detect(ctx, source)
		if err != nil {
			return err
		}
		fstype = string(detected)
	}

	if _, err := os.Stat(target); os.IsNotExist(err) {
		if err := os.MkdirAll(target, 0o750); err != nil {
			return err
		}
	}

	if err := e.host.mounter.mount(ctx, filesystem.MountParams{
		Source: source,
		Target: target,
		Type:   filesystem.Type(fstype),
		Flags:  flags,
	}); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "Mounted %s on %s as %s\n", source, target, fstype)
	return nil
}

// unmountUsage is also printed directly to stdout by runUnmount when
// <mountpoint> is missing, matching the pre-rewrite CLI
// (docs/volumes/cli.md#unmount).
const unmountUsage = "Usage: luks2 unmount <mountpoint>\nExample: luks2 unmount /mnt/encrypted\n"

func unmountCommand() *command {
	return &command{
		name:     "unmount",
		synopsis: "Unmount a volume",
		usage:    unmountUsage,
		run:      runUnmount,
	}
}

func runUnmount(ctx context.Context, e *env, args []string) error {
	if len(args) < 1 {
		_, _ = fmt.Fprint(e.stdout, unmountUsage)
		return &UsageError{Command: "unmount", Detail: "want <mountpoint>"}
	}
	target := args[0]

	mounted, err := e.host.mounter.isMounted(ctx, target)
	if err != nil {
		return err
	}
	if !mounted {
		_, _ = fmt.Fprintf(e.stderr, "Not mounted: %s\n", target)
		return &UsageError{Command: "unmount", Detail: fmt.Sprintf("%s is not mounted", target)}
	}

	if err := e.host.mounter.unmount(ctx, target, 0); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "Unmounted %s\n", target)
	return nil
}
