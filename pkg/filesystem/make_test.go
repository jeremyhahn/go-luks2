// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package filesystem

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestSupportedCanBeCreatedAndChecked is the #195 invariant: everything
// Supported() advertises can be created AND checked, and nothing can be
// created or checked that it does not advertise.
func TestSupportedCanBeCreatedAndChecked(t *testing.T) {
	advertised := Supported()
	if len(advertised) == 0 {
		t.Fatal("Supported() is empty")
	}

	seen := make(map[Type]bool, len(advertised))
	for _, fs := range advertised {
		if seen[fs] {
			t.Errorf("Supported() lists %q twice", fs)
		}
		seen[fs] = true

		to, ok := dispatch[fs]
		if !ok {
			t.Errorf("%q is advertised but has no dispatch entry", fs)
			continue
		}
		if to.make == nil {
			t.Errorf("%q is advertised but cannot be created", fs)
		}
		if to.check == nil {
			t.Errorf("%q is advertised but cannot be checked", fs)
		}
		if !isSupported(fs) {
			t.Errorf("isSupported(%q) = false for an advertised type", fs)
		}
	}

	for fs := range dispatch {
		if !seen[fs] {
			t.Errorf("%q can be created/checked but Supported() does not advertise it", fs)
		}
	}
}

// TestSupportedExactSet pins the owner's ruling on #195: ext4, xfs, zfs and
// vfat, and not ext2 or ext3.
func TestSupportedExactSet(t *testing.T) {
	var got []string
	for _, fs := range Supported() {
		got = append(got, string(fs))
	}
	sort.Strings(got)

	want := []string{"ext4", "vfat", "xfs", "zfs"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Supported() = %v, want %v", got, want)
	}
}

// TestSupportedReturnsACopy guards the single source of truth against a
// caller mutating the slice it was handed.
func TestSupportedReturnsACopy(t *testing.T) {
	first := Supported()
	first[0] = Type("mutated")
	if isSupported(Type("mutated")) {
		t.Fatal("mutating the returned slice changed the supported set")
	}
}

// TestUnsupportedTypesAreRefused checks that Make and Check/Repair refuse
// every type outside the supported set -- ext2 and ext3 included -- with
// ErrUnsupported, before any device is touched.
func TestUnsupportedTypesAreRefused(t *testing.T) {
	for _, fs := range []Type{"ext2", "ext3", "btrfs", ""} {
		t.Run(string(fs), func(t *testing.T) {
			if isSupported(fs) {
				t.Errorf("isSupported(%q) = true", fs)
			}

			err := Make(t.Context(), "luks2-test-no-such-volume", fs, MakeParams{})
			if !errors.Is(err, ErrUnsupported) {
				t.Errorf("Make(%q) = %v, want ErrUnsupported", fs, err)
			}

			_, err = Check(t.Context(), "/dev/luks2-test-no-such-device", fs)
			if !errors.Is(err, ErrUnsupported) {
				t.Errorf("Check(%q) = %v, want ErrUnsupported", fs, err)
			}

			res, err := Repair(t.Context(), "/dev/luks2-test-no-such-device", fs)
			if !errors.Is(err, ErrUnsupported) || res != (CheckResult{}) {
				t.Errorf("Repair(%q) = %+v, %v, want a zero result and ErrUnsupported", fs, res, err)
			}
		})
	}
}

// fakeTools puts stand-ins for external programs in the ONLY directory the
// creators resolve programs from (sys.tools.Dirs), so their real lookups
// reach them. Each records the argv it was run with, one argument per line,
// prints stdout and exits with code; record returns what a tool was run
// with, or nil if it never ran.
//
// sys is package state, so every caller is sequential.
func fakeTools(t *testing.T, fakes map[string]fakeTool) (record func(name string) []string) {
	t.Helper()
	bin := t.TempDir()
	// t.TempDir makes its directories 0777 less the umask, and a program
	// directory others can write to is refused.
	if err := os.Chmod(bin, 0o700); err != nil {
		t.Fatalf("restricting the fake tool directory: %v", err)
	}
	logs := t.TempDir()
	for name, tool := range fakes {
		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s\nprintf '%%s' %s\nexit %d\n",
			shellQuote(filepath.Join(logs, name)), shellQuote(tool.stdout), tool.code)
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
			t.Fatalf("writing the fake %s: %v", name, err)
		}
	}
	previous := sys
	t.Cleanup(func() { sys = previous })
	sys.tools.Dirs = []string{bin}
	return func(name string) []string {
		data, err := os.ReadFile(filepath.Join(logs, name)) // #nosec G304 -- under t.TempDir()
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			t.Fatalf("reading what %s was run with: %v", name, err)
		}
		return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	}
}

type fakeTool struct {
	stdout string
	code   int
}

// shellQuote renders s as a single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// TestCreatorsTranslateEveryOption pins the argv each creator hands its mkfs
// for every option it accepts. The flags are the whole of what these
// functions do, and a wrong one is silent: mkfs accepts most of them either
// way, so the filesystem is made, just not the one that was asked for.
func TestCreatorsTranslateEveryOption(t *testing.T) {
	const dev = "/dev/mapper/vol"
	tests := []struct {
		name   string
		tool   string
		create func(context.Context, string, MakeParams) error
		params MakeParams
		want   []string
	}{
		{"ext4, no options", "mkfs.ext4", makeExt4, MakeParams{}, []string{"--", dev}},
		{"ext4, every option", "mkfs.ext4", makeExt4, MakeParams{
			Label: "data", BlockSize: 4096, Force: true,
			Ext4: &Ext4Params{
				JournalSize: 64, InodeSize: 256, ReservedBlocksPercent: 2.5,
				StrideSize: 16, StripeWidth: 64,
				Enable64bit: true, EnableLargeDir: true, DisableMetadataChecksums: true,
			},
		}, []string{"-L", "data", "-b", "4096", "-F", "-J", "size=64", "-I", "256", "-m", "2.5",
			"-E", "stride=16,stripe_width=64", "-O", "64bit,dir_index,large_dir,^metadata_csum", "--", dev}},
		{"ext4, a stripe width alone", "mkfs.ext4", makeExt4, MakeParams{
			Ext4: &Ext4Params{StripeWidth: 64},
		}, []string{"-E", "stripe_width=64", "--", dev}},
		{"xfs, no options", "mkfs.xfs", makeXFS, MakeParams{}, []string{"--", dev}},
		{"xfs, every option", "mkfs.xfs", makeXFS, MakeParams{
			Label: "data", Force: true,
			XFS: &XFSParams{
				BlockSize: 4096, SectorSize: 4096, InodeSize: 512, AgCount: 4, LogSize: 64,
				RefLink: true, BigTime: true, NoAlign: true,
			},
		}, []string{"-L", "data", "-f", "-b", "size=4096", "-s", "size=4096", "-i", "size=512",
			"-d", "agcount=4", "-l", "size=64m", "-m", "reflink=1,bigtime=1", "-d", "noalign", "--", dev}},
		{"vfat, no label", "mkfs.fat", makeFAT32, MakeParams{}, []string{"-F", "32", "--", dev}},
		{"vfat, with a label", "mkfs.fat", makeFAT32, MakeParams{Label: "BOOT"}, []string{"-F", "32", "-n", "BOOT", "--", dev}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := fakeTools(t, map[string]fakeTool{tt.tool: {}})
			if err := tt.create(context.Background(), dev, tt.params); err != nil {
				t.Fatalf("create = %v, want nil from a %s that succeeded", err, tt.tool)
			}
			if got := record(tt.tool); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%s ran with %q, want %q", tt.tool, got, tt.want)
			}
		})
	}
}

// TestCreatorsReportTheToolsFailure: a mkfs that exits nonzero is an error
// naming it and carrying what it printed, since that output is the only
// account of why.
func TestCreatorsReportTheToolsFailure(t *testing.T) {
	for _, tt := range []struct {
		tool   string
		create func(context.Context, string, MakeParams) error
	}{
		{"mkfs.ext4", makeExt4},
		{"mkfs.xfs", makeXFS},
		{"mkfs.fat", makeFAT32},
	} {
		t.Run(tt.tool, func(t *testing.T) {
			fakeTools(t, map[string]fakeTool{tt.tool: {stdout: "the device is too small", code: 1}})
			err := tt.create(context.Background(), "/dev/mapper/vol", MakeParams{})
			if err == nil {
				t.Fatalf("create succeeded although %s exited 1", tt.tool)
			}
			var ce *CommandError
			if !errors.As(err, &ce) || ce.Command != tt.tool || ce.Output != "the device is too small" {
				t.Fatalf("create = %v, want a CommandError naming %s and its output", err, tt.tool)
			}
			if !strings.Contains(err.Error(), "exit status 1") {
				t.Errorf("error %q does not carry the exit status", err)
			}
		})
	}
}

// TestMakeZFSTranslatesEveryOption covers the two commands a ZFS create is:
// the pool, with its pool (-o) and root-dataset (-O) properties and
// features, then -- for a named dataset other than the root -- that dataset
// with the same dataset properties.
func TestMakeZFSTranslatesEveryOption(t *testing.T) {
	const dev = "/dev/mapper/vol"
	record := fakeTools(t, map[string]fakeTool{"zpool": {}, "zfs": {}})
	err := makeZFS(context.Background(), dev, MakeParams{
		Force: true,
		ZFS: &ZFSParams{
			PoolName: "tank", DatasetName: "data", MountPoint: "/srv/tank", Ashift: 12,
			Properties:  map[string]string{"autotrim": "on"},
			Compression: "lz4", RecordSize: "1M", EnableDedup: true,
			Features: []string{"async_destroy", "lz4_compress"},
		},
	})
	if err != nil {
		t.Fatalf("makeZFS = %v, want nil", err)
	}
	wantPool := []string{"create", "-f", "-m", "/srv/tank", "-o", "ashift=12", "-o", "autotrim=on",
		"-O", "compression=lz4", "-O", "recordsize=1M", "-O", "dedup=on",
		"-o", "feature@async_destroy=enabled", "-o", "feature@lz4_compress=enabled", "--", "tank", dev}
	if got := record("zpool"); !reflect.DeepEqual(got, wantPool) {
		t.Errorf("zpool ran with %q, want %q", got, wantPool)
	}
	wantDataset := []string{"create", "-o", "compression=lz4", "-o", "recordsize=1M", "-o", "dedup=on", "--", "tank/data"}
	if got := record("zfs"); !reflect.DeepEqual(got, wantDataset) {
		t.Errorf("zfs ran with %q, want %q", got, wantDataset)
	}
}

// TestMakeZFSCreatesNoDatasetForTheRoot: "root" and "" both mean the pool's
// own root dataset, which zpool create already made.
func TestMakeZFSCreatesNoDatasetForTheRoot(t *testing.T) {
	for _, dataset := range []string{"", "root"} {
		record := fakeTools(t, map[string]fakeTool{"zpool": {}, "zfs": {}})
		if err := makeZFS(context.Background(), "/dev/mapper/vol", MakeParams{ZFS: &ZFSParams{PoolName: "tank", DatasetName: dataset}}); err != nil {
			t.Fatalf("dataset %q: makeZFS = %v, want nil", dataset, err)
		}
		if got := record("zpool"); !reflect.DeepEqual(got, []string{"create", "--", "tank", "/dev/mapper/vol"}) {
			t.Errorf("dataset %q: zpool ran with %q", dataset, got)
		}
		if got := record("zfs"); got != nil {
			t.Errorf("dataset %q: zfs ran with %q, want it not run for the root dataset", dataset, got)
		}
	}
}

// TestMakeZFSRefusesWhatItCannotCreate covers the refusals before any command
// runs, and each command's failure afterwards -- a dataset that could not be
// created is an error even though the pool was.
func TestMakeZFSRefusesWhatItCannotCreate(t *testing.T) {
	record := fakeTools(t, map[string]fakeTool{"zpool": {}})
	if err := makeZFS(context.Background(), "/dev/mapper/vol", MakeParams{}); err == nil || !strings.Contains(err.Error(), "requires ZFS params") {
		t.Errorf("no ZFS params: %v, want a refusal", err)
	}
	if err := makeZFS(context.Background(), "/dev/mapper/vol", MakeParams{ZFS: &ZFSParams{}}); err == nil || !strings.Contains(err.Error(), "pool name is required") {
		t.Errorf("no pool name: %v, want a refusal", err)
	}
	if got := record("zpool"); got != nil {
		t.Errorf("zpool ran with %q for options it should have refused", got)
	}

	fakeTools(t, map[string]fakeTool{"zpool": {stdout: "no such pool", code: 1}})
	err := makeZFS(context.Background(), "/dev/mapper/vol", MakeParams{ZFS: &ZFSParams{PoolName: "tank"}})
	var ce *CommandError
	if !errors.As(err, &ce) || ce.Command != "zpool create" || ce.Output != "no such pool" {
		t.Errorf("zpool exiting 1: %v, want zpool's failure with its output", err)
	}

	fakeTools(t, map[string]fakeTool{"zpool": {}, "zfs": {stdout: "dataset already exists", code: 1}})
	err = makeZFS(context.Background(), "/dev/mapper/vol", MakeParams{ZFS: &ZFSParams{PoolName: "tank", DatasetName: "data"}})
	if !errors.As(err, &ce) || ce.Command != "zfs create" || ce.Output != "dataset already exists" {
		t.Errorf("zfs exiting 1: %v, want zfs's failure with its output", err)
	}
}

// TestMakeRefusesACanceledContext checks the ctx boundary check: Make does
// not run a tool once its context is already done.
func TestMakeRefusesACanceledContext(t *testing.T) {
	record := fakeTools(t, map[string]fakeTool{"mkfs.ext4": {}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := Make(ctx, "/dev/mapper/vol", Ext4, MakeParams{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Make with a canceled context = %v, want context.Canceled", err)
	}
	if got := record("mkfs.ext4"); got != nil {
		t.Fatalf("mkfs.ext4 ran with %q, want it not run at all", got)
	}
}
