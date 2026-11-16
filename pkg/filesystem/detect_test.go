// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package filesystem

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// TestProbeFilesystemReportsWhatBlkidFound: the probe reads blkid's
// low-level answer for the device, never its cache, and hands back the TYPE
// only when blkid says it is a filesystem. Everything else is a refusal
// naming what was found, so Mount cannot be steered into a guess.
func TestProbeFilesystemReportsWhatBlkidFound(t *testing.T) {
	const dev = "/dev/mapper/vol"
	tests := []struct {
		name    string
		output  string
		err     error
		want    Type
		wantErr error
	}{
		{name: "xfs", output: "DEVNAME=/dev/mapper/vol\nUUID=1\nTYPE=xfs\nUSAGE=filesystem\n", want: XFS},
		{name: "vfat", output: "TYPE=vfat\nUSAGE=filesystem\n", want: FAT32},
		{name: "ext4 with a label holding an equals sign", output: "LABEL=a=b\nTYPE=ext4\nUSAGE=filesystem\n", want: Ext4},
		{name: "nothing found", err: exitCode(blkidNothingFound), wantErr: ErrNotDetected},
		{name: "two signatures", err: exitCode(blkidAmbivalent), wantErr: ErrNotDetected},
		{name: "another LUKS container", output: "TYPE=crypto_LUKS\nUSAGE=crypto\n", wantErr: ErrNotDetected},
		{name: "swap", output: "TYPE=swap\nUSAGE=other\n", wantErr: ErrNotDetected},
		{name: "a RAID member", output: "TYPE=linux_raid_member\nUSAGE=raid\n", wantErr: ErrNotDetected},
		{name: "an LVM member", output: "TYPE=LVM2_member\nUSAGE=raid\n", wantErr: ErrNotDetected},
		{name: "ext2 is reported raw, though unsupported", output: "TYPE=ext2\nUSAGE=filesystem\n", want: Type("ext2")},
		{name: "ext3 is reported raw, though unsupported", output: "TYPE=ext3\nUSAGE=filesystem\n", want: Type("ext3")},
		{name: "a TYPE with no USAGE", output: "TYPE=ext4\n", wantErr: ErrNotDetected},
		{name: "no TYPE at all", output: "USAGE=filesystem\n", wantErr: ErrNotDetected},
	}

	for _, tt := range tests {
		var argv []string
		run := func(_ context.Context, name string, args ...string) ([]byte, error) {
			argv = append([]string{name}, args...)
			return []byte(tt.output), tt.err
		}

		got, err := probeFilesystem(context.Background(), run, dev)
		if want := []string{"blkid", "-p", "-o", "export", "--", dev}; !slices.Equal(argv, want) {
			t.Errorf("%s: ran %q, want %q", tt.name, argv, want)
		}
		if tt.wantErr != nil {
			if !errors.Is(err, tt.wantErr) || got != "" {
				t.Errorf("%s: probeFilesystem = %q, %v; want a refusal matching %v", tt.name, got, err, tt.wantErr)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%s: probeFilesystem = %q, %v; want %q", tt.name, got, err, tt.want)
		}
	}
}

// TestProbeFilesystemKeepsAFailedProbeDistinct: blkid failing for any other
// reason is a command failure carrying its output, not "no filesystem".
func TestProbeFilesystemKeepsAFailedProbeDistinct(t *testing.T) {
	run := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("blkid: permission denied"), exitCode(4)
	}
	_, err := probeFilesystem(context.Background(), run, "/dev/mapper/vol")

	var ce *CommandError
	if !errors.As(err, &ce) || ce.Command != "blkid" || ce.Output != "blkid: permission denied" {
		t.Fatalf("probeFilesystem = %v, want a *CommandError carrying blkid's output", err)
	}
	if errors.Is(err, ErrNotDetected) {
		t.Fatalf("a failed probe was reported as an empty device: %v", err)
	}
}

// TestDetectRefusesACanceledContext checks the ctx boundary check.
func TestDetectRefusesACanceledContext(t *testing.T) {
	record := fakeTools(t, map[string]fakeTool{"blkid": {}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Detect(ctx, "/dev/mapper/vol"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Detect with a canceled context = %v, want context.Canceled", err)
	}
	if got := record("blkid"); got != nil {
		t.Fatalf("blkid ran with %q, want it not run at all", got)
	}
}
