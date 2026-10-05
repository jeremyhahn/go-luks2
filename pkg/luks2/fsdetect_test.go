// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package luks2

import (
	"errors"
	"slices"
	"testing"
)

// TestProbeFilesystemReportsWhatBlkidFound: the probe reads blkid's low-level
// answer for the device, never its cache, and hands back the TYPE only when
// blkid says it is a filesystem. Everything else is a refusal naming what was
// found, so Mount cannot be steered into a guess.
func TestProbeFilesystemReportsWhatBlkidFound(t *testing.T) {
	defer parallel(t)()

	const dev = "/dev/mapper/vol"
	tests := []struct {
		name    string
		output  string
		err     error
		want    FilesystemType
		wantErr error
	}{
		{name: "xfs", output: "DEVNAME=/dev/mapper/vol\nUUID=1\nTYPE=xfs\nUSAGE=filesystem\n", want: FilesystemXFS},
		{name: "vfat", output: "TYPE=vfat\nUSAGE=filesystem\n", want: FilesystemFAT32},
		{name: "ext4 with a label holding an equals sign", output: "LABEL=a=b\nTYPE=ext4\nUSAGE=filesystem\n", want: FilesystemExt4},
		{name: "nothing found", err: exitCode(blkidNothingFound), wantErr: ErrFilesystemNotDetected},
		{name: "two signatures", err: exitCode(blkidAmbivalent), wantErr: ErrFilesystemNotDetected},
		{name: "another LUKS container", output: "TYPE=crypto_LUKS\nUSAGE=crypto\n", wantErr: ErrFilesystemNotDetected},
		{name: "swap", output: "TYPE=swap\nUSAGE=other\n", wantErr: ErrFilesystemNotDetected},
		{name: "a TYPE with no USAGE", output: "TYPE=ext4\n", wantErr: ErrFilesystemNotDetected},
		{name: "no TYPE at all", output: "USAGE=filesystem\n", wantErr: ErrFilesystemNotDetected},
	}

	for _, tt := range tests {
		var argv []string
		run := func(name string, args ...string) ([]byte, error) {
			argv = append([]string{name}, args...)
			return []byte(tt.output), tt.err
		}

		got, err := probeFilesystem(run, dev)
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
	defer parallel(t)()

	run := func(string, ...string) ([]byte, error) { return []byte("blkid: permission denied"), exitCode(4) }
	_, err := probeFilesystem(run, "/dev/mapper/vol")

	var cmdErr *FilesystemCommandError
	if !errors.As(err, &cmdErr) || cmdErr.Command != "blkid" || cmdErr.Output != "blkid: permission denied" {
		t.Fatalf("probeFilesystem = %v, want a *FilesystemCommandError carrying blkid's output", err)
	}
	if errors.Is(err, ErrFilesystemNotDetected) {
		t.Fatalf("a failed probe was reported as an empty device: %v", err)
	}
}
