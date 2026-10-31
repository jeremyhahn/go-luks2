// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunOpenUnlocksAndActivates(t *testing.T) {
	path := newTestVolumeImage(t, "open.img")
	e, act, _, stdout, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))

	err := runOpen(context.Background(), e, []string{path, "myvolume"})
	if err != nil {
		t.Fatalf("runOpen: %v", err)
	}
	if len(act.activated) != 1 || act.activated[0] != "myvolume" {
		t.Errorf("activated = %v, want [myvolume]", act.activated)
	}
	if !strings.Contains(stdout.String(), "unlocked") {
		t.Errorf("stdout = %q, want it to report success", stdout.String())
	}
}

func TestRunOpenWrongPassphrase(t *testing.T) {
	path := newTestVolumeImage(t, "open-wrong.img")
	e, act, _, _, _ := newTestEnv(bytes.NewBufferString("not the passphrase\n"))

	if err := runOpen(context.Background(), e, []string{path, "myvolume"}); err == nil {
		t.Fatal("runOpen: want an error for the wrong passphrase")
	}
	if len(act.activated) != 0 {
		t.Errorf("activated = %v, want none when Unlock fails", act.activated)
	}
}

func TestRunOpenActivateFailurePropagates(t *testing.T) {
	path := newTestVolumeImage(t, "open-activate-fail.img")
	e, act, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	act.activateErr = errors.New("dm-crypt refused")

	if err := runOpen(context.Background(), e, []string{path, "myvolume"}); err == nil {
		t.Fatal("runOpen: want the activator's error")
	}
}

func TestRunOpenNonexistentDevice(t *testing.T) {
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	if err := runOpen(context.Background(), e, []string{filepath.Join(t.TempDir(), "nope"), "name"}); err == nil {
		t.Fatal("runOpen: want an error for a device that does not exist")
	}
}

func TestRunCloseDeactivatesWhenNotMounted(t *testing.T) {
	e, act, mnt, stdout, _ := newTestEnv(&bytes.Buffer{})
	mnt.deviceMounted_ = false

	if err := runClose(context.Background(), e, []string{"myvolume"}); err != nil {
		t.Fatalf("runClose: %v", err)
	}
	if len(act.deactivated) != 1 || act.deactivated[0] != "myvolume" {
		t.Errorf("deactivated = %v, want [myvolume]", act.deactivated)
	}
	if !strings.Contains(stdout.String(), "locked") {
		t.Errorf("stdout = %q, want it to report success", stdout.String())
	}
}

func TestRunCloseRefusesWhileMounted(t *testing.T) {
	e, act, mnt, _, _ := newTestEnv(&bytes.Buffer{})
	mnt.deviceMounted_ = true

	if err := runClose(context.Background(), e, []string{"myvolume"}); err == nil {
		t.Fatal("runClose: want an error while the volume is mounted")
	}
	if len(act.deactivated) != 0 {
		t.Errorf("deactivated = %v, want none while mounted", act.deactivated)
	}
}

// TestRunCloseLookupFailureReportsFailedToLock locks docs/volumes/cli.md's
// "Failed to lock volume" text, which the pre-rewrite CLI printed on stderr
// when a close could not find or release the mapping.
func TestRunCloseLookupFailureReportsFailedToLock(t *testing.T) {
	e, _, _, _, stderr := newTestEnv(&bytes.Buffer{})
	e.host.activator.(*fakeActivator).lookupErr = errors.New("no such mapping")

	if err := runClose(context.Background(), e, []string{"myvolume"}); err == nil {
		t.Fatal("runClose: want the lookup error")
	}
	if !strings.Contains(stderr.String(), "Failed to lock") {
		t.Errorf("stderr = %q, want it to report a failure to lock", stderr.String())
	}
}

func TestRunIsLUKSOnARealVolume(t *testing.T) {
	path := newTestVolumeImage(t, "isluks.img")
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runIsLUKS(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runIsLUKS: %v", err)
	}
	if !strings.Contains(stdout.String(), "is a LUKS device") {
		t.Errorf("stdout = %q, want a positive answer", stdout.String())
	}
}

func TestRunIsLUKSOnANonLUKSFile(t *testing.T) {
	path := newPlainImage(t, "plain.img")
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	err := runIsLUKS(context.Background(), e, []string{path})
	if !errors.Is(err, errNotLUKSDevice) {
		t.Fatalf("runIsLUKS error = %v, want errNotLUKSDevice", err)
	}
	if !strings.Contains(stdout.String(), "is not a LUKS device") {
		t.Errorf("stdout = %q, want a negative answer", stdout.String())
	}
	if exitCode(err) != 1 {
		t.Errorf("exitCode = %d, want 1 (isluks keeps its own 0/1 contract)", exitCode(err))
	}
}

func TestRunIsLUKSMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runIsLUKS(context.Background(), e, nil); err == nil {
		t.Fatal("runIsLUKS: want a usage error with no arguments")
	}
}

func TestRunIsLUKSEmptyDeviceArg(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	err := runIsLUKS(context.Background(), e, []string{""})
	var usageErr *UsageError
	if !errors.As(err, &usageErr) {
		t.Fatalf("runIsLUKS error = %v, want a *UsageError from absPath", err)
	}
}

func TestRunIsLUKSDeviceDoesNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.img")
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	err := runIsLUKS(context.Background(), e, []string{path})
	if !errors.Is(err, errNotLUKSDevice) {
		t.Fatalf("runIsLUKS error = %v, want errNotLUKSDevice", err)
	}
	if !strings.Contains(stdout.String(), "is not a LUKS device") {
		t.Errorf("stdout = %q, want a negative answer", stdout.String())
	}
}

// TestRunIsLUKSVerboseGivesTheReason: under -v or --verbose a no carries its
// reason on stderr, as cryptsetup isLuks -v does, and still exits 1; without
// it stderr stays empty.
func TestRunIsLUKSVerboseGivesTheReason(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag []string
		want bool
	}{
		{"quiet", nil, false},
		{"long", []string{"--verbose"}, true},
		{"short", []string{"-v"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "does-not-exist.img")
			e, _, _, _, stderr := newTestEnv(&bytes.Buffer{})

			err := runIsLUKS(context.Background(), e, append(append([]string{}, tc.flag...), path))
			if got := exitCode(err); got != 1 {
				t.Fatalf("exit status = %d (%v), want 1", got, err)
			}
			if gave := strings.Contains(stderr.String(), path+":"); gave != tc.want {
				t.Errorf("stderr = %q, reason reported = %v, want %v", stderr.String(), gave, tc.want)
			}
		})
	}
}

func TestRunInfoOnARealVolume(t *testing.T) {
	path := newTestVolumeImage(t, "info.img")
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runInfo(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runInfo: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"UUID:", "Cipher:", "Active Keyslots:", "Slot 0:", "valid and accessible"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want it to contain %q", out, want)
		}
	}
}

func TestRunInfoOnANonLUKSFile(t *testing.T) {
	path := newPlainImage(t, "info-plain.img")
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})

	if err := runInfo(context.Background(), e, []string{path}); err == nil {
		t.Fatal("runInfo: want an error for a non-LUKS2 file")
	}
}
