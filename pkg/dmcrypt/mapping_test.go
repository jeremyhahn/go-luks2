// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package dmcrypt

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

func TestValidateNameAcceptsOrdinaryNames(t *testing.T) {
	for _, name := range []string{"cryptroot", "vol-1", "vol_1", "vg0.lv0", "a", "0", "x+y"} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) refused an ordinary name: %v", name, err)
		}
	}
}

func TestValidateNameRefusesHostileNames(t *testing.T) {
	for _, name := range []string{
		"",
		"has space",
		"has\ttab",
		"has\nnewline",
		"has\x00nul",
		"../escape",
		"/absolute",
		"-leading-dash",
		".",
		"..",
		"control",
		strings.Repeat("a", MaxNameLength+1),
	} {
		if err := ValidateName(name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("ValidateName(%q) = %v, want ErrInvalidName", name, err)
		}
	}
}

func TestMaxNameLengthMatchesTheDMNameLimit(t *testing.T) {
	// 127: the kernel's DM_NAME_LEN (128) less its terminating NUL.
	if MaxNameLength != 127 {
		t.Fatalf("MaxNameLength = %d, want 127", MaxNameLength)
	}
	if err := ValidateName(strings.Repeat("n", MaxNameLength)); err != nil {
		t.Errorf("a name of exactly MaxNameLength was refused: %v", err)
	}
	if err := ValidateName(strings.Repeat("n", MaxNameLength+1)); !errors.Is(err, ErrInvalidName) {
		t.Errorf("a name one byte over MaxNameLength was accepted")
	}
}

func TestMappingPathIsTheConventionalMapperEntry(t *testing.T) {
	m := &Mapping{Name: "vol"}
	if got, want := m.Path(), "/dev/mapper/vol"; got != want {
		t.Fatalf("Path() = %q, want %q", got, want)
	}
}

func TestLookupReportsTheLiveMappingsIdentity(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["vol"] = "CRYPT-LUKS2-deadbeef-vol"
	fake.devNos["vol"] = unix.Mkdev(253, 7)
	fake.install(t)

	m, err := Lookup(context.Background(), "vol")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if m.Name != "vol" || m.UUID != "CRYPT-LUKS2-deadbeef-vol" || m.Major != 253 || m.Minor != 7 {
		t.Fatalf("Lookup = %+v, want {vol CRYPT-LUKS2-deadbeef-vol 253 7}", m)
	}
}

func TestLookupReportsErrNotActiveForAnUnknownName(t *testing.T) {
	newFakeDeviceMapper().install(t)

	if _, err := Lookup(context.Background(), "absent"); !errors.Is(err, ErrNotActive) {
		t.Fatalf("Lookup(absent) = %v, want ErrNotActive", err)
	}
}

func TestLookupPropagatesAnInspectionFailure(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.infoErr = unix.EACCES
	fake.install(t)

	if _, err := Lookup(context.Background(), "vol"); !errors.Is(err, unix.EACCES) {
		t.Fatalf("Lookup = %v, want the inspection failure reachable", err)
	}
}

// A device-mapper step refused for lack of privilege is ErrPermissionDenied,
// with the errno still reachable.
func TestADeviceMapperPrivilegeRefusalIsErrPermissionDenied(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EACCES, unix.EPERM} {
		fake := newFakeDeviceMapper()
		fake.infoErr = os.NewSyscallError("dm ioctl", errno)
		fake.install(t)

		_, lookupErr := Lookup(context.Background(), "vol")
		deactivateErr := Deactivate(context.Background(), "vol")
		for op, err := range map[string]error{"Lookup": lookupErr, "Deactivate": deactivateErr} {
			if !errors.Is(err, ErrPermissionDenied) || !errors.Is(err, errno) {
				t.Errorf("%s with %v = %v, want ErrPermissionDenied wrapping the errno", op, errno, err)
			}
		}
	}
}

func TestDMKindKeepsAnEarlierClassificationAndCancellation(t *testing.T) {
	denied := os.NewSyscallError("dm ioctl", unix.EACCES)
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"privilege", denied, ErrPermissionDenied},
		{"other errno", os.NewSyscallError("dm ioctl", unix.EINVAL), errs.ErrIO},
		{"classified", &Error{Kind: ErrNodeUnverified, Err: denied}, ErrNodeUnverified},
		{"canceled", errors.Join(context.Canceled, denied), context.Canceled},
	} {
		if got := dmKind(tc.err, errs.ErrIO); got != tc.want {
			t.Errorf("%s: dmKind = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestErrPermissionDeniedIsTheSharedDeviceSentinel(t *testing.T) {
	if ErrPermissionDenied != device.ErrPermissionDenied {
		t.Fatal("dmcrypt.ErrPermissionDenied is not internal/device's ErrPermissionDenied")
	}
}

func TestLookupRefusesAnInvalidName(t *testing.T) {
	newFakeDeviceMapper().install(t)

	if _, err := Lookup(context.Background(), "../escape"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Lookup(../escape) = %v, want ErrInvalidName", err)
	}
}

func TestLookupHonoursACanceledContext(t *testing.T) {
	newFakeDeviceMapper().install(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Lookup(ctx, "vol"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Lookup with a canceled context = %v, want context.Canceled", err)
	}
}
