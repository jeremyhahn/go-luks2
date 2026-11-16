package luks2

import (
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/pkg/wipe"
)

// TestSharedKindsAreReExportedByValue pins the error-semantics rule of
// docs/volumes/engineering.md: the module-wide kinds are defined once in
// internal/errs and the shared device kinds once in internal/device, and
// pkg/luks2 and pkg/wipe re-export the same values, so errors.Is matches a
// kind whichever package's name a caller holds.
func TestSharedKindsAreReExportedByValue(t *testing.T) {
	same := []struct {
		name      string
		got, want error
	}{
		{"luks2.ErrInvalidArgument", ErrInvalidArgument, errs.ErrInvalidArgument},
		{"luks2.ErrInvalidCredential", ErrInvalidCredential, errs.ErrInvalidCredential},
		{"luks2.ErrIO", ErrIO, errs.ErrIO},
		{"luks2.ErrDeviceNotFound", ErrDeviceNotFound, device.ErrNotFound},
		{"luks2.ErrPermissionDenied", ErrPermissionDenied, device.ErrPermissionDenied},
		{"luks2.ErrDeviceInUse", ErrDeviceInUse, device.ErrInUse},
		{"luks2.ErrDeviceChanged", ErrDeviceChanged, device.ErrChanged},
		{"luks2.ErrDeviceCacheStale", ErrDeviceCacheStale, device.ErrCacheStale},
		{"luks2.ErrLockContended", ErrLockContended, device.ErrLockContended},
		{"luks2.ErrMetadataLockUnavailable", ErrMetadataLockUnavailable, device.ErrMetadataLockUnavailable},
		{"wipe.ErrDeviceInUse", wipe.ErrDeviceInUse, ErrDeviceInUse},
		{"wipe.ErrDeviceChanged", wipe.ErrDeviceChanged, ErrDeviceChanged},
		{"wipe.ErrPermissionDenied", wipe.ErrPermissionDenied, ErrPermissionDenied},
		{"wipe.ErrLockContended", wipe.ErrLockContended, ErrLockContended},
	}
	for _, s := range same {
		if s.got != s.want {
			t.Errorf("%s is not the shared value it re-exports", s.name)
		}
	}
}
