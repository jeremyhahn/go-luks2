// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func TestExitCodeNilIsZero(t *testing.T) {
	if got := exitCode(nil); got != 0 {
		t.Errorf("exitCode(nil) = %d, want 0", got)
	}
}

func TestExitCodeTable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"wrong key", luks2.ErrWrongKey, 2},
		{"permission denied", luks2.ErrPermissionDenied, 2},
		{"passphrase mismatch", ErrPassphraseMismatch, 2},
		{"protected memory", luks2.ErrProtectedMemory, 3},
		{"device not found", luks2.ErrDeviceNotFound, 4},
		{"not luks2", luks2.ErrNotLUKS2, 4},
		{"invalid header", luks2.ErrInvalidHeader, 4},
		{"device in use", luks2.ErrDeviceInUse, 5},
		{"lock contended", luks2.ErrLockContended, 5},
		{"dmcrypt active", dmcrypt.ErrActive, 5},
		{"dmcrypt busy", dmcrypt.ErrBusy, 5},
		{"dmcrypt wrapped active (open path)", errs.At("dmcrypt", "Activate", "", &errs.Error{Kind: dmcrypt.ErrActive, Detail: "taken"}), 5},
		{"dmcrypt wrapped busy (close path)", errs.At("dmcrypt", "Deactivate", "", &errs.Error{Kind: dmcrypt.ErrBusy, Detail: "held", Err: errors.New("EBUSY")}), 5},
		{"dmcrypt still live has no row", dmcrypt.ErrStillLive, 1},
		{"dmcrypt not active has no row", dmcrypt.ErrNotActive, 1},
		{"unmatched", errors.New("something else"), 1},
		{"usage error", &UsageError{Command: "x", Detail: "y"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := exitCode(c.err); got != c.want {
				t.Errorf("exitCode(%v) = %d, want %d", c.err, got, c.want)
			}
		})
	}
}

func TestExitCodeWrapsThroughCustomErrors(t *testing.T) {
	wrapped := &KeyInputError{Op: "read passphrase", Source: "terminal", Err: luks2.ErrProtectedMemory}
	if got := exitCode(wrapped); got != 3 {
		t.Errorf("exitCode(wrapped) = %d, want 3", got)
	}
}
