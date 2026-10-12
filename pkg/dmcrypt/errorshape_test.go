// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package dmcrypt

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// TestErrorIsTheModuleErrorShape pins the module's one error shape: the
// package exports Error as an alias of errs.Error.
func TestErrorIsTheModuleErrorShape(t *testing.T) {
	var err error = &Error{Kind: ErrNotActive}
	var e *errs.Error
	if !errors.As(err, &e) || !errors.Is(err, ErrNotActive) {
		t.Fatalf("Error is not the module's *errs.Error: %v", err)
	}
}

// TestSentinelsCarryThePackagePrefix pins that every sentinel's text starts
// with its package's name ("dmcrypt: "). A sentinel
// re-exported by value from internal/device keeps the module-wide "luks2: "
// prefix, since one value cannot carry two texts.
func TestSentinelsCarryThePackagePrefix(t *testing.T) {
	for name, err := range map[string]error{
		"ErrActive":                ErrActive,
		"ErrNotActive":             ErrNotActive,
		"ErrBusy":                  ErrBusy,
		"ErrStillLive":             ErrStillLive,
		"ErrInvalidName":           ErrInvalidName,
		"ErrNodeUnverified":        ErrNodeUnverified,
		"ErrIntegerOverflow":       ErrIntegerOverflow,
		"ErrPermissionDenied":      ErrPermissionDenied,
		"ErrDeviceChanged":         ErrDeviceChanged,
		"ErrKeyring":               ErrKeyring,
		"ErrKeyringUnavailable":    ErrKeyringUnavailable,
		"ErrKeyringBlocked":        ErrKeyringBlocked,
		"ErrKeyringUnsupported":    ErrKeyringUnsupported,
		"ErrKeyringQuotaExhausted": ErrKeyringQuotaExhausted,
		"ErrKeyringFailed":         ErrKeyringFailed,
		"ErrKeyringEntryExists":    ErrKeyringEntryExists,
		"ErrKeyringKeyNotReleased": ErrKeyringKeyNotReleased,
	} {
		msg := err.Error()
		if !strings.HasPrefix(msg, "dmcrypt: ") && !strings.HasPrefix(msg, "luks2: ") {
			t.Errorf("%s text %q lacks a package prefix", name, msg)
		}
	}
}
