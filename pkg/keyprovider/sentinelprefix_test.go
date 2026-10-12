// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"strings"
	"testing"
)

// TestSentinelsCarryThePackagePrefix pins that every exported sentinel of
// this package starts with the package's name.
func TestSentinelsCarryThePackagePrefix(t *testing.T) {
	for name, err := range map[string]error{
		"ErrInvalidArgument":  ErrInvalidArgument,
		"ErrHelperFailed":     ErrHelperFailed,
		"ErrHelperOutput":     ErrHelperOutput,
		"ErrNoDevice":         ErrNoDevice,
		"ErrInvalidBinding":   ErrInvalidBinding,
		"ErrUnsupportedToken": ErrUnsupportedToken,
	} {
		if !strings.HasPrefix(err.Error(), "keyprovider: ") {
			t.Errorf("%s text %q lacks the \"keyprovider: \" prefix", name, err.Error())
		}
	}
}
