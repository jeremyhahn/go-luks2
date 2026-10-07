// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// exitCode maps an error to a cryptsetup(8)-compatible exit status
// (DESIGN.md §F). The table is tried in order and the first match wins; an
// unmatched non-nil error exits 1, the same status usage errors use.
//
// This table names the sentinels pkg/luks2 exports TODAY. ErrMasterKeyVerification
// was renamed to ErrWrongKey at H13 (DESIGN.md §C.3); ErrInvalidCredential and
// pkg/dmcrypt's ErrActive/ErrBusy are not yet landed. This table is updated in
// the same change that renames or adds them.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	for _, row := range exitTable {
		for _, sentinel := range row.is {
			if errors.Is(err, sentinel) {
				return row.code
			}
		}
	}
	return 1
}

var exitTable = []struct {
	code int
	is   []error
}{
	// 2: no permission or bad passphrase.
	{2, []error{luks2.ErrWrongKey, luks2.ErrInvalidCredential, luks2.ErrPermissionDenied, ErrPassphraseMismatch}},
	// 3: out of memory (protected memory could not be obtained).
	{3, []error{luks2.ErrProtectedMemory}},
	// 4: wrong device.
	{4, []error{luks2.ErrDeviceNotFound, luks2.ErrNotLUKS2, luks2.ErrInvalidHeader}},
	// 5: exists or busy.
	{5, []error{luks2.ErrDeviceInUse, luks2.ErrLockContended}},
}
