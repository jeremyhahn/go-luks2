// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package device

import (
	"os"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Size reports the size of f. BLKGETSIZE64 is Linux-only (A.3), so off Linux
// this is always a regular file's size.
func Size(f *os.File) (int64, error) {
	stat, err := f.Stat()
	if err != nil {
		return 0, &errs.Error{Kind: errs.ErrIO, Detail: "failed to get device/file size", Err: err}
	}
	return stat.Size(), nil
}
