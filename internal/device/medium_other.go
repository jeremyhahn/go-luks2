// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package device

import (
	"context"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// ReadPastCache fails closed off Linux (A.3): there is no portable O_DIRECT,
// so what is on the medium can never be confirmed here.
func ReadPastCache(ctx context.Context, op, path string, off int64, n int, openFile OpenFunc) ([]byte, error) {
	return nil, &errs.Error{Kind: ErrUnsupported, Detail: path}
}
