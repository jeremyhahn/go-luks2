// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package filesystem

import (
	"context"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Info describes a filesystem, as blkid's cached export reports it.
// TotalSize, UsedSize, FreeSize and MountPoint are reserved for a future
// probe that reads them; Inspect does not populate them today, the same as
// the function it replaces.
type Info struct {
	Type       Type
	Label      string
	UUID       string
	BlockSize  int
	TotalSize  uint64
	UsedSize   uint64
	FreeSize   uint64
	MountPoint string
}

// Inspect retrieves filesystem information from device, a device path (not
// a device-mapper mapping name), using blkid's cache.
func Inspect(ctx context.Context, device string) (info *Info, err error) {
	defer func() { err = errs.At("filesystem", "Inspect", device, err) }()
	if err := ctx.Err(); err != nil {
		return nil, &Error{Kind: err}
	}

	output, err := sys.tools.Output(ctx, "blkid", "-o", "export", "--", device)
	if err != nil {
		return nil, &Error{Kind: errs.KindOf(err, ErrTool), Detail: "blkid failed", Err: err}
	}

	info = &Info{}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "TYPE":
			info.Type = Type(value)
		case "LABEL":
			info.Label = value
		case "UUID":
			info.UUID = value
		case "BLOCK_SIZE":
			_, _ = fmt.Sscanf(value, "%d", &info.BlockSize)
		}
	}

	return info, nil
}
