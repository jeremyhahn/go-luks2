// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package wipe

import (
	"bytes"
	"context"
	"fmt"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// verifyWrite reads back [0, size) of the device through mediumPath -- at
// every place device.MediumSources says its bytes must be read past a cache
// for the read to be the medium's, rather than the page cache's -- and
// compares it with what stream wrote.
func verifyWrite(ctx context.Context, path, mediumPath string, size int64, stream *passStream,
	progress func(Progress), totalPasses int, s sys) error {
	if size <= 0 {
		return nil
	}

	sources, err := device.MediumSources(mediumPath, s.sysDevBlockRoot, s.statRdev)
	if err != nil {
		return err
	}

	want := make([]byte, chunk)
	defer clear(want)

	for _, src := range sources {
		for off := int64(0); off < size; {
			if err := ctx.Err(); err != nil {
				return &errs.Error{Kind: err, Detail: fmt.Sprintf("%d of %d bytes verified", off, size), Err: err}
			}

			n := int64(chunk)
			if size-off < n {
				n = size - off
			}
			got, err := device.ReadPastCache(ctx, "read back the sanitize", src.Path, src.Offset+off, int(n), s.openFile)
			if err != nil {
				return err
			}
			if int64(len(got)) < n {
				return &errs.Error{Kind: ErrVerification, Detail: fmt.Sprintf(
					"%s: %s ended at byte %d of %d", path, src.Path, off+int64(len(got)), size)}
			}
			stream.fill(want[:n], off)
			if !bytes.Equal(got[:n], want[:n]) {
				at := off
				for i := range n {
					if got[i] != want[i] {
						at = off + i
						break
					}
				}
				return &errs.Error{Kind: ErrVerification, Detail: fmt.Sprintf(
					"%s: %s differs from the %s pass at byte %d", path, src.Path, stream.pattern, at)}
			}
			off += n

			if progress != nil {
				progress(Progress{
					Pass: totalPasses + 1, Passes: totalPasses + 1,
					Written: off, Total: size, Pattern: stream.pattern, Verifying: true,
				})
			}
		}
	}
	return nil
}
