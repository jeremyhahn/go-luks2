// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// wipeHeaders zeroes every LUKS2 header copy (binary header and JSON) and the keyslots area, never touching the data segment (see wipeHeaderPlan).
func wipeHeaders(ctx context.Context, f *os.File) error {
	for _, r := range wipeHeaderPlan(f) {
		if err := zeroRange(ctx, f, r.offset, r.size); err != nil {
			return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "wipe headers " + f.Name(), Err: err}
		}
	}
	return f.Sync()
}

// zeroRange writes size zero bytes at offset, in fixed-size chunks so a size
// read from a header never chooses an allocation.
func zeroRange(ctx context.Context, f *os.File, offset, size int64) error {
	zeros := make([]byte, keyslotWipeChunk)
	for done := int64(0); done < size; {
		// ctx is checked per chunk, so a cancellation stops the wipe between
		// writes.
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(int64(len(zeros)), size-done)
		if _, err := f.WriteAt(zeros[:n], offset+done); err != nil {
			return err
		}
		done += n
	}
	return nil
}

// wipeRegion is one byte range a header-only wipe zeroes.
type wipeRegion struct {
	offset, size int64
}

// wipeHeaderPlan decides what a header-only wipe zeroes, taking geometry only from a checksum-validated copy; damaged copies are zeroed over their binary header and JSON.
func wipeHeaderPlan(f *os.File) []wipeRegion {
	var (
		chosenOffset int64 = -1
		area         int64
		strays       []wipeRegion
		offsets      = append([]int64{header.PrimaryHeaderOffset}, header.LegalHeaderAreaSizes()...)
	)
	for _, offset := range offsets {
		size, valid, ok := wipeProbeHeaderCopy(f, offset)
		if !ok {
			continue
		}
		if valid && chosenOffset < 0 {
			chosenOffset, area = offset, size
			continue
		}
		if !valid {
			// An unvalidated copy's declared area is not believed: it may
			// overstate into payload. What makes the copy usable is its JSON,
			// which is NUL-terminated, so that is how far it is zeroed.
			size = headerCopyExtent(f, offset, size)
		}
		strays = append(strays, wipeRegion{offset: offset, size: size})
	}
	if area == 0 {
		area = header.HeaderMinSize
	}

	front := 2 * area
	dataStart := int64(-1)
	var keyslots []wipeRegion
	if chosenOffset >= 0 {
		if hdr, metadata, err := readHeaderCopyFrom(f, chosenOffset); err == nil {
			dataStart = firstDataOffset(metadata)
			if _, end, err := keyslotsAreaBounds(hdr, metadata); err == nil && end > front {
				front = end
			}
			keyslots = declaredKeyslotAreas(metadata)
		}
	}
	clip := func(r wipeRegion) (wipeRegion, bool) {
		if dataStart >= 0 && r.offset+r.size > dataStart {
			r.size = dataStart - r.offset
		}
		return r, r.size > 0
	}

	var plan []wipeRegion
	if r, ok := clip(wipeRegion{offset: 0, size: front}); ok {
		plan = append(plan, r)
	}
	for _, r := range append(keyslots, strays...) {
		if r.offset+r.size <= front {
			continue
		}
		if r, ok := clip(r); ok {
			plan = append(plan, r)
		}
	}
	return plan
}

// headerCopyExtent returns how much of the header copy at offset is meaningful:
// its binary header and its JSON up to and including the terminating NUL,
// never more than the area it declares.
func headerCopyExtent(f *os.File, offset, area int64) int64 {
	buf := make([]byte, keyslotWipeChunk)
	for pos := int64(header.HeaderSize); pos < area; {
		n, err := f.ReadAt(buf[:min(int64(len(buf)), area-pos)], offset+pos)
		if i := bytes.IndexByte(buf[:n], 0); i >= 0 {
			return pos + int64(i) + 1
		}
		pos += int64(n)
		if err != nil {
			return pos
		}
	}
	return area
}

// firstDataOffset returns the lowest offset any segment declares, or -1 when
// none parses.
func firstDataOffset(metadata *header.Metadata) int64 {
	first := int64(-1)
	for _, seg := range metadata.Segments {
		if seg == nil {
			continue
		}
		off, err := parseSize(seg.Offset)
		if err != nil || off < 0 {
			continue
		}
		if first < 0 || off < first {
			first = off
		}
	}
	return first
}

// declaredKeyslotAreas returns every keyslot area the metadata declares as a
// byte range, skipping any that does not parse.
func declaredKeyslotAreas(metadata *header.Metadata) []wipeRegion {
	var areas []wipeRegion
	for _, ks := range metadata.Keyslots {
		if ks == nil || ks.Area == nil {
			continue
		}
		off, offErr := parseSize(ks.Area.Offset)
		size, sizeErr := parseSize(ks.Area.Size)
		if offErr != nil || sizeErr != nil || off < 0 || size <= 0 || size > header.MaxKeyslotAreaSize || off > (1<<62) {
			continue
		}
		areas = append(areas, wipeRegion{offset: off, size: size})
	}
	return areas
}

// wipeProbeHeaderCopy reports whether a LUKS2 header copy belongs at offset (ok), whether its checksum validates (valid), and its declared area size.
func wipeProbeHeaderCopy(f *os.File, offset int64) (size int64, valid, ok bool) {
	raw := make([]byte, header.HeaderSize)
	if _, err := f.ReadAt(raw, offset); err != nil {
		return 0, false, false
	}
	var hdr header.BinaryHeader
	if err := binary.Read(bytes.NewReader(raw), binary.BigEndian, &hdr); err != nil {
		return 0, false, false
	}
	if !bytes.Equal(hdr.Magic[:], []byte(header.ExpectedMagic(offset))) || hdr.Version != header.Version {
		return 0, false, false
	}
	area, err := header.HeaderAreaSize(&hdr)
	if err != nil {
		return 0, false, false
	}
	if recorded, err := header.HeaderAreaOffset(&hdr); err != nil || recorded != offset {
		return 0, false, false
	}
	if offset != header.PrimaryHeaderOffset && int64(area) != offset {
		return 0, false, false
	}
	valid = header.ValidateHeaderChecksum(&hdr, f, offset, area) == nil
	return int64(area), valid, true
}

// keyslotWipeChunk is how much of a keyslot area is zeroed per write.
//
//nolint:unused // Test-only helper: the tests that call it are excluded under
const keyslotWipeChunk = 64 * 1024

// writeZeros zeroes size bytes at the file's current position, in fixed-size
// chunks, so a size read from a header never chooses an allocation.
func writeZeros(f *os.File, size int64) error {
	zeros := make([]byte, keyslotWipeChunk)
	for remaining := size; remaining > 0; {
		n := min(int64(len(zeros)), remaining)
		if _, err := f.Write(zeros[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	return nil
}
