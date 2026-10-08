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

// wipeHeaders destroys every LUKS2 header copy and the keyslots area: what a
// header-only wipe claims, a crypto-erase.
//
// Zeroing the two header copies alone was not one. Each copy's JSON carries the
// keyslot salts and digests, the keyslot areas carry the wrapped volume key,
// and a STRAY copy left over from an earlier format with a different metadata
// size had only its 4 KiB binary header zeroed -- its JSON, salts included,
// survived. Rebuilding a binary header in front of surviving JSON is a
// checksum computation, and the original passphrase then opened the volume
// from the keyslot material that had never been touched. So this zeroes:
//
//   - the front of the device up to the end of the keyslots area the
//     validated header declares (both copies and every keyslot);
//   - every keyslot area the header declares, wherever it lies below the data;
//   - every other recognizable header copy, binary header AND JSON.
//
// Nothing at or past the first data segment is touched (see wipeHeaderPlan).
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
		// Checked per chunk (DESIGN.md §D.2).
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

// wipeHeaderPlan decides what a header-only wipe zeroes, trusting geometry
// only from a CHECKSUM-VALIDATED copy.
//
// Neither direction of error is safe (#47 review):
//
//   - Believing a damaged copy that UNDERSTATES the geometry leaves a valid
//     copy, or keyslot material, further out intact.
//   - Believing a damaged copy that OVERSTATES it zeroes payload: cryptsetup's
//     --offset can put the data segment as low as the end of the keyslots
//     area.
//
// So the header area, the keyslots area, the keyslot areas and the start of
// the data come from the validated primary, else the smallest validated
// secondary; with none, the area is the 16 KiB default and the data start is
// unknown. Every OTHER recognizable copy is zeroed too, clipped to the data
// start when it is known: a valid one over its whole area, a damaged one over
// its binary header and its JSON (headerCopyExtent), because its declared area
// is exactly the number that cannot be believed.
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

// wipeProbeHeaderCopy reports whether what is at offset is recognizably a
// LUKS2 header copy belonging there (ok) -- magic, version, a legal area size,
// hdr_offset equal to offset and, for a secondary copy, an area equal to its
// offset -- and whether its checksum also validates (valid). size is the area
// it declares.
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

// wipePass performs one wipe pass over the device
// -tags=integration, so `unused` fires on a function the default build exercises.
//
// WipeKeyslot wipes a specific keyslot
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
