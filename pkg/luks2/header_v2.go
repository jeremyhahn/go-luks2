// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"context"
	"io"
	"os"
	"strconv"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// SizeDynamic is Segment.Size for a segment whose size is the device's
// remaining space, resolved only at activation (DESIGN.md §B.2).
const SizeDynamic int64 = -1

// Segment is one of a volume's data segments: the on-disk segment's offset
// and size, already parsed to the integers this package's own reader and
// writer compute them as (header.Segment stores both as decimal strings).
type Segment struct {
	ID         int
	Type       string
	Offset     int64
	Size       int64
	Encryption string
	SectorSize int
	IVTweak    uint64
}

// Header is a read-only snapshot of a volume's LUKS2 metadata, taken under
// the shared lock (DESIGN.md §B.2). It does not change when the volume's
// on-disk header does; call (*Volume).Header again for a fresh one.
type Header struct {
	hdr      *header.BinaryHeader
	metadata *header.Metadata
}

// UUID is the volume's UUID.
func (h *Header) UUID() string { return trimmedField(h.hdr.UUID[:]) }

// Label is the volume label, or "" if none was set.
func (h *Header) Label() string { return trimmedField(h.hdr.Label[:]) }

// Subsystem is the volume's subsystem label, or "" if none was set.
func (h *Header) Subsystem() string { return trimmedField(h.hdr.SubsystemLabel[:]) }

// SequenceID is the header's sequence number, incremented on every write.
func (h *Header) SequenceID() uint64 { return h.hdr.SequenceID }

// Requirements lists the LUKS2 requirements the container declares, nil if
// it declares none. An implementation that does not understand every entry
// here must refuse to modify the container.
func (h *Header) Requirements() []string {
	if h.metadata.Config == nil || h.metadata.Config.Requirements == nil {
		return nil
	}
	return h.metadata.Config.Requirements.Mandatory
}

// Dropped names the keyslot and token entries this read removed because the
// header spelled them as JSON null. It is nil for every intact header.
func (h *Header) Dropped() []DroppedEntry { return h.metadata.DroppedNullEntries }

// Size is this header copy's on-disk size: the 4096-byte binary header plus
// its JSON metadata area, in bytes.
func (h *Header) Size() int64 { return int64(h.hdr.HeaderSize) } // #nosec G115 -- bounded by header.HeaderMaxSize (4 MiB), far under int64's range

// Keyslots lists the volume's keyslots, in the order an unlock attempts
// them. It shares listKeyslotsFrom with the old ListKeyslots, so the two
// never report a different shape for one container.
func (h *Header) Keyslots() []KeyslotInfo {
	slots, _ := listKeyslotsFrom(h.metadata)
	return slots
}

// Segments lists the volume's data segments, in ascending id order. A
// segment whose id does not parse as a decimal integer is omitted: the same
// tolerance (*Header).Keyslots already applies to a keyslot cryptsetup
// itself could never address (see listKeyslotsFrom) -- no LUKS2
// implementation reaches such a segment either, so reporting nothing about
// it is more honest than inventing an id. A segment field that fails to
// parse (a malformed offset, size or iv_tweak) reads back as its zero value
// rather than failing the whole listing: Segments, like Keyslots, is an
// inspection operation and must report what is there.
func (h *Header) Segments() []Segment {
	var out []Segment
	for _, idStr := range header.SortedIDs(h.metadata.Segments) {
		seg := h.metadata.Segments[idStr]
		if seg == nil {
			continue
		}
		id, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}

		size := SizeDynamic
		if seg.Size != "dynamic" {
			if parsed, err := strconv.ParseInt(seg.Size, 10, 64); err == nil {
				size = parsed
			}
		}
		offset, _ := strconv.ParseInt(seg.Offset, 10, 64)
		ivTweak, _ := strconv.ParseUint(seg.IVTweak, 10, 64)

		out = append(out, Segment{
			ID:         id,
			Type:       seg.Type,
			Offset:     offset,
			Size:       size,
			Encryption: seg.Encryption,
			SectorSize: seg.SectorSize,
			IVTweak:    ivTweak,
		})
	}
	return out
}

// Tokens returns every token the header carries, converted to the §B.2
// value shape (DESIGN.md), keyed by its canonical slot id. A map key that
// is not the canonical spelling of a slot 0..MaxTokens-1 -- "01", "-1",
// "999" -- addresses no token in any LUKS2 implementation (cryptsetup
// included, #35) and is omitted rather than reported, the same tolerance
// Keyslots and Segments already give a malformed entry: a listing is an
// inspection operation.
func (h *Header) Tokens() map[int]Token {
	out := make(map[int]Token, len(h.metadata.Tokens))
	for idStr, lt := range h.metadata.Tokens {
		if lt == nil {
			continue
		}
		id, ok := canonicalTokenID(idStr)
		if !ok {
			continue
		}
		t, err := tokenFromLegacy(lt)
		if err != nil {
			continue
		}
		out[id] = t
	}
	return out
}

// MarshalJSON renders the header's metadata as the canonical JSON this
// package writes to disk.
func (h *Header) MarshalJSON() ([]byte, error) {
	return header.MarshalCanonicalJSON(h.metadata)
}

// trimmedField reads a NUL-padded fixed-size binary-header field as a
// string, exactly as GetVolumeInfo already does for UUID and Label.
func trimmedField(b []byte) string {
	return string(bytes.TrimRight(b, "\x00"))
}

// Header reads the current header copy -- the valid one with the higher
// sequence id, as cryptsetup chooses (readCurrentHeader) -- under the shared
// lock. It does not require a valid header to have been written yet by
// anything other than Format -- with no valid copy it fails with ErrNotLUKS2
// or ErrInvalidHeader, same as the old ReadHeader.
func (v *Volume) Header(ctx context.Context) (*Header, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.checkOpen("Volume.Header"); err != nil {
		return nil, err
	}

	locked, err := v.lockFor(ctx, device.LockShared)
	if err != nil {
		return nil, errAt("Volume.Header", v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	cur, err := readCurrentHeader(locked.File())
	if err != nil {
		return nil, errAt("Volume.Header", v.path, err)
	}
	return &Header{hdr: cur.Header, metadata: cur.Metadata}, nil
}

// SecondaryHeader reads the secondary header copy under the shared lock.
func (v *Volume) SecondaryHeader(ctx context.Context) (*Header, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.checkOpen("Volume.SecondaryHeader"); err != nil {
		return nil, err
	}

	locked, err := v.lockFor(ctx, device.LockShared)
	if err != nil {
		return nil, errAt("Volume.SecondaryHeader", v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	hdr, metadata, err := header.ReadSecondaryHeaderFrom(locked.File())
	if err != nil {
		return nil, errAt("Volume.SecondaryHeader", v.path, reclassifyUnsupportedChecksum(err))
	}
	return &Header{hdr: hdr, metadata: metadata}, nil
}

// RestorePrimaryHeader rewrites the primary header copy from the secondary
// one, under the exclusive lock, refusing with ErrPrimaryHeaderCurrent when
// the primary is intact and at least as new -- restoring it would roll the
// volume back rather than repair it. ReplacePrimaryHeader skips that
// refusal.
func (v *Volume) RestorePrimaryHeader(ctx context.Context) error {
	return v.restorePrimaryHeader(ctx, "Volume.RestorePrimaryHeader", false)
}

// ReplacePrimaryHeader unconditionally rewrites the primary header copy
// from the secondary one, under the exclusive lock.
func (v *Volume) ReplacePrimaryHeader(ctx context.Context) error {
	return v.restorePrimaryHeader(ctx, "Volume.ReplacePrimaryHeader", true)
}

func (v *Volume) restorePrimaryHeader(ctx context.Context, op string, force bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.checkOpen(op); err != nil {
		return err
	}
	if err := v.checkWritable(op); err != nil {
		return err
	}

	locked, err := v.lockFor(ctx, device.LockExclusive)
	if err != nil {
		return errAt(op, v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	claimed, err := locked.Claim(ctx, "restore the primary header", os.O_RDWR|os.O_EXCL, v.sys.openFile)
	if err != nil {
		return errAt(op, v.path, err)
	}
	defer func() { _ = claimed.Close() }()

	if err := restorePrimaryHeaderCore(claimed.File(), v.path, force, v.sys.syncDevice); err != nil {
		return errAt(op, v.path, err)
	}
	return nil
}

// readCurrentHeader reads the header copy cryptsetup would use -- the valid
// one with the higher sequence id, the primary at a tie (header.ReadCurrentHeader)
// -- with the checksum-algorithm reclassification every header read applies.
//
// Every reader goes through it. A reader under the shared lock (Unlock,
// Header) uses the chosen copy and leaves the medium alone; here this package
// DEVIATES from cryptsetup, whose LUKS2_hdr_read, finding a stale copy, takes
// the write lock and rewrites it as part of the read. A shared lock does not
// permit a write, and promoting it would let a read block on, or race, a
// writer. The stale copy is rewritten by the next operation that holds the
// exclusive lock (keyslotDevice.readHeader), or by RestorePrimaryHeader.
func readCurrentHeader(r io.ReaderAt) (*header.CurrentHeader, error) {
	cur, err := header.ReadCurrentHeader(r)
	if err != nil {
		return nil, reclassifyUnsupportedChecksum(err)
	}
	return cur, nil
}

// repairHeaderCopies rewrites the stale header copy from the current one,
// under the exclusive lock the caller holds, before the caller's own
// read-modify-write: the repair cryptsetup's LUKS2_hdr_read makes.
//
// As in cryptsetup the sequence id is not advanced: the repaired copy becomes
// the current one again, at the same generation. A stale secondary is
// rewritten alone, after the primary is made durable. A stale primary is
// rewritten through the ordinary two-copy writer, which puts the primary on
// the medium first and then rewrites the secondary from the same metadata;
// cryptsetup writes the primary alone, but at every instant of either order
// one copy is complete and current, so a crash part way loses nothing.
//
// The repair reproduces a copy already on the medium and authors nothing, so,
// like restorePrimaryHeaderCore, it is held to the header-wide rules the copy
// passed when it was read and not to the per-entry ones a write applies: a
// damaged entry must not stop the repair that precedes its removal.
//
// It is one write step (keyslotWriteStep), uncancellable as a rollback is:
// readHeader has no context, and a repair left half-done by a cancellation
// would be the state it exists to remove.
func repairHeaderCopies(d *keyslotDevice, cur *header.CurrentHeader) error {
	op := "repair the secondary LUKS2 header"
	if cur.Offset != header.PrimaryHeaderOffset {
		op = "repair the primary LUKS2 header"
	}
	// The reader accepts header areas the writer refuses (#50); a copy written
	// at such an area would land inside the primary's own JSON area.
	if _, err := header.HeaderAreaSizeForWrite(cur.Header); err != nil {
		return err
	}
	if err := d.sys.keyslotWriteStep(context.Background(), d, op); err != nil {
		return err
	}

	jsonData, area, err := header.EncodeMetadata(cur.Header, cur.Metadata)
	if err != nil {
		return reclassifyMetadataTooLarge(err)
	}
	if err := header.ValidateHeaderWideStructure(area, cur.Metadata); err != nil {
		return err
	}

	if cur.Offset != header.PrimaryHeaderOffset {
		// WriteEncodedHeader gives cur.Header the primary's identity, so the
		// caller goes on with a header shaped as every other read returns it.
		return header.WriteEncodedHeader(d.file, cur.Header, jsonData, area, d.sys.syncDevice)
	}

	if err := d.sys.syncDevice(d.file); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to make the primary header durable before repairing the secondary", Err: err}
	}
	if err := header.WriteSecondaryCopy(d.file, cur.Header, jsonData, area-header.HeaderSize, int64(area)); err != nil {
		return err
	}
	if err := d.sys.syncDevice(d.file); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to sync the repaired secondary header", Err: err}
	}
	return nil
}
