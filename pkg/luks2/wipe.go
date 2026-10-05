// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BLKDISCARD ioctl number for TRIM/discard on block devices
const BLKDISCARD = 0x1277

var (
	// ErrDeviceInUse indicates a destructive operation refused a block device
	// that something else holds: it is mounted, it backs a device-mapper
	// mapping or an md array, or another process opened it exclusively. The
	// kernel reports this when the device is opened with O_EXCL.
	ErrDeviceInUse = errors.New("the device is in use: it is mounted, mapped, or held open exclusively")

	// ErrWipeVerification indicates that what was read back from the medium,
	// past the page cache, is not what the last wipe pass wrote.
	ErrWipeVerification = errors.New("wipe verification failed: the medium does not hold what the last pass wrote")
)

// WipePattern defines the data pattern for a wipe pass
type WipePattern uint8

const (
	PatternZeros  WipePattern = iota // 0x00
	PatternOnes                      // 0xFF
	PatternRandom                    // a keyed AES-256-CTR stream, fresh per pass
)

// String returns the string representation of a WipePattern
func (p WipePattern) String() string {
	switch p {
	case PatternZeros:
		return "zeros"
	case PatternOnes:
		return "ones"
	case PatternRandom:
		return "random"
	default:
		return "unknown"
	}
}

// WipeStandard defines a named wipe methodology
type WipeStandard uint8

const (
	StandardCustom   WipeStandard = iota // Legacy/custom configuration
	StandardNIST                         // NIST SP 800-88 Rev 1
	StandardDoD3Pass                     // DoD 5220.22-M 3-pass
	StandardDoD7Pass                     // DoD 5220.22-M ECE 7-pass
)

// String returns the string representation of a WipeStandard
func (s WipeStandard) String() string {
	switch s {
	case StandardCustom:
		return "custom"
	case StandardNIST:
		return "nist"
	case StandardDoD3Pass:
		return "dod3"
	case StandardDoD7Pass:
		return "dod7"
	default:
		return "unknown"
	}
}

// GetPatternSequence returns the pattern sequence for a standard
func (s WipeStandard) GetPatternSequence() []WipePattern {
	switch s {
	case StandardNIST:
		// NIST SP 800-88: Single pass of random data
		return []WipePattern{PatternRandom}
	case StandardDoD3Pass:
		// DoD 5220.22-M 3-pass: Zeros -> Ones -> Random
		return []WipePattern{PatternZeros, PatternOnes, PatternRandom}
	case StandardDoD7Pass:
		// DoD 5220.22-M ECE 7-pass: (Z->O->R) + R + (Z->O->R)
		return []WipePattern{
			PatternZeros, PatternOnes, PatternRandom,
			PatternRandom,
			PatternZeros, PatternOnes, PatternRandom,
		}
	default:
		return nil
	}
}

// RequiresVerification returns whether the standard requires verification
func (s WipeStandard) RequiresVerification() bool {
	switch s {
	case StandardDoD3Pass, StandardDoD7Pass:
		return true
	default:
		return false
	}
}

// WipeProgress reports wipe operation progress
type WipeProgress struct {
	CurrentPass     int
	TotalPasses     int
	BytesWritten    int64
	TotalBytes      int64
	Pattern         WipePattern
	IsVerification  bool
	PercentComplete float64
}

// WipeProgressFunc is a callback for reporting wipe progress
type WipeProgressFunc func(WipeProgress)

// WipeOptions contains options for wiping a LUKS volume
type WipeOptions struct {
	// Existing fields (backward compatible)
	Device     string
	Passes     int  // Number of wipe passes (default: 1)
	Random     bool // Use random data (default: zeros)
	HeaderOnly bool // Destroy the headers and the keyslots area only (default: false, wipes all data)
	Trim       bool // Issue TRIM/DISCARD after wipe (for SSDs)

	// New fields for standards support
	Standard     WipeStandard     // Named standard (overrides Passes/Random if set)
	Patterns     []WipePattern    // Custom pattern sequence (overrides Passes/Random if set)
	Verify       bool             // Enable verification pass
	NoVerify     bool             // Disable verification, even for a standard that requires it
	ProgressFunc WipeProgressFunc // Progress callback (optional)
}

// wipeChunk is how much one write or one verification read covers. It is a
// multiple of directIOAlign and of the AES block size, so every chunk starts on
// a boundary both the O_DIRECT reader and the CTR counter can address.
const wipeChunk = 1024 * 1024

// passStream is the byte stream one wipe pass writes, and can write again.
//
// The random pattern is not drawn from crypto/rand directly. It is AES-256 in
// CTR mode under a key drawn from crypto/rand for this pass alone, which is a
// CSPRNG whose output at any offset can be produced a second time. That is the
// point: verification has to compare what is on the medium with what was
// written, and a pass of crypto/rand bytes cannot be compared with anything.
// The DoD sequences end with a random pass, so "verify" used to verify nothing
// at all.
type passStream struct {
	pattern WipePattern
	block   cipher.Block
	iv      [aes.BlockSize]byte
}

// newPassStream prepares the stream for one pass of pattern.
func newPassStream(pattern WipePattern) (*passStream, error) {
	s := &passStream{pattern: pattern}
	switch pattern {
	case PatternZeros, PatternOnes:
		return s, nil
	case PatternRandom:
	default:
		return nil, &detailError{Kind: ErrInvalidSize, Detail: "unknown wipe pattern " + strconv.Itoa(int(pattern))}
	}

	key := make([]byte, 32)
	defer clearBytes(key)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, &CryptoError{Op: "draw the wipe pass key", Err: err}
	}
	if _, err := io.ReadFull(rand.Reader, s.iv[:]); err != nil {
		return nil, &CryptoError{Op: "draw the wipe pass IV", Err: err}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &CryptoError{Op: "key the wipe pass stream", Err: err}
	}
	s.block = block
	return s, nil
}

// fill writes the stream's bytes for [off, off+len(buf)) into buf. off must be
// a multiple of the AES block size, which every chunk boundary is.
func (s *passStream) fill(buf []byte, off int64) {
	switch s.pattern {
	case PatternZeros:
		clear(buf)
		return
	case PatternOnes:
		// Doubling copies: a handful of memmoves for a whole chunk.
		if len(buf) > 0 {
			buf[0] = 0xFF
			for n := 1; n < len(buf); n *= 2 {
				copy(buf[n:], buf[:n])
			}
		}
		return
	}

	// The counter for byte off is the IV plus off/16, as a 128-bit big-endian
	// sum, so the stream at any chunk can be regenerated on its own.
	var ctr [aes.BlockSize]byte
	hi := binary.BigEndian.Uint64(s.iv[:8])
	lo := binary.BigEndian.Uint64(s.iv[8:])
	add := uint64(off) / aes.BlockSize // #nosec G115 -- off is a non-negative device offset
	sum := lo + add
	if sum < lo {
		hi++
	}
	binary.BigEndian.PutUint64(ctr[:8], hi)
	binary.BigEndian.PutUint64(ctr[8:], sum)

	clear(buf)
	cipher.NewCTR(s.block, ctr[:]).XORKeyStream(buf, buf)
}

// wipePassWithStream performs one wipe pass, writing stream over [0, size).
func wipePassWithStream(f *os.File, size int64, stream *passStream,
	progress WipeProgressFunc, passNum, totalPasses int) error {
	if size < 0 {
		return &detailError{Kind: ErrInvalidSize, Detail: "wipe size " + strconv.FormatInt(size, 10) + " is negative"}
	}

	buffer := make([]byte, wipeChunk)
	defer clearBytes(buffer)

	for off := int64(0); off < size; {
		n := int64(wipeChunk)
		if size-off < n {
			n = size - off
		}
		stream.fill(buffer[:n], off)
		if _, err := f.WriteAt(buffer[:n], off); err != nil {
			return &DeviceError{Device: f.Name(), Op: "write wipe pass", Err: err}
		}
		off += n

		if progress != nil {
			progress(WipeProgress{
				CurrentPass:     passNum,
				TotalPasses:     totalPasses,
				BytesWritten:    off,
				TotalBytes:      size,
				Pattern:         stream.pattern,
				PercentComplete: float64(off) / float64(size) * 100,
			})
		}
	}

	return nil
}

// mediumReader reads a device or file past every page cache in front of it.
type mediumReader interface {
	io.ReaderAt
	Close() error
}

// openMediumReader opens path for reading past the page cache. It is a seam
// because a medium that disagrees with what was written cannot be produced in
// a test without a failing device: this package's tests substitute it to model
// one. Unexported, substituted only by this package's tests.
var openMediumReader = openDirectReader

// directReader is an O_DIRECT descriptor with a page-aligned buffer, so a
// verification pass makes one open and one mapping rather than one per chunk.
type directReader struct {
	f   *os.File
	buf []byte
}

// openDirectReader opens path with O_DIRECT. Where O_DIRECT is refused it
// falls back to a buffered read only when the page cache IS the storage (a
// memory filesystem); otherwise it fails with ErrDirectIOUnsupported, because a
// read that cannot reach the medium cannot verify it.
func openDirectReader(path string) (mediumReader, error) {
	f, err := openDevice("read the device past the page cache", path, os.O_RDONLY|unix.O_DIRECT)
	if err != nil {
		if !errors.Is(err, unix.EINVAL) {
			return nil, err
		}
		memory, statErr := cacheIsTheStorage(path)
		if statErr != nil {
			return nil, statErr
		}
		if !memory {
			return nil, &detailError{Kind: ErrDirectIOUnsupported, Detail: path, Err: err}
		}
		return openDevice("read the device", path, os.O_RDONLY)
	}
	buf, err := unix.Mmap(-1, 0, wipeChunk+2*directIOAlign, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		_ = f.Close()
		return nil, &detailError{Detail: "failed to allocate an aligned buffer for a direct read", Err: err}
	}
	return &directReader{f: f, buf: buf}, nil
}

// ReadAt reads len(p) bytes at off, at most wipeChunk at a time, through the
// aligned buffer.
func (r *directReader) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for total < len(p) {
		want := min(len(p)-total, wipeChunk)
		at := off + int64(total)
		start := at - at%directIOAlign
		skip := int(at - start)
		span := (skip + want + directIOAlign - 1) / directIOAlign * directIOAlign
		n, err := r.f.ReadAt(r.buf[:span], start)
		got := max(0, min(n-skip, want))
		copy(p[total:], r.buf[skip:skip+got])
		total += got
		if err != nil {
			return total, err
		}
		if got < want {
			return total, io.EOF
		}
	}
	return total, nil
}

// Close releases the descriptor and the buffer.
func (r *directReader) Close() error {
	unmapErr := unix.Munmap(r.buf)
	if err := r.f.Close(); err != nil {
		return err
	}
	return unmapErr
}

// verifyWipe reads [0, size) of device back from the medium -- at every place
// mediumSources says its bytes must be read past a cache -- and compares it
// with what stream wrote.
func verifyWipe(device, mediumPath string, size int64, stream *passStream, progress WipeProgressFunc, totalPasses int) error {
	if size <= 0 {
		return nil
	}

	sources, err := mediumSources(mediumPath)
	if err != nil {
		return err
	}

	got := make([]byte, wipeChunk)
	want := make([]byte, wipeChunk)
	defer clearBytes(got)
	defer clearBytes(want)

	for _, src := range sources {
		r, err := openMediumReader(src.path)
		if err != nil {
			return err
		}
		err = compareMedium(r, src, device, size, stream, got, want, progress, totalPasses)
		closeErr := r.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return &DeviceError{Device: src.path, Op: "close the verification reader", Err: closeErr}
		}
	}
	return nil
}

// compareMedium is one source's half of verifyWipe.
func compareMedium(r io.ReaderAt, src mediumSource, device string, size int64, stream *passStream,
	got, want []byte, progress WipeProgressFunc, totalPasses int) error {
	for off := int64(0); off < size; {
		n := int64(wipeChunk)
		if size-off < n {
			n = size - off
		}
		read, err := r.ReadAt(got[:n], src.offset+off)
		if err != nil && !errors.Is(err, io.EOF) {
			return &DeviceError{Device: src.path, Op: "read back the wipe", Err: err}
		}
		if int64(read) < n {
			return &detailError{Kind: ErrWipeVerification, Detail: fmt.Sprintf(
				"%s: %s ended at byte %d of %d", device, src.path, off+int64(read), size)}
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
			return &detailError{Kind: ErrWipeVerification, Detail: fmt.Sprintf(
				"%s: %s differs from the %s pass at byte %d", device, src.path, stream.pattern, at)}
		}
		off += n

		if progress != nil {
			progress(WipeProgress{
				CurrentPass:     totalPasses + 1,
				TotalPasses:     totalPasses + 1,
				BytesWritten:    off,
				TotalBytes:      size,
				Pattern:         stream.pattern,
				IsVerification:  true,
				PercentComplete: float64(off) / float64(size) * 100,
			})
		}
	}
	return nil
}

// resolvePatternSequence determines patterns from options
// Returns (patterns, needsVerification)
func resolvePatternSequence(opts WipeOptions) ([]WipePattern, bool) {
	// Priority 1: Named standard
	if opts.Standard != StandardCustom {
		patterns := opts.Standard.GetPatternSequence()
		verify := opts.Standard.RequiresVerification()
		// Allow explicit override of verification, either way
		if opts.Verify {
			verify = true
		}
		if opts.NoVerify {
			verify = false
		}
		return patterns, verify
	}

	// Priority 2: Custom pattern sequence
	if len(opts.Patterns) > 0 {
		return opts.Patterns, opts.Verify && !opts.NoVerify
	}

	// Priority 3: Legacy mode (Passes + Random)
	var pattern WipePattern
	if opts.Random {
		pattern = PatternRandom
	} else {
		pattern = PatternZeros
	}

	passes := opts.Passes
	if passes <= 0 {
		passes = 1
	}

	patterns := make([]WipePattern, passes)
	for i := range patterns {
		patterns[i] = pattern
	}

	return patterns, opts.Verify && !opts.NoVerify
}

// openForWipe opens device for writing, EXCLUSIVELY.
//
// O_EXCL on a block device is the kernel's own in-use check: the open fails
// with EBUSY while the device is mounted, backs a device-mapper mapping, an md
// array or a swap area, or is held open exclusively by anyone else -- and a
// whole disk is refused while any of its partitions is held, because claiming a
// partition marks its disk. On a regular file Linux ignores O_EXCL without
// O_CREAT, so a file container opens as before.
//
// The kernel grants that claim only on an open BY PATH, so it is a second
// descriptor beside the locked one, and the path may name a different file by
// now. It is refused with ErrDeviceChanged unless it is the very file the lock
// is held on (requireSameDevice), and that check runs before anything is
// written: a wipe proven against the lock, or no wipe.
func openForWipe(dev *keyslotDevice) (*os.File, error) {
	f, err := openDevice("open the device for wiping", dev.path, os.O_RDWR|unix.O_EXCL)
	if errors.Is(err, unix.EBUSY) {
		return nil, &DeviceError{Device: dev.path, Op: "wipe", Err: &detailError{Kind: ErrDeviceInUse,
			Detail: "unmount it, close any mapping on it, and retry", Err: err}}
	}
	if err != nil {
		return nil, err
	}
	if err := requireSameDevice(dev.file, f, dev.path, "wipe it"); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// Wipe securely wipes a LUKS volume
func Wipe(opts WipeOptions) error {
	// Validate device path
	if err := ValidateDevicePath(opts.Device); err != nil {
		return err
	}

	// Resolve pattern sequence (handles standards, custom patterns, and legacy mode)
	patterns, needsVerify := resolvePatternSequence(opts)

	// Validate we have at least one pass (legacy compatibility check)
	if len(patterns) == 0 {
		// Fall back to legacy validation for backward compatibility
		if opts.Passes <= 0 && opts.Standard == StandardCustom && len(opts.Patterns) == 0 {
			return &detailError{Kind: ErrInvalidSize, Detail: "invalid number of passes " + strconv.Itoa(opts.Passes) + " (must be >= 1)"}
		}
		// If still no patterns, default to single zeros pass
		patterns = []WipePattern{PatternZeros}
	}

	// Locked on one descriptor, then claimed exclusively on a second that is
	// proven to be the same file before a byte is written (openForWipe). The
	// path is not resolved again after that: the passes write through the
	// claim, and the verification reads the locked file through its
	// /proc/self/fd entry.
	lock, dev, err := lockKeyslotDevice(opts.Device)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	f, err := openForWipe(dev)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if opts.HeaderOnly {
		return wipeHeaders(f)
	}

	// Measured on the descriptor that is about to be written, not by
	// reopening the path.
	size, err := measureDeviceSize(f)
	if err != nil {
		return &DeviceError{Device: opts.Device, Op: "measure the device", Err: err}
	}
	if size <= 0 {
		return &DeviceError{Device: opts.Device, Op: "measure the device",
			Err: &detailError{Kind: ErrInvalidSize, Detail: "the device reports a size of " + strconv.FormatInt(size, 10)}}
	}

	totalPasses := len(patterns)

	// Wipe in passes with pattern sequence
	var last *passStream
	for i, pattern := range patterns {
		stream, err := newPassStream(pattern)
		if err != nil {
			return err
		}
		if err := wipePassWithStream(f, size, stream, opts.ProgressFunc, i+1, totalPasses); err != nil {
			return &detailError{Detail: fmt.Sprintf("wipe pass %d (%s) failed", i+1, pattern), Err: err}
		}
		last = stream
	}

	// Sync to ensure writes are flushed
	if err := f.Sync(); err != nil {
		return &DeviceError{Device: opts.Device, Op: "sync the wipe", Err: err}
	}

	// Verification reads the medium PAST THE PAGE CACHE. Read through f, it
	// compared the cache with itself: the pages this process had just written
	// were served straight back, whatever reached the medium.
	if needsVerify {
		if err := verifyWipe(opts.Device, dev.mediumPath(), size, last, opts.ProgressFunc, totalPasses); err != nil {
			return err
		}
	}

	// Issue TRIM/DISCARD if requested (for SSDs). Best effort: a device that
	// does not support it has already been overwritten.
	if opts.Trim {
		_ = issueDiscard(f, size)
	}

	return nil
}

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
func wipeHeaders(f *os.File) error {
	for _, r := range wipeHeaderPlan(f) {
		if err := zeroRange(f, r.offset, r.size); err != nil {
			return &DeviceError{Device: f.Name(), Op: "wipe headers", Err: err}
		}
	}
	return f.Sync()
}

// zeroRange writes size zero bytes at offset, in fixed-size chunks so a size
// read from a header never chooses an allocation.
func zeroRange(f *os.File, offset, size int64) error {
	zeros := make([]byte, keyslotWipeChunk)
	for done := int64(0); done < size; {
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
		offsets      = append([]int64{LUKS2PrimaryHeaderOffset}, legalHeaderAreaSizes()...)
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
		area = LUKS2HeaderMinSize
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
	for pos := int64(LUKS2HeaderSize); pos < area; {
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
func firstDataOffset(metadata *LUKS2Metadata) int64 {
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
func declaredKeyslotAreas(metadata *LUKS2Metadata) []wipeRegion {
	var areas []wipeRegion
	for _, ks := range metadata.Keyslots {
		if ks == nil || ks.Area == nil {
			continue
		}
		off, offErr := parseSize(ks.Area.Offset)
		size, sizeErr := parseSize(ks.Area.Size)
		if offErr != nil || sizeErr != nil || off < 0 || size <= 0 || size > maxKeyslotAreaSize || off > (1<<62) {
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
	raw := make([]byte, LUKS2HeaderSize)
	if _, err := f.ReadAt(raw, offset); err != nil {
		return 0, false, false
	}
	var hdr LUKS2BinaryHeader
	if err := binary.Read(bytes.NewReader(raw), binary.BigEndian, &hdr); err != nil {
		return 0, false, false
	}
	if !bytes.Equal(hdr.Magic[:], []byte(expectedMagic(offset))) || hdr.Version != LUKS2Version {
		return 0, false, false
	}
	area, err := headerAreaSize(&hdr)
	if err != nil {
		return 0, false, false
	}
	if recorded, err := headerAreaOffset(&hdr); err != nil || recorded != offset {
		return 0, false, false
	}
	if offset != LUKS2PrimaryHeaderOffset && int64(area) != offset {
		return 0, false, false
	}
	valid = validateHeaderChecksum(&hdr, f, offset, area) == nil
	return int64(area), valid, true
}

// wipePass performs one wipe pass over the device
// -tags=integration, so `unused` fires on a function the default build exercises.
//
//nolint:unused // Test-only helper: the tests that call it are excluded under
func wipePass(f *os.File, size int64, random bool) error {
	const bufferSize = 1024 * 1024 // 1MB buffer

	// Validate size to prevent issues with negative values
	if size < 0 {
		return fmt.Errorf("invalid size: %d (must be >= 0)", size)
	}

	buffer := make([]byte, bufferSize)
	// Ensure buffer is cleared when function exits (defense in depth)
	defer clearBytes(buffer)

	if _, err := f.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}

	remaining := size
	for remaining > 0 {
		writeSize := bufferSize
		if remaining < int64(bufferSize) {
			writeSize = int(remaining)
		}

		// Fill buffer
		if random {
			if _, err := rand.Read(buffer[:writeSize]); err != nil {
				return fmt.Errorf("failed to generate random data: %w", err)
			}
		} else {
			// Zeros - clear the portion we're using
			for i := 0; i < writeSize; i++ {
				buffer[i] = 0
			}
		}

		// Write buffer
		n, err := f.Write(buffer[:writeSize])
		if err != nil {
			return fmt.Errorf("write error: %w", err)
		}

		remaining -= int64(n)
	}

	return nil
}

// WipeKeyslot wipes a specific keyslot
func WipeKeyslot(device string, keyslot int) error {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return err
	}

	// Acquire file lock for exclusive access, and do everything below through
	// the descriptor the lock was taken on rather than the path (#249, A10).
	lock, dev, err := lockKeyslotDevice(device)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	// Read the header once. It used to be read twice, through the path each
	// time; the copy the gate judged is now the copy that is rewritten.
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return err
	}

	// Find keyslot
	keyslotID := fmt.Sprintf("%d", keyslot)
	ks, ok := metadata.Keyslots[keyslotID]
	if !ok {
		return fmt.Errorf("keyslot %d not found", keyslot)
	}

	// THE GATE, and it was missing HERE while every sibling path had it.
	//
	// This function is identically destructive to KillKeyslot -- it overwrites
	// the key material and removes the entry -- and it needs no passphrase.
	// Without this it destroyed a single-keyslot volume that KillKeyslot refused
	// to touch, for the same operation.
	//
	// The gap was not an oversight in a list; it was two lists. The last-keyslot
	// guard was applied to the sites enumerated from a review finding, while the
	// metadata cleanup was written per site from the code, and nobody diffed
	// them. A rule and the set it must cover have to come from the same place --
	// see TestEveryKeyslotRemovalPathIsGuarded, which asserts over the paths as a
	// group so a sixth cannot be added without one.
	// It also refuses an area that is not keyslot space (#249, A2): this path
	// zeroed whatever range the header declared, the header copies and the
	// encrypted payload included.
	if err := checkKeyslotRemovable(dev, hdr, metadata, keyslotID); err != nil {
		return err
	}

	// The keyslot comes straight from the header and nothing has unlocked it, so
	// its geometry is untrusted: validated before it reaches a Seek or sizes an
	// allocation. Same call the unlock path and wipeKeyslotArea make.
	if err := validateKeyslot(keyslotID, ks); err != nil {
		return err
	}

	offset, err := parseSize(ks.Area.Offset)
	if err != nil {
		return fmt.Errorf("invalid keyslot offset: %w", err)
	}

	size, err := parseSize(ks.Area.Size)
	if err != nil {
		return fmt.Errorf("invalid keyslot size: %w", err)
	}

	// The resulting metadata is proved writable BEFORE anything is destroyed,
	// while the key material is still intact (#50).
	removeKeyslotFromMetadata(metadata, keyslotID)

	// THE SEQUENCE ID ADVANCES, and this path was the one that did not.
	//
	// LUKS2 keeps two header copies and uses the sequence id to decide which is
	// current. writeHeaderTo writes both, so a failure between them leaves
	// two copies with DIFFERENT metadata at the SAME sequence id -- and a reader
	// then has no way to tell which one is newer. That defeats the format's own
	// recovery mechanism, on a path whose whole purpose is destroying key
	// material.
	//
	// Every other mutating path already did this; WipeKeyslot was the eighth of
	// eight and the only omission. Audited rather than assumed after review of
	// e975ed5 named this site: Format, WriteHeader and RestorePrimaryHeader also
	// do not advance it, and all three are correct not to -- Format creates a
	// container with no older copy to disambiguate, WriteHeader is the primitive
	// whose caller owns the header, and RestorePrimaryHeader clones the
	// secondary onto the primary, where advancing would make the repaired copy
	// falsely claim to be newer than the copy it was made from.
	//
	// It is incremented before the pre-flight, matching the other paths exactly.
	// The field lives in the binary header rather than the JSON, so it does not
	// change what checkHeaderWritable measures.
	hdr.SequenceID++

	if err := checkHeaderWritable(hdr, metadata); err != nil {
		return err
	}

	// Claimed EXCLUSIVELY for the duration (#246 D4): a keyslot of a volume
	// that is open, or of a device something holds, is not wiped out from
	// under it. The claim is a second descriptor taken after the device lock
	// -- the same order Wipe takes them in -- and the writes still go through
	// the locked descriptor (#249, A10).
	claim, err := openForWipe(dev)
	if err != nil {
		return err
	}
	defer func() { _ = claim.Close() }()
	if err := keyslotWriteStep(dev, "zero the keyslot area"); err != nil {
		return err
	}
	f := dev.file

	if err := checkAreaWithinDevice(f, offset, size); err != nil {
		return fmt.Errorf("keyslot %d: %w", keyslot, err)
	}

	// Wipe the keyslot area in fixed-size chunks, so a header-supplied size
	// cannot choose an allocation.
	if err := zeroRange(f, offset, size); err != nil {
		return fmt.Errorf("failed to wipe keyslot: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync: %w", err)
	}

	// Write updated metadata through the locked descriptor.
	return dev.writeHeader(hdr, metadata)
}

// keyslotWipeChunk is how much of a keyslot area is zeroed per write.
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

// issueDiscard issues a BLKDISCARD ioctl to inform the SSD to release blocks.
// This is a best-effort operation - failure is not fatal as the device may not support TRIM.
//
// Security note: TRIM on encrypted volumes can leak information about which blocks
// are in use vs. free space. However, when used as part of a secure wipe operation
// (after overwriting data), TRIM provides an additional layer of erasure for SSDs.
func issueDiscard(f *os.File, size int64) error {
	// Validate size to prevent integer overflow when converting to uint64
	// A negative size would wrap to a very large value, potentially causing issues
	if size <= 0 {
		return &detailError{Kind: ErrInvalidSize, Detail: "invalid discard size " + strconv.FormatInt(size, 10) + " (must be > 0)"}
	}

	// BLKDISCARD takes a uint64[2] array: [offset, length]
	discardRange := [2]uint64{0, uint64(size)}

	// #nosec G103 -- unsafe.Pointer required for IOCTL syscall to pass array to kernel
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		f.Fd(),
		uintptr(BLKDISCARD),
		uintptr(unsafe.Pointer(&discardRange[0])),
	)

	if errno != 0 {
		return &DeviceError{Device: f.Name(), Op: "BLKDISCARD", Err: errno}
	}

	return nil
}
