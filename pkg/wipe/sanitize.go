// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package wipe

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// chunk is how much one write or one verification read covers: a multiple of
// the O_DIRECT alignment and of the AES block size, so every chunk starts on
// a boundary a counter-mode stream can be regenerated from on its own, and
// ctx is checked once per chunk (DESIGN.md D.2).
const chunk = 1024 * 1024

// defaultCryptsetupLockDir is cryptsetup's own locking directory.
const defaultCryptsetupLockDir = "/run/cryptsetup"

// sys collects Sanitize's seams: every place it reaches the filesystem, a
// clock or a lock protocol, defaulted by defaultSys and overridden only by
// this package's own tests (DESIGN.md §E -- no package-level mutable vars).
type sys struct {
	openFile        device.OpenFunc
	clk             clock.Clock
	lockWait        time.Duration
	lockDir         string
	openLockFile    device.OpenLockFileFunc
	lockHeld        func(string)
	sysDevBlockRoot string
	statRdev        func(string) (uint64, error)
}

// defaultSys is what Sanitize uses in production.
func defaultSys() sys {
	return sys{
		openFile:        os.OpenFile,
		clk:             clock.System{},
		lockWait:        device.DefaultLockWait,
		lockDir:         defaultCryptsetupLockDir,
		openLockFile:    device.DefaultOpenLockFile,
		sysDevBlockRoot: device.DefaultSysDevBlockRoot,
		statRdev:        device.StatRdev,
	}
}

// Sanitize destroys the data on the device or file at path: a pass for each
// of p's patterns, in order, optionally a read-back verification of the last
// pass, and optionally a TRIM/DISCARD once every pass has landed.
//
// The device is locked (the node flock, then cryptsetup's own lock, excluding
// cryptsetup as well) and then claimed exclusively -- a second, O_EXCL open of
// the SAME locked descriptor's own inode, never of path again -- before a byte
// is written. A device something else holds returns ErrDeviceInUse and
// nothing is written.
func Sanitize(ctx context.Context, path string, p Params) error {
	return errs.At("wipe", "Sanitize", path, sanitize(ctx, path, p, defaultSys()))
}

// validate refuses a Standard or a Pattern this package does not know, before
// anything is opened or written.
func (p Params) validate() error {
	if p.Standard != NoStandard && p.Standard.Patterns() == nil {
		return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("unknown wipe standard %d", p.Standard)}
	}
	if p.Standard == NoStandard {
		for _, pattern := range p.Patterns {
			switch pattern {
			case Zeros, Ones, Random:
			default:
				return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("unknown wipe pattern %d", pattern)}
			}
		}
	}
	return nil
}

func sanitize(ctx context.Context, path string, p Params, s sys) error {
	if err := p.validate(); err != nil {
		return err
	}
	pinned, err := device.OpenPinned(ctx, "open the device to sanitize", path, os.O_RDWR, s.openFile)
	if err != nil {
		return err
	}

	locked, err := pinned.Lock(ctx, device.LockExclusive, s.lockWait, s.clk, s.lockDir, s.openLockFile, s.lockHeld)
	if err != nil {
		_ = pinned.Close()
		return err
	}
	defer func() {
		_ = locked.Unlock()
		_ = locked.File().Close()
	}()

	claimed, err := locked.Claim(ctx, "open the device exclusively to sanitize", os.O_RDWR|unix.O_EXCL, s.openFile)
	if err != nil {
		return err
	}
	defer func() { _ = claimed.Close() }()

	f := claimed.File()
	size, err := device.Size(f)
	if err != nil {
		return err
	}
	if size <= 0 {
		return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: path + ": the device reports a size of " + strconv.FormatInt(size, 10)}
	}

	patterns, verify := resolvePatterns(p)
	totalPasses := len(patterns)

	var last *passStream
	for i, pattern := range patterns {
		stream, err := newPassStream(pattern)
		if err != nil {
			return err
		}
		if err := writePass(ctx, f, path, size, stream, p.Progress, i+1, totalPasses); err != nil {
			return err
		}
		last = stream
	}

	// Every pass was synced as it ended (writePass), so the last one is on
	// the medium before it is verified.

	// Verification reads the medium PAST THE PAGE CACHE, through the locked
	// descriptor's own /proc/self/fd entry rather than path: the claim
	// targets exactly the inode that was locked (the H6 invariant), and
	// resolving path again here would let a retargeted symlink verify one
	// device while the passes wrote another.
	if verify {
		mediumPath := "/proc/self/fd/" + strconv.Itoa(int(locked.File().Fd())) // #nosec G115 -- a descriptor number fits an int
		if err := verifyWrite(ctx, path, mediumPath, size, last, p.Progress, totalPasses, s); err != nil {
			return err
		}
	}

	// Best effort, and documented so on Params.Discard: a device that does
	// not support TRIM has already been overwritten by the passes above, so
	// its refusal is not a failure of the wipe.
	if p.Discard {
		_ = device.Discard(f, size)
	}

	return nil
}

// resolvePatterns decides the pass sequence and the verification flag from
// p: Standard, if set, overrides Patterns; an empty sequence either way is a
// single Zeros pass; Verify overrides whatever Standard would otherwise
// decide.
func resolvePatterns(p Params) (patterns []Pattern, verify bool) {
	if p.Standard != NoStandard {
		patterns = p.Standard.Patterns()
		verify = p.Standard.requiresVerification()
	} else {
		patterns = p.Patterns
	}
	if len(patterns) == 0 {
		patterns = []Pattern{Zeros}
	}
	switch p.Verify {
	case VerifyAlways:
		verify = true
	case VerifyNever:
		verify = false
	}
	return patterns, verify
}

// passStream generates one pass's bytes: a constant for Zeros and Ones, or a
// keyed AES-256-CTR stream for Random, regenerable at any chunk offset on its
// own so a verification pass needs none of what was written to check it.
type passStream struct {
	pattern Pattern
	block   cipher.Block
	iv      [aes.BlockSize]byte
}

// newPassStream draws a fresh key and IV for a Random pass. Zeros and Ones
// need neither.
func newPassStream(pattern Pattern) (*passStream, error) {
	s := &passStream{pattern: pattern}
	switch pattern {
	case Zeros, Ones:
		return s, nil
	case Random:
	default:
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("unknown wipe pattern %d", pattern)}
	}

	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to draw the wipe pass key", Err: err}
	}
	if _, err := io.ReadFull(rand.Reader, s.iv[:]); err != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to draw the wipe pass IV", Err: err}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "failed to key the wipe pass stream", Err: err}
	}
	s.block = block
	return s, nil
}

// fill writes the stream's bytes for [off, off+len(buf)) into buf. off must
// be a multiple of the AES block size, which every chunk boundary is.
func (s *passStream) fill(buf []byte, off int64) {
	switch s.pattern {
	case Zeros:
		clear(buf)
		return
	case Ones:
		// Doubling copies: a handful of memmoves for a whole chunk.
		if len(buf) > 0 {
			buf[0] = 0xFF
			for n := 1; n < len(buf); n *= 2 {
				copy(buf[n:], buf[:n])
			}
		}
		return
	}

	// The counter for byte off is the IV plus off/16, as a 128-bit
	// big-endian sum, so the stream at any chunk can be regenerated on its
	// own.
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

// passFile is what a pass writes to: *os.File in production.
type passFile interface {
	io.WriterAt
	Sync() error
}

// writePass performs one wipe pass, writing stream over [0, size) of f in
// chunk-sized writes, checking ctx once per chunk, and syncing f when the
// pass is complete: a pass still in the page cache when the next one starts
// can be coalesced with it and never reach the medium.
func writePass(ctx context.Context, f passFile, path string, size int64, stream *passStream,
	progress func(Progress), passNum, totalPasses int) error {
	buffer := make([]byte, chunk)
	defer clear(buffer)

	for off := int64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return &errs.Error{Kind: err, Detail: fmt.Sprintf("%d of %d bytes written", off, size), Err: err}
		}

		n := int64(chunk)
		if size-off < n {
			n = size - off
		}
		stream.fill(buffer[:n], off)
		if _, err := f.WriteAt(buffer[:n], off); err != nil {
			return &errs.Error{Kind: errs.ErrIO, Detail: "write wipe pass on " + path, Err: err}
		}
		off += n

		if progress != nil {
			progress(Progress{Pass: passNum, Passes: totalPasses, Written: off, Total: size, Pattern: stream.pattern})
		}
	}

	if err := f.Sync(); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: fmt.Sprintf("sync wipe pass %d of %d on %s", passNum, totalPasses, path), Err: err}
	}
	return nil
}
