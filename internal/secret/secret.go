// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"errors"
	"io"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Custody allocates the enclaves key material lives in, and releases them.
//
// Its fields are go-enclave's three constructors and its release. They are
// fields, not calls written where they are needed, for one reason: the
// fail-closed paths cannot otherwise be tested. RLIMIT_MEMLOCK is
// process-wide, so exhausting it for real inside a test binary takes the rest
// of the suite with it, and a refusal that only ever runs on a machine already
// out of locked memory is a refusal nothing checks on the way in. A test
// builds a Custody whose constructors refuse; production code uses System.
type Custody struct {
	// Sized returns an enclave over n bytes of locked, zeroed, writable
	// memory, as enclave.NewMemoryEnclaveSized does.
	Sized func(n int) (*enclave.MemoryEnclave, error)

	// Moved moves b into a frozen enclave and wipes b on every path, as
	// enclave.NewMemoryEnclave does.
	Moved func(b []byte) (*enclave.MemoryEnclave, error)

	// Copied copies b into a frozen enclave and leaves b alone, as
	// enclave.NewMemoryEnclaveCopy does.
	Copied func(b []byte) (*enclave.MemoryEnclave, error)

	// Destroy releases an enclave and returns go-enclave's release report.
	Destroy func(e *enclave.MemoryEnclave) error

	// Allocator returns the allocator the constructors admit through.
	Allocator func() (*enclave.Allocator, error)
}

// System is the custody every production path uses: the constructors admit
// through go-enclave's process Allocator.
func System() Custody {
	return Admitted(enclave.ProcessAllocator)
}

// Admitted is a Custody whose constructors ADMIT through the allocator
// returns before anything is mapped (#26): the module allocates against the
// one budget the binary sized (enclave.SetAllocator), or against
// RLIMIT_MEMLOCK by default, and never installs or builds an allocator of its
// own. A refusal is the allocator's typed enclave.ErrBudgetExhausted rather
// than an mlock failure partway through.
func Admitted(allocator func() (*enclave.Allocator, error)) Custody {
	sized := func(n int) (*enclave.MemoryEnclave, error) {
		a, err := allocator()
		if err != nil {
			return nil, err
		}
		return a.NewSized(n)
	}
	return Custody{
		Sized: sized,
		Moved: func(b []byte) (*enclave.MemoryEnclave, error) {
			a, err := allocator()
			if err != nil {
				enclave.Wipe(b)
				return nil, err
			}
			return a.New(b)
		},
		Copied: func(src []byte) (*enclave.MemoryEnclave, error) {
			if len(src) == 0 {
				return nil, enclave.ErrEmptyEnclave
			}
			e, err := sized(len(src))
			if err != nil {
				return nil, err
			}
			if err := e.WithBytes(func(dst []byte) error {
				copy(dst, src)
				return nil
			}); err != nil {
				_ = e.Destroy()
				return nil, err
			}
			if err := e.Freeze(); err != nil {
				_ = e.Destroy()
				return nil, err
			}
			return e, nil
		},
		Destroy:   (*enclave.MemoryEnclave).Destroy,
		Allocator: allocator,
	}
}

// Admissible reports ErrProtectedMemory unless n bytes could ever be held at
// once: an operation whose peak exceeds the allocator's whole limit is refused
// before it starts, rather than partway through, after work it cannot finish.
func (c Custody) Admissible(op string, n int64) error {
	a, err := c.Allocator()
	if err != nil {
		return &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: err}
	}
	if limit := a.Limit(); n > limit {
		return &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: &enclave.BudgetError{Requested: n, Limit: limit}}
	}
	return nil
}

// New returns an enclave over n bytes of locked, zeroed memory for the caller
// to fill IN PLACE, through a borrow.
//
// It is the constructor to reach for whenever the material does not exist
// yet, because material produced inside the borrow is never anywhere else.
// Use Adopt only for material that already exists outside an enclave and
// cannot be produced inside one. op names the material in an error; it never
// carries key content or a key length.
func (c Custody) New(op string, n int) (*enclave.MemoryEnclave, error) {
	e, err := c.Sized(n)
	if err != nil {
		return nil, &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: err}
	}
	return e, nil
}

// Adopt moves already-materialized key material into an enclave.
//
// It TAKES OWNERSHIP of b: go-enclave wipes the caller's slice on every return
// path, including the failure path, so the material does not survive in
// ordinary memory even when the lock is refused. The caller must not read b
// afterwards.
//
// This is the second-best constructor and exists only for the stdlib boundary
// where a value is handed back already on the heap -- a KDF return, an
// AF-merge result. Prefer New.
func (c Custody) Adopt(op string, b []byte) (*enclave.MemoryEnclave, error) {
	e, err := c.Moved(b)
	if err != nil {
		return nil, &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: err}
	}
	return e, nil
}

// Random draws n bytes from rand DIRECTLY into locked memory.
//
// The read happens inside the borrow, so the bytes are written into the locked
// pages themselves and never exist on the Go heap -- which is the whole point.
// A master key produced on the heap and then moved would have spent its first
// moments on swappable, core-dumpable memory that a later wipe cannot reliably
// reach. rand is crypto/rand.Reader on every production path.
func (c Custody) Random(op string, n int, rand io.Reader) (*enclave.MemoryEnclave, error) {
	e, err := c.New(op, n)
	if err != nil {
		return nil, err
	}
	if err := e.WithBytes(func(b []byte) error {
		_, err := io.ReadFull(rand, b)
		return err
	}); err != nil {
		c.Release(e)
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: op, Err: err}
	}
	return e, nil
}

// Clone returns a FROZEN enclave holding a copy of b.
//
// It is for material that is ALREADY in protected memory and must be narrowed
// -- a line located inside a locked file buffer, a body trimmed of its
// surrounding whitespace -- where Adopt cannot be used because the source is
// not the caller's to wipe. b must itself be protected; copying unprotected
// bytes with this only moves them, it does not un-expose them.
//
// The result is read-only, exactly as Adopt's is: the material is complete
// when this returns, so a write through a slice retained past its borrow
// faults the process instead of silently corrupting a credential.
func (c Custody) Clone(op string, b []byte) (*enclave.MemoryEnclave, error) {
	e, err := c.Copied(b)
	if err != nil {
		return nil, &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: err}
	}
	return e, nil
}

// CloneWritable is Clone whose result a borrow may WRITE to.
//
// It exists for a copy that is normalised in place after it is taken -- a
// candidate body lower-cased before the hex test -- which the frozen result
// of Clone cannot be. The pages are writable for the enclave's whole life, so
// the copy should be short-lived scratch, destroyed as soon as the normalised
// bytes have been consumed; material returned to a caller belongs in Clone.
func (c Custody) CloneWritable(op string, b []byte) (*enclave.MemoryEnclave, error) {
	return c.CloneFiltered(op, b, func(byte) bool { return true })
}

// CloneFiltered is CloneWritable keeping only the bytes keep reports true
// for, sized exactly to what survives.
//
// It exists so that stripping separators out of a formatted secret happens
// inside locked memory rather than through strings.ReplaceAll, which would
// yield an unwipeable copy of the whole thing.
func (c Custody) CloneFiltered(op string, b []byte, keep func(byte) bool) (*enclave.MemoryEnclave, error) {
	n := 0
	for _, x := range b {
		if keep(x) {
			n++
		}
	}
	if n == 0 {
		return nil, &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: enclave.ErrEmptyEnclave}
	}

	e, err := c.New(op, n)
	if err != nil {
		return nil, err
	}
	if err := Borrow(op, e, func(dst []byte) error {
		i := 0
		for _, x := range b {
			if keep(x) {
				dst[i] = x
				i++
			}
		}
		return nil
	}); err != nil {
		c.Release(e)
		return nil, err
	}
	return e, nil
}

// Release destroys every enclave given -- zeroizing the material and
// returning its pages -- skipping nils. It is the ONE place this module
// receives go-enclave's release report, so the decision below is made once
// rather than re-made, or silently not made, at each call site. A function
// holding several pieces of key material releases all of them in a single
// deferred call, and one enclave's report never stops the next release.
//
// # What the report can say, and why it is not an operation failure
//
// Destroy returns the release report directly (go-enclave v0.7.0-alpha).
// Apart from nil it is one of two things, and neither means key material
// escaped locked memory:
//
//   - enclave.ErrReleasedWithoutWipe: the mprotect that makes a frozen region
//     writable was denied (a seccomp filter or sandbox), so the pages were
//     unmapped without the in-process overwrite. They were mlock'd for their
//     whole life, so nothing reached swap, and the kernel zeroes an anonymous
//     page before any reuse. What it reports is the ENVIRONMENT: the same
//     denial reaches every frozen enclave in the process.
//   - enclave.ErrLockedMemoryUnavailable: the release itself was refused
//     (ENOMEM at vm.max_map_count is the realistic cause), so the pages are
//     still MAPPED and stay on go-enclave's WipeAll ledger. go-enclave wipes
//     before it unlocks, so material is never left both unwiped and unlocked:
//     if the wipe ran the pages hold zeroes, and if it could not run the pages
//     are still mlock'd, as they have been all along. Only the process's
//     WipeAll, or its exit, takes them back.
//
// This module can do nothing with either. It cannot remedy the environment,
// retrying at once with nothing changed is refused again (go-enclave's own
// guidance), and WipeAll belongs to the binary that owns the process, never to
// a library. Nor may it turn either into the operation's error: every release
// happens after the operation's outcome is already decided -- a volume
// formatted, a keyslot written, a mapping created -- or while an earlier error
// is already being returned. Reporting a completed Format or Unlock as failed
// because an unmap was refused afterwards would invite the caller to repeat
// it, and a repeated Format destroys a volume. And it may not log: a logger in
// a layer-0 primitive imposes a logging decision on every embedding
// application.
//
// So the report is dropped HERE, deliberately and for those reasons. An
// application that wants to see these conditions has them where it can act:
// its own Destroy calls on the enclaves this module hands it report the same
// environment, and its shutdown WipeAll counts any pages still held and
// reports, as a *enclave.SweepError, the unwiped releases and corruption the
// sweep itself meets.
//
// Detected CORRUPTION is not a report and is not dropped: go-enclave panics
// with enclave.ErrEnclaveCorrupted, after wiping, and Release does not recover
// it. A process whose locked memory was written by something that did not own
// it must not carry on.
func (c Custody) Release(secrets ...*enclave.MemoryEnclave) {
	for _, s := range secrets {
		if s == nil {
			continue
		}
		// Dropped on purpose; see the doc comment for every outcome and why
		// none of them is this module's to act on or to return.
		_ = c.Destroy(s)
	}
}

// Borrow runs fn against the material inside e, translating a dead or
// destroyed enclave into ErrProtectedMemory so callers get one error
// vocabulary rather than go-enclave's.
//
// fn must not retain the slice and must not call back into the same enclave;
// both are go-enclave contracts, not local conventions. fn MAY borrow other
// enclaves, which is what makes the crypto helpers composable. fn's own error
// passes through unwrapped; only the custody failure is reclassified.
func Borrow(op string, e *enclave.MemoryEnclave, fn func([]byte) error) error {
	err := e.WithBytes(fn)
	if err == nil {
		return nil
	}
	if errors.Is(err, enclave.ErrEnclaveDestroyed) {
		return &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: err}
	}
	return err
}
