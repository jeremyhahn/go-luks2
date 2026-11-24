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

// Custody allocates and releases the enclaves key material lives in; its constructors are fields so tests can make them refuse. Production uses System.
type Custody struct {
	// Sized returns an enclave over n bytes of locked, zeroed, writable
	// memory, as enclave.NewMemorySized does.
	Sized func(n int) (enclave.ByteAccess, error)

	// Moved moves b into a frozen enclave and wipes b on every path, as
	// enclave.NewMemory does.
	Moved func(b []byte) (enclave.ByteAccess, error)

	// Copied copies b into a frozen enclave and leaves b alone, as
	// enclave.NewMemoryCopy does.
	Copied func(b []byte) (enclave.ByteAccess, error)

	// Destroy releases an enclave and returns go-enclave's release report.
	Destroy func(e enclave.ByteAccess) error

	// Allocator returns the allocator the constructors admit through.
	Allocator func() (enclave.Allocator, error)
}

// System is the custody every production path uses: the constructors admit
// through go-enclave's process Allocator.
func System() Custody {
	return Admitted(enclave.ProcessAllocator)
}

// Admitted is a Custody whose constructors admit through the process allocator before mapping anything.
func Admitted(allocator func() (enclave.Allocator, error)) Custody {
	sized := func(n int) (enclave.ByteAccess, error) {
		a, err := allocator()
		if err != nil {
			return nil, err
		}
		return a.NewSized(n)
	}
	return Custody{
		Sized: sized,
		Moved: func(b []byte) (enclave.ByteAccess, error) {
			a, err := allocator()
			if err != nil {
				enclave.Wipe(b)
				return nil, err
			}
			return a.New(b)
		},
		Copied:    copiedInto(sized),
		Destroy:   enclave.ByteAccess.Destroy,
		Allocator: allocator,
	}
}

// copiedInto copies into a fresh enclave and freezes it read-only; a non-Freezer handle fails and is destroyed.
func copiedInto(sized func(n int) (enclave.ByteAccess, error)) func([]byte) (enclave.ByteAccess, error) {
	return func(src []byte) (enclave.ByteAccess, error) {
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
		var f enclave.Freezer
		if !enclave.As(e, &f) {
			_ = e.Destroy()
			return nil, &enclave.CapabilityError{Backend: e.Backend().Name(), Capability: enclave.CapabilityFreeze}
		}
		if err := f.Freeze(); err != nil {
			_ = e.Destroy()
			return nil, err
		}
		return e, nil
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

// New returns an enclave over n bytes of locked, zeroed memory to fill in place; op names the material in errors.
func (c Custody) New(op string, n int) (enclave.ByteAccess, error) {
	e, err := c.Sized(n)
	if err != nil {
		return nil, &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: err}
	}
	return e, nil
}

// Adopt moves existing material into an enclave and takes ownership of b, which is wiped on every path. Prefer New.
func (c Custody) Adopt(op string, b []byte) (enclave.ByteAccess, error) {
	e, err := c.Moved(b)
	if err != nil {
		return nil, &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: err}
	}
	return e, nil
}

// Random reads n bytes from rand directly into locked memory.
func (c Custody) Random(op string, n int, rand io.Reader) (enclave.ByteAccess, error) {
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

// Clone returns a frozen enclave holding a copy of b, which must itself be protected.
func (c Custody) Clone(op string, b []byte) (enclave.ByteAccess, error) {
	e, err := c.Copied(b)
	if err != nil {
		return nil, &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: err}
	}
	return e, nil
}

// CloneWritable is Clone with writable pages, for short-lived scratch normalized in place.
func (c Custody) CloneWritable(op string, b []byte) (enclave.ByteAccess, error) {
	return c.CloneFiltered(op, b, func(byte) bool { return true })
}

// CloneFiltered is CloneWritable keeping only the bytes keep accepts.
func (c Custody) CloneFiltered(op string, b []byte, keep func(byte) bool) (enclave.ByteAccess, error) {
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

// Release destroys every non-nil enclave and drops go-enclave's release report: none means material escaped, the outcome is already decided, and WipeAll at shutdown reports it again.
func (c Custody) Release(secrets ...enclave.ByteAccess) {
	for _, s := range secrets {
		if s == nil {
			continue
		}
		// Dropped on purpose; see the doc comment for every outcome and why
		// none of them is this module's to act on or to return.
		_ = c.Destroy(s)
	}
}

// Borrow runs fn on e's material, reporting a dead enclave as ErrProtectedMemory; fn must not retain the slice or re-borrow e.
func Borrow(op string, e enclave.ByteAccess, fn func([]byte) error) error {
	if e == nil {
		// A nil handle holds nothing: it is reported as a destroyed one.
		return &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: enclave.ErrEnclaveDestroyed}
	}
	if err := Locked(op, e); err != nil {
		return err
	}
	err := e.WithBytes(fn)
	if err == nil {
		return nil
	}
	if errors.Is(err, enclave.ErrEnclaveDestroyed) {
		return &errs.Error{Kind: ErrProtectedMemory, Detail: op, Err: err}
	}
	return err
}

// Locked refuses a handle whose reported backend is not go-enclave locked memory, without reading or destroying it.
func Locked(op string, e enclave.ByteAccess) error {
	if e == nil {
		return nil
	}
	if name := e.Backend().Name(); name != enclave.LockedMemoryBackendName {
		return &errs.Error{Kind: ErrNotLockedMemory, Detail: op, Err: &NotLockedMemoryError{Backend: name}}
	}
	return nil
}
