// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// enclaveBuffer grows a credential directly in locked memory, one byte at a
// time, so a key file or a piped passphrase of unknown length is never held
// anywhere else (DESIGN.md §B.7: "input is read straight into an enclave").
// It doubles capacity by allocating a new, larger enclave and copying the
// old one's content across under a borrow of both, which is the only way to
// grow without a plain-heap intermediate.
type enclaveBuffer struct {
	custody secret.Custody
	op      string
	e       *enclave.MemoryEnclave
	cap     int
	n       int
}

// newEnclaveBuffer returns an empty buffer that allocates lazily, on the
// first append, so a caller that reads zero bytes never takes an enclave at
// all.
func newEnclaveBuffer(custody secret.Custody, op string, initCap int) *enclaveBuffer {
	return &enclaveBuffer{custody: custody, op: op, cap: initCap}
}

// len reports how many bytes have been appended so far.
func (b *enclaveBuffer) len() int { return b.n }

// append adds one byte, growing the backing enclave first if it is full.
func (b *enclaveBuffer) append(c byte) error {
	if b.e == nil {
		e, err := b.custody.New(b.op, b.cap)
		if err != nil {
			return err
		}
		b.e = e
	}
	if b.n == b.cap {
		grownCap := b.cap * 2
		grown, err := b.custody.New(b.op, grownCap)
		if err != nil {
			return err
		}
		if err := secret.Borrow(b.op, b.e, func(oldBytes []byte) error {
			return secret.Borrow(b.op, grown, func(newBytes []byte) error {
				copy(newBytes, oldBytes[:b.n])
				return nil
			})
		}); err != nil {
			b.custody.Release(grown)
			return err
		}
		b.custody.Release(b.e)
		b.e = grown
		b.cap = grownCap
	}
	if err := secret.Borrow(b.op, b.e, func(buf []byte) error {
		buf[b.n] = c
		return nil
	}); err != nil {
		return err
	}
	b.n++
	return nil
}

// finish returns a frozen, exactly-sized enclave over what was appended,
// and releases the buffer's own scratch enclave either way. ErrEmptyCredential
// if nothing was ever appended.
func (b *enclaveBuffer) finish() (*enclave.MemoryEnclave, error) {
	defer b.release()
	if b.n == 0 {
		return nil, &Error{Kind: ErrEmptyCredential}
	}
	var result *enclave.MemoryEnclave
	err := secret.Borrow(b.op, b.e, func(buf []byte) error {
		var cerr error
		result, cerr = b.custody.Clone(b.op, buf[:b.n])
		return cerr
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// release destroys the buffer's scratch enclave, if any, without
// finishing. Safe to call more than once.
func (b *enclaveBuffer) release() {
	if b.e != nil {
		b.custody.Release(b.e)
		b.e = nil
	}
}
