// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

var errFakeCustody = errors.New("fake custody failure")

func TestEnclaveBufferFirstAllocationFailure(t *testing.T) {
	custody := secret.Custody{
		Sized: func(int) (*enclave.Memory, error) { return nil, errFakeCustody },
	}
	b := newEnclaveBuffer(custody, "test", 4)
	if err := b.append('a'); !errors.Is(err, errFakeCustody) {
		t.Fatalf("append error = %v, want errFakeCustody", err)
	}
}

func TestEnclaveBufferGrowthAllocationFailure(t *testing.T) {
	real := secret.System()
	calls := 0
	custody := secret.Custody{
		Sized: func(n int) (*enclave.Memory, error) {
			calls++
			if calls > 1 {
				return nil, errFakeCustody
			}
			return real.Sized(n)
		},
		Destroy: real.Destroy,
	}
	b := newEnclaveBuffer(custody, "test", 1)
	if err := b.append('a'); err != nil {
		t.Fatalf("first append: %v", err)
	}
	// The buffer is now full (cap 1, len 1): the next append must grow,
	// which is the second Sized call, which the fake refuses.
	if err := b.append('b'); !errors.Is(err, errFakeCustody) {
		t.Fatalf("append error = %v, want errFakeCustody", err)
	}
}

func TestEnclaveBufferFinishCloneFailure(t *testing.T) {
	real := secret.System()
	custody := secret.Custody{
		Sized:   real.Sized,
		Destroy: real.Destroy,
		Copied:  func([]byte) (*enclave.Memory, error) { return nil, errFakeCustody },
	}
	b := newEnclaveBuffer(custody, "test", 4)
	if err := b.append('a'); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := b.finish(); !errors.Is(err, errFakeCustody) {
		t.Fatalf("finish error = %v, want errFakeCustody", err)
	}
}
