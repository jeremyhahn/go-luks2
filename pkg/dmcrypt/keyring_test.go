// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package dmcrypt

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	keyringpkg "github.com/jeremyhahn/go-luks2/internal/keyring"
)

// TestCheckKeyringLeavesNothingBehind is the preflight's happy path.
func TestCheckKeyringLeavesNothingBehind(t *testing.T) {
	fake := &fakeKeyring{}
	fake.install(t)

	if err := CheckKeyring(context.Background()); err != nil {
		t.Fatalf("the preflight failed against a working keyring: %v", err)
	}
	if n := fake.linkedKeys(memorySessionRing); n != 0 {
		t.Fatalf("the preflight left %d key(s) in the ring; it leaked its probe", n)
	}
	if len(fake.added) != 1 {
		t.Fatalf("the preflight added %d keys, want exactly one probe", len(fake.added))
	}
}

func TestCheckKeyringIsRepeatableWithAFreshVolumeSizedLogonProbe(t *testing.T) {
	fake := &fakeKeyring{}
	fake.install(t)
	add := sys.keyring.Add
	var types []string
	var sizes []int
	sys.keyring.Add = func(keyType, description string, payload []byte, ring int) (int, error) {
		types = append(types, keyType)
		sizes = append(sizes, len(payload))
		return add(keyType, description, payload, ring)
	}

	for i := 0; i < 2; i++ {
		if err := CheckKeyring(context.Background()); err != nil {
			t.Fatalf("preflight %d failed against a working keyring: %v", i+1, err)
		}
	}
	if n := fake.linkedKeys(memorySessionRing); n != 0 {
		t.Fatalf("two preflights left %d key(s) in the ring", n)
	}
	if len(fake.added) != 2 || fake.added[0] == fake.added[1] {
		t.Fatalf("probe descriptions = %v, want two distinct ones", fake.added)
	}
	for i := range types {
		if types[i] != keyringpkg.KeyType || sizes[i] != 64 {
			t.Fatalf("probe %d was a %d-byte %q key, want a 64-byte %q key", i+1, sizes[i], types[i], keyringpkg.KeyType)
		}
	}
}

// TestCheckKeyringReportsTheSameTypedFailureAnActivateWould is the point of
// the preflight: a daemon that calls it at startup must get exactly the
// diagnosis it would have got at the first activation.
func TestCheckKeyringReportsTheSameTypedFailureAnActivateWould(t *testing.T) {
	fake := &fakeKeyring{addErr: unix.EPERM}
	fake.install(t)

	err := CheckKeyring(context.Background())
	if err == nil {
		t.Fatal("the preflight passed with the keyring syscalls blocked")
	}
	if !errors.Is(err, ErrKeyringBlocked) || !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("the preflight's failure is not the one Activate would report: %v", err)
	}
	var kerr *KeyringError
	if !errors.As(err, &kerr) {
		t.Fatalf("the preflight's failure is not a *KeyringError: %T %v", err, err)
	}
	if !strings.Contains(err.Error(), "seccomp") {
		t.Fatalf("the preflight's failure carries no remedy: %v", err)
	}
}

// TestCheckKeyringCatchesABrokenReleasePath makes the preflight cover
// teardown as well as setup.
func TestCheckKeyringCatchesABrokenReleasePath(t *testing.T) {
	fake := &fakeKeyring{revokeErr: unix.EACCES, unlinkErr: unix.EACCES}
	fake.install(t)

	err := CheckKeyring(context.Background())
	if err == nil {
		t.Fatal("the preflight passed even though the probe key could not be released")
	}
	if !errors.Is(err, ErrKeyringKeyNotReleased) {
		t.Fatalf("the preflight did not report the release failure: %v", err)
	}
	if fake.linkedKeys(memorySessionRing) != 1 {
		t.Errorf("the preflight reported an unreleasable probe but the ring does not hold one")
	}
}

// --- KeyringError ---

func TestKeyringFailureClassifiesAndAttachesTheErrno(t *testing.T) {
	kerr := keyringFailure("probe", unix.ENOSYS)
	if !errors.Is(kerr, ErrKeyringUnsupported) {
		t.Fatalf("keyringFailure(ENOSYS) = %v, want ErrKeyringUnsupported", kerr)
	}
	if !errors.Is(kerr, unix.ENOSYS) {
		t.Fatalf("the underlying errno is not reachable: %v", kerr)
	}
}

func TestErrStringHandlesANilError(t *testing.T) {
	if got := errString(nil); got != "<nil>" {
		t.Fatalf("errString(nil) = %q, want %q", got, "<nil>")
	}
	if got := errString(errors.New("boom")); got != "boom" {
		t.Fatalf("errString = %q, want %q", got, "boom")
	}
}

func TestKeyringErrorFormatsWithTheRemedy(t *testing.T) {
	err := &KeyringError{Op: "add the volume key", Kind: keyringpkg.ErrBlocked, Err: unix.EPERM}
	if got := err.Error(); !strings.Contains(got, "add the volume key") || !strings.Contains(got, "seccomp") {
		t.Fatalf("Error() = %q, want the op and the remedy", got)
	}
}

func TestKeyringErrorIsMatchesTheSentinelFamily(t *testing.T) {
	err := &KeyringError{Op: "x", Kind: ErrKeyringQuotaExhausted, Err: unix.EDQUOT}
	for _, target := range []error{ErrKeyring, ErrKeyringUnavailable, ErrKeyringQuotaExhausted} {
		if !errors.Is(err, target) {
			t.Errorf("a quota failure does not match %v: %v", target, err)
		}
	}
	for _, target := range []error{ErrKeyringBlocked, ErrKeyringUnsupported, ErrKeyringFailed} {
		if errors.Is(err, target) {
			t.Errorf("a quota failure also matches %v, so the classification is not exclusive", target)
		}
	}
	if !errors.Is(err, unix.EDQUOT) {
		t.Errorf("the underlying errno is not reachable through Unwrap: %v", err)
	}
}

func TestClassifyKeyringErrTranslatesUnavailableError(t *testing.T) {
	uae := keyringpkg.Failure("resolve the session keyring", unix.EPERM)
	got := classifyKeyringErr(uae)

	var kerr *KeyringError
	if !errors.As(got, &kerr) {
		t.Fatalf("classifyKeyringErr(%T) = %T, want *KeyringError", uae, got)
	}
	if !errors.Is(got, ErrKeyringBlocked) {
		t.Fatalf("the translated error lost its classification: %v", got)
	}

	// Everything else -- the two anomalies, and nil -- passes through
	// unchanged.
	if classifyKeyringErr(nil) != nil {
		t.Error("classifyKeyringErr(nil) is not nil")
	}
	other := errors.New("unrelated")
	if classifyKeyringErr(other) != other { //nolint:errorlint // identity check, not a classification
		t.Error("classifyKeyringErr altered an error it does not own")
	}
}
