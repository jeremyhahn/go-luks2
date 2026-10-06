// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package keyring

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// memoryKey is one entry in the fake in-memory keyring, mirroring the shape
// of the kernel's own: revocation frees the payload immediately, and a
// revoked key still resolves as EKEYREVOKED rather than disappearing.
type memoryKey struct {
	keyType     string
	description string
	revoked     bool
}

// fakeSyscalls is an in-process stand-in for the real kernel keyring, so this
// package's unit suite never depends on add_key/keyctl being reachable (they
// are frequently blocked by a seccomp profile, which is the exact condition
// Classify exists to diagnose).
type fakeSyscalls struct {
	mu         sync.Mutex
	nextID     int
	ring       int
	keys       map[int]*memoryKey
	stillThere bool

	sessionRingErr error
	addErr         error
	searchErr      error
	revokeErr      error
	unlinkErr      error
}

func newFakeSyscalls() *fakeSyscalls {
	return &fakeSyscalls{nextID: 1, ring: 100, keys: map[int]*memoryKey{}}
}

func (f *fakeSyscalls) seam() Syscalls {
	return Syscalls{
		SessionRing: func() (int, error) {
			if f.sessionRingErr != nil {
				return 0, f.sessionRingErr
			}
			return f.ring, nil
		},
		Add: func(keyType, description string, _ []byte, ringID int) (int, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.addErr != nil {
				return 0, f.addErr
			}
			if ringID != f.ring {
				return 0, unix.ENOKEY
			}
			for _, k := range f.keys {
				if k.keyType == keyType && k.description == description {
					k.revoked = false
					return 0, nil
				}
			}
			id := f.nextID
			f.nextID++
			f.keys[id] = &memoryKey{keyType: keyType, description: description}
			return id, nil
		},
		Search: func(ringID int, keyType, description string) (int, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.searchErr != nil {
				return 0, f.searchErr
			}
			if ringID != f.ring {
				return 0, unix.ENOKEY
			}
			for id, k := range f.keys {
				if k.keyType == keyType && k.description == description {
					if k.revoked && !f.stillThere {
						return 0, unix.EKEYREVOKED
					}
					return id, nil
				}
			}
			return 0, unix.ENOKEY
		},
		Revoke: func(keyID int) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.revokeErr != nil {
				return f.revokeErr
			}
			k, ok := f.keys[keyID]
			if !ok {
				return unix.ENOKEY
			}
			k.revoked = true
			return nil
		},
		Unlink: func(keyID, ringID int) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.unlinkErr != nil {
				return f.unlinkErr
			}
			if _, ok := f.keys[keyID]; !ok {
				return unix.ENOKEY
			}
			if !f.stillThere {
				delete(f.keys, keyID)
			}
			return nil
		},
	}
}

func TestAddVolumeKeyThenReleaseLeavesNoEntry(t *testing.T) {
	fake := newFakeSyscalls()
	s := fake.seam()

	entry, err := AddVolumeKey(s, "CRYPT-LUKS2-deadbeef-held", []byte("a volume key"))
	if err != nil {
		t.Fatalf("AddVolumeKey: %v", err)
	}
	if _, err := s.Search(entry.Ring, KeyType, entry.Description); err != nil {
		t.Fatalf("the added entry does not resolve: %v", err)
	}
	if err := entry.Release(s); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := s.Search(entry.Ring, KeyType, entry.Description); err == nil {
		t.Fatal("the entry still resolves after Release")
	}
}

func TestAddVolumeKeyRefusesAPreExistingEntry(t *testing.T) {
	fake := newFakeSyscalls()
	s := fake.seam()

	first, err := AddVolumeKey(s, "CRYPT-LUKS2-deadbeef-occupied", []byte("key one"))
	if err != nil {
		t.Fatalf("AddVolumeKey: %v", err)
	}
	defer func() { _ = first.Release(s) }()

	if _, err := AddVolumeKey(s, "CRYPT-LUKS2-deadbeef-occupied", []byte("key two")); !errors.Is(err, ErrEntryExists) {
		t.Fatalf("AddVolumeKey over an existing entry = %v, want ErrEntryExists", err)
	}
}

func TestAddVolumeKeyClassifiesSessionRingFailures(t *testing.T) {
	fake := newFakeSyscalls()
	fake.sessionRingErr = unix.EPERM
	s := fake.seam()

	_, err := AddVolumeKey(s, "uuid", []byte("key"))
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("AddVolumeKey with a blocked session ring = %v, want ErrBlocked", err)
	}
	var unavailable *UnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("AddVolumeKey error is not an *UnavailableError: %v", err)
	}
}

func TestReleaseTreatsAnAlreadyGoneEntryAsReleased(t *testing.T) {
	fake := newFakeSyscalls()
	s := fake.seam()

	entry, err := AddVolumeKey(s, "uuid-twice", []byte("key"))
	if err != nil {
		t.Fatalf("AddVolumeKey: %v", err)
	}
	if err := entry.Release(s); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := entry.Release(s); err != nil {
		t.Fatalf("second Release on an already-gone entry = %v, want nil", err)
	}
}

func TestReleaseVerifiesRatherThanTrustsASuccessfulUnlink(t *testing.T) {
	fake := newFakeSyscalls()
	fake.stillThere = true
	s := fake.seam()

	entry, err := AddVolumeKey(s, "uuid-lying", []byte("key"))
	if err != nil {
		t.Fatalf("AddVolumeKey: %v", err)
	}
	if err := entry.Release(s); !errors.Is(err, ErrKeyNotReleased) {
		t.Fatalf("Release when the kernel reports success but the key still resolves = %v, want ErrKeyNotReleased", err)
	}
}

func TestReleaseReportsAnEntryItCannotRevoke(t *testing.T) {
	fake := newFakeSyscalls()
	fake.revokeErr = unix.EPERM
	fake.unlinkErr = unix.EPERM
	s := fake.seam()

	entry, err := AddVolumeKey(s, "uuid-stuck", []byte("key"))
	if err != nil {
		t.Fatalf("AddVolumeKey: %v", err)
	}
	if err := entry.Release(s); !errors.Is(err, ErrKeyNotReleased) {
		t.Fatalf("Release when revoke/unlink are refused = %v, want ErrKeyNotReleased", err)
	}
}

func TestAddVolumeKeySearchFailureIsClassified(t *testing.T) {
	fake := newFakeSyscalls()
	fake.searchErr = unix.EACCES
	s := fake.seam()

	_, err := AddVolumeKey(s, "uuid-unsearchable", []byte("key"))
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("AddVolumeKey when the collision search is refused = %v, want ErrBlocked", err)
	}
}

func TestVerifyGoneReportsAnUnsearchableRing(t *testing.T) {
	fake := newFakeSyscalls()
	s := fake.seam()

	entry, err := AddVolumeKey(s, "uuid-unverifiable", []byte("key"))
	if err != nil {
		t.Fatalf("AddVolumeKey: %v", err)
	}
	fake.searchErr = unix.EACCES

	if err := entry.verifyGone(s); err == nil {
		t.Fatal("verifyGone = nil when the ring cannot be searched, want an error")
	}
}

func TestTrimTrailingPeriod(t *testing.T) {
	if got := trimTrailingPeriod("no period here"); got != "no period here" {
		t.Errorf("trimTrailingPeriod without a trailing period = %q, want it unchanged", got)
	}
	if got := trimTrailingPeriod("with a period."); got != "with a period" {
		t.Errorf("trimTrailingPeriod = %q, want the trailing period stripped", got)
	}
	if got := trimTrailingPeriod(""); got != "" {
		t.Errorf("trimTrailingPeriod(\"\") = %q, want \"\"", got)
	}
}

func TestTableKeyIDDeclaresTheKeySizeInBytes(t *testing.T) {
	fake := newFakeSyscalls()
	s := fake.seam()

	key := make([]byte, 64)
	entry, err := AddVolumeKey(s, "uuid-sized", key)
	if err != nil {
		t.Fatalf("AddVolumeKey: %v", err)
	}
	defer func() { _ = entry.Release(s) }()

	want := fmt.Sprintf(":%d:%s:%s", len(key), KeyType, entry.Description)
	if got := entry.TableKeyID(); got != want {
		t.Fatalf("TableKeyID = %q, want %q", got, want)
	}
}

func TestDescriptionIsDeterministicAndHexEncoded(t *testing.T) {
	a := Description("CRYPT-LUKS2-aaa-vol-a")
	b := Description("CRYPT-LUKS2-bbb-vol-b")
	if a == b {
		t.Fatal("Description produced the same digest for two different UUIDs")
	}
	if a != Description("CRYPT-LUKS2-aaa-vol-a") {
		t.Fatal("Description is not deterministic")
	}
	if !hasPrefix(a, DescriptionPrefix+":") {
		t.Fatalf("Description %q does not carry the required subsystem prefix", a)
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestIgnoreAbsent(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool // true if IgnoreAbsent should return nil
	}{
		{"nil", nil, true},
		{"ENOKEY", unix.ENOKEY, true},
		{"ENOENT", unix.ENOENT, true},
		{"EKEYREVOKED", unix.EKEYREVOKED, true},
		{"EPERM", unix.EPERM, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IgnoreAbsent(tc.err)
			if tc.want && got != nil {
				t.Errorf("IgnoreAbsent(%v) = %v, want nil", tc.err, got)
			}
			if !tc.want && got == nil {
				t.Errorf("IgnoreAbsent(%v) = nil, want the error unchanged", tc.err)
			}
		})
	}
}

func TestClassifyAndRemedy(t *testing.T) {
	cases := []struct {
		err  error
		want error
	}{
		{unix.EPERM, ErrBlocked},
		{unix.EACCES, ErrBlocked},
		{unix.ENOSYS, ErrUnsupported},
		{unix.EDQUOT, ErrQuotaExhausted},
		{unix.EKEYREJECTED, ErrQuotaExhausted},
		{errors.New("mystery"), ErrFailed},
	}
	for _, tc := range cases {
		got := Classify(tc.err)
		if got != tc.want {
			t.Errorf("Classify(%v) = %v, want %v", tc.err, got, tc.want)
		}
		if Remedy(got) == "" {
			t.Errorf("Remedy(%v) returned an empty string", got)
		}
	}
}

func TestKeyringSentinelsFormOneFamily(t *testing.T) {
	for _, s := range []error{ErrUnavailable, ErrBlocked, ErrUnsupported, ErrQuotaExhausted, ErrFailed, ErrEntryExists, ErrKeyNotReleased} {
		if !errors.Is(s, ErrKeyring) {
			t.Errorf("%v does not match the ErrKeyring root", s)
		}
	}

	unavailable := &UnavailableError{Op: "add", Kind: ErrBlocked, Err: unix.EPERM}
	if !errors.Is(unavailable, ErrKeyring) {
		t.Error("*UnavailableError does not match ErrKeyring")
	}
	if !errors.Is(unavailable, ErrUnavailable) {
		t.Error("*UnavailableError does not match ErrUnavailable")
	}
	if !errors.Is(unavailable, ErrBlocked) {
		t.Error("*UnavailableError does not match its own Kind")
	}
	if !errors.Is(unavailable, unix.EPERM) {
		t.Error("*UnavailableError does not unwrap to its errno")
	}

	zero := &UnavailableError{}
	if !errors.Is(zero, ErrFailed) {
		t.Error("a zero-Kind *UnavailableError does not default to ErrFailed")
	}
	if zero.Error() == "" {
		t.Error("UnavailableError.Error() returned an empty string")
	}
}

func TestPinOSThreadReturnsAnUnlockFunc(t *testing.T) {
	unlock := PinOSThread()
	unlock()
}

func TestRunOnDiscardedThreadCarriesErrorsAndPanics(t *testing.T) {
	sentinel := errors.New("from the discarded thread")
	if err := RunOnDiscardedThread(func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("RunOnDiscardedThread = %v, want the function's error", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("the panic was swallowed")
		}
	}()
	_ = RunOnDiscardedThread(func() error { panic("boom") })
	t.Fatal("unreachable")
}
