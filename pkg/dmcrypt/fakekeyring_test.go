// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package dmcrypt

import (
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	keyringpkg "github.com/jeremyhahn/go-luks2/internal/keyring"
)

// The unit suite talks to an IN-MEMORY keyring and never to the kernel.
//
// Docker's default seccomp profile denies add_key, keyctl and request_key,
// so a CI runner cannot exercise the real syscalls at all (pkg/luks2's
// pre-split keyringfake_test.go found this the hard way). internal/keyring
// has its own suite proving the real syscall mechanics against its own
// fake; this one exists only so Activate, Deactivate's neighbors and
// CheckKeyring can be driven deterministically in this package's tests.

// memorySessionRing is the serial the fake reports for the session keyring.
const memorySessionRing = 0x5e5510

type memoryKey struct {
	keyType     string
	description string
	payload     []byte
	revoked     bool
}

// fakeKeyring is a complete in-memory kernel keyring, plus the ability to
// make any single operation fail the way a policy, a quota or a broken
// kernel would. The zero value is a working keyring.
type fakeKeyring struct {
	mu     sync.Mutex
	nextID int
	keys   map[int]*memoryKey
	links  map[int]map[int]bool // ring serial -> set of key serials

	ringErr   error
	addErr    error
	searchErr error
	revokeErr error
	unlinkErr error

	// stillThere makes search report a key as present however it was
	// released, to reach Release's "the syscalls said yes and it is still
	// there" branch.
	stillThere bool

	added   []string
	revoked []int
}

func (f *fakeKeyring) seam() keyringpkg.Syscalls {
	return keyringpkg.Syscalls{
		SessionRing: f.sessionRing,
		Add:         f.add,
		Search:      f.search,
		Revoke:      f.revoke,
		Unlink:      f.unlink,
	}
}

func (f *fakeKeyring) install(t *testing.T) {
	t.Helper()

	previous := sys.keyring
	t.Cleanup(func() { sys.keyring = previous })
	sys.keyring = f.seam()
}

func (f *fakeKeyring) init() {
	if f.keys == nil {
		f.keys = map[int]*memoryKey{}
		f.links = map[int]map[int]bool{}
		f.nextID = 1000
	}
}

func (f *fakeKeyring) sessionRing() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.ringErr != nil {
		return 0, f.ringErr
	}
	f.init()
	return memorySessionRing, nil
}

func (f *fakeKeyring) add(keyType, description string, payload []byte, ring int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.addErr != nil {
		return 0, f.addErr
	}
	f.init()

	if keyType == keyringpkg.KeyType && !validLogonDescription(description) {
		return 0, unix.EINVAL
	}
	if len(payload) == 0 {
		return 0, unix.EINVAL
	}

	f.added = append(f.added, description)

	if id, found := f.lookupLocked(ring, keyType, description); found {
		// The kernel updates rather than refusing, and keeps the serial.
		f.keys[id].payload = append([]byte(nil), payload...)
		f.keys[id].revoked = false
		return id, nil
	}

	f.nextID++
	id := f.nextID
	f.keys[id] = &memoryKey{
		keyType:     keyType,
		description: description,
		payload:     append([]byte(nil), payload...),
	}
	if f.links[ring] == nil {
		f.links[ring] = map[int]bool{}
	}
	f.links[ring][id] = true
	return id, nil
}

func (f *fakeKeyring) search(ring int, keyType, description string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.searchErr != nil {
		return 0, f.searchErr
	}
	if f.stillThere {
		return f.nextID, nil
	}
	f.init()

	if id, found := f.lookupLocked(ring, keyType, description); found {
		return id, nil
	}
	return 0, unix.ENOKEY
}

func (f *fakeKeyring) lookupLocked(ring int, keyType, description string) (int, bool) {
	for id := range f.links[ring] {
		key := f.keys[id]
		if key != nil && !key.revoked && key.keyType == keyType && key.description == description {
			return id, true
		}
	}
	return 0, false
}

func (f *fakeKeyring) revoke(id int) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.revoked = append(f.revoked, id)
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.init()

	key, exists := f.keys[id]
	if !exists {
		return unix.ENOKEY
	}
	if key.revoked {
		return unix.EKEYREVOKED
	}
	for i := range key.payload {
		key.payload[i] = 0
	}
	key.payload = nil
	key.revoked = true
	return nil
}

func (f *fakeKeyring) unlink(id, ring int) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.unlinkErr != nil {
		return f.unlinkErr
	}
	f.init()

	if !f.links[ring][id] {
		return unix.ENOENT
	}
	delete(f.links[ring], id)
	delete(f.keys, id)
	return nil
}

// linkedKeys reports how many keys a ring holds, so a test can assert that
// something left nothing behind.
func (f *fakeKeyring) linkedKeys(ring int) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.links[ring])
}

// validLogonDescription mirrors the kernel's logon_vet_description: a
// logon key description must carry a subsystem qualifier, which means a
// colon that is neither the first nor the last character.
func validLogonDescription(description string) bool {
	for i := 0; i < len(description); i++ {
		if description[i] == ':' {
			return i > 0 && i < len(description)-1
		}
	}
	return false
}

// TestMain installs the in-memory keyring for the whole unit suite, so no
// test can accidentally depend on the host's keyring policy.
func TestMain(m *testing.M) {
	sys.keyring = (&fakeKeyring{}).seam()
	os.Exit(m.Run())
}
