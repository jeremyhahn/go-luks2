// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// The unit suite talks to an IN-MEMORY keyring and never to the kernel.
//
// # Why, stated plainly, because the first version of this got it wrong
//
// These tests used to call the real add_key. That worked on the machine they
// were written on -- add_key is unprivileged for logon keys -- and failed in
// CI, because the CI runner is a container under Docker's DEFAULT SECCOMP
// PROFILE, which denies add_key, keyctl and request_key. This branch's own
// documentation says so. The suite asserted a property the runner would not let
// it observe, and because the seam delegated anything it had not been told to
// fake, the EPERM spread out of the keyring tests and into the unlock and
// rollback tests as well.
//
// So: no live syscalls here at all, not even for the operations a test is not
// interested in. `go test ./pkg/luks2` has to be deterministic on a
// workstation, in a default-seccomp container, and on a CI runner, and the only
// way to get that is for the package under test to reach nothing outside the
// process.
//
// # What stays here and what moved
//
// The guards are behavior of THIS package -- collision refusal, release
// verification, description derivation, error classification, fail-closed --
// and they are tested here, against the fake, because the kernel was never what
// made them true.
//
// The KERNEL's behavior is a different claim: that a logon payload cannot be
// read back, that the ring really is a session keyring, that an unqualified
// description is refused, that a revoked key stops resolving. Asserting those
// against a fake would only prove the fake agrees with itself. They live in
// keyring_integration_test.go, which runs privileged alongside the real
// device-mapper activation they pair with.
//
// # Fidelity
//
// The model reproduces the kernel behaviors this package depends on, and each
// one is load-bearing for some test:
//
//   - add_key UPDATES a key with the same type and description in place and
//     returns the same serial, rather than failing. This is the behavior the
//     pre-add collision guard exists to defeat, so a fake that returned an
//     error instead would make that guard look unnecessary.
//   - logon descriptions are vetted: a colon is required and may not be first.
//   - revoking makes a key stop resolving and clears its payload; revoking
//     twice reports EKEYREVOKED.
//   - unlinking a key that is not linked reports ENOENT, and searching for one
//     that is not there reports ENOKEY. release treats all of those as
//     "already gone", so getting them wrong would hide a real failure.

// memorySessionRing is the serial the fake reports for the session keyring. Its
// value is arbitrary; what matters is that every operation agrees on it, the
// way a real ring serial would.
const memorySessionRing = 0x5e5510

// memoryKey is one entry in the fake keyring.
type memoryKey struct {
	keyType     string
	description string
	payload     []byte
	revoked     bool
}

// fakeKeyring is a complete in-memory kernel keyring, plus the ability to make
// any single operation fail the way a policy, a quota or a broken kernel would.
//
// The zero value is a working keyring. Setting one of the *Err fields makes
// exactly that operation fail; everything else keeps working, so a test that
// wants one specific failure is not also silently changing the rest.
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

	// stillThere makes search report a key as present however it was released.
	// It is the only way to reach release's "the syscalls said yes and the key
	// is still there" branch, which is the branch that exists because a return
	// value is a claim rather than evidence.
	stillThere bool

	added   []string
	revoked []int
}

// seam returns the kernelKeyring this fake implements.
func (f *fakeKeyring) seam() kernelKeyring {
	return kernelKeyring{
		sessionRing: f.sessionRing,
		add:         f.add,
		search:      f.search,
		revoke:      f.revoke,
		unlink:      f.unlink,
	}
}

// install replaces the package's keyring for the duration of one test.
func (f *fakeKeyring) install(t *testing.T) {
	t.Helper()

	previous := keyring
	t.Cleanup(func() { keyring = previous })
	keyring = f.seam()
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

// add models add_key, including the update-in-place behavior that the pre-add
// collision guard exists because of.
func (f *fakeKeyring) add(keyType, description string, payload []byte, ring int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.addErr != nil {
		return 0, f.addErr
	}
	f.init()

	if keyType == keyringKeyType && !validLogonDescription(description) {
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

// lookupLocked finds a live key by type and description within a ring. A
// revoked key does not resolve, which is what the kernel's keyring search does.
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
	// A revoked logon key has its payload freed with kfree_sensitive, so the
	// bytes are gone at once rather than when the key is collected.
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

// validLogonDescription mirrors the kernel's logon_vet_description: a logon key
// description must carry a subsystem qualifier, which means a colon that is
// neither the first nor the last character.
func validLogonDescription(description string) bool {
	for i := 0; i < len(description); i++ {
		if description[i] == ':' {
			return i > 0 && i < len(description)-1
		}
	}
	return false
}

// TestMain installs the in-memory keyring for the WHOLE unit suite.
//
// It is not only the keyring tests that need it. Every test that calls Unlock
// goes through addVolumeKeyToKeyring, so the unlock and rollback suites reach
// the keyring too -- which is how a CI runner that denies add_key managed to
// fail tests that have nothing to do with #78. Installing the fake once, here,
// means no test can accidentally depend on the host's keyring policy.
//
// # WHICH TESTS RUN IN PARALLEL (#92)
//
// The suite was entirely sequential: the sum of its tests' times WAS its wall
// time -- 213s under -race on a loaded 8-core workstation, and the CI runner has
// 112 cores. The cost is real work in the code under test (a keyslot unlock is
// a 4000-stripe AF merge and an XTS pass, ~5x slower instrumented), so it
// cannot be trimmed away; it can be overlapped.
//
// A top-level test runs in parallel -- through `defer parallel(t)()`, which
// also keeps the concurrent tests inside the process's locked-memory limit
// (lockedmemorybudget_test.go) -- when it costs at least ~100ms and it, and
// everything it calls, writes NO package-level variable -- none of the seams
// (dm, keyring, cryptoRand, newUUID, digestIterationsFor, importToken, ...), no
// process-wide setting (Setenv, Chdir, umask), and it does not measure
// something process-wide (VmLck, MemStats) or time itself against a wall
// clock. Everything else stays sequential, and that is safe by construction:
// the testing package runs every sequential top-level test to completion
// before it releases the first parallel one, so a seam is never swapped while
// a parallel test is running. The race detector is the check on the rule, and
// every CI run is a -race run.
func TestMain(m *testing.M) {
	keyring = (&fakeKeyring{}).seam()
	os.Exit(m.Run())
}
