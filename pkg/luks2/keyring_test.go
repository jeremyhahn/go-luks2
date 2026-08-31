// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Keyring behavior that belongs to THIS package.
//
// These run against the in-memory keyring in keyringfake_test.go, never against
// the kernel. The guards asserted here -- a pre-existing entry is refused, a
// release is verified rather than trusted, a description is derived from volume
// identity with a closed alphabet, a failure is classified with a remedy -- are
// behavior of this package's code, and the kernel was never what made them
// true.
//
// The KERNEL's own behavior is asserted in keyring_integration_test.go, which
// runs privileged. Everything that would be proved only by asking a real kernel
// -- that a logon payload cannot be read back, that the ring is a session
// keyring, that an unqualified description is refused, that add_key really does
// update in place -- lives there, because asserting it against a fake would
// only prove the fake agrees with itself.
//
// This file used to call the real syscalls. See keyringfake_test.go for why
// that failed in CI and what the split is.

// keyringTestKey is a stand-in volume key. Its length is deliberately 64 bytes,
// the aes-xts-plain64 default this library formats with, so the size in the
// dm-crypt reference is the one a real unlock would produce.
var keyringTestKey = []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

// testRunNonce makes every run of this suite use its own volume identities.
//
// The descriptions production derives are DELIBERATELY deterministic -- that is
// what makes the pre-add collision guard able to detect a stale entry -- and
// these tests add real keys under them. So a run that dies before its cleanup
// (a t.Fatal at the wrong moment, a SIGKILL, an interrupted `go test`) leaves
// entries in the session keyring, and the NEXT run in the same login session
// fails with ErrKeyringEntryExists on a volume it never touched. CI never sees
// it, because each job gets a fresh session; a workstation running the suite
// repeatedly does.
//
// The nonce is in the TEST's synthetic UUID, not in keyringDescription: within
// a run the mapping is still identity -> description, which is what
// TestKeyringRefusesAPreExistingEntry relies on.
var testRunNonce = func() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("no randomness for the keyring test suite: " + err.Error())
	}
	return hex.EncodeToString(b)
}()

// testDMUUID builds a dm UUID of the shape Unlock generates, which is what the
// key description is derived from.
func testDMUUID(name string) string {
	return "CRYPT-LUKS2-0123456789abcdef0123456789abcdef-" + name + "-" + testRunNonce
}

// testRing resolves the session keyring the code under test will use, through
// whatever seam is currently installed.
func testRing(t *testing.T) int {
	t.Helper()

	ring, err := keyring.sessionRing()
	if err != nil {
		t.Fatalf("could not resolve the session keyring: %v", err)
	}
	return ring
}

// TestKeyringHoldsTheVolumeKeyAndThenDoesNot walks the whole lifetime: the key
// is resolvable while the activation would need it, and gone the moment it is
// released.
func TestKeyringHoldsTheVolumeKeyAndThenDoesNot(t *testing.T) {
	defer pinToOSThread()()

	uuid := testDMUUID("held")
	entry, err := addVolumeKeyToKeyring(uuid, keyringTestKey)
	if err != nil {
		t.Fatalf("the volume key could not be placed in the kernel keyring: %v", err)
	}

	id, err := keyring.search(entry.ring, keyringKeyType, entry.description)
	if err != nil {
		t.Fatalf("the kernel could not resolve the reference dm-crypt would be given: %v", err)
	}
	if id != entry.id {
		t.Fatalf("the description resolves to key %d, not to the one that was added (%d)", id, entry.id)
	}

	if err := entry.release(); err != nil {
		t.Fatalf("release reported a failure: %v", err)
	}
	if _, err := keyring.search(entry.ring, keyringKeyType, entry.description); err == nil {
		t.Fatal("the volume key is still resolvable in the kernel keyring after release")
	}
}

// TestKeyringRefusesAPreExistingEntry is the guard against the silent failure
// add_key builds in.
//
// add_key UPDATES a key of the same type and description in place rather than
// failing. So a leftover from a crashed process, a concurrent unlock of the
// same volume, or an entry planted by another process of the same uid would be
// silently overwritten -- or worse, silently adopted. It has to be refused, and
// it has to be refused with an error a caller can recognize.
func TestKeyringRefusesAPreExistingEntry(t *testing.T) {
	defer pinToOSThread()()

	uuid := testDMUUID("occupied")
	first, err := addVolumeKeyToKeyring(uuid, keyringTestKey)
	if err != nil {
		t.Fatalf("the first add failed: %v", err)
	}
	defer func() { _ = first.release() }()

	second, err := addVolumeKeyToKeyring(uuid, keyringTestKey)
	if err == nil {
		_ = second.release()
		t.Fatal("a second add against an occupied description succeeded; it would have overwritten the first entry")
	}
	if !errors.Is(err, ErrKeyringEntryExists) {
		t.Fatalf("the collision is not matchable as ErrKeyringEntryExists: %v", err)
	}
	if !strings.Contains(err.Error(), "keyctl unlink") {
		t.Fatalf("the error does not tell an operator how to clear the stale entry: %v", err)
	}

	// The refusal must not have disturbed what was already there: the first
	// entry is still the one the description resolves to.
	id, err := keyring.search(first.ring, keyringKeyType, first.description)
	if err != nil {
		t.Fatalf("the refused add removed the existing entry: %v", err)
	}
	if id != first.id {
		t.Fatalf("the description now resolves to key %d, not the original %d", id, first.id)
	}
}

// TestKeyringDescriptionIsDerivedFromVolumeIdentity is what makes the guard
// above meaningful.
//
// A random nonce would make collisions impossible and the pre-add search
// vacuous -- a stale entry would never be detected because it could never be
// hit. The description is therefore deterministic and derived from the dm UUID,
// which carries the LUKS2 header UUID and the mapping name, so two different
// volumes cannot collide and the same volume always lands on the same name.
func TestKeyringDescriptionIsDerivedFromVolumeIdentity(t *testing.T) {
	a := keyringDescription(testDMUUID("vol-a"))
	b := keyringDescription(testDMUUID("vol-b"))

	if a != keyringDescription(testDMUUID("vol-a")) {
		t.Fatal("the description is not deterministic, so a stale entry could never be detected")
	}
	if a == b {
		t.Fatalf("two different volumes share the description %q", a)
	}
	if !strings.HasPrefix(a, keyringDescriptionPrefix+":") {
		t.Fatalf("description %q lacks the subsystem qualifier the kernel requires", a)
	}

	// CLOSED ALPHABET, not a charset check. The description becomes one
	// space-delimited token in the dm target specification, and it is derived
	// from a header UUID read off the device and a caller-supplied name. It is
	// hashed, so the output is 64 hex characters whatever went in -- there is
	// no separator that can appear and no escaping to forget.
	if !regexp.MustCompile(`^` + keyringDescriptionPrefix + `:[0-9a-f]{64}$`).MatchString(a) {
		t.Fatalf("description %q is not the closed-alphabet digest form", a)
	}
	if strings.Contains(a, testDMUUID("vol-a")) {
		t.Fatalf("description %q carries its input verbatim; the dm UUID reaches a parsed grammar", a)
	}

	// A hostile header UUID and a hostile mapping name must not be able to
	// reach the target specification, whatever they contain.
	for _, hostile := range []string{
		"CRYPT-LUKS2-aaaa- name with spaces",
		"CRYPT-LUKS2-aaaa-\nnewline",
		"CRYPT-LUKS2-\x00-nul",
		"CRYPT-LUKS2-aaaa-:colons:everywhere:",
	} {
		got := keyringDescription(hostile)
		if strings.ContainsAny(got[len(keyringDescriptionPrefix)+1:], " \t\n\r\x00:") {
			t.Fatalf("description %q built from %q can split the dm target specification", got, hostile)
		}
	}

	// That the KERNEL accepts this description, and refuses one without the
	// qualifier, is asserted in the integration suite -- it is a claim about
	// logon_vet_description, not about this function.
}

// TestTableKeyIDDeclaresTheKeySizeInBytes pins the reference format dm-crypt
// parses. The kernel checks the declared size against the keyring payload and
// refuses the table load with EINVAL if they disagree, so this is not cosmetic.
func TestTableKeyIDDeclaresTheKeySizeInBytes(t *testing.T) {
	defer pinToOSThread()()

	for _, size := range []int{32, 64} {
		key := make([]byte, size)
		entry, err := addVolumeKeyToKeyring(testDMUUID(fmt.Sprintf("sized-%d", size)), key)
		if err != nil {
			t.Fatalf("adding a %d-byte key failed: %v", size, err)
		}

		want := fmt.Sprintf(":%d:logon:%s", size, entry.description)
		if got := entry.tableKeyID(); got != want {
			t.Errorf("tableKeyID() = %q, want %q", got, want)
		}
		if err := entry.release(); err != nil {
			t.Errorf("release failed: %v", err)
		}
	}
}

// TestTableKeyIDNeverCarriesKeyMaterial is the negative form of the same
// assertion: the reference is a name, and a name derived from nothing secret.
func TestTableKeyIDNeverCarriesKeyMaterial(t *testing.T) {
	defer pinToOSThread()()

	entry, err := addVolumeKeyToKeyring(testDMUUID("named"), keyringTestKey)
	if err != nil {
		t.Fatalf("the volume key could not be placed in the kernel keyring: %v", err)
	}
	defer func() { _ = entry.release() }()

	reference := entry.tableKeyID()
	if strings.Contains(reference, hex.EncodeToString(keyringTestKey)) {
		t.Fatalf("the dm-crypt reference contains the hex-encoded volume key: %q", reference)
	}
	if strings.Contains(reference, string(keyringTestKey)) {
		t.Fatalf("the dm-crypt reference contains the raw volume key: %q", reference)
	}
}

// TestKeyringFailuresAreClassifiedWithARemedy covers the requirement that four
// different problems do not collapse into one useless message.
//
// A blocked syscall, a kernel without key support, an exhausted quota and a
// bare refusal need four different actions from an operator. Each must be
// matchable on its own sentinel, must still match the umbrella, must keep the
// errno reachable, and must carry guidance specific enough to act on.
func TestKeyringFailuresAreClassifiedWithARemedy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		errno    error
		want     error
		mustSay  []string
		mustNot  []string
		umbrella error
	}{
		{
			name:    "seccomp",
			errno:   unix.EPERM,
			want:    ErrKeyringBlocked,
			mustSay: []string{"seccomp", "add_key", "keyctl", "request_key", "SYS_ADMIN"},
			mustNot: []string{"CONFIG_KEYS"},
		},
		{
			name:    "no key support",
			errno:   unix.ENOSYS,
			want:    ErrKeyringUnsupported,
			mustSay: []string{"CONFIG_KEYS"},
			mustNot: []string{"seccomp"},
		},
		{
			name:    "quota",
			errno:   unix.EDQUOT,
			want:    ErrKeyringQuotaExhausted,
			mustSay: []string{"maxkeys", "keyctl show"},
			mustNot: []string{"seccomp"},
		},
		{
			name:    "anything else",
			errno:   unix.EIO,
			want:    ErrKeyringFailed,
			mustSay: []string{"reachable"},
			mustNot: []string{"seccomp", "CONFIG_KEYS"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeKeyring{addErr: tc.errno}
			fake.install(t)
			defer pinToOSThread()()

			_, err := addVolumeKeyToKeyring(testDMUUID("classified"), keyringTestKey)
			if err == nil {
				t.Fatal("a refused add_key was reported as success")
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("the failure does not match %v: %v", tc.want, err)
			}
			if !errors.Is(err, ErrKeyringUnavailable) {
				t.Errorf("the failure does not match the ErrKeyringUnavailable umbrella: %v", err)
			}
			if !errors.Is(err, tc.errno) {
				t.Errorf("the underlying errno was lost: %v", err)
			}
			for _, phrase := range tc.mustSay {
				if !strings.Contains(err.Error(), phrase) {
					t.Errorf("the guidance never mentions %q: %v", phrase, err)
				}
			}
			for _, phrase := range tc.mustNot {
				if strings.Contains(err.Error(), phrase) {
					t.Errorf("the guidance points at the wrong problem (%q): %v", phrase, err)
				}
			}
			if strings.Contains(err.Error(), string(keyringTestKey)) {
				t.Errorf("the error message carries key material: %v", err)
			}
		})
	}
}

// TestKeyringFailuresAreClassifiedAtEveryStep makes sure the classification is
// not attached only at the add.
//
// The measured container case fails at the FIRST keyring syscall, which is the
// ring resolution, not add_key -- so an operator whose seccomp profile blocks
// keyctl must get the seccomp guidance rather than a bare errno.
func TestKeyringFailuresAreClassifiedAtEveryStep(t *testing.T) {
	for _, tc := range []struct {
		name string
		fake *fakeKeyring
		step string
	}{
		{"resolving the ring", &fakeKeyring{ringErr: unix.EPERM}, "session keyring"},
		{"searching the ring", &fakeKeyring{searchErr: unix.EPERM}, "search"},
		{"adding the key", &fakeKeyring{addErr: unix.EPERM}, "add"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.fake.install(t)
			defer pinToOSThread()()

			_, err := addVolumeKeyToKeyring(testDMUUID("step"), keyringTestKey)
			if !errors.Is(err, ErrKeyringBlocked) {
				t.Fatalf("a blocked syscall at this step was not classified: %v", err)
			}
			if !strings.Contains(err.Error(), tc.step) {
				t.Errorf("the error does not name the step that failed (%q): %v", tc.step, err)
			}
		})
	}
}

// TestKeyringSentinelsFormOneFamily pins the relationships between the
// sentinels, because getting them wrong is silent in exactly the way that
// matters.
//
// An earlier version of errors.go claimed ErrKeyringUnavailable was the
// umbrella for every keyring refusal. It was not: the two ANOMALIES did not
// match it, so a caller using it as a catch-all would have missed
// ErrKeyringKeyNotReleased -- the one that says a volume master key may still
// be resident in the kernel. Nothing would have reported that; the errors.Is
// would simply have returned false.
//
// So the family is asserted rather than described: ErrKeyring matches
// everything, ErrKeyringUnavailable matches unavailability only, and the causes
// stay distinct from each other.
func TestKeyringSentinelsFormOneFamily(t *testing.T) {
	unavailability := []error{
		ErrKeyringBlocked, ErrKeyringUnsupported, ErrKeyringQuotaExhausted, ErrKeyringFailed,
	}
	anomalies := []error{ErrKeyringEntryExists, ErrKeyringKeyNotReleased}

	all := append(append([]error{ErrKeyringUnavailable}, unavailability...), anomalies...)
	for _, sentinel := range all {
		if !errors.Is(sentinel, ErrKeyring) {
			t.Errorf("%v does not match the ErrKeyring root, so a catch-all cannot see it", sentinel)
		}
	}

	for _, anomaly := range anomalies {
		if errors.Is(anomaly, ErrKeyringUnavailable) {
			t.Errorf("%v matches ErrKeyringUnavailable; the two are different conditions with different responses", anomaly)
		}
	}

	// A real unavailability error carries all three levels at once.
	err := keyringFailure("probe", unix.EPERM)
	for _, target := range []error{ErrKeyring, ErrKeyringUnavailable, ErrKeyringBlocked, unix.EPERM} {
		if !errors.Is(err, target) {
			t.Errorf("a blocked-syscall failure does not match %v: %v", target, err)
		}
	}
	for _, target := range []error{ErrKeyringUnsupported, ErrKeyringQuotaExhausted, ErrKeyringEntryExists, ErrKeyringKeyNotReleased} {
		if errors.Is(err, target) {
			t.Errorf("a blocked-syscall failure also matches %v, so the classification is not exclusive", target)
		}
	}

	// And so does a real release failure, through the other branch.
	stuck := &keyringVolumeKey{id: 1, ring: 2, description: "luks2:deadbeef"}
	(&fakeKeyring{revokeErr: unix.EPERM, unlinkErr: unix.EPERM, stillThere: true}).install(t)
	releaseErr := stuck.release()
	if !errors.Is(releaseErr, ErrKeyring) || !errors.Is(releaseErr, ErrKeyringKeyNotReleased) {
		t.Fatalf("a release failure is not reachable from the root: %v", releaseErr)
	}
	// It must also carry the remedy for the errno underneath it, because this
	// is the path that reports a possibly-resident master key.
	if !strings.Contains(releaseErr.Error(), "seccomp") {
		t.Errorf("the release failure carries a bare errno with no remedy: %v", releaseErr)
	}
}

// TestReleaseTreatsAnAlreadyGoneEntryAsReleased pins the conservative direction
// for the cleanup path.
//
// "The key is not there" is the outcome release wants, however it came about --
// a second release, or a kernel that reaped the entry first. Reporting it as a
// failure would raise a custody alarm on precisely the evidence that there is
// nothing left to worry about, and would fail otherwise-good unlocks.
func TestReleaseTreatsAnAlreadyGoneEntryAsReleased(t *testing.T) {
	defer pinToOSThread()()

	entry, err := addVolumeKeyToKeyring(testDMUUID("twice"), keyringTestKey)
	if err != nil {
		t.Fatalf("the volume key could not be placed in the kernel keyring: %v", err)
	}
	if err := entry.release(); err != nil {
		t.Fatalf("the first release failed: %v", err)
	}
	if err := entry.release(); err != nil {
		t.Fatalf("releasing an entry that was already gone was reported as a failure: %v", err)
	}
}

// TestReleaseVerifiesRatherThanTrusts is the guard the owner asked for: a
// release that returns success while the key is still there must not be
// believed.
//
// Every syscall here reports success; only the confirming search disagrees.
// Without the verification this case is indistinguishable from a clean release,
// and a volume master key stays in the kernel keyring with nobody told.
func TestReleaseVerifiesRatherThanTrusts(t *testing.T) {
	defer pinToOSThread()()

	entry, err := addVolumeKeyToKeyring(testDMUUID("lying-kernel"), keyringTestKey)
	if err != nil {
		t.Fatalf("the volume key could not be placed in the kernel keyring: %v", err)
	}

	// Release for real first, so the test does not leak, then make the search
	// claim the key is still resolvable.
	if err := entry.release(); err != nil {
		t.Fatalf("the real release failed: %v", err)
	}
	(&fakeKeyring{stillThere: true}).install(t)

	err = entry.release()
	if err == nil {
		t.Fatal("release believed the syscalls instead of checking; a key still in the keyring was reported as gone")
	}
	if !errors.Is(err, ErrKeyringKeyNotReleased) {
		t.Fatalf("the failure does not match ErrKeyringKeyNotReleased: %v", err)
	}
	if !strings.Contains(err.Error(), "still resolvable") {
		t.Fatalf("the error does not say what was actually observed: %v", err)
	}
}

// TestReleaseReportsAnEntryItCouldNotRemove covers the failures of the removal
// itself, and the case where absence cannot be CONFIRMED.
//
// The last one matters as much as the others: a search that cannot answer means
// the state is unknown, and unknown must be reported as possibly-still-present.
// The cost of a false alarm is an operator running `keyctl show`; the cost of a
// false all-clear is a volume master key nobody knows is there.
//
// Each case breaks the keyring AFTER the entry has been added, so the add path
// itself is the working one and only the release is under test.
func TestReleaseReportsAnEntryItCouldNotRemove(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(*fakeKeyring)
	}{
		{"revoke fails", func(f *fakeKeyring) { f.revokeErr = unix.EACCES }},
		{"unlink fails", func(f *fakeKeyring) { f.unlinkErr = unix.EACCES }},
		{"absence cannot be confirmed", func(f *fakeKeyring) { f.searchErr = unix.EACCES }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeKeyring{}
			fake.install(t)

			entry, err := addVolumeKeyToKeyring(testDMUUID("stuck"), keyringTestKey)
			if err != nil {
				t.Fatalf("the volume key could not be placed in the keyring: %v", err)
			}

			tc.break_(fake)

			err = entry.release()
			if err == nil {
				t.Fatal("a release that did not take was reported as success")
			}
			if !errors.Is(err, ErrKeyringKeyNotReleased) {
				t.Fatalf("the failure does not match ErrKeyringKeyNotReleased: %v", err)
			}
			if !strings.Contains(err.Error(), entry.description) {
				t.Fatalf("the error does not say which entry is still there: %v", err)
			}
			if !strings.Contains(err.Error(), "keyctl unlink") {
				t.Fatalf("the error does not tell an operator how to clear it: %v", err)
			}
		})
	}
}

// TestCheckKeyringAvailableLeavesNothingBehind is the preflight's happy path.
//
// A startup check that leaked a probe key on every call would be its own
// defect, and on a long-lived process it would be one that grows. The count is
// taken from the keyring itself rather than from the preflight's own
// bookkeeping.
//
// That the preflight passes on a real kernel where activation works is asserted
// in the integration suite; here the claim is only that it cleans up.
func TestCheckKeyringAvailableLeavesNothingBehind(t *testing.T) {
	fake := &fakeKeyring{}
	fake.install(t)

	if err := CheckKeyringAvailable(); err != nil {
		t.Fatalf("the preflight failed against a working keyring: %v", err)
	}
	if n := fake.linkedKeys(memorySessionRing); n != 0 {
		t.Fatalf("the preflight left %d key(s) in the ring; it leaked its probe", n)
	}
	if len(fake.added) != 1 {
		t.Fatalf("the preflight added %d keys, want exactly one probe", len(fake.added))
	}
	if !strings.HasPrefix(fake.added[0], keyringDescriptionPrefix+":") {
		t.Fatalf("the probe description %q is not of the package's own form", fake.added[0])
	}
}

// TestCheckKeyringAvailableReportsTheSameTypedFailureAsUnlock is the point of
// the preflight: a daemon that calls it at startup must get exactly the
// diagnosis it would have got at the first unlock, so that moving the check
// earlier does not change the answer.
func TestCheckKeyringAvailableReportsTheSameTypedFailureAsUnlock(t *testing.T) {
	fake := &fakeKeyring{addErr: unix.EPERM}
	fake.install(t)

	err := CheckKeyringAvailable()
	if err == nil {
		t.Fatal("the preflight passed with the keyring syscalls blocked")
	}
	if !errors.Is(err, ErrKeyringBlocked) || !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("the preflight's failure is not the one Unlock would report: %v", err)
	}
	if !strings.Contains(err.Error(), "seccomp") {
		t.Fatalf("the preflight's failure carries no remedy: %v", err)
	}
}

// TestCheckKeyringAvailableCatchesABrokenReleasePath makes the preflight cover
// teardown as well as setup.
//
// A kernel or policy that permits add_key but refuses to revoke would leave a
// volume key in the keyring after every unlock. Catching it at startup is the
// difference between a refusal to boot and a slow accumulation of master keys.
func TestCheckKeyringAvailableCatchesABrokenReleasePath(t *testing.T) {
	fake := &fakeKeyring{revokeErr: unix.EACCES, unlinkErr: unix.EACCES}
	fake.install(t)

	err := CheckKeyringAvailable()
	if err == nil {
		t.Fatal("the preflight passed even though the probe key could not be released")
	}
	if !errors.Is(err, ErrKeyringKeyNotReleased) {
		t.Fatalf("the preflight did not report the release failure: %v", err)
	}

	// And the probe really is stuck: the preflight is not reporting a failure
	// it has already tidied up after. Nothing to clean here -- the fake goes
	// away with the test.
	if fake.linkedKeys(memorySessionRing) != 1 {
		t.Errorf("the preflight reported an unreleasable probe but the ring does not hold one")
	}
}
