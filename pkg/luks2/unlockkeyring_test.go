// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"
)

// What Unlock hands to device-mapper (#78).
//
// The transactional tests next door assert that the mapping is unwound
// correctly. These assert something different and narrower: that the VOLUME KEY
// is not in the table at all.
//
// The distinction is the point of the change. devmapper.go's buildSpec is
//
//	key := c.KeyID
//	if key == "" {
//		key = hex.EncodeToString(c.Key)
//	}
//
// so a table carrying Key produces two immutable Go strings holding the key in
// hex plus an uncleared ioctl buffer, none of which this library can wipe or
// reach into. A table carrying only KeyID produces none of them. Both tables
// activate the same volume, so no round-trip test can tell them apart -- the
// difference is only visible by looking at what was handed over, which is what
// these tests do.

// masterKeyOf recovers the volume key of a container the tests just wrote, so
// the assertions below can look for it rather than assume its absence.
func masterKeyOf(t *testing.T, device string, passphrase []byte) []byte {
	t.Helper()

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("reading the header failed: %v", err)
	}
	secret, err := getMasterKey(device, passphrase, metadata)
	if err != nil {
		t.Fatalf("recovering the master key failed: %v", err)
	}
	defer mustDestroy(t, secret)

	var key []byte
	if err := secret.WithBytes(func(b []byte) error {
		key = append([]byte(nil), b...)
		return nil
	}); err != nil {
		t.Fatalf("borrowing the master key failed: %v", err)
	}
	return key
}

// descriptionOf pulls the key description back out of a dm-crypt reference
// (":<size>:<type>:<description>").
func descriptionOf(reference string) string {
	parts := strings.SplitN(reference, ":", 4)
	if len(parts) != 4 {
		return ""
	}
	return parts[3]
}

// keyringStillHolds reports whether the entry named by a dm-crypt reference is
// still resolvable in the session keyring.
func keyringStillHolds(t *testing.T, reference string) bool {
	t.Helper()
	defer pinToOSThread()()

	_, err := keyring.search(testRing(t), keyringKeyType, descriptionOf(reference))
	return err == nil
}

// TestUnlockPassesTheVolumeKeyByKeyringReferenceAndNotInTheTable is the
// regression test for #78.
//
// Against the pre-fix code it fails on the first assertion: the table carried
// Key and no KeyID, which is exactly the state that makes devmapper.go build
// the hex strings.
func TestUnlockPassesTheVolumeKeyByKeyringReferenceAndNotInTheTable(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	masterKey := masterKeyOf(t, device, passphrase)

	fake := newFakeDeviceMapper()
	fake.install(t)

	if err := Unlock(device, passphrase, "by-reference"); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	table := fake.cryptTable(t)

	// The whole change: Key must be empty, because a non-empty Key is what
	// devmapper hex-encodes.
	if len(table.Key) != 0 {
		t.Fatalf("the volume key was placed in the device-mapper table (%d bytes); devmapper will hex-encode it into unwipeable strings", len(table.Key))
	}
	if table.KeyID == "" {
		t.Fatal("the table carries no kernel-keyring reference, so device-mapper has no way to get the key at all")
	}

	// And the negative that gives the change its meaning: nothing anywhere in
	// the table is the key, in either encoding.
	encoded := hex.EncodeToString(masterKey)
	for field, value := range map[string]string{
		"KeyID":         table.KeyID,
		"Encryption":    table.Encryption,
		"BackendDevice": table.BackendDevice,
		"Flags":         strings.Join(table.Flags, " "),
	} {
		if strings.Contains(value, encoded) {
			t.Errorf("table field %s contains the hex-encoded volume key", field)
		}
		if strings.Contains(value, string(masterKey)) {
			t.Errorf("table field %s contains the raw volume key", field)
		}
	}

	// The reference names a logon key of the right size, described by the
	// digest of this volume's own identity.
	hdr, _, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("reading the header failed: %v", err)
	}
	uuid := "CRYPT-LUKS2-" + strings.ReplaceAll(string(TrimRight(hdr.UUID[:], "\x00")), "-", "") + "-by-reference"
	want := ":" + strconv.Itoa(len(masterKey)) + ":logon:" + keyringDescription(uuid)
	if table.KeyID != want {
		t.Errorf("the reference is %q, want %q", table.KeyID, want)
	}

	// THE ARGV BOUNDARY. devmapper joins the target specification with
	// strings.Join(args, " "), so the reference is one space-delimited token in
	// a positional grammar the kernel parses. The header UUID it is derived
	// from is 40 bytes read off the device whose charset nothing constrains,
	// and the mapping name is the caller's. Hashing closes that by
	// construction; this asserts the closure rather than the intent.
	if strings.ContainsAny(table.KeyID, " \t\n\r\x00") {
		t.Fatalf("the reference contains a byte that would split the dm target specification: %q", table.KeyID)
	}
	if !regexp.MustCompile(`^:\d+:logon:` + keyringDescriptionPrefix + `:[0-9a-f]{64}$`).MatchString(table.KeyID) {
		t.Fatalf("the reference is not the closed-alphabet form: %q", table.KeyID)
	}
}

// TestTheKeyringEntryIsLiveExactlyDuringActivation is the lifetime assertion,
// and it has to be made from inside the activation call because that is the
// only moment the entry is supposed to exist.
//
// Both halves matter. If the key were not resolvable during CreateAndLoad the
// real kernel would refuse the table load with ENOKEY -- the reference would be
// a dangling name. If it were still resolvable afterwards, the change would
// have moved the volume key from an unwipeable userspace string into a kernel
// keyring that outlives its mapping, which is a leak in a new place rather than
// a fix.
func TestTheKeyringEntryIsLiveExactlyDuringActivation(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	var reference string
	var resolvedDuring error
	fake.onCreate = func(_, _ string, tables []devmapper.Table) {
		table := tables[0].(devmapper.CryptTable)
		reference = table.KeyID
		// The goroutine is pinned by unlockLoadTable for exactly this window,
		// so a search here runs against the same task credentials -- and
		// therefore the same ring -- that dm-crypt's request_key would use.
		ring, ringErr := keyring.sessionRing()
		if ringErr != nil {
			resolvedDuring = ringErr
			return
		}
		_, resolvedDuring = keyring.search(ring, keyringKeyType, descriptionOf(reference))
	}
	fake.install(t)

	if err := Unlock(device, passphrase, "lifetime"); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	if reference == "" {
		t.Fatal("no keyring reference was ever put in the table")
	}
	if resolvedDuring != nil {
		t.Fatalf("the kernel could not resolve the reference at the moment device-mapper would need it: %v", resolvedDuring)
	}
	if keyringStillHolds(t, reference) {
		t.Fatal("the volume key is still in the kernel keyring after Unlock returned; the entry outlived its activation")
	}
}

// TestUnlockReleasesTheKeyringEntryWhenTheActivationFails is the same lifetime
// claim on the path where it is easiest to get wrong: the entry has to go even
// though the call it was made for did not succeed.
func TestUnlockReleasesTheKeyringEntryWhenTheActivationFails(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.createErr = errors.New("device-mapper table load failed")
	var reference string
	fake.onCreate = func(_, _ string, tables []devmapper.Table) {
		reference = tables[0].(devmapper.CryptTable).KeyID
	}
	fake.install(t)

	if err := Unlock(device, passphrase, "failed-load"); err == nil {
		t.Fatal("Unlock reported success even though the table load failed")
	}

	if reference == "" {
		t.Fatal("no keyring reference was ever put in the table")
	}
	if keyringStillHolds(t, reference) {
		t.Fatal("a failed activation left the volume key in the kernel keyring")
	}
}

// TestUnlockFailsClosedWhenTheKeyringIsUnavailable pins the owner's ruling
// (2026-08-31): fail closed, no fallback to the in-table key.
//
// Refusing means device-mapper is never reached at all -- a caller that got
// ErrKeyringUnavailable must be able to conclude that no plaintext mapping was
// created and no key was ever handed over -- and the error has to carry the
// remedy, because the operator meeting it is reading a log line rather than
// this source.
func TestUnlockFailsClosedWhenTheKeyringIsUnavailable(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.install(t)
	(&fakeKeyring{addErr: unix.EPERM}).install(t)

	err := Unlock(device, passphrase, "no-keyring")
	if err == nil {
		t.Fatal("Unlock succeeded with the kernel keyring unavailable; the key must have gone into the table")
	}
	if !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("the refusal is not matchable as ErrKeyringUnavailable: %v", err)
	}
	if !errors.Is(err, ErrKeyringBlocked) {
		t.Fatalf("the refusal does not name the cause an operator has to act on: %v", err)
	}
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("the underlying errno was lost: %v", err)
	}
	for _, phrase := range []string{"seccomp", "add_key", "keyctl", "request_key"} {
		if !strings.Contains(err.Error(), phrase) {
			t.Errorf("the refusal never mentions %q, so a profile cannot be written from it: %v", phrase, err)
		}
	}
	if len(fake.loaded) != 0 {
		t.Fatalf("a table was handed to device-mapper anyway: %+v", fake.loaded)
	}
	if live := fake.live(); len(live) != 0 {
		t.Fatalf("a refused unlock left device-mapper targets live: %v", live)
	}
}

// TestUnlockHasNoInTableFallbackAtAll is the structural form of the owner's
// ruling, and it is deliberately not a behavioral test.
//
// Every other test here can only observe the paths it drives. A fallback that
// existed but happened to be disabled would still be one mistaken condition
// away from putting the volume key in the device-mapper table, and no
// behavioral test would notice until that condition was met in production. So
// this one reads the module's own source: nothing we ship may write
// devmapper.CryptTable.Key, anywhere, on any path.
//
// It is here rather than in a comment because the comment version of this --
// "Key is deliberately not set, here or anywhere else" -- is exactly the kind
// of warning that a check can enforce instead.
func TestUnlockHasNoInTableFallbackAtAll(t *testing.T) {
	defer parallel(t)()

	if assignments := cryptTableKeyAssignments(t); len(assignments) != 0 {
		t.Fatalf("this module writes a device-mapper table Key field, so the in-table volume key is still reachable:\n\t%s",
			strings.Join(assignments, "\n\t"))
	}
}

// cryptTableKeyAssignments walks the WHOLE MODULE's non-test Go sources and
// returns every place that could write a Key field on a device-mapper table.
//
// # Scope
//
// The module, not this package. pkg/luks2 is where the table is built today,
// but the claim being enforced is "nothing we ship puts the volume key in a dm
// table", and a helper added under cmd/ or test/ would satisfy a
// package-scoped scan while breaking the claim. Vendor and build directories
// are skipped; _test.go files are skipped because a test is allowed to
// construct a table with a key in order to assert something about it.
//
// # What counts as a write
//
// Three shapes, because between them they are the only ways the field can be
// set:
//
//   - a devmapper.CryptTable literal with a keyed Key element;
//   - a devmapper.CryptTable literal written POSITIONALLY. Those elements are
//     not KeyValueExprs, so a keyed-only scan skips them entirely and would
//     report a clean result for a literal that sets every field including Key.
//     go vet's composites check would object to one today, which is why this
//     is not a live hole -- but a guard that depends on a different tool to
//     cover its blind spot is not the thing making the claim true. Positional
//     literals are reported outright rather than analyzed.
//   - an assignment to a .Key selector in a file that imports devmapper. The
//     import restriction is what keeps this from tripping over unrelated Key
//     fields elsewhere -- RecoveryKey has one.
func cryptTableKeyAssignments(t *testing.T) []string {
	t.Helper()

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("could not resolve the module root: %v", err)
	}

	fset := token.NewFileSet()
	literals := 0
	var found []string

	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor", "build", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return fmt.Errorf("parsing %s: %w", path, parseErr)
		}
		local := devmapperImportName(file)

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				if !isCryptTableLiteral(node, local) {
					return true
				}
				literals++
				for _, elt := range node.Elts {
					kv, keyed := elt.(*ast.KeyValueExpr)
					if !keyed {
						found = append(found, fmt.Sprintf("%s: CryptTable written positionally, so every field including Key is set",
							fset.Position(elt.Pos())))
						continue
					}
					if key, isIdent := kv.Key.(*ast.Ident); isIdent && key.Name == "Key" {
						found = append(found, fmt.Sprintf("%s: CryptTable literal sets Key", fset.Position(kv.Pos())))
					}
				}
			case *ast.AssignStmt:
				if local == "" {
					return true // this file cannot be talking about a dm table
				}
				for _, lhs := range node.Lhs {
					if sel, isSel := lhs.(*ast.SelectorExpr); isSel && sel.Sel.Name == "Key" {
						found = append(found, fmt.Sprintf("%s: assignment to a .Key field", fset.Position(sel.Pos())))
					}
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("could not scan the module source: %v", walkErr)
	}

	// A guard on the guard: if the scan finds no CryptTable literal at all,
	// something has moved and this test is no longer looking at anything.
	if literals == 0 {
		t.Fatal("the source scan found no devmapper.CryptTable literal; this check is no longer looking at the dm-crypt table")
	}
	return found
}

// isCryptTableLiteral reports whether a composite literal is a
// devmapper.CryptTable built under the local import name of that package.
func isCryptTableLiteral(node *ast.CompositeLit, local string) bool {
	if local == "" {
		return false
	}
	sel, isSel := node.Type.(*ast.SelectorExpr)
	if !isSel || sel.Sel.Name != "CryptTable" {
		return false
	}
	ident, isIdent := sel.X.(*ast.Ident)
	return isIdent && ident.Name == local
}

// devmapperImportName returns the local name a file imports devmapper.go
// under, or "" if it does not import it. The package's name (devmapper) and its
// path (…/devmapper.go) differ, so the import spec is what has to be read.
func devmapperImportName(file *ast.File) string {
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != "github.com/anatol/devmapper.go" {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name
		}
		return "devmapper"
	}
	return ""
}

// TestAHostileHeaderUUIDCannotSplitTheTargetSpecification is the half of the
// argv boundary that no input validation can reach.
//
// The dm UUID is built from the LUKS2 header's 40-byte uuid field, read
// straight off the device. readHeaderCopy validates the magic, the version, the
// offsets, the checksum and the JSON -- but not the CHARSET, and a hostile
// header author controls the checksum too, so those bytes are fully
// attacker-controlled. They then become part of the keyring description and
// therefore part of CryptTable.KeyID, which devmapper joins into a
// space-delimited positional target specification.
//
// ValidateMappingName cannot help here: the name is fine, the header is not.
// The digest is what closes it, and this drives the real load path with a UUID
// no header reader would have rejected to prove the closure end to end.
func TestAHostileHeaderUUIDCannotSplitTheTargetSpecification(t *testing.T) {
	// Built through the validator rather than as a literal, so this test drives
	// the same construction path Unlock does (#40).
	params, err := cryptTableParams("0", &Segment{
		Type:       "crypt",
		Offset:     "0",
		Size:       "dynamic",
		IVTweak:    "0",
		Encryption: "aes-xts-plain64",
		SectorSize: 512,
	})
	if err != nil {
		t.Fatalf("the fixture segment does not validate: %v", err)
	}

	for _, hostile := range []string{
		"CRYPT-LUKS2-aaaa 0 crypt aes-xts-plain64 0000-victim",
		"CRYPT-LUKS2-aa\nbb-victim",
		"CRYPT-LUKS2-aa\tbb-victim",
		"CRYPT-LUKS2-aa\x00bb-victim",
	} {
		t.Run(strconv.Quote(hostile), func(t *testing.T) {
			fake := newFakeDeviceMapper()
			fake.install(t)

			key, err := randomSecret("hostile uuid test", 64)
			if err != nil {
				t.Fatalf("could not obtain protected memory: %v", err)
			}
			defer mustDestroy(t, key)

			if err := unlockLoadTable("victim", hostile, "/dev/null", params, key, 4096, 0); err != nil {
				t.Fatalf("unlockLoadTable failed: %v", err)
			}

			reference := fake.cryptTable(t).KeyID
			if strings.ContainsAny(reference, " \t\n\r\x00") {
				t.Fatalf("a hostile header UUID reached the dm target specification intact: %q", reference)
			}
			if !regexp.MustCompile(`^:\d+:logon:` + keyringDescriptionPrefix + `:[0-9a-f]{64}$`).MatchString(reference) {
				t.Fatalf("the reference is not the closed-alphabet form: %q", reference)
			}
		})
	}
}

// TestUnlockRefusesAMappingNameItWillNotCreate covers the other half of the
// argv boundary.
//
// The keyring description is hashed, so a hostile name cannot reach the dm
// target specification through it. But the name is not only a keyring input:
// it becomes the /dev/mapper/<name> path this package creates, stats and
// unlinks, the fixed-width dm ioctl name field, and part of the dm UUID that
// the rollback uses to prove a target is its own. None of those want a
// caller's arbitrary bytes either, and Unlock validated the device path and
// the passphrase while never looking at the name.
//
// The refusal has to happen BEFORE anything exists: no keyring entry, no dm
// target.
func TestUnlockRefusesAMappingNameItWillNotCreate(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	for _, name := range []string{
		"",
		"has space",
		"has\ttab",
		"has\nnewline",
		"has\x00nul",
		"../escape",
		"/absolute",
		"-leading-dash",
		".",
		"..",
		strings.Repeat("a", MaxMappingNameLength+1),
	} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			fake := newFakeDeviceMapper()
			fake.install(t)

			err := Unlock(device, passphrase, name)
			if err == nil {
				t.Fatalf("Unlock accepted the mapping name %q", name)
			}
			if !errors.Is(err, ErrInvalidMappingName) {
				t.Fatalf("the refusal is not matchable as ErrInvalidMappingName: %v", err)
			}
			if len(fake.loaded) != 0 || len(fake.created) != 0 {
				t.Fatalf("device-mapper was reached with a name that should have been refused: %+v", fake.created)
			}
		})
	}
}

// TestUnlockAcceptsOrdinaryMappingNames is the control: the validator must not
// be so strict that the names real callers use stop working. go-blockstore and
// the CLI both use dashed and underscored names.
func TestUnlockAcceptsOrdinaryMappingNames(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	for _, name := range []string{"cryptroot", "vol-1", "vol_1", "vg0.lv0", "a", "0", "x+y"} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateMappingName(name); err != nil {
				t.Fatalf("ValidateMappingName(%q) refused an ordinary name: %v", name, err)
			}

			fake := newFakeDeviceMapper()
			fake.install(t)
			if err := Unlock(device, passphrase, name); err != nil {
				t.Fatalf("Unlock(%q) failed: %v", name, err)
			}
		})
	}
}

// TestUnlockRefusesWhenAKeyringEntryAlreadyExists is the guard against
// add_key's update-in-place behavior, driven all the way through Unlock.
//
// The entry could be a leftover from a process that crashed between activation
// and release, or one planted by another process of the same uid. Either way
// proceeding would attach a mapping to key material this call did not create,
// or overwrite material that belongs to something else, and both are silent.
func TestUnlockRefusesWhenAKeyringEntryAlreadyExists(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	// Work out the description this unlock will use, and occupy it first.
	hdr, _, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("reading the header failed: %v", err)
	}
	uuid := "CRYPT-LUKS2-" + strings.ReplaceAll(string(TrimRight(hdr.UUID[:], "\x00")), "-", "") + "-occupied"

	func() {
		defer pinToOSThread()()
		squatter, addErr := addVolumeKeyToKeyring(uuid, keyringTestKey)
		if addErr != nil {
			t.Fatalf("could not plant the pre-existing entry: %v", addErr)
		}
		t.Cleanup(func() {
			defer pinToOSThread()()
			_ = squatter.release()
		})
	}()

	fake := newFakeDeviceMapper()
	fake.install(t)

	err = Unlock(device, passphrase, "occupied")
	if err == nil {
		t.Fatal("Unlock proceeded over an existing keyring entry, silently overwriting or adopting it")
	}
	if !errors.Is(err, ErrKeyringEntryExists) {
		t.Fatalf("the refusal is not matchable as ErrKeyringEntryExists: %v", err)
	}
	if len(fake.loaded) != 0 {
		t.Fatalf("a table was handed to device-mapper anyway: %+v", fake.loaded)
	}
}

// TestUnlockReportsAKeyringEntryItCouldNotRelease is the counterpart of
// ErrMappingStillLive for key material.
//
// An entry that could not be confirmed gone means a volume key may still be
// sitting in the kernel keyring. Reporting that on an otherwise-successful
// unlock costs an operator a false alarm at worst; staying quiet costs them
// undestroyed key material they have no way to learn about.
func TestUnlockReportsAKeyringEntryItCouldNotRelease(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.install(t)
	stuck := &fakeKeyring{unlinkErr: unix.EACCES}
	stuck.install(t)

	err := Unlock(device, passphrase, "unreleased")
	if err == nil {
		t.Fatal("an unlock that left the volume key in the kernel keyring reported success")
	}
	if !errors.Is(err, ErrKeyringKeyNotReleased) {
		t.Fatalf("the failure is not matchable as ErrKeyringKeyNotReleased: %v", err)
	}

	// The caller was told the unlock failed, so no plaintext mapping may be
	// left behind either.
	if live := fake.live(); len(live) != 0 {
		t.Fatalf("the unlock failed but left live device-mapper targets: %v", live)
	}

	// And the entry really is still there: Unlock is not reporting a failure it
	// has already tidied up after. The in-memory keyring goes away with the
	// test, so there is nothing to clean.
	if stuck.linkedKeys(memorySessionRing) != 1 {
		t.Errorf("the unlock reported an unreleasable entry but the ring does not hold one")
	}
}
