// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// These are the tests of the fleet pattern set itself. They spell no fleet
// value: TestFleet_PinsTheDigestTable pins the digests Fleet carries, and every
// other test scans with plantedFleet, a copy of Fleet in which each pattern
// also carries the digest, computed here, of one synthetic value its shape
// yields. A planted value then stands in for the fleet value in every sample.

// plant is one synthetic key per fleet pattern, in Fleet's order. None is a
// fleet value; each is what the pattern's shape yields as the key of a sample.
var plant = []string{
	"198.18.0",   // the fleet subnet's /24
	"4001",       // the forge's web and API port
	"4022",       // the forge's ssh port
	"rack",       // the agent workstations, rack-NN
	"blade",      // the CI runners, blade-NN
	"anvil",      // the GPU host
	"zenith",     // the build host
	"gate",       // the tunnel gateway, gate-NN
	"pod",        // the mini nodes, pod-NN
	"pilot",      // the coordinator hosts, pilot-<letter>
	plantedLogin, // the owner's home directory
	"labshare",   // the lab's NFS mount
	plantedLogin, // the owner's login
}

// plantedLogin is the synthetic owner login, and plantedHome its home
// directory.
const (
	plantedLogin = "jdoe"
	plantedHome  = "/home/" + plantedLogin
)

// plantedFleet returns Fleet with each pattern's planted digest appended.
func plantedFleet(t *testing.T) []Pattern {
	t.Helper()
	set := Fleet()
	if len(plant) != len(set) {
		t.Fatalf("plant has %d values for %d fleet patterns: add one per pattern", len(plant), len(set))
	}
	out := make([]Pattern, len(set))
	for i, p := range set {
		p.Digests = append(slices.Clone(p.Digests), Digest(plant[i]))
		out[i] = p
	}
	return out
}

// archiveLeaks reads a tar stream and returns every place a pattern of the
// given set matches. Nothing exempts a place: no waiver, no allow rule, no
// yield to a more specific class, so this is stricter than the gate.
//
// It reads every text field the tar reader surfaces, because each is published
// with the archive:
//   - the entry name;
//   - the link target of a symbolic or hard link, which git archive stores in
//     the header with no payload;
//   - the owner and group names;
//   - every PAX record, key and value, the global header git archive writes
//     (the commit id) included; extended attributes arrive here too;
//   - the payload, line by line.
//
// The numeric fields (mode, ids, sizes, times, device numbers) carry no text.
// An entry type other than a regular file, directory, link or PAX global
// header is an error: the check cannot vouch for what it does not read.
func archiveLeaks(archive io.Reader, set []Pattern) (files int, leaks []string, err error) {
	tr := tar.NewReader(archive)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, leaks, nil
		}
		if err != nil {
			return files, leaks, err
		}
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeDir, tar.TypeSymlink, tar.TypeLink:
			files++
		case tar.TypeXGlobalHeader:
		default:
			return files, leaks, fmt.Errorf("%s: unsupported tar entry type %q", hdr.Name, hdr.Typeflag)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			return files, leaks, err
		}
		fields := []struct{ where, text string }{
			{"path", hdr.Name},
			{"link target", hdr.Linkname},
			{"owner", hdr.Uname},
			{"group", hdr.Gname},
		}
		keys := make([]string, 0, len(hdr.PAXRecords))
		for key := range hdr.PAXRecords {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fields = append(fields,
				struct{ where, text string }{"pax key", key},
				struct{ where, text string }{"pax " + key, hdr.PAXRecords[key]})
		}
		var lines [][]byte
		if mayContainLabValue(set, content) {
			lines = bytes.Split(content, []byte("\n"))
		}
		for _, p := range set {
			for _, f := range fields {
				if len(p.find(f.text)) > 0 {
					leaks = append(leaks, fmt.Sprintf("%s (%s): %s", hdr.Name, f.where, p.Class))
				}
			}
			for i, line := range lines {
				if len(p.find(string(line))) > 0 {
					leaks = append(leaks, fmt.Sprintf("%s:%d: %s", hdr.Name, i+1, p.Class))
				}
			}
		}
	}
}

// TestTheArchiveCarriesNoFleetValue archives HEAD exactly as the public tree
// is produced and requires that no published file, the gate's own sources
// and tests included, names a value of the fleet pattern set.
// archiveFleetLeaks archives HEAD of the repository at root as a clean
// publishing checkout would (ArchiveHEAD) and scans the archive for fleet
// values.
func archiveFleetLeaks(root string, set []Pattern) (files int, leaks []string, err error) {
	out, err := ArchiveHEAD(root)
	if err != nil {
		return 0, nil, err
	}
	return archiveLeaks(bytes.NewReader(out), set)
}

func TestTheArchiveCarriesNoFleetValue(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("no go.mod above the working directory")
		}
		root = parent
	}
	files, leaks, err := archiveFleetLeaks(root, Fleet())
	if err != nil {
		t.Fatalf("reading the archive: %v", err)
	}
	if files == 0 {
		t.Fatal("the archive of HEAD holds no file; the check proves nothing")
	}
	for _, leak := range leaks {
		t.Errorf("the published archive names a fleet value: %s", leak)
	}
}

// committedGuide commits a document that names a fleet value under a waiver,
// with the given committed .gitattributes, into a repository of its own.
func committedGuide(t *testing.T, attributes string) string {
	t.Helper()
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"docs/guide.md":  "Measured on anvil. <!-- lab-string-ok: provenance -->\n",
		".gitattributes": attributes,
	})
	git(t, root, "", "init", "-q")
	git(t, root, "", "add", "-A")
	git(t, root, "", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
		"commit", "-q", "-m", "fixture")
	return root
}

// unsetenv removes key for the rest of the test and restores it afterwards.
func unsetenv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
}

// TestArchiveFleetLeaks_HonorsOnlyCommittedAttributes marks a committed
// document export-ignore in every place git reads attributes from except the
// committed .gitattributes. A clean publishing checkout of the commit has none
// of those rules and ships the document, so the check must still report it.
func TestArchiveFleetLeaks_HonorsOnlyCommittedAttributes(t *testing.T) {
	const rule = "docs/guide.md export-ignore\n"
	// attributesIn writes rule to a new file and returns its path.
	attributesIn := func(t *testing.T) string {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{"attributes": rule})
		return filepath.Join(dir, "attributes")
	}
	for name, hide := range map[string]func(t *testing.T, root string){
		"info/attributes": func(t *testing.T, root string) {
			writeFiles(t, filepath.Join(root, ".git", "info"), map[string]string{"attributes": rule})
		},
		"local core.attributesFile": func(t *testing.T, root string) {
			git(t, root, "", "config", "core.attributesFile", attributesIn(t))
		},
		"global core.attributesFile through HOME": func(t *testing.T, _ string) {
			home := t.TempDir()
			writeFiles(t, home, map[string]string{".gitconfig": "[core]\n\tattributesFile = " + attributesIn(t) + "\n"})
			unsetenv(t, "GIT_CONFIG_GLOBAL")
			t.Setenv("HOME", home)
		},
		"global core.attributesFile through GIT_CONFIG_GLOBAL": func(t *testing.T, _ string) {
			config := filepath.Join(t.TempDir(), "config")
			writeFiles(t, filepath.Dir(config), map[string]string{"config": "[core]\n\tattributesFile = " + attributesIn(t) + "\n"})
			t.Setenv("GIT_CONFIG_GLOBAL", config)
		},
		"system core.attributesFile through GIT_CONFIG_SYSTEM": func(t *testing.T, _ string) {
			config := filepath.Join(t.TempDir(), "config")
			writeFiles(t, filepath.Dir(config), map[string]string{"config": "[core]\n\tattributesFile = " + attributesIn(t) + "\n"})
			unsetenv(t, "GIT_CONFIG_NOSYSTEM")
			t.Setenv("GIT_CONFIG_SYSTEM", config)
		},
		"core.attributesFile through GIT_CONFIG_COUNT": func(t *testing.T, _ string) {
			t.Setenv("GIT_CONFIG_COUNT", "1")
			t.Setenv("GIT_CONFIG_KEY_0", "core.attributesFile")
			t.Setenv("GIT_CONFIG_VALUE_0", attributesIn(t))
		},
		"XDG attributes": func(t *testing.T, _ string) {
			// An empty global configuration, so no core.attributesFile
			// shadows the XDG file.
			home := t.TempDir()
			xdg := t.TempDir()
			writeFiles(t, xdg, map[string]string{"git/attributes": rule})
			unsetenv(t, "GIT_CONFIG_GLOBAL")
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", xdg)
		},
		"uncommitted .gitattributes": func(t *testing.T, root string) {
			writeFiles(t, root, map[string]string{".gitattributes": rule})
		},
		"staged .gitattributes": func(t *testing.T, root string) {
			writeFiles(t, root, map[string]string{".gitattributes": rule})
			git(t, root, "", "add", ".gitattributes")
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := committedGuide(t, "*.sh text eol=lf\n")
			hide(t, root)
			files, leaks, err := archiveFleetLeaks(root, plantedFleet(t))
			if err != nil {
				t.Fatalf("archiveFleetLeaks: %v", err)
			}
			if files == 0 {
				t.Fatal("the archive holds no file")
			}
			want := "docs/guide.md:1: " + string(ClassLabHost)
			if strings.Join(leaks, "\n") != want {
				t.Errorf("leaks = %q, want %q: an export-ignore rule outside the commit hid a published leak", leaks, want)
			}
		})
	}
}

// TestArchiveFleetLeaks_HonorsTheCommittedAttributes is the control: the
// committed .gitattributes does keep the document out of the archive.
func TestArchiveFleetLeaks_HonorsTheCommittedAttributes(t *testing.T) {
	root := committedGuide(t, "docs/guide.md export-ignore\n")
	files, leaks, err := archiveFleetLeaks(root, plantedFleet(t))
	if err != nil {
		t.Fatalf("archiveFleetLeaks: %v", err)
	}
	if files == 0 {
		t.Fatal("the archive holds no file")
	}
	if len(leaks) != 0 {
		t.Errorf("leaks = %q, want none: the committed .gitattributes export-ignores the document", leaks)
	}
}

// TestArchiveLeaks_FindsAFleetValueWhateverWaivesIt proves the archive check
// can fail: a value in a file's content or name is a leak, a waiver on its
// line notwithstanding.
func TestArchiveLeaks_FindsAFleetValueWhateverWaivesIt(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range map[string]string{
		"docs/guide.md":    "Measured on anvil. <!-- lab-string-ok: provenance -->\n",
		"logs/rack-04.log": "ordinary text\n",
		"clean.txt":        "dial 198.51.100.7:8443\n",
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	files, leaks, err := archiveLeaks(&buf, plantedFleet(t))
	if err != nil {
		t.Fatalf("archiveLeaks: %v", err)
	}
	if files != 3 {
		t.Errorf("files = %d, want 3", files)
	}
	sort.Strings(leaks)
	want := []string{"docs/guide.md:1: " + string(ClassLabHost), "logs/rack-04.log (path): " + string(ClassLabHost)}
	if strings.Join(leaks, "\n") != strings.Join(want, "\n") {
		t.Errorf("leaks = %q, want %q", leaks, want)
	}
}

// writeArchive writes the headers to a tar stream, each with its content when
// it has one.
func writeArchive(t *testing.T, entries []archiveEntry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := e.hdr
		hdr.Size = int64(len(e.content))
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

type archiveEntry struct {
	hdr     tar.Header
	content string
}

// TestArchiveLeaks_FindsAFleetValueInALinkTarget proves that an innocently
// named symbolic link publishes its target: git archive stores the target in
// the header's link name, with no payload, so the check must read it.
func TestArchiveLeaks_FindsAFleetValueInALinkTarget(t *testing.T) {
	buf := writeArchive(t, []archiveEntry{
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "clean.txt", Mode: 0o644}, content: "nothing here\n"},
		{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: "workspace", Linkname: plantedHome + "/go-luks2", Mode: 0o777}},
	})
	_, leaks, err := archiveLeaks(buf, plantedFleet(t))
	if err != nil {
		t.Fatalf("archiveLeaks: %v", err)
	}
	sort.Strings(leaks)
	want := []string{"workspace (link target): " + string(ClassOwnerAccount), "workspace (link target): " + string(ClassOwnerPath)}
	if strings.Join(leaks, "\n") != strings.Join(want, "\n") {
		t.Errorf("leaks = %q, want %q", leaks, want)
	}
}

// TestArchiveLeaks_FindsAFleetValueInEveryHeaderField covers the header's
// other text fields: a hard link's target, the owner and group names, and the
// PAX records, a per-entry record and the global header git archive writes.
func TestArchiveLeaks_FindsAFleetValueInEveryHeaderField(t *testing.T) {
	buf := writeArchive(t, []archiveEntry{
		{hdr: tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "built on anvil"}}},
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "a.txt", Mode: 0o644, Uname: "rack-04", Gname: "blade-07"}, content: "plain\n"},
		{hdr: tar.Header{Typeflag: tar.TypeLink, Name: "b.txt", Linkname: "pod-01.txt", Mode: 0o644}},
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "c.txt", Mode: 0o644, PAXRecords: map[string]string{
			"SCHILY.xattr.user.origin": "198.18.0.7",
			"SCHILY.xattr.user.zenith": "x",
		}}},
	})
	files, leaks, err := archiveLeaks(buf, plantedFleet(t))
	if err != nil {
		t.Fatalf("archiveLeaks: %v", err)
	}
	if files != 3 {
		t.Errorf("files = %d, want 3: the global header is not a file", files)
	}
	sort.Strings(leaks)
	want := []string{
		"a.txt (group): " + string(ClassLabHost),
		"a.txt (owner): " + string(ClassLabHost),
		"b.txt (link target): " + string(ClassLabHost),
		"c.txt (pax SCHILY.xattr.user.origin): " + string(ClassLabAddress),
		"c.txt (pax key): " + string(ClassLabHost),
		"pax_global_header (pax comment): " + string(ClassLabHost),
	}
	if strings.Join(leaks, "\n") != strings.Join(want, "\n") {
		t.Errorf("leaks = %q, want %q", leaks, want)
	}
}

// TestArchiveLeaks_FailsClosedOnAnEntryTypeItDoesNotRead proves that an entry
// the check has no reading for is an error, not a skip.
func TestArchiveLeaks_FailsClosedOnAnEntryTypeItDoesNotRead(t *testing.T) {
	for _, typ := range []byte{tar.TypeFifo, tar.TypeChar, tar.TypeBlock, 'Z'} {
		buf := writeArchive(t, []archiveEntry{
			{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "clean.txt", Mode: 0o644}, content: "plain\n"},
			{hdr: tar.Header{Typeflag: typ, Name: "odd", Mode: 0o644}},
		})
		if _, _, err := archiveLeaks(buf, Fleet()); err == nil {
			t.Errorf("type %q: archiveLeaks returned no error", typ)
		}
	}
}

func TestFleet_CoversEveryClass(t *testing.T) {
	seen := map[Class]bool{}
	for _, p := range Fleet() {
		seen[p.Class] = true
	}
	for _, c := range classes {
		if !seen[c] {
			t.Errorf("the fleet pattern set has no %s pattern", c)
		}
	}
}

func TestFleet_ReportsEveryClassWithItsLineAndMatch(t *testing.T) {
	cases := []struct {
		name      string
		content   string
		wantClass Class
		wantMatch string
		wantLine  int
	}{
		{"fleet address in help text", "package main\n\nconst help = \"dial 198.18.0.51:8443\"\n", ClassLabAddress, "198.18.0.51", 3},
		{"forge port in a URL", "forge: https://forge.example:4001/api/v1\n", ClassLabAddress, ":4001", 1},
		{"forge ssh port in a remote", "remote: ssh://git@forge.example:4022/x.git\n", ClassLabAddress, ":4022", 1},
		{"fleet hostname in a doc", "# Runbook\n\nRun it on ANVIL first.\n", ClassLabHost, "ANVIL", 3},
		{"runner hostname in a captured log", "2026-09-12T00:00:00Z blade-02(version:v3.1.0)\n", ClassLabHost, "blade-02", 1},
		{"fleet hostname quoted in a workflow comment", "jobs:\n# the fleet is idle: Zenith is at 21%\n", ClassLabHost, "Zenith", 2},
		{"fleet hostname as an internal endpoint", "cfg.BaseURL = \"http://zenith.internal:8077\"\n", ClassLabHost, "zenith.internal", 1},
		{"agent hostname in a comment", "// observed on rack-04\n", ClassLabHost, "rack-04", 1},
		{"tunnel gateway in prose", "The tunnel comes up on gate-01 before the runners.\n", ClassLabHost, "gate-01", 1},
		{"tunnel gateway in a URL, mixed case", "proxy: https://GATE-01:8443/v1\n", ClassLabHost, "GATE-01", 1},
		{"mini node in YAML", "runners:\n  - host: pod-05\n", ClassLabHost, "pod-05", 2},
		{"mini node in a URL, mixed case", "see http://Pod-02.internal:8077/status\n", ClassLabHost, "Pod-02", 1},
		{"coordinator host in prose", "# Notes\nThe coordinator runs on pilot-b.\n", ClassLabHost, "pilot-b", 2},
		{"coordinator host in YAML, mixed case", "coordinator: Pilot-b\n", ClassLabHost, "Pilot-b", 1},
		{"coordinator host in a URL", "forge: http://pilot-b:4001/api/v1\n", ClassLabHost, "pilot-b", 1},
		{"owner home path in a doc", "See " + plantedHome + "/sources for the checkout.\n", ClassOwnerPath, plantedHome, 1},
		{"owner account in an ssh command", "ssh jdoe@ci-runner-01 uptime\n", ClassOwnerAccount, "jdoe", 1},
		{"owner account as a mixed-case author, in YAML", "maintainers:\n  - JDoe\n", ClassOwnerAccount, "JDoe", 2},
		{"lab NFS mount in a script default", "QRDB=${QRDB:-/mnt/labshare/go-qrdb}\n", ClassOwnerPath, "/mnt/labshare", 1},
	}

	set := plantedFleet(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := entriesOf(map[string]string{"shipping/file.txt": tc.content})
			findings, err := Scan(files, set, nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			var got *Finding
			for i := range findings {
				if findings[i].Class == tc.wantClass {
					got = &findings[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("no %s finding; got %v", tc.wantClass, findings)
			}
			if got.Match != tc.wantMatch {
				t.Errorf("match = %q, want %q", got.Match, tc.wantMatch)
			}
			if got.Line != tc.wantLine {
				t.Errorf("line = %d, want %d", got.Line, tc.wantLine)
			}
			if got.Guidance == "" {
				t.Error("finding carries no guidance; the report would not say what to do")
			}
			if !strings.Contains(got.String(), "shipping/file.txt:"+strconv.Itoa(tc.wantLine)) {
				t.Errorf("String() is not file:line clickable: %s", got.String())
			}

			// The shape alone is not a finding: without the planted digest
			// the same line is clean.
			unplanted, err := Scan(files, Fleet(), nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(unplanted) != 0 {
				t.Errorf("the fleet set reports a synthetic value: %v", unplanted)
			}
		})
	}
}

func TestFleet_AcceptsWhatItShould(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"documentation addresses", "dial 198.51.100.7:8443 or 192.0.2.10 or 203.0.113.4\n"},
		{"addresses outside the fleet subnet", "peers: 198.18.1.10, 198.19.0.4, 10.0.0.1\n"},
		{"the repository's own example names", "--keyserver https://luks.example.com:8443 --runner ci-runner-01\n"},
		{"a port that merely starts like the forge's", "listen on :40011 and :40220\n"},
		{"a waiver on the offending line", "Measured on anvil. <!-- lab-string-ok: measurement provenance -->\n"},
		{"a hostname that merely contains a fleet name as a substring", "unanvillike is not a host, and rack-0 has no second digit\n"},
		{"a word that merely contains a fleet name", "megazenithlith and zeniths are words, not hosts\n"},
		{"words that merely start like a mini node", "a podcast, one pod-batch at a time, pod-2026 and pod-5\n"},
		{"words that merely start like a coordinator host", "the pilot-plane talks over the pilot-bus; pilot-b2 is not a host\n"},
		{"a key chord is not a coordinator host", "press Pilot-C to abort, Pilot-D at the prompt\n"},
		{"the forge owner in a module path and a repository URL", "import \"github.com/jeremyhahn/go-enclave\"\nsee https://github.com/jeremyhahn/go-luks2\n"},
		{"a word that merely contains the owner account", "xjdoe and jdoes and jdoe_x are not the account\n"},
		{"a tunnel gateway without a number", "the gate role, gate-a, gate-1 and gate-001 are not hosts\n"},
	}

	set := plantedFleet(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := Scan(entriesOf(map[string]string{"clean.txt": tc.content}), set, nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("expected no findings, got %v", findings)
			}
		})
	}
}

// TestFleet_PinsTheDigestTable pins the digests the fleet set carries, one per
// pattern in order, so a digest cannot be dropped or changed unnoticed. The
// values behind them are computed outside the tree and written nowhere in it.
func TestFleet_PinsTheDigestTable(t *testing.T) {
	want := []string{
		"c3da830da769bd8f45c7203550255793e1bc9f0e921beeccd41017e87cac0f66",
		"a20c25627ed7bbb6d2b999c589b698e6ecd84384e2e0e510d8869d79a5ad244c",
		"edee29f882543b956620b26d0ee0e7e950399b1c4222f5de05e06425b4c995e9",
		"d7509e2c30b4aa6e7950f93b176ce45cf749a1c5199db383648c2be7a6170a7b",
		"c9f72ed606186d2cab997a7e41e44bd66bb7d8117cb13d2928906884e0090062",
		"b2f896bb37f772a0dd0d4fdae6ec20020143f642ec30edd22c10a759f847bc9b",
		"304b4a90a76a1cbe4c112e074b30e75181f54df43d60f883597457844293b341",
		"471db7c8254c7b5fc929214cba734ac9f93f5198893686beb975c05f8e75e4d1",
		"43385991f0be5fed6db7fb640c5f510d41bcaac6ecca6c842a0c2a2d2d2bf510",
		"0fcd568a5cb9bdb4677b69354b11ee415af8f784519cff3da49a26f84eaee7f2",
		"6c47ecac10bc97a16b8ef358127f8630bf8cda0db7213a792ace464465f47419",
		"d7509e2c30b4aa6e7950f93b176ce45cf749a1c5199db383648c2be7a6170a7b",
		"6c47ecac10bc97a16b8ef358127f8630bf8cda0db7213a792ace464465f47419",
	}
	set := Fleet()
	if len(set) != len(want) {
		t.Fatalf("the fleet set has %d patterns, the pinned table %d", len(set), len(want))
	}
	hexDigest := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for i, p := range set {
		if len(p.Digests) != 1 || p.Digests[0] != want[i] {
			t.Errorf("pattern %d (%s) carries %q, want [%s]", i, p.Class, p.Digests, want[i])
		}
		for _, d := range p.Digests {
			if !hexDigest.MatchString(d) {
				t.Errorf("pattern %d (%s): %q is not a lower-case hex SHA-256 digest", i, p.Class, d)
			}
		}
	}
}

// TestFleet_EveryShapeYieldsItsPlantedKey proves the matching rule each
// pattern relies on: its shape yields the planted key from a sample, the
// digest of that key is what Digest computes whatever the key's case, and a
// pattern without that digest reports nothing.
func TestFleet_EveryShapeYieldsItsPlantedKey(t *testing.T) {
	samples := []string{
		"at 198.18.0.51:8443",
		"http://forge.example:4001/api/v1",
		"ssh://git@forge.example:4022/x.git",
		"RACK-01 rebooted",
		"runner blade-02",
		"http://ANVIL.internal:8077",
		"zenith is 21%",
		"tunnel up on gate-01",
		"Pod-02.internal",
		"runs on pilot-b",
		plantedHome + "/sources",
		"/mnt/labshare/go-qrdb",
		"jdoe@ci-runner-01",
	}
	set := plantedFleet(t)
	if len(samples) != len(set) {
		t.Fatalf("%d samples for %d patterns: add one per pattern", len(samples), len(set))
	}
	if Digest("ANVIL") != Digest("anvil") {
		t.Error("Digest does not fold case")
	}
	for i, p := range set {
		if got := p.find(samples[i]); len(got) != 1 {
			t.Errorf("pattern %d (%s): %d matches in %q, want 1", i, p.Class, len(got), samples[i])
		}
		if got := Fleet()[i].find(samples[i]); len(got) != 0 {
			t.Errorf("pattern %d (%s) reports the synthetic sample %q without its digest", i, p.Class, samples[i])
		}
	}
}

// A tracked file's path ships as surely as its content.
func TestFleet_ReportsAValueThatAppearsOnlyInThePath(t *testing.T) {
	cases := []struct {
		path      string
		wantClass Class
		wantMatch string
	}{
		{"logs/rack-04.log", ClassLabHost, "rack-04"},
		{"testdata/198.18.0.7/capture.txt", ClassLabAddress, "198.18.0.7"},
		{"docs/runs/BLADE-02-bench.md", ClassLabHost, "BLADE-02"},
	}
	set := plantedFleet(t)
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			findings, err := Scan(entriesOf(map[string]string{tc.path: "ordinary text\n"}), set, nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("findings = %v, want exactly one for the path", findings)
			}
			got := findings[0]
			if got.Path != tc.path || got.Line != 0 || got.Class != tc.wantClass || got.Match != tc.wantMatch {
				t.Errorf("finding = %+v, want path %s line 0 class %s match %q", got, tc.path, tc.wantClass, tc.wantMatch)
			}
		})
	}
}

// TestThePlantedViolationIsCaught proves the gate can fail. A gate nobody
// has seen fail is indistinguishable from a gate that does not run: this writes
// one of each class into a copy of the tree's own layout and asserts all
// come back, then asserts the same values pass once waived.
func TestThePlantedViolationIsCaught(t *testing.T) {
	planted := map[string]string{
		"cmd/luks2/help.go":         "const help = \"--keyserver https://198.18.0.51:8443\"\n",
		"docs/cli/mount.md":         "Mount it on anvil, then check " + plantedHome + "/sources.\n",
		"pkg/luks2/testdata/x.json": "{\"host\": \"rack-04\", \"user\": \"jdoe\"}\n",
	}
	files := entriesOf(planted)
	set := plantedFleet(t)

	findings, err := Scan(files, set, DefaultAllowList)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	byClass := map[Class]int{}
	for _, f := range findings {
		byClass[f.Class]++
	}
	for _, want := range classes {
		if byClass[want] == 0 {
			t.Errorf("no %s finding in %v", want, findings)
		}
	}

	var report strings.Builder
	dirty, err := Report(&report, findings)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if !dirty {
		t.Fatal("Report says a tree with planted violations is clean")
	}
	for name := range planted {
		if !strings.Contains(report.String(), name) {
			t.Errorf("report does not name %s:\n%s", name, report.String())
		}
	}

	// The same values, waived in place, are accepted -- which is what makes
	// the gate usable for the cases where the value is the point.
	waived := entriesOf(map[string]string{
		"docs/guide.md": "Deploy it on anvil <!-- lab-string-ok: measurement provenance -->\n",
	})
	rest, err := Scan(waived, set, DefaultAllowList)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("a waived line was still reported: %v", rest)
	}
}

// TestTheGateWouldHaveCaughtTheFirstAudit pins the kinds of value the audit
// of the sibling repository found, planted in the kind of file each was found
// in. That audit is what the rule set
// was written against, so it is the regression test for the rule set here too:
// if a future change to the patterns stops matching any of these, the gate has
// stopped doing the job it was written for.
func TestTheGateWouldHaveCaughtTheFirstAudit(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		content string
		want    Class
	}{
		{"the repo-root symlink into the lab NFS mount", "note.txt", "/mnt/labshare/go-quicbaas/\n", ClassOwnerPath},
		{"the private registry in the release workflow", ".github/workflows/release.yml", "  REGISTRY: 198.18.0.91:4001\n", ClassLabAddress},
		{"a forge issue link in a shipped doc", "docs/barrier/cli.md", "([#1](http://198.18.0.91:4001/example/go-quicbaas/issues/1))\n", ClassLabAddress},
		{"the fleet host in --help text", "cmd/quicbaas/orchestrator.go", "\t\t\"Pin the session by Name or Host (e.g. 'anvil')\")\n", ClassLabHost},
		{"the fleet address in exported godoc", "pkg/agent/config.go", "\t// (e.g., \"https://198.18.0.51:8443\"). Required.\n", ClassLabAddress},
		{"a copy-pasteable endpoint in a doc", "docs/embeddings/npu.md", "cfg.BaseURL = \"http://anvil.internal:8077\"\n", ClassLabHost},
		{"the private registry in a captured runner log", "pkg/cifault/testdata/registry-unreachable.log", "image: 198.18.0.91:4001/example/ci-runner:latest\n", ClassLabAddress},
		{"a session note full of owner paths", "SESSION_RESUME.md", "- `" + plantedHome + "/sources/...`\n", ClassOwnerPath},
	}

	set := plantedFleet(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := Scan(entriesOf(map[string]string{tc.file: tc.content}), set, DefaultAllowList)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			for _, f := range findings {
				if f.Class == tc.want {
					return
				}
			}
			t.Fatalf("no %s finding for %s: %v", tc.want, tc.file, findings)
		})
	}
}
