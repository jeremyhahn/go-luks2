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
	"sort"
	"strconv"
	"strings"
	"testing"
)

// These are the tests of the fleet pattern set itself, against the real values
// it was written for. Like fleet.go they are stripped at publish: the
// published tests prove the scanner with documentation-value fixtures
// (labstrings_test.go), and these prove that the set compiled into the
// development tree finds the fleet.

// archiveLeaks reads a tar stream and returns every place it spells a needle
// of the given set, case-folded. Nothing exempts a place: no waiver, no allow
// rule. The needle is the literal every match of its pattern contains, so this
// is stricter than the gate: it also finds a needle the gate's own source
// spells to define a pattern.
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
		lines := bytes.Split(bytes.ToLower(content), []byte("\n"))
		for _, p := range set {
			needle := []byte(p.Needle)
			for _, f := range fields {
				if bytes.Contains(bytes.ToLower([]byte(f.text)), needle) {
					leaks = append(leaks, fmt.Sprintf("%s (%s): %s", hdr.Name, f.where, p.Class))
				}
			}
			for i, line := range lines {
				if bytes.Contains(line, needle) {
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
func archiveFleetLeaks(root string) (files int, leaks []string, err error) {
	out, err := ArchiveHEAD(root)
	if err != nil {
		return 0, nil, err
	}
	return archiveLeaks(bytes.NewReader(out), Fleet())
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
	files, leaks, err := archiveFleetLeaks(root)
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
		"docs/guide.md":  "Measured on gpu-host. <!-- lab-string-ok: provenance -->\n",
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
			files, leaks, err := archiveFleetLeaks(root)
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
	files, leaks, err := archiveFleetLeaks(root)
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
		"docs/guide.md":        "Measured on gpu-host. <!-- lab-string-ok: provenance -->\n",
		"logs/vm-host-4.log": "ordinary text\n",
		"clean.txt":            "dial 198.51.100.7:8443\n",
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
	files, leaks, err := archiveLeaks(&buf, Fleet())
	if err != nil {
		t.Fatalf("archiveLeaks: %v", err)
	}
	if files != 3 {
		t.Errorf("files = %d, want 3", files)
	}
	sort.Strings(leaks)
	want := []string{"docs/guide.md:1: " + string(ClassLabHost), "logs/vm-host-4.log (path): " + string(ClassLabHost)}
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
		{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: "workspace", Linkname: "/home/jhahn/go-luks2", Mode: 0o777}},
	})
	_, leaks, err := archiveLeaks(buf, Fleet())
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
		{hdr: tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "built on gpu-host"}}},
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "a.txt", Mode: 0o644, Uname: "vm-host-4", Gname: "dellemc-r730"}, content: "plain\n"},
		{hdr: tar.Header{Typeflag: tar.TypeLink, Name: "b.txt", Linkname: "mini-1.txt", Mode: 0o644}},
		{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "c.txt", Mode: 0o644, PAXRecords: map[string]string{
			"SCHILY.xattr.user.origin": "198.51.100.7",
			"SCHILY.xattr.user.omega":  "x",
		}}},
	})
	files, leaks, err := archiveLeaks(buf, Fleet())
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
		{"fleet address in help text", "package main\n\nconst help = \"dial 198.51.100.51:8443\"\n", ClassLabAddress, "198.51.100.51", 3},
		{"forge port in a URL", "forge: https://forge.example:3001/api/v1\n", ClassLabAddress, ":3001", 1},
		{"forge ssh port in a remote", "remote: ssh://git@forge.example:2222/x.git\n", ClassLabAddress, ":2222", 1},
		{"fleet hostname in a doc", "# Runbook\n\nRun it on GODLIKE first.\n", ClassLabHost, "GODLIKE", 3},
		{"runner hostname in a captured log", "2026-09-12T00:00:00Z ci-node-2(version:v3.1.0)\n", ClassLabHost, "ci-node-2", 1},
		{"fleet hostname quoted in a workflow comment", "jobs:\n# the fleet is idle: Omega is at 21%\n", ClassLabHost, "Omega", 2},
		{"fleet hostname as an internal endpoint", "cfg.BaseURL = \"http://omega.internal:8077\"\n", ClassLabHost, "omega.internal", 1},
		{"agent hostname in a comment", "// observed on vm-host-4\n", ClassLabHost, "vm-host-4", 1},
		{"tunnel gateway in prose", "The tunnel comes up on tgw-01 before the runners.\n", ClassLabHost, "tgw-01", 1},
		{"tunnel gateway in a URL, mixed case", "proxy: https://TGW-01:8443/v1\n", ClassLabHost, "TGW-01", 1},
		{"mini node in YAML", "runners:\n  - host: lab-node-5\n", ClassLabHost, "lab-node-5", 2},
		{"mini node in a URL, mixed case", "see http://Mini-02.internal:8077/status\n", ClassLabHost, "Mini-02", 1},
		{"coordinator host in prose", "# Notes\nThe coordinator runs on control-b.\n", ClassLabHost, "control-b", 2},
		{"coordinator host in YAML, mixed case", "coordinator: Control-b\n", ClassLabHost, "Control-b", 1},
		{"coordinator host in a URL", "forge: http://git.example.internal:3001/api/v1\n", ClassLabHost, "control-b", 1},
		{"owner home path in a doc", "See /home/jhahn/sources for the checkout.\n", ClassOwnerPath, "/home/jhahn", 1},
		{"owner account in an ssh command", "ssh jhahn@ci-runner-01 uptime\n", ClassOwnerAccount, "jhahn", 1},
		{"owner account as a mixed-case author, in YAML", "maintainers:\n  - JHahn\n", ClassOwnerAccount, "JHahn", 2},
		{"lab NFS mount in a script default", "QRDB=${QRDB:-/mnt/vm-host-1/go-qrdb}\n", ClassOwnerPath, "/mnt/vstation", 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := entriesOf(map[string]string{"shipping/file.txt": tc.content})
			findings, err := Scan(files, Fleet(), nil)
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
		})
	}
}

func TestFleet_AcceptsWhatItShould(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"documentation addresses", "dial 198.51.100.7:8443 or 192.0.2.10 or 203.0.113.4\n"},
		{"RFC 1918 literals that are not the fleet subnet", "peers: 192.168.1.10, 192.168.100.4, 10.0.0.1\n"},
		{"the repository's own example names", "--keyserver https://luks.example.com:8443 --runner ci-runner-01\n"},
		{"a port that merely starts like the forge's", "listen on :30011 and :22220\n"},
		{"a waiver on the offending line", "Measured on gpu-host. <!-- lab-string-ok: measurement provenance -->\n"},
		{"a hostname that merely contains a fleet name as a substring", "ungodlikeness is not a host, and vstation-0 has no second digit\n"},
		{"a word that merely contains the fleet name omega", "megaomegalith and omegas are words, not hosts\n"},
		{"words that merely start like a mini node", "a minimal minix build, one mini-batch at a time, mini-2026 and mini-5\n"},
		{"words that merely start like a coordinator host", "the control-plane talks over the control-bus; control-b2 is not a host\n"},
		{"a key chord is not a coordinator host", "press Control-C to abort, Control-D at the prompt\n"},
		{"the forge owner in a module path and a repository URL", "import \"github.com/jeremyhahn/go-enclave\"\nsee https://github.com/jeremyhahn/go-luks2\n"},
		{"a word that merely contains the owner account", "xjhahn and jhahns and jhahn_x are not the account\n"},
		{"a tunnel gateway without a number", "the tgw role, tgw-a, tgw-1 and tgw-001 are not hosts\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := Scan(entriesOf(map[string]string{"clean.txt": tc.content}), Fleet(), nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("expected no findings, got %v", findings)
			}
		})
	}
}

// TestFleet_EveryNeedleIsImpliedByItsExpr pins the sieve's invariant: a
// pattern whose Needle its own matches do not contain would be skipped for every
// file in the tree, and the gate would pass while seeing nothing.
func TestFleet_EveryNeedleIsImpliedByItsExpr(t *testing.T) {
	// One string per pattern that the pattern is known to match. They are the
	// values the audit actually found, so this doubles as the record of what
	// each rule was written for.
	samples := map[string][]string{
		`\b192\.168\.101\.\d{1,3}\b`:   {"198.51.100.91:3001", "at 198.51.100.51:8443"},
		`:3001\b`:                      {"http://forge.example:3001/api/v1"},
		`:2222\b`:                      {"ssh://git@forge.example:2222/x.git"},
		`(?i)\bvstation-\d{2}\b`:       {"agent-vm-host-4", "VSTATION-01 rebooted"},
		`(?i)\bdellemc-\d{2}\b`:        {"runner ci-node-2", "DELLEMC-01"},
		`(?i)\bgodlike(\.internal)?\b`: {"on gpu-host", "http://GODLIKE.internal:8077"},
		`(?i)\bomega(\.internal)?\b`:   {"omega is 21%", "http://OMEGA.internal:8077"},
		`(?i)\btgw-\d{2}\b`:            {"tunnel up on tgw-01", "https://TGW-01:8443"},
		`(?i)\bmini-\d{2}\b`:           {"host: lab-node-5", "Mini-02.internal"},
		`(?i:\bcontrol)-[a-z]\b`:       {"runs on control-b", "http://git.example.internal:3001"},
		`/home/jhahn\b`:                {"/home/jhahn/sources"},
		`/mnt/vstation`:                {"/mnt/vm-host-1/go-qrdb"},
		`(?i)\bjhahn\b`:                {"jhahn@ci-runner-01"},
	}

	for _, p := range Fleet() {
		t.Run(p.Expr.String(), func(t *testing.T) {
			if p.Needle == "" {
				t.Fatal("pattern has no sieve needle")
			}
			if p.Needle != strings.ToLower(p.Needle) {
				t.Errorf("needle %q is not lowercase; the sieve folds case before searching", p.Needle)
			}
			got, ok := samples[p.Expr.String()]
			if !ok {
				t.Fatalf("no sample for this pattern: add one so its needle stays honest")
			}
			for _, sample := range got {
				if !p.Expr.MatchString(sample) {
					t.Errorf("%q does not match its own sample %q", p.Expr, sample)
				}
				if !strings.Contains(strings.ToLower(sample), p.Needle) {
					t.Errorf("sample %q matches but does not contain needle %q: the sieve would skip it", sample, p.Needle)
				}
			}
		})
	}
}

// A tracked file's path ships as surely as its content.
func TestFleet_ReportsAValueThatAppearsOnlyInThePath(t *testing.T) {
	cases := []struct {
		path      string
		wantClass Class
		wantMatch string
	}{
		{"logs/vm-host-4.log", ClassLabHost, "vm-host-4"},
		{"testdata/198.51.100.7/capture.txt", ClassLabAddress, "198.51.100.7"},
		{"docs/runs/DELLEMC-02-bench.md", ClassLabHost, "DELLEMC-02"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			findings, err := Scan(entriesOf(map[string]string{tc.path: "ordinary text\n"}), Fleet(), nil)
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
		"cmd/luks2/help.go":         "const help = \"--keyserver https://198.51.100.51:8443\"\n",
		"docs/cli/mount.md":         "Mount it on gpu-host, then check /home/jhahn/sources.\n",
		"pkg/luks2/testdata/x.json": "{\"host\": \"vm-host-4\", \"user\": \"jhahn\"}\n",
	}
	files := entriesOf(planted)

	findings, err := Scan(files, Fleet(), DefaultAllowList)
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
		"docs/guide.md": "Deploy it on gpu-host <!-- lab-string-ok: measurement provenance -->\n",
	})
	rest, err := Scan(waived, Fleet(), DefaultAllowList)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("a waived line was still reported: %v", rest)
	}
}

// TestTheGateWouldHaveCaughtIssue944 pins the specific values go-quicbaas#944
// found, in the kind of file each was found in. That audit is what the rule set
// was written against, so it is the regression test for the rule set here too:
// if a future change to the patterns stops matching any of these, the gate has
// stopped doing the job it was written for.
func TestTheGateWouldHaveCaughtIssue944(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		content string
		want    Class
	}{
		{"the repo-root symlink into the lab NFS mount", "note.txt", "/mnt/vm-host-1/go-quicbaas/\n", ClassOwnerPath},
		{"the private registry in the release workflow", ".github/workflows/release.yml", "  REGISTRY: 198.51.100.91:3001\n", ClassLabAddress},
		{"a forge issue link in a shipped doc", "docs/barrier/cli.md", "([#491](http://198.51.100.91:3001/jeremyhahn/go-quicbaas/issues/491))\n", ClassLabAddress},
		{"the fleet host in --help text", "cmd/quicbaas/orchestrator.go", "\t\t\"Pin the session by Name or Host (e.g. 'gpu-host')\")\n", ClassLabHost},
		{"the fleet address in exported godoc", "pkg/agent/config.go", "\t// (e.g., \"https://198.51.100.51:8443\"). Required.\n", ClassLabAddress},
		{"a copy-pasteable endpoint in a doc", "docs/embeddings/npu.md", "cfg.BaseURL = \"http://gpu-host.internal:8077\"\n", ClassLabHost},
		{"the private registry in a captured runner log", "pkg/cifault/testdata/registry-unreachable.log", "image: git.example.internal/jeremyhahn/ci-runner:latest\n", ClassLabAddress},
		{"a session note full of owner paths", "SESSION_RESUME.md", "- `/home/jhahn/sources/...`\n", ClassOwnerPath},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := Scan(entriesOf(map[string]string{tc.file: tc.content}), Fleet(), DefaultAllowList)
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
