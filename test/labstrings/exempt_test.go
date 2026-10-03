// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseExemptions_ReadsPathAndReason(t *testing.T) {
	tracked := map[string]bool{"testdata/a.bin": true, "testdata/b.img": true}
	content := "# header\n\ntestdata/a.bin  a golden fixture\ntestdata/b.img\tcaptured from cryptsetup 2.7\n"

	ex, err := ParseExemptions([]byte(content), tracked)
	if err != nil {
		t.Fatalf("ParseExemptions: %v", err)
	}
	want := Exemptions{"testdata/a.bin": "a golden fixture", "testdata/b.img": "captured from cryptsetup 2.7"}
	if len(ex) != len(want) {
		t.Fatalf("exemptions = %v, want %v", ex, want)
	}
	for path, reason := range want {
		if ex[path] != reason {
			t.Errorf("%s: reason %q, want %q", path, ex[path], reason)
		}
	}
}

func TestParseExemptions_RefusesAnUnusableLine(t *testing.T) {
	tracked := map[string]bool{"a.bin": true}
	for name, content := range map[string]string{
		"no reason":      "a.bin\n",
		"blank reason":   "a.bin   \t\n",
		"untracked path": "gone.bin  it used to ship\n",
		"listed twice":   "a.bin  one\na.bin  two\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseExemptions([]byte(content), tracked)
			var exErr *ExemptionError
			if !errors.As(err, &exErr) {
				t.Fatalf("ParseExemptions(%q) = %v, want *ExemptionError", content, err)
			}
			if !strings.HasPrefix(err.Error(), ExemptFile+":") {
				t.Errorf("error %q does not name the file", err)
			}
		})
	}
}

func TestIsBinary(t *testing.T) {
	if IsBinary([]byte("plain text\n")) || IsBinary(nil) {
		t.Error("text was called binary")
	}
	if !IsBinary([]byte("late\x00nul")) {
		t.Error("a NUL past the start was not called binary")
	}
}

// An unexempted binary file fails; an exempted one does not; text is not
// affected either way.
func TestScanUnpublishable_ABinaryFileNeedsAnExemption(t *testing.T) {
	entries := []Entry{
		{Path: "capture.bin", Kind: KindFile, Content: []byte("\x00\x01payload")},
		{Path: "fixture.bin", Kind: KindFile, Content: []byte("\x00\x02"), Exemption: "a golden fixture"},
		{Path: "README.md", Kind: KindFile, Content: []byte("text\n")},
	}
	findings, err := ScanUnpublishable(entries, DefaultUnpublishable)
	if err != nil {
		t.Fatalf("ScanUnpublishable: %v", err)
	}
	if len(findings) != 1 || findings[0].Path != "capture.bin" || !strings.Contains(findings[0].Reason, ExemptFile) {
		t.Fatalf("findings = %v, want only capture.bin, naming %s", findings, ExemptFile)
	}
}

func TestExempted_ListsEveryExemptionAndWhatWasNotRead(t *testing.T) {
	got := Exempted([]Entry{
		{Path: "a.bin", Exemption: "fixture"},
		{Path: "big.img", Exemption: "captured image", Unread: true},
		{Path: "README.md"},
	})
	if len(got) != 2 || got[0].Reason != "fixture" || !strings.HasPrefix(got[1].Reason, "NOT READ") {
		t.Fatalf("Exempted = %v", got)
	}
}

// Through a real index: the exemption list is read from its staged blob, an
// exempt oversize blob comes back unread, an unexempted binary fails, and an
// exemption that exists only in the working tree is not honored.
func TestIndexEntries_HonorsOnlyTheStagedExemptionList(t *testing.T) {
	const limit = 60
	root := gitIndexTree(t, map[string]string{
		"capture.bin": "\x00\x01payload",
		"huge.img":    strings.Repeat("x", limit+10),
		ExemptFile:    "huge.img  a captured image\n",
	})

	scan := func() []FileFinding {
		t.Helper()
		entries, err := indexEntries(root, limit)
		if err != nil {
			t.Fatalf("indexEntries: %v", err)
		}
		for _, e := range entries {
			if e.Path == "huge.img" && (!e.Unread || e.Content != nil || e.Exemption != "a captured image") {
				t.Fatalf("huge.img = %+v, want exempt and unread", e)
			}
		}
		findings, err := ScanUnpublishable(entries, DefaultUnpublishable)
		if err != nil {
			t.Fatalf("ScanUnpublishable: %v", err)
		}
		return findings
	}

	if findings := scan(); len(findings) != 1 || findings[0].Path != "capture.bin" {
		t.Fatalf("findings = %v, want only the unexempted binary capture.bin", findings)
	}

	// Exempting capture.bin in the working tree, unstaged, changes nothing.
	if err := os.WriteFile(filepath.Join(root, ExemptFile), []byte("huge.img  a captured image\ncapture.bin  ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if findings := scan(); len(findings) != 1 || findings[0].Path != "capture.bin" {
		t.Fatalf("an unstaged exemption was honored: findings = %v", findings)
	}

	// Staged, it is honored.
	git(t, root, "", "add", ExemptFile)
	if findings := scan(); len(findings) != 0 {
		t.Fatalf("a staged exemption was not honored: findings = %v", findings)
	}
}

// A staged exemption list that does not parse stops the gate.
func TestIndexEntries_AMalformedExemptionListFails(t *testing.T) {
	root := gitIndexTree(t, map[string]string{
		"a.txt":    "text\n",
		ExemptFile: "a.txt\n",
	})
	_, err := IndexEntries(root)
	var exErr *ExemptionError
	if !errors.As(err, &exErr) {
		t.Fatalf("IndexEntries = %v, want *ExemptionError", err)
	}
}
