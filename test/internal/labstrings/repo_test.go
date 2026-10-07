// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"strings"
	"testing"
)

// TestThePlantedViolationIsCaught proves the gate can fail. A gate nobody
// has seen fail is indistinguishable from a gate that does not run: this writes
// one of each class into a copy of the tree's own layout and asserts all three
// come back, then asserts the same values pass once waived.
func TestThePlantedViolationIsCaught(t *testing.T) {
	planted := map[string]string{
		"cmd/luks2/help.go":         "const help = \"--keyserver https://198.51.100.51:8443\"\n",
		"docs/cli/mount.md":         "Mount it on gpu-host, then check " + ownerPathFixture + "/sources.\n",
		"pkg/luks2/testdata/x.json": "{\"host\": \"vm-host-4\"}\n",
	}
	files := entriesOf(planted)

	findings, err := Scan(files, DefaultAllowList)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	byClass := map[Class]int{}
	for _, f := range findings {
		byClass[f.Class]++
	}
	for _, want := range []Class{ClassLabAddress, ClassLabHost, ClassOwnerPath} {
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
		t.Fatal("Report says a tree with three planted violations is clean")
	}
	for name := range planted {
		if !strings.Contains(report.String(), name) {
			t.Errorf("report does not name %s:\n%s", name, report.String())
		}
	}

	// The same values, waived in place, are accepted -- which is what makes
	// the gate usable for the cases where the value is the point.
	waived := map[string]string{
		"docs/guide.md": "Deploy it on gpu-host <!-- lab-string-ok: measurement provenance -->\n",
	}
	waivedFiles := entriesOf(waived)
	rest, err := Scan(waivedFiles, DefaultAllowList)
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
		{
			name:    "the repo-root symlink into the lab NFS mount",
			file:    "note.txt",
			content: "/mnt/" + "vstation" + "-01/go-quicbaas/\n", // lab-string-ok: the value the audit found
			want:    ClassOwnerPath,
		},
		{
			name:    "the private registry in the release workflow",
			file:    ".github/workflows/release.yml",
			content: "  REGISTRY: 198.51.100.91:3001\n",
			want:    ClassLabAddress,
		},
		{
			name:    "a forge issue link in a shipped doc",
			file:    "docs/barrier/cli.md",
			content: "([#491](http://198.51.100.91:3001/jeremyhahn/go-quicbaas/issues/491))\n",
			want:    ClassLabAddress,
		},
		{
			name:    "the fleet host in --help text",
			file:    "cmd/quicbaas/orchestrator.go",
			content: "\t\t\"Pin the session by Name or Host (e.g. 'gpu-host')\")\n",
			want:    ClassLabHost,
		},
		{
			name:    "the fleet address in exported godoc",
			file:    "pkg/agent/config.go",
			content: "\t// (e.g., \"https://198.51.100.51:8443\"). Required.\n",
			want:    ClassLabAddress,
		},
		{
			name:    "a copy-pasteable endpoint in a doc",
			file:    "docs/embeddings/npu.md",
			content: "cfg.BaseURL = \"http://gpu-host.internal:8077\"\n",
			want:    ClassLabHost,
		},
		{
			name:    "the private registry in a captured runner log",
			file:    "pkg/cifault/testdata/registry-unreachable.log",
			content: "image: git.example.internal/jeremyhahn/ci-runner:latest\n",
			want:    ClassLabAddress,
		},
		{
			name:    "a session note full of owner paths",
			file:    "SESSION_RESUME.md",
			content: "- `" + ownerPathFixture + "/sources/...`\n",
			want:    ClassOwnerPath,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := entriesOf(map[string]string{tc.file: tc.content})
			findings, err := Scan(files, DefaultAllowList)
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
