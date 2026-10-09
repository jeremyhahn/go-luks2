// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package makefile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// `make trivy-install` replaced `curl .../contrib/install.sh | sh` (#247). What
// makes it safe is that nothing is unpacked, installed or reused unless it
// matches a pinned SHA-256. These tests run the real target against a local
// HTTPS server serving a stand-in archive, with the pins overridden on the
// command line to that archive's hashes, and prove each check REFUSES.

// trivyArchive builds a release-shaped .tar.gz holding one file, trivy.
func trivyArchive(t *testing.T, binary []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		body []byte
	}{{"README.md", []byte("readme\n")}, {"trivy", binary}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type trivyFixture struct {
	archive  []byte
	binary   []byte
	requests atomic.Int32
	base     string
	caFile   string
	tools    string
}

// newTrivyFixture serves archive as the v0.75.0 release for both
// architectures, over TLS, and returns where.
func newTrivyFixture(t *testing.T, archive, binary []byte) *trivyFixture {
	t.Helper()
	f := &trivyFixture{archive: archive, binary: binary}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		switch r.URL.Path {
		case "/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz", "/v0.75.0/trivy_0.75.0_Linux-ARM64.tar.gz":
			_, _ = w.Write(f.archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	f.caFile = filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(f.caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	f.base = srv.URL
	f.tools = filepath.Join(dir, "tools dir") // a space: the path is data, not shell
	return f
}

// install runs make trivy-install with every pin set to the given hashes.
func (f *trivyFixture) install(t *testing.T, archiveSum, binarySum string) (string, error) {
	t.Helper()
	env := environ(nil, map[string]string{"CURL_CA_BUNDLE": f.caFile, "SSL_CERT_FILE": f.caFile})
	stdout, stderr, err := runMakeErr(t, env, "--no-print-directory", "trivy-install",
		"TRIVY_DOWNLOAD_BASE="+f.base,
		"TOOLS_DIR="+f.tools,
		"TRIVY_SHA256_LINUX_AMD64="+archiveSum,
		"TRIVY_SHA256_LINUX_ARM64="+archiveSum,
		"TRIVY_BIN_SHA256_LINUX_AMD64="+binarySum,
		"TRIVY_BIN_SHA256_LINUX_ARM64="+binarySum,
	)
	return stdout + stderr, err
}

func (f *trivyFixture) installed() string {
	return filepath.Join(f.tools, "trivy-v0.75.0", "trivy")
}

func TestTrivyInstallVerifiesThenInstalls(t *testing.T) {
	binary := []byte("#!/bin/sh\necho 'Version: 0.75.0'\n")
	f := newTrivyFixture(t, trivyArchive(t, binary), binary)

	out, err := f.install(t, sum(f.archive), sum(binary))
	if err != nil {
		t.Fatalf("trivy-install failed on a matching archive: %v\n%s", err, out)
	}
	got, err := os.ReadFile(f.installed())
	if err != nil || !bytes.Equal(got, binary) {
		t.Fatalf("installed binary = %q, %v; want the archive's", got, err)
	}
	if mode := mode(t, f.installed()); mode.Perm() != 0o755 {
		t.Errorf("installed mode = %v, want 0755", mode)
	}

	// A second run reuses the verified copy without downloading.
	before := f.requests.Load()
	if out, err := f.install(t, sum(f.archive), sum(binary)); err != nil || !strings.Contains(out, "already installed") {
		t.Fatalf("second install: %v\n%s", err, out)
	}
	if f.requests.Load() != before {
		t.Error("a verified installed copy was downloaded again")
	}

	// A tampered installed copy is NOT reused: its hash is checked, not its
	// presence, and it is replaced by a verified one.
	if err := os.WriteFile(f.installed(), []byte("#!/bin/sh\necho evil\n"), 0o755); err != nil { // #nosec G306 -- test fixture standing in for an executable
		t.Fatal(err)
	}
	if out, err := f.install(t, sum(f.archive), sum(binary)); err != nil || strings.Contains(out, "already installed") {
		t.Fatalf("a tampered installed copy was reused: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(f.installed()); !bytes.Equal(got, binary) {
		t.Errorf("the tampered copy was not replaced: %q", got)
	}
}

// The archive's hash is checked BEFORE it is unpacked: a substituted archive
// installs nothing.
func TestTrivyInstallRefusesAnArchiveThatDoesNotMatchItsPin(t *testing.T) {
	binary := []byte("#!/bin/sh\necho 'Version: 0.75.0'\n")
	f := newTrivyFixture(t, trivyArchive(t, binary), binary)

	out, err := f.install(t, strings.Repeat("0", 64), sum(binary))
	if err == nil {
		t.Fatalf("trivy-install accepted an archive that does not match its pin\n%s", out)
	}
	if !strings.Contains(out, "does not match its pinned SHA-256; refusing to unpack it") {
		t.Errorf("output does not name the mismatch:\n%s", out)
	}
	if _, err := os.Stat(f.installed()); !os.IsNotExist(err) {
		t.Errorf("something was installed from a mismatching archive: %v", err)
	}
}

// The binary inside is checked too: an archive whose pin was raised without
// its binary's is refused.
func TestTrivyInstallRefusesABinaryThatDoesNotMatchItsPin(t *testing.T) {
	binary := []byte("#!/bin/sh\necho 'Version: 0.75.0'\n")
	f := newTrivyFixture(t, trivyArchive(t, binary), binary)

	out, err := f.install(t, sum(f.archive), strings.Repeat("f", 64))
	if err == nil {
		t.Fatalf("trivy-install accepted a binary that does not match its pin\n%s", out)
	}
	if !strings.Contains(out, "binary in trivy_0.75.0_Linux-") {
		t.Errorf("output does not name the binary mismatch:\n%s", out)
	}
	if _, err := os.Stat(f.installed()); !os.IsNotExist(err) {
		t.Errorf("a mismatching binary was installed: %v", err)
	}
}

// The real pins are full SHA-256s for both architectures: an empty or short
// pin would make sha256sum's check meaningless or broken.
func TestTrivyPinsAreFullHashes(t *testing.T) {
	stdout, _ := runMake(t, environ(nil, nil), "--no-print-directory", "-pn", "trivy-install")
	for _, name := range []string{
		"TRIVY_SHA256_LINUX_AMD64", "TRIVY_SHA256_LINUX_ARM64",
		"TRIVY_BIN_SHA256_LINUX_AMD64", "TRIVY_BIN_SHA256_LINUX_ARM64",
	} {
		var value string
		for _, line := range strings.Split(stdout, "\n") {
			if v, ok := strings.CutPrefix(line, name+" := "); ok {
				value = v
			}
		}
		if len(value) != 64 || strings.Trim(value, "0123456789abcdef") != "" {
			t.Errorf("%s = %q, want 64 lower-case hex digits", name, value)
		}
	}
}

// TOOLS_REQUIRED=1 is what the release and the nightly gate run under: a
// scanner that is absent FAILS the target instead of skipping with a warning,
// so a release cannot publish on a scan that never ran (#247). Without it the
// developer default still skips.
func TestToolsRequiredTurnsAMissingScannerIntoAFailure(t *testing.T) {
	// No scanner on PATH, and the Makefile's GOBIN fallback pointed at an empty
	// directory (a command-line override, so go's own GOPATH and its module
	// cache are untouched). PATH is a directory of links to the system's
	// executables minus the scanners, so the test does not depend on whether
	// the host happens to have them installed (CI runners do).
	scanners := []string{"gosec", "govulncheck", "trivy"}
	env := environ([]string{"GOBIN"}, map[string]string{"PATH": systemPathWithout(t, scanners...)})
	emptyBin := t.TempDir()
	// trivy is not part of this contract: its targets fail closed with or
	// without TOOLS_REQUIRED (#296), asserted in the trivy-fs case below.
	t.Run("trivy-fs", func(t *testing.T) {
		args := []string{"--no-print-directory", "trivy-fs", "TOOLS_DIR=" + t.TempDir(), "GOBIN=" + emptyBin}
		for _, extra := range [][]string{nil, {"TOOLS_REQUIRED=1"}} {
			out, errOut, err := runMakeErr(t, env, append(append([]string{}, args...), extra...)...)
			if err == nil {
				t.Fatalf("make trivy-fs %v passed with trivy absent\n%s%s", extra, out, errOut)
			}
			msg := out + errOut
			if !strings.Contains(msg, "not installed") || !strings.Contains(msg, "make trivy-install") {
				t.Errorf("the failure does not say why or how to install (%v):\n%s", extra, msg)
			}
			if strings.Contains(msg, "skipping") {
				t.Errorf("trivy-fs %v skipped instead of failing:\n%s", extra, msg)
			}
		}
	})
	for _, target := range []string{"gosec", "govulncheck"} {
		t.Run(target, func(t *testing.T) {
			args := []string{"--no-print-directory", target, "TOOLS_DIR=" + t.TempDir(), "GOBIN=" + emptyBin}
			out, errOut, err := runMakeErr(t, env, append(args, "TOOLS_REQUIRED=1")...)
			if err == nil {
				t.Fatalf("make %s TOOLS_REQUIRED=1 passed with the tool absent\n%s%s", target, out, errOut)
			}
			if !strings.Contains(out+errOut, "TOOLS_REQUIRED=1") {
				t.Errorf("the failure does not say why:\n%s%s", out, errOut)
			}
			out, errOut, err = runMakeErr(t, env, args...)
			if err != nil || !strings.Contains(out+errOut, "skipping") {
				t.Fatalf("make %s without TOOLS_REQUIRED did not skip: %v\n%s%s", target, err, out, errOut)
			}
		})
	}
}

// systemPathWithout returns a PATH holding links to every executable in the
// standard system directories except the named ones. The first directory that
// provides a name wins, as it would on the real PATH.
func systemPathWithout(t *testing.T, exclude ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, sys := range []string{"/usr/local/bin", "/usr/bin", "/bin"} {
		entries, err := os.ReadDir(sys)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if slices.Contains(exclude, name) {
				continue
			}
			link := filepath.Join(dir, name)
			if _, err := os.Lstat(link); err == nil {
				continue
			}
			if err := os.Symlink(filepath.Join(sys, name), link); err != nil {
				t.Fatalf("link %s: %v", name, err)
			}
		}
	}
	for _, name := range exclude {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("%s is still on the test PATH", name)
		}
	}
	return dir
}
