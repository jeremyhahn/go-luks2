// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// hardenProbeEnv names the variable that turns this test binary, re-executed
// by TestRunHardensBeforeFirstSecret, into the child that drives the CLI.
const hardenProbeEnv = "LUKS2_HARDEN_PROBE"

// hardenProbePrefix marks the child's one line of findings on stdout.
const hardenProbePrefix = "harden-probe:"

// coreProbe is the CLI's standard input in the child. The CLI reads it only
// as a credential (--key-file -), so its first Read is the moment the CLI
// first handles a secret; it records the process's core-dump state there
// and returns end of input.
type coreProbe struct {
	called   bool
	cur, max uint64
	dumpable int
	err      error
}

func (p *coreProbe) Read([]byte) (int, error) {
	if !p.called {
		p.called = true
		var lim unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
			p.err = err
		}
		p.cur, p.max = lim.Cur, lim.Max
		d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil && p.err == nil {
			p.err = err
		}
		p.dumpable = d
	}
	return 0, io.EOF
}

// TestHardenProbeChild is the child half of TestRunHardensBeforeFirstSecret.
// Run directly it has nothing to probe and returns; the parent re-executes
// the test binary with hardenProbeEnv set and only this test selected.
func TestHardenProbeChild(t *testing.T) {
	if os.Getenv(hardenProbeEnv) != "1" {
		return
	}

	// Start from a process that WOULD dump core: a nonzero RLIMIT_CORE,
	// soft and hard, and the dumpable flag set. A hard limit of zero is
	// raised (CI runs as root, so it can be); failing to set either
	// precondition fails the test rather than proving nothing. The limit is
	// inherited from the test binary, which no other test in this package
	// hardens: each real CLI call runs in its own child (main_test.go).
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		t.Fatalf("getrlimit(RLIMIT_CORE): %v", err)
	}
	if lim.Max == 0 {
		lim.Max = 1 << 20
	}
	lim.Cur = lim.Max
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Fatalf("setrlimit(RLIMIT_CORE, %d/%d): %v: the inherited hard core limit is below it and raising it needs CAP_SYS_RESOURCE; run the tests from a shell whose hard core limit is not 0 (ulimit -Hc)", lim.Cur, lim.Max, err)
		}
		t.Fatalf("setrlimit(RLIMIT_CORE, %d/%d): %v", lim.Cur, lim.Max, err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		t.Fatalf("prctl(PR_SET_DUMPABLE, 1): %v", err)
	}

	// A new file volume reads its passphrase after creating the file and
	// before any device work, so this needs neither root nor a loop device.
	probe := &coreProbe{}
	vol := filepath.Join(t.TempDir(), "probe.img")
	code := run([]string{"luks2", "create", "--key-file", "-", vol, "1M"}, probe, io.Discard, io.Discard)

	errText := "none"
	if probe.err != nil {
		errText = strings.ReplaceAll(probe.err.Error(), " ", "_")
	}
	fmt.Printf("%s called=%t cur=%d max=%d dumpable=%d code=%d err=%s\n",
		hardenProbePrefix, probe.called, probe.cur, probe.max, probe.dumpable, code, errText)
}

// TestRunHardensBeforeFirstSecret proves the CLI disables core dumps before
// it reads a credential: the heap copies internal/secret lists as raw-bytes
// boundaries are outside go-enclave's MADV_DONTDUMP pages, and only process
// hardening keeps them out of a core file.
func TestRunHardensBeforeFirstSecret(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHardenProbeChild$", "-test.count=1") // #nosec G204 -- the test binary re-executing itself
	cmd.Env = append(os.Environ(), hardenProbeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe child: %v\n%s", err, out)
	}

	var line string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), hardenProbePrefix) {
			line = sc.Text()
		}
	}
	if line == "" {
		t.Fatalf("probe child printed no %q line:\n%s", hardenProbePrefix, out)
	}

	var called bool
	var cur, max uint64
	var dumpable, code int
	var errText string
	if _, err := fmt.Sscanf(line, hardenProbePrefix+" called=%t cur=%d max=%d dumpable=%d code=%d err=%s",
		&called, &cur, &max, &dumpable, &code, &errText); err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	if !called {
		t.Fatalf("the CLI never read its credential (exit %d); the probe saw nothing:\n%s", code, out)
	}
	if errText != "none" {
		t.Fatalf("probe could not read the process state: %s", errText)
	}
	if cur != 0 || max != 0 {
		t.Errorf("RLIMIT_CORE at the first credential read = %d/%d, want 0/0", cur, max)
	}
	if dumpable != 0 {
		t.Errorf("PR_GET_DUMPABLE at the first credential read = %d, want 0", dumpable)
	}
}
