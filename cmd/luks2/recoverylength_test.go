// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// TestRecoveryGenerateRefusesAShortKeyOrAnUnknownFormat (#249, A4): through the
// real library, a recovery key under 256 bits and a format that does not exist
// are refused rather than printed -- a short key under the recovery cost would
// be a weak credential, and an unknown format used to print dashed silently.
func TestRecoveryGenerateRefusesAShortKeyOrAnUnknownFormat(t *testing.T) {
	for _, args := range [][]string{
		{"recovery", "generate", "--length", "4"},
		{"recovery", "generate", "--length", "-1"},
		{"recovery", "generate", "--format", "morse"},
	} {
		t.Run(strings.Join(args[2:], " "), func(t *testing.T) {
			cli, stdout, stderr := runCLI(t, "", args...)
			if code := cli.Run(); code != 1 {
				t.Fatalf("%v exited %d, want 1", args, code)
			}
			if strings.Contains(stdout.String(), "RECOVERY KEY") {
				t.Fatalf("a refused request still printed a key:\n%s", stdout.String())
			}
			if !strings.Contains(stderr.String(), "recovery key") {
				t.Errorf("stderr = %q, want it to say what was refused", stderr.String())
			}
		})
	}
}
