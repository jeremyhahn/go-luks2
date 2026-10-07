// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestDevNoDecodingMatchesTheKernelEncoding pins the decoder against
// unix.Mkdev, which is what device nodes are made with. The two must be
// exact inverses or a node is made under one name and looked for under
// another.
//
// The write-side node-placement tests that used to sit beside this one
// moved to pkg/dmcrypt with the code they tested (#268): removeMappingNodes,
// ensureDeviceNode and the rest are activation's now. decodeDevNo itself
// stays, because (*Volume).Target still needs it.
func TestDevNoDecodingMatchesTheKernelEncoding(t *testing.T) {
	cases := []struct {
		major uint32
		minor uint32
	}{
		{253, 0},
		{253, 1},
		{253, 254},
		// 255 is the last minor the truncating form gets right; everything
		// below it is where the two decoders part company.
		{253, 255},
		{253, 256},
		{253, 300},
		{253, 1000},
		{253, 1048575}, // the largest minor the 32-bit encoding holds
		{4095, 42},     // the largest major
	}

	for _, tc := range cases {
		devNo := unix.Mkdev(tc.major, tc.minor)

		major, minor := decodeDevNo(devNo)
		if major != tc.major || minor != tc.minor {
			t.Errorf("decodeDevNo(Mkdev(%d, %d)) = (%d, %d), want (%d, %d)",
				tc.major, tc.minor, major, minor, tc.major, tc.minor)
		}

		// The truncating form this replaced, shown failing for exactly the
		// values that matter. It is asserted rather than merely described so
		// that "minors above 255 differ" is a measured claim.
		if truncated := uint32(devNo & 0xFF); tc.minor > 255 && truncated == tc.minor {
			t.Errorf("fixture is not exercising the defect: minor %d survives truncation", tc.minor)
		}
	}
}
