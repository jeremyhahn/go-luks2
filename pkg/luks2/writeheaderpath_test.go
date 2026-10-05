// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// No build constraint: both tiers write fixtures through it.

package luks2

import "os"

// writeHeaderInternal writes a validated LUKS2 header to the file at device,
// opening it by path and taking no lock: a FIXTURE writer for tests that build
// a header by hand. Production code writes through the descriptor its lock is
// held on (keyslotDevice.writeHeader), never by reopening a path.
func writeHeaderInternal(device string, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	f, err := openDevice("write the LUKS2 header", device, os.O_RDWR)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return writeHeaderTo(f, hdr, metadata)
}
