// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package keyprovider implements luks2.KeyProvider with external credentials: Command runs a helper and takes a line of its output, and FIDO2 drives the libfido2 helper binaries.
// The application must call enclave.HardenProcess itself; this package never does.
package keyprovider
