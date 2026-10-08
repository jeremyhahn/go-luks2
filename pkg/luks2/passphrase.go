// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// ValidatePassphrase judges pass against this package's passphrase policy
// (MinPassphraseLength..MaxPassphraseLength) -- the same bounds
// validatePassphraseBytes enforces for the internal
// formatOptionsForTest/addKeyOptionsForTest path. pass is the caller's enclave and stays the caller's:
// this only ever borrows it, for exactly the length check, and never copies
// it to a plain []byte or string that outlives the call.
func ValidatePassphrase(pass *enclave.MemoryEnclave) error {
	return secret.Borrow("ValidatePassphrase", pass, validatePassphraseBytes)
}
