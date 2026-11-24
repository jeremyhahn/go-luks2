// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// ValidatePassphrase checks pass against MinPassphraseLength..MaxPassphraseLength, only borrowing it; failures are *Error of kind ErrInvalidCredential or ErrProtectedMemory.
func ValidatePassphrase(pass enclave.ByteAccess) error {
	const op = "ValidatePassphrase"
	return errAt(op, "", secret.Borrow(op, pass, validatePassphraseBytes))
}
