// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package recoverykey

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// TestDecodeInvalidHexNamesNoCredentialByte pins that a body that is hex in
// every position but one is refused as ErrInvalidCredential, and that the
// message does not echo the offending character the way hex.InvalidByteError
// does.
func TestDecodeInvalidHexNamesNoCredentialByte(t *testing.T) {
	body := []byte(strings.Repeat("ab", 15) + "a\x01")
	// 0x01 would be printed as U+0001 by hex.InvalidByteError.
	_, err := Decode(testCustody, enclaveFrom(t, body))
	if err == nil {
		t.Fatal("an invalid hex body was accepted")
	}
	if !errors.Is(err, errs.ErrInvalidCredential) {
		t.Fatalf("not classified ErrInvalidCredential: %v", err)
	}
	var ib interface{ Error() string }
	_ = ib
	if bytes.ContainsRune([]byte(err.Error()), 1) || strings.Contains(err.Error(), "invalid byte") {
		t.Fatalf("the error echoes a credential byte: %q", err.Error())
	}
}
