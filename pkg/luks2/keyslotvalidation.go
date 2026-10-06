// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Keyslot geometry and KDF-cost validation now live in internal/header; see
// docs/design/DECISIONS.md's H5 entry. These are transitional forwards, kept
// under their original names so every existing caller and test in this
// package keeps compiling unchanged. They are removed at H13.
const (
	MaxKeyslotKeySize  = header.MaxKeyslotKeySize
	maxKeyslotAreaSize = header.MaxKeyslotAreaSize
	maxKeyslotStripes  = header.MaxKeyslotStripes

	minKDFIterations = header.MinKDFIterations
	maxKDFIterations = header.MaxKDFIterations

	minArgon2Time = header.MinArgon2Time
	maxArgon2Time = header.MaxArgon2Time

	minArgon2Memory = header.MinArgon2Memory
	maxArgon2Memory = header.MaxArgon2Memory

	minArgon2Parallel = header.MinArgon2Parallel
	maxArgon2Parallel = header.MaxArgon2Parallel
)

// validateKeyslot forwards to header.ValidateKeyslot. See keyslot.go's
// callers.
var validateKeyslot = header.ValidateKeyslot

// validateKDFCost forwards to header.ValidateKDFCost.
var validateKDFCost = header.ValidateKDFCost
