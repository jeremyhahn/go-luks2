// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// parseSize converts create's <size> argument: a positive whole number with
// an optional K, M, G or T suffix (powers of 1024, either case). No suffix
// means bytes.
func parseSize(command, s string) (int64, error) {
	if len(s) == 0 {
		return 0, &UsageError{Command: command, Detail: "empty size"}
	}

	multiplier := int64(1)
	valueStr := s
	switch s[len(s)-1] {
	case 'K', 'k':
		multiplier = 1 << 10
	case 'M', 'm':
		multiplier = 1 << 20
	case 'G', 'g':
		multiplier = 1 << 30
	case 'T', 't':
		multiplier = 1 << 40
	}
	if multiplier != 1 {
		valueStr = s[:len(s)-1]
	}

	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil || value <= 0 || strings.HasPrefix(valueStr, "+") {
		return 0, &UsageError{Command: command, Detail: fmt.Sprintf("invalid size %q: want a positive whole number with an optional K, M, G or T suffix", s)}
	}
	if value > math.MaxInt64/multiplier {
		return 0, &UsageError{Command: command, Detail: fmt.Sprintf("size %q is too large", s)}
	}

	return value * multiplier, nil
}
