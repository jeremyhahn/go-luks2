// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package makefile holds regression tests for the repository's Makefile.
//
// The Makefile is the one entry point both developers and CI drive every gate
// through, and some of its defects exit zero: #205 printed a spurious
// diagnostic on every invocation without failing anything, so ordinary
// build/test success can never catch its return. The tests here run GNU make
// against the real Makefile and assert on what it prints.
package makefile
