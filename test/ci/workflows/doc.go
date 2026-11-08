// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package workflows holds regression tests for .github/workflows (#247).
//
// The workflows decide what reaches main and what is published, and most of
// their defects pass quietly: an action pinned to a moving tag, or a release that
// does not wait for CI. Each of these merges and publishes with every check
// green. The tests read the workflow files the forge runs.
package workflows
