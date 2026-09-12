// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"os"
	"testing"
)

// requireRoot fails the calling test when it is not running as uid 0, and
// does so LOUDLY: this tier exists to exercise the device-mapper, loop and
// mount syscalls a non-root process cannot reach, so a bare uid check that
// quietly skips converts "root was not available" into a pass, and the
// whole reason this tier is privileged is so that is never true.
//
// Both sanctioned ways to run this tier already hand out uid 0:
// test/integration/docker-run.sh starts the image with no --user, so the
// container is root by default, and `make host-integration-test` /
// `make coverage` re-exec themselves under sudo when the calling shell is
// not root already (see Makefile). So reaching this branch means one of
// those two paths was bypassed -- `go test -tags=integration` was invoked
// directly from a non-root shell -- and it says so, instead of letting the
// first syscall that needs CAP_SYS_ADMIN fail with an opaque "operation not
// permitted" three calls deep into the test body.
func requireRoot(t *testing.T) {
	t.Helper()

	if uid := os.Getuid(); uid != 0 {
		t.Fatalf("THIS INTEGRATION TEST REQUIRES ROOT -- running as uid %d. "+
			"Use `make integration-test` (Docker, root by default) or "+
			"`make host-integration-test` (re-execs under sudo); do not invoke "+
			"`go test -tags=integration` directly from a non-root shell.", uid)
	}
}
