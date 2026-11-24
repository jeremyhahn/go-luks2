// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package dm

import "errors"

// ErrNameTooLong indicates that a mapping name or UUID does not fit the
// DM_DEV_CREATE ioctl's fixed-width fields without being silently cut by the
// kernel. CreateTarget refuses rather than cut; the caller is expected to
// have already bounded the name with its own validation, and this is the
// belt-and-suspenders check behind that.
var ErrNameTooLong = errors.New("the device-mapper name or UUID does not fit the create ioctl without being cut")

// ErrNodeUnverified indicates that PlaceNode found something at path that is
// not a safe candidate to replace -- not a symlink or a block device -- or
// that a caller could not verify a newly placed node actually names the
// device it was meant to.
var ErrNodeUnverified = errors.New("no device node verifiably names the device-mapper target")
