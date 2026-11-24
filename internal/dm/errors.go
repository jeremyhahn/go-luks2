// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package dm

import "errors"

// ErrNameTooLong indicates a mapping name or UUID does not fit DM_DEV_CREATE's fixed-width fields.
var ErrNameTooLong = errors.New("the device-mapper name or UUID does not fit the create ioctl without being cut")

// ErrNodeUnverified indicates PlaceNode found something unsafe to replace at path, or a placed node could not be verified.
var ErrNodeUnverified = errors.New("no device node verifiably names the device-mapper target")
