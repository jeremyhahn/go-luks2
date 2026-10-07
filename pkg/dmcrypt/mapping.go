// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package dmcrypt

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"

	dmpkg "github.com/jeremyhahn/go-luks2/internal/dm"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

const pkgName = "dmcrypt"

// Mapping identifies a live device-mapper target. Lookup and a successful
// Activate are the only ways to obtain one.
type Mapping struct {
	Name  string
	UUID  string
	Major uint32
	Minor uint32
}

// Path is the conventional /dev/mapper/<name> entry for m. It is not
// re-verified against the kernel; Lookup is what confirms a mapping's
// identity, and it has already run by the time a caller holds an m.
func (m *Mapping) Path() string {
	return "/dev/mapper/" + m.Name
}

// MaxNameLength is the longest mapping name Activate accepts: the kernel's
// DM_NAME_LEN (128 bytes including the terminating NUL), less one byte so
// the name is never silently truncated on the way into the create ioctl.
const MaxNameLength = 127

// ValidateName validates a device-mapper mapping name.
//
// The rules cover the name reaching the dm ioctl's fixed-width field, the
// /dev/mapper/<name> path this package creates and removes, the dm UUID
// that proves a target belongs to one activation, and the kernel-keyring
// description derived from that UUID -- one whitelist for all of it. This
// was luks2.ValidateMappingName before B.6 moved it here (#268): pkg/luks2
// no longer has a mapping-name-shaped call site of its own.
func ValidateName(name string) error {
	if name == "" {
		return &errs.Error{Kind: ErrInvalidName, Detail: "the name is empty"}
	}
	if len(name) > MaxNameLength {
		return &errs.Error{
			Kind: ErrInvalidName,
			Detail: fmt.Sprintf("%d bytes exceeds the %d the device-mapper ioctl can carry without truncation",
				len(name), MaxNameLength),
		}
	}

	// A leading dash would be read as an option by the command lines this
	// library's own error messages tell an operator to run, and "." and ".."
	// are directory entries rather than names.
	if name == "." || name == ".." {
		return &errs.Error{
			Kind:   ErrInvalidName,
			Detail: fmt.Sprintf("%q is a directory entry, not a name", name),
		}
	}
	// /dev/mapper/control is device-mapper's own control node. A mapping
	// called "control" would make /dev/mapper/<name> that node, and the node
	// repair after an unlock would replace it (#250).
	if name == "control" {
		return &errs.Error{Kind: ErrInvalidName, Detail: `"control" names the device-mapper control node`}
	}
	if first := name[0]; !isMappingNameStart(first) {
		return &errs.Error{
			Kind:   ErrInvalidName,
			Detail: fmt.Sprintf("%q must start with a letter or a digit", name),
		}
	}

	for i := 0; i < len(name); i++ {
		if !isMappingNameByte(name[i]) {
			return &errs.Error{
				Kind: ErrInvalidName,
				Detail: fmt.Sprintf("byte %d of %q is not one of A-Z a-z 0-9 _ . + -; a device-mapper name reaches a /dev path and a space-delimited target specification, so the permitted set is a whitelist",
					i, name),
			}
		}
	}

	return nil
}

// isMappingNameStart and isMappingNameByte are ValidateName's character
// whitelist: isMappingNameStart for the first byte, isMappingNameByte for
// every byte including it.
func isMappingNameStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isMappingNameByte(c byte) bool {
	return isMappingNameStart(c) || c == '_' || c == '.' || c == '+' || c == '-'
}

// Lookup reports the live mapping named name, or ErrNotActive if
// device-mapper has no target under that name.
func Lookup(ctx context.Context, name string) (*Mapping, error) {
	const op = "Lookup"
	if err := ctxErr(ctx); err != nil {
		return nil, errs.At(pkgName, op, "", err)
	}
	if err := ValidateName(name); err != nil {
		return nil, errs.At(pkgName, op, "", err)
	}

	info, err := sys.infoByName(name)
	if err != nil {
		if dmpkg.IsNoSuchDevice(err) {
			return nil, errs.At(pkgName, op, "", &errs.Error{Kind: ErrNotActive,
				Detail: fmt.Sprintf("no device-mapper mapping named %q exists", name)})
		}
		return nil, errs.At(pkgName, op, "", &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "inspect the device-mapper target of " + name, Err: err})
	}

	major, minor := unix.Major(info.DevNo), unix.Minor(info.DevNo)
	return &Mapping{Name: name, UUID: info.UUID, Major: major, Minor: minor}, nil
}

// ctxErr reports ctx's own error, classified as DESIGN.md §C.2 rule 5
// requires: Kind is ctx.Err() itself, so errors.Is(err,
// context.DeadlineExceeded) holds.
func ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &errs.Error{Kind: err}
	}
	return nil
}
