// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Crypt segment validation: sector_size, iv_tweak and encryption go straight to a device-mapper ioctl, so they are checked when the header is read (limits per cryptsetup 2.7.0).

const (
	// MaxSegmentEncryptionLength bounds the cipher specification a header may hand to a kernel ioctl.
	MaxSegmentEncryptionLength = 128
)

// SegmentSectorSizes maps each accepted crypt-segment sector size (cryptsetup's 512 to 4096) to its uint64 table value, avoiding a conversion.
var SegmentSectorSizes = map[int]uint64{
	512:  512,
	1024: 1024,
	2048: 2048,
	4096: 4096,
}

// CryptSegmentParams is the validated crypt-segment geometry a dm-crypt table is built from, filled only by CryptTableParams.
type CryptSegmentParams struct {
	Encryption string
	IVTweak    uint64
	SectorSize uint64

	// Flags are the dm-crypt optional parameters the header's persistent
	// flags ask for; see persistentCryptFlags.
	Flags []string
}

// persistentCryptFlags are the config.flags passed to dm-crypt, in cryptsetup's order; allow-discards is deliberately not honored.
var persistentCryptFlags = []struct{ luks2, dm string }{
	{"same-cpu-crypt", "same_cpu_crypt"},
	{"submit-from-crypt-cpus", "submit_from_crypt_cpus"},
	{"no-read-workqueue", "no_read_workqueue"},
	{"no-write-workqueue", "no_write_workqueue"},
}

// cryptTableFlags returns the dm-crypt options config.flags asks for. A flag
// this package does not pass -- allow-discards, an integrity flag, one it does
// not know -- is ignored, as cryptsetup ignores a flag it does not know.
func cryptTableFlags(config *Config) []string {
	if config == nil {
		return nil
	}
	var flags []string
	for _, f := range persistentCryptFlags {
		if slices.Contains(config.Flags, f.luks2) {
			flags = append(flags, f.dm)
		}
	}
	return flags
}

// validateMetadataSegments validates every segment in sorted id order, so the error is stable.
func validateMetadataSegments(metadata *Metadata) error {
	for _, id := range slices.Sorted(maps.Keys(metadata.Segments)) {
		if err := validateSegment(id, metadata.Segments[id]); err != nil {
			return err
		}
	}
	return nil
}

// validateSegment checks one segment's geometry; non-crypt segments (reencryption's linear) are checked only for presence.
func validateSegment(id string, segment *Segment) error {
	if segment == nil {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf("%s is null", segmentLabel(id))}
	}
	if segment.Type != "crypt" {
		return nil
	}
	_, err := cryptSegmentChecks(id, segment)
	return err
}

// CryptTableParams validates a crypt segment for activation and returns its table parameters, refusing a segment that starts before the keyslots area ends.
func CryptTableParams(metadata *Metadata, id string, segment *Segment) (CryptSegmentParams, error) {
	geometry, err := configGeometry(metadata.Config)
	if err != nil {
		return CryptSegmentParams{}, err
	}
	offset, ok := parseNumberedUint64(segment.Offset)
	if !ok || offset < geometry.end() {
		detail := fmt.Sprintf("%s starts at offset %q, inside the %d bytes the header copies and keyslots area occupy; mapping it would expose them to the plaintext device",
			segmentLabel(id), segment.Offset, geometry.end())
		if ok && offset == 0 {
			detail = segmentLabel(id) + " is at offset 0, which is a detached header whose data lives on another device; this package does not activate detached headers"
		}
		return CryptSegmentParams{}, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: detail}
	}
	params, err := cryptSegmentChecks(id, segment)
	if err != nil {
		return params, err
	}
	params.Flags = cryptTableFlags(metadata.Config)
	return params, nil
}

// cryptSegmentChecks is what every read checks about a crypt segment's three
// device-mapper fields, returning them in the types the table wants.
func cryptSegmentChecks(id string, segment *Segment) (CryptSegmentParams, error) {
	label := segmentLabel(id)

	sectorSize, accepted := SegmentSectorSizes[segment.SectorSize]
	if !accepted {
		return CryptSegmentParams{}, &errs.Error{
			Kind: errs.ErrInvalidHeader,
			Detail: fmt.Sprintf("%s declares a sector size of %d; a LUKS2 crypt segment uses one of %s, and this value is handed to the device-mapper ioctl",
				label, segment.SectorSize, acceptedSectorSizes()),
		}
	}

	// A malformed iv_tweak is refused, never mapped to 0.
	ivTweak, err := strconv.ParseUint(segment.IVTweak, 10, 64)
	if err != nil {
		return CryptSegmentParams{}, &errs.Error{
			Kind: errs.ErrInvalidHeader,
			Detail: fmt.Sprintf("%s declares an iv_tweak of %q, which is not a decimal 64-bit unsigned integer",
				label, segment.IVTweak),
		}
	}

	if err := validateSegmentEncryption(label, segment.Encryption); err != nil {
		return CryptSegmentParams{}, err
	}

	return CryptSegmentParams{
		Encryption: segment.Encryption,
		IVTweak:    ivTweak,
		SectorSize: sectorSize,
	}, nil
}

// validateSegmentEncryption checks the cipher spec against a whitelist charset, since it becomes field zero of a space-delimited target spec.
func validateSegmentEncryption(label, encryption string) error {
	if encryption == "" {
		return &errs.Error{
			Kind: errs.ErrInvalidHeader,
			Detail: fmt.Sprintf("%s declares an empty cipher specification; a crypt segment names the cipher its data was written with",
				label),
		}
	}
	if len(encryption) > MaxSegmentEncryptionLength {
		return &errs.Error{
			Kind: errs.ErrInvalidHeader,
			Detail: fmt.Sprintf("%s declares a %d-byte cipher specification; the accepted maximum is %d, which is above the longest form LUKS2 can express",
				label, len(encryption), MaxSegmentEncryptionLength),
		}
	}
	for i := 0; i < len(encryption); i++ {
		if !isSegmentEncryptionByte(encryption[i]) {
			return &errs.Error{
				Kind: errs.ErrInvalidHeader,
				Detail: fmt.Sprintf("byte %d of the cipher specification %q declared by %s is not one of A-Z a-z 0-9 - _ . : ( ) , ; the value becomes the first field of a space-delimited device-mapper target specification, where a separator would shift the key reference and the backing device that follow it, so the permitted set is a whitelist",
					i, encryption, label),
			}
		}
	}
	return nil
}

func isSegmentEncryptionByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == ':' || c == '(' || c == ')' || c == ','
}

// segmentLabel names a segment in a message. The id may be empty for a segment
// reached by something other than its position in the header, and the phrasing
// degrades to "the crypt segment" rather than to `segment ""`.
func segmentLabel(id string) string {
	if id == "" {
		return "the crypt segment"
	}
	return fmt.Sprintf("segment %q", id)
}

// acceptedSectorSizes renders the whitelist in ascending order for error messages.
func acceptedSectorSizes() string {
	sizes := slices.Sorted(maps.Keys(SegmentSectorSizes))
	rendered := make([]string, 0, len(sizes))
	for _, size := range sizes {
		rendered = append(rendered, strconv.Itoa(size))
	}
	return strings.Join(rendered, ", ") + " (measured against cryptsetup 2.7.0)"
}
