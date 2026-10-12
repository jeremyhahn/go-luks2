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

// Validation of the crypt segment a device declares about itself.
//
// # What an unvalidated segment does
//
// Three of a segment's declared fields are handed STRAIGHT to a device-mapper
// ioctl, and none of them was checked before this file existed (#40). Measured
// against this package on main, by crafting a segment through the library's own
// writer and driving the real unlock path:
//
//	sector_size = -1                ReadHeader accepted it, and the dm-crypt
//	                                table received 18446744073709551615.
//	                                devmapper then renders that with
//	                                strconv.Itoa(int(...)), so the target flag
//	                                reads "sector_size:-1"
//	iv_tweak = "not-a-number"       ReadHeader accepted it, and the table
//	                                received 0 -- a VALID-LOOKING tweak. The
//	                                mapping is created at the wrong IV offset
//	                                rather than refused
//	encryption = "aes-xts-plain64 " ReadHeader accepted it, the table received
//	  ":32:logon:attacker 0 ..."    it verbatim, and the unlock SUCCEEDED
//
// The last one is the sharpest, and the issue did not name it. devmapper builds
// the crypt target specification by joining
//
//	<cipher> <key> <iv_offset> <device> <start>
//
// with SPACES (devmapper.go crypt.go, CryptTable.buildSpec). The cipher is field
// zero, so a space inside it shifts every field after it: a header can nominate
// the key reference the kernel resolves and the block device the target is
// backed by. That is the same positional-grammar hazard dmcrypt.ValidateName
// exists for, on an input the caller does not choose.
//
// # Why the sector-size suppression was worse than no comment
//
// The conversion carried a G115 suppression justified as "sector size is
// validated (512 or 4096)". The only sector-size validation in the package is
// in ValidateFormatOptions, which checks the value a CALLER passes to Format.
// It has never applied to a segment read off a device. So a gosec finding was
// silenced by a justification that was not true of the code it annotated --
// and an annotation is precisely what stops the next reader checking. There is
// no suppression here now, and none is needed: the conversion is gone, replaced
// by a lookup in a whitelist whose values are already uint64.
//
// # Why this is a header refusal and keyslot validation is not
//
// ValidateKeyslot refuses a keyslot rather than a header, because a LUKS2
// container carries up to 32 keyslots so that damage to one is survivable, and
// converting a damaged unused slot into an unopenable volume is data loss
// manufactured by a safety check.
//
// A segment has no such redundancy. It IS the volume's data, and a segment
// whose geometry is wrong cannot be worked around by trying another one -- the
// same reasoning by which the JSON parse already REJECTS a null segment while
// merely dropping a null keyslot. So these failures are ErrInvalidHeader, they
// are raised where the metadata is parsed, and every consumer inherits them
// rather than restating a bound.
//
// # Where the limits come from
//
// Measured against cryptsetup 2.7.0, not invented, and not copied from this
// package's own writer -- a bound that refuses a container another
// implementation can create is its own kind of defect.

const (
	// MaxSegmentEncryptionLength bounds the cipher specification a header may
	// hand to a kernel ioctl.
	//
	// The charset check is the load-bearing half; this is the other one. An
	// unbounded string out of an untrusted header has no business reaching a
	// kernel interface whatever it contains.
	//
	// 128 is comfortably above anything the format can express. The longest
	// spelling LUKS2 permits is the kernel-crypto-API form --
	// "capi:authenc(hmac(sha256),xts(aes))-plain64", 43 bytes -- and the
	// ordinary form this package and cryptsetup write,
	// "aes-xts-plain64"/"aes-cbc-essiv:sha256", is 15 to 20.
	MaxSegmentEncryptionLength = 128
)

// SegmentSectorSizes is the whitelist of crypt-segment sector sizes, mapping
// each accepted value to the uint64 the device-mapper table carries.
//
// It is a map rather than a range check FOR that mapping. The header field is
// an int and the table field is a uint64, and looking the value up is what
// relates the two without a conversion: `uint64(segment.SectorSize)` is how a
// declared -1 became 18446744073709551615, and there is no conversion left to
// get wrong or to suppress.
//
// The four values are measured against cryptsetup 2.7.0: --sector-size accepts
// 512, 1024, 2048 and 4096, refuses 256 and 8192, and each accepted value was
// read back out of the header it wrote. ValidateFormatOptions imposes a
// narrower 512-or-4096 on this package's own WRITER, which is a choice about
// what we emit; imposing it on the READ path would refuse two containers
// cryptsetup can create.
var SegmentSectorSizes = map[int]uint64{
	512:  512,
	1024: 1024,
	2048: 2048,
	4096: 4096,
}

// CryptSegmentParams is the crypt-segment geometry a dm-crypt table is built
// from, in the types the table wants.
//
// Its fields are filled by CryptTableParams and by nothing else, and
// unlockLoadTable takes one of these instead of a *Segment. That is what makes
// the values validated by construction: there is no route from a header field
// to the ioctl that does not pass through the validator.
type CryptSegmentParams struct {
	Encryption string
	IVTweak    uint64
	SectorSize uint64

	// Flags are the dm-crypt optional parameters the header's persistent
	// flags ask for; see persistentCryptFlags.
	Flags []string
}

// persistentCryptFlags are the LUKS2 config.flags this package passes to
// dm-crypt, in the order cryptsetup puts them in the table, each with its
// dm-crypt option name. They are the performance flags `cryptsetup open
// --perf-* --persistent` stores; they change how dm-crypt schedules its work
// and nothing about the bytes on the medium.
//
// allow-discards is deliberately NOT here. cryptsetup honors it; this package
// does not, because the header is untrusted input and the flag is a
// disclosure: with it, TRIM through the mapping reveals which blocks are free
// to anyone who can read the medium, and a header edit -- by anyone who has
// had the disk -- is all it takes to switch it on. The volume opens and reads
// and writes the same bytes either way (docs/cryptsetup-interop/architecture.md).
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

// validateMetadataSegments validates every segment in parsed metadata, and is
// called once where the header is read.
//
// Segments are visited in sorted id order so that a container with more than
// one bad segment reports the same one every time. Go randomizes map iteration,
// and an error message that changes between runs on identical input is the
// shape that made #54 and #57 hard to see.
func validateMetadataSegments(metadata *Metadata) error {
	for _, id := range slices.Sorted(maps.Keys(metadata.Segments)) {
		if err := validateSegment(id, metadata.Segments[id]); err != nil {
			return err
		}
	}
	return nil
}

// validateSegment checks one segment's declared geometry.
//
// A segment whose type is not "crypt" is checked only for presence. LUKS2 uses
// a "linear" segment to describe the untouched half of a container being
// reencrypted; it declares no cipher, no IV tweak and no sector size, so
// imposing the crypt rules on it would make a container mid-reencryption
// unreadable -- including by GetVolumeInfo, which is what an operator reaches
// for when something is wrong. Same reasoning as ValidateKeyslot's treatment of
// a "reencrypt" keyslot.
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

// CryptTableParams validates a crypt segment of metadata for ACTIVATION and
// returns the parameters the device-mapper table is built from.
//
// It is the only way those three values are obtained. Unlock calls it for the
// segment it selected, and the header read applies the same checks to every
// segment through validateSegment, so a value that reaches the ioctl has been
// through here whether the caller remembered or not.
//
// On top of what the read path checks, it refuses a segment that starts before
// the end of the keyslots area (#248). A plaintext mapping over the header
// copies or the keyslots would hand them to whatever is written to the volume:
// the first filesystem write destroys every keyslot. cryptsetup reads such a
// header only as a DETACHED one, at offset 0, whose data lives on another
// device; this package maps the data on the device that carries the header, so
// it has no detached form to offer and refuses that too.
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

	// The error was DISCARDED here before #40, which mapped every malformed
	// value to 0 -- an IV offset that looks entirely legitimate, so the mapping
	// was created at the wrong offset rather than refused. A wrong IV offset
	// decrypts to garbage, and a caller that was told the unlock succeeded has
	// no reason to suspect the header.
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

// validateSegmentEncryption checks the cipher specification a segment declares.
//
// The charset is a WHITELIST for the same reason dmcrypt.ValidateName's is: the
// value becomes field zero of a space-delimited positional target
// specification, and enumerating which bytes such a grammar considers harmless
// is the kind of list that is always one character short.
//
// The permitted set is what a cipher specification contains: alphanumerics for
// the algorithm and mode names, "-" between them, ":" before an IV hash or a
// capi prefix, "()" and "," for the kernel-crypto-API form, and "_" and "."
// which appear in kernel algorithm names.
//
// Two of those are measured and the rest are read from the grammar, which is
// worth stating rather than blurring. "aes-xts-plain64" and
// "aes-cbc-essiv:sha256" were formatted with cryptsetup 2.7.0 on this host and
// read back out of the header it wrote. The capi form could NOT be measured
// here: cryptsetup probes the kernel crypto API for it and so demands a real
// loop device, which needs root, and it refuses to format a plain file. It is
// admitted from the documented cipher-specification grammar in cryptsetup(8)
// -- capi:cipher_api_spec-ivmode -- because a whitelist that refuses a legal
// container is the defect this package keeps measuring, and a comma inside
// parentheses cannot separate anything in a space-delimited target spec.
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

// acceptedSectorSizes renders the whitelist for an error message, in ascending
// order, so the refusal carries the remedy and not only the verdict. It is
// derived from the map rather than written out, so the message cannot drift
// from what the code accepts.
func acceptedSectorSizes() string {
	sizes := slices.Sorted(maps.Keys(SegmentSectorSizes))
	rendered := make([]string, 0, len(sizes))
	for _, size := range sizes {
		rendered = append(rendered, strconv.Itoa(size))
	}
	return strings.Join(rendered, ", ") + " (measured against cryptsetup 2.7.0)"
}
