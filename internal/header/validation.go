// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Structural validator following cryptsetup 2.7.0's LUKS2_hdr_validate in order; every rule runs before a write, header-wide rules on read (per-keyslot and per-token damage is refused where used).
// Stricter than cryptsetup: json_size and keyslots_size must be decimal digits, and token keyslot references must be canonical ids.

// headerStructureError reports a header that breaks a LUKS2 structural rule.
// It is ErrInvalidHeader, so every caller that already classifies a malformed
// header keeps doing so.
func headerStructureError(format string, args ...any) error {
	return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf(format, args...)}
}

// ValidateHeaderStructure checks metadata, whose header area is hdrSize bytes,
// against every structural rule cryptsetup applies on read. See the file
// comment for what it covers.
func ValidateHeaderStructure(hdrSize int, metadata *Metadata) error {
	return runStructureChecks(hdrSize, metadata, true)
}

// ValidateHeaderWideStructure is ValidateHeaderStructure without the rules
// about a single keyslot or token: what the read path refuses a header for.
// See "Where it runs" above.
func ValidateHeaderWideStructure(hdrSize int, metadata *Metadata) error {
	return runStructureChecks(hdrSize, metadata, false)
}

// structureChecks is LUKS2_hdr_validate's list, in its order. perEntry marks
// the rules about one keyslot or one token.
var structureChecks = []struct {
	check    func(*Metadata) error
	perEntry bool
}{
	{validateObjectCounts, false},
	{validateRequirementsStructure, false},
	{validateTokensStructure, true},
	{validateDigestsStructure, false},
	{validateSegmentsStructure, false},
	{validateKeyslotsStructure, true},
	{validateConfigStructure, false},
	{validateKeyslotAreasStructure, true},
	{validateKeyslotAssignmentStructure, true},
}

func runStructureChecks(hdrSize int, metadata *Metadata, perEntry bool) error {
	if metadata == nil {
		return headerStructureError("the header carries no JSON metadata")
	}
	for _, c := range structureChecks {
		if c.perEntry && !perEntry {
			continue
		}
		if err := c.check(metadata); err != nil {
			return err
		}
	}
	return validateJSONSizeStructure(hdrSize, metadata)
}

// numbered is cryptsetup's numbered(): every byte a decimal digit. The empty
// string qualifies, as it does there.
func numbered(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseNumberedUint64 parses a member cryptsetup reads with numbered() and
// json_str_to_uint64: non-empty decimal digits that fit 64 bits.
func parseNumberedUint64(s string) (uint64, bool) {
	if s == "" || !numbered(s) {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// SortedIDs returns a map's keys in sorted order, so a header with more than
// one fault reports the same one every time.
func SortedIDs[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// validateRequirementsStructure is hdr_validate_requirements: at most one entry names an online reencryption.
func validateRequirementsStructure(metadata *Metadata) error {
	if metadata.Config == nil || metadata.Config.Requirements == nil {
		return nil
	}
	count := 0
	for _, flag := range metadata.Config.Requirements.Mandatory {
		if isReencryptCandidateFlag(flag) {
			count++
		}
	}
	if count > 1 {
		return headerStructureError("config.requirements.mandatory names %d online reencryptions; a LUKS2 header may name at most one", count)
	}
	return nil
}

// isReencryptCandidateFlag is cryptsetup's reencrypt_candidate_flag:
// "online-reencrypt", or "online-reencrypt-v" followed by one or more digits.
func isReencryptCandidateFlag(flag string) bool {
	if flag == "online-reencrypt" {
		return true
	}
	version, ok := strings.CutPrefix(flag, "online-reencrypt-v")
	return ok && version != "" && numbered(version)
}

// validateTokensStructure is hdr_validate_tokens and LUKS2_token_validate.
func validateTokensStructure(metadata *Metadata) error {
	for _, id := range SortedIDs(metadata.Tokens) {
		if !numbered(id) {
			return headerStructureError("token id %q is not a number", id)
		}
		token := metadata.Tokens[id]
		if token == nil {
			return headerStructureError("token %q is null", id)
		}
		if token.Type == "" {
			return headerStructureError("token %q declares no type", id)
		}
		if token.Keyslots == nil {
			return headerStructureError("token %q has no keyslots array; LUKS2 requires one, empty when the token names no keyslot", id)
		}
		for _, ref := range token.Keyslots {
			if _, ok := CanonicalKeyslotID(ref); !ok {
				return headerStructureError("token %q references keyslot %q, which is not a canonical keyslot id (0..%d)", id, ref, MaxKeyslots-1)
			}
			if _, exists := metadata.Keyslots[ref]; !exists {
				return headerStructureError("token %q references keyslot %q, which the header does not have", id, ref)
			}
		}
	}
	return nil
}

// validateObjectCounts holds keyslots and digests to MaxKeyslots entries each, refused on read.
func validateObjectCounts(metadata *Metadata) error {
	if n := len(metadata.Keyslots); n > MaxKeyslots {
		return headerStructureError("the header declares %d keyslots; cryptsetup creates at most %d", n, MaxKeyslots)
	}
	if n := len(metadata.Digests); n > MaxKeyslots {
		return headerStructureError("the header declares %d digests; cryptsetup creates at most one per keyslot, %d", n, MaxKeyslots)
	}
	return nil
}

// validateDigestsStructure is hdr_validate_digests: every digest has a type, keyslots and segments arrays, and names only existing keyslots and segments.
func validateDigestsStructure(metadata *Metadata) error {
	for _, id := range SortedIDs(metadata.Digests) {
		if !numbered(id) {
			return headerStructureError("digest id %q is not a number", id)
		}
		digest := metadata.Digests[id]
		if digest == nil {
			return headerStructureError("digest %q is null", id)
		}
		if digest.Type == "" {
			return headerStructureError("digest %q declares no type", id)
		}
		if digest.Keyslots == nil || digest.Segments == nil {
			return headerStructureError("digest %q must carry a keyslots array and a segments array", id)
		}
		for _, ref := range digest.Keyslots {
			if _, exists := metadata.Keyslots[ref]; !exists {
				return headerStructureError("digest %q references keyslot %q, which the header does not have", id, ref)
			}
		}
		for _, ref := range digest.Segments {
			if _, exists := metadata.Segments[ref]; !exists {
				return headerStructureError("digest %q references segment %q, which the header does not have", id, ref)
			}
		}
	}
	return nil
}

// segmentGeometry is one segment's offset and size as cryptsetup reads them.
// size 0 means "dynamic": to the end of the device.
type segmentGeometry struct {
	offset, size uint64
	backup       bool
}

// validateSegmentsStructure is hdr_validate_segments: the per-segment rules,
// then the layout of the segments as a whole.
func validateSegmentsStructure(metadata *Metadata) error {
	if len(metadata.Segments) == 0 {
		return headerStructureError("the header declares no segments")
	}
	firstBackup := -1
	geometry := make(map[int]segmentGeometry, len(metadata.Segments))
	for _, id := range SortedIDs(metadata.Segments) {
		g, index, err := validateOneSegment(metadata, id, len(metadata.Segments))
		if err != nil {
			return err
		}
		geometry[index] = g
		if g.backup && (firstBackup < 0 || index < firstBackup) {
			firstBackup = index
		}
	}
	// A regular segment numbered at or above a backup one. cryptsetup checks
	// this in key order as it goes; checked here over all of them, which
	// refuses exactly the same headers.
	for index, g := range geometry {
		if !g.backup && firstBackup >= 0 && index >= firstBackup {
			return headerStructureError("regular segment %d is numbered after backup segment %d", index, firstBackup)
		}
	}
	return validateSegmentLayout(metadata, geometry, firstBackup)
}

// validateOneSegment applies the per-segment rules to segment id, one of count
// segments, and returns its geometry and numeric index.
func validateOneSegment(metadata *Metadata, id string, count int) (segmentGeometry, int, error) {
	if !numbered(id) {
		return segmentGeometry{}, 0, headerStructureError("segment id %q is not a number", id)
	}
	// cryptsetup looks segments up by the canonical spelling of 0..count-1,
	// so count segments must be exactly those ids: any other spelling ("00"),
	// or any id from count up, leaves one of them missing -- a gap.
	index, err := strconv.Atoi(id)
	if err != nil || strconv.Itoa(index) != id || index >= count {
		return segmentGeometry{}, 0, headerStructureError("segment id %q leaves a gap in the segments object, whose %d ids must be 0 to %d", id, count, count-1)
	}
	segment := metadata.Segments[id]
	if segment == nil {
		return segmentGeometry{}, 0, headerStructureError("%s is null", segmentLabel(id))
	}
	if segment.Type == "" || segment.Offset == "" || segment.Size == "" {
		return segmentGeometry{}, 0, headerStructureError("%s must declare a type, an offset and a size", segmentLabel(id))
	}
	offset, ok := parseNumberedUint64(segment.Offset)
	if !ok {
		return segmentGeometry{}, 0, headerStructureError("%s declares offset %q, which is not a decimal 64-bit byte offset", segmentLabel(id), segment.Offset)
	}
	var size uint64
	if segment.Size != "dynamic" {
		if size, ok = parseNumberedUint64(segment.Size); !ok || size == 0 {
			return segmentGeometry{}, 0, headerStructureError("%s declares size %q; a segment size is \"dynamic\" or a positive decimal byte count", segmentLabel(id), segment.Size)
		}
	}
	// Every device-mapper device is addressed in 512-byte sectors, so an
	// offset or size off that grid would be silently rounded by the kernel.
	if offset%SectorSize != 0 || size%SectorSize != 0 {
		return segmentGeometry{}, 0, headerStructureError("%s offset %d and size %d must both be multiples of %d bytes", segmentLabel(id), offset, size, SectorSize)
	}
	flags, err := segmentFlags(id, segment)
	if err != nil {
		return segmentGeometry{}, 0, err
	}
	g := segmentGeometry{offset: offset, size: size, backup: hasFlagPrefix(flags, "backup-")}

	switch {
	case segment.Type == "crypt":
		err = validateCryptSegmentStructure(metadata, id, segment, size)
	case strings.HasPrefix(segment.Type, "hw-opal"):
		err = validateOpalSegmentStructure(metadata, id, segment, size)
	}
	return g, index, err
}

// segmentFlags returns a segment's optional flags member, which must be an
// array of strings. Segment does not model it, so it is read from the members
// carried through unmodeled.
func segmentFlags(id string, segment *Segment) ([]string, error) {
	raw, present := segment.unknown["flags"]
	if !present {
		return nil, nil
	}
	var flags []string
	if err := json.Unmarshal(raw, &flags); err != nil || flags == nil {
		return nil, headerStructureError("%s declares flags that are not an array of strings", segmentLabel(id))
	}
	return flags, nil
}

func hasFlagPrefix(flags []string, prefix string) bool {
	return slices.ContainsFunc(flags, func(f string) bool { return strings.HasPrefix(f, prefix) })
}

// validateCryptSegmentStructure is hdr_validate_crypt_segment.
func validateCryptSegmentStructure(metadata *Metadata, id string, segment *Segment, size uint64) error {
	label := segmentLabel(id)
	if segment.IVTweak == "" {
		return headerStructureError("%s declares an empty iv_tweak", label)
	}
	if segment.Encryption == "" {
		return headerStructureError("%s declares an empty cipher specification", label)
	}
	if raw, present := segment.unknown["integrity"]; present {
		var integrity map[string]json.RawMessage
		if err := json.Unmarshal(raw, &integrity); err != nil || integrity == nil {
			return headerStructureError("%s declares an integrity member that is not an object", label)
		}
		for _, member := range []string{"type", "journal_encryption", "journal_integrity"} {
			var s string
			if err := json.Unmarshal(integrity[member], &s); err != nil || s == "" {
				return headerStructureError("%s integrity must declare %s", label, member)
			}
		}
		// LUKS2 On-Disk Format 1.1.4: key_size [integer,optional]. The text
		// gives the type and no range.
		if keySize, present := integrity["key_size"]; present && !isJSONInteger(keySize) {
			return headerStructureError("%s integrity must declare an integer key_size when it declares one", label)
		}
	}
	if segment.SectorSize <= 0 || int64(segment.SectorSize) > math.MaxUint32 || segment.SectorSize%SectorSize != 0 {
		return headerStructureError("%s declares a sector size of %d, which is not a positive multiple of %d", label, segment.SectorSize, SectorSize)
	}
	if _, ok := parseNumberedUint64(segment.IVTweak); !ok {
		return headerStructureError("%s declares an iv_tweak of %q, which is not a decimal 64-bit unsigned integer", label, segment.IVTweak)
	}
	if size%uint64(segment.SectorSize) != 0 { // #nosec G115 -- checked positive above
		return headerStructureError("%s size %d is not a multiple of its sector size %d", label, size, segment.SectorSize)
	}
	for _, digest := range metadata.Digests {
		if digest != nil && slices.Contains(digest.Segments, id) {
			return nil
		}
	}
	return headerStructureError("%s is not assigned to any digest, so no key can be verified for it", label)
}

// validateOpalSegmentStructure is the hw-opal branch of hdr_validate_segments.
func validateOpalSegmentStructure(metadata *Metadata, id string, segment *Segment, size uint64) error {
	label := segmentLabel(id)
	if size == 0 {
		return headerStructureError("%s of type %s cannot have a dynamic size", label, segment.Type)
	}
	for _, name := range []string{"opal_segment_number", "opal_key_size"} {
		if !isJSONInteger(segment.unknown[name]) {
			return headerStructureError("%s must declare an integer %s", label, name)
		}
	}
	var opalSizeText string
	if err := json.Unmarshal(segment.unknown["opal_segment_size"], &opalSizeText); err != nil {
		return headerStructureError("%s must declare opal_segment_size as a string", label)
	}
	opalSize, ok := parseNumberedUint64(opalSizeText)
	if !ok || opalSize == 0 {
		return headerStructureError("%s declares opal_segment_size %q, which is not a positive decimal byte count", label, opalSizeText)
	}
	if size > opalSize {
		return headerStructureError("%s size %d overflows its OPAL locking range of %d bytes", label, size, opalSize)
	}
	if segment.Type == "hw-opal-crypt" {
		return validateCryptSegmentStructure(metadata, id, segment, size)
	}
	return nil
}

// isJSONInteger reports whether raw is a JSON number with no fraction or
// exponent that fits 64 bits: what json-c types as json_type_int. A quoted
// number is a string, and is not one.
func isJSONInteger(raw json.RawMessage) bool {
	if len(raw) == 0 || raw[0] == '"' {
		return false
	}
	_, err := strconv.ParseInt(string(raw), 10, 64)
	return err == nil
}

// validateSegmentLayout: regular segments 0..n-1 then backups, gap-free, non-overlapping, only the last dynamic, and reencryption backups present.
func validateSegmentLayout(metadata *Metadata, geometry map[int]segmentGeometry, firstBackup int) error {
	count := len(geometry) // every id is canonical and below the count, so none collided
	if firstBackup == 0 {
		return headerStructureError("the header declares no regular segment, only backups")
	}
	if firstBackup >= count {
		return headerStructureError("the segments object has a gap before backup segment %d", firstBackup)
	}
	if firstBackup < 0 {
		firstBackup = count
	}
	for i := 0; i < count; i++ {
		if _, ok := geometry[i]; !ok {
			return headerStructureError("the segments object has a gap at segment %d", i)
		}
	}
	for i := 0; i < firstBackup; i++ {
		a := geometry[i]
		if a.size == 0 && i != firstBackup-1 {
			return headerStructureError("segment %d is dynamic; only the last regular segment may run to the end of the device", i)
		}
		for j := 0; j < firstBackup; j++ {
			if i == j {
				continue
			}
			b := geometry[j]
			if b.size != 0 && b.offset > math.MaxUint64-b.size {
				return headerStructureError("segment %d offset plus size overflows", j)
			}
			if a.offset >= b.offset && (b.size == 0 || a.offset < b.offset+b.size) {
				return headerStructureError("segments %d and %d overlap", i, j)
			}
		}
	}
	return validateReencryptSegments(metadata, firstBackup, count)
}

// OnlineReencryptRequirements are the requirement names cryptsetup maps to
// CRYPT_REQUIREMENT_ONLINE_REENCRYPT.
var OnlineReencryptRequirements = []string{"online-reencrypt", "online-reencrypt-v2", "online-reencrypt-v3"}

// validateReencryptSegments is validate_reencrypt_segments: a header in online
// reencryption keeps a backup-final and a backup-previous segment, and every
// regular segment matches one of them.
func validateReencryptSegments(metadata *Metadata, firstBackup, count int) error {
	if metadata.Config == nil || metadata.Config.Requirements == nil ||
		!slices.ContainsFunc(metadata.Config.Requirements.Mandatory, func(r string) bool {
			return slices.Contains(OnlineReencryptRequirements, r)
		}) {
		return nil
	}
	var final, previous *Segment
	for i := firstBackup; i < count; i++ {
		id := strconv.Itoa(i)
		flags, _ := segmentFlags(id, metadata.Segments[id]) // validated per segment already
		switch {
		case slices.Contains(flags, "backup-final"):
			final = metadata.Segments[id]
		case slices.Contains(flags, "backup-previous"):
			previous = metadata.Segments[id]
		}
	}
	if final == nil || previous == nil {
		return headerStructureError("the header is in online reencryption but lacks its backup-final or backup-previous segment")
	}
	for i := 0; i < firstBackup; i++ {
		id := strconv.Itoa(i)
		segment := metadata.Segments[id]
		flags, _ := segmentFlags(id, segment)
		if slices.Contains(flags, "in-reencryption") {
			if !segmentsMatch(segment, final) {
				return headerStructureError("segment %d is in reencryption but does not match the backup-final segment", i)
			}
			continue
		}
		if !segmentsMatch(segment, final) && !segmentsMatch(segment, previous) {
			return headerStructureError("segment %d matches neither the backup-final nor the backup-previous segment", i)
		}
	}
	return nil
}

// segmentsMatch is json_segment_cmp: the same type and, for a crypt segment,
// the same sector size and cipher.
func segmentsMatch(a, b *Segment) bool {
	if a.Type != b.Type {
		return false
	}
	if a.Type == "crypt" {
		return a.SectorSize == b.SectorSize && a.Encryption == b.Encryption
	}
	return true
}

// validateKeyslotsStructure is hdr_validate_keyslots and LUKS2_keyslot_validate:
// a numeric id, a type, and a key_size that fits a uint32.
func validateKeyslotsStructure(metadata *Metadata) error {
	for _, id := range SortedIDs(metadata.Keyslots) {
		if !numbered(id) {
			return headerStructureError("keyslot id %q is not a number", id)
		}
		// A non-canonical keyslot id refuses the header; ids 32 and above are read.
		if n, err := strconv.ParseUint(id, 10, 64); err != nil || strconv.FormatUint(n, 10) != id {
			return headerStructureError("keyslot id %q is not the canonical spelling of a number", id)
		}
		keyslot := metadata.Keyslots[id]
		if keyslot == nil {
			return headerStructureError("keyslot %q is null", id)
		}
		if keyslot.Type == "" {
			return headerStructureError("keyslot %q declares no type", id)
		}
		if keyslot.KeySize < 0 || int64(keyslot.KeySize) > math.MaxUint32 {
			return headerStructureError("keyslot %q declares key_size %d, which is not a 32-bit unsigned integer", id, keyslot.KeySize)
		}
	}
	return nil
}

// headerGeometry is the area a header occupies at the start of the device, as
// its config declares it.
type headerGeometry struct {
	// metadataSize is one header copy: the binary header plus its JSON area.
	metadataSize uint64
	// keyslotsSize is the keyslots area, which starts at 2*metadataSize.
	keyslotsSize uint64
}

// end is where the keyslots area ends: the first byte past everything the
// header owns.
func (g headerGeometry) end() uint64 { return 2*g.metadataSize + g.keyslotsSize }

// configGeometry parses the sizes config declares. It is the parse
// validateConfigStructure performs, so the activation path can measure the
// header with the same rules the read path enforced.
func configGeometry(config *Config) (headerGeometry, error) {
	if config == nil {
		return headerGeometry{}, headerStructureError("the header has no config object")
	}
	jsonSize, ok := parseNumberedUint64(config.JSONSize)
	if !ok || jsonSize > HeaderMaxSize {
		return headerGeometry{}, headerStructureError("config.json_size %q is not a decimal byte count", config.JSONSize)
	}
	keyslotsSize, ok := parseNumberedUint64(config.KeyslotsSize)
	if !ok {
		return headerGeometry{}, headerStructureError("config.keyslots_size %q is not a decimal byte count", config.KeyslotsSize)
	}
	return headerGeometry{metadataSize: jsonSize + HeaderSize, keyslotsSize: keyslotsSize}, nil
}

// validateConfigStructure is hdr_validate_config: a legal metadata size, a
// 4 KiB-aligned keyslots area no larger than 128 MiB, and room for both
// header copies and the keyslots area before the first data segment.
func validateConfigStructure(metadata *Metadata) error {
	geometry, err := configGeometry(metadata.Config)
	if err != nil {
		return err
	}
	if !slices.Contains(LegalHeaderAreaSizes(), int64(geometry.metadataSize)) { // #nosec G115 -- configGeometry bounds it by HeaderMaxSize+4096
		return headerStructureError("config.json_size %s gives a %d-byte header, which is not a LUKS2 metadata size (a power of two, %d to %d)",
			metadata.Config.JSONSize, geometry.metadataSize, HeaderMinSize, HeaderMaxSize)
	}
	if geometry.keyslotsSize%4096 != 0 || geometry.keyslotsSize > MaxKeyslotsSize {
		return headerStructureError("config.keyslots_size %d is not a multiple of 4096 no larger than %d", geometry.keyslotsSize, MaxKeyslotsSize)
	}
	// Offset 0 is a detached header, exempt here; activation refuses it (CryptTableParams).
	dataOffset := minimalSegmentOffset(metadata)
	if dataOffset != 0 && (dataOffset < geometry.keyslotsSize || dataOffset-geometry.keyslotsSize < 2*geometry.metadataSize) {
		return headerStructureError("config.keyslots_size %d does not fit between the header copies (ending at %d) and the data at %d",
			geometry.keyslotsSize, 2*geometry.metadataSize, dataOffset)
	}
	return nil
}

// minimalSegmentOffset is json_segments_get_minimal_offset: the lowest offset of
// any regular segment, or 0 as soon as one sits at 0. The segments have been
// validated, so every offset parses.
func minimalSegmentOffset(metadata *Metadata) uint64 {
	lowest := uint64(math.MaxUint64)
	for id, segment := range metadata.Segments {
		if flags, _ := segmentFlags(id, segment); hasFlagPrefix(flags, "backup-") {
			continue
		}
		offset, _ := parseNumberedUint64(segment.Offset)
		if offset == 0 {
			return 0
		}
		lowest = min(lowest, offset)
	}
	return lowest
}

// validateKeyslotAreasStructure is hdr_validate_areas and validate_intervals:
// every keyslot area lies inside the keyslots area, is non-empty, and overlaps
// no other.
func validateKeyslotAreasStructure(metadata *Metadata) error {
	if len(metadata.Keyslots) == 0 {
		return nil
	}
	geometry, err := configGeometry(metadata.Config)
	if err != nil {
		return err
	}
	type interval struct {
		id             string
		offset, length uint64
	}
	ids := SortedIDs(metadata.Keyslots)
	areas := make([]interval, 0, len(ids))
	for _, id := range ids {
		area := metadata.Keyslots[id].Area
		if area == nil || area.Type == "" {
			return headerStructureError("keyslot %q must declare an area with a type", id)
		}
		offset, okOffset := parseNumberedUint64(area.Offset)
		length, okLength := parseNumberedUint64(area.Size)
		if !okOffset || !okLength {
			return headerStructureError("keyslot %q area offset %q and size %q must be decimal byte counts", id, area.Offset, area.Size)
		}
		areas = append(areas, interval{id: id, offset: offset, length: length})
	}
	for _, a := range areas {
		switch {
		case a.offset < 2*geometry.metadataSize:
			return headerStructureError("keyslot %q area at %d lies inside the header copies, which end at %d", a.id, a.offset, 2*geometry.metadataSize)
		case a.length == 0:
			return headerStructureError("keyslot %q area is empty", a.id)
		case a.offset > math.MaxUint64-a.length:
			return headerStructureError("keyslot %q area offset plus size overflows", a.id)
		case a.offset+a.length > geometry.end():
			return headerStructureError("keyslot %q area [%d, %d) runs past the keyslots area, which ends at %d", a.id, a.offset, a.offset+a.length, geometry.end())
		}
		for _, b := range areas {
			if a.id == b.id {
				continue
			}
			if b.offset > math.MaxUint64-b.length {
				return headerStructureError("keyslot %q area offset plus size overflows", b.id)
			}
			if a.offset >= b.offset && a.offset < b.offset+b.length {
				return headerStructureError("keyslot areas %q and %q overlap", a.id, b.id)
			}
		}
	}
	return nil
}

// validateKeyslotAssignmentStructure is LUKS2_keyslots_validate's structural part: one digest per luks2 keyslot, and reencrypt keyslot rules.
func validateKeyslotAssignmentStructure(metadata *Metadata) error {
	reencrypt := 0
	for _, id := range SortedIDs(metadata.Keyslots) {
		switch metadata.Keyslots[id].Type {
		case "luks2":
			named := 0
			for _, digest := range metadata.Digests {
				if digest != nil && slices.Contains(digest.Keyslots, id) {
					named++
				}
			}
			if named != 1 {
				return headerStructureError("luks2 keyslot %q is named by %d digests; it must be named by exactly one", id, named)
			}
		case "reencrypt":
			reencrypt++
		}
	}
	var mandatory []string
	if metadata.Config != nil && metadata.Config.Requirements != nil {
		mandatory = metadata.Config.Requirements.Mandatory
	}
	switch {
	case reencrypt > 1:
		return headerStructureError("the header carries %d reencrypt keyslots; at most one is allowed", reencrypt)
	case reencrypt == 1 && !slices.ContainsFunc(mandatory, isReencryptCandidateFlag):
		return headerStructureError("the header carries a reencrypt keyslot but no reencryption requirement flag")
	case reencrypt == 0 && slices.ContainsFunc(mandatory, func(r string) bool { return slices.Contains(OnlineReencryptRequirements, r) }):
		return headerStructureError("the header requires an online reencryption but carries no reencrypt keyslot")
	}
	return nil
}

// validateJSONSizeStructure is hdr_validate_json_size: config.json_size is the
// JSON area this header copy actually has. Whether the JSON fits that area is
// decided where it is encoded (EncodeMetadataForHeader).
func validateJSONSizeStructure(hdrSize int, metadata *Metadata) error {
	geometry, err := configGeometry(metadata.Config)
	if err != nil {
		return err
	}
	if hdrSize < 0 || geometry.metadataSize != uint64(hdrSize) {
		return headerStructureError("config.json_size %q does not match the %d-byte JSON area of this %d-byte header",
			metadata.Config.JSONSize, hdrSize-HeaderSize, hdrSize)
	}
	return nil
}

// LegalHeaderAreaSizes returns the powers of two from HeaderMinSize to HeaderMaxSize, which are also the legal secondary header offsets.
func LegalHeaderAreaSizes() []int64 {
	var sizes []int64
	for size := int64(HeaderMinSize); size <= HeaderMaxSize; size *= 2 {
		sizes = append(sizes, size)
	}
	return sizes
}
