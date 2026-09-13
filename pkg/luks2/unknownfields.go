// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// JSON passthrough for the LUKS2 metadata objects.
//
// WHY THIS EXISTS
//
// Every mutation this package performs -- AddKey, RemoveKey, ChangeKey,
// ImportToken, RemoveToken -- goes through writeHeaderInternal, and
// writeHeaderInternal re-marshals the ENTIRE metadata blob. So the header that
// lands on disk contains exactly what these Go structs managed to hold, and a
// JSON member no field models is not left alone: it is deleted, from an object
// the operation never meant to touch.
//
// MEASURED, against systemd 255 and cryptsetup 2.7.0: a complete eight-member
// `systemd-fido2` token was imported with `cryptsetup token import`, an
// unrelated key was added with AddKey, and the token came back with six --
// `fido2-clientPin-required` and `fido2-uv-required` were gone. That token no
// longer describes the credential it was enrolled from.
//
// So each object carries the members it does not model, verbatim, and writes
// them back out. The typed half always wins: a member the struct produces is
// never overwritten by a carried one, because the struct is what the rest of
// this package actually reasons about.
//
// WHY json.RawMessage AND NOT interface{}
//
// A JSON number decoded into interface{} becomes a float64. 2^64-1 comes back
// as 18446744073709552000 -- a different number, silently -- and `1e3` comes
// back as `1000`. LUKS2 objects carry byte offsets, shift sizes and TPM key
// handles that reach that far, and a passthrough that alters a value it was
// asked to preserve is worse than one that admits it dropped it. RawMessage is
// the original bytes and cannot lie about them.
//
// WHAT THIS REPLACES
//
// Keyslot.Custom, a map[string]interface{} tagged json:"-" that was assigned
// on every decode and read by nothing. It stored the WHOLE object, so every
// typed field was also held a second time in a form that mangled large
// integers, and because the package declared no MarshalJSON at all it could
// not have reached the disk in any case.
//
// WHAT THIS DOES NOT COVER
//
// The Segment, Digest and Config objects are still closed, and an unmodeled
// member of one of those is still dropped. That is #152, and it is not
// hypothetical: cryptsetup flags the backup segments of an in-progress
// reencryption `backup-previous` and `backup-final`, Segment has no field for
// them, and a rewrite drops exactly what `cryptsetup reencrypt --resume-only`
// needs. Extending this mechanism to Segment is mechanical -- splitKnown and
// mergeInto are type-agnostic and the known-member lists are derived by
// reflection. Config is not: its requirements member has the wrong Go TYPE,
// which is a hard read failure rather than a silent drop, so it needs a shape
// change and an owner decision about what this package does when it meets a
// mandatory requirement it does not implement.

// unknownFields holds the members of one JSON object that the Go struct for
// that object does not model, exactly as they were read.
//
// A nil map is the normal state: an object this package fully understands
// carries no passthrough at all rather than an empty one.
type unknownFields map[string]json.RawMessage

// The metadata objects that carry a passthrough, named for the errors they
// raise. They are constants rather than literals at each site so a caller
// switching on MetadataJSONError.Object cannot be broken by a typo.
const (
	metadataObjectKeyslot      = "keyslot"
	metadataObjectKeyslotArea  = "keyslot area"
	metadataObjectKDF          = "kdf"
	metadataObjectAntiForensic = "af"
	metadataObjectToken        = "token"
	metadataObjectSegment      = "segment"
	metadataObjectDigest       = "digest"
	metadataObjectConfig       = "config"
	metadataObjectRequirements = "config.requirements"
)

// The two directions a metadata object crosses the JSON boundary.
const (
	metadataJSONDecode = "decode"
	metadataJSONEncode = "encode"
)

// ErrMetadataJSON indicates that a LUKS2 metadata object could not be
// converted to or from JSON.
//
// It is raised where the CONVERSION fails, and says nothing about whether the
// object is a valid LUKS2 object: a syntactically perfect keyslot with an
// impossible key size decodes cleanly and is refused elsewhere.
var ErrMetadataJSON = errors.New("LUKS2 metadata object could not be converted to or from JSON")

// MetadataJSONError reports which metadata object failed to convert, in which
// direction, and why.
//
// The encoding/json cause stays reachable through Unwrap, so a caller that
// already matched on *json.SyntaxError or *json.UnmarshalTypeError keeps
// working while gaining the object name it never had.
type MetadataJSONError struct {
	// Object names the LUKS2 object -- "keyslot", "token", "kdf" and so on.
	// It is the object's KIND and never its id: an id would have to be
	// threaded through encoding/json, which does not carry one.
	Object string

	// Op is metadataJSONDecode or metadataJSONEncode.
	Op string

	// Member names the single JSON member at fault, and is empty when the
	// fault is the object as a whole.
	Member string

	// Err is the underlying cause, kept reachable through Unwrap.
	Err error
}

func (e *MetadataJSONError) Error() string {
	if e.Member != "" {
		return fmt.Sprintf("failed to %s %s member %q: %v", e.Op, e.Object, e.Member, e.Err)
	}
	return fmt.Sprintf("failed to %s %s: %v", e.Op, e.Object, e.Err)
}

func (e *MetadataJSONError) Unwrap() error { return e.Err }

// Is reports every MetadataJSONError as ErrMetadataJSON, so a caller can match
// the sentinel without knowing this type, while errors.Is also still reaches
// the encoding/json cause through Unwrap.
func (e *MetadataJSONError) Is(target error) bool {
	return target == ErrMetadataJSON
}

// splitKnown returns the members of raw that are NOT in known.
//
// Removing the modeled members is what keeps a value from being held twice --
// once typed and once raw -- which is how the two halves would come to
// disagree about what the object says. It does not modify raw: the caller's
// map is its own.
//
// known has at most a handful of entries, so a linear scan beats building a
// set, and the common case allocates nothing at all.
func splitKnown(raw map[string]json.RawMessage, known []string) unknownFields {
	var unknown unknownFields
	for name, value := range raw {
		if containsMember(known, name) {
			continue
		}
		if unknown == nil {
			unknown = make(unknownFields)
		}
		unknown[name] = value
	}
	return unknown
}

// containsMember reports whether names holds name, matching case-
// INSENSITIVELY to agree with how encoding/json itself binds a decoded
// member to a struct field: when a raw object has no exact-case match for a
// field, json.Unmarshal still binds it case-insensitively rather than
// leaving the field unset. A case-sensitive comparison here would let that
// same member survive a second time as "unknown", so the typed half and the
// carried half would both reach the wire -- and disagree the moment a caller
// changes the typed field, which is the very state splitKnown exists to rule
// out.
func containsMember(names []string, name string) bool {
	for _, candidate := range names {
		if strings.EqualFold(candidate, name) {
			return true
		}
	}
	return false
}

// mergeInto splices the carried members into typed -- the JSON object the
// struct half produced -- and returns the combined object.
//
// It appends rather than re-encoding, so the struct's member ORDER survives:
// cryptsetup emits a keyslot's members in a fixed order, this package matches
// it through field declaration order, and decoding the typed half into a map
// to merge would destroy that. A member the struct already produced is skipped,
// which is what makes the typed half authoritative.
//
// Carried members are emitted in sorted order. Go randomizes map iteration, so
// without the sort the same unchanged metadata would marshal to different
// bytes on every write.
func (u unknownFields) mergeInto(typed []byte, object string) ([]byte, error) {
	if len(u) == 0 {
		return typed, nil
	}

	var present map[string]json.RawMessage
	if err := json.Unmarshal(typed, &present); err != nil {
		return nil, &MetadataJSONError{Object: object, Op: metadataJSONEncode, Err: err}
	}

	names := make([]string, 0, len(u))
	for name := range u {
		if _, taken := present[name]; taken {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return typed, nil
	}
	sort.Strings(names)

	// typed is compact, comes from encoding/json, and is an object -- the
	// Unmarshal above established the last of those -- so its final byte is
	// the closing brace and everything before it can be reused as written.
	var out bytes.Buffer
	out.Grow(len(typed) + 32*len(names))
	out.Write(typed[:len(typed)-1])

	first := len(present) == 0
	for _, name := range names {
		if !first {
			out.WriteByte(',')
		}
		first = false

		quoted, err := json.Marshal(name)
		if err != nil {
			return nil, &MetadataJSONError{Object: object, Op: metadataJSONEncode, Member: name, Err: err}
		}
		out.Write(quoted)
		out.WriteByte(':')

		// Compacting validates the member and strips the indentation it
		// carried in from the header's JSON area, so MarshalJSON returns a
		// well-formed compact object on its own rather than relying on the
		// caller to normalize it.
		if err := json.Compact(&out, u[name]); err != nil {
			return nil, &MetadataJSONError{Object: object, Op: metadataJSONEncode, Member: name, Err: err}
		}
	}
	out.WriteByte('}')

	return out.Bytes(), nil
}

// jsonMemberNames returns the JSON member names the exported fields of a
// struct type marshal to.
//
// The lists below are DERIVED rather than written out, because a hand-kept
// list is one that goes stale: the first field added without touching it would
// be modeled by the struct AND carried as unmodeled, and the object would
// then hold the same member twice.
func jsonMemberNames(t reflect.Type) []string {
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			continue // unexported; encoding/json never sees it
		}

		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		switch name {
		case "-":
			continue // deliberately not on the wire
		case "":
			name = field.Name
		}
		names = append(names, name)
	}
	return names
}

// The members each metadata object models, derived once at init.
var (
	keyslotKnownMembers      = jsonMemberNames(reflect.TypeOf(Keyslot{}))
	keyslotAreaKnownMembers  = jsonMemberNames(reflect.TypeOf(KeyslotArea{}))
	kdfKnownMembers          = jsonMemberNames(reflect.TypeOf(KDF{}))
	antiForensicKnownMembers = jsonMemberNames(reflect.TypeOf(AntiForensic{}))
	tokenKnownMembers        = jsonMemberNames(reflect.TypeOf(Token{}))
	segmentKnownMembers      = jsonMemberNames(reflect.TypeOf(Segment{}))
	digestKnownMembers       = jsonMemberNames(reflect.TypeOf(Digest{}))
	configKnownMembers       = jsonMemberNames(reflect.TypeOf(Config{}))
	requirementsKnownMembers = jsonMemberNames(reflect.TypeOf(Requirements{}))
)

// UnmarshalJSON decodes a keyslot and carries any member this package does not
// model.
func (k *Keyslot) UnmarshalJSON(data []byte) error {
	// The alias sheds Keyslot's methods, so encoding/json handles the typed
	// half by reflection instead of calling this function again.
	type alias Keyslot
	if err := json.Unmarshal(data, (*alias)(k)); err != nil {
		return &MetadataJSONError{Object: metadataObjectKeyslot, Op: metadataJSONDecode, Err: err}
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return &MetadataJSONError{Object: metadataObjectKeyslot, Op: metadataJSONDecode, Err: err}
	}
	k.unknown = splitKnown(raw, keyslotKnownMembers)

	return nil
}

// MarshalJSON encodes a keyslot together with the members it carried in.
//
// The receiver is a VALUE so that it is in the method set reached wherever a
// keyslot is encountered as one -- json.Marshal of a bare Keyslot does not
// take its address, and a pointer-receiver marshaler is simply not called
// there. See Token.MarshalJSON.
//
// It does NOT normalize priority. Whether a default priority is written is
// decided where the keyslot is BUILT, in createMetadata; a serializer that
// silently dropped a value the caller set would be deciding it twice, in the
// one place a caller cannot see.
func (k Keyslot) MarshalJSON() ([]byte, error) {
	type alias Keyslot
	typed, err := json.Marshal(alias(k))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectKeyslot, Op: metadataJSONEncode, Err: err}
	}
	return k.unknown.mergeInto(typed, metadataObjectKeyslot)
}

// UnmarshalJSON decodes a keyslot area and carries any member this package
// does not model.
//
// The nested objects need this as much as the keyslot around them does. A
// reencryption keyslot's area is where cryptsetup keeps `hash`, `sector_size`
// and `shift_size`, none of which this package models, and all of which it
// needs to resume an interrupted reencryption.
func (a *KeyslotArea) UnmarshalJSON(data []byte) error {
	type alias KeyslotArea
	if err := json.Unmarshal(data, (*alias)(a)); err != nil {
		return &MetadataJSONError{Object: metadataObjectKeyslotArea, Op: metadataJSONDecode, Err: err}
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return &MetadataJSONError{Object: metadataObjectKeyslotArea, Op: metadataJSONDecode, Err: err}
	}
	a.unknown = splitKnown(raw, keyslotAreaKnownMembers)

	return nil
}

// MarshalJSON encodes a keyslot area together with the members it carried in.
func (a KeyslotArea) MarshalJSON() ([]byte, error) {
	type alias KeyslotArea
	typed, err := json.Marshal(alias(a))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectKeyslotArea, Op: metadataJSONEncode, Err: err}
	}
	return a.unknown.mergeInto(typed, metadataObjectKeyslotArea)
}

// UnmarshalJSON decodes a KDF and carries any member this package does not
// model.
func (k *KDF) UnmarshalJSON(data []byte) error {
	type alias KDF
	if err := json.Unmarshal(data, (*alias)(k)); err != nil {
		return &MetadataJSONError{Object: metadataObjectKDF, Op: metadataJSONDecode, Err: err}
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return &MetadataJSONError{Object: metadataObjectKDF, Op: metadataJSONDecode, Err: err}
	}
	k.unknown = splitKnown(raw, kdfKnownMembers)

	return nil
}

// MarshalJSON encodes a KDF together with the members it carried in.
func (k KDF) MarshalJSON() ([]byte, error) {
	type alias KDF
	typed, err := json.Marshal(alias(k))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectKDF, Op: metadataJSONEncode, Err: err}
	}
	return k.unknown.mergeInto(typed, metadataObjectKDF)
}

// UnmarshalJSON decodes an anti-forensic specification and carries any member
// this package does not model.
func (a *AntiForensic) UnmarshalJSON(data []byte) error {
	type alias AntiForensic
	if err := json.Unmarshal(data, (*alias)(a)); err != nil {
		return &MetadataJSONError{Object: metadataObjectAntiForensic, Op: metadataJSONDecode, Err: err}
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return &MetadataJSONError{Object: metadataObjectAntiForensic, Op: metadataJSONDecode, Err: err}
	}
	a.unknown = splitKnown(raw, antiForensicKnownMembers)

	return nil
}

// MarshalJSON encodes an anti-forensic specification together with the members
// it carried in.
func (a AntiForensic) MarshalJSON() ([]byte, error) {
	type alias AntiForensic
	typed, err := json.Marshal(alias(a))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectAntiForensic, Op: metadataJSONEncode, Err: err}
	}
	return a.unknown.mergeInto(typed, metadataObjectAntiForensic)
}

// UnmarshalJSON decodes a token and carries any member this package does not
// model.
//
// Tokens are where the passthrough earns most of its keep: the token types
// that matter are defined by systemd, not by this package, and a token is
// written once by whatever enrolled it and then only ever read.
func (t *Token) UnmarshalJSON(data []byte) error {
	type alias Token
	if err := json.Unmarshal(data, (*alias)(t)); err != nil {
		return &MetadataJSONError{Object: metadataObjectToken, Op: metadataJSONDecode, Err: err}
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return &MetadataJSONError{Object: metadataObjectToken, Op: metadataJSONDecode, Err: err}
	}
	t.unknown = splitKnown(raw, tokenKnownMembers)

	return nil
}

// MarshalJSON encodes a token together with the members it carried in.
//
// The receiver is a VALUE so that it fires wherever a token is reached,
// including through the map[string]*Token that LUKS2Metadata holds. A
// marshaler that is never called drops exactly what it was written to
// preserve, and every direct test of it still passes.
func (t Token) MarshalJSON() ([]byte, error) {
	type alias Token
	typed, err := json.Marshal(alias(t))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectToken, Op: metadataJSONEncode, Err: err}
	}
	return t.unknown.mergeInto(typed, metadataObjectToken)
}

// UnmarshalJSON decodes a segment and carries any member this package does not
// model.
func (x *Segment) UnmarshalJSON(data []byte) error {
	type alias Segment
	if err := json.Unmarshal(data, (*alias)(x)); err != nil {
		return &MetadataJSONError{Object: metadataObjectSegment, Op: metadataJSONDecode, Err: err}
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return &MetadataJSONError{Object: metadataObjectSegment, Op: metadataJSONDecode, Err: err}
	}
	x.unknown = splitKnown(raw, segmentKnownMembers)

	return nil
}

// MarshalJSON encodes a segment together with the members it carried in.
//
// VALUE receiver, like every other marshaler here. A pointer-receiver
// MarshalJSON is simply not in the method set reached by json.Marshal of a bare
// value, so it stops firing wherever the object is encountered as one -- while
// every test that happens to hold a pointer keeps passing. That is the hazard
// #143 measured and #151 was told to pin per type.
func (x Segment) MarshalJSON() ([]byte, error) {
	type alias Segment
	typed, err := json.Marshal(alias(x))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectSegment, Op: metadataJSONEncode, Err: err}
	}
	return x.unknown.mergeInto(typed, metadataObjectSegment)
}

// UnmarshalJSON decodes a digest and carries any member this package does not
// model.
func (x *Digest) UnmarshalJSON(data []byte) error {
	type alias Digest
	if err := json.Unmarshal(data, (*alias)(x)); err != nil {
		return &MetadataJSONError{Object: metadataObjectDigest, Op: metadataJSONDecode, Err: err}
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return &MetadataJSONError{Object: metadataObjectDigest, Op: metadataJSONDecode, Err: err}
	}
	x.unknown = splitKnown(raw, digestKnownMembers)

	return nil
}

// MarshalJSON encodes a digest together with the members it carried in.
//
// VALUE receiver, like every other marshaler here. A pointer-receiver
// MarshalJSON is simply not in the method set reached by json.Marshal of a bare
// value, so it stops firing wherever the object is encountered as one -- while
// every test that happens to hold a pointer keeps passing. That is the hazard
// #143 measured and #151 was told to pin per type.
func (x Digest) MarshalJSON() ([]byte, error) {
	type alias Digest
	typed, err := json.Marshal(alias(x))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectDigest, Op: metadataJSONEncode, Err: err}
	}
	return x.unknown.mergeInto(typed, metadataObjectDigest)
}

// UnmarshalJSON decodes a config and carries any member this package does not
// model.
func (x *Config) UnmarshalJSON(data []byte) error {
	type alias Config
	if err := json.Unmarshal(data, (*alias)(x)); err != nil {
		return &MetadataJSONError{Object: metadataObjectConfig, Op: metadataJSONDecode, Err: err}
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return &MetadataJSONError{Object: metadataObjectConfig, Op: metadataJSONDecode, Err: err}
	}
	x.unknown = splitKnown(raw, configKnownMembers)

	return nil
}

// MarshalJSON encodes a config together with the members it carried in.
//
// VALUE receiver, like every other marshaler here. A pointer-receiver
// MarshalJSON is simply not in the method set reached by json.Marshal of a bare
// value, so it stops firing wherever the object is encountered as one -- while
// every test that happens to hold a pointer keeps passing. That is the hazard
// #143 measured and #151 was told to pin per type.
func (x Config) MarshalJSON() ([]byte, error) {
	type alias Config
	typed, err := json.Marshal(alias(x))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectConfig, Op: metadataJSONEncode, Err: err}
	}
	return x.unknown.mergeInto(typed, metadataObjectConfig)
}

// UnmarshalJSON decodes the requirements object and carries any member this
// package does not model.
func (x *Requirements) UnmarshalJSON(data []byte) error {
	type alias Requirements
	if err := json.Unmarshal(data, (*alias)(x)); err != nil {
		return &MetadataJSONError{Object: metadataObjectRequirements, Op: metadataJSONDecode, Err: err}
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return &MetadataJSONError{Object: metadataObjectRequirements, Op: metadataJSONDecode, Err: err}
	}
	x.unknown = splitKnown(raw, requirementsKnownMembers)

	return nil
}

// MarshalJSON encodes the requirements object together with the members it
// carried in. Value receiver, for the reason given on Segment.MarshalJSON.
func (x Requirements) MarshalJSON() ([]byte, error) {
	type alias Requirements
	typed, err := json.Marshal(alias(x))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectRequirements, Op: metadataJSONEncode, Err: err}
	}
	return x.unknown.mergeInto(typed, metadataObjectRequirements)
}
