// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// JSON passthrough: each metadata object keeps the members it does not model as json.RawMessage and writes them back, so a rewrite never drops them; the typed half wins.

// unknownFields holds one object's unmodeled members as read; nil when there are none.
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
	metadataObjectHeader       = "metadata"
)

// The two directions a metadata object crosses the JSON boundary.
const (
	metadataJSONDecode = "decode"
	metadataJSONEncode = "encode"
)

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

// splitKnown returns the members of raw not in known, without modifying raw.
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

// containsMember reports whether names holds name, case-insensitively as encoding/json binds fields.
func containsMember(names []string, name string) bool {
	for _, candidate := range names {
		if strings.EqualFold(candidate, name) {
			return true
		}
	}
	return false
}

// decodeMembers splits object data into members before the typed decode, refusing duplicates or case variants of known (ErrAmbiguousJSONMember).
func decodeMembers(object string, data []byte, known []string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, nil
	}
	members := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, &MetadataJSONError{Object: object, Op: metadataJSONDecode, Err: err}
		}
		name, _ := tok.(string) // an object key is always a string token
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, &MetadataJSONError{Object: object, Op: metadataJSONDecode, Member: name, Err: err}
		}
		if _, dup := members[name]; dup {
			return nil, &MetadataJSONError{Object: object, Op: metadataJSONDecode, Member: name,
				Err: &errs.Error{Kind: ErrAmbiguousJSONMember, Detail: "the member appears more than once"}}
		}
		for _, modeled := range known {
			if name != modeled && strings.EqualFold(name, modeled) {
				return nil, &MetadataJSONError{Object: object, Op: metadataJSONDecode, Member: name,
					Err: &errs.Error{Kind: ErrAmbiguousJSONMember, Detail: fmt.Sprintf("the LUKS2 member is spelled %q", modeled)}}
			}
		}
		members[name] = value
	}
	return members, nil
}

// mergeInto appends the carried members to typed in sorted order, keeping the struct's member order and skipping members typed already produced.
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

		quoted, err := MarshalCanonicalJSON(name)
		if err != nil {
			return nil, &MetadataJSONError{Object: object, Op: metadataJSONEncode, Member: name, Err: err}
		}
		out.Write(quoted)
		out.WriteByte(':')

		// Compact the member so MarshalJSON returns a well-formed compact object.
		if err := json.Compact(&out, u[name]); err != nil {
			return nil, &MetadataJSONError{Object: object, Op: metadataJSONEncode, Member: name, Err: err}
		}
	}
	out.WriteByte('}')

	return out.Bytes(), nil
}

// JSONMemberNames returns the JSON member names the exported fields of a
// struct type marshal to.
//
// The lists below are DERIVED rather than written out, because a hand-kept
// list is one that goes stale: the first field added without touching it would
// be modeled by the struct AND carried as unmodeled, and the object would
// then hold the same member twice.
func JSONMemberNames(t reflect.Type) []string {
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
	keyslotKnownMembers      = JSONMemberNames(reflect.TypeOf(Keyslot{}))
	keyslotAreaKnownMembers  = JSONMemberNames(reflect.TypeOf(KeyslotArea{}))
	kdfKnownMembers          = JSONMemberNames(reflect.TypeOf(KDF{}))
	antiForensicKnownMembers = JSONMemberNames(reflect.TypeOf(AntiForensic{}))
	tokenKnownMembers        = JSONMemberNames(reflect.TypeOf(Token{}))
	segmentKnownMembers      = JSONMemberNames(reflect.TypeOf(Segment{}))
	digestKnownMembers       = JSONMemberNames(reflect.TypeOf(Digest{}))
	configKnownMembers       = JSONMemberNames(reflect.TypeOf(Config{}))
	requirementsKnownMembers = JSONMemberNames(reflect.TypeOf(Requirements{}))
	metadataKnownMembers     = JSONMemberNames(reflect.TypeOf(Metadata{}))
)

// UnmarshalJSON decodes a keyslot and carries any member this package does not
// model.
func (k *Keyslot) UnmarshalJSON(data []byte) error {
	raw, err := decodeMembers(metadataObjectKeyslot, data, keyslotKnownMembers)
	if err != nil {
		return err
	}

	// The alias sheds Keyslot's methods, so encoding/json handles the typed
	// half by reflection instead of calling this function again.
	type alias Keyslot
	if err := json.Unmarshal(data, (*alias)(k)); err != nil {
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
// EVERY MarshalJSON BELOW ENCODES THROUGH marshalCanonicalJSON, NOT json.Marshal.
//
// encoding/json HTML-escapes <, > and & by default; json-c, which is what
// cryptsetup writes the header with, emits them literally. The header's encoder
// turns that off (marshalCanonicalJSON, codec.go), but a type implementing
// Marshaler is encoded by the bytes it RETURNS: the outer encoder compacts them
// into the output and, with escaping off, neither adds escapes nor removes ones
// already there. So a json.Marshal inside one of these methods reintroduces the
// exact escapes the canonical encoder exists to avoid, and does it on the
// members most likely to carry those characters -- a foreign token's strings and
// the names of members this package does not model.
//
// Measured before the fix: a fido2-rp of `a<b>c&d` round-tripped as
// `a<b>c&d`, which is a different byte sequence for the same
// string and breaks byte-for-byte conformance and the header digest with it.
func (k Keyslot) MarshalJSON() ([]byte, error) {
	type alias Keyslot
	typed, err := MarshalCanonicalJSON(alias(k))
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
	raw, err := decodeMembers(metadataObjectKeyslotArea, data, keyslotAreaKnownMembers)
	if err != nil {
		return err
	}

	type alias KeyslotArea
	if err := json.Unmarshal(data, (*alias)(a)); err != nil {
		return &MetadataJSONError{Object: metadataObjectKeyslotArea, Op: metadataJSONDecode, Err: err}
	}
	a.unknown = splitKnown(raw, keyslotAreaKnownMembers)

	return nil
}

// MarshalJSON encodes a keyslot area together with the members it carried in.
func (a KeyslotArea) MarshalJSON() ([]byte, error) {
	type alias KeyslotArea
	typed, err := MarshalCanonicalJSON(alias(a))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectKeyslotArea, Op: metadataJSONEncode, Err: err}
	}
	return a.unknown.mergeInto(typed, metadataObjectKeyslotArea)
}

// UnmarshalJSON decodes a KDF and carries any member this package does not
// model.
func (k *KDF) UnmarshalJSON(data []byte) error {
	raw, err := decodeMembers(metadataObjectKDF, data, kdfKnownMembers)
	if err != nil {
		return err
	}

	type alias KDF
	if err := json.Unmarshal(data, (*alias)(k)); err != nil {
		return &MetadataJSONError{Object: metadataObjectKDF, Op: metadataJSONDecode, Err: err}
	}
	k.unknown = splitKnown(raw, kdfKnownMembers)

	return nil
}

// MarshalJSON encodes a KDF together with the members it carried in.
func (k KDF) MarshalJSON() ([]byte, error) {
	type alias KDF
	typed, err := MarshalCanonicalJSON(alias(k))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectKDF, Op: metadataJSONEncode, Err: err}
	}
	return k.unknown.mergeInto(typed, metadataObjectKDF)
}

// UnmarshalJSON decodes an anti-forensic specification and carries any member
// this package does not model.
func (a *AntiForensic) UnmarshalJSON(data []byte) error {
	raw, err := decodeMembers(metadataObjectAntiForensic, data, antiForensicKnownMembers)
	if err != nil {
		return err
	}

	type alias AntiForensic
	if err := json.Unmarshal(data, (*alias)(a)); err != nil {
		return &MetadataJSONError{Object: metadataObjectAntiForensic, Op: metadataJSONDecode, Err: err}
	}
	a.unknown = splitKnown(raw, antiForensicKnownMembers)

	return nil
}

// MarshalJSON encodes an anti-forensic specification together with the members
// it carried in.
func (a AntiForensic) MarshalJSON() ([]byte, error) {
	type alias AntiForensic
	typed, err := MarshalCanonicalJSON(alias(a))
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
	raw, err := decodeMembers(metadataObjectToken, data, tokenKnownMembers)
	if err != nil {
		return err
	}

	type alias Token
	if err := json.Unmarshal(data, (*alias)(t)); err != nil {
		return &MetadataJSONError{Object: metadataObjectToken, Op: metadataJSONDecode, Err: err}
	}
	t.unknown = splitKnown(raw, tokenKnownMembers)

	return nil
}

// MarshalJSON encodes a token together with the members it carried in.
//
// The receiver is a VALUE so that it fires wherever a token is reached,
// including through the map[string]*Token that Metadata holds. A marshaler
// that is never called drops exactly what it was written to preserve, and
// every direct test of it still passes.
func (t Token) MarshalJSON() ([]byte, error) {
	type alias Token
	typed, err := MarshalCanonicalJSON(alias(t))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectToken, Op: metadataJSONEncode, Err: err}
	}
	return t.unknown.mergeInto(typed, metadataObjectToken)
}

// UnmarshalJSON decodes a segment and carries any member this package does not
// model.
func (x *Segment) UnmarshalJSON(data []byte) error {
	raw, err := decodeMembers(metadataObjectSegment, data, segmentKnownMembers)
	if err != nil {
		return err
	}

	type alias Segment
	if err := json.Unmarshal(data, (*alias)(x)); err != nil {
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
	typed, err := MarshalCanonicalJSON(alias(x))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectSegment, Op: metadataJSONEncode, Err: err}
	}
	return x.unknown.mergeInto(typed, metadataObjectSegment)
}

// UnmarshalJSON decodes a digest and carries any member this package does not
// model.
func (x *Digest) UnmarshalJSON(data []byte) error {
	raw, err := decodeMembers(metadataObjectDigest, data, digestKnownMembers)
	if err != nil {
		return err
	}

	type alias Digest
	if err := json.Unmarshal(data, (*alias)(x)); err != nil {
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
	typed, err := MarshalCanonicalJSON(alias(x))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectDigest, Op: metadataJSONEncode, Err: err}
	}
	return x.unknown.mergeInto(typed, metadataObjectDigest)
}

// UnmarshalJSON decodes a config and carries any member this package does not
// model.
func (x *Config) UnmarshalJSON(data []byte) error {
	raw, err := decodeMembers(metadataObjectConfig, data, configKnownMembers)
	if err != nil {
		return err
	}

	type alias Config
	if err := json.Unmarshal(data, (*alias)(x)); err != nil {
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
	typed, err := MarshalCanonicalJSON(alias(x))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectConfig, Op: metadataJSONEncode, Err: err}
	}
	return x.unknown.mergeInto(typed, metadataObjectConfig)
}

// UnmarshalJSON decodes the requirements object and carries any member this
// package does not model.
func (x *Requirements) UnmarshalJSON(data []byte) error {
	raw, err := decodeMembers(metadataObjectRequirements, data, requirementsKnownMembers)
	if err != nil {
		return err
	}

	type alias Requirements
	if err := json.Unmarshal(data, (*alias)(x)); err != nil {
		return &MetadataJSONError{Object: metadataObjectRequirements, Op: metadataJSONDecode, Err: err}
	}
	x.unknown = splitKnown(raw, requirementsKnownMembers)

	return nil
}

// MarshalJSON encodes the requirements object together with the members it
// carried in. Value receiver, for the reason given on Segment.MarshalJSON.
func (x Requirements) MarshalJSON() ([]byte, error) {
	type alias Requirements
	typed, err := MarshalCanonicalJSON(alias(x))
	if err != nil {
		return nil, &MetadataJSONError{Object: metadataObjectRequirements, Op: metadataJSONEncode, Err: err}
	}
	return x.unknown.mergeInto(typed, metadataObjectRequirements)
}
