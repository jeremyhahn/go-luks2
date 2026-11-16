// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// MaxTokens is the maximum number of token slots in LUKS2.
const MaxTokens = 32

// canonicalTokenID returns the slot a token map key names, and whether the key
// ADDRESSES a token at all: it must be the canonical spelling of a number, and
// that number must be a slot this library and cryptsetup can both reach.
//
// Two independent things are checked, and leaving either one out reproduces the
// same defect in a different disguise -- a listing that names a token no caller
// can retrieve.
//
// SPELLING. strconv.Atoi accepts "01", "+1" and " 1" and returns 1 for all of
// them, so parsing alone does not answer whether a key addresses a token.
// Requiring the round trip does: a key is canonical exactly when it is what
// strconv.Itoa produces.
//
// RANGE. "-1", "32" and "999" are canonical spellings, so the round trip alone
// admits them -- and every other entry point rejects them, because AddToken,
// SetToken and RemoveToken all bound the id to 0..MaxTokens-1. A listing that
// reports a token no lookup can retrieve is exactly the inconsistency #35
// exists to remove, so the same bound applies here.
//
// # Why an unaddressable key is IGNORED rather than refused or honored
//
// MEASURED against cryptsetup 2.7.0 on containers this library wrote, which is
// what #35 was blocked on -- and the answer is neither of the two the issue
// expected:
//
//	tokens {"01": t}            luksDump exit 0, "Tokens:" section EMPTY
//	tokens {"1": a, "01": b}    luksDump exit 0, shows "1: a" once
//	tokens {"1": a}             luksDump exit 0, shows "1: a" once
//	tokens {"32": t}            luksDump exit 0, "Tokens:" section EMPTY
//	tokens {"999": t}           luksDump exit 0, "Tokens:" section EMPTY
//	tokens {"31": t}            luksDump exit 0, shows "31: t"  <- control
//	tokens {"-1": t}            luksDump exit 1, "is not a valid LUKS device"
//
// cryptsetup neither rejects those headers nor reaches those entries: it
// addresses tokens by looking up the canonical spelling of each slot number
// from 0 to LUKS2_TOKENS_MAX-1, so "01", "32" and "999" are all unreachable to
// it while "31" is not. MaxTokens is the same boundary, which the 31/32
// pair pins rather than assumes.
//
// So such a key is not a working token that refusing would strand -- no LUKS2
// implementation can use it -- and it is not grounds to refuse the header
// either, which would be the bricking direction the tokens-are-tolerated ruling
// exists to avoid.
//
// The negative id is the one case where cryptsetup refuses the whole container,
// and it does not change what this function does. The header is still readable
// HERE, which is the point of tolerating a damaged token: an operator has to be
// able to inspect a container that cryptsetup will not open, and reporting a
// token that nothing can retrieve does not help them do it.
//
// The defect that closes is not that these keys are invisible. It is that
// "01" could silently REPLACE the working token at "1" -- both mapped to the
// same int key and Go's randomized map iteration decided which survived, so a
// real token vanished from inspection on a different read each time -- and that
// an out-of-range key was listed as a token no lookup could retrieve.
func canonicalTokenID(key string) (int, bool) {
	id, err := strconv.Atoi(key)
	if err != nil || strconv.Itoa(id) != key {
		return 0, false
	}
	if id < 0 || id >= MaxTokens {
		return 0, false
	}
	return id, true
}

// TokenTypeRecovery is the LUKS2 token type for this package's own recovery
// keys: systemd-cryptenroll's "systemd-recovery".
const TokenTypeRecovery = header.TokenTypeSystemdRecovery

// Token is a LUKS2 token: a named external-credential binding recorded in the
// header. Keyslots is the set of keyslot ids the token
// identifies -- empty for a token that names none, never nil on the wire,
// since LUKS2 requires the member to be an array. Members carries every field
// this package does not model as a typed one itself -- a systemd-fido2
// token's fido2-credential/fido2-salt/fido2-rp and requirement flags, a
// systemd-tpm2 token's fields, or any other token type's -- untouched, so
// writing a token back never drops what wrote it.
//
// A zero Token (empty Type) is the KeyProvider.Token anonymous case: no token
// should be written for it.
type Token struct {
	Type     string
	Keyslots []int
	Members  map[string]json.RawMessage
}

// MarshalJSON renders the token as LUKS2 writes it on disk: type and keyslots
// (as the canonical decimal-string array the format requires), merged with
// every member in Members.
func (t Token) MarshalJSON() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(t.Members)+2)
	for k, v := range t.Members {
		out[k] = v
	}

	typeJSON, err := json.Marshal(t.Type)
	if err != nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "failed to encode token type", Err: err}
	}
	out["type"] = typeJSON

	keyslots := make([]string, len(t.Keyslots))
	for i, id := range t.Keyslots {
		keyslots[i] = strconv.Itoa(id)
	}
	keyslotsJSON, err := json.Marshal(keyslots)
	if err != nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "failed to encode token keyslots", Err: err}
	}
	out["keyslots"] = keyslotsJSON

	return json.Marshal(out)
}

// UnmarshalJSON reads a token's type and keyslots out of the on-disk object
// and keeps everything else, verbatim and unparsed, in Members.
func (t *Token) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "token is not a JSON object", Err: err}
	}

	// JSON null decodes into a string or a slice without complaint, but it is
	// neither: cryptsetup's token validation requires type to be a string and
	// keyslots an array, so null is refused here as the wrong type it is.
	var typ string
	if v, ok := raw["type"]; ok {
		if isJSONNull(v) {
			return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "token type is not a string"}
		}
		if err := json.Unmarshal(v, &typ); err != nil {
			return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "token type is not a string", Err: err}
		}
		delete(raw, "type")
	}

	var keyslots []int
	if v, ok := raw["keyslots"]; ok {
		if isJSONNull(v) {
			return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "token keyslots is not an array of strings"}
		}
		var ids []string
		if err := json.Unmarshal(v, &ids); err != nil {
			return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "token keyslots is not an array of strings", Err: err}
		}
		keyslots = make([]int, len(ids))
		for i, id := range ids {
			n, err := strconv.Atoi(id)
			if err != nil {
				return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "token keyslots entry " + id + " is not a number", Err: err}
			}
			keyslots[i] = n
		}
		delete(raw, "keyslots")
	}

	if len(raw) == 0 {
		raw = nil
	}
	t.Type = typ
	t.Keyslots = keyslots
	t.Members = raw
	return nil
}

// isJSONNull reports whether a raw JSON member is the literal null.
func isJSONNull(v json.RawMessage) bool {
	return string(bytes.TrimSpace(v)) == "null"
}

// toLegacyToken converts t to the on-disk LegacyToken shape, through
// LegacyToken's own JSON codec: a member this package models as a typed
// field (the systemd-fido2 schema) lands there, and everything else passes
// through LegacyToken's own unknown-field passthrough untouched.
func (t Token) toLegacyToken() (*LegacyToken, error) {
	raw, err := t.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var lt LegacyToken
	if err := json.Unmarshal(raw, &lt); err != nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "failed to decode token", Err: err}
	}
	return &lt, nil
}

// tokenFromLegacy is toLegacyToken's inverse.
func tokenFromLegacy(lt *LegacyToken) (Token, error) {
	raw, err := json.Marshal(lt)
	if err != nil {
		return Token{}, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "failed to encode token", Err: err}
	}
	var t Token
	if err := json.Unmarshal(raw, &t); err != nil {
		return Token{}, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "failed to decode token", Err: err}
	}
	return t, nil
}

// AddToken writes t to the first free token slot and returns its id.
func (v *Volume) AddToken(ctx context.Context, t Token) (int, error) {
	const op = "Volume.AddToken"
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.checkOpen(op); err != nil {
		return 0, err
	}
	if err := v.checkWritable(op); err != nil {
		return 0, err
	}

	if t.Type == "" {
		return 0, errAt(op, v.path, &errs.Error{Kind: ErrInvalidArgument, Detail: "a token must have a type"})
	}

	locked, err := v.lockFor(ctx, device.LockExclusive)
	if err != nil {
		return 0, errAt(op, v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	// No exclusive open: the exclusive flock is what excludes other writers,
	// as for AddKeyslot and cryptsetup token import, and a claim would refuse
	// a volume that is mapped or mounted. The header is the CURRENT copy, as
	// for the keyslot writes, and reading it levels a stale one: a primary one
	// write behind the secondary must not hide a token from freeTokenSlot.
	dev, err := v.keyslotDeviceFor(locked)
	if err != nil {
		return 0, errAt(op, v.path, err)
	}
	f := dev.file
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return 0, errAt(op, v.path, err)
	}

	id, err := freeTokenSlot(metadata)
	if err != nil {
		return 0, errAt(op, v.path, err)
	}

	lt, err := t.toLegacyToken()
	if err != nil {
		return 0, errAt(op, v.path, err)
	}
	if metadata.Tokens == nil {
		metadata.Tokens = make(map[string]*LegacyToken)
	}
	metadata.Tokens[strconv.Itoa(id)] = lt
	hdr.SequenceID++

	if err := writeHeaderTo(f, hdr, metadata, v.sys.syncDevice); err != nil {
		return 0, errAt(op, v.path, err)
	}
	return id, nil
}

// SetToken writes t to slot id, replacing whatever is there.
func (v *Volume) SetToken(ctx context.Context, id int, t Token) error {
	const op = "Volume.SetToken"
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.checkOpen(op); err != nil {
		return err
	}
	if err := v.checkWritable(op); err != nil {
		return err
	}

	if id < 0 || id >= MaxTokens {
		return errAt(op, v.path, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("invalid token ID: %d (must be 0-%d)", id, MaxTokens-1)})
	}
	if t.Type == "" {
		return errAt(op, v.path, &errs.Error{Kind: ErrInvalidArgument, Detail: "a token must have a type"})
	}

	locked, err := v.lockFor(ctx, device.LockExclusive)
	if err != nil {
		return errAt(op, v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	// No exclusive open, and the current header copy: see AddToken.
	dev, err := v.keyslotDeviceFor(locked)
	if err != nil {
		return errAt(op, v.path, err)
	}
	f := dev.file
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return errAt(op, v.path, err)
	}

	lt, err := t.toLegacyToken()
	if err != nil {
		return errAt(op, v.path, err)
	}
	if metadata.Tokens == nil {
		metadata.Tokens = make(map[string]*LegacyToken)
	}
	metadata.Tokens[strconv.Itoa(id)] = lt
	hdr.SequenceID++

	if err := writeHeaderTo(f, hdr, metadata, v.sys.syncDevice); err != nil {
		return errAt(op, v.path, err)
	}
	return nil
}

// RemoveToken removes the token at id, refusing with ErrTokenNotFound if
// there is none.
func (v *Volume) RemoveToken(ctx context.Context, id int) error {
	const op = "Volume.RemoveToken"
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.checkOpen(op); err != nil {
		return err
	}
	if err := v.checkWritable(op); err != nil {
		return err
	}

	if id < 0 || id >= MaxTokens {
		return errAt(op, v.path, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("invalid token ID: %d (must be 0-%d)", id, MaxTokens-1)})
	}

	locked, err := v.lockFor(ctx, device.LockExclusive)
	if err != nil {
		return errAt(op, v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	// No exclusive open, and the current header copy: see AddToken.
	dev, err := v.keyslotDeviceFor(locked)
	if err != nil {
		return errAt(op, v.path, err)
	}
	f := dev.file
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return errAt(op, v.path, err)
	}

	key := strconv.Itoa(id)
	if _, exists := metadata.Tokens[key]; !exists {
		return errAt(op, v.path, &errs.Error{Kind: ErrTokenNotFound, Detail: "token " + key})
	}
	delete(metadata.Tokens, key)
	hdr.SequenceID++

	if err := writeHeaderTo(f, hdr, metadata, v.sys.syncDevice); err != nil {
		return errAt(op, v.path, err)
	}
	return nil
}
