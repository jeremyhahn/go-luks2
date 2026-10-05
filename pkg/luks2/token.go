// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// MaxTokenSlots is the maximum number of token slots in LUKS2
const MaxTokenSlots = 32

// ErrTokenNotFound indicates the token was not found
var ErrTokenNotFound = fmt.Errorf("token not found")

// ErrNoFreeTokenSlot indicates no free token slots are available
var ErrNoFreeTokenSlot = fmt.Errorf("no free token slots available")

// GetToken retrieves a token by ID from a LUKS2 device
func GetToken(device string, tokenID int) (*Token, error) {
	if tokenID < 0 || tokenID >= MaxTokenSlots {
		return nil, fmt.Errorf("invalid token ID: %d (must be 0-%d)", tokenID, MaxTokenSlots-1)
	}

	_, metadata, err := ReadHeader(device)
	if err != nil {
		return nil, fmt.Errorf("failed to read LUKS header: %w", err)
	}

	if metadata.Tokens == nil {
		return nil, ErrTokenNotFound
	}

	tokenKey := strconv.Itoa(tokenID)
	token, exists := metadata.Tokens[tokenKey]
	if !exists {
		return nil, ErrTokenNotFound
	}

	return token, nil
}

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
// admits them -- and every other entry point rejects them, because GetToken,
// ImportToken, RemoveToken and TokenExists all bound the id to 0..MaxTokenSlots-1.
// A listing that reports a token GetToken refuses to retrieve is exactly the
// inconsistency #35 exists to remove, so the same bound applies here.
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
// it while "31" is not. MaxTokenSlots is the same boundary, which the 31/32
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
// an out-of-range key was listed as a token that GetToken then refused.
func canonicalTokenID(key string) (int, bool) {
	id, err := strconv.Atoi(key)
	if err != nil || strconv.Itoa(id) != key {
		return 0, false
	}
	if id < 0 || id >= MaxTokenSlots {
		return 0, false
	}
	return id, true
}

// ListTokens returns all tokens from a LUKS2 device, keyed by slot.
//
// A key that does not address a token -- a non-canonical spelling, or a number
// outside 0..MaxTokenSlots-1 -- is skipped rather than folded onto a slot or
// reported as one. Every id in the returned map is one GetToken will retrieve;
// see canonicalTokenID for the cryptsetup measurement that settles why.
func ListTokens(device string) (map[int]*Token, error) {
	_, metadata, err := ReadHeader(device)
	if err != nil {
		return nil, fmt.Errorf("failed to read LUKS header: %w", err)
	}

	result := make(map[int]*Token)
	if metadata.Tokens == nil {
		return result, nil
	}

	for key, token := range metadata.Tokens {
		id, ok := canonicalTokenID(key)
		if !ok {
			continue
		}
		result[id] = token
	}

	return result, nil
}

// ExportToken exports a token as JSON from a LUKS2 device
func ExportToken(device string, tokenID int) ([]byte, error) {
	token, err := GetToken(device, tokenID)
	if err != nil {
		return nil, err
	}

	jsonData, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token: %w", err)
	}

	return jsonData, nil
}

// ImportToken imports a token into a LUKS2 device at the specified slot
func ImportToken(device string, tokenID int, token *Token) error {
	if tokenID < 0 || tokenID >= MaxTokenSlots {
		return fmt.Errorf("invalid token ID: %d (must be 0-%d)", tokenID, MaxTokenSlots-1)
	}

	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	if token.Type == "" {
		return fmt.Errorf("token type cannot be empty")
	}

	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return err
	}

	// One descriptor: locked, read through and written through, so a path
	// re-pointed after the lock cannot have the header of one device rewritten
	// onto another (as the keyslot operations, #249 A10).
	lock, dev, err := lockKeyslotDevice(device)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return &detailError{Detail: "failed to read LUKS header", Err: err}
	}

	// Initialize tokens map if nil
	if metadata.Tokens == nil {
		metadata.Tokens = make(map[string]*Token)
	}

	// LUKS2 requires a token's keyslots member to be an ARRAY. A nil slice
	// encodes as `"keyslots":null`, which cryptsetup and systemd-cryptsetup
	// refuse along with the whole header, so a token that names no keyslot is
	// written with an empty one. The caller's token is copied rather than
	// changed (#248).
	//
	// Whether the keyslots it names exist, under their canonical ids, is not
	// checked here: the header write below refuses a dangling reference along
	// with every other header cryptsetup would not read (headervalidation.go),
	// and that is one rule rather than two that could disagree.
	imported := *token
	if imported.Keyslots == nil {
		imported.Keyslots = []string{}
	}

	// Add or replace token
	tokenKey := strconv.Itoa(tokenID)
	metadata.Tokens[tokenKey] = &imported

	// Increment sequence ID
	hdr.SequenceID++

	if err := dev.writeHeader(hdr, metadata); err != nil {
		return &detailError{Detail: "failed to write header", Err: err}
	}
	return nil
}

// ImportTokenJSON imports a token from JSON into a LUKS2 device
func ImportTokenJSON(device string, tokenID int, tokenJSON []byte) error {
	var token Token
	if err := json.Unmarshal(tokenJSON, &token); err != nil {
		return fmt.Errorf("failed to parse token JSON: %w", err)
	}

	return ImportToken(device, tokenID, &token)
}

// RemoveToken removes a token from a LUKS2 device
func RemoveToken(device string, tokenID int) error {
	if tokenID < 0 || tokenID >= MaxTokenSlots {
		return fmt.Errorf("invalid token ID: %d (must be 0-%d)", tokenID, MaxTokenSlots-1)
	}

	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return err
	}

	// One descriptor, as ImportToken.
	lock, dev, err := lockKeyslotDevice(device)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return &detailError{Detail: "failed to read LUKS header", Err: err}
	}

	if metadata.Tokens == nil {
		return ErrTokenNotFound
	}

	tokenKey := strconv.Itoa(tokenID)
	if _, exists := metadata.Tokens[tokenKey]; !exists {
		return ErrTokenNotFound
	}

	// Remove token
	delete(metadata.Tokens, tokenKey)

	// The map is deliberately left in place when it empties. Nilling it out
	// existed to make the `tokens,omitempty` tag drop the key entirely, which
	// is the opposite of what LUKS2 wants: tokens is mandatory and a container
	// with no tokens carries `{}`.
	//
	// ensureRequiredObjects would restore the empty map before this metadata
	// reached the disk either way, so removing the nilling is not what makes
	// the container valid -- it removes a second place that has to be reasoned
	// about to see that it stays valid.

	// Increment sequence ID
	hdr.SequenceID++

	if err := dev.writeHeader(hdr, metadata); err != nil {
		return &detailError{Detail: "failed to write header", Err: err}
	}
	return nil
}

// FindFreeTokenSlot finds the first available token slot
func FindFreeTokenSlot(device string) (int, error) {
	_, metadata, err := ReadHeader(device)
	if err != nil {
		return -1, fmt.Errorf("failed to read LUKS header: %w", err)
	}

	// If no tokens exist, slot 0 is free
	if metadata.Tokens == nil {
		return 0, nil
	}

	// Find first free slot
	for i := 0; i < MaxTokenSlots; i++ {
		tokenKey := strconv.Itoa(i)
		if _, exists := metadata.Tokens[tokenKey]; !exists {
			return i, nil
		}
	}

	return -1, ErrNoFreeTokenSlot
}

// TokenExists checks if a token exists at the specified slot
func TokenExists(device string, tokenID int) (bool, error) {
	if tokenID < 0 || tokenID >= MaxTokenSlots {
		return false, fmt.Errorf("invalid token ID: %d (must be 0-%d)", tokenID, MaxTokenSlots-1)
	}

	_, metadata, err := ReadHeader(device)
	if err != nil {
		return false, fmt.Errorf("failed to read LUKS header: %w", err)
	}

	if metadata.Tokens == nil {
		return false, nil
	}

	tokenKey := strconv.Itoa(tokenID)
	_, exists := metadata.Tokens[tokenKey]
	return exists, nil
}

// CountTokens returns the number of tokens in the LUKS2 header.
//
// It counts the entries ListTokens returns, not the size of the map on disk.
// len() would count a key that no LUKS2 implementation can address, so a
// container carrying both "1" and "01" -- or one carrying "32" -- would report
// a token that every listing omitted and every lookup refused, a count nothing
// else in the library or in cryptsetup agrees with. See canonicalTokenID.
func CountTokens(device string) (int, error) {
	_, metadata, err := ReadHeader(device)
	if err != nil {
		return 0, fmt.Errorf("failed to read LUKS header: %w", err)
	}

	count := 0
	for key := range metadata.Tokens {
		if _, ok := canonicalTokenID(key); ok {
			count++
		}
	}

	return count, nil
}
