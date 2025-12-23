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

// ListTokens returns all tokens from a LUKS2 device
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
		id, err := strconv.Atoi(key)
		if err != nil {
			continue // Skip invalid keys
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

	// Acquire file lock for exclusive access
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read current header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read LUKS header: %w", err)
	}

	// Initialize tokens map if nil
	if metadata.Tokens == nil {
		metadata.Tokens = make(map[string]*Token)
	}

	// Add or replace token
	tokenKey := strconv.Itoa(tokenID)
	metadata.Tokens[tokenKey] = token

	// Increment sequence ID
	hdr.SequenceID++

	// Write updated header
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
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

	// Acquire file lock for exclusive access
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read current header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read LUKS header: %w", err)
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

	// Clean up empty map
	if len(metadata.Tokens) == 0 {
		metadata.Tokens = nil
	}

	// Increment sequence ID
	hdr.SequenceID++

	// Write updated header
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
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

// CountTokens returns the number of tokens in the LUKS2 header
func CountTokens(device string) (int, error) {
	_, metadata, err := ReadHeader(device)
	if err != nil {
		return 0, fmt.Errorf("failed to read LUKS header: %w", err)
	}

	if metadata.Tokens == nil {
		return 0, nil
	}

	return len(metadata.Tokens), nil
}
