// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// External key providers; the exec-helper implementations are in pkg/keyprovider.

// KeyProvider yields a volume credential from outside this process, in protected memory the caller destroys, with the token recording its origin.
type KeyProvider interface {
	// Passphrase runs whatever produces the credential and returns it. ctx
	// bounds the work: a hardware authenticator waiting for a touch blocks
	// until the user acts, and an unattended unlock needs that to end.
	Passphrase(ctx context.Context) (enclave.ByteAccess, error)

	// Token returns the header metadata identifying this credential. A zero
	// Token (empty Type) means the provider is anonymous and no token should
	// be written.
	Token() Token
}

// recoveryTokenType is the LUKS2 token type for this package's recovery keys.
const recoveryTokenType = "systemd-recovery"

// importTokenLocked writes token into the free slot tokenID for a caller holding the device lock; it refuses what (*Volume).SetToken refuses.
func importTokenLocked(ctx context.Context, dev *keyslotDevice, tokenID int, token *LegacyToken) error {
	if tokenID < 0 || tokenID >= MaxTokens {
		return &errs.Error{Kind: ErrInvalidHeader, Detail: "token id " + strconv.Itoa(tokenID) + " is out of range"}
	}
	if token == nil || token.Type == "" {
		return &errs.Error{Kind: ErrInvalidHeader, Detail: "a token must have a type"}
	}
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return err
	}
	if metadata.Tokens == nil {
		metadata.Tokens = make(map[string]*LegacyToken)
	}
	key := strconv.Itoa(tokenID)
	if _, taken := metadata.Tokens[key]; taken {
		return &errs.Error{Kind: ErrNoSpace, Detail: "token slot " + key + " was taken while this enrollment held the device lock"}
	}
	metadata.Tokens[key] = token
	hdr.SequenceID++
	return dev.writeHeader(ctx, hdr, metadata)
}

// freeTokenSlot returns the lowest token id metadata does not use.
func freeTokenSlot(metadata *header.Metadata) (int, error) {
	for i := 0; i < MaxTokens; i++ {
		if _, used := metadata.Tokens[strconv.Itoa(i)]; !used {
			return i, nil
		}
	}
	return -1, ErrNoSpace
}

// killKeyslotLocked removes a keyslot for a caller that holds the device lock,
// through the same gate every removal takes (removeKeyslotOn).
func killKeyslotLocked(ctx context.Context, dev *keyslotDevice, keyslot int) error {
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return err
	}
	id := strconv.Itoa(keyslot)
	if _, ok := metadata.Keyslots[id]; !ok {
		return &errs.Error{Kind: ErrKeyslotNotFound, Detail: "keyslot " + id + " does not exist"}
	}
	// Through the pinned descriptor: the rollback must remove the keyslot
	// from the device the enrollment wrote, not whatever the path names now.
	_, err = removeKeyslotOn(ctx, dev, hdr, metadata, id)
	return err
}

// volumeSys.importToken is importTokenLocked; tests override it to fail the token write.

// volumeSys.killKeyslot is killKeyslotLocked; tests override it to exercise rollback failure.

// Errors: the sentinels are in errors.go; each type here reports its sentinel through Is.

// Provider errors are returned as given; only an OrphanedKeyslotError matches ErrKeyProvider, and none carries credential material.

// OrphanedKeyslotError reports a keyslot holding a live credential that no token describes and that could not be removed; remove it with luks2 killslot.
type OrphanedKeyslotError struct {
	// Keyslot is the slot holding the credential.
	Keyslot int

	// Err is why the token could not be written -- the original failure.
	Err error

	// Cause is why the keyslot could not then be removed.
	Cause error
}

func (e *OrphanedKeyslotError) Error() string {
	return fmt.Sprintf("%s: keyslot %d holds a credential no token describes: the token write failed (%v) and the keyslot could not be removed (%v). Remove it with: luks2 killslot <device> %d",
		ErrOrphanedKeyslot.Error(), e.Keyslot, e.Err, e.Cause, e.Keyslot)
}

// Unwrap returns ErrOrphanedKeyslot, ErrKeyProvider and the original failure.
func (e *OrphanedKeyslotError) Unwrap() []error {
	return []error{ErrOrphanedKeyslot, ErrKeyProvider, e.Err}
}
