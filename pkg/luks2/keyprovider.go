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

// External key providers: credentials that come from something outside this
// process -- a hardware authenticator, an agent, a script -- rather than from a
// human at a terminal.
//
// Implementations that exec a helper binary -- the command and systemd-fido2
// providers -- live in pkg/keyprovider (#271), which depends on this package
// for the KeyProvider interface rather than the other way around. What stays
// here is the interface itself and the operations that consume one --
// (*Volume).Enroll (provider.go) and (*Volume).UnlockWithProvider -- because
// they also need this package's own Token and keyslot/device internals that
// pkg/keyprovider must not import.

// KeyProvider yields a volume credential from outside this process, together
// with the token that records where it came from (DESIGN.md §B.2).
//
// The credential is returned in protected memory and is the CALLER's to
// Destroy. Token returns the metadata to write into the LUKS2 header alongside
// the keyslot; its Keyslots field is filled in by Enroll (provider.go), which
// is the only place that knows the answer.
//
// This replaces the old KeyProvider{Token() *Token} in place (DECISIONS.md
// H9d): the method set cannot be redeclared under one name with two shapes,
// and "no backward compatibility is required" is the owner ruling that
// settles which shape keeps the name.
type KeyProvider interface {
	// Passphrase runs whatever produces the credential and returns it. ctx
	// bounds the work: a hardware authenticator waiting for a touch blocks
	// until the user acts, and an unattended unlock needs that to end.
	Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error)

	// Token returns the header metadata identifying this credential. A zero
	// Token (empty Type) means the provider is anonymous and no token should
	// be written.
	Token() Token
}

// recoveryTokenType is the LUKS2 token type for this package's own recovery
// keys. fido2TokenType, its FIDO2 counterpart, moved to
// pkg/keyprovider.TokenTypeFIDO2 with the rest of the exec-helper code (#271).
const recoveryTokenType = "systemd-recovery"

// importTokenLocked writes token into slot tokenID for a caller that holds the
// device lock -- (*Volume).SetToken would wait on that same lock for ever,
// since flock on a second descriptor waits on the first. The slot must still
// be free: it was chosen under this lock, so anything else there is a defect,
// and overwriting it would destroy another credential's record.
//
// It refuses what (*Volume).SetToken refuses: an id out of range, and a
// token with no type.
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

// importToken (volumeSys.importToken) is importTokenLocked: the rollback
// itself can be exercised by overriding the field on a keyslotDevice a test
// constructs, since the token this package writes for a recovery key is
// built internally and is always well-formed -- there is no argument a test
// can pass that makes the write fail at the point where a keyslot is already
// on the device.

// killKeyslot (volumeSys.killKeyslot) is killKeyslotLocked: the rollback's
// own failure path is exercised the same way, by overriding the field. The
// branch behind it is the only one in this file that ends with a human
// holding a volume that needs attention, so it is the last one that should
// go untested.

// The old free-function UnlockWithProvider is gone (#268): it activated a
// volume, which is now pkg/dmcrypt's job, and pkg/luks2 no longer has a
// route to device-mapper or the kernel keyring. Its replacement is
// (*Volume).UnlockWithProvider (provider.go) plus pkg/dmcrypt.Activate.

// ---------------------------------------------------------------------------
// Errors
//
// The external-key sentinels are in errors.go with every other sentinel. The
// types here follow the same shape: a structured type carrying what a
// diagnosis needs, and an Is that reports the type as its sentinel so a caller
// never has to know the type exists.
// ---------------------------------------------------------------------------

// A failure obtaining or enrolling an external credential keeps its own
// sentinel: the provider's error is returned as the provider gave it, and
// this package's refusals are ErrInvalidArgument or ErrKeyslotNotFound. Only
// an OrphanedKeyslotError matches ErrKeyProvider. None carries credential
// material.

// OrphanedKeyslotError reports a keyslot holding a live credential that no
// token describes and that could not be removed.
//
// It names the slot because that number is the only way back: an operator
// removes it with `luks2 killslot <device> <n>`, and no other record of it
// exists anywhere.
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

// Unwrap reports an OrphanedKeyslotError as both ErrOrphanedKeyslot and
// ErrKeyProvider -- it is the provider vocabulary, and it is also the one
// condition a caller may want to single out -- and keeps the original
// failure reachable too.
func (e *OrphanedKeyslotError) Unwrap() []error {
	return []error{ErrOrphanedKeyslot, ErrKeyProvider, e.Err}
}
