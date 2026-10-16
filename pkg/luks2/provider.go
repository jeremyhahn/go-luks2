// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"slices"
	"strconv"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/secret"
	"github.com/jeremyhahn/go-luks2/internal/volkey"
)

// Enrollment reports what Enroll wrote: the keyslot it added, and the token
// slot it named or -1 when the provider was anonymous and no token was
// written.
type Enrollment struct {
	Keyslot KeyslotInfo
	Token   int
}

// Enroll adds a KeyProvider's credential to the volume under key -- the
// caller's already-recovered volume key -- and records the provider's token
// alongside the keyslot it went to.
//
// It is built on the internals AddRecoveryKey also uses:
// addKeyslotWithMasterKey for the keyslot, which re-verifies key against the
// header's digests under THIS call's own exclusive lock (the
// header may have changed since Unlock), and importTokenLocked for the
// token. key is only ever borrowed; a clone of its bytes is what
// addKeyslotWithMasterKey consumes, so the caller's Key is unchanged and
// still theirs to Destroy.
//
// If the token write fails, the keyslot is rolled back, as AddRecoveryKey
// does: a keyslot nothing describes is a live credential indistinguishable from one still in
// use.
//
// The provider runs BEFORE mu and the device lock, and so do AddKeyslot's creation checks on kp and on the credential: a provider
// that blocks on a FIDO2 touch or a helper process must not hold off
// cryptsetup's writers, and one that reads this Volume must not deadlock on
// it. As for AddKeyslot, no exclusive open is taken: the exclusive flock
// excludes other writers, and a volume that is mapped or mounted can still
// be enrolled, as cryptsetup's own token import can.
func (v *Volume) Enroll(ctx context.Context, key *Key, p KeyProvider, kp KeyslotParams) (Enrollment, error) {
	const op = "Volume.Enroll"
	if err := v.checkOpenNow(op); err != nil {
		return Enrollment{}, err
	}
	if err := v.checkWritable(op); err != nil {
		return Enrollment{}, err
	}
	if key == nil {
		return Enrollment{}, errAt(op, v.path, &errs.Error{Kind: ErrInvalidArgument, Detail: "key is required"})
	}
	if p == nil {
		return Enrollment{}, errAt(op, v.path, &errs.Error{Kind: ErrInvalidArgument})
	}
	if err := kp.KDF.validateWith(v.sys.fipsMode); err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}
	opts := addKeyOptionsFromKeyslotParams(kp)
	if err := refuseSHA1ForCreation(opts.KDFType, opts.Hash); err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}
	if err := validateArgon2CreateCost(callerArgon2Options(opts)); err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}

	t := p.Token()
	credential, err := p.Passphrase(ctx)
	if err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}
	defer v.sys.custody.Release(credential)
	if err := secret.Borrow(op, credential, validatePassphraseBytes); err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.checkOpen(op); err != nil {
		return Enrollment{}, err
	}

	locked, err := v.lockFor(ctx, device.LockExclusive)
	if err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	dev, err := v.keyslotDeviceFor(locked)
	if err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}

	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}

	tokenID := -1
	if t.Type != "" {
		tokenID, err = freeTokenSlot(metadata)
		if err != nil {
			return Enrollment{}, errAt(op, v.path, err)
		}
	}

	// addKeyslotWithMasterKey only derives from and verifies against the
	// master key; it does not take ownership of it. A clone is handed in, the
	// same pattern UnlockWithVolumeKey uses for the opposite direction, so
	// the caller's key is untouched by this call.
	var masterKey enclave.ByteAccess
	if err := volkey.Borrow(op, key, func(b []byte) error {
		var cerr error
		masterKey, cerr = v.sys.custody.Clone(op, b)
		return cerr
	}); err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}
	defer v.sys.custody.Release(masterKey)

	priority := onDiskPriority(kp.Priority)

	var slot int
	err = secret.Borrow(op, credential, func(raw []byte) error {
		var ierr error
		slot, ierr = addKeyslotWithMasterKeyAndPriority(ctx, dev, hdr, metadata, masterKey, raw, opts, callerSuppliedCredential, priority)
		return ierr
	})
	if err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}

	info := keyslotInfoFromEntry(slot, metadata.Keyslots[strconv.Itoa(slot)])

	if t.Type == "" {
		return Enrollment{Keyslot: info, Token: -1}, nil
	}

	// A COPY, so enrolling the same provider twice does not accumulate
	// keyslot references on the caller's token.
	record := t
	record.Keyslots = []int{slot}
	// The rollback runs whether or not ctx is still live, as
	// rollBackAddedKeyslot's does: a cancellation that arrived with the token
	// write must not also leave behind the keyslot it was to describe.
	rollBack := func(cause error) (Enrollment, error) {
		if killErr := dev.sys.killKeyslot(context.WithoutCancel(ctx), dev, slot); killErr != nil {
			return Enrollment{}, errAt(op, v.path, &OrphanedKeyslotError{Keyslot: slot, Err: cause, Cause: killErr})
		}
		return Enrollment{}, errAt(op, v.path, cause)
	}
	legacy, err := record.toLegacyToken()
	if err != nil {
		return rollBack(err)
	}
	if err := dev.sys.importToken(ctx, dev, tokenID, legacy); err != nil {
		return rollBack(err)
	}

	return Enrollment{Keyslot: info, Token: tokenID}, nil
}

// UnlockWithProvider opens the volume with a KeyProvider's credential, trying
// only the keyslots p.Token().Keyslots names -- unlike
// Unlock, which tries every keyslot bound to the data segment.
//
// They are tried by priority, as cryptsetup tries the keyslots of a token the
// caller names (luks2_token.c, LUKS2_keyslot_open_by_token): every prefer
// keyslot first, then every normal one, then every ignore one, each group in
// the token's order. A named token makes its ignore keyslots eligible, last;
// only cryptsetup's scan of every token skips them, and this library never
// chooses a token for the caller.
//
// The provider runs BEFORE mu and the shared device lock, for the reasons
// Enroll gives.
func (v *Volume) UnlockWithProvider(ctx context.Context, p KeyProvider) (*Key, error) {
	const op = "Volume.UnlockWithProvider"
	if err := v.checkOpenNow(op); err != nil {
		return nil, err
	}

	if p == nil {
		return nil, errAt(op, v.path, &errs.Error{Kind: ErrInvalidArgument})
	}

	t := p.Token()
	if len(t.Keyslots) == 0 {
		return nil, errAt(op, v.path, &errs.Error{Kind: ErrInvalidArgument, Detail: "the provider's token names no keyslot"})
	}
	ids := make([]string, len(t.Keyslots))
	for i, s := range t.Keyslots {
		ids[i] = strconv.Itoa(s)
	}

	credential, err := p.Passphrase(ctx)
	if err != nil {
		return nil, errAt(op, v.path, err)
	}
	defer v.sys.custody.Release(credential)

	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.checkOpen(op); err != nil {
		return nil, err
	}

	locked, _, metadata, err := v.unlockHeader(ctx, op)
	if err != nil {
		return nil, err
	}
	defer func() { _ = locked.Unlock() }()

	for _, id := range ids {
		if !keyslotBoundToDataSegments(metadata, id) {
			return nil, errAt(op, v.path, &errs.Error{Kind: ErrKeyslotNotFound,
				Detail: "keyslot " + id + " does not exist or is not bound to the volume's data segment"})
		}
	}

	// The token was chosen by the caller, so its keyslots are tried as
	// cryptsetup tries a token named with --token-id: the prefer ones, then
	// the normal ones, then the ignore ones, each group in the token's order.
	preferred, normal, ignored := keyslotsByPriority(metadata, ids)
	order := slices.Concat(preferred, normal, ignored)

	var masterKey enclave.ByteAccess
	var slotID string
	err = secret.Borrow(op, credential, func(b []byte) error {
		var derr error
		masterKey, slotID, derr = getMasterKeySlot(ctx, locked.File(), v.path, b, metadata, order, v.sys)
		return derr
	})
	if err != nil {
		return nil, errAt(op, v.path, err)
	}

	slot, _ := strconv.Atoi(slotID) // slotID always came from header.CanonicalKeyslotID, through ids above
	return volkey.New(masterKey, slot), nil
}
