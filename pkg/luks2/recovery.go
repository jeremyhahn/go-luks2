// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/recoverykey"
	"github.com/jeremyhahn/go-luks2/internal/secret"
	"github.com/jeremyhahn/go-luks2/internal/volkey"
)

// RecoveryKeyFormat selects how a generated recovery key's credential is
// rendered as text. The zero value is RecoveryDashed, systemd's own
// rendering.
type RecoveryKeyFormat uint8

const (
	// RecoveryDashed renders the credential as dash-separated hex groups
	// (like systemd and Windows BitLocker). It is the zero value.
	RecoveryDashed RecoveryKeyFormat = iota
	// RecoveryHex renders the credential as plain hexadecimal.
	RecoveryHex
	// RecoveryBase64 renders the credential as base64.
	RecoveryBase64
)

// String names the format the way an operator would type it for --format.
func (f RecoveryKeyFormat) String() string {
	switch f {
	case RecoveryDashed:
		return "dashed"
	case RecoveryHex:
		return "hex"
	case RecoveryBase64:
		return "base64"
	default:
		return fmt.Sprintf("RecoveryKeyFormat(%d)", uint8(f))
	}
}

// rendering maps f to the internal/recoverykey.Format it selects, and
// reports whether f is one of the three known formats.
func (f RecoveryKeyFormat) rendering() (recoverykey.Format, bool) {
	switch f {
	case RecoveryDashed:
		return recoverykey.Dashed, true
	case RecoveryHex:
		return recoverykey.Hex, true
	case RecoveryBase64:
		return recoverykey.Base64, true
	default:
		return 0, false
	}
}

// ParseRecoveryKeyFormat parses a --format name (dashed, hex or base64); anything else, empty included, matches ErrInvalidArgument.
func ParseRecoveryKeyFormat(name string) (RecoveryKeyFormat, error) {
	switch name {
	case "dashed":
		return RecoveryDashed, nil
	case "hex":
		return RecoveryHex, nil
	case "base64":
		return RecoveryBase64, nil
	default:
		return 0, &errs.Error{Kind: ErrInvalidArgument, Detail: fmt.Sprintf("%q", name)}
	}
}

// DefaultRecoveryKeyLength is the default length, in random bytes drawn, of a
// generated recovery key -- and the shortest NewRecoveryKey will draw.
const DefaultRecoveryKeyLength = 32

// recoveryToken builds systemd's recovery token: type and keyslots only.
func recoveryToken() *LegacyToken {
	return &LegacyToken{Type: recoveryTokenType}
}

// parseLegacyRecoveryKey decodes a formatted recovery key into its key material in protected memory, for volumes whose keyslot holds the decoded bytes; use ParseRecoveryKey otherwise.
func parseLegacyRecoveryKey(formatted string) (enclave.ByteAccess, error) {
	if len(formatted) == 0 {
		return nil, &errs.Error{Kind: errs.ErrInvalidCredential, Detail: "recovery key is empty"}
	}

	// One copy, into locked memory. []byte(formatted) is the last ordinary
	// allocation the key sees, and custody.Adopt's enclave takes ownership of it
	// and wipes it.
	held, err := custody.Adopt("recovery key", []byte(formatted))
	if err != nil {
		return nil, err
	}
	defer custody.Release(held)

	return recoverykey.Decode(custody, held)
}

// RecoveryKey is a generated recovery credential, obtainable only from NewRecoveryKey; the keyslot holds the printed text byte for byte.
type RecoveryKey struct {
	credential enclave.ByteAccess
	format     RecoveryKeyFormat
	hash       string
}

// recoveryOptions is RecoveryKeyOption's target. Its zero value is the
// library's policy: RecoveryDashed at DefaultRecoveryKeyLength.
type recoveryOptions struct {
	format RecoveryKeyFormat
	length int
}

// RecoveryKeyOption configures NewRecoveryKey.
type RecoveryKeyOption func(*recoveryOptions)

// WithRecoveryFormat selects the credential's rendering. The default is
// RecoveryDashed.
func WithRecoveryFormat(f RecoveryKeyFormat) RecoveryKeyOption {
	return func(o *recoveryOptions) { o.format = f }
}

// WithRecoveryLength selects how many random bytes NewRecoveryKey draws. The
// default, and the shortest length it will draw, is DefaultRecoveryKeyLength.
func WithRecoveryLength(n int) RecoveryKeyOption {
	return func(o *recoveryOptions) { o.length = n }
}

// NewRecoveryKey draws length random bytes (default DefaultRecoveryKeyLength) into locked memory and renders them in format; the caller must Destroy the result.
func NewRecoveryKey(opts ...RecoveryKeyOption) (*RecoveryKey, error) {
	o := recoveryOptions{format: RecoveryDashed, length: DefaultRecoveryKeyLength}
	for _, opt := range opts {
		opt(&o)
	}
	if o.length == 0 {
		o.length = DefaultRecoveryKeyLength
	}

	rendering, ok := o.format.rendering()
	if !ok {
		return nil, &errs.Error{Kind: ErrInvalidArgument, Detail: fmt.Sprintf("%v", o.format)}
	}

	// At least 256 bits, which the library-generated exemption requires.
	if o.length < DefaultRecoveryKeyLength || recoverykey.Len(o.length, rendering) > MaxPassphraseLength {
		return nil, &errs.Error{Kind: ErrInvalidArgument, Detail: fmt.Sprintf("%d random bytes rendered %s", o.length, o.format)}
	}

	key, err := custody.Random("recovery key", o.length, defaultVolumeSys().cryptoRand)
	if err != nil {
		return nil, err
	}
	defer custody.Release(key)

	credential, err := recoverykey.Render(custody, key, rendering)
	if err != nil {
		return nil, err
	}

	hash, err := recoverykey.Hash(credential)
	if err != nil {
		custody.Release(credential)
		return nil, err
	}

	return &RecoveryKey{credential: credential, format: o.format, hash: hash}, nil
}

// Format is the rendering the credential is written in.
func (r *RecoveryKey) Format() RecoveryKeyFormat { return r.format }

// Hash is a hex SHA-256 of the credential text; it is not secret.
func (r *RecoveryKey) Hash() string { return r.hash }

// WriteTo writes the credential text to w; a write failure is ErrIO, a protected-memory failure ErrProtectedMemory.
func (r *RecoveryKey) WriteTo(w io.Writer) (int64, error) {
	var n int64
	var werr error
	err := secret.Borrow("recovery key", r.credential, func(b []byte) error {
		var written int
		written, werr = w.Write(b)
		n = int64(written)
		return werr
	})
	if werr != nil {
		return n, &errs.Error{Kind: ErrIO, Detail: "write the recovery key", Err: werr}
	}
	if err != nil {
		return n, &errs.Error{Kind: ErrProtectedMemory, Detail: "recovery key", Err: err}
	}
	return n, nil
}

// Destroy releases the key material from protected memory. It is idempotent
// and safe on a nil *RecoveryKey or a zero-valued one, so it can always be
// deferred.
func (r *RecoveryKey) Destroy() {
	if r == nil {
		return
	}
	custody.Release(r.credential)
	r.credential = nil
}

// ParseRecoveryKey trims a recovery key held in protected memory and refuses anything not a single line; the result is a new enclave.
func ParseRecoveryKey(text enclave.ByteAccess) (enclave.ByteAccess, error) {
	return recoverykey.Credential(custody, text)
}

// AddRecoveryKey enrolls rk (from NewRecoveryKey) with a systemd-recovery token, re-verifying key under the exclusive lock; a failed token write rolls the keyslot back.
func (v *Volume) AddRecoveryKey(ctx context.Context, key *Key, rk *RecoveryKey, p KeyslotParams) (Enrollment, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.checkOpen("Volume.AddRecoveryKey"); err != nil {
		return Enrollment{}, err
	}
	if err := v.checkWritable("Volume.AddRecoveryKey"); err != nil {
		return Enrollment{}, err
	}

	const op = "Volume.AddRecoveryKey"
	if key == nil {
		return Enrollment{}, errAt(op, v.path, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "key is required"})
	}
	if rk == nil || rk.credential == nil {
		return Enrollment{}, errAt(op, v.path, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "recovery key is required"})
	}
	if err := p.KDF.validateWith(v.sys.fipsMode); err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}

	locked, err := v.lockFor(ctx, device.LockExclusive)
	if err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	dev := &keyslotDevice{path: v.path, file: locked.File(), locked: locked, sys: v.sys}
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}

	tokenID, err := freeTokenSlot(metadata)
	if err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}

	addOpts := p.toAddKeyOptions()
	addOpts.Keyslot = p.Slot
	priority := onDiskPriority(p.Priority)
	var assignedSlot int
	err = volkey.Borrow(op, key, func(raw []byte) error {
		masterKey, cerr := v.sys.custody.Clone(op, raw)
		if cerr != nil {
			return cerr
		}
		defer v.sys.custody.Release(masterKey)

		return secret.Borrow(op, rk.credential, func(credential []byte) error {
			var aerr error
			assignedSlot, aerr = addKeyslotWithMasterKeyAndPriority(ctx, dev, hdr, metadata, masterKey, credential, addOpts, libraryGeneratedCredential, priority)
			return aerr
		})
	})
	if err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}

	record := *recoveryToken()
	record.Keyslots = []string{strconv.Itoa(assignedSlot)}
	if err := dev.sys.importToken(ctx, dev, tokenID, &record); err != nil {
		// The rollback runs whatever became of the caller's context: a
		// cancellation that failed the token write must not also stop the
		// keyslot from being taken back out.
		if killErr := dev.sys.killKeyslot(context.WithoutCancel(ctx), dev, assignedSlot); killErr != nil {
			return Enrollment{}, errAt(op, v.path, &OrphanedKeyslotError{Keyslot: assignedSlot, Err: err, Cause: killErr})
		}
		return Enrollment{}, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to record the recovery key token", Err: err})
	}

	slotIDStr := strconv.Itoa(assignedSlot)
	info, err := keyslotInfoFromMetadata(assignedSlot, metadata.Keyslots[slotIDStr])
	if err != nil {
		return Enrollment{}, errAt(op, v.path, err)
	}
	return Enrollment{Keyslot: info, Token: tokenID}, nil
}
