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

// ParseRecoveryKeyFormat parses the name a person types for --format: dashed,
// hex or base64. Anything else -- the empty string included, since a caller
// that names a format has not asked for the default -- is refused with an
// error matching ErrInvalidArgument.
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

// recoveryToken builds the token that identifies a recovery keyslot.
//
// It is systemd's, and it is the WHOLE token: type and keyslots, nothing else.
// systemd-cryptenroll --recovery-key writes no format member and no algorithm
// member, because there is no material to describe -- the credential is the
// printed text. Adding fields of our own here would produce a token systemd
// reads differently from the way we wrote it.
//
// Keyslots is filled in by AddRecoveryKey once it knows which slot the
// credential landed in.
func recoveryToken() *LegacyToken {
	return &LegacyToken{Type: recoveryTokenType}
}

// parseLegacyRecoveryKey decodes a formatted recovery key into the KEY MATERIAL
// BEHIND it and returns that in protected memory.
//
// # This is probably not the function you want
//
// Its behavior is unchanged, and so is its meaning: it turns "9F3A2C-4B81DE-..."
// into the bytes that rendering encodes. What changed around it is which of the
// two is the credential. A keyslot enrolled by the current code holds the TEXT,
// so ParseRecoveryKey is what produces something that opens such a volume;
// this function is for a volume enrolled before that change, whose keyslot holds
// the decoded bytes.
//
// It is tolerant in a way ParseRecoveryKey is deliberately not -- it accepts
// either case, with or without dashes, hex or base64 -- because it is decoding a
// rendering rather than reproducing a credential.
//
// # What is exposed, precisely
//
// formatted is a Go string and Go strings are immutable, so the CALLER'S copy
// of the key cannot be wiped by anyone. That is unavoidable at this boundary: a
// recovery key reaches a program by being typed, pasted or read out of a file,
// all of which are string-shaped.
//
// What is avoidable is this package making more of them, and it used to make
// about four -- ReplaceAll and ToLower each yield a new string when they change
// anything, and both decoders took []byte(s) of the result. An earlier version
// of this comment described only the caller's copy, which understated the
// exposure by that factor. The string is now copied ONCE, into locked memory,
// and every normalisation and decode happens there.
//
// Callers that already hold the key in an enclave should not come through
// here at all.
func parseLegacyRecoveryKey(formatted string) (*enclave.Memory, error) {
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

// RecoveryKey is a generated recovery credential, obtainable only from
// NewRecoveryKey. That restriction is deliberate: AddRecoveryKey enrolls the
// credential under the library-generated KDF exemption (a relaxed PBKDF2
// floor, sound only because the bytes behind it are 256 CSPRNG bits with no
// candidate list to multiply), and sealing the type to NewRecoveryKey is
// what keeps a caller from handing AddRecoveryKey a credential of its own
// under that exemption.
//
// THE PRINTED TEXT IS THE PASSPHRASE: the keyslot holds the FORMATTED TEXT
// WriteTo prints -- "9F3A2C-4B81DE-..." -- byte for byte, not an encoding of
// it, so a printed page opens the volume from any rescue system with stock
// cryptsetup and nothing else.
type RecoveryKey struct {
	credential *enclave.Memory
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

// NewRecoveryKey draws a cryptographically secure recovery key: length
// random bytes (DefaultRecoveryKeyLength if unset), rendered in format
// (RecoveryDashed if unset). See RecoveryKey's doc comment for why the
// credential is the rendered TEXT and not the bytes behind it.
//
// The random bytes are drawn directly into locked memory and destroyed
// before this returns; only the rendering survives. The caller owns the
// result and must Destroy it.
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

	// AT LEAST 256 BITS: that is what the recovery key's cost model assumes,
	// and AddRecoveryKey's library-generated exemption is sound only above it.
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

// Hash is a SHA-256 of the credential text, hex-encoded. It is a one-way
// function of the credential and is not itself secret: it is safe to print
// or save in the clear so a transcription can be checked without going near
// the volume.
func (r *RecoveryKey) Hash() string { return r.hash }

// WriteTo writes the credential text to w -- the formatted recovery key
// itself, byte for byte, never a Go string. It is the only way to
// materialize the credential for display or storage; call it as late as
// possible, at the point of output, and do not store the result.
//
// A failure of w is ErrIO, wrapping w's error; a failure to reach the
// protected memory holding the credential is ErrProtectedMemory.
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

// ParseRecoveryKey normalizes a typed-or-pasted recovery key that the caller
// has already placed in protected memory: trims surrounding whitespace and
// refuses anything that cannot be a single-line credential. text stays the
// caller's; the result is a new enclave. Unlike the internal
// parseLegacyRecoveryKey, the input never passes through a Go string at this
// boundary.
func ParseRecoveryKey(text *enclave.Memory) (*enclave.Memory, error) {
	return recoverykey.Credential(custody, text)
}

// AddRecoveryKey adds rk to the volume as a new keyslot and records a
// systemd-recovery token naming it, re-verifying key against the volume's
// digests under the exclusive lock taken here rather than
// trusting it was still valid as of whatever Unlock call produced it. It is
// built on the same keyslot and token internals as Enroll (provider.go),
// used directly with key rather than re-deriving the master key from a
// passphrase -- key already is it.
//
// rk must come from NewRecoveryKey: the library-generated KDF exemption this
// enrolls under assumes exactly that. If the token cannot be written the
// keyslot is rolled back, the same guard Enroll uses, so a credential that
// nothing describes is never left live.
//
// Two-phase on purpose: the caller shows or persists rk
// BEFORE calling this, so there is no save-error field to report through.
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
