// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/secret"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// TokenTypeFIDO2 is the token type systemd-cryptenroll --fido2-device
// writes, and the one this package drives.
//
// It is systemd's spelling, and that is deliberate: a token type is how an
// implementation decides whether it can drive a keyslot at all, so a private
// spelling would produce a container only this library can use -- the
// opposite of what binding a volume to a hardware key is for.
const TokenTypeFIDO2 = "systemd-fido2"

// DefaultRelyingParty is the relying-party id systemd-cryptenroll uses.
// Matching it is part of being openable by systemd-cryptsetup.
const DefaultRelyingParty = "io.systemd.cryptsetup"

// SaltLength is the length of the hmac-secret salt, in bytes. The
// authenticator derives a SecretLength-byte secret from it; 32 is what
// systemd writes.
const SaltLength = 32

// SecretLength is the length of the hmac-secret an authenticator derives
// from a single salt, in bytes.
//
// It is checked rather than assumed, and that check is the backstop for
// fido2AssertSecretLine: reading the wrong line yields a field of some other
// length, and refusing it turns a credential that enrolls cleanly and never
// opens the volume into an error at enrollment time.
const SecretLength = 32

// fido2ClientDataHashLength is the length of the client data hash the
// helpers expect, in bytes -- a SHA-256 digest.
const fido2ClientDataHashLength = 32

// Default helper locations, used when no FIDO2Option names one. These are
// where the libfido2 tools package installs them on Linux.
const (
	defaultFIDO2CredPath   = "/usr/bin/fido2-cred" // #nosec G101 -- a program path; "cred" here is the fido2-cred binary, not a credential
	defaultFIDO2AssertPath = "/usr/bin/fido2-assert"
)

// Line numbers in the helper protocols, from the fido2-cred(1) and
// fido2-assert(1) output formats.
//
// They are named rather than written at the call sites because they are the
// single most fragile assumption in this file: a helper that grows a field
// silently moves the credential to a different line, and the failure mode is
// a keyslot that enrolls cleanly and opens nothing.
const (
	// fido2CredIDLine is the credential id in `fido2-cred -M` output.
	fido2CredIDLine = 5

	// fido2AssertSecretLine is the hmac-secret in `fido2-assert -G -h`
	// output for the assertion THIS PACKAGE PERFORMS.
	//
	// fido2-assert(1) OUTPUT FORMAT lists, for each assertion:
	//
	//	1. client data hash      4. assertion signature
	//	2. relying party id      5. user id, IF CREDENTIAL RESIDENT
	//	3. authenticator data    6. hmac secret, if -h
	//	                         7. largeBlobKey, if -b
	//
	// Field 5 is CONDITIONAL, so the secret is on line 6 only when the
	// assertion was obtained from a resident (discoverable) credential.
	// This package always supplies a credential id -- FIDO2Params.validate
	// refuses a binding without one, and `-r` is never passed to
	// fido2-assert -- so the user id is not emitted and the secret is on
	// line 5. `-b` is never passed either, so nothing follows it.
	//
	// NOT EXECUTED AGAINST HARDWARE. The ordering is the documented one and
	// it could not be confirmed on this host: a production authenticator is
	// attached and enrolling against it is forbidden. CTAP2 leaves the
	// authenticator some latitude about returning user information for a
	// single-entry allow list, which is precisely the latitude that would
	// shift this line -- so the secret's LENGTH is checked as well as its
	// position. See FIDO2.Passphrase: field 4, the signature, is a ~70-byte
	// DER blob and would be refused rather than enrolled.
	fido2AssertSecretLine = 5
)

// fido2SecretEncoding is THE ONE PLACE the enrolled form of a FIDO2
// hmac-secret is decided, and every caller of normalizeFIDO2Secret -- this
// library's own and a token someone else wrote -- goes through it.
//
// # What is enrolled is not the secret
//
// systemd does not enroll the raw 32 bytes the authenticator produces. It
// enrolls the BASE64 TEXT of those bytes as an ASCII passphrase. Enrolling
// the raw bytes instead produces a keyslot that systemd-cryptsetup can never
// open, and vice versa.
//
// That it base64-encodes before enrolling is VERIFIED, on systemd 255: the
// string "Failed to base64 encode secret key: %m" is in the
// systemd-cryptenroll binary, alongside the token type "systemd-fido2" and
// the field names this package writes.
//
// # Which base64, MEASURED against a real artifact
//
// Standard alphabet, padded. That was an inference until three YubiKeys were
// enrolled into a real volume with systemd-cryptenroll (systemd 255,
// cryptsetup 2.7.0) and the resulting header was counted. Across the six
// base64 members of the three tokens it wrote -- fido2-credential and
// fido2-salt:
//
//	standard-only characters (+ /)   4
//	URL-safe-only characters (- _)   0
//	padding characters       (=)     9
//
// The nine padding characters settle padding OUTRIGHT: base64.RawStdEncoding
// and base64.RawURLEncoding emit none, ever, so neither is what wrote that
// header. The alphabet count settles the alphabet for those fields: over
// roughly 250 characters of random material a URL-safe encoder would be
// expected to emit several "-" or "_", and it emitted none while emitting
// four "+" or "/".
//
// # What this still does not prove
//
// It proves the encoding of the TOKEN FIELDS. The secret-as-passphrase goes
// through the same systemd base64 helper, which makes this strong evidence
// for that path rather than direct proof of it. Settling it outright takes
// one non-destructive step -- run fido2-assert with the recorded credential
// and salt, base64 the result, offer it to `cryptsetup luksOpen
// --test-passphrase` -- and an assertion only reads the key.
//
// Until that lands, this variable is the whole of the exposure: if the
// passphrase path ever turns out to differ, one of the other three encodings
// goes here and nothing else in the package moves.
var fido2SecretEncoding = base64.StdEncoding

// FIDO2Params is what a volume's FIDO2 binding consists of: which credential
// on which authenticator, salted with what, and what the user has to do to
// use it.
//
// None of it is secret. All of it is written into the LUKS2 header in the
// clear -- the security comes from the authenticator refusing to derive the
// secret without the credential and the user's consent, not from hiding the
// parameters.
type FIDO2Params struct {
	// RelyingParty is the rp id the credential was made under. Empty means
	// DefaultRelyingParty.
	RelyingParty string

	// CredentialID identifies the credential on the authenticator.
	CredentialID []byte

	// Salt is the hmac-secret salt. The same salt against the same
	// credential yields the same secret; a different salt yields a
	// different one.
	Salt []byte

	// UserPresence requires a touch (`-t up=true`).
	UserPresence bool

	// UserVerification requires the authenticator to verify the user, by
	// biometric or on-device PIN (`-t uv=true`).
	UserVerification bool

	// ClientPIN requires a PIN typed to the helper (`-t pin=true`). The
	// helper prompts for it on its own controlling terminal, which is why
	// an unattended unlock must not set this.
	ClientPIN bool
}

func (p FIDO2Params) relyingParty() string {
	if p.RelyingParty != "" {
		return p.RelyingParty
	}
	return DefaultRelyingParty
}

// validate refuses a binding that cannot produce a secret.
func (p FIDO2Params) validate() error {
	switch {
	case len(p.CredentialID) == 0:
		return &errs.Error{Kind: ErrInvalidBinding, Detail: "no credential id"}
	case len(p.Salt) == 0:
		return &errs.Error{Kind: ErrInvalidBinding, Detail: "no salt"}
	}
	return nil
}

// NewFIDO2Salt draws a fresh hmac-secret salt.
//
// It is ordinary memory on purpose: the salt is written into the header in
// the clear and protecting the copy in this process would protect nothing.
func NewFIDO2Salt() ([]byte, error) {
	salt, err := randomFIDO2Bytes(SaltLength)
	if err != nil {
		return nil, errAt("NewFIDO2Salt", "", err)
	}
	return salt, nil
}

// fido2Options is what WithFIDO2Tools and WithDevice set: the helper
// binaries and the authenticator an operation talks to.
//
// The paths are ABSOLUTE and are not looked up on PATH. What unlocks a
// volume must not depend on the environment of whoever invoked the process
// -- a PATH entry a user controls would otherwise be a way to substitute the
// program that produces the credential.
type fido2Options struct {
	credPath   string
	assertPath string
	device     string
}

// FIDO2Option configures NewFIDO2, NewFIDO2Credential and FromToken.
type FIDO2Option func(*fido2Options)

// WithFIDO2Tools names the fido2-cred and fido2-assert binaries. Empty
// strings keep the default for that one.
func WithFIDO2Tools(credPath, assertPath string) FIDO2Option {
	return func(o *fido2Options) { o.credPath, o.assertPath = credPath, assertPath }
}

// WithDevice names the authenticator, as libfido2 names it (a hidraw path on
// Linux). It is required: the helpers take the device as a mandatory
// argument and have no default.
func WithDevice(path string) FIDO2Option {
	return func(o *fido2Options) { o.device = path }
}

func (o fido2Options) resolvedCredPath() string {
	if o.credPath != "" {
		return o.credPath
	}
	return defaultFIDO2CredPath
}

func (o fido2Options) resolvedAssertPath() string {
	if o.assertPath != "" {
		return o.assertPath
	}
	return defaultFIDO2AssertPath
}

func (o fido2Options) resolvedDevice() (string, error) {
	if o.device == "" {
		return "", &errs.Error{Kind: ErrNoDevice}
	}
	return o.device, nil
}

// FIDO2 is the unlock side of a FIDO2 binding: a Command running
// fido2-assert, plus the normalization that decides what the enrolled
// credential actually is.
//
// It WRAPS Command rather than reimplementing it. There is one exec path in
// this package and this is not a second one -- what is added here is the
// base64 round trip and nothing else.
type FIDO2 struct {
	cmd      *Command
	encoding *base64.Encoding
}

var _ luks2.KeyProvider = (*FIDO2)(nil)

// Token returns the metadata for this binding, per luks2.KeyProvider.
func (f *FIDO2) Token() luks2.Token { return f.cmd.Token() }

// Passphrase runs the assertion and returns the base64 text of the
// authenticator's hmac-secret -- what is actually enrolled, per
// fido2SecretEncoding.
func (f *FIDO2) Passphrase(ctx context.Context) (enclave.ByteAccess, error) {
	const op = "FIDO2.Passphrase"

	line, err := f.cmd.Passphrase(ctx)
	if err != nil {
		return nil, err
	}
	defer secret.System().Release(line)

	var credential enclave.ByteAccess
	if err := secret.Borrow("fido2 secret", line, func(b []byte) error {
		var err error
		credential, err = normalizeFIDO2Secret(f.encoding, b)
		return err
	}); err != nil {
		return nil, errAt(op, "", err)
	}

	// The enrolled credential is base64 TEXT, so its length is the encoded
	// length of a SecretLength secret. Anything else means the line taken
	// from the helper was not the hmac-secret -- see fido2AssertSecretLine
	// -- and enrolling it would produce a keyslot that opens nothing.
	if want := f.encoding.EncodedLen(SecretLength); credential.Size() != want {
		secret.System().Release(credential)
		return nil, errAt(op, "", &errs.Error{
			Kind: ErrHelperOutput,
			Detail: fmt.Sprintf("line %d of the assertion is not a %d-byte hmac-secret; the helper's output format is not the one this package expects",
				f.cmd.line, SecretLength),
		})
	}

	return credential, nil
}

// NewFIDO2 builds the provider that unlocks a volume with a FIDO2
// authenticator, and the token that records the binding.
func NewFIDO2(p FIDO2Params, opts ...FIDO2Option) (*FIDO2, error) {
	const op = "NewFIDO2"

	if err := p.validate(); err != nil {
		return nil, errAt(op, "", err)
	}

	var o fido2Options
	for _, opt := range opts {
		opt(&o)
	}
	device, err := o.resolvedDevice()
	if err != nil {
		return nil, errAt(op, "", err)
	}

	clientData, err := newFIDO2ClientDataHash()
	if err != nil {
		return nil, errAt(op, "", err)
	}

	// The assertion's input fields, one per line, in the order fido2-assert
	// reads them: client data hash, rp id, credential id, salt.
	stdin := fido2Lines(
		base64.StdEncoding.EncodeToString(clientData),
		p.relyingParty(),
		base64.StdEncoding.EncodeToString(p.CredentialID),
		base64.StdEncoding.EncodeToString(p.Salt),
	)

	args := []string{"-G", "-h"}
	if p.UserPresence {
		args = append(args, "-t", "up=true")
	}
	if p.ClientPIN {
		args = append(args, "-t", "pin=true")
	}
	if p.UserVerification {
		args = append(args, "-v")
	}
	// "--" ends the options: a device name is never read as one.
	args = append(args, "--", device)

	cmd, err := NewCommand(o.resolvedAssertPath(),
		WithArgs(args...),
		WithStdin(stdin),
		WithLine(fido2AssertSecretLine),
		WithToken(fido2Token(p)),
	)
	if err != nil {
		return nil, errAt(op, "", err)
	}

	return &FIDO2{cmd: cmd, encoding: fido2SecretEncoding}, nil
}

// FIDO2CredentialParams are the enrollment-time choices that are made once,
// when the credential is created on the authenticator, and cannot be changed
// afterwards.
type FIDO2CredentialParams struct {
	// RelyingParty is the rp id to create the credential under. Empty
	// means DefaultRelyingParty.
	RelyingParty string

	// UserName and UserID identify the credential to the authenticator.
	// They are only meaningful for a resident credential.
	UserName string
	UserID   []byte

	// Resident asks for a discoverable (resident) credential, which the
	// authenticator stores itself so that unlocking needs no credential id
	// from the header (`-r`).
	Resident bool

	// UserVerification requires the authenticator to verify the user at
	// creation (`-v`).
	UserVerification bool
}

// NewFIDO2Credential creates a credential on an authenticator and returns
// its id.
//
// The `-h` flag is not optional and is not a preference: it is what enables
// the hmac-secret extension ON THE CREDENTIAL, at creation. A credential
// made without it can never produce a secret, no matter what the assertion
// asks for, and the failure surfaces much later as an unlock that yields
// nothing.
//
// The credential id is NOT secret -- it is written into the LUKS2 header in
// the clear -- but it arrives through the same locked-memory path as
// everything else the helpers produce, because that path is Command, and
// having a second one would mean having a second thing to get right.
func NewFIDO2Credential(ctx context.Context, p FIDO2CredentialParams, opts ...FIDO2Option) ([]byte, error) {
	const op = "NewFIDO2Credential"

	var o fido2Options
	for _, opt := range opts {
		opt(&o)
	}
	device, err := o.resolvedDevice()
	if err != nil {
		return nil, errAt(op, "", err)
	}

	clientData, err := newFIDO2ClientDataHash()
	if err != nil {
		return nil, errAt(op, "", err)
	}

	userID := p.UserID
	if len(userID) == 0 {
		userID, err = randomFIDO2Bytes(fido2ClientDataHashLength)
		if err != nil {
			return nil, errAt(op, "", err)
		}
	}
	rp := p.RelyingParty
	if rp == "" {
		rp = DefaultRelyingParty
	}
	userName := p.UserName
	if userName == "" {
		userName = "luks2"
	}

	// The creation input fields, one per line, in the order fido2-cred
	// reads them: client data hash, rp id, user name, user id.
	stdin := fido2Lines(
		base64.StdEncoding.EncodeToString(clientData),
		rp,
		userName,
		base64.StdEncoding.EncodeToString(userID),
	)

	args := []string{"-M", "-h"}
	if p.Resident {
		args = append(args, "-r")
	}
	if p.UserVerification {
		args = append(args, "-v")
	}
	args = append(args, "--", device, "es256")

	cred, err := NewCommand(o.resolvedCredPath(), WithArgs(args...), WithStdin(stdin), WithLine(fido2CredIDLine))
	if err != nil {
		return nil, errAt(op, "", err)
	}

	encoded, err := cred.Passphrase(ctx)
	if err != nil {
		return nil, errAt(op, "", err)
	}
	defer secret.System().Release(encoded)

	var id []byte
	if err := secret.Borrow("fido2 credential id", encoded, func(b []byte) error {
		decoded, err := base64.StdEncoding.DecodeString(string(b))
		if err != nil {
			return &errs.Error{Kind: ErrHelperOutput, Detail: "the credential id is not base64"}
		}
		id = decoded
		return nil
	}); err != nil {
		return nil, errAt(op, "", err)
	}

	return id, nil
}

// FromToken builds the provider a token describes, so a volume can be opened
// from what is recorded on the device rather than from options supplied
// again at unlock time.
//
// A token type this package cannot drive is refused rather than
// approximated.
func FromToken(t luks2.Token, opts ...FIDO2Option) (luks2.KeyProvider, error) {
	const op = "FromToken"

	if t.Type == "" {
		return nil, errAt(op, "", &errs.Error{Kind: ErrInvalidArgument, Detail: "no token"})
	}

	switch t.Type {
	case TokenTypeFIDO2:
		params, err := fido2ParamsFromToken(t)
		if err != nil {
			return nil, errAt(op, "", err)
		}
		p, err := NewFIDO2(params, opts...)
		if err != nil {
			return nil, errAt(op, "", err)
		}
		return p, nil
	default:
		return nil, errAt(op, "", &errs.Error{Kind: ErrUnsupportedToken, Detail: fmt.Sprintf("%q", t.Type)})
	}
}

// ---------------------------------------------------------------------------
// Token <-> FIDO2Params
//
// EVERY read and write of a Token's FIDO2 fields in this package happens in
// the two functions below, so the schema is confined to one pair of
// functions rather than scattered across the package.
// ---------------------------------------------------------------------------

// fido2Token renders a binding as the token that goes in the header.
//
// FIDO2UPRequired is written EXPLICITLY, including when it is false. The
// member is a *bool precisely because false is a value systemd records on
// purpose -- `--fido2-with-user-presence=no` writes it -- and this package
// knows which of the two it means, because it is the one assembling the
// binding. Emitting the pointer rather than relying on omitempty is what
// keeps "presence not required" distinguishable from "this token says
// nothing about presence" on the way back in.
//
// The PIN and user-verification requirements are written the same way, for
// the same reason: a token that omitted them was rebuilt by
// fido2ParamsFromToken into a binding that asked for neither, dropping the
// PIN the enrollment demanded (#246 D9).
func fido2Token(p FIDO2Params) luks2.Token {
	return luks2.Token{
		Type: TokenTypeFIDO2,
		Members: map[string]json.RawMessage{
			"fido2-credential":         mustJSONString(base64.StdEncoding.EncodeToString(p.CredentialID)),
			"fido2-salt":               mustJSONString(base64.StdEncoding.EncodeToString(p.Salt)),
			"fido2-rp":                 mustJSONString(p.relyingParty()),
			"fido2-clientPin-required": mustJSONBool(p.ClientPIN),
			"fido2-up-required":        mustJSONBool(p.UserPresence),
			"fido2-uv-required":        mustJSONBool(p.UserVerification),
		},
	}
}

// mustJSONString and mustJSONBool build the json.RawMessage values
// fido2Token writes into Token.Members. Marshaling a string or a bool cannot
// fail, so the error is not propagated.
func mustJSONString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

func mustJSONBool(b bool) json.RawMessage {
	out, _ := json.Marshal(b)
	return out
}

// fido2Member reads a string member out of a token's Members, or "" if it is
// absent -- the same default the old typed string fields gave an absent
// member.
func fido2Member(members map[string]json.RawMessage, key string) (string, error) {
	raw, ok := members[key]
	if !ok {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", &errs.Error{Kind: ErrInvalidBinding, Detail: key + " is not a string"}
	}
	return s, nil
}

// fido2RequirementMember reads a boolean requirement member, defaulting to
// false when absent -- see fido2ParamsFromToken's original reasoning: the
// member was a plain bool before the three requirement flags became
// pointers, so "not set" and false were the same value on the way in.
func fido2RequirementMember(members map[string]json.RawMessage, key string) bool {
	raw, ok := members[key]
	if !ok {
		return false
	}
	var b bool
	_ = json.Unmarshal(raw, &b)
	return b
}

// fido2ParamsFromToken reads a binding back out of a token.
//
// A field that does not decode is REFUSED rather than defaulted. A binding
// assembled from a half-read token produces an assertion that returns a
// different secret, and "the volume no longer opens" is not the error
// message anyone should get for a malformed base64 field.
func fido2ParamsFromToken(t luks2.Token) (FIDO2Params, error) {
	credentialB64, err := fido2Member(t.Members, "fido2-credential")
	if err != nil {
		return FIDO2Params{}, err
	}
	credential, err := base64.StdEncoding.DecodeString(credentialB64)
	if err != nil {
		return FIDO2Params{}, &errs.Error{Kind: ErrInvalidBinding, Detail: "fido2-credential is not base64"}
	}
	saltB64, err := fido2Member(t.Members, "fido2-salt")
	if err != nil {
		return FIDO2Params{}, err
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return FIDO2Params{}, &errs.Error{Kind: ErrInvalidBinding, Detail: "fido2-salt is not base64"}
	}
	rp, err := fido2Member(t.Members, "fido2-rp")
	if err != nil {
		return FIDO2Params{}, err
	}

	// An ABSENT fido2-up-required reads as false: the member was a plain
	// bool before the three requirement flags became pointers, so "not
	// set" and false were the same value on the way in and every token
	// read so far was read this way.
	//
	// The PIN and user-verification requirements are read the same way:
	// absent is false, present is what it says.
	params := FIDO2Params{
		RelyingParty:     rp,
		CredentialID:     credential,
		Salt:             salt,
		UserPresence:     fido2RequirementMember(t.Members, "fido2-up-required"),
		ClientPIN:        fido2RequirementMember(t.Members, "fido2-clientPin-required"),
		UserVerification: fido2RequirementMember(t.Members, "fido2-uv-required"),
	}
	if err := params.validate(); err != nil {
		return FIDO2Params{}, err
	}
	return params, nil
}

// fido2Lines renders the helpers' stdin: one field per line,
// newline-terminated.
func fido2Lines(fields ...string) []byte {
	var buf []byte
	for _, f := range fields {
		buf = append(buf, f...)
		buf = append(buf, '\n')
	}
	return buf
}

// newFIDO2ClientDataHash draws the client data hash the helpers require.
//
// It is random rather than fixed, and it does NOT participate in the
// hmac-secret derivation: the secret is a function of the credential, the
// authenticator's own seed and the salt. Nothing depends on this value being
// the same at enrollment and at unlock, which is why it is not recorded.
func newFIDO2ClientDataHash() ([]byte, error) {
	return randomFIDO2Bytes(fido2ClientDataHashLength)
}

// randomFIDO2Bytes draws n bytes of ordinary (not locked) memory. Every
// value drawn here -- a client data hash, a salt, a fallback user id -- is
// written into the LUKS2 header in the clear, so protecting the copy in this
// process would protect nothing.
func randomFIDO2Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Err: err}
	}
	return b, nil
}

// normalizeFIDO2Secret turns a helper's base64 output line into the
// credential that is actually enrolled, under encoding (fido2SecretEncoding
// on every production path).
//
// It decodes and re-encodes rather than forwarding the helper's bytes, so
// the enrolled form is decided HERE and not by whatever the helper happened
// to print. A line that does not decode is refused: a credential built from
// garbage enrolls perfectly well and opens nothing, which is the failure
// this package exists to make impossible.
func normalizeFIDO2Secret(encoding *base64.Encoding, line []byte) (enclave.ByteAccess, error) {
	const op = "fido2 secret"
	custody := secret.System()

	// Refused HERE rather than left to the allocator. An empty input is a
	// protocol failure -- the authenticator returned no secret -- and
	// reporting it as "protected memory unavailable" would send an
	// operator to look at RLIMIT_MEMLOCK for a problem with their key.
	if len(line) == 0 {
		return nil, &errs.Error{Kind: ErrHelperOutput, Detail: "the authenticator returned an empty secret"}
	}

	raw, err := custody.New(op, encoding.DecodedLen(len(line)))
	if err != nil {
		return nil, err
	}
	defer custody.Release(raw)

	var rawLen int
	if err := secret.Borrow(op, raw, func(dst []byte) error {
		n, err := encoding.Decode(dst, line)
		if err != nil {
			return &errs.Error{
				Kind:   ErrHelperOutput,
				Detail: fmt.Sprintf("the authenticator's secret is not %s base64", fido2EncodingName(encoding)),
			}
		}
		rawLen = n
		return nil
	}); err != nil {
		return nil, err
	}
	if rawLen == 0 {
		return nil, &errs.Error{Kind: ErrHelperOutput, Detail: "the authenticator returned an empty secret"}
	}

	encoded, err := custody.New(op, encoding.EncodedLen(rawLen))
	if err != nil {
		return nil, err
	}
	if err := secret.Borrow(op, raw, func(src []byte) error {
		return secret.Borrow(op, encoded, func(dst []byte) error {
			encoding.Encode(dst, src[:rawLen])
			return nil
		})
	}); err != nil {
		custody.Release(encoded)
		return nil, err
	}

	return encoded, nil
}

// fido2EncodingName describes encoding in an error message, so a report from
// the field says which alphabet was expected without the reader having to go
// and look.
func fido2EncodingName(encoding *base64.Encoding) string {
	switch encoding {
	case base64.StdEncoding:
		return "standard, padded"
	case base64.RawStdEncoding:
		return "standard, unpadded"
	case base64.URLEncoding:
		return "URL-safe, padded"
	case base64.RawURLEncoding:
		return "URL-safe, unpadded"
	default:
		return "the configured"
	}
}
