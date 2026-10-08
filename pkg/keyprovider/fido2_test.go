// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package keyprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func TestNormalizeFIDO2SecretIsCanonicalBase64(t *testing.T) {
	secret := make([]byte, SecretLength)
	for i := range secret {
		secret[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(secret)

	got, err := normalizeFIDO2Secret(base64.StdEncoding, []byte(encoded))
	if err != nil {
		t.Fatalf("normalizeFIDO2Secret() error = %v", err)
	}
	defer mustDestroy(t, got)

	if s := string(openSecret(t, got)); s != encoded {
		t.Errorf("enrolled credential = %q, want %q", s, encoded)
	}

	// It is TEXT that is enrolled, not the raw bytes. Getting this backwards
	// produces a keyslot systemd-cryptsetup can never open.
	if s := string(openSecret(t, got)); s == string(secret) {
		t.Error("the raw secret was enrolled; systemd enrolls its base64 text")
	}
}

func TestNormalizeFIDO2SecretRefusesWhatItCannotDecode(t *testing.T) {
	secret := make([]byte, SecretLength)
	std := base64.StdEncoding.EncodeToString(secret)

	tests := []struct {
		name string
		line string
	}{
		{name: "not base64 at all", line: "!!! not base64 !!!"},
		{name: "unpadded", line: strings.TrimRight(std, "=")},
		{name: "empty", line: ""},
		{name: "url-safe alphabet", line: base64.URLEncoding.EncodeToString([]byte{0xfb, 0xff, 0xfe})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeFIDO2Secret(base64.StdEncoding, []byte(tt.line))
			if err == nil {
				mustDestroy(t, got)
				t.Fatal("normalizeFIDO2Secret() accepted output it cannot decode")
			}
			if !errors.Is(err, ErrHelperOutput) {
				t.Errorf("error = %v, want errors.Is(_, ErrHelperOutput)", err)
			}
		})
	}
}

func TestFIDO2EncodingNameDescribesTheAlphabet(t *testing.T) {
	tests := []struct {
		encoding *base64.Encoding
		want     string
	}{
		{encoding: base64.StdEncoding, want: "standard, padded"},
		{encoding: base64.RawStdEncoding, want: "standard, unpadded"},
		{encoding: base64.URLEncoding, want: "URL-safe, padded"},
		{encoding: base64.RawURLEncoding, want: "URL-safe, unpadded"},
		{encoding: base64.NewEncoding("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"), want: "the configured"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := fido2EncodingName(tt.encoding); got != tt.want {
				t.Errorf("fido2EncodingName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestChangingTheEncodingChangesWhatIsEnrolled is the point of taking the
// encoding as a parameter: if hardware ever disproves the standard-padded
// inference, swapping it in NewFIDO2 is the whole change.
func TestChangingTheEncodingChangesWhatIsEnrolled(t *testing.T) {
	secret := make([]byte, SecretLength)
	for i := range secret {
		secret[i] = byte(i * 7)
	}

	got, err := normalizeFIDO2Secret(base64.RawStdEncoding, []byte(base64.RawStdEncoding.EncodeToString(secret)))
	if err != nil {
		t.Fatalf("normalizeFIDO2Secret() error = %v", err)
	}
	defer mustDestroy(t, got)

	if s := string(openSecret(t, got)); s != base64.RawStdEncoding.EncodeToString(secret) {
		t.Errorf("enrolled = %q, want the unpadded encoding", s)
	}
}

// assertOutput renders the stdout of a non-resident `fido2-assert -G -h`
// run, with secret as the hmac-secret field.
//
// The field ORDER is the assumption under test everywhere below; it is
// written once, here, so there is one place to change if hardware disproves
// it.
func assertOutput(secret string) string {
	return strings.Join([]string{
		base64.StdEncoding.EncodeToString([]byte("client data hash")), // 1
		DefaultRelyingParty, // 2
		base64.StdEncoding.EncodeToString([]byte("authdata")),  // 3
		base64.StdEncoding.EncodeToString([]byte("signature")), // 4
		secret, // 5
	}, "\n") + "\n"
}

func fido2TestParams(t *testing.T) FIDO2Params {
	t.Helper()

	salt, err := NewFIDO2Salt()
	if err != nil {
		t.Fatalf("NewFIDO2Salt() error = %v", err)
	}
	if len(salt) != SaltLength {
		t.Fatalf("salt length = %d, want %d", len(salt), SaltLength)
	}
	return FIDO2Params{
		CredentialID: []byte("credential-id-bytes"),
		Salt:         salt,
		UserPresence: true,
	}
}

func TestFIDO2EnrollsTheBase64OfTheSecret(t *testing.T) {
	secret := make([]byte, SecretLength)
	for i := range secret {
		secret[i] = byte(255 - i)
	}
	encoded := base64.StdEncoding.EncodeToString(secret)

	helper, argsFile, stdinFile := echoingHelper(t, "fido2-assert", assertOutput(encoded))
	params := fido2TestParams(t)

	p, err := NewFIDO2(params, WithFIDO2Tools("", helper), WithDevice("/dev/hidraw9"))
	if err != nil {
		t.Fatalf("NewFIDO2() error = %v", err)
	}

	credential, err := p.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase() error = %v", err)
	}
	defer mustDestroy(t, credential)

	if s := string(openSecret(t, credential)); s != encoded {
		t.Errorf("credential = %q, want the base64 text %q", s, encoded)
	}

	// The invocation itself is interop-critical. -h is what enables
	// hmac-secret on the assertion; without it no secret is ever returned.
	args := readFixture(t, argsFile)
	for _, want := range []string{"-G\n", "-h\n", "up=true\n", "/dev/hidraw9\n"} {
		if !strings.Contains(args, want) {
			t.Errorf("argv = %q, want it to contain %q", args, want)
		}
	}
	if strings.Contains(args, "-r\n") {
		t.Error("argv asked for a resident assertion; the secret's line number assumes it did not")
	}

	// The input fields, in the order fido2-assert(1) documents.
	stdin := strings.Split(strings.TrimRight(readFixture(t, stdinFile), "\n"), "\n")
	if len(stdin) != 4 {
		t.Fatalf("stdin had %d fields, want 4: %q", len(stdin), stdin)
	}
	if stdin[1] != DefaultRelyingParty {
		t.Errorf("stdin[1] = %q, want the relying party %q", stdin[1], DefaultRelyingParty)
	}
	if stdin[2] != base64.StdEncoding.EncodeToString(params.CredentialID) {
		t.Errorf("stdin[2] = %q, want the base64 credential id", stdin[2])
	}
	if stdin[3] != base64.StdEncoding.EncodeToString(params.Salt) {
		t.Errorf("stdin[3] = %q, want the base64 salt", stdin[3])
	}
}

// TestFIDO2RefusesAFieldThatIsNotTheSecret is the backstop for
// fido2AssertSecretLine.
//
// If an authenticator ever emits a user id for a single-entry allow list,
// the package reads the signature instead of the secret. That field decodes
// as base64 perfectly well, so only its LENGTH distinguishes it -- and
// enrolling it would produce a keyslot that opens nothing, discovered months
// later.
func TestFIDO2RefusesAFieldThatIsNotTheSecret(t *testing.T) {
	signature := base64.StdEncoding.EncodeToString(make([]byte, 71))

	helper := helperScript(t, "fido2-assert", assertOutput(signature))
	p, err := NewFIDO2(fido2TestParams(t), WithFIDO2Tools("", helper), WithDevice("/dev/hidraw9"))
	if err != nil {
		t.Fatalf("NewFIDO2() error = %v", err)
	}

	got, err := p.Passphrase(context.Background())
	if err == nil {
		mustDestroy(t, got)
		t.Fatal("Passphrase() accepted a field that is not a 32-byte hmac-secret")
	}
	if !errors.Is(err, ErrHelperOutput) {
		t.Errorf("error = %v, want errors.Is(_, ErrHelperOutput)", err)
	}
}

func TestNewFIDO2RefusesAnIncompleteBinding(t *testing.T) {
	tests := []struct {
		name   string
		params FIDO2Params
	}{
		{name: "no credential id", params: FIDO2Params{Salt: []byte("salt")}},
		{name: "no salt", params: FIDO2Params{CredentialID: []byte("cred")}},
		{name: "nothing at all", params: FIDO2Params{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewFIDO2(tt.params); !errors.Is(err, ErrInvalidBinding) {
				t.Errorf("error = %v, want errors.Is(_, ErrInvalidBinding)", err)
			}
		})
	}
}

func TestNewFIDO2CredentialReadsTheCredentialID(t *testing.T) {
	credID := []byte("a credential identifier")
	stdout := strings.Join([]string{
		base64.StdEncoding.EncodeToString([]byte("client data hash")), // 1
		DefaultRelyingParty, // 2
		"packed",            // 3
		base64.StdEncoding.EncodeToString([]byte("authdata")),    // 4
		base64.StdEncoding.EncodeToString(credID),                // 5
		base64.StdEncoding.EncodeToString([]byte("attestation")), // 6
	}, "\n") + "\n"

	helper, argsFile, stdinFile := echoingHelper(t, "fido2-cred", stdout)

	got, err := NewFIDO2Credential(context.Background(), FIDO2CredentialParams{UserName: "operator"},
		WithFIDO2Tools(helper, ""), WithDevice("/dev/hidraw9"))
	if err != nil {
		t.Fatalf("NewFIDO2Credential() error = %v", err)
	}
	if string(got) != string(credID) {
		t.Errorf("credential id = %q, want %q", got, credID)
	}

	// -h at CREATION is what gives the credential an hmac-secret at all. A
	// credential made without it can never produce a secret, however the
	// assertion is phrased.
	args := readFixture(t, argsFile)
	for _, want := range []string{"-M\n", "-h\n", "es256\n", "/dev/hidraw9\n"} {
		if !strings.Contains(args, want) {
			t.Errorf("argv = %q, want it to contain %q", args, want)
		}
	}

	stdin := strings.Split(strings.TrimRight(readFixture(t, stdinFile), "\n"), "\n")
	if len(stdin) != 4 {
		t.Fatalf("stdin had %d fields, want 4: %q", len(stdin), stdin)
	}
	if stdin[2] != "operator" {
		t.Errorf("stdin[2] = %q, want the user name", stdin[2])
	}
}

func TestNewFIDO2CredentialRefusesUnusableOutput(t *testing.T) {
	helper := helperScript(t, "fido2-cred", "one\ntwo\nthree\nfour\n!!! not base64 !!!\n")

	if _, err := NewFIDO2Credential(context.Background(), FIDO2CredentialParams{}, WithFIDO2Tools(helper, ""), WithDevice("/dev/hidraw9")); !errors.Is(err, ErrHelperOutput) {
		t.Errorf("error = %v, want errors.Is(_, ErrHelperOutput)", err)
	}
}

func TestFromTokenBuildsTheBindingTheHeaderRecords(t *testing.T) {
	params := fido2TestParams(t)
	token := fido2Token(params)

	if token.Type != TokenTypeFIDO2 {
		t.Fatalf("token type = %q, want %q", token.Type, TokenTypeFIDO2)
	}

	round, err := fido2ParamsFromToken(token)
	if err != nil {
		t.Fatalf("fido2ParamsFromToken() error = %v", err)
	}
	if string(round.CredentialID) != string(params.CredentialID) {
		t.Errorf("credential id = %q, want %q", round.CredentialID, params.CredentialID)
	}
	if string(round.Salt) != string(params.Salt) {
		t.Errorf("salt = %x, want %x", round.Salt, params.Salt)
	}
	if round.relyingParty() != DefaultRelyingParty {
		t.Errorf("relying party = %q, want %q", round.relyingParty(), DefaultRelyingParty)
	}

	if _, err := FromToken(token, WithDevice("/dev/hidraw9")); err != nil {
		t.Errorf("FromToken() error = %v", err)
	}
}

func TestFromTokenRefusesWhatItCannotDrive(t *testing.T) {
	tests := []struct {
		name  string
		token luks2.Token
		want  error
	}{
		{name: "no token", token: luks2.Token{}, want: ErrInvalidArgument},
		{
			name:  "a token type this package cannot drive",
			token: luks2.Token{Type: "systemd-tpm2"},
			want:  ErrUnsupportedToken,
		},
		{
			name: "a credential id that is not base64",
			token: luks2.Token{Type: TokenTypeFIDO2, Members: map[string]json.RawMessage{
				"fido2-credential": json.RawMessage(`"!!!"`),
				"fido2-salt":       json.RawMessage(`"AAAA"`),
			}},
			want: ErrInvalidBinding,
		},
		{
			name: "a salt that is not base64",
			token: luks2.Token{Type: TokenTypeFIDO2, Members: map[string]json.RawMessage{
				"fido2-credential": json.RawMessage(`"AAAA"`),
				"fido2-salt":       json.RawMessage(`"!!!"`),
			}},
			want: ErrInvalidBinding,
		},
		{
			name: "a binding with no salt",
			token: luks2.Token{Type: TokenTypeFIDO2, Members: map[string]json.RawMessage{
				"fido2-credential": json.RawMessage(`"AAAA"`),
			}},
			want: ErrInvalidBinding,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := FromToken(tt.token); !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want errors.Is(_, %v)", err, tt.want)
			}
		})
	}
}

// TestVolumeEnrollWritesTheKeyslotAndTheTokenThatNamesIt-equivalent
// coverage for FIDO2's own Token wiring lives in pkg/luks2 no longer -- this
// is the provider-side half: FIDO2.Token must carry what FromToken rebuilds.
func TestFIDO2CarriesItsToken(t *testing.T) {
	params := fido2TestParams(t)

	p, err := NewFIDO2(params, WithDevice("/dev/hidraw9"))
	if err != nil {
		t.Fatalf("NewFIDO2() error = %v", err)
	}

	token := p.Token()
	if token.Type != TokenTypeFIDO2 {
		t.Errorf("token type = %q, want %q", token.Type, TokenTypeFIDO2)
	}
	saltMember, err := fido2Member(token.Members, "fido2-salt")
	if err != nil {
		t.Fatalf("fido2Member(fido2-salt) error = %v", err)
	}
	if saltMember != base64.StdEncoding.EncodeToString(params.Salt) {
		t.Error("the token does not carry the salt the provider asserts with")
	}
}

// TestFIDO2OptionsDefaultToTheInstalledHelpers: no FIDO2Option naming a
// helper must still reach the libfido2 tools, and must do so by ABSOLUTE
// PATH -- a PATH lookup would let whoever controls the environment decide
// what produces the credential.
func TestFIDO2OptionsDefaultToTheInstalledHelpers(t *testing.T) {
	var o fido2Options

	if o.resolvedCredPath() != defaultFIDO2CredPath {
		t.Errorf("resolvedCredPath() = %q, want %q", o.resolvedCredPath(), defaultFIDO2CredPath)
	}
	if o.resolvedAssertPath() != defaultFIDO2AssertPath {
		t.Errorf("resolvedAssertPath() = %q, want %q", o.resolvedAssertPath(), defaultFIDO2AssertPath)
	}
	for _, path := range []string{defaultFIDO2CredPath, defaultFIDO2AssertPath} {
		if !strings.HasPrefix(path, "/") {
			t.Errorf("%q is not an absolute path", path)
		}
	}
	if _, err := o.resolvedDevice(); !errors.Is(err, ErrNoDevice) {
		t.Errorf("resolvedDevice() error = %v, want errors.Is(_, ErrNoDevice)", err)
	}

	WithFIDO2Tools("/opt/fido2-cred", "/opt/fido2-assert")(&o)
	WithDevice("/dev/hidraw9")(&o)
	if o.resolvedCredPath() != "/opt/fido2-cred" || o.resolvedAssertPath() != "/opt/fido2-assert" {
		t.Error("an explicit helper path was not used")
	}
	if dev, err := o.resolvedDevice(); err != nil || dev != "/dev/hidraw9" {
		t.Errorf("resolvedDevice() = %q, %v, want %q, nil", dev, err, "/dev/hidraw9")
	}
}

// TestFIDO2ArgumentsFollowTheRequirementFlags: what the authenticator
// demands of the user is expressed in argv, and each flag has its own
// branch.
//
// These are not cosmetic. `-t pin=true` makes the helper prompt on its own
// controlling terminal, which is precisely what an unattended unlock must
// not do, and `-v` asks the authenticator for user verification. A provider
// built from a token that requires them and invoked without them gets a
// DIFFERENT assertion -- or none.
func TestFIDO2ArgumentsFollowTheRequirementFlags(t *testing.T) {
	tests := []struct {
		name    string
		params  FIDO2Params
		want    []string
		notWant []string
	}{
		{
			name:    "nothing required",
			params:  FIDO2Params{CredentialID: []byte("c"), Salt: []byte("s")},
			want:    []string{"-G", "-h"},
			notWant: []string{"up=true", "pin=true", "-v"},
		},
		{
			name:    "user presence",
			params:  FIDO2Params{CredentialID: []byte("c"), Salt: []byte("s"), UserPresence: true},
			want:    []string{"up=true"},
			notWant: []string{"pin=true", "-v"},
		},
		{
			name:    "client pin",
			params:  FIDO2Params{CredentialID: []byte("c"), Salt: []byte("s"), ClientPIN: true},
			want:    []string{"pin=true"},
			notWant: []string{"up=true"},
		},
		{
			name:   "user verification",
			params: FIDO2Params{CredentialID: []byte("c"), Salt: []byte("s"), UserVerification: true},
			want:   []string{"-v"},
		},
		{
			name: "everything",
			params: FIDO2Params{
				CredentialID: []byte("c"), Salt: []byte("s"),
				UserPresence: true, ClientPIN: true, UserVerification: true,
			},
			want: []string{"-G", "-h", "up=true", "pin=true", "-v"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewFIDO2(tt.params, WithFIDO2Tools("", "/usr/bin/fido2-assert"), WithDevice("/dev/hidraw9"))
			if err != nil {
				t.Fatalf("NewFIDO2() error = %v", err)
			}

			args := strings.Join(p.cmd.args, " ")
			for _, want := range tt.want {
				if !strings.Contains(args, want) {
					t.Errorf("argv = %q, want it to contain %q", args, want)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(args, notWant) {
					t.Errorf("argv = %q, want it NOT to contain %q", args, notWant)
				}
			}
		})
	}
}

func TestNewFIDO2CredentialArgumentsFollowTheOptions(t *testing.T) {
	credID := base64.StdEncoding.EncodeToString([]byte("id"))
	stdout := "1\n2\n3\n4\n" + credID + "\n6\n"

	tests := []struct {
		name    string
		params  FIDO2CredentialParams
		want    []string
		notWant []string
	}{
		{
			name:    "defaults",
			params:  FIDO2CredentialParams{},
			want:    []string{"-M\n", "-h\n", "es256\n"},
			notWant: []string{"-r\n", "-v\n"},
		},
		{
			name:   "resident and verified",
			params: FIDO2CredentialParams{Resident: true, UserVerification: true, UserID: []byte("a user id")},
			want:   []string{"-r\n", "-v\n"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helper, argsFile, stdinFile := echoingHelper(t, "fido2-cred", stdout)

			if _, err := NewFIDO2Credential(context.Background(), tt.params, WithFIDO2Tools(helper, ""), WithDevice("/dev/hidraw9")); err != nil {
				t.Fatalf("NewFIDO2Credential() error = %v", err)
			}

			args := readFixture(t, argsFile)
			for _, want := range tt.want {
				if !strings.Contains(args, want) {
					t.Errorf("argv = %q, want it to contain %q", args, want)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(args, notWant) {
					t.Errorf("argv = %q, want it NOT to contain %q", args, notWant)
				}
			}

			// A relying party is always sent, defaulted when the caller gave
			// none: systemd-cryptsetup looks the credential up by it.
			stdin := strings.Split(strings.TrimRight(readFixture(t, stdinFile), "\n"), "\n")
			if stdin[1] != DefaultRelyingParty {
				t.Errorf("relying party = %q, want %q", stdin[1], DefaultRelyingParty)
			}
		})
	}
}
