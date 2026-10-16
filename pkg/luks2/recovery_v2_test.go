// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto/fips140"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// argon2TestKDF is the minimum legal Argon2 cost keyslot tests use:
// m=64MiB t=1 p=1, fast enough for a unit test and still exercising the
// Argon2 path rather than PBKDF2's. A FIPS process refuses Argon2, so there
// it is the cheap PBKDF2 the migration tests use; wantKDFType names what the
// keyslot comes out with.
func argon2TestKDF() KDFParams {
	if fips140.Enabled() {
		return cheapMigrationParams()
	}
	return KDFParams{Type: KDFArgon2id, Time: 1, MemoryKiB: 64 * 1024, Parallel: 1}
}

// wantKDFType is the KDF type a keyslot written with argon2TestKDF carries.
func wantKDFType() KDFType {
	if fips140.Enabled() {
		return KDFPBKDF2
	}
	return KDFArgon2id
}

func TestNewRecoveryKeyDefaultsToDashedAt32Bytes(t *testing.T) {
	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	if got := rk.Format(); got != RecoveryDashed {
		t.Errorf("Format() = %v, want RecoveryDashed", got)
	}
	if rk.Hash() == "" {
		t.Error("Hash() is empty")
	}

	var buf bytes.Buffer
	n, err := rk.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if n == 0 || int(n) != buf.Len() {
		t.Errorf("WriteTo wrote %d, buffer holds %d", n, buf.Len())
	}
}

// failingWriter accepts nothing and fails every Write with err.
type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// TestRecoveryKeyWriteToReportsAWriteFailureAsIO: a failing writer is an I/O
// failure with the writer's error as its cause, not a protected-memory one.
func TestRecoveryKeyWriteToReportsAWriteFailureAsIO(t *testing.T) {
	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	cause := errors.New("disk full")
	_, err = rk.WriteTo(failingWriter{err: cause})
	if !errors.Is(err, ErrIO) {
		t.Errorf("WriteTo error = %v, want ErrIO", err)
	}
	if errors.Is(err, ErrProtectedMemory) {
		t.Errorf("WriteTo error = %v, reports a write failure as ErrProtectedMemory", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("WriteTo error = %v, does not wrap the writer's error", err)
	}
}

func TestNewRecoveryKeyHonorsFormatAndLengthOptions(t *testing.T) {
	rk, err := NewRecoveryKey(WithRecoveryFormat(RecoveryHex), WithRecoveryLength(64))
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	if got := rk.Format(); got != RecoveryHex {
		t.Errorf("Format() = %v, want RecoveryHex", got)
	}

	var buf bytes.Buffer
	if _, err := rk.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if got, want := buf.Len(), 128; got != want {
		t.Errorf("hex rendering of 64 bytes is %d chars, want %d", got, want)
	}
}

func TestNewRecoveryKeyRefusesATooShortLength(t *testing.T) {
	_, err := NewRecoveryKey(WithRecoveryLength(16))
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("NewRecoveryKey(16 bytes) = %v, want ErrInvalidArgument", err)
	}
}

func TestRecoveryKeyDestroyIsIdempotentAndNilSafe(t *testing.T) {
	var nilKey *RecoveryKey
	nilKey.Destroy() // must not panic

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	rk.Destroy()
	rk.Destroy() // idempotent
}

func TestParseRecoveryKeyFormatRoundTripsWithString(t *testing.T) {
	for _, f := range []RecoveryKeyFormat{RecoveryDashed, RecoveryHex, RecoveryBase64} {
		got, err := ParseRecoveryKeyFormat(f.String())
		if err != nil {
			t.Fatalf("ParseRecoveryKeyFormat(%q) failed: %v", f.String(), err)
		}
		if got != f {
			t.Errorf("ParseRecoveryKeyFormat(%q) = %v, want %v", f.String(), got, f)
		}
	}
}

func TestParseRecoveryKeyFormatRefusesUnknownName(t *testing.T) {
	if _, err := ParseRecoveryKeyFormat("rot13"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ParseRecoveryKeyFormat(\"rot13\") = %v, want ErrInvalidArgument", err)
	}
}

func TestParseRecoveryKeyNormalizesWhitespaceWithoutAGoString(t *testing.T) {
	typed, err := enclave.NewMemoryCopy([]byte("  9F3A2C-4B81DE  \n"))
	if err != nil {
		t.Fatalf("could not build a test enclave: %v", err)
	}
	defer func() { _ = typed.Destroy() }()

	credential, err := ParseRecoveryKey(typed)
	if err != nil {
		t.Fatalf("ParseRecoveryKey failed: %v", err)
	}
	defer custody.Release(credential)

	var s string
	if err := credential.WithBytes(func(b []byte) error {
		s = string(b)
		return nil
	}); err != nil {
		t.Fatalf("WithBytes failed: %v", err)
	}
	if s != "9F3A2C-4B81DE" {
		t.Errorf("ParseRecoveryKey normalized to %q, want %q", s, "9F3A2C-4B81DE")
	}
}

// recoveryKeyEnclave materializes rk's credential as a fresh enclave, the
// way a caller would before handing it to Unlock. Test-only: production
// code never round-trips a RecoveryKey's credential through WriteTo.
func recoveryKeyEnclave(t *testing.T, rk *RecoveryKey) enclave.ByteAccess {
	t.Helper()
	var buf bytes.Buffer
	if _, err := rk.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	e, err := enclave.NewMemoryCopy(buf.Bytes())
	if err != nil {
		t.Fatalf("could not build an enclave from the recovery key text: %v", err)
	}
	return e
}

func TestVolumeAddRecoveryKeyEnrollsAWorkingKeyslot(t *testing.T) {
	path := formattedVolumeImage(t, "addrecoverykey.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	enrollment, err := v.AddRecoveryKey(context.Background(), key, rk, KeyslotParams{KDF: argon2TestKDF()})
	if err != nil {
		t.Fatalf("AddRecoveryKey failed: %v", err)
	}
	if enrollment.Keyslot.ID == 0 {
		t.Errorf("header.Keyslot.ID = 0, want the new slot (the passphrase already holds 0)")
	}
	if enrollment.Keyslot.Type != "luks2" {
		t.Errorf("header.Keyslot.Type = %q, want %q", enrollment.Keyslot.Type, "luks2")
	}
	if got := enrollment.Keyslot.KDF.Type; got != wantKDFType() {
		t.Errorf("header.Keyslot.KDF.Type = %v, want %v", got, wantKDFType())
	}
	if enrollment.Keyslot.Priority != PriorityNormal {
		t.Errorf("header.Keyslot.Priority = %v, want PriorityNormal (unset KeyslotParams.Priority)", enrollment.Keyslot.Priority)
	}
	if enrollment.Token < 0 {
		t.Errorf("Token = %d, want a recorded token slot", enrollment.Token)
	}

	// The recovery key must actually open the volume.
	recovered := recoveryKeyEnclave(t, rk)
	defer func() { _ = recovered.Destroy() }()

	unlocked, err := v.Unlock(context.Background(), recovered)
	if err != nil {
		t.Fatalf("Unlock with the recovery key failed: %v", err)
	}
	defer unlocked.Destroy()
	if unlocked.Keyslot() != enrollment.Keyslot.ID {
		t.Errorf("Unlock with the recovery key opened keyslot %d, want %d", unlocked.Keyslot(), enrollment.Keyslot.ID)
	}
}

func TestVolumeAddRecoveryKeyHonorsPriorityPrefer(t *testing.T) {
	path := formattedVolumeImage(t, "addrecoverykeypriority.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	enrollment, err := v.AddRecoveryKey(context.Background(), key, rk, KeyslotParams{Priority: PriorityPrefer, KDF: argon2TestKDF()})
	if err != nil {
		t.Fatalf("AddRecoveryKey failed: %v", err)
	}
	if enrollment.Keyslot.Priority != PriorityPrefer {
		t.Errorf("header.Keyslot.Priority = %v, want PriorityPrefer", enrollment.Keyslot.Priority)
	}

	// The write must be durable, not just reflected in the return value.
	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	for _, s := range h.Keyslots() {
		if s.ID == enrollment.Keyslot.ID && s.Priority != PriorityPrefer {
			t.Errorf("re-read Priority = %v, want PriorityPrefer", s.Priority)
		}
	}
}

func TestVolumeAddRecoveryKeyRefusesANilKey(t *testing.T) {
	path := formattedVolumeImage(t, "addrecoverykeynilkey.img", "", "")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	if _, err := v.AddRecoveryKey(context.Background(), nil, rk, KeyslotParams{}); err == nil {
		t.Fatal("AddRecoveryKey with a nil key succeeded, want an error")
	}
}

func TestVolumeAddRecoveryKeyRefusesANilRecoveryKey(t *testing.T) {
	path := formattedVolumeImage(t, "addrecoverykeynilrk.img", "", "")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	if _, err := v.AddRecoveryKey(context.Background(), key, nil, KeyslotParams{}); err == nil {
		t.Fatal("AddRecoveryKey with a nil recovery key succeeded, want an error")
	}
}

func TestVolumeAddRecoveryKeyOnAReadOnlyVolumeFailsWithErrReadOnly(t *testing.T) {
	path := formattedVolumeImage(t, "addrecoverykeyreadonly.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	if _, err := v.AddRecoveryKey(context.Background(), nil, rk, KeyslotParams{}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("AddRecoveryKey on a read-only Volume = %v, want ErrReadOnly", err)
	}
}

func TestVolumeAddRecoveryKeyRollsBackTheKeyslotIfTheTokenWriteFails(t *testing.T) {
	path := formattedVolumeImage(t, "addrecoverykeyrollback.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	sentinel := &errs.Error{Detail: "injected token write failure"}
	v.sys.importToken = func(context.Context, *keyslotDevice, int, *LegacyToken) error { return sentinel }

	if _, err := v.AddRecoveryKey(context.Background(), key, rk, KeyslotParams{KDF: argon2TestKDF()}); err == nil {
		t.Fatal("AddRecoveryKey succeeded despite the injected token failure, want an error")
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := len(metadata.Keyslots); got != 1 {
		t.Errorf("keyslots after a rolled-back enrollment: %d, want 1 (the original passphrase only)", got)
	}
}
