package luks2

// Conformance tests for docs/recovery-keys/engineering.md: the requirements
// of its Exported surface, Invariants and Generated credentials sections that
// no other test pins. Each test names the sentence it holds the code to.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// openUnlockedLibraryVolume formats a fresh image with the library, opens it
// with the production volumeSys (so the production KDF floors apply) and
// unlocks it with the conformance passphrase.
func openUnlockedLibraryVolume(t *testing.T, name string) (string, *Volume, *Key) {
	t.Helper()
	path := newImage(t, name)
	formatWithLibrary(t, path)

	ctx := context.Background()
	v, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	pass, err := enclave.NewMemoryCopy([]byte(conformancePassphrase))
	if err != nil {
		t.Fatalf("could not build a test passphrase enclave: %v", err)
	}
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	t.Cleanup(key.Destroy)
	return path, v, key
}

// "Recovery keys are random bytes drawn by the library": the reader
// NewRecoveryKey draws from is the operating system's CSPRNG, and no
// exported option can hand it another source.
func TestRecoveryEngCredentialComesOnlyFromTheLibraryCSPRNG(t *testing.T) {
	if got := defaultVolumeSys().cryptoRand; got != rand.Reader {
		t.Fatalf("the production random source is %T, want crypto/rand.Reader", got)
	}

	// RecoveryKeyOption is func(*recoveryOptions): whatever recoveryOptions
	// holds is all a caller can set. A reader, a seed or the bytes themselves
	// in it would let a caller choose the credential.
	opts := reflect.TypeOf(recoveryOptions{})
	want := map[string]reflect.Type{
		"format": reflect.TypeOf(RecoveryKeyFormat(0)),
		"length": reflect.TypeOf(0),
	}
	if opts.NumField() != len(want) {
		t.Fatalf("recoveryOptions has %d fields, want only format and length", opts.NumField())
	}
	for i := 0; i < opts.NumField(); i++ {
		f := opts.Field(i)
		if wt, ok := want[f.Name]; !ok || f.Type != wt {
			t.Errorf("recoveryOptions.%s (%v) is not an option this document allows", f.Name, f.Type)
		}
	}

	// Two draws differ: the credential is not a fixed or derived value.
	var texts [2]bytes.Buffer
	for i := range texts {
		rk, err := NewRecoveryKey()
		if err != nil {
			t.Fatalf("NewRecoveryKey failed: %v", err)
		}
		if _, err := rk.WriteTo(&texts[i]); err != nil {
			t.Fatalf("WriteTo failed: %v", err)
		}
		rk.Destroy()
	}
	if bytes.Equal(texts[0].Bytes(), texts[1].Bytes()) {
		t.Fatal("two NewRecoveryKey calls produced the same key")
	}
}

// "a credential never becomes a Go string in this API": the generated
// credential, and the one ParseRecoveryKey returns, are go-enclave
// locked-memory handles.
func TestRecoveryEngCredentialStaysInLockedMemory(t *testing.T) {
	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()
	if got := rk.credential.Backend().Name(); got != enclave.LockedMemoryBackendName {
		t.Errorf("NewRecoveryKey holds its credential in %q, want %q", got, enclave.LockedMemoryBackendName)
	}

	var text bytes.Buffer
	if _, err := rk.WriteTo(&text); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	typed, err := enclave.NewMemoryCopy(text.Bytes())
	if err != nil {
		t.Fatalf("could not build a test enclave: %v", err)
	}
	defer func() { _ = typed.Destroy() }()
	credential, err := ParseRecoveryKey(typed)
	if err != nil {
		t.Fatalf("ParseRecoveryKey failed: %v", err)
	}
	defer custody.Release(credential)
	if got := credential.Backend().Name(); got != enclave.LockedMemoryBackendName {
		t.Errorf("ParseRecoveryKey returns a credential in %q, want %q", got, enclave.LockedMemoryBackendName)
	}
}

// "only a failure to reach the protected memory holding the credential is
// ErrProtectedMemory": a destroyed key reports that, not ErrIO, and writes
// nothing.
func TestRecoveryEngWriteToADestroyedKeyIsProtectedMemory(t *testing.T) {
	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	rk.Destroy()

	var out bytes.Buffer
	n, err := rk.WriteTo(&out)
	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("WriteTo after Destroy = %v, want ErrProtectedMemory", err)
	}
	if errors.Is(err, ErrIO) {
		t.Errorf("WriteTo after Destroy = %v, also reports ErrIO", err)
	}
	if n != 0 || out.Len() != 0 {
		t.Errorf("WriteTo after Destroy wrote %d bytes (reported %d), want none", out.Len(), n)
	}
}

// "`--length` is the number of random bytes, default 32; zero means 32."
func TestRecoveryEngZeroLengthMeansTheDefault(t *testing.T) {
	if DefaultRecoveryKeyLength != 32 {
		t.Fatalf("DefaultRecoveryKeyLength = %d, want 32", DefaultRecoveryKeyLength)
	}
	rk, err := NewRecoveryKey(WithRecoveryFormat(RecoveryHex), WithRecoveryLength(0))
	if err != nil {
		t.Fatalf("NewRecoveryKey(length 0) failed: %v", err)
	}
	defer rk.Destroy()
	var text bytes.Buffer
	if _, err := rk.WriteTo(&text); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if got, want := text.Len(), 2*DefaultRecoveryKeyLength; got != want {
		t.Errorf("hex key for length 0 is %d characters, want %d (32 bytes)", got, want)
	}
}

// "For keyslots written by AddRecoveryKey the floor is 1000": the floor is
// systemd's count, and AddRecoveryKey refuses one iteration below it without
// touching the header.
func TestRecoveryEngAddRecoveryKeyRefusesBelowItsOwnFloor(t *testing.T) {
	if minPBKDF2Iterations != 1000 {
		t.Fatalf("the recovery keyslot floor is %d, want systemd's 1000", minPBKDF2Iterations)
	}

	path, v, key := openUnlockedLibraryVolume(t, "recovery-below-floor.img")
	_, before, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	_, err = v.AddRecoveryKey(context.Background(), key, rk, KeyslotParams{KDF: KDFParams{
		Type:       KDFPBKDF2,
		Hash:       crypto.SHA512,
		Iterations: minPBKDF2Iterations - 1,
	}})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("AddRecoveryKey at %d iterations = %v, want ErrInvalidArgument", minPBKDF2Iterations-1, err)
	}
	var refusal *KDFCostError
	if !errors.As(err, &refusal) {
		t.Fatalf("AddRecoveryKey error %v is not a *KDFCostError", err)
	}
	if refusal.Min != minPBKDF2Iterations {
		t.Errorf("AddRecoveryKey reports a floor of %d, want %d", refusal.Min, minPBKDF2Iterations)
	}

	_, after, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if len(after.Keyslots) != len(before.Keyslots) || len(after.Tokens) != len(before.Tokens) {
		t.Errorf("a refused AddRecoveryKey changed the header: keyslots %d -> %d, tokens %d -> %d",
			len(before.Keyslots), len(after.Keyslots), len(before.Tokens), len(after.Tokens))
	}
}

// "Enroll keeps the full passphrase floor": the count AddRecoveryKey accepts
// is refused for a provider's credential.
func TestRecoveryEngEnrollKeepsTheFullFloor(t *testing.T) {
	_, v, key := openUnlockedLibraryVolume(t, "recovery-enroll-floor.img")

	provider := &fakeKeyProvider{credential: []byte("a-provider-credential")}
	_, err := v.Enroll(context.Background(), key, provider, KeyslotParams{KDF: KDFParams{
		Type:       KDFPBKDF2,
		Hash:       crypto.SHA512,
		Iterations: minPBKDF2Iterations,
	}})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Enroll at the recovery floor (%d) = %v, want ErrInvalidArgument", minPBKDF2Iterations, err)
	}
	var refusal *KDFCostError
	if !errors.As(err, &refusal) {
		t.Fatalf("Enroll error %v is not a *KDFCostError", err)
	}
	if refusal.Min <= minPBKDF2Iterations {
		t.Errorf("Enroll reports a floor of %d, want the passphrase floor above %d", refusal.Min, minPBKDF2Iterations)
	}
}
