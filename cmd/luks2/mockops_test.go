// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// The LuksOperations mock, in its own file for the same reason operations.go
// exists: the interface covers the whole library surface the tool reaches, and
// two hundred lines of one-line stubs in the middle of cli_test.go would bury
// the tests that matter.
//
// EVERY method answers from a Func field when one is set and returns a benign
// zero value otherwise. That default is what lets a test that cares about one
// call ignore the other thirty -- but it is also why a test must assert on what
// it was HANDED rather than only on the exit code: a mock that returns nil for
// everything makes any command look like it worked.

// MockLuksOperations implements LuksOperations for testing
type MockLuksOperations struct {
	FormatFunc           func(opts luks2.FormatOptions) error
	UnlockFunc           func(device string, passphrase []byte, name string) error
	LockFunc             func(name string) error
	MountFunc            func(opts luks2.MountOptions) error
	UnmountFunc          func(mountPoint string, flags int) error
	GetVolumeInfoFunc    func(device string) (*luks2.VolumeInfo, error)
	WipeFunc             func(opts luks2.WipeOptions) error
	SetupLoopDeviceFunc  func(filename string) (string, error)
	DetachLoopDeviceFunc func(loopDev string) error
	MakeFilesystemFunc   func(volumeName, fstype, label string) error
	IsMountedFunc        func(mountPoint string) (bool, error)
	IsUnlockedFunc       func(name string) bool

	// Keyslots
	TestKeyFunc      func(device string, passphrase []byte) error
	AddKeyFunc       func(device string, existing, newPassphrase []byte, opts *luks2.AddKeyOptions) (int, error)
	RemoveKeyFunc    func(device string, passphrase []byte, keyslot int) error
	KillSlotFunc     func(device string, authPassphrase []byte, targetSlot int) error
	ChangeKeyFunc    func(device string, oldPassphrase, newPassphrase []byte, keyslot int) error
	ListKeyslotsFunc func(device string) ([]luks2.KeyslotInfo, error)

	// Recovery keys
	GenerateRecoveryKeyFunc    func(length int, format luks2.RecoveryKeyFormat) (*luks2.RecoveryKey, error)
	AddRecoveryKeyFunc         func(device string, existing []byte, opts *luks2.RecoveryKeyOptions) (*luks2.RecoveryKey, error)
	SaveRecoveryKeyFunc        func(key *luks2.RecoveryKey, path string) error
	LoadRecoveryCredentialFunc func(path string) (*enclave.MemoryEnclave, error)
	RecoveryCredentialFunc     func(formatted string) (*enclave.MemoryEnclave, error)
	VerifyRecoveryKeyFunc      func(device string, key *enclave.MemoryEnclave) (bool, error)

	// Tokens
	GetTokenFunc          func(device string, tokenID int) (*luks2.Token, error)
	ListTokensFunc        func(device string) (map[int]*luks2.Token, error)
	ExportTokenFunc       func(device string, tokenID int) ([]byte, error)
	ImportTokenFunc       func(device string, tokenID int, token *luks2.Token) error
	ImportTokenJSONFunc   func(device string, tokenID int, tokenJSON []byte) error
	RemoveTokenFunc       func(device string, tokenID int) error
	FindFreeTokenSlotFunc func(device string) (int, error)
	TokenExistsFunc       func(device string, tokenID int) (bool, error)
	CountTokensFunc       func(device string) (int, error)

	// Header
	ReadHeaderFunc           func(device string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error)
	ReadSecondaryHeaderFunc  func(device string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error)
	RestorePrimaryHeaderFunc func(device string) error
	IsLUKSFunc               func(device string) (bool, error)
	IsLUKS2Func              func(device string) (bool, error)
}

func (m *MockLuksOperations) Format(opts luks2.FormatOptions) error {
	if m.FormatFunc != nil {
		return m.FormatFunc(opts)
	}
	return nil
}

func (m *MockLuksOperations) Unlock(device string, passphrase []byte, name string) error {
	if m.UnlockFunc != nil {
		return m.UnlockFunc(device, passphrase, name)
	}
	return nil
}

func (m *MockLuksOperations) Lock(name string) error {
	if m.LockFunc != nil {
		return m.LockFunc(name)
	}
	return nil
}

func (m *MockLuksOperations) Mount(opts luks2.MountOptions) error {
	if m.MountFunc != nil {
		return m.MountFunc(opts)
	}
	return nil
}

func (m *MockLuksOperations) Unmount(mountPoint string, flags int) error {
	if m.UnmountFunc != nil {
		return m.UnmountFunc(mountPoint, flags)
	}
	return nil
}

func (m *MockLuksOperations) GetVolumeInfo(device string) (*luks2.VolumeInfo, error) {
	if m.GetVolumeInfoFunc != nil {
		return m.GetVolumeInfoFunc(device)
	}
	return &luks2.VolumeInfo{
		UUID:           "test-uuid",
		Label:          "TestVolume",
		Version:        2,
		Cipher:         "aes-xts-plain64",
		SectorSize:     512,
		ActiveKeyslots: []int{0},
		Metadata: &luks2.LUKS2Metadata{
			Keyslots: map[string]*luks2.Keyslot{
				"0": {
					Type:    "luks2",
					KeySize: 64,
					KDF:     &luks2.KDF{Type: "argon2id"},
				},
			},
		},
	}, nil
}

func (m *MockLuksOperations) Wipe(opts luks2.WipeOptions) error {
	if m.WipeFunc != nil {
		return m.WipeFunc(opts)
	}
	return nil
}

func (m *MockLuksOperations) SetupLoopDevice(filename string) (string, error) {
	if m.SetupLoopDeviceFunc != nil {
		return m.SetupLoopDeviceFunc(filename)
	}
	return "/dev/loop0", nil
}

func (m *MockLuksOperations) DetachLoopDevice(loopDev string) error {
	if m.DetachLoopDeviceFunc != nil {
		return m.DetachLoopDeviceFunc(loopDev)
	}
	return nil
}

func (m *MockLuksOperations) MakeFilesystem(volumeName, fstype, label string) error {
	if m.MakeFilesystemFunc != nil {
		return m.MakeFilesystemFunc(volumeName, fstype, label)
	}
	return nil
}

func (m *MockLuksOperations) IsMounted(mountPoint string) (bool, error) {
	if m.IsMountedFunc != nil {
		return m.IsMountedFunc(mountPoint)
	}
	return false, nil
}

func (m *MockLuksOperations) IsUnlocked(name string) bool {
	if m.IsUnlockedFunc != nil {
		return m.IsUnlockedFunc(name)
	}
	return false
}

// --- Keyslots ---

func (m *MockLuksOperations) TestKey(device string, passphrase []byte) error {
	if m.TestKeyFunc != nil {
		return m.TestKeyFunc(device, passphrase)
	}
	return nil
}

func (m *MockLuksOperations) AddKey(device string, existing, newPassphrase []byte, opts *luks2.AddKeyOptions) (int, error) {
	if m.AddKeyFunc != nil {
		return m.AddKeyFunc(device, existing, newPassphrase, opts)
	}
	return 0, nil
}

func (m *MockLuksOperations) RemoveKey(device string, passphrase []byte, keyslot int) error {
	if m.RemoveKeyFunc != nil {
		return m.RemoveKeyFunc(device, passphrase, keyslot)
	}
	return nil
}

func (m *MockLuksOperations) KillSlot(device string, authPassphrase []byte, targetSlot int) error {
	if m.KillSlotFunc != nil {
		return m.KillSlotFunc(device, authPassphrase, targetSlot)
	}
	return nil
}

func (m *MockLuksOperations) ChangeKey(device string, oldPassphrase, newPassphrase []byte, keyslot int) error {
	if m.ChangeKeyFunc != nil {
		return m.ChangeKeyFunc(device, oldPassphrase, newPassphrase, keyslot)
	}
	return nil
}

func (m *MockLuksOperations) ListKeyslots(device string) ([]luks2.KeyslotInfo, error) {
	if m.ListKeyslotsFunc != nil {
		return m.ListKeyslotsFunc(device)
	}
	return []luks2.KeyslotInfo{{ID: 0, Type: "luks2", KeySize: 64, KDFType: "argon2id", Encryption: "aes-xts-plain64"}}, nil
}

// --- Recovery keys ---

func (m *MockLuksOperations) GenerateRecoveryKey(length int, format luks2.RecoveryKeyFormat) (*luks2.RecoveryKey, error) {
	if m.GenerateRecoveryKeyFunc != nil {
		return m.GenerateRecoveryKeyFunc(length, format)
	}
	// A REAL recovery key, from the library, because the tests here assert on
	// what is displayed and a hand-built fixture would let a formatting bug
	// through: the printed string is the credential, character for character.
	return luks2.GenerateRecoveryKey(length, format)
}

func (m *MockLuksOperations) AddRecoveryKey(device string, existing []byte, opts *luks2.RecoveryKeyOptions) (*luks2.RecoveryKey, error) {
	if m.AddRecoveryKeyFunc != nil {
		return m.AddRecoveryKeyFunc(device, existing, opts)
	}
	return luks2.GenerateRecoveryKey(opts.Length, opts.Format)
}

func (m *MockLuksOperations) SaveRecoveryKey(key *luks2.RecoveryKey, path string) error {
	if m.SaveRecoveryKeyFunc != nil {
		return m.SaveRecoveryKeyFunc(key, path)
	}
	return nil
}

func (m *MockLuksOperations) LoadRecoveryCredential(path string) (*enclave.MemoryEnclave, error) {
	if m.LoadRecoveryCredentialFunc != nil {
		return m.LoadRecoveryCredentialFunc(path)
	}
	return enclave.NewMemoryEnclave([]byte("a-loaded-recovery-key"))
}

func (m *MockLuksOperations) RecoveryCredential(formatted string) (*enclave.MemoryEnclave, error) {
	if m.RecoveryCredentialFunc != nil {
		return m.RecoveryCredentialFunc(formatted)
	}
	return enclave.NewMemoryEnclave([]byte(formatted))
}

func (m *MockLuksOperations) VerifyRecoveryKey(device string, key *enclave.MemoryEnclave) (bool, error) {
	if m.VerifyRecoveryKeyFunc != nil {
		return m.VerifyRecoveryKeyFunc(device, key)
	}
	return true, nil
}

// --- Tokens ---

func (m *MockLuksOperations) GetToken(device string, tokenID int) (*luks2.Token, error) {
	if m.GetTokenFunc != nil {
		return m.GetTokenFunc(device, tokenID)
	}
	return &luks2.Token{Type: "systemd-fido2", Keyslots: []string{"1"}}, nil
}

func (m *MockLuksOperations) ListTokens(device string) (map[int]*luks2.Token, error) {
	if m.ListTokensFunc != nil {
		return m.ListTokensFunc(device)
	}
	return map[int]*luks2.Token{}, nil
}

func (m *MockLuksOperations) ExportToken(device string, tokenID int) ([]byte, error) {
	if m.ExportTokenFunc != nil {
		return m.ExportTokenFunc(device, tokenID)
	}
	return []byte(`{"type":"systemd-fido2","keyslots":["1"]}`), nil
}

func (m *MockLuksOperations) ImportToken(device string, tokenID int, token *luks2.Token) error {
	if m.ImportTokenFunc != nil {
		return m.ImportTokenFunc(device, tokenID, token)
	}
	return nil
}

func (m *MockLuksOperations) ImportTokenJSON(device string, tokenID int, tokenJSON []byte) error {
	if m.ImportTokenJSONFunc != nil {
		return m.ImportTokenJSONFunc(device, tokenID, tokenJSON)
	}
	return nil
}

func (m *MockLuksOperations) RemoveToken(device string, tokenID int) error {
	if m.RemoveTokenFunc != nil {
		return m.RemoveTokenFunc(device, tokenID)
	}
	return nil
}

func (m *MockLuksOperations) FindFreeTokenSlot(device string) (int, error) {
	if m.FindFreeTokenSlotFunc != nil {
		return m.FindFreeTokenSlotFunc(device)
	}
	return 0, nil
}

func (m *MockLuksOperations) TokenExists(device string, tokenID int) (bool, error) {
	if m.TokenExistsFunc != nil {
		return m.TokenExistsFunc(device, tokenID)
	}
	return false, nil
}

func (m *MockLuksOperations) CountTokens(device string) (int, error) {
	if m.CountTokensFunc != nil {
		return m.CountTokensFunc(device)
	}
	return 0, nil
}

// --- Header ---

func (m *MockLuksOperations) ReadHeader(device string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error) {
	if m.ReadHeaderFunc != nil {
		return m.ReadHeaderFunc(device)
	}
	return mockHeader(2, 7), mockMetadata(), nil
}

func (m *MockLuksOperations) ReadSecondaryHeader(device string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error) {
	if m.ReadSecondaryHeaderFunc != nil {
		return m.ReadSecondaryHeaderFunc(device)
	}
	return mockHeader(2, 7), mockMetadata(), nil
}

func (m *MockLuksOperations) RestorePrimaryHeader(device string) error {
	if m.RestorePrimaryHeaderFunc != nil {
		return m.RestorePrimaryHeaderFunc(device)
	}
	return nil
}

func (m *MockLuksOperations) IsLUKS(device string) (bool, error) {
	if m.IsLUKSFunc != nil {
		return m.IsLUKSFunc(device)
	}
	return true, nil
}

func (m *MockLuksOperations) IsLUKS2(device string) (bool, error) {
	if m.IsLUKS2Func != nil {
		return m.IsLUKS2Func(device)
	}
	return true, nil
}

// mockHeader builds a binary header with the fields the header report prints.
func mockHeader(version uint16, sequence uint64) *luks2.LUKS2BinaryHeader {
	hdr := &luks2.LUKS2BinaryHeader{
		Version:    version,
		HeaderSize: 16384,
		SequenceID: sequence,
	}
	copy(hdr.UUID[:], "12345678-1234-1234-1234-123456789abc")
	copy(hdr.Label[:], "TestVolume")
	copy(hdr.ChecksumAlgorithm[:], "sha256")
	return hdr
}

// mockMetadata builds the JSON metadata the header report counts.
func mockMetadata() *luks2.LUKS2Metadata {
	return &luks2.LUKS2Metadata{
		Keyslots: map[string]*luks2.Keyslot{"0": {Type: "luks2", KeySize: 64}},
		Tokens:   map[string]*luks2.Token{},
		Segments: map[string]*luks2.Segment{"0": {Type: "crypt"}},
		Digests:  map[string]*luks2.Digest{"0": {Type: "pbkdf2"}},
	}
}
