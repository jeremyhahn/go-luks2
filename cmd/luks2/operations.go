// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// The library calls the keyslot, recovery, token and header subcommands make.
//
// They live behind LuksOperations for the same reason the seven original
// commands do: a CLI test must be able to say "the library refused" without
// having a LUKS container to refuse with. The implementations here are one line
// each and deliberately so -- anything with a decision in it belongs in the
// library, where it can be tested against cryptsetup, not in a shim the tests
// mock away.

// --- Keyslots ---

func (d *DefaultLuksOperations) TestKey(device string, passphrase []byte) error {
	return luks2.TestKey(device, passphrase)
}

func (d *DefaultLuksOperations) AddKey(device string, existing, newPassphrase []byte, opts *luks2.AddKeyOptions) (int, error) {
	return luks2.AddKey(device, existing, newPassphrase, opts)
}

func (d *DefaultLuksOperations) RemoveKey(device string, passphrase []byte, keyslot int) error {
	return luks2.RemoveKey(device, passphrase, keyslot)
}

func (d *DefaultLuksOperations) KillSlot(device string, authPassphrase []byte, targetSlot int) error {
	return luks2.KillSlot(device, authPassphrase, targetSlot)
}

func (d *DefaultLuksOperations) ChangeKey(device string, oldPassphrase, newPassphrase []byte, keyslot int) error {
	return luks2.ChangeKey(device, oldPassphrase, newPassphrase, keyslot)
}

func (d *DefaultLuksOperations) ListKeyslots(device string) ([]luks2.KeyslotInfo, error) {
	return luks2.ListKeyslots(device)
}

// --- Recovery keys ---

func (d *DefaultLuksOperations) GenerateRecoveryKey(length int, format luks2.RecoveryKeyFormat) (*luks2.RecoveryKey, error) {
	return luks2.GenerateRecoveryKey(length, format)
}

func (d *DefaultLuksOperations) AddRecoveryKey(device string, existing []byte, opts *luks2.RecoveryKeyOptions) (*luks2.RecoveryKey, error) {
	return luks2.AddRecoveryKey(device, existing, opts)
}

func (d *DefaultLuksOperations) SaveRecoveryKey(key *luks2.RecoveryKey, path string) error {
	return luks2.SaveRecoveryKey(key, path)
}

func (d *DefaultLuksOperations) LoadRecoveryCredential(path string) (*enclave.MemoryEnclave, error) {
	return luks2.LoadRecoveryCredential(path)
}

func (d *DefaultLuksOperations) RecoveryCredential(formatted string) (*enclave.MemoryEnclave, error) {
	return luks2.RecoveryCredential(formatted)
}

func (d *DefaultLuksOperations) VerifyRecoveryKey(device string, key *enclave.MemoryEnclave) (bool, error) {
	return luks2.VerifyRecoveryKey(device, key)
}

// --- Tokens ---

func (d *DefaultLuksOperations) GetToken(device string, tokenID int) (*luks2.Token, error) {
	return luks2.GetToken(device, tokenID)
}

func (d *DefaultLuksOperations) ListTokens(device string) (map[int]*luks2.Token, error) {
	return luks2.ListTokens(device)
}

func (d *DefaultLuksOperations) ExportToken(device string, tokenID int) ([]byte, error) {
	return luks2.ExportToken(device, tokenID)
}

func (d *DefaultLuksOperations) ImportToken(device string, tokenID int, token *luks2.Token) error {
	return luks2.ImportToken(device, tokenID, token)
}

func (d *DefaultLuksOperations) ImportTokenJSON(device string, tokenID int, tokenJSON []byte) error {
	return luks2.ImportTokenJSON(device, tokenID, tokenJSON)
}

func (d *DefaultLuksOperations) RemoveToken(device string, tokenID int) error {
	return luks2.RemoveToken(device, tokenID)
}

func (d *DefaultLuksOperations) FindFreeTokenSlot(device string) (int, error) {
	return luks2.FindFreeTokenSlot(device)
}

func (d *DefaultLuksOperations) TokenExists(device string, tokenID int) (bool, error) {
	return luks2.TokenExists(device, tokenID)
}

func (d *DefaultLuksOperations) CountTokens(device string) (int, error) {
	return luks2.CountTokens(device)
}

// --- Header ---

func (d *DefaultLuksOperations) ReadHeader(device string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error) {
	return luks2.ReadHeader(device)
}

func (d *DefaultLuksOperations) ReadSecondaryHeader(device string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error) {
	return luks2.ReadSecondaryHeader(device)
}

func (d *DefaultLuksOperations) RestorePrimaryHeader(device string) error {
	return luks2.RestorePrimaryHeader(device)
}

func (d *DefaultLuksOperations) IsLUKS(device string) (bool, error) {
	return luks2.IsLUKS(device)
}

func (d *DefaultLuksOperations) IsLUKS2(device string) (bool, error) {
	return luks2.IsLUKS2(device)
}
