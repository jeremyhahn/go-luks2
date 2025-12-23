// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"fmt"
	"testing"
)

func TestEncryptKeyMaterial(t *testing.T) {
	// Test with valid data
	data := make([]byte, 512) // Must be multiple of sector size
	for i := range data {
		data[i] = byte(i % 256)
	}

	key := make([]byte, 64) // 512-bit key for AES-256-XTS
	for i := range key {
		key[i] = byte(i)
	}

	encrypted, err := encryptKeyMaterial(data, key, "aes")
	if err != nil {
		t.Fatalf("encryptKeyMaterial() error = %v", err)
	}

	if len(encrypted) != len(data) {
		t.Errorf("encrypted length = %d, want %d", len(encrypted), len(data))
	}

	// Verify data was actually encrypted (not the same as input)
	same := true
	for i := range data {
		if data[i] != encrypted[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("encrypted data is same as input")
	}
}

func TestEncryptKeyMaterial_InvalidCipher(t *testing.T) {
	data := make([]byte, 512)
	key := make([]byte, 64)

	_, err := encryptKeyMaterial(data, key, "invalid")
	if err == nil {
		t.Error("encryptKeyMaterial() should fail with invalid cipher")
	}
}

func TestDecryptKeyMaterial(t *testing.T) {
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i % 256)
	}

	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}

	// Encrypt then decrypt
	encrypted, err := encryptKeyMaterial(data, key, "aes")
	if err != nil {
		t.Fatalf("encryptKeyMaterial() error = %v", err)
	}

	decrypted, err := decryptKeyMaterial(encrypted, key, "aes", 512)
	if err != nil {
		t.Fatalf("decryptKeyMaterial() error = %v", err)
	}

	// Verify decrypted data matches original
	for i := range data {
		if data[i] != decrypted[i] {
			t.Errorf("decrypted[%d] = %d, want %d", i, decrypted[i], data[i])
		}
	}
}

func TestDecryptKeyMaterial_InvalidCipher(t *testing.T) {
	data := make([]byte, 512)
	key := make([]byte, 64)

	_, err := decryptKeyMaterial(data, key, "invalid", 512)
	if err == nil {
		t.Error("decryptKeyMaterial() should fail with invalid cipher")
	}
}

func TestDecryptKeyMaterial_DifferentDataSizes(t *testing.T) {
	// Test different data sizes (multiples of 512-byte sectors)
	dataSizes := []int{512, 1024, 2048, 4096}

	for _, dataSize := range dataSizes {
		t.Run(fmt.Sprintf("size_%d", dataSize), func(t *testing.T) {
			data := make([]byte, dataSize)
			for i := range data {
				data[i] = byte(i % 256)
			}

			key := make([]byte, 64)
			for i := range key {
				key[i] = byte(i)
			}

			encrypted, err := encryptKeyMaterial(data, key, "aes")
			if err != nil {
				t.Fatalf("encryptKeyMaterial() error = %v", err)
			}

			// Always use 512-byte sectors for decryption (matches encryptKeyMaterial)
			decrypted, err := decryptKeyMaterial(encrypted, key, "aes", 512)
			if err != nil {
				t.Fatalf("decryptKeyMaterial() error = %v", err)
			}

			for i := range data {
				if data[i] != decrypted[i] {
					t.Errorf("decrypted[%d] = %d, want %d", i, decrypted[i], data[i])
					break
				}
			}
		})
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Test multiple sector round trips
	testData := make([]byte, 4096) // Multiple sectors
	for i := range testData {
		testData[i] = byte((i * 7) % 256) // Some pattern
	}

	key := make([]byte, 64)
	for i := range key {
		key[i] = byte((i + 17) % 256)
	}

	encrypted, err := encryptKeyMaterial(testData, key, "aes")
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	decrypted, err := decryptKeyMaterial(encrypted, key, "aes", 512)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	for i := range testData {
		if testData[i] != decrypted[i] {
			t.Fatalf("mismatch at position %d: got %d, want %d", i, decrypted[i], testData[i])
		}
	}
}
