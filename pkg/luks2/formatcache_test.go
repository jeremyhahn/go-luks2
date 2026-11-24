// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// No build constraint: tokenIDVolume (token_test.go, also unconstrained) is
// shared with the integration build and formats through here.

package luks2

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// formattedImage copies a container Format produced from opts once per process per key; key must change with opts or size.
func formattedImage(t *testing.T, key, name string, size int64, opts func() formatOptionsForTest) string {
	t.Helper()

	entry := formatCacheEntry(key)
	entry.once.Do(func() {
		entry.image, entry.err = formatSnapshot(size, opts())
	})
	if entry.err != nil {
		t.Fatalf("Format failed while building the shared %q container: %v", key, entry.err)
	}

	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to create image %s: %v", path, err)
	}
	defer func() { _ = f.Close() }() // failure paths only: success closes, checked, below
	if err := f.Truncate(size); err != nil {
		t.Fatalf("failed to size image %s: %v", path, err)
	}
	if _, err := f.WriteAt(entry.image, 0); err != nil {
		t.Fatalf("failed to copy the shared %q container onto %s: %v", key, path, err)
	}
	// Closed, not fsynced: see stampImagePrefix.
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close %s: %v", path, err)
	}
	return path
}

type formatCacheItem struct {
	once  sync.Once
	image []byte
	err   error
}

var (
	formatCacheMu    sync.Mutex
	formatCacheItems = map[string]*formatCacheItem{}
)

func formatCacheEntry(key string) *formatCacheItem {
	formatCacheMu.Lock()
	defer formatCacheMu.Unlock()

	entry, ok := formatCacheItems[key]
	if !ok {
		entry = &formatCacheItem{}
		formatCacheItems[key] = entry
	}
	return entry
}

// formatSnapshot runs a real Format on a scratch image of size bytes and
// returns the image's contents up to its last non-zero byte.
func formatSnapshot(size int64, opts formatOptionsForTest) ([]byte, error) {
	dir, err := os.MkdirTemp("", "luks2-formatcache-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	seed := filepath.Join(dir, "seed.img")
	f, err := os.Create(seed) // #nosec G304 -- path is under a temp dir this function made
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	opts.Device = seed
	if err := formatForTest(opts); err != nil {
		return nil, err
	}

	image, err := os.ReadFile(seed) // #nosec G304 -- path is under a temp dir this function made
	if err != nil {
		return nil, err
	}
	// Everything past the last non-zero byte is what Truncate already gives
	// every copy, so it need not be stored or written.
	// Cloned so the cache does not pin the whole image's backing array.
	return bytes.Clone(bytes.TrimRight(image, "\x00")), nil
}
