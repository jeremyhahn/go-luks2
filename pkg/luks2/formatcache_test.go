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

// formattedImage gives a test a fresh image, of size bytes, holding a
// container Format produced from opts. It FORMATS ONCE PER PROCESS PER KEY and
// copies the result thereafter (#92).
//
// This is formatWithLibrary's idea extended to the fixtures that format with a
// configuration of their own and so could not share its golden image.
// headerSizeVolume and tokenIDVolume ran a real Format per call -- several
// from inside table loops -- and between them were ~22s of the package's CPU
// time, most of it the digest calibration Format has to do and none of it
// what those tests are about. Both only need a genuine container to alter.
//
// Unlike formatWithLibrary's 2 MiB prefix, the snapshot here is the WHOLE
// image up to its last non-zero byte, so each copy is byte-for-byte what
// Format wrote -- keyslots-area fill included -- apart from not being a
// different random draw. What a caller loses is a fresh UUID and fresh salts;
// no caller of either fixture compares two volumes.
//
// key names the configuration and MUST change whenever opts or size does: it
// is what distinguishes one cached image from another. opts receives the path
// to format and returns the options; its Device is overwritten with that path.
//
// The failure is carried out of the sync.Once rather than reported inside it,
// for the reason formatWithLibrary gives: a t.Fatalf in there would abort
// whichever test happened to be first.
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
