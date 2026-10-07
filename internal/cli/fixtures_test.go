// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// imageChunkSize is the granularity a template image is scanned and copied
// at. Only chunks holding a non-zero byte are kept, so a copy writes the
// header and keyslot material and leaves the rest of the image sparse.
const imageChunkSize = 64 << 10

// imageChunk is one non-zero stretch of a template image.
type imageChunk struct {
	off  int64
	data []byte
}

// volumeTemplate is a formatted volume built once per package run and handed
// to each test as a byte-for-byte copy. Every key derivation at the
// production PBKDF2 floor costs seconds under -race; formatting the same
// volume once instead of once per test is what keeps the package inside its
// unit-test budget without lowering that floor.
type volumeTemplate struct {
	build func(dir string) (string, error)

	once   sync.Once
	size   int64
	chunks []imageChunk
	err    error
}

// load builds the template on first use and captures its contents. A build
// failure is kept and reported to every test that asks for the template.
func (vt *volumeTemplate) load() error {
	vt.once.Do(func() {
		dir, err := os.MkdirTemp("", "cli-fixture-")
		if err != nil {
			vt.err = fmt.Errorf("fixture dir: %w", err)
			return
		}
		defer func() { _ = os.RemoveAll(dir) }()

		path, err := vt.build(dir)
		if err != nil {
			vt.err = err
			return
		}
		vt.size, vt.chunks, vt.err = readImageChunks(path)
	})
	return vt.err
}

// copyTo writes a copy of the template to name under t.TempDir() and returns
// its path.
func (vt *volumeTemplate) copyTo(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := vt.writeImage(path); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	return path
}

// writeImage builds the template if it has not been built and writes a copy
// of it to path.
func (vt *volumeTemplate) writeImage(path string) error {
	if err := vt.load(); err != nil {
		return fmt.Errorf("build fixture: %w", err)
	}

	f, err := os.Create(path) // #nosec G304 -- path is a test's or fixture's own temp path
	if err != nil {
		return fmt.Errorf("create image: %w", err)
	}
	for _, c := range vt.chunks {
		if _, err := f.WriteAt(c.data, c.off); err != nil {
			_ = f.Close()
			return fmt.Errorf("write image: %w", err)
		}
	}
	if err := f.Truncate(vt.size); err != nil {
		_ = f.Close()
		return fmt.Errorf("size image: %w", err)
	}
	return f.Close()
}

// readImageChunks returns path's size and every imageChunkSize chunk of it
// that holds a non-zero byte.
func readImageChunks(path string) (int64, []imageChunk, error) {
	f, err := os.Open(path) // #nosec G304 -- path is under the fixture's temp dir
	if err != nil {
		return 0, nil, fmt.Errorf("open fixture: %w", err)
	}
	defer func() { _ = f.Close() }()

	var (
		chunks []imageChunk
		off    int64
		zero   = make([]byte, imageChunkSize)
	)
	for {
		buf := make([]byte, imageChunkSize)
		n, err := io.ReadFull(f, buf)
		if n > 0 && !bytes.Equal(buf[:n], zero[:n]) {
			chunks = append(chunks, imageChunk{off: off, data: buf[:n]})
		}
		off += int64(n)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return off, chunks, nil
		}
		if err != nil {
			return 0, nil, fmt.Errorf("read fixture: %w", err)
		}
	}
}
