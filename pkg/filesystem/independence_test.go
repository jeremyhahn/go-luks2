// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/jeremyhahn/go-luks2/"

// importsOf returns every import path of the non-test sources in dir.
func importsOf(t *testing.T, dir string) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	imports := map[string]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range f.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			imports[path] = name
		}
	}
	if len(files) == 0 {
		t.Fatalf("no sources in %s", dir)
	}
	return imports
}

// The package is independent of LUKS2 both ways (architecture.md): it knows
// nothing about headers, keys or mappings, so it imports no package of this
// module that handles one, nor the protected-memory module keys live in, and
// pkg/luks2 does not import it.
func TestFilesystemIsIndependentOfLUKS2(t *testing.T) {
	forbidden := []string{
		modulePath + "pkg/luks2", modulePath + "pkg/dmcrypt", modulePath + "pkg/keyprovider",
		modulePath + "internal/header", modulePath + "internal/dm", modulePath + "internal/keyring",
		modulePath + "internal/volkey", modulePath + "internal/kdf", modulePath + "internal/af",
		modulePath + "internal/areacipher", modulePath + "internal/recoverykey", modulePath + "internal/secret",
		"github.com/jeremyhahn/go-enclave",
	}
	for path, file := range importsOf(t, ".") {
		for _, forbidden := range forbidden {
			if path == forbidden || strings.HasPrefix(path, forbidden+"/") {
				t.Errorf("%s imports %s; pkg/filesystem is independent of LUKS2", file, path)
			}
		}
	}
	for path, file := range importsOf(t, filepath.Join("..", "luks2")) {
		if path == modulePath+"pkg/filesystem" {
			t.Errorf("%s imports pkg/filesystem; pkg/luks2 must not", file)
		}
	}
}
