package wipe

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// pkg/wipe is LUKS-independent and carries only the whole-device trust
// boundary: of this module it imports internal/device, internal/clock and
// internal/errs and nothing else, never pkg/luks2 (so it cannot grow a
// crypto-erase mode beside Sanitize), and it runs no external program.
func TestWipeImportsOnlyItsTrustBoundary(t *testing.T) {
	const module = "github.com/jeremyhahn/go-luks2/"
	allowed := map[string]bool{
		module + "internal/device": true,
		module + "internal/clock":  true,
		module + "internal/errs":   true,
		"golang.org/x/sys/unix":    true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		seen++
		for _, spec := range f.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if path == "os/exec" {
				t.Errorf("%s imports %s: pkg/wipe runs no external program", name, path)
			}
			stdlib := !strings.Contains(strings.SplitN(path, "/", 2)[0], ".")
			if !stdlib && !allowed[path] {
				t.Errorf("%s imports %s, outside pkg/wipe's trust boundary", name, path)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no package source files found")
	}
}

// Crypto-erase and full-device sanitization are two separate calls, not one
// call with a mode flag: Params holds exactly the fields the architecture
// names, none of which selects a header-only erase.
func TestParamsHasNoEraseModeFlag(t *testing.T) {
	want := []string{"Standard", "Patterns", "Verify", "Discard", "Progress"}
	typ := reflect.TypeOf(Params{})
	if typ.NumField() != len(want) {
		t.Fatalf("Params has %d fields, want %v", typ.NumField(), want)
	}
	for i, name := range want {
		if got := typ.Field(i).Name; got != name {
			t.Errorf("Params field %d = %s, want %s", i, got, name)
		}
	}
}
