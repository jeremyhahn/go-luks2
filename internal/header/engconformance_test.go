package header

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// engImage returns an empty 1 MiB image under t.TempDir.
func engImage(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "eng-*.img")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Truncate(1 << 20); err != nil {
		t.Fatal(err)
	}
	return f
}

// engReadAt returns n bytes of f at off.
func engReadAt(t *testing.T, f *os.File, off int64, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, off); err != nil {
		t.Fatal(err)
	}
	return buf
}

// engineering.md, Invariants: every write applies the full structural
// validator first. A per-entry fault the reader would tolerate (a token bound
// to a keyslot that does not exist) is refused before a byte is written.
func TestEngWriteRefusesAPerEntryFaultBeforeWriting(t *testing.T) {
	f := engImage(t)
	metadata := metadataWithOneKeyslot()
	metadata.Tokens["0"] = &Token{Type: "systemd-recovery", Keyslots: []string{"7"}}

	err := WriteHeaderTo(f, newBinaryHeader(t), metadata, func(*os.File) error {
		t.Fatal("a refused write reached sync")
		return nil
	})
	if !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("WriteHeaderTo: got %v, want ErrInvalidHeader", err)
	}
	if got := engReadAt(t, f, 0, 2*HeaderMinSize); !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatal("a refused write changed the image")
	}
}

// engineering.md, Invariants: a header write syncs the primary, then writes
// and syncs the secondary, so a crash tears at most one copy.
func TestEngWriteSyncsThePrimaryBeforeTouchingTheSecondary(t *testing.T) {
	f := engImage(t)
	syncs := 0
	err := WriteHeaderTo(f, newBinaryHeader(t), metadataWithOneKeyslot(), func(g *os.File) error {
		syncs++
		_, _, secErr := ReadSecondaryHeaderFrom(g)
		switch syncs {
		case 1:
			if _, _, err := ReadHeaderCopyFrom(g, PrimaryHeaderOffset); err != nil {
				t.Errorf("first sync: the primary is not complete: %v", err)
			}
			if secErr == nil {
				t.Error("first sync: the secondary was written before the primary was synced")
			}
		case 2:
			if secErr != nil {
				t.Errorf("second sync: the secondary is not complete: %v", secErr)
			}
		}
		return g.Sync()
	})
	if err != nil {
		t.Fatalf("WriteHeaderTo: %v", err)
	}
	if syncs != 2 {
		t.Fatalf("WriteHeaderTo synced %d times, want 2 (primary, then secondary)", syncs)
	}
}

// engineering.md, Invariants: both copies carry one state; each has its own
// magic, its own offset and a checksum over its own bytes.
func TestEngBothCopiesCarryOneStateWithTheirOwnIdentity(t *testing.T) {
	f := engImage(t)
	if err := WriteHeaderTo(f, newBinaryHeader(t), metadataWithOneKeyslot(), zeroSync); err != nil {
		t.Fatalf("WriteHeaderTo: %v", err)
	}
	primary, pm, err := ReadHeaderCopyFrom(f, PrimaryHeaderOffset)
	if err != nil {
		t.Fatalf("primary: %v", err)
	}
	secondary, sm, err := ReadSecondaryHeaderFrom(f)
	if err != nil {
		t.Fatalf("secondary: %v", err)
	}
	if primary.HeaderOffset != 0 || secondary.HeaderOffset != primary.HeaderSize {
		t.Errorf("offsets %d and %d, want 0 and the area size %d", primary.HeaderOffset, secondary.HeaderOffset, primary.HeaderSize)
	}
	if primary.SequenceID != secondary.SequenceID || primary.UUID != secondary.UUID {
		t.Errorf("the copies disagree: sequence %d/%d", primary.SequenceID, secondary.SequenceID)
	}
	if string(bytes.TrimRight(primary.Magic[:], "\x00")) == string(bytes.TrimRight(secondary.Magic[:], "\x00")) {
		t.Error("the copies carry the same magic")
	}
	pj, _ := MarshalCanonicalJSON(pm)
	sj, _ := MarshalCanonicalJSON(sm)
	if !bytes.Equal(pj, sj) {
		t.Error("the copies carry different metadata")
	}
	if err := HeaderCopiesAgree(f); err != nil {
		t.Errorf("HeaderCopiesAgree: %v", err)
	}

	// A flipped byte in the secondary's JSON fails only the secondary.
	area := int64(primary.HeaderSize)
	b := engReadAt(t, f, area+HeaderSize+1, 1)
	if _, err := f.WriteAt([]byte{b[0] ^ 0xff}, area+HeaderSize+1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadSecondaryHeaderFrom(f); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Errorf("secondary after a flipped byte: got %v, want ErrInvalidHeader", err)
	}
	if _, _, err := ReadHeaderCopyFrom(f, PrimaryHeaderOffset); err != nil {
		t.Errorf("primary after a flip in the secondary: %v", err)
	}
}

// engInject adds member name with the raw value to the object at path in the
// JSON document doc. Every level is kept as raw JSON, so values elsewhere
// keep their spelling.
func engInject(t *testing.T, doc []byte, path []string, name, value string) []byte {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(doc, &obj); err != nil {
		t.Fatalf("decode %v: %v", path, err)
	}
	if len(path) == 0 {
		obj[name] = json.RawMessage(value)
	} else {
		child, ok := obj[path[0]]
		if !ok {
			t.Fatalf("fixture has no member %q", path[0])
		}
		obj[path[0]] = engInject(t, child, path[1:], name, value)
	}
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// engineering.md, Invariants: unknown JSON members round-trip exactly
// (byte-identical values, including non-canonical number spellings) through
// every nested object in every rewrite.
func TestEngUnknownMembersRoundTripThroughEveryNestedObject(t *testing.T) {
	metadata := metadataWithOneKeyslot()
	base, err := MarshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatal(err)
	}
	// The top level itself is not a nested object: its unknown members are
	// dropped (architecture.md, Encoding).
	paths := map[string][]string{
		"x-eng-config":  {"config"},
		"x-eng-keyslot": {"keyslots", "0"},
		"x-eng-area":    {"keyslots", "0", "area"},
		"x-eng-token":   {"tokens", "0"},
		"x-eng-segment": {"segments", "0"},
		"x-eng-digest":  {"digests", "0"},
	}
	values := map[string]string{}
	doc := base
	for name, path := range paths {
		// Distinct, non-canonical spellings per object.
		v := `{"n":1.50e0,"z":-0.0,"s":"` + name + `"}`
		values[name] = v
		doc = engInject(t, doc, path, name, v)
	}

	parsed, err := ParseJSONMetadata(append(doc, 0), HeaderMinSize)
	if err != nil {
		t.Fatalf("ParseJSONMetadata: %v", err)
	}

	f := engImage(t)
	hdr := newBinaryHeader(t)
	for rewrite := 1; rewrite <= 2; rewrite++ {
		if err := WriteHeaderTo(f, hdr, parsed, zeroSync); err != nil {
			t.Fatalf("rewrite %d: WriteHeaderTo: %v", rewrite, err)
		}
		for _, off := range []int64{PrimaryHeaderOffset, HeaderMinSize} {
			raw := engReadAt(t, f, off+HeaderSize, HeaderMinSize-HeaderSize)
			for name, v := range values {
				if want := `"` + name + `":` + v; !strings.Contains(string(raw), want) {
					t.Errorf("rewrite %d, copy at %d: %s not preserved byte for byte", rewrite, off, want)
				}
			}
		}
		if _, parsed, err = ReadHeaderCopyFrom(f, PrimaryHeaderOffset); err != nil {
			t.Fatalf("rewrite %d: read back: %v", rewrite, err)
		}
		hdr.SequenceID++
	}
}

// engineering.md, Observability: no logging; every failure is a returned
// error. No non-test file of this package imports a logger.
func TestEngThePackageDoesNotLog(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			switch path := strings.Trim(imp.Path.Value, `"`); path {
			case "log", "log/slog", "log/syslog":
				t.Errorf("%s imports %s", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no source files found")
	}
}
