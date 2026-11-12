package luks2

import (
	"context"
	"os"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// openHeaderEngVolume formats a fresh image and opens it with the test
// syscalls; the volume is closed when the test ends.
func openHeaderEngVolume(t *testing.T, name string) (*Volume, string) {
	t.Helper()
	path := formattedVolumeImage(t, name, "", "")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v, path
}

// engineering.md, Exported surface: Offset is 0 for the primary copy and the
// header area size for the secondary.
func TestHeaderEngOffsetIsZeroForPrimaryAndHeaderSizeForSecondary(t *testing.T) {
	v, _ := openHeaderEngVolume(t, "offset.img")
	ctx := context.Background()

	primary, err := v.Header(ctx)
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	if got := primary.Offset(); got != 0 {
		t.Errorf("primary Offset() = %d, want 0", got)
	}
	secondary, err := v.SecondaryHeader(ctx)
	if err != nil {
		t.Fatalf("SecondaryHeader failed: %v", err)
	}
	if got, want := secondary.Offset(), primary.Size(); got != want || got == 0 {
		t.Errorf("secondary Offset() = %d, want the header area size %d", got, want)
	}
}

// engineering.md, Invariants: sequence_id advances on every token change, and
// both copies carry it.
func TestHeaderEngSequenceIDAdvancesOnEveryTokenChange(t *testing.T) {
	v, _ := openHeaderEngVolume(t, "tokseq.img")
	ctx := context.Background()

	seq := func(step string) uint64 {
		t.Helper()
		p, err := v.Header(ctx)
		if err != nil {
			t.Fatalf("%s: Header: %v", step, err)
		}
		s, err := v.SecondaryHeader(ctx)
		if err != nil {
			t.Fatalf("%s: SecondaryHeader: %v", step, err)
		}
		if p.SequenceID() != s.SequenceID() {
			t.Fatalf("%s: copies carry sequence ids %d and %d", step, p.SequenceID(), s.SequenceID())
		}
		return p.SequenceID()
	}

	before := seq("format")
	id, err := v.AddToken(ctx, Token{Type: "x-test", Keyslots: []int{0}})
	if err != nil {
		t.Fatalf("AddToken: %v", err)
	}
	afterAdd := seq("AddToken")
	if afterAdd <= before {
		t.Fatalf("AddToken: sequence_id %d, was %d", afterAdd, before)
	}
	if err := v.SetToken(ctx, id, Token{Type: "x-test-2", Keyslots: []int{0}}); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	afterSet := seq("SetToken")
	if afterSet <= afterAdd {
		t.Fatalf("SetToken: sequence_id %d, was %d", afterSet, afterAdd)
	}
	if err := v.RemoveToken(ctx, id); err != nil {
		t.Fatalf("RemoveToken: %v", err)
	}
	if afterRemove := seq("RemoveToken"); afterRemove <= afterSet {
		t.Fatalf("RemoveToken: sequence_id %d, was %d", afterRemove, afterSet)
	}
}

// engineering.md, Invariants: SecondaryHeader and RestorePrimaryHeader never
// read or derive against the data segment. The image is cut off where the
// data segment starts, so any read there fails.
func TestHeaderEngSecondaryAndRestoreNeverReadTheDataSegment(t *testing.T) {
	path := formattedVolumeImage(t, "nodata.img", "", "")
	ctx := context.Background()

	v, err := Open(ctx, path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	h, err := v.Header(ctx)
	if err != nil {
		t.Fatalf("Header: %v", err)
	}
	segs := h.Segments()
	if len(segs) != 1 || segs[0].Offset <= 2*h.Size() {
		t.Fatalf("fixture: segments %+v", segs)
	}
	want := h.SequenceID()
	_ = v.Close()

	if err := os.Truncate(path, segs[0].Offset); err != nil {
		t.Fatal(err)
	}
	writeBytesAt(t, path, header.HeaderSize, []byte("torn"))

	v, err = Open(ctx, path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open without a data segment: %v", err)
	}
	defer func() { _ = v.Close() }()
	s, err := v.SecondaryHeader(ctx)
	if err != nil {
		t.Fatalf("SecondaryHeader without a data segment: %v", err)
	}
	if s.SequenceID() != want {
		t.Fatalf("SecondaryHeader sequence %d, want %d", s.SequenceID(), want)
	}
	if err := v.RestorePrimaryHeader(ctx); err != nil {
		t.Fatalf("RestorePrimaryHeader without a data segment: %v", err)
	}
	if p, err := v.Header(ctx); err != nil || p.Offset() != 0 || p.SequenceID() != want+1 {
		t.Fatalf("after the restore: %v, %v; want the primary at sequence %d", p, err, want+1)
	}
}
