// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

func TestFlagsParsesBoolStringAndInt(t *testing.T) {
	f := newFlags("test")
	full := f.Bool("full")
	name := f.String("name", "default")
	n := f.Int("count", 1)

	positional, err := f.parse([]string{"--full", "--name", "x", "--count", "5", "pos1", "pos2"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !*full {
		t.Error("full = false, want true")
	}
	if *name != "x" {
		t.Errorf("name = %q, want x", *name)
	}
	if *n != 5 {
		t.Errorf("count = %d, want 5", *n)
	}
	if got := positional; len(got) != 2 || got[0] != "pos1" || got[1] != "pos2" {
		t.Errorf("positional = %v, want [pos1 pos2]", got)
	}
	if !f.Given("full") || !f.Given("name") {
		t.Error("Given should report true for flags that appeared")
	}
	if f.Given("count") == false {
		t.Error("Given(count) should be true")
	}
}

func TestFlagsInlineValue(t *testing.T) {
	f := newFlags("test")
	name := f.String("name", "")
	full := f.Bool("full")

	_, err := f.parse([]string{"--name=inline", "--full=true"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *name != "inline" {
		t.Errorf("name = %q, want inline", *name)
	}
	if !*full {
		t.Error("full = false, want true")
	}
}

func TestFlagsBoolInlineRejectsNonBool(t *testing.T) {
	f := newFlags("test")
	f.Bool("full")
	if _, err := f.parse([]string{"--full=notabool"}); err == nil {
		t.Fatal("parse: want an error for a non-bool inline value")
	}
}

func TestFlagsBareDashIsPositional(t *testing.T) {
	f := newFlags("test")
	positional, err := f.parse([]string{"-"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(positional) != 1 || positional[0] != "-" {
		t.Errorf("positional = %v, want [-]", positional)
	}
}

func TestFlagsMissingValue(t *testing.T) {
	f := newFlags("test")
	f.String("name", "")
	if _, err := f.parse([]string{"--name"}); err == nil {
		t.Fatal("parse: want an error when --name has no value")
	}
}

func TestFlagsIntRequiresNumber(t *testing.T) {
	f := newFlags("test")
	f.Int("count", 0)
	if _, err := f.parse([]string{"--count", "notanumber"}); err == nil {
		t.Fatal("parse: want an error for a non-numeric --count")
	}
}

func TestFlagsUnknownOption(t *testing.T) {
	f := newFlags("test")
	if _, err := f.parse([]string{"--nope"}); err == nil {
		t.Fatal("parse: want an error for an unknown option")
	}
}

func TestBatchFlags(t *testing.T) {
	f := newFlags("test")
	batch := batchFlags(f)
	if _, err := f.parse([]string{"--yes"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !batch() {
		t.Error("batch() = false after --yes, want true")
	}

	f2 := newFlags("test")
	batch2 := batchFlags(f2)
	if _, err := f2.parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if batch2() {
		t.Error("batch() = true with no flags, want false")
	}
}
