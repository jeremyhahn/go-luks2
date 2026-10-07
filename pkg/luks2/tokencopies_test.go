// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"os"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// The token writes read the primary header copy alone and then wrote both
// copies. With the secondary the current copy, AddToken saw recovery token 0
// as free and overwrote it; with the primary torn, all three refused a volume
// `cryptsetup token import` accepts. They read the current copy, as the
// keyslot writes do, and so also repair the stale one.

// tokenInCurrentCopyOnly leaves recovery token 0 in the secondary copy alone:
// either the primary is one header write behind it, or the primary is torn.
func tokenInCurrentCopyOnly(tearThePrimary bool) func(t *testing.T, path string, area int64) {
	if !tearThePrimary {
		return staleCopyAt(func(int64) int64 { return 0 })
	}
	return func(t *testing.T, path string, area int64) {
		if err := setTokenForTest(path, 0, Token{Type: TokenTypeRecovery, Keyslots: []int{0}}); err != nil {
			t.Fatalf("SetToken: %v", err)
		}
		tearPrimary(t, path, area)
	}
}

func TestTokenWritesUseTheCurrentHeaderCopy(t *testing.T) {
	extra := Token{Type: "go-luks2-test", Keyslots: []int{0}}
	ops := []struct {
		name       string
		write      func(v *Volume) error
		wantTokens []string
	}{
		{
			name: "AddToken",
			write: func(v *Volume) error {
				id, err := v.AddToken(context.Background(), extra)
				if err == nil && id != 1 {
					t.Errorf("AddToken chose token %d, want 1: token 0 is the recovery token", id)
				}
				return err
			},
			wantTokens: []string{"0", "1"},
		},
		{
			name:       "SetToken",
			write:      func(v *Volume) error { return v.SetToken(context.Background(), 1, extra) },
			wantTokens: []string{"0", "1"},
		},
		{
			name:  "RemoveToken",
			write: func(v *Volume) error { return v.RemoveToken(context.Background(), 0) },
		},
	}
	damages := []struct {
		name string
		torn bool
	}{
		{name: "the secondary is newer"},
		{name: "the primary is torn", torn: true},
	}
	for _, op := range ops {
		for _, d := range damages {
			t.Run(op.name+"/"+d.name, func(t *testing.T) {
				path := headerCopyVolume(t, "tokencopies.img", tokenInCurrentCopyOnly(d.torn))
				v := openTestVolume(t, path)
				if err := op.write(v); err != nil {
					t.Fatalf("%s: %v", op.name, err)
				}

				f, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }()
				if err := headerCopiesAgree(f); err != nil {
					t.Fatalf("the header copies after %s: %v", op.name, err)
				}
				_, metadata, err := readHeaderCopyFrom(f, header.PrimaryHeaderOffset)
				if err != nil {
					t.Fatalf("the primary after %s: %v", op.name, err)
				}
				if len(metadata.Tokens) != len(op.wantTokens) {
					t.Fatalf("after %s: %d tokens, want %v", op.name, len(metadata.Tokens), op.wantTokens)
				}
				for _, id := range op.wantTokens {
					if _, ok := metadata.Tokens[id]; !ok {
						t.Fatalf("after %s: token %s is missing", op.name, id)
					}
				}
				if len(op.wantTokens) > 0 && metadata.Tokens["0"].Type != TokenTypeRecovery {
					t.Fatalf("after %s: token 0 is %q, want the recovery token", op.name, metadata.Tokens["0"].Type)
				}
			})
		}
	}
}

// TestRemoveTokenOfAnEmptySlotIsTokenNotFound: the bare sentinel went out
// through errAt unrecognized, so its Kind read ErrIO.
func TestRemoveTokenOfAnEmptySlotIsTokenNotFound(t *testing.T) {
	path := formattedVolumeImage(t, "token-absent.img", "", "")
	err := openTestVolume(t, path).RemoveToken(context.Background(), 3)
	requireKindAndOp(t, "RemoveToken", err, ErrTokenNotFound, "Volume.RemoveToken", path)
}
