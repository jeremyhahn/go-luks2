// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// requireClassified fails unless err is an *errs.Error with a Kind and the Op
// and Path the exported entry point stamps.
func requireClassified(t *testing.T, what string, err error, wantPath string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: no error", what)
		return
	}
	var e *errs.Error
	if !errors.As(err, &e) {
		t.Errorf("%s: %T %q is not an *errs.Error", what, err, err)
		return
	}
	if e.Kind == nil {
		t.Errorf("%s: Kind is nil: %v", what, err)
	}
	if e.Op == "" {
		t.Errorf("%s: Op is empty: %v", what, err)
	}
	if wantPath != "" && e.Path != wantPath {
		t.Errorf("%s: Path = %q, want %q: %v", what, e.Path, wantPath, err)
	}
}

func scratchDevice(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dev.img")
	if err := os.WriteFile(path, make([]byte, 4<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestOpenErrorsAreClassified drives every refusal Open has.
func TestOpenErrorsAreClassified(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	missing := filepath.Join(t.TempDir(), "absent")

	for _, tc := range []struct {
		name string
		ctx  context.Context
		path string
		kind error
	}{
		{"empty path", context.Background(), "", ErrInvalidArgument},
		{"relative path", context.Background(), "dev.img", ErrInvalidArgument},
		{"missing path", context.Background(), missing, ErrDeviceNotFound},
		{"canceled", canceled, scratchDevice(t), context.Canceled},
	} {
		_, err := Open(tc.ctx, tc.path)
		requireClassified(t, "Open("+tc.name+")", err, tc.path)
		if !errors.Is(err, tc.kind) {
			t.Errorf("Open(%s): %v is not %v", tc.name, err, tc.kind)
		}
	}
}

// TestCloseErrorIsClassified drives Close's one failure: the descriptor
// cannot be closed.
func TestCloseErrorIsClassified(t *testing.T) {
	path := scratchDevice(t)
	v, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.pinned.File().Close(); err != nil {
		t.Fatal(err)
	}
	err = v.Close()
	requireClassified(t, "Close", err, path)
	if !errors.Is(err, ErrIO) {
		t.Errorf("Close: %v is not ErrIO", err)
	}
}

// requireKindAndOp fails unless err is classified with exactly kind and its
// *errs.Error names exactly op: the method the caller called, not a helper
// it went through on the way.
func requireKindAndOp(t *testing.T, what string, err error, kind error, op, wantPath string) {
	t.Helper()
	requireClassified(t, what, err, wantPath)
	if got := errs.KindOf(err, nil); got != kind {
		t.Errorf("%s: Kind = %v, want %v: %v", what, got, kind, err)
	}
	var e *errs.Error
	if errors.As(err, &e) && e.Op != op {
		t.Errorf("%s: Op = %q, want %q: %v", what, e.Op, op, err)
	}
}

// TestVolumeMethodErrorsAreClassified calls every Volume method that returns
// an error on a closed volume, a read-only volume and with a canceled
// context, and requires every refusal to be an *errs.Error with the one Kind
// that refusal has and the Op of the method called. The device is blank, so
// a method the condition does not stop reports what it meets next: no LUKS2
// header, or the nil credential or provider it was handed.
func TestVolumeMethodErrorsAreClassified(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	type call struct {
		run func(v *Volume, ctx context.Context) error
		// What a read-only volume and a canceled context report. A nil
		// readOnly is ErrReadOnly: the method writes.
		readOnly, canceled error
	}
	calls := map[string]call{
		"Header":              {func(v *Volume, ctx context.Context) error { _, err := v.Header(ctx); return err }, ErrInvalidHeader, context.Canceled},
		"SecondaryHeader":     {func(v *Volume, ctx context.Context) error { _, err := v.SecondaryHeader(ctx); return err }, ErrInvalidHeader, context.Canceled},
		"Unlock":              {func(v *Volume, ctx context.Context) error { _, err := v.Unlock(ctx, nil); return err }, ErrInvalidHeader, context.Canceled},
		"UnlockKeyslot":       {func(v *Volume, ctx context.Context) error { _, err := v.UnlockKeyslot(ctx, 0, nil); return err }, ErrInvalidHeader, context.Canceled},
		"UnlockWithVolumeKey": {func(v *Volume, ctx context.Context) error { _, err := v.UnlockWithVolumeKey(ctx, nil); return err }, ErrInvalidCredential, ErrInvalidCredential},
		"UnlockWithProvider":  {func(v *Volume, ctx context.Context) error { _, err := v.UnlockWithProvider(ctx, nil); return err }, ErrInvalidArgument, ErrInvalidArgument},
		"Target":              {func(v *Volume, ctx context.Context) error { _, err := v.Target(ctx, &Key{}); return err }, ErrInvalidHeader, context.Canceled},
		"Erase":               {func(v *Volume, ctx context.Context) error { return v.Erase(ctx) }, nil, context.Canceled},
		"Format":              {func(v *Volume, ctx context.Context) error { return v.Format(ctx, nil, FormatParams{}) }, nil, ErrProtectedMemory},
		"MigrateToFIPS": {func(v *Volume, ctx context.Context) error {
			_, err := v.MigrateToFIPS(ctx, nil, MigrateParams{})
			return err
		}, nil, ErrProtectedMemory},
		"AddKeyslot": {func(v *Volume, ctx context.Context) error {
			_, err := v.AddKeyslot(ctx, &Key{}, nil, KeyslotParams{})
			return err
		}, nil, context.Canceled},
		"ChangeKeyslot": {func(v *Volume, ctx context.Context) error {
			_, err := v.ChangeKeyslot(ctx, &Key{}, nil, KeyslotParams{})
			return err
		}, nil, context.Canceled},
		"RemoveKeyslot": {func(v *Volume, ctx context.Context) error { return v.RemoveKeyslot(ctx, 0) }, nil, context.Canceled},
		"AddRecoveryKey": {func(v *Volume, ctx context.Context) error {
			_, err := v.AddRecoveryKey(ctx, &Key{}, nil, KeyslotParams{})
			return err
		}, nil, ErrInvalidArgument},
		"Enroll": {func(v *Volume, ctx context.Context) error {
			_, err := v.Enroll(ctx, &Key{}, nil, KeyslotParams{})
			return err
		}, nil, ErrInvalidArgument},
		"AddToken":             {func(v *Volume, ctx context.Context) error { _, err := v.AddToken(ctx, Token{}); return err }, nil, ErrInvalidArgument},
		"SetToken":             {func(v *Volume, ctx context.Context) error { return v.SetToken(ctx, 0, Token{}) }, nil, ErrInvalidArgument},
		"RemoveToken":          {func(v *Volume, ctx context.Context) error { return v.RemoveToken(ctx, 0) }, nil, context.Canceled},
		"RestorePrimaryHeader": {func(v *Volume, ctx context.Context) error { return v.RestorePrimaryHeader(ctx) }, nil, context.Canceled},
		"ReplacePrimaryHeader": {func(v *Volume, ctx context.Context) error { return v.ReplacePrimaryHeader(ctx) }, nil, context.Canceled},
	}

	t.Run("closed", func(t *testing.T) {
		path := scratchDevice(t)
		v, err := Open(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Close(); err != nil {
			t.Fatal(err)
		}
		for name, c := range calls {
			requireKindAndOp(t, "closed "+name, c.run(v, context.Background()), ErrClosed, "Volume."+name, path)
		}
	})

	t.Run("read-only", func(t *testing.T) {
		path := scratchDevice(t)
		v, err := Open(context.Background(), path, WithReadOnly())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = v.Close() }()
		for name, c := range calls {
			want := c.readOnly
			if want == nil {
				want = ErrReadOnly
			}
			requireKindAndOp(t, "read-only "+name, c.run(v, context.Background()), want, "Volume."+name, path)
		}
	})

	t.Run("canceled", func(t *testing.T) {
		path := scratchDevice(t)
		v, err := Open(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = v.Close() }()
		for name, c := range calls {
			requireKindAndOp(t, "canceled "+name, c.run(v, canceled), c.canceled, "Volume."+name, path)
		}
	})
}
