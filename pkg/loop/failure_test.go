// Failure-path tests for detachDevice, findLoopDeviceIn and lookup.

//go:build linux && !integration

package loop

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

func TestDetachDeviceReportsAnOpenFailure(t *testing.T) {
	cleared := 0
	s := detachSys(t, nil, &cleared)
	s.openFile = func(string, int, os.FileMode) (*os.File, error) { return nil, os.ErrPermission }

	_, err := detachDevice(context.Background(), "/dev/loop0", backingIdentity{}, s, reader(attachedTo("/img")))
	if !errors.Is(err, errs.ErrIO) || !errors.Is(err, os.ErrPermission) {
		t.Errorf("detachDevice() = %v, want an ErrIO wrapping the open failure", err)
	}
	if cleared != 0 {
		t.Errorf("LOOP_CLR_FD sent %d time(s), want none", cleared)
	}
}

func TestDetachDeviceReportsAClearFailure(t *testing.T) {
	ours := backingIdentity{dev: 1, ino: 2, known: true}
	cleared := 0
	s := detachSys(t, func(*os.File) (uint64, uint64, error) { return 1, 2, nil }, &cleared)
	s.clearFD = func(*os.File) error { return errors.New("ioctl refused") }

	_, err := detachDevice(context.Background(), "/dev/loop0", ours, s, reader(attachedTo("/img")))
	if !errors.Is(err, errs.ErrIO) {
		t.Errorf("detachDevice() = %v, want errors.Is(_, ErrIO)", err)
	}
}

func TestDetachDeviceReportsAFailedCloseAlongsideTheWait(t *testing.T) {
	ours := backingIdentity{dev: 1, ino: 2, known: true}
	cleared := 0
	s := detachSys(t, func(*os.File) (uint64, uint64, error) { return 1, 2, nil }, &cleared)
	// Closing the descriptor inside clearFD makes the caller's own Close fail.
	s.clearFD = func(f *os.File) error { return f.Close() }

	state, err := detachDevice(context.Background(), "/dev/loop0", ours, s, reader(attachedTo("/img"), loopState{}))
	if !errors.Is(err, errs.ErrIO) {
		t.Fatalf("detachDevice() = %v, want errors.Is(_, ErrIO) for the failed close", err)
	}
	if state != Released {
		t.Errorf("state = %v, want Released: the wait still observed the release", state)
	}
}

func TestCheckBackingIdentityReportsAnIdentifyFailure(t *testing.T) {
	s := defaultSys()
	s.fdBackingIdentity = func(*os.File) (uint64, uint64, error) { return 0, 0, errors.New("ioctl failed") }

	err := checkBackingIdentity("/dev/loop0", nil, backingIdentity{known: true}, s)
	if !errors.Is(err, errs.ErrIO) || errors.Is(err, ErrDeviceReassigned) {
		t.Errorf("checkBackingIdentity() = %v, want a plain ErrIO", err)
	}
}

func TestFindLoopDeviceInReportsAnUnreadableSysBlockRoot(t *testing.T) {
	file := filepath.Join(t.TempDir(), "volume.img")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := errors.New("readdir failed")
	s := defaultSys()
	s.readDir = func(string) ([]os.DirEntry, error) { return nil, want }

	_, _, _, err := findLoopDeviceIn(t.TempDir(), file, s)
	if !errors.Is(err, want) {
		t.Errorf("findLoopDeviceIn() = %v, want the readDir error", err)
	}
}

func TestFindPropagatesASearchFailure(t *testing.T) {
	s := defaultSys()
	if _, err := find(context.Background(), filepath.Join(t.TempDir(), "absent.img"), s); !errors.Is(err, errs.ErrIO) {
		t.Errorf("find() = %v, want errors.Is(_, ErrIO)", err)
	}
}

func TestLookupReportsAnUnidentifiableBackingFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "loop0", "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "loop0", "loop", "backing_file"), []byte("/img\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := defaultSys()
	s.sysBlockRoot = root
	s.loopBackingIdentity = func(string) (uint64, uint64, error) { return 0, 0, errors.New("ioctl failed") }

	if _, err := lookup(context.Background(), "/dev/loop0", s); !errors.Is(err, errs.ErrIO) {
		t.Errorf("lookup() = %v, want errors.Is(_, ErrIO)", err)
	}
}
