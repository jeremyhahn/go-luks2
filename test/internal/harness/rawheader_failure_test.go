package harness

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadCurrentHeaderReportsAMissingDevice(t *testing.T) {
	bin, meta, err := ReadCurrentHeader(filepath.Join(t.TempDir(), "absent.img"))
	if err == nil || bin != nil || meta != nil {
		t.Fatalf("ReadCurrentHeader = %v, %v, %v; want only an error", bin, meta, err)
	}
}

func TestReadCurrentHeaderRefusesAFileWithoutALUKSHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blank.img")
	if err := os.WriteFile(path, make([]byte, 64*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	bin, meta, err := ReadCurrentHeader(path)
	if err == nil || bin != nil || meta != nil {
		t.Fatalf("ReadCurrentHeader = %v, %v, %v; want only an error", bin, meta, err)
	}
}

// noSysInfo is a FileInfo whose Sys() is not a *syscall.Stat_t.
type noSysInfo struct{}

func (noSysInfo) Name() string       { return "x" }
func (noSysInfo) Size() int64        { return 0 }
func (noSysInfo) Mode() fs.FileMode  { return 0 }
func (noSysInfo) ModTime() time.Time { return time.Time{} }
func (noSysInfo) IsDir() bool        { return false }
func (noSysInfo) Sys() any           { return nil }

func TestFileOwnerReportsWhenTheOwnerIsUnknowable(t *testing.T) {
	if uid, ok := fileOwner(noSysInfo{}); ok || uid != 0 {
		t.Errorf("fileOwner = %d, %v; want 0, false", uid, ok)
	}
	fi, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fileOwner(fi); !ok {
		t.Error("fileOwner reported no owner for a real directory")
	}
}
