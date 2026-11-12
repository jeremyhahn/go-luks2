package luks2

import (
	"go/build"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/jeremyhahn/go-luks2"

// coreForbiddenImports are the packages the rootless, exec-free core must not
// reach: exec, device-mapper, the kernel keyring and every public package
// with a trust boundary of its own.
var coreForbiddenImports = []string{
	"os/exec",
	"github.com/anatol/devmapper.go",
	modulePath + "/pkg/dmcrypt",
	modulePath + "/pkg/loop",
	modulePath + "/pkg/filesystem",
	modulePath + "/pkg/wipe",
	modulePath + "/pkg/keyprovider",
	modulePath + "/internal/dm",
	modulePath + "/internal/keyring",
	modulePath + "/internal/command",
	modulePath + "/internal/cli",
}

// TestTheCoreImportClosureIsRootlessAndExecFree walks every in-module package
// pkg/luks2 reaches, on each OS the core builds for, and fails if any of them
// imports a forbidden package. depguard checks only pkg/luks2's own imports;
// this catches the same import arriving through a leaf package below it.
func TestTheCoreImportClosureIsRootlessAndExecFree(t *testing.T) {
	forbidden := make(map[string]bool, len(coreForbiddenImports))
	for _, p := range coreForbiddenImports {
		forbidden[p] = true
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"linux", "darwin"} {
		ctx := build.Default
		ctx.GOOS = goos
		ctx.CgoEnabled = false
		seen := map[string]bool{}
		queue := []string{modulePath + "/pkg/luks2"}
		for len(queue) > 0 {
			pkg := queue[0]
			queue = queue[1:]
			if seen[pkg] {
				continue
			}
			seen[pkg] = true
			dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(pkg, modulePath+"/")))
			bp, err := ctx.ImportDir(dir, 0)
			if err != nil {
				t.Fatalf("%s: import %s: %v", goos, pkg, err)
			}
			for _, imp := range bp.Imports {
				if forbidden[imp] {
					t.Errorf("%s: %s imports %s; the core must stay rootless and exec-free", goos, pkg, imp)
				}
				if strings.HasPrefix(imp, modulePath+"/") {
					queue = append(queue, imp)
				}
			}
		}
		walked := make([]string, 0, len(seen))
		for p := range seen {
			walked = append(walked, p)
		}
		sort.Strings(walked)
		// Control: the walk must reach the leaf packages, or an empty closure
		// would pass vacuously.
		for _, want := range []string{"/internal/device", "/internal/kdf", "/internal/header"} {
			if !seen[modulePath+want] {
				t.Fatalf("%s: closure %v does not reach %s", goos, walked, want)
			}
		}
	}
}
