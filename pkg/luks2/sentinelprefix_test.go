// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// exportedSentinels names every exported Err* variable of this package. The
// AST scan below fails when a sentinel is declared and not listed, so a new
// one cannot dodge the prefix rule.
var exportedSentinels = map[string]error{
	"ErrInvalidHeader":           ErrInvalidHeader,
	"ErrInvalidArgument":         ErrInvalidArgument,
	"ErrInvalidCredential":       ErrInvalidCredential,
	"ErrIO":                      ErrIO,
	"ErrUnsupported":             ErrUnsupported,
	"ErrNoSpace":                 ErrNoSpace,
	"ErrDeviceNotFound":          ErrDeviceNotFound,
	"ErrKeyslotNotFound":         ErrKeyslotNotFound,
	"ErrUnsupportedRequirement":  ErrUnsupportedRequirement,
	"ErrNoKeyslots":              ErrNoKeyslots,
	"ErrPermissionDenied":        ErrPermissionDenied,
	"ErrWrongKey":                ErrWrongKey,
	"ErrLastKeyslot":             ErrLastKeyslot,
	"ErrKeyslotAreaOverlap":      ErrKeyslotAreaOverlap,
	"ErrFIPSNotApproved":         ErrFIPSNotApproved,
	"ErrFIPSImportRequired":      ErrFIPSImportRequired,
	"ErrFIPSMigration":           ErrFIPSMigration,
	"ErrDeviceCacheStale":        ErrDeviceCacheStale,
	"ErrKDFCalibration":          ErrKDFCalibration,
	"ErrDeviceChanged":           ErrDeviceChanged,
	"ErrProtectedMemory":         ErrProtectedMemory,
	"ErrNotLockedMemory":         ErrNotLockedMemory,
	"ErrLockContended":           ErrLockContended,
	"ErrMetadataLockUnavailable": ErrMetadataLockUnavailable,
	"ErrDeviceInUse":             ErrDeviceInUse,
	"ErrKeyProvider":             ErrKeyProvider,
	"ErrOrphanedKeyslot":         ErrOrphanedKeyslot,
	"ErrPrimaryHeaderCurrent":    ErrPrimaryHeaderCurrent,
	"ErrTokenNotFound":           ErrTokenNotFound,
	"ErrReadOnly":                ErrReadOnly,
	"ErrClosed":                  ErrClosed,
	"ErrNotLUKS2":                ErrNotLUKS2,
}

func TestExportedSentinelsAreListed(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				gen, ok := d.(*ast.GenDecl)
				if !ok || gen.Tok != token.VAR {
					continue
				}
				for _, s := range gen.Specs {
					for _, n := range s.(*ast.ValueSpec).Names {
						if strings.HasPrefix(n.Name, "Err") {
							if _, ok := exportedSentinels[n.Name]; !ok {
								t.Errorf("exported sentinel %s is not in exportedSentinels", n.Name)
							}
						}
					}
				}
			}
		}
	}
}

func TestExportedSentinelsCarryThePackagePrefix(t *testing.T) {
	names := make([]string, 0, len(exportedSentinels))
	for n := range exportedSentinels {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		err := exportedSentinels[n]
		if err == nil {
			t.Errorf("%s is nil", n)
			continue
		}
		if !strings.HasPrefix(err.Error(), "luks2: ") {
			t.Errorf("%s text %q lacks the \"luks2: \" prefix", n, err.Error())
		}
	}
}
