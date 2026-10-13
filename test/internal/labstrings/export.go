// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitAttributes is the file whose export-ignore entries keep the
// strip-at-publish files out of every archive of the tree: `git archive` and a
// forge's tag tarball both honor it. The public tree is produced as such an
// export, so a strip-at-publish file it does not export-ignore would ship.
const GitAttributes = ".gitattributes"

// notExportIgnored is the reason given for a strip-at-publish file that
// GitAttributes does not exclude.
const notExportIgnored = "listed as stripped at publish, but " + GitAttributes + " does not " +
	"export-ignore it, so an archive of the tree would ship it: add its DefaultStripAtPublish " +
	"pattern to " + GitAttributes + " (and to .dockerignore)"

// exportIgnored reports which of paths the staged GitAttributes files mark
// export-ignore. attributes maps each staged GitAttributes path to its staged
// content, so an unstaged edit changes nothing, like the content the gate
// scans.
//
// Only those files decide. `git check-attr --cached` in the scanned repository
// would also read its .git/info/attributes and every core.attributesFile, none
// of which travel with the tree: a rule in one of them would make a file look
// excluded that a forge's archive of the commit ships. So the files are
// written into a scratch repository of their own, created without templates
// (no info/attributes), and git runs there with no system, global or XDG
// configuration and no GIT_ variable inherited from the caller.
func exportIgnored(root string, attributes map[string][]byte, paths []string) (map[string]bool, error) {
	if len(paths) == 0 {
		return map[string]bool{}, nil
	}
	scratch, err := os.MkdirTemp("", "labstrings-attr-")
	if err != nil {
		return nil, &AttrError{Root: root, Err: err}
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	home := filepath.Join(scratch, "home")
	repo := filepath.Join(scratch, "repo")
	for _, dir := range []string{home, repo} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, &AttrError{Root: root, Err: err}
		}
	}
	for name, content := range attributes {
		if !filepath.IsLocal(filepath.FromSlash(name)) || filepath.Base(filepath.FromSlash(name)) != GitAttributes {
			return nil, &AttrError{Root: root, Err: errors.New("not a " + GitAttributes + " path in the tree: " + name)}
		}
		full := filepath.Join(repo, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return nil, &AttrError{Root: root, Err: err}
		}
		if err := os.WriteFile(full, content, 0o600); err != nil {
			return nil, &AttrError{Root: root, Err: err}
		}
	}
	env := hermeticGitEnv(home)
	if _, err := runGit(root, repo, env, nil, "init", "-q", "--template="); err != nil {
		return nil, err
	}
	out, err := runGit(root, repo, env, strings.NewReader(strings.Join(paths, "\x00")+"\x00"),
		"check-attr", "--stdin", "-z", "export-ignore")
	if err != nil {
		return nil, err
	}
	return parseExportIgnored(root, out, len(paths))
}

// hermeticGitEnv is the caller's environment without anything that points git
// at configuration or attributes outside the scratch repository: every GIT_
// variable (GIT_DIR, GIT_CONFIG_PARAMETERS, GIT_ATTR_SOURCE, ...), HOME and
// XDG_CONFIG_HOME, with the latter two pointed at the empty home.
func hermeticGitEnv(home string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_") || strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "HOME="+home, "XDG_CONFIG_HOME="+home,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
}

// runGit runs git in dir with env and returns its stdout; a failure is an
// AttrError about root, the repository the gate scans.
func runGit(root, dir string, env []string, stdin io.Reader, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) // #nosec G204 -- fixed git argv; dir is the scratch repository
	cmd.Env = env
	cmd.Stdin = stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, &AttrError{Root: root, Stderr: strings.TrimSpace(stderr.String()), Err: err}
	}
	return out, nil
}

// parseExportIgnored reads `git check-attr -z` output: path, attribute and
// value, each NUL-terminated, one triple per path asked about. Anything else
// is an error rather than a guess, because a path the parse lost would be
// reported as not export-ignored -- or, worse, the reverse.
func parseExportIgnored(root string, out []byte, want int) (map[string]bool, error) {
	fields := strings.Split(string(out), "\x00")
	if len(fields) == 0 || fields[len(fields)-1] != "" || (len(fields)-1) != 3*want {
		return nil, &AttrError{Root: root, Err: errors.New("git check-attr did not print one path/attribute/value triple per path")}
	}
	ignored := make(map[string]bool, want)
	for i := 0; i+2 < len(fields); i += 3 {
		ignored[fields[i]] = fields[i+2] == "set"
	}
	return ignored, nil
}

// NotExportIgnored reports every tracked entry a strip rule names that
// GitAttributes does not export-ignore: the strip is only mechanical for a
// file the archive actually leaves out.
func NotExportIgnored(entries []Entry, strip []Unpublishable) []FileFinding {
	var out []FileFinding
	for _, e := range entries {
		if _, ok := matchUnpublishable(strip, e.Path); ok && !e.ExportIgnored {
			out = append(out, FileFinding{Path: e.Path, Reason: notExportIgnored})
		}
	}
	return out
}
