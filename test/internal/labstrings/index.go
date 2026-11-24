// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Kind is what an index entry holds, taken from its git mode.
type Kind int

const (
	// KindFile is a regular file, executable or not (modes 100644, 100755).
	KindFile Kind = iota

	// KindSymlink is a symbolic link (mode 120000). Its content is the link
	// target, which is what the published tree carries.
	KindSymlink

	// KindGitlink is a submodule commit (mode 160000). It has no content in
	// this repository's object store and nothing of it is published here.
	KindGitlink
)

// Entry is one path as the git index records it: exactly what a commit made
// now would carry, whatever the working tree holds.
type Entry struct {
	// Path is slash-separated and relative to the repository root.
	Path string

	// Kind is what the entry holds.
	Kind Kind

	// Content is the staged blob: a file's bytes, or a symlink's target.
	// It is nil for a gitlink, and for an oversize file ExemptFile lists.
	Content []byte

	// Exemption is the reason ExemptFile gives for this path, or empty.
	Exemption string

	// Unread is set for an oversize file ExemptFile lists: its content was
	// not read, on the exemption's say-so. Every other entry was read in full.
	Unread bool

	// ExportIgnored is set when the index's GitAttributes marks the path
	// export-ignore: `git archive` and a forge's tag tarball leave it out.
	ExportIgnored bool
}

// IndexEntries reads every entry in the git index at root, content included,
// sorted by path.
//
// The content is read from the staged blobs, never from the working tree. The
// index is what the next commit carries, so a value staged and then edited out
// of the working tree, or a staged file deleted from it, or a file a sparse
// checkout never wrote, still ships -- and is still scanned. A blob that cannot
// be read fails the call; one larger than the scan limit fails it with
// FileTooLargeError unless ExemptFile lists it, in which case it is returned
// Unread. No other entry is ever passed over unread.
func IndexEntries(root string) ([]Entry, error) {
	return indexEntries(root, maxFileSize)
}

// stagedPath is one line of `git ls-files --stage`.
type stagedPath struct {
	path string
	kind Kind
	oid  string
}

func indexEntries(root string, limit int64) ([]Entry, error) {
	staged, err := listStaged(root)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(staged))
	var blobs []int
	tracked := make(map[string]bool, len(staged))
	exemptAt := -1
	for _, s := range staged {
		entries = append(entries, Entry{Path: s.path, Kind: s.kind})
		tracked[s.path] = true
		if s.kind != KindGitlink {
			blobs = append(blobs, len(entries)-1)
		}
		if s.path == ExemptFile && s.kind == KindFile {
			exemptAt = len(entries) - 1
		}
	}

	// The exemption list first, from its own staged blob, because it decides
	// how the rest are read.
	ex := Exemptions{}
	if exemptAt >= 0 {
		if err := readBlobs(root, staged, entries, []int{exemptAt}, limit, nil); err != nil {
			return nil, err
		}
		if ex, err = ParseExemptions(entries[exemptAt].Content, tracked); err != nil {
			return nil, err
		}
	}
	for i := range entries {
		entries[i].Exemption = ex[entries[i].Path]
	}
	if err := readBlobs(root, staged, entries, blobs, limit, ex); err != nil {
		return nil, err
	}

	paths := make([]string, len(entries))
	attributes := map[string][]byte{}
	for i, e := range entries {
		paths[i] = e.Path
		// git reads a GitAttributes only as a regular file, never through a
		// symlink.
		if e.Kind != KindFile || path.Base(e.Path) != GitAttributes {
			continue
		}
		if e.Unread {
			return nil, &IndexEntryError{Path: e.Path, Problem: "too large to read, and it decides what is export-ignored"}
		}
		attributes[e.Path] = e.Content
	}
	ignored, err := exportIgnored(root, attributes, paths)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		entries[i].ExportIgnored = ignored[entries[i].Path]
	}
	return entries, nil
}

// listStaged runs `git ls-files --stage`. An unmerged path is listed once per
// conflict stage and every stage is kept: each is content that could ship.
func listStaged(root string) ([]stagedPath, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "--stage", "-z") // #nosec G204 -- fixed git argv; root is the repository the gate scans
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, &ListError{Root: root, Stderr: strings.TrimSpace(stderr.String()), Err: err}
	}
	var staged []stagedPath
	for _, record := range strings.Split(string(out), "\x00") {
		if record == "" {
			continue
		}
		s, err := parseStaged(record)
		if err != nil {
			return nil, err
		}
		staged = append(staged, s)
	}
	sort.SliceStable(staged, func(i, j int) bool { return staged[i].path < staged[j].path })
	return staged, nil
}

// parseStaged parses "<mode> <oid> <stage>\t<path>".
func parseStaged(record string) (stagedPath, error) {
	meta, path, ok := strings.Cut(record, "\t")
	fields := strings.Fields(meta)
	if !ok || len(fields) != 3 || path == "" {
		return stagedPath{}, &IndexEntryError{Path: path, Problem: "unparseable index record " + strconv.Quote(record)}
	}
	s := stagedPath{path: path, oid: fields[1]}
	switch fields[0] {
	case "100644", "100755":
		s.kind = KindFile
	case "120000":
		s.kind = KindSymlink
	case "160000":
		s.kind = KindGitlink
	default:
		// An entry the gate does not understand is an entry it cannot
		// vouch for.
		return stagedPath{}, &IndexEntryError{Path: path, Problem: "unsupported index mode " + fields[0]}
	}
	return s, nil
}

// readBlobs fills entries[i].Content for every i in blobs from one
// `git cat-file --batch`, which answers the object ids in the order asked.
func readBlobs(root string, staged []stagedPath, entries []Entry, blobs []int, limit int64, ex Exemptions) error {
	if len(blobs) == 0 {
		return nil
	}
	var request strings.Builder
	for _, i := range blobs {
		request.WriteString(staged[i].oid)
		request.WriteByte('\n')
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", root, "cat-file", "--batch") // #nosec G204 -- fixed git argv; root is the repository the gate scans
	cmd.Stdin = strings.NewReader(request.String())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return &ListError{Root: root, Err: err}
	}
	if err := cmd.Start(); err != nil {
		return &ListError{Root: root, Err: err}
	}

	out := bufio.NewReader(stdout)
	for _, i := range blobs {
		content, unread, err := readBlob(out, staged[i], limit, ex[staged[i].path] != "")
		if err != nil {
			// Stop git rather than drain what is left; the verdict is
			// already "could not run".
			cancel()
			_ = cmd.Wait()
			return err
		}
		entries[i].Content = content
		entries[i].Unread = unread
	}
	if err := cmd.Wait(); err != nil {
		return &ListError{Root: root, Stderr: strings.TrimSpace(stderr.String()), Err: err}
	}
	return nil
}

// readBlob reads one "<oid> <type> <size>\n<content>\n" answer. A blob over
// limit is an error unless exempt, in which case it is consumed unread and
// reported so.
func readBlob(out *bufio.Reader, s stagedPath, limit int64, exempt bool) ([]byte, bool, error) {
	header, err := out.ReadString('\n')
	if err != nil {
		return nil, false, &ReadError{Path: s.path, Err: err}
	}
	fields := strings.Fields(header)
	if len(fields) == 2 && fields[1] == "missing" {
		// A partial clone without the blob, or a corrupt index: either
		// way the content that would ship was not seen.
		return nil, false, &IndexEntryError{Path: s.path, Problem: "blob " + s.oid + " is missing from the object store"}
	}
	if len(fields) != 3 || fields[0] != s.oid {
		return nil, false, &IndexEntryError{Path: s.path, Problem: "unexpected cat-file answer " + strconv.Quote(strings.TrimSpace(header))}
	}
	if fields[1] != "blob" {
		return nil, false, &IndexEntryError{Path: s.path, Problem: "object " + s.oid + " is a " + fields[1] + ", not a blob"}
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return nil, false, &IndexEntryError{Path: s.path, Problem: "unparseable blob size " + strconv.Quote(fields[2])}
	}
	if size > limit {
		if !exempt {
			return nil, false, &FileTooLargeError{Path: s.path, Size: size, Limit: limit}
		}
		if _, err := io.CopyN(io.Discard, out, size+1); err != nil {
			return nil, false, &ReadError{Path: s.path, Err: err}
		}
		return nil, true, nil
	}
	content := make([]byte, size+1) // the blob and its trailing newline
	if _, err := io.ReadFull(out, content); err != nil {
		return nil, false, &ReadError{Path: s.path, Err: err}
	}
	if content[size] != '\n' {
		return nil, false, &IndexEntryError{Path: s.path, Problem: "cat-file answer is not newline-terminated"}
	}
	return content[:size], false, nil
}
