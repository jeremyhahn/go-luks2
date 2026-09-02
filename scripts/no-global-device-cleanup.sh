#!/bin/sh
# no-global-device-cleanup.sh — refuse a tree that contains an ownership-blind
# device teardown.
#
# THE PATTERN (#17)
#
# `losetup -D` detaches EVERY loop device on the machine. `dmsetup remove_all`
# removes EVERY device-mapper mapping. Neither loop devices nor device-mapper
# are namespaced, and this repository's integration suite runs under
# `docker run --privileged`, so "the machine" is the HOST: the developer's
# workstation, or a runner shared with every other container on it.
#
# The measured damage was not hypothetical. The visible dm stack on the machine
# where this was found was nvme0n1p3_crypt -> vgmint-root, mounted at /. Every
# run asked the kernel to remove the mapping underneath the root filesystem,
# and survived only because those devices were held open — DM_DEV_REMOVE
# returned EBUSY and `|| true` discarded it.
#
# It is also not a defect in how devices are allocated. SetupLoopDevice already
# asks the kernel for a free device through LOOP_CTL_GET_FREE and touches only
# what it was given. No amount of careful allocation defends against a forcible,
# ownership-blind detach performed by somebody else.
#
# WHY A SCRIPT AND NOT A RULE
#
# A standing written instruction not to add a second `losetup -D` call site
# already existed. There were then FOUR: the container entrypoint, two CLI test
# teardowns, and the devcontainer entrypoint. A fix landed for three of them
# and the fourth stayed, in a file nothing that looked at CI would open. A
# doc-only rule was demonstrably not enough, which is what this issue's
# acceptance says in as many words.
#
# HOW IT DISTINGUISHES A COMMAND FROM A DESCRIPTION
#
# Several files legitimately NAME these commands while explaining why they are
# gone. Comments are stripped before matching: everything from the first `#` or
# `//` on a line is discarded, so prose about the pattern is invisible here and
# an actual command is not.
#
# KNOWN LIMIT, stated rather than left to be discovered: stripping at `//` also
# truncates a line at a URL, so an offending command written AFTER a URL on the
# same line would be missed. That is the only gap, it is narrow, and naming it
# is better than implying the check is total.
#
# FAIL-CLOSED: if the scan cannot find files to examine, that is a failure and
# not a clean result. A search that returned nothing because it did not run is
# indistinguishable from a clean tree unless the check says so.

set -eu

cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

# The commands that operate on everything on the machine, whoever made it.
# `-D` and `--detach-all` are the SAME flag; a guard that knows only the short
# spelling reports success while the teardown sits in the tree under its long
# name.
#
# The match is anchored on the COMMAND and then looks anywhere up to the next
# command separator for the destructive flag, rather than requiring the two to
# be adjacent and double-quoted. An earlier version required adjacency, and
# review demonstrated it missing every one of these:
#
#	losetup --verbose --detach-all
#	subprocess.run(['losetup', '--detach-all'])
#	subprocess.run(["/sbin/losetup", "--detach-all"])
#	dmsetup --verbose remove_all
#
# A guard that only recognises the one spelling its author happened to write is
# how the pattern reached four call sites in the first place.
#
# Case matters and is load-bearing: `-D` detaches EVERYTHING, `-d` detaches one
# named device and is the correct, scoped call this repository uses.
PATTERN='losetup[^;|&]*(-D|--detach-all)([^A-Za-z0-9-]|$)|dmsetup[^;|&]*remove_all([^A-Za-z0-9_-]|$)'

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

if ! git ls-files -z > "$work/files.z" 2>"$work/err"; then
	echo "FAIL: 'git ls-files' failed; its output cannot be trusted to be the" >&2
	echo "complete file list, and a partial list scanned clean is not a clean" >&2
	echo "tree." >&2
	sed 's/^/  /' "$work/err" >&2
	exit 1
fi
if [ ! -s "$work/files.z" ]; then
	echo "FAIL: 'git ls-files' listed nothing, so no file was examined." >&2
	echo "An empty search is not a clean tree. Refusing to report success on" >&2
	echo "a scan that did not run." >&2
	exit 1
fi

# NUL-delimited, then converted to lines. Word-splitting a plain listing would
# skip or mis-scan a tracked path containing a space or a tab, and a file the
# scan never opened is not a file it found clean. A newline inside a path
# cannot be handled line-by-line at all, so that case is refused outright
# rather than scanned wrongly. (Both defects were found by review on the
# sibling guard, no-internal-disclosure.sh; leaving the identical hole here
# while fixing it there would have been indefensible.)
records="$(tr -cd '\0' < "$work/files.z" | wc -c | tr -d ' ')"
tr '\0' '\n' < "$work/files.z" > "$work/files"
lines="$(wc -l < "$work/files" | tr -d ' ')"
if [ "$records" != "$lines" ]; then
	echo "FAIL: a tracked path contains a newline (${records} paths, ${lines} lines)." >&2
	echo "This scanner iterates line by line and would mis-scan or skip it." >&2
	exit 1
fi

: > "$work/hits"
scanned=0

while IFS= read -r f; do
	[ -n "$f" ] || continue

	# A tracked path that is not a readable regular file is NOT skipped.
	# Skipping was fail-open twice over: a tracked file missing from the
	# worktree went unexamined and counted as clean, and a symlink was either
	# skipped or followed to its target instead of having its own content --
	# the link target string -- examined, though that string is what the
	# repository publishes.
	if [ -L "$f" ]; then
		if ! target="$(readlink "$f")"; then
			echo "FAIL: ${f} is a tracked symlink whose target could not be read." >&2
			exit 1
		fi
		printf '%s\n' "$target" > "$work/content"
	elif [ -f "$f" ]; then
		# Binary files are scanned too, as text. They were skipped, and the
		# summary still counted the tree as fully examined -- a tracked blob
		# can carry a command string or an internal name just as a source file
		# can, and "we did not look" is not "there was nothing there". This
		# tree currently has no binary tracked files, so the change costs
		# nothing today and closes the hole for the day one appears.
		if ! cat "$f" > "$work/content" 2>"$work/err"; then
			echo "FAIL: could not read tracked file ${f}:" >&2
			sed 's/^/  /' "$work/err" >&2
			exit 1
		fi
	else
		echo "FAIL: ${f} is tracked but is not present as a regular file or" >&2
		echo "symlink, so it could not be examined. A file the scan never" >&2
		echo "opened is not a file it found clean." >&2
		exit 1
	fi
	scanned=$((scanned + 1))

	# The matching is done in one interpreter pass below, on the RAW lines.
	printf '%s\n' "$f" >> "$work/text"
done < "$work/files"

# Match on the raw line, suppressing only what is genuinely a comment.
#
# The previous version ran `sed 's|//.*$||; s|#.*$||'` first. That is not
# comment awareness, it is truncation at the first marker-looking character
# anywhere on the line, and it FAILED OPEN on executable code:
#
#	cmd="http://example; losetup -D"      <- cut at the // inside the string
#	x="not a comment # losetup -D"        <- cut at the # inside the string
#
# Both lines contain the teardown, both were truncated before grep saw it, and
# the guard reported the tree clean. A fail-open in a guard against a
# host-destructive pattern, introduced by the step meant to stop prose being
# flagged. Found by review; the suite had no case for it.
#
# So: find the first comment marker that is OUTSIDE quotes, and suppress a
# match only if it starts after that. A marker inside a string is not a
# comment, and a line with no unquoted marker is entirely code.
python3 - "$work/text" "$PATTERN" >> "$work/hits" <<'PY' || exit 1
import os, re, sys

paths = [p for p in open(sys.argv[1], encoding="utf-8", errors="replace").read().split("\n") if p]
pattern = re.compile(sys.argv[2])


def comment_starts_at(line):
    """Index of the first `#` or `//` that is not inside a quoted string, or
    len(line) if the line carries no comment."""
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#":
            return i
        elif c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            return i
        i += 1
    return len(line)


def lines_of(path):
    """The file's own published content.

    A symlink's content is its TARGET STRING, not the bytes it points at.
    Reading through the link scans someone else's file and misses what this
    repository actually publishes -- and the earlier version did exactly that,
    because the shell preflight read the link text into a buffer the scan then
    ignored. A tracked symlink whose target string is the teardown was
    accepted whenever a harmless file of that name existed.
    """
    if os.path.islink(path):
        return [os.readlink(path)]
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [ln.rstrip("\n") for ln in fh]


for path in paths:
    try:
        content = lines_of(path)
    except OSError as exc:
        print(f"FAIL: could not read {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    for n, line in enumerate(content, 1):
        cut = comment_starts_at(line)
        for m in pattern.finditer(line):
            if m.start() < cut:
                print(f"{path}:{n}:{line}")
                break
PY

if [ "$scanned" -eq 0 ]; then
	echo "FAIL: listed files, but examined none of them." >&2
	exit 1
fi

if [ -s "$work/hits" ]; then
	echo "FAIL: ownership-blind device teardown found (#17):" >&2
	sed 's/^/  /' "$work/hits" >&2
	echo "" >&2
	echo "These commands operate on EVERY loop device / dm mapping on the" >&2
	echo "machine, and neither is namespaced — under --privileged that means" >&2
	echo "the host, including devices belonging to other containers, other" >&2
	echo "suites, and the developer's own root filesystem." >&2
	echo "" >&2
	echo "Detach only what this code attached: 'losetup -j <backing-file>' to" >&2
	echo "find them, then 'losetup -d <dev>' each one, and treat a failure of" >&2
	echo "either as a failure rather than a log line." >&2
	exit 1
fi

echo "ok  no ownership-blind device teardown in ${scanned} tracked files"
