#!/bin/sh
# no-internal-disclosure.sh — refuse a tree that publishes internal
# infrastructure detail from a repository with a public mirror.
#
#   scripts/no-internal-disclosure.sh              # the gate
#   scripts/no-internal-disclosure.sh --add NAME   # digest for a new name
#
# WHY (#20)
#
# This repository is mirrored publicly, and the release path publishes a tree
# byte-identical to the internal tag. Every tracked file is therefore a
# published file. Several carried detail a public reader must never see and
# could not act on if they did: an absolute path into a private repository on a
# named workstation, that repository's name, an internal forge IP and port,
# named internal runner hosts, an internal mail domain, internal ticket numbers
# and citations of company documents that resolve to nothing outside.
#
# WHY IT IS A CHECK AND NOT A ONE-TIME SWEEP
#
# #20 asserts a WHOLE-TREE property, and a whole-tree property established on a
# branch stops holding the moment anything merges beneath it. It cannot be kept
# by remembering to re-run a grep: it has to fail a build. Same lesson as the
# device-teardown guard beside this file — a standing written rule existed
# there, and the pattern still reached four call sites.
#
# THE PREDICATE IS "DOES THIS REPOSITORY PUBLISH COMPANY DETAIL",
# not "does anything break for an outside user". An overridable default is not
# a fix: a Makefile variable defaulting to an absolute path under someone's
# home directory in a private checkout still publishes a login name, a private
# repository's name and a machine's directory layout to everyone who reads the
# file, whether or not they ever override it.
#
# ---------------------------------------------------------------------------
# HOW IT AVOIDS BEING THE LEAK ITSELF
#
# The first draft listed the internal names it searches for, in plaintext, and
# excluded itself from its own scan. Review called that what it was: a CI
# workaround rather than compliance. A guard against publishing a private
# repository's name cannot work by publishing that name — the exclusion made
# the check pass while the file leaked more than anything it caught.
#
# There is no exclusion now. This file is scanned like every other, and
# detection takes three forms, none of which names anything internal:
#
#   1. STRUCTURAL patterns — a home-directory path, an RFC1918 address, an
#      internal-only DNS suffix, an internal ticket reference. These describe a
#      SHAPE. "No RFC1918 literals in this repo" tells a reader nothing about
#      the network.
#
#   2. DANGLING DOCUMENT CITATIONS — a Markdown file named in a tracked file
#      that this repository does not contain. This catches every citation of a
#      company convention document without naming one, because the real
#      property is "cites a document this repository does not contain", which
#      is exactly what makes such a reference useless to an outside reader.
#
#      A citation carrying a PATH is resolved, not reduced to its basename.
#      Basename matching alone let a company document through whenever this
#      repository happened to contain a file of the same name -- reproduced on
#      this branch before the fix, using a company path whose last component
#      matches one of ours. A path is accepted only if it resolves to a tracked
#      file either relative to the citing file's own directory or relative to
#      the repository root. Both are tried because both spellings occur
#      legitimately here: a doc deep in docs/ links to a sibling with a
#      leading parent reference, while the top-level README names the same
#      file from the root.
#
#   3. HASHED NAMES — proper nouns (the private repository, the named hosts)
#      stored as SHA-256 of the lowercased token. TRACKED PATHNAMES ARE HASHED
#      TOO, not only file contents: a file or directory named after an internal
#      host is published by its name alone, and content-only tokenisation let
#      that through. A digest publishes nothing
#      but the fact that N such names exist. Text is split on non-alphanumerics
#      and every PREFIX of each token from four characters up is hashed, so a
#      name reached by a separator (a role or numeric suffix after a dash or a
#      slash) and one glued straight on with no separator both match the same
#      stem. Prefix hashing is what covers the second case: whole-token hashing
#      alone would not, and the earlier comment here claimed coverage the code
#      did not have.
#
#      LIMIT, stated rather than implied: a digest is not encryption, and a
#      short dictionary word could be brute-forced. These are chosen names, not
#      secrets; recovering one costs embarrassment, not compromise. The
#      alternative — keeping the list outside the repository — yields a gate
#      that cannot run for a developer and fails open wherever the list is
#      absent, which is worse. `--add` prints the digest for a new name.
#
# WHAT IT DOES NOT CATCH, measured rather than assumed
#
# A repo-relative path into another repository with no `.md` on the end — say a
# reference to a Dockerfile three directories deep in the company's infra tree.
# Generalising rule 2 to any multi-segment path was TRIED and reverted: it
# cannot be told apart from ordinary content, and produced 19 false positives
# on this tree at the first run. Real examples it flagged — `patch/minor/major`
# and `race/msan/asan` (prose with slashes), `x/crypto/xts` and
# `crypto/internal/fips140/pbkdf2` (upstream package paths),
# `cryptsetup/lib/luks2/luks2.h` (a citation of the C implementation this
# library interoperates with, which is exactly the kind of reference a public
# reader WANTS), `github/codeql-action/upload-sarif` (an action reference), and
# a base64 fragment out of go.sum.
#
# A guard that cries wolf gets switched off, and switched off it protects
# nothing — so the narrower rule is deliberate. That gap is a review concern,
# named here so nobody reads a green result as covering it.
#
# FAIL-CLOSED throughout. A file list that cannot be obtained, a tracked path
# this scanner cannot iterate safely, a grep that ERRORS rather than
# not-matching, a missing interpreter: each is a failure. A search that
# returned nothing because it did not run looks exactly like a clean tree
# unless the check says otherwise.

set -eu

cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

# Fully resolved: a symlink target is compared against this, and realpath
# returns a resolved path. An unresolved root makes every in-tree target look
# external (#120).
root="$(pwd -P)"

# SHA-256 of lowercased tokens that must not appear anywhere in the tree.
# Add one with: scripts/no-internal-disclosure.sh --add <name>
FORBIDDEN_DIGESTS='
017f21de44a3f75808d81824ff1284db8c9c0629cb66d43cbe94a274186bb56b
b2f896bb37f772a0dd0d4fdae6ec20020143f642ec30edd22c10a759f847bc9b
d7509e2c30b4aa6e7950f93b176ce45cf749a1c5199db383648c2be7a6170a7b
9227f148839d1cc2c2483f0e4bb8c0053dfd4bb9d30d2b9bacca8cb4a69f7d34
304b4a90a76a1cbe4c112e074b30e75181f54df43d60f883597457844293b341
'

# Shapes, not names.
#   - a home directory belonging to a named account
#   - every RFC1918 range, with or without a port: 10/8, 172.16/12, 192.168/16
#   - internal-only DNS suffixes
#   - an internal ticket reference
STRUCTURAL_PATTERNS='
/(home|Users)/[a-z][a-z0-9._-]*/
(^|[^0-9.])10(\.[0-9]{1,3}){3}([^0-9.]|$)
(^|[^0-9.])172\.(1[6-9]|2[0-9]|3[01])(\.[0-9]{1,3}){2}([^0-9.]|$)
(^|[^0-9.])192\.168(\.[0-9]{1,3}){2}([^0-9.]|$)
[a-z0-9-]+\.(internal|localdomain|lan)([^a-z0-9.-]|$)
(company|portfolio|fleet) task #[0-9]
'

if [ "${1:-}" = "--add" ]; then
	[ -n "${2:-}" ] || { echo "usage: $0 --add <name>" >&2; exit 1; }
	printf '%s' "$2" | tr '[:upper:]' '[:lower:]' | sha256sum | cut -d' ' -f1
	exit 0
fi

command -v python3 >/dev/null 2>&1 || {
	echo "FAIL: python3 is not available. The hashed-name pass needs it, and" >&2
	echo "a check that cannot run is not a check that passed." >&2
	exit 1
}

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

# NUL-delimited listing, converted to lines for iteration. That is safe for
# spaces and tabs but NOT for a newline inside a path, so refuse outright if
# the two counts disagree rather than silently scanning the wrong thing — a
# file this scanner never opened is not a file it found clean. POSIX sh has no
# NUL-aware `read`, so detecting and refusing is the honest option.
records="$(tr -cd '\0' < "$work/files.z" | wc -c | tr -d ' ')"
tr '\0' '\n' < "$work/files.z" > "$work/files"
lines="$(wc -l < "$work/files" | tr -d ' ')"
if [ "$records" != "$lines" ]; then
	echo "FAIL: a tracked path contains a newline (${records} paths, ${lines} lines)." >&2
	echo "This scanner iterates line by line and would mis-scan or skip it." >&2
	echo "Refusing rather than reporting a result it cannot stand behind." >&2
	exit 1
fi

printf '%s' "$STRUCTURAL_PATTERNS" | sed '/^$/d' > "$work/structural"
printf '%s' "$FORBIDDEN_DIGESTS" | sed '/^$/d' | sort -u > "$work/digests"

: > "$work/hits"
: > "$work/text"
mkdir -p "$work/scan"
scanned=0

while IFS= read -r f; do
	[ -n "$f" ] || continue

	# A tracked path that is not a readable regular file is NOT skipped.
	# Skipping was fail-open twice over: a tracked file missing from the
	# worktree went unexamined and counted as clean, and a symlink was either
	# skipped or followed to its target rather than having its own content --
	# the link target string -- examined, though that string is exactly what
	# the repository publishes and could name an internal path.
	if [ -L "$f" ]; then
		# A TRACKED SYMLINK HAS TWO CONTENTS AND THE GUARD NEEDS BOTH (#120).
		#
		# Its own published content is the target PATH STRING -- that is
		# literally the blob git stores -- and `readlink` gives that. But what
		# the link RESOLVES to is also part of this tree at scan time, and a
		# release publishes a tree byte-identical to the internal tag, so the
		# link resolves for whoever unpacks it too.
		#
		# Reading only the link text is a fail-open, MEASURED against main at
		# 5c7b578 with a control: a tracked link to an untracked file holding
		# the violation was reported CLEAN, while the identical bytes as a
		# regular tracked file were rejected. A path string never matches any
		# pattern here, so the target was never examined at all.
		#
		# Every case where the target cannot be examined is a FAILURE. A link
		# this scanner cannot follow is not evidence that what it points at is
		# clean -- the same rule the non-symlink branches below already apply.
		if ! readlink -- "$f" > "$work/content" 2>"$work/err"; then
			echo "FAIL: could not read tracked symlink ${f}:" >&2
			sed 's/^/  /' "$work/err" >&2
			exit 1
		fi
		if ! real="$(realpath -- "$f" 2>"$work/err")"; then
			echo "FAIL: tracked symlink ${f} does not resolve (dangling, or a" >&2
			echo "loop), so what it points at could not be examined." >&2
			sed 's/^/  /' "$work/err" >&2
			exit 1
		fi
		# $root is fully resolved (pwd -P). Comparing against an unresolved
		# root reads every in-tree target as "outside" whenever any component
		# of the worktree path is itself a link -- which is true of every
		# worktree in this repository.
		# "$root" ITSELF, not only descendants of it. A link to `.` or to
		# `subdir/..` resolves to exactly the root, which "$root"/* does not
		# match -- so the containment check rejected an in-tree directory as
		# external. Codex caught it on #120; the reviewed implementation this
		# branch copied from (#108) has the same bug, which is the fourth
		# instance of the repeated-pattern failure #120 is about: adopting a
		# reviewed shape carries its findings only if you re-check them.
		case "$real" in
		"$root" | "$root"/*) ;;
		*)
			echo "FAIL: tracked symlink ${f} resolves OUTSIDE the worktree:" >&2
			echo "  ${real}" >&2
			echo "Its target is not part of this tree and is not scanned, so" >&2
			echo "nothing here can vouch for what it contains." >&2
			exit 1
			;;
		esac
		if [ -d "$real" ]; then
			: # A directory has no bytes of its own. Whatever is tracked under
			  # it is listed and scanned under its own path.
		elif [ -f "$real" ]; then
			if ! cat -- "$real" >> "$work/content" 2>"$work/err"; then
				echo "FAIL: could not read the target of tracked symlink ${f}:" >&2
				sed 's/^/  /' "$work/err" >&2
				exit 1
			fi
		else
			echo "FAIL: tracked symlink ${f} resolves to something that is" >&2
			echo "neither a regular file nor a directory, so it could not be" >&2
			echo "examined." >&2
			exit 1
		fi
	elif [ -f "$f" ]; then
		# Binary files are scanned too, as text. They were skipped while the
		# summary still counted the tree as fully examined -- a tracked blob
		# can carry an internal hostname or path just as a source file can, and
		# "we did not look" is not "there was nothing there".
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

	# HAND THE ASSEMBLED CONTENT TO EVERY CONSUMER, not just the nearest one.
	#
	# This buffer has TWO consumers: the structural grep loop below, and the
	# hashed-name/citation pass after it. The first reads "$work/content"; the
	# second used to re-open the path itself and call os.readlink for a
	# symlink, so it never saw the target bytes appended above -- a tracked
	# link to an untracked file holding a forbidden hostname, or a dangling
	# internal citation with no structural shape, was still reported clean.
	#
	# One buffer, both consumers. Two readers of one thing agree until they
	# do not, and fixing the nearer one is what hides the other.
	cp -- "$work/content" "$work/scan/$scanned"
	printf '%s\t%s\n' "$scanned" "$f" >> "$work/text"

	# grep exit codes: 0 matched, 1 no match, >=2 ERROR. Only 1 is clean.
	while IFS= read -r pat; do
		# -i: a capitalised variant is the same disclosure. Without it, an
		# upper-case internal DNS suffix, a capitalised home-directory
		# prefix, or a sentence-cased ticket reference all pass. Written
		# without literal examples on purpose -- this file is scanned by
		# this rule, and the first draft of this very comment failed it.
		out="$(grep -ainE "$pat" "$work/content" 2>"$work/err")" && rc=0 || rc=$?
		if [ "${rc:-0}" -ge 2 ]; then
			echo "FAIL: could not search ${f} (grep exit ${rc}):" >&2
			sed 's/^/  /' "$work/err" >&2
			echo "A search that errored is not a search that found nothing." >&2
			exit 1
		fi
		[ "${rc:-0}" -eq 0 ] || continue
		printf '%s\n' "$out" | sed "s|^|${f}: [shape] |" >> "$work/hits"
	done < "$work/structural"

done < "$work/files"

if [ "$scanned" -eq 0 ]; then
	echo "FAIL: listed files, but examined none of them." >&2
	exit 1
fi

# Structural shapes in the tracked PATHNAMES themselves. A path is published
# by its name alone, so a directory named after an internal host discloses just
# as a line of text would.
while IFS= read -r pat; do
	out="$(grep -inE "$pat" "$work/files" 2>"$work/err")" && rc=0 || rc=$?
	if [ "${rc:-0}" -ge 2 ]; then
		echo "FAIL: could not search the tracked path list (grep exit ${rc})." >&2
		exit 1
	fi
	[ "${rc:-0}" -eq 0 ] || continue
	printf '%s\n' "$out" | sed 's|^[0-9]*:|| ; s|^|[path] |' >> "$work/hits"
done < "$work/structural"

# Content pass: hashed names and dangling document citations, in one
# interpreter run. Both need per-file context -- the name check hashes the
# PATH as well as the content, and the citation check resolves a cited path
# against the citing file's own directory -- so they live together here rather
# than as two more grep loops.
python3 - "$work/text" "$work/digests" "$work/files" "$work/scan" >> "$work/hits" <<'PY' || exit 1
import hashlib, os, posixpath, re, sys

# Each line is "<scan-id>\t<display path>"; the bytes live in <scan dir>/<id>,
# assembled by the shell loop -- for a symlink, its target string FOLLOWED BY
# the target's bytes.
entries = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace").read().split("\n"):
    if not line:
        continue
    scan_id, _, display = line.partition("\t")
    entries.append((os.path.join(sys.argv[4], scan_id), display))
digests = {d.strip() for d in open(sys.argv[2]) if d.strip()}
tracked = {f for f in open(sys.argv[3], encoding="utf-8", errors="replace").read().split("\n") if f}
tracked_lower = {f.lower() for f in tracked}
basenames = {posixpath.basename(f).lower() for f in tracked if f.lower().endswith(".md")}

token = re.compile(r"[A-Za-z][A-Za-z0-9]{3,}")
citation = re.compile(r"[A-Za-z0-9_./-]+\.md", re.IGNORECASE)
# Absolute URLs are not repository paths. Without this, a public link to a
# Markdown document matches from its double slash onward, resolves nowhere
# inside the checkout, and is reported as a dangling citation -- so a
# legitimate public documentation link would fail the build. URL spans are
# computed first and any citation falling inside one is skipped.
#
# The obvious way to write this comment is to quote the matched form. That
# form has no scheme, so it is not inside a URL span, so the guard flags its
# own explanation -- which it did. Describe the shape, do not paste it.
url = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+")


# THE ONE SANCTIONED SIBLING. Owner ruling, recorded against #138.
#
# The context repository holding the engineering standards is checked out
# BESIDE this one, never inside it, so every pointer to it takes the parent
# form below and reads identically on a developer's host and in a build
# container. That is the whole point of the layout, and it makes such a
# citation -- by construction -- a citation of a document this repository does
# not contain, which is exactly rule 2's predicate. Two rules that are both
# working as designed, disagreeing.
#
# This is a HOLE IN A SECURITY GUARD and is written to be the narrowest one
# that resolves the conflict:
#
#   - ONE literal prefix, compared after normalisation. A candidate is
#     normalised FIRST, so a citation that merely passes through the sibling
#     on its way somewhere else -- climbing back out with further parent
#     traversals -- normalises to a path that no longer carries the prefix and
#     is rejected exactly as before. The prefix cannot be used as a doorway.
#   - The trailing slash is load-bearing. Without it the prefix also admits a
#     sibling whose name merely STARTS with these characters, which would turn
#     one sanctioned repository into an open-ended family of them.
#   - It lifts the [dangling] rule ONLY. The [name] and [shape] rules still
#     scan these lines in full, so a citation that also carries an internal
#     host, an RFC1918 literal or a private ticket reference still fails.
#
# What it costs a public reader is bounded: the prefix publishes a directory
# name and nothing else -- no host, no address, no private repository name, no
# ticket. What it buys is that this control can be adopted by the other
# repositories in the portfolio, every one of which already carries these
# citations and would otherwise inherit a red build on the day it turned the
# guard on.
SANCTIONED_SIBLING = "../handbook/"


def inside(candidate):
    """True if candidate normalizes to a tracked path that stays beneath the
    repository root, or to the one sanctioned sibling context repository.
    An absolute path, or one that climbs out with '..', is NOT resolved back
    inside -- it is a reference to something this repository does not contain,
    which is the whole point of the check."""
    norm = posixpath.normpath(candidate)
    # Normalised before comparison, so this admits the sibling itself and not
    # a path that only travels through it.
    if norm.startswith(SANCTIONED_SIBLING):
        return True
    if posixpath.isabs(norm) or norm == ".." or norm.startswith("../"):
        return False
    return norm.lower() in tracked_lower


def forbidden(text):
    """True if any token, or any prefix of one from four characters up, is
    a forbidden name. Prefixes are checked so a name glued straight onto a
    suffix with no separator still matches."""
    for tok in {m.group(0).lower() for m in token.finditer(text)}:
        for n in range(4, len(tok) + 1):
            if hashlib.sha256(tok[:n].encode()).hexdigest() in digests:
                return True
    return False


for scan_path, path in entries:
    try:
        text = open(scan_path, encoding="utf-8", errors="replace").read()
    except OSError as exc:
        print(f"FAIL: could not read the scanned content of {path}: {exc}", file=sys.stderr)
        sys.exit(1)

    # The PATH is hashed alongside the content: a file or directory named after
    # an internal host is published by its name whatever it contains.
    if forbidden(path + "\n" + text):
        print(f"{path}: [name] a forbidden internal name appears in this file or its path")

    url_spans = [m.span() for m in url.finditer(text)]

    def in_url(pos):
        return any(a <= pos < b for a, b in url_spans)

    seen = set()
    for m in citation.finditer(text):
        if in_url(m.start()):
            continue  # a public link, not a path into this repository
        cited = m.group(0)
        # A match immediately preceded by an interpolation sigil is a
        # CONSTRUCTED path, not a citation: `$d/README.md` and
        # `${HOST}-runbook.md` are a script assembling a filename at runtime.
        # Treating those as citations produced thirteen false positives on the
        # first file that builds paths programmatically, and a guard that cries
        # wolf gets switched off.
        if m.start() > 0 and text[m.start() - 1] in "${}":
            continue
        if cited.lower() in seen:
            continue
        seen.add(cited.lower())
        if "/" in cited:
            # Resolve, do not reduce to a basename: a company document whose
            # last component matches one of ours would otherwise be accepted
            # on the strength of our file. Both spellings are tried because
            # both occur legitimately.
            #
            # A candidate that normalizes OUTSIDE the repository is rejected
            # outright rather than trimmed back inside it. Trimming was the
            # bug: str.lstrip removes every leading dot and slash CHARACTER,
            # not a prefix, so a citation that climbed above the root with
            # repeated parent traversals was flattened to a bare filename and
            # then matched a tracked file of that name. Any citation whose
            # last component matched something tracked could escape that way.
            # Covered by the traversal case in scripts/guards-test.sh.
            if (inside(posixpath.join(posixpath.dirname(path), cited))
                    or inside(cited)):
                continue
        elif cited.lower() in basenames:
            continue
        print(f"{path}: [dangling] cites {cited}, which is not a file in this repository")
PY

if [ -s "$work/hits" ]; then
	echo "FAIL: internal infrastructure detail in a publicly mirrored repo (#20):" >&2
	sort -u "$work/hits" | sed 's/^/  /' >&2
	echo "" >&2
	echo "REWRITE, do not redact. A redacted line loses the meaning that" >&2
	echo "earned it, and the next reader deletes it as noise. An internal" >&2
	echo "ticket number becomes the reasoning it stood for; a named host" >&2
	echo "becomes the shape of the constraint; a company doc citation becomes" >&2
	echo "the rule stated inline. A stranger should be able to recognise the" >&2
	echo "situation in their own system." >&2
	exit 1
fi

echo "ok  no internal infrastructure detail in ${scanned} tracked files"
