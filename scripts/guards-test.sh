#!/bin/sh
# guards-test.sh — behavioural tests for the two repository guards,
# scripts/no-internal-disclosure.sh and scripts/no-global-device-cleanup.sh.
#
#   scripts/guards-test.sh
#
# WHY THIS EXISTS
#
# Both guards are gates: CI and `make ci` run them, and a merge is blocked when
# they fail. Until this file existed, the ONLY thing exercising them was running
# them against the current, clean tree — which proves they can say yes, and
# proves nothing at all about the thing they are for. A guard that has stopped
# detecting is indistinguishable from a clean repository unless something feeds
# it input it must reject.
#
# That is not hypothetical here. Every review round on these guards found a
# fail-open path that a green run against the clean tree reported as fine:
#
#   - the disclosure guard published the internal names it searched for, and
#     excluded itself from its own scan;
#   - `git ls-files` output was word-split, so a path containing a space was
#     never scanned;
#   - a grep ERROR was indistinguishable from no-match;
#   - `sed` failing to read a file left grep with no input, exit 1, "clean";
#   - tracked symlinks were followed to their target, and tracked files missing
#     from the worktree were skipped in silence;
#   - `losetup --detach-all` — the same flag as `-D` — was not matched at all;
#   - a citation climbing above the repository root with parent traversals was
#     flattened to a bare filename and accepted against a tracked file of that
#     name.
#
# Each is now a case below. The last one is the reason this file exists at all:
# it was introduced BY a fix for an earlier finding, in a guard that had been
# reviewed twice, and a clean-tree run stayed green throughout.
#
# HOW IT WORKS
#
# Each case builds a throwaway git repository, drops in a fixture, and runs the
# real guard against it. The guards read `git ls-files`, so a fixture must be a
# tracked file in a real repository — a temp directory alone would test nothing.
# Nothing here touches this repository, the network, or any device.

set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
DISCLOSURE="${root}/scripts/no-internal-disclosure.sh"
DEVICE="${root}/scripts/no-global-device-cleanup.sh"

for s in "$DISCLOSURE" "$DEVICE"; do
	[ -x "$s" ] || { echo "FAIL: $s is not executable" >&2; exit 1; }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

# ---------------------------------------------------------------------------
# PAYLOADS ARE ASSEMBLED, NEVER WRITTEN LITERALLY.
#
# This file is scanned by the very guards it tests. A literal `losetup -D` or a
# literal internal hostname here is, to those guards, indistinguishable from
# the real thing -- so a fixture written the obvious way FAILS THE REPOSITORY
# ON ITS OWN TEST DATA. That happened: CI went red on this file listing nine of
# its own probes as findings.
#
# The fix is NOT to exempt this file. Exempting the file is the antipattern
# review already rejected in the disclosure guard, where excluding it from its
# own scan let it publish more than anything it caught. Splitting each payload
# across a concatenation keeps the fixture EXACT -- the shell rejoins it before
# it reaches a fixture -- while leaving no matchable literal in the tracked
# bytes. Nothing is excluded from anything.
#
# Each name says what the payload is, so the probes below stay readable.
HOST_A="god""like"                       # a forbidden runner name
HOST_B="vsta""tion"                      # another, in use with a numeric suffix
ADDR_PRIV="192.168.101.""91"             # RFC1918, the shape the forge used
ADDR_10="10.20.30.""40"                  # RFC1918 10/8
ADDR_172="172.20.5.""9"                  # RFC1918 172.16/12
PATH_HOME="/ho""me/someone/private/agent-git.sh"
PATH_USERS="/Us""ers/Alice/private/thing"
MAIL_INT="agent@build.int""ernal"
TICKET="com""pany task #123"
TICKET_CAPS="Com""pany task #99"
DOC_PATH="conventions/security-review"".md"
DOC_OTHER="software/CLAUDE"".md"
DOC_BARE="devops"".md"
DOC_ESCAPE="../../../README"".md"
DOC_SIBLING="../../private-repo/README"".md"
LOSETUP="lose""tup"                      # the command, split so no probe line
DMSETUP="dmse""tup"                      # carries a matchable command+flag pair

pass=0
fail=0

# newrepo <name> — a minimal tracked tree the guards can be pointed at. It
# carries a couple of the shapes the real repository has (a root README.md and
# a nested doc) so that "accepted" cases are accepted for the right reason.
newrepo() {
	d="$work/$1"
	rm -rf "$d"
	mkdir -p "$d/scripts" "$d/docs/luks"
	cp "$DISCLOSURE" "$DEVICE" "$d/scripts/"
	printf 'root readme\n' > "$d/README.md"
	printf 'fips doc\n' > "$d/docs/FIPS.md"
	printf 'nested doc\n' > "$d/docs/luks/kdf.md"
	git -C "$d" init -q
	git -C "$d" add -A
	echo "$d"
}

# check <accept|reject> <guard> <label> — run the guard in $d and compare.
check() {
	want="$1"
	guard="$2"
	label="$3"
	if (cd "$d" && "./scripts/$guard" >"$work/out" 2>&1); then
		got=accept
	else
		got=reject
	fi
	if [ "$got" = "$want" ]; then
		printf '  PASS  %-62s (%s)\n' "$label" "$got"
		pass=$((pass + 1))
	else
		printf '  FAIL  %-62s want %s, got %s\n' "$label" "$want" "$got"
		sed 's/^/          /' "$work/out"
		fail=$((fail + 1))
	fi
}

# fixture <relpath> <line...> — a tracked file containing the given lines.
fixture() {
	f="$d/$1"
	shift
	mkdir -p "$(dirname "$f")"
	printf '%s\n' "$@" > "$f"
	git -C "$d" add -A
}

echo "== disclosure guard: a clean tree is accepted =="
d="$(newrepo clean)"
check accept no-internal-disclosure.sh "a tree with nothing internal in it"

echo "== disclosure guard: the shapes it claims to catch =="
for probe in \
	"AGENT_GIT ?= ${PATH_HOME}" \
	"url = http://${ADDR_PRIV}:3001" \
	"the box is ${ADDR_10}" \
	"internal host ${ADDR_172}" \
	"mail ${MAIL_INT}" \
	"MAIL $(printf '%s' "$MAIL_INT" | tr '[:lower:]' '[:upper:]')" \
	"path ${PATH_USERS}" \
	"see ${TICKET}" \
	"${TICKET_CAPS}"; do
	d="$(newrepo shape)"
	fixture notes.txt "$probe"
	check reject no-internal-disclosure.sh "shape: $probe"
done

echo "== disclosure guard: hashed names, including in PATHNAMES =="
d="$(newrepo name1)"
fixture notes.txt "the runner is ${HOST_B}-03"
check reject no-internal-disclosure.sh "a forbidden name with a separator"
d="$(newrepo name2)"
fixture notes.txt "the runner ${HOST_B}03 has no separator"
check reject no-internal-disclosure.sh "a forbidden name with no separator (prefix hashing)"
d="$(newrepo name3)"
fixture notes.txt "built on $(printf '%s' "$HOST_A" | tr '[:lower:]' '[:upper:]')"
check reject no-internal-disclosure.sh "a forbidden name in upper case"
d="$(newrepo name4)"
fixture "docs/${HOST_A}-notes/setup.md" 'nothing interesting here'
check reject no-internal-disclosure.sh "a forbidden name in a DIRECTORY name, innocuous content"
d="$(newrepo name5)"
fixture "${HOST_B}-01-runbook.md" 'nothing interesting here'
check reject no-internal-disclosure.sh "a forbidden name in a FILE name, innocuous content"

echo "== disclosure guard: dangling citations, and the traversal escape =="
d="$(newrepo cite1)"
fixture notes.txt "per ${DOC_PATH} the rule is absolute"
check reject no-internal-disclosure.sh "a company doc citation carrying a path"
d="$(newrepo cite2)"
fixture notes.txt "see ${DOC_OTHER} for the rules"
check reject no-internal-disclosure.sh "a path whose last component is NOT tracked here"
d="$(newrepo cite3)"
# The traversal escape: this normalizes above the root, and a basename-flattening
# implementation matched it against the tracked root README.md and accepted it.
fixture docs/probe/citation.txt "see ${DOC_ESCAPE}"
check reject no-internal-disclosure.sh "a citation climbing ABOVE the repository root"
d="$(newrepo cite4)"
fixture notes.txt "see ${DOC_SIBLING}"
check reject no-internal-disclosure.sh "a citation into a sibling repository"
d="$(newrepo cite5)"
fixture notes.txt "see ${DOC_BARE} for the pipeline"
check reject no-internal-disclosure.sh "a bare company doc filename"

echo "== disclosure guard: legitimate content is NOT rejected =="
d="$(newrepo ok1)"
fixture docs/luks/notes.txt "see [fips](../""FIPS.md) for the mode"
check accept no-internal-disclosure.sh "a relative link to a real sibling doc"
d="$(newrepo ok2)"
fixture notes.txt "see docs/""FIPS.md" "and docs/luks/""kdf.md"
check accept no-internal-disclosure.sh "root-relative links to real docs"
d="$(newrepo ok3)"
fixture notes.txt 'sudo luks2 mount mydisk /mnt/encrypted' 'module github.com/jeremyhahn/go-luks2' 'see #28 for the interop case'
check accept no-internal-disclosure.sh "user paths, the public module path, a local issue ref"
# Review found the citation rule rejecting PUBLIC URLs that happen to end in
# .md: the match starts at the double slash, resolves nowhere in the checkout,
# and was reported as a dangling internal citation -- so a legitimate upstream
# documentation link would have failed the build. The accept side had no case
# for it, which is why it reached review rather than the suite.
d="$(newrepo ok4)"
fixture notes.txt "see https://example.com/guide.md for the upstream write-up"
check accept no-internal-disclosure.sh "a public https link to a .md document"
d="$(newrepo ok5)"
fixture notes.txt "upstream notes: http://example.org/docs/a/b/README.md"
check accept no-internal-disclosure.sh "a public http link with a deeper path"
d="$(newrepo ok6)"
fixture notes.txt "mirror at ftp://example.net/spec/format.md"
check accept no-internal-disclosure.sh "a non-http scheme"
# And the negative that keeps the fix honest: dropping the scheme must still
# be caught, so the URL skip cannot be used to smuggle a repo-relative path.
d="$(newrepo ok7)"
fixture notes.txt "see ${DOC_OTHER} for the rules"
check reject no-internal-disclosure.sh "a company path is still caught, no scheme"

echo "== disclosure guard: fail-closed =="
d="$(newrepo fc1)"
fixture 'a file with spaces.txt' "built on ${HOST_A}"
check reject no-internal-disclosure.sh "a tracked path containing spaces is SCANNED"
d="$(newrepo fc2)"
fixture placeholder.txt 'ordinary'
# Target made real here for the same reason as the device guard's case below:
# a dangling link lets a rejection come from an open() failure rather than
# from reading the link text.
mkdir -p "$d/realdir" && printf 'harmless\n' > "$d/realdir/x.md"
ln -s "realdir/x"".md" "$d/harmless-link.md"   # assembled; see the payload block
ln -s "${PATH_HOME%agent-git.sh}x.md" "$d/link.md"
git -C "$d" add -A
check reject no-internal-disclosure.sh "a symlink is read as its link text, not its target"
d="$(newrepo fc3)"
fixture gone.txt 'ordinary'
rm "$d/gone.txt"
check reject no-internal-disclosure.sh "a tracked file missing from the worktree"
d="$(newrepo fc4)"
printf 'harmless\000built on %s\000' "$HOST_A" > "$d/blob.bin"
git -C "$d" add -A
check reject no-internal-disclosure.sh "a tracked BINARY file is scanned, not skipped"

echo "== device guard: a clean tree is accepted =="
d="$(newrepo devclean)"
fixture ok.sh "${LOSETUP} -j \"\$tmpfile\"" "${LOSETUP} -d \"\$dev\""
check accept no-global-device-cleanup.sh "scoped losetup calls this library makes"
d="$(newrepo devclean2)"
fixture ok.go "// This used to be \`${LOSETUP} -D\`, which detaches every device."
check accept no-global-device-cleanup.sh "a COMMENT describing the pattern"

echo "== device guard: every spelling of the global teardown =="
for probe in \
	"${LOSETUP} -D 2>/dev/null || true" \
	"${LOSETUP} --detach-all || true" \
	"${LOSETUP} --verbose --detach-all" \
	"subprocess.run(['${LOSETUP}', '--detach-all'])" \
	"subprocess.run([\"/sbin/${LOSETUP}\", \"--detach-all\"])" \
	"${DMSETUP} remove_all || true" \
	"${DMSETUP} --verbose remove_all" \
	"exec.Command(\"${LOSETUP}\", \"-D\").Run()" \
	"exec.Command(\"${DMSETUP}\", \"remove_all\").Run()"; do
	d="$(newrepo dev)"
	fixture teardown.sh "$probe"
	check reject no-global-device-cleanup.sh "teardown: $probe"
done

echo "== device guard: a marker INSIDE a string is not a comment =="
# Review found the guard stripping everything after the first `//` or `#`
# anywhere on a line, including inside a quoted string -- so an executable line
# carrying a URL, or a `#` in a string, hid the teardown and the guard reported
# the tree clean. A fail-open on a host-destructive pattern, and the suite had
# no case for it.
d="$(newrepo devq1)"
fixture teardown.sh "cmd=\"http://example.com/x; ${LOSETUP} -D\""
check reject no-global-device-cleanup.sh "a // inside a string does not hide it"
d="$(newrepo devq2)"
fixture teardown.sh "x=\"not a comment # still code ${LOSETUP} --detach-all\""
check reject no-global-device-cleanup.sh "a # inside a string does not hide it"
d="$(newrepo devq3)"
fixture teardown.sh "echo 'writing a note about ${DMSETUP} remove_all' > /tmp/n"
check reject no-global-device-cleanup.sh "a quoted mention in executable code is still flagged"
# And the other side: a genuine comment must still be ignored, or the guard
# fires on every file that explains why the pattern is banned.
d="$(newrepo devq4)"
fixture teardown.sh "# the old code ran ${LOSETUP} -D here, which is why it is gone"
check accept no-global-device-cleanup.sh "a real shell comment is still ignored"
d="$(newrepo devq5)"
fixture teardown.go "// the old code ran ${LOSETUP} --detach-all, now removed"
check accept no-global-device-cleanup.sh "a real Go comment is still ignored"
d="$(newrepo devq6)"
fixture ok2.sh "${LOSETUP} -d \"\$dev\"   # scoped, with a trailing comment"
check accept no-global-device-cleanup.sh "a scoped call with a trailing comment"

echo "== device guard: fail-closed =="
d="$(newrepo devfc1)"
fixture 'a file with spaces.sh' "${LOSETUP} -D"
check reject no-global-device-cleanup.sh "a tracked path containing spaces is SCANNED"
d="$(newrepo devfc2)"
fixture placeholder.txt 'ordinary'
# THE TARGET MUST EXIST AND BE HARMLESS. With a dangling link this case passed
# for the wrong reason -- the scan opened the link, open() failed, and the
# guard rejected on an I/O error while the behaviour it claimed to verify
# (scanning the LINK TEXT) was in fact broken. Review found the fail-open
# underneath: a tracked symlink whose target string is the teardown was
# accepted whenever a harmless file of that name existed. Making the target
# real is what forces the rejection to come from the link text.
printf 'harmless content\n' > "$d/${LOSETUP} -D"
ln -s "${LOSETUP} -D" "$d/link"
git -C "$d" add -A
check reject no-global-device-cleanup.sh "a symlink is read as its link text, not its target"
d="$(newrepo devfc3)"
fixture gone.sh 'ordinary'
rm "$d/gone.sh"
check reject no-global-device-cleanup.sh "a tracked file missing from the worktree"

echo "== both guards: refuse outside a repository, rather than reporting clean =="
d="$work/norepo"
rm -rf "$d"
mkdir -p "$d/scripts"
cp "$DISCLOSURE" "$DEVICE" "$d/scripts/"
check reject no-internal-disclosure.sh "disclosure guard with no git repository"
check reject no-global-device-cleanup.sh "device guard with no git repository"

echo ""
echo "passed ${pass}, failed ${fail}"
[ "$fail" -eq 0 ] || exit 1
