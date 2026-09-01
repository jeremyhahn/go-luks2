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
PATTERN='losetup[[:space:]]+-D([[:space:]]|$)|dmsetup[[:space:]]+remove_all([[:space:]]|$)|"losetup",[[:space:]]*"-D"|"dmsetup",[[:space:]]*"remove_all"'

files="$(git ls-files 2>/dev/null || true)"
if [ -z "$files" ]; then
	echo "FAIL: 'git ls-files' listed nothing, so no file was examined." >&2
	echo "An empty search is not a clean tree. Refusing to report success on" >&2
	echo "a scan that did not run." >&2
	exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
: > "$work/hits"
scanned=0

for f in $files; do
	[ -f "$f" ] || continue
	# Binary files have nothing to say here and would produce noise.
	case "$(file -b --mime-encoding "$f" 2>/dev/null || echo unknown)" in
	binary) continue ;;
	esac
	scanned=$((scanned + 1))
	# Strip comments, keep line numbers, then match.
	sed -e 's|//.*$||' -e 's|#.*$||' "$f" |
		grep -nE "$PATTERN" |
		sed "s|^|${f}:|" >> "$work/hits" || :
done

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
