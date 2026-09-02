#!/bin/sh
# error-collapse-guard.sh — fail when an error is collapsed into a benign answer.
#
#   scripts/error-collapse-guard.sh [dir ...]
#   scripts/error-collapse-guard.sh --self-test
#
# WHY (#96)
#
# Six defects in one branch were one idea: "I could not find out" rendered as
# "it is fine". Each was found by a different reviewer on a different round,
# and five of them were written INSIDE the harness whose whole purpose is to
# know what it removed:
#
#   Finish trusted the test verdict to mean the host was clean
#   Finish declined to let a failed cleanup change the exit code
#   the reaper read another reaper's lock as "owner alive"
#   three post-removal confirmations read `err == nil && stillThere`
#   the state directory existing was taken to mean it was trustworthy
#   a sysfs read that FAILED was taken to mean "no backing file"
#
# The last one is the shape this script detects, and it is the expensive one:
# the scan returns empty, the reaper reports AlreadyGone, and the ledger --
# the only record of a device that may still be attached -- is DELETED.
#
# A pre-push grep catches instance seven. A gate catches eight through twenty,
# including the ones written by people who never read the issue. That argument
# is not hypothetical here: the #20 lane turned a one-time sweep into a gate and
# it caught three fresh violations across two rebases that the sweep would have
# missed by construction.
#
# WHAT IT REJECTS
#
#   err == nil && ...          an error swallowed by an AND: the branch is not
#                              taken when the check could not run, so the
#                              failure path silently becomes the success path.
#
#   if err != nil { ... }      where the body never mentions `err` again. Such
#                              a block has decided something about an error it
#                              does not carry, name, or classify -- a bare
#                              `continue` or `return nil` after a failed read.
#
# WHAT IT ACCEPTS, and this half is why it can be a gate rather than a rule
# people switch off:
#
#   if err != nil {                     mentions err -> classified and
#       if os.IsNotExist(err) {         propagated. ENOENT genuinely means
#           return "", false, nil       "not there"; everything else is
#       }                               returned.
#       return fmt.Errorf("...: %w", err)
#   }
#
#   if err != nil {                     mentions err -> collected, not
#       failures = append(failures,     discarded.
#           ReapFailure{Err: err})
#       continue
#   }
#
# FAIL-CLOSED: a scan that matches no files at all is a failure, not a pass. A
# guard that reports clean because it looked at nothing is the very defect it
# exists to catch, one level up.

set -eu

cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

scan() {
	target_dir=$1
	files=$(find "$target_dir" -name '*.go' ! -name '*_test.go' | sort)
	if [ -z "$files" ]; then
		echo "FAIL: no Go files under $target_dir; this guard examined nothing" >&2
		return 2
	fi

	# shellcheck disable=SC2086
	awk '
	FNR == 1 { brace = 0; in_guard = 0 }

	# A COMMENT IS A MENTION, NOT A USE. Whole-line comments are skipped
	# entirely, and the reason is not tidiness -- it is that a guard which
	# cannot tell quoting from doing punishes the one thing it should reward.
	# This rule was added because the guard flagged the COMMENT explaining why
	# a nearby line had been rewritten to satisfy it: documenting the defect
	# became indistinguishable from committing it, and the only ways out are to
	# reword the explanation until the scanner is fooled, or to switch the guard
	# off. Both teach the wrong lesson.
	#
	# Skipping is also STRICTER, not laxer, in the other direction: a comment
	# inside an `if err != nil` block that happens to contain the word "err" no
	# longer counts as the block classifying its error.
	#
	# A trailing comment after code is still scanned, which errs toward flagging.
	/^[[:space:]]*\/\// { next }

	# An error swallowed by an AND.
	/err == nil &&/ {
		printf "%s:%d: an error is swallowed by an AND; the branch is skipped when the check could not run\n", FILENAME, FNR
		printf "    %s\n", $0
		bad = 1
	}

	# Track the body of an `if err != nil {` block and whether it names err.
	in_guard {
		body = body "\n" $0
		if ($0 ~ /err/) mentions = 1
		n = gsub(/{/, "{"); brace += n
		n = gsub(/}/, "}"); brace -= n
		if (brace <= 0) {
			if (!mentions) {
				printf "%s:%d: this `if err != nil` block never mentions err again; the error is discarded, not classified\n", FILENAME, start
				printf "    %s\n", guardline
				printf "    (classify it -- os.IsNotExist for genuinely-absent -- and return or collect the rest)\n"
				bad = 1
			}
			in_guard = 0
		}
		next
	}

	/if err != nil \{/ || /if err := .*; err != nil \{/ {
		in_guard = 1; brace = 1; mentions = 0; start = FNR; guardline = $0; body = ""
		next
	}

	END { exit (bad ? 1 : 0) }
	' $files
}

self_test() {
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT

	mkdir -p "$tmp/good" "$tmp/bad"

	cat > "$tmp/good/ok.go" <<'GOOD'
package good

import (
	"fmt"
	"os"
)

func read(p string) (string, bool, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("reading %s: %w", p, err)
	}
	return string(raw), true, nil
}

func collect(paths []string) error {
	var failures []error
	for _, p := range paths {
		if _, _, err := read(p); err != nil {
			failures = append(failures, err)
			continue
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d failed", len(failures))
	}
	return nil
}
GOOD

	cat > "$tmp/good/mention.go" <<'GOOD2'
package good

// This file quotes the rejected patterns inside comments and must NOT be
// flagged: a guard that cannot tell a mention from a use makes its own defect
// impossible to document.
//
//	if err == nil && present {
//		return false
//	}
//
// and the other one:
//
//	if err != nil {
//		continue
//	}
func documented() bool {
	return true
}
GOOD2

	cat > "$tmp/bad/skip.go" <<'BAD'
package bad

import "os"

func scan(paths []string) []string {
	var found []string
	for _, p := range paths {
		_, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		found = append(found, p)
	}
	return found
}
BAD

	cat > "$tmp/bad/and.go" <<'BAD2'
package bad

func confirm(present bool, err error) bool {
	if err == nil && present {
		return false
	}
	return true
}
BAD2

	echo "self-test: the accept side (a classified, propagated error; a quoted one)"
	if ! scan "$tmp/good" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: the guard rejects correct code, so it would be switched off" >&2
		scan "$tmp/good" >&2 || true
		return 1
	fi
	echo "  ok — not flagged"
	if scan "$tmp/good" 2>/dev/null | grep -q "mention\.go"; then
		echo "SELF-TEST FAILED: the guard flagged a pattern quoted in a comment, so it cannot be documented" >&2
		return 1
	fi
	echo "  ok — a pattern quoted in a comment is not flagged"

	echo "self-test: the reject side (a discarded error, and an AND)"
	for c in skip and; do
		if scan "$tmp/bad" 2>/dev/null | grep -q "$c\.go"; then
			echo "  ok — $c.go flagged"
		else
			echo "SELF-TEST FAILED: the guard did not flag $c.go, so it cannot see the defect it exists for" >&2
			return 1
		fi
	done

	echo "self-test passed: the guard can say both yes and no"
}

if [ "${1:-}" = "--self-test" ]; then
	self_test
	exit 0
fi

# Default scope is the harness. Widening to pkg/luks2 is a separate change with
# its own findings; a guard introduced together with a hundred pre-existing
# violations is a guard that gets an exclusion list on day one.
dirs=${*:-test/harness}

status=0
for d in $dirs; do
	scan "$d" || status=$?
done

if [ "$status" -eq 2 ]; then
	exit 2
fi
if [ "$status" -ne 0 ]; then
	echo "" >&2
	echo "An error was collapsed into a benign answer. 'I could not find out' and" >&2
	echo "'it is fine' are different answers, and only the second may act." >&2
	exit 1
fi

echo "ok  no collapsed errors in: $dirs"
