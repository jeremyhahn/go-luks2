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
#   if err != nil {                     REFUSES with a classified error. It
#       return fmt.Errorf("%w: ...",    does not name err, and does not need
#           ErrInvalidKeyslot, name)    to: the failure is not discarded, it is
#   }                                   replaced by one that describes the DATA
#                                       rather than the parse. Ten of the first
#                                       23 findings on this tree were this
#                                       shape (#128).
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

	# Track the body of an `if err != nil {` block: does it name err, and does
	# it REFUSE?
	#
	# Naming err is not the only way to handle a failure. A block that returns a
	# classified error has handled it -- often better than wrapping would, since
	# a domain error tells the caller what is wrong with the DATA rather than
	# what the parser thought of it:
	#
	#     if err != nil {
	#         return fmt.Errorf("%w: %s declares an area offset %q that is not
	#             a number", ErrInvalidKeyslot, name, ks.Area.Offset)
	#     }
	#
	# The original rule flagged that, and it is the opposite of a collapse.
	# MEASURED on this repository: of 23 findings across the whole tree, TEN
	# were blocks of that shape -- a 43% false-positive rate on first contact
	# with pkg/luks2.
	#
	# That is not cosmetic. The value of this guard rests on the accept side (see
	# WHAT IT ACCEPTS above): a gate that is wrong four times in ten acquires a
	# --skip flag, or has its scope quietly narrowed by the next person it
	# blocks -- which is the state #128 exists to correct. Widening the scope
	# with this predicate would have manufactured the outcome the guard exists
	# to prevent.
	# code_only(line) returns the line with any Go line comment removed, where
	# "comment" means a `//` that is OUTSIDE a string literal. Truncating at the
	# first `//` would cut `fmt.Errorf("http://%s: %w", host, err)` in half and
	# lose the classification; not stripping at all lets a TRAILING COMMENT
	# satisfy the predicate, so `return false // TODO: return ErrReadFailed`
	# reads as a classified refusal when it is the exact collapse this guard
	# exists to catch. Both directions are fail-open in a security guard.
	#
	# The sibling device-cleanup guard solves the same problem for `#` and `//`
	# with a quote-aware scanner; this is that rule in awk. Two implementations
	# of one rule is a known defect (#120 proposes a shared helper) -- recorded
	# here rather than left for the next reader to rediscover.
	function code_only(line,   i, c, n, dq, sq, bt, out, SQ) {
		SQ = sprintf("%c", 39)
		n = length(line); dq = 0; sq = 0; bt = 0; out = ""
		for (i = 1; i <= n; i++) {
			c = substr(line, i, 1)
			if (dq) {
				if (c == "\\") { i++; continue }
				if (c == "\"") { dq = 0; out = out c }
				continue
			}
			if (sq) {
				if (c == "\\") { i++; continue }
				if (c == SQ) { sq = 0; out = out c }
				continue
			}
			if (bt) {
				if (c == "`") { bt = 0; out = out c }
				continue
			}
			if (c == "\"") { dq = 1; out = out c; continue }
			if (c == SQ)    { sq = 1; out = out c; continue }
			if (c == "`")   { bt = 1; out = out c; continue }
			if (c == "/" && substr(line, i+1, 1) == "/") return out
			out = out c
		}
		return out
	}

	in_guard {
		body = body "\n" $0
		code = code_only($0)
		if (code ~ /err/) mentions = 1
		# A return of a constructed error, or of something already named like
		# one. Deliberately NOT any `return`: `return false` and a bare `return`
		# are the collapse this guard is for.
		# A constructed error anywhere in the return is a classification.
		if (code ~ /return[^\n]*(fmt\.Errorf|errors\.New|errors\.Join|&[A-Za-z]*Error\{)/) refuses = 1
		# A SENTINEL only counts when it is in the RETURN POSITION -- the
		# expression must END with it. Accepting any return that merely
		# CONTAINS an ErrX token is fail-open: "return errors.Is(err,
		# ErrBadInput)" returns a BOOL and collapses the failure, which is
		# exactly the defect this guard exists for, yet it contains the token.
		# Ending with the identifier admits "return ErrX" and "return nil,
		# ErrX" and rejects any form where the sentinel is an argument,
		# because those end with a closing parenthesis.
		if (code ~ /return[[:space:]]+([^()]*,[[:space:]]*)?([A-Za-z_][A-Za-z0-9_]*\.)?Err[A-Z][A-Za-z0-9_]*[[:space:]]*$/) refuses = 1
		bracecode = code
		n = gsub(/{/, "{", bracecode); brace += n
		n = gsub(/}/, "}", bracecode); brace -= n
		if (brace <= 0) {
			if (!mentions && !refuses) {
				printf "%s:%d: this `if err != nil` block never mentions err again; the error is discarded, not classified\n", FILENAME, start
				printf "    %s\n", guardline
				printf "    (classify it -- os.IsNotExist for genuinely-absent -- and return or collect the rest)\n"
				bad = 1
			}
			in_guard = 0
		}
		next
	}

	# ANY `if ...; err != nil {`, not just `if err := ...`.
	#
	# The original pattern required the initialiser to start with `err :=`, so
	# it could not see the commonest Go idiom of all:
	#
	#     if _, err := read(p); err != nil {
	#     if n, err := f(); err != nil {
	#
	# MEASURED: 152 such sites in pkg/ and cmd/. The guard reported ok over all
	# of them -- not because they were clean, but because it never opened the
	# block. A scanner anchored on the examples its author had in mind, which is
	# the defect this guard exists to catch, in its own start condition.
	#
	# Found by writing a self-test fixture in an idiom I had not used when I
	# wrote the pattern, which is the argument for fixtures that are not
	# derived from the implementation.
	# The START condition reads STRIPPED code too. A Go string containing
	# "; err != nil {" would otherwise open a synthetic guard block, and every
	# real collapse later in that file would be masked -- fail-open in the
	# scanner itself. Stripping for "mentions" and "refuses" but not for the
	# start was two of three sites: the same partial-enumeration defect this
	# change was written to correct.
	#
	# NOTE: no apostrophes anywhere in this awk program. It is embedded in a
	# single-quoted shell string, so one apostrophe ends the program and the
	# rest is parsed by the shell.
	{ startcode = code_only($0) }
	startcode ~ /if err != nil \{/ || startcode ~ /;[[:space:]]*err != nil \{/ {
		in_guard = 1; brace = 1; mentions = 0; refuses = 0; start = FNR; guardline = $0; body = ""
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

	cat > "$tmp/good/refuses.go" <<'GOOD3'
package good

import "fmt"

// A block that REFUSES with a classified error has handled the failure, even
// though it never names err. This is the shape that made ten of the first 23
// findings on this tree false positives (#128), and the reason the accept side
// of this guard is what decides whether it can be a gate.
func validate(raw string) error {
	if _, err := parse(raw); err != nil {
		return fmt.Errorf("%w: %q is not a number", ErrBadInput, raw)
	}
	return nil
}

// The same shape with a typed error value rather than a wrap.
func check(raw string) error {
	if _, err := parse(raw); err != nil {
		return &ParseError{Field: "size"}
	}
	return nil
}
GOOD3

	cat > "$tmp/bad/collapse.go" <<'BAD3'
package bad

// A bare `return false` on a failed check is the collapse itself: "I could not
// find out" rendered as "no". It must stay rejected, or widening the accept
// side would have turned this guard off.
func looksOK(p string) bool {
	if _, err := read(p); err != nil {
		return false
	}
	return true
}
BAD3

	cat > "$tmp/good/sentinel.go" <<'GOOD4'
package good

import "errors"

var ErrBadInput = errors.New("bad input")

// A BARE SENTINEL RETURN is a classification, not a collapse. The block does not
// mention err again because it deliberately REPLACES the low-level failure with
// a typed domain error the caller can match on with errors.Is.
//
// This fixture exists because the predicate branch that accepts it was written
// as `\bErr[A-Z]` -- and `\b` is a BACKSPACE in awk, gawk included, not a word
// boundary. The branch therefore never fired on any host, the guard flagged
// every sentinel return, and no case asserted otherwise, so nothing failed.
//
// A new ACCEPT-side rule needs an ACCEPT-side fixture: without one the rule can
// be a no-op, a typo, or a regex in the wrong dialect and every test still
// passes.
func parse(raw string) error {
	if _, err := decode(raw); err != nil {
		return ErrBadInput
	}
	return nil
}

func decode(string) (int, error) { return 0, nil }
GOOD4

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

	cat > "$tmp/bad/trailing.go" <<'BAD4'
package bad

func read(p string) bool {
	if _, err := open(p); err != nil {
		return false // TODO: return ErrReadFailed
	}
	return true
}

func open(string) (int, error) { return 0, nil }
BAD4

	cat > "$tmp/bad/quoted.go" <<'BAD5'
package bad

// A quoted guard line must not open a synthetic block. If it does, every real
// collapse later in the file is masked and the scanner reports the file clean --
// fail-open in the scanner itself, which is worse than a missed rule.
var _ = "if _, err := parse(raw); err != nil {"

func read(p string) bool {
	if _, err := open(p); err != nil {
		return false
	}
	return true
}

func open(string) (int, error) { return 0, nil }
BAD5

	cat > "$tmp/bad/sentinelarg.go" <<'BAD6'
package bad

// The body never names the failure again -- it returns a value that merely
// CONTAINS a sentinel token as an ARGUMENT. A predicate that accepts any return
// containing ErrX calls this handled; the sentinel is not what is returned, and
// the failure is discarded. The sentinel only counts in the RETURN POSITION.
func read(p string) bool {
	if _, err := open(p); err != nil {
		return classify(cached, ErrBadInput)
	}
	return true
}

func classify(int, error) bool { return false }
func open(string) (int, error) { return 0, nil }

var cached error
var ErrBadInput error
BAD6

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
	if scan "$tmp/good" 2>/dev/null | grep -q "sentinel\.go"; then
		echo "SELF-TEST FAILED: a bare sentinel return was flagged as a collapse -- the classification branch is not firing (check the awk dialect: \\b is a BACKSPACE, not a word boundary)" >&2
		return 1
	fi
	echo "  ok — a bare sentinel return is accepted as a classification"

	echo "self-test: the reject side (a discarded error, an AND, a bare return)"
	for c in skip and collapse trailing quoted sentinelarg; do
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
