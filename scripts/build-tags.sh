#!/bin/sh
# build-tags.sh — compile this module under EVERY build-tag configuration it
# supports, with the tag list DERIVED from the tree rather than typed here.
#
#   scripts/build-tags.sh          # vet every configuration (the gate)
#   scripts/build-tags.sh --list   # print the derived tag set and stop
#
# THE INVARIANT (#43)
#
# An untagged .go file is implicitly a member of EVERY configuration, so it is
# the most constrained file in its package, not the least: it must satisfy the
# intersection of what all tag sets provide. Nothing in the Go toolchain says
# so, and the natural reading of a missing `//go:build` line is the opposite —
# that the file is unconstrained. Compiling every configuration is the only
# check that enforces it, because the constraint is a property of the
# COMBINATION and not of any file read on its own.
#
# It has already cost something here. A test file landed with no build tag
# while a helper it called fifteen times lives under `//go:build !integration`.
# `go build ./...`, `go vet ./...`, `go test -race` on both packages,
# golangci-lint, gosec, govulncheck and `go mod verify` ALL returned 0. Only
# `-tags=integration` was red, and nothing in the fast tier ran it.
#
# WHY THE LIST IS DERIVED, NOT WRITTEN DOWN
#
# A hand-written list is accurate until someone adds a tag, and then it is
# silently short: the missing configuration is not compiled, no job fails, and
# the only signal is that a reader notices. Deriving it means a third tag is
# covered the moment it appears in a `//go:build` line.
#
# Derivation: take every `//go:build` constraint in the tree, split it into
# identifiers, and subtract the ones the toolchain defines rather than this
# repository — GOOS and GOARCH values (asked of `go tool dist list`, not typed
# out), the release tags (`go1.N`), and the standard implicit terms. What is
# left is this module's own vocabulary.
#
# FAIL-CLOSED. Every step that could fail to find something treats the failure
# as a failure, never as an empty result: a tag set that could not be derived
# is not an empty tag set, and this refuses to report success on one.
#
# WHAT THIS DELIBERATELY DOES NOT DO
#
# It does not add non-linux configurations. `go vet` off linux fails inside a
# third-party dependency (github.com/anatol/devmapper.go, undefined
# unix.DM_DEV_CREATE), identically with and without every tag, so such a leg
# would carry no information about tag/symbol consistency and would be
# permanently red. The `//go:build linux` constraints in this module are
# decorative for the same reason: nothing here can satisfy their negative
# branch, since untagged production code in cmd/luks2 calls symbols defined
# only in linux-tagged files. Recorded so nobody adds the leg and then
# suppresses it.
#
# It also compiles each tag INDIVIDUALLY against the default, not the power set
# of tags. With one custom tag those are the same thing. If this module ever
# grows two tags that can be combined, that combination needs a deliberate
# decision rather than a silent expansion of this loop.

set -eu

cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

# Standard constraint terms that come from the toolchain, not from this
# repository. `unix` and `cgo` are implicit; `ignore` is the conventional
# never-build tag; `gc`/`gccgo` name the compiler; race/msan/asan are set by
# the corresponding -flags; `boringcrypto` and `purego` are toolchain-level.
IMPLICIT_TAGS="unix cgo ignore gc gccgo race msan asan boringcrypto purego"

platforms="$(go tool dist list 2>/dev/null | tr '/' '\n' | sort -u)"
if [ -z "$platforms" ]; then
	echo "FAIL: 'go tool dist list' returned nothing, so GOOS/GOARCH values" >&2
	echo "cannot be subtracted from the constraint vocabulary. Refusing to" >&2
	echo "guess: an undetermined platform list would make every platform name" >&2
	echo "look like one of this module's own build tags." >&2
	exit 1
fi

constraints="$(grep -rhE '^//go:build ' --include='*.go' . || true)"
if [ -z "$constraints" ]; then
	echo "FAIL: no //go:build lines found anywhere in the tree." >&2
	echo "This module is known to carry them, so finding none means the scan" >&2
	echo "did not work — which is not the same as there being no tags, and is" >&2
	echo "exactly the reading that would let this gate pass vacuously." >&2
	exit 1
fi

# Split constraints into bare identifiers: drop the directive, turn the
# operators into separators, then filter to the tokens that name a tag.
tags="$(
	printf '%s\n' "$constraints" |
		sed -e 's|^//go:build ||' -e 's/[()&|!]/ /g' |
		tr -s '[:space:]' '\n' |
		grep -E '^[A-Za-z_][A-Za-z0-9_.]*$' |
		grep -Ev '^go1\.[0-9]+$' |
		sort -u
)"

custom=""
for t in $tags; do
	skip=""
	for p in $platforms; do
		[ "$t" = "$p" ] && skip=1 && break
	done
	[ -n "$skip" ] && continue
	for i in $IMPLICIT_TAGS; do
		[ "$t" = "$i" ] && skip=1 && break
	done
	[ -n "$skip" ] && continue
	custom="${custom}${custom:+ }${t}"
done

if [ "${1:-}" = "--list" ]; then
	echo "derived build tags: ${custom:-<none>}"
	exit 0
fi

# The default (untagged) configuration always runs: it is the build the library
# ships and the one every other gate already covers.
echo "==> go vet ./...            (default configuration)"
go vet ./...

for t in $custom; do
	echo "==> go vet -tags=$t ./...  (derived from //go:build lines)"
	go vet "-tags=$t" ./...
done

echo "ok  compiled every supported configuration: default${custom:+, }${custom}"
