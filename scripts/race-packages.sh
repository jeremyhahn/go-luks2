#!/bin/sh
# race-packages.sh — fail when the packages CI race-checks are not all the
# packages there are.
#
#   scripts/race-packages.sh ./pkg/luks2 ./cmd/luks2
#
# WHY (#34)
#
# The race legs in .github/workflows/ci.yml and in the Makefile NAME their
# packages rather than deriving them. Today the enumeration is complete, so
# nothing is wrong — and that is precisely the moment to install the check,
# because the failure it prevents is silent. The day someone adds a third
# package, CI races two of three: no job fails, no warning appears, the legs
# just quietly stop covering the module, and the only signal is that a reader
# notices the list is short.
#
# That is the shape a sibling repository spent six review rounds under — a
# local race check covering two packages while its ledger claimed "CI's race
# shape", which hid a genuine data race until an unrelated merge candidate went
# red. THE OVERCLAIM IS WHAT KEPT IT HIDDEN. Here the enumeration is accurate,
# so there is no overclaim yet, only the mechanism for one.
#
# The enumeration is kept, rather than replaced with `./...`, because each leg
# writes its own coverage profile and the two are reported separately. Keeping
# the list and asserting it is the other branch of the issue's acceptance, and
# it fails LOUDLY at the moment of divergence instead of silently narrowing.
#
# FAIL-CLOSED: an empty `go list` is treated as a failure, not as "no packages
# to check". A list you could not obtain is not evidence of an empty module,
# and a check that passes when it cannot see anything is not a check.

set -eu

cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

if [ "$#" -eq 0 ]; then
	echo "usage: race-packages.sh <pkg> [pkg...]" >&2
	echo "Pass the exact package list the race legs run, so this can assert" >&2
	echo "it against what the module actually contains." >&2
	exit 1
fi

# The DEFAULT tag set, deliberately: this asserts the completeness of the legs
# as they are actually run. The tag dimension is a separate property, covered
# by scripts/build-tags.sh, and conflating the two would make this check report
# on something nobody runs. See the coverage statement in README.md.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

go list ./... > "$work/actual.raw" 2>/dev/null || :
sort "$work/actual.raw" > "$work/actual"
if [ ! -s "$work/actual" ]; then
	echo "FAIL: 'go list ./...' returned nothing." >&2
	echo "Refusing to report a complete race enumeration against a package" >&2
	echo "list that could not be obtained: an unanswered question is not an" >&2
	echo "empty module, and passing here would be the exact silent-narrowing" >&2
	echo "failure this check exists to prevent." >&2
	exit 1
fi

module="$(go list -m 2>/dev/null || :)"
if [ -z "$module" ]; then
	echo "FAIL: could not determine the module path with 'go list -m'." >&2
	exit 1
fi

# Normalise the arguments (./pkg/luks2) to full package paths so the two sides
# are comparable.
: > "$work/declared.raw"
for p in "$@"; do
	rel="${p#./}"
	printf '%s/%s\n' "$module" "$rel" >> "$work/declared.raw"
done
sort -u "$work/declared.raw" > "$work/declared"

rc=0
comm -23 "$work/actual" "$work/declared" > "$work/missing"
comm -13 "$work/actual" "$work/declared" > "$work/extra"

if [ -s "$work/missing" ]; then
	echo "FAIL: these packages exist but are NOT race-checked:" >&2
	sed 's/^/  /' "$work/missing" >&2
	rc=1
fi
if [ -s "$work/extra" ]; then
	echo "FAIL: these packages are named by a race leg but do not exist:" >&2
	sed 's/^/  /' "$work/extra" >&2
	rc=1
fi
if [ "$rc" -ne 0 ]; then
	echo "" >&2
	echo "Update the race legs in .github/workflows/ci.yml and the Makefile" >&2
	echo "test-unit target, and update the coverage statement in README.md" >&2
	echo "(Testing section) so it keeps describing what is actually run." >&2
	exit 1
fi

echo "ok  race legs cover every package under the default tag set:"
sed 's/^/  /' "$work/actual"
