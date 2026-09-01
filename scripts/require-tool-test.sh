#!/bin/sh
# require-tool-test.sh — the test suite for .github/require-tool.sh's version
# comparison.
#
# WHY THIS EXISTS
#
# The comparison it tests was originally `case "$report" in *"$bare"*)` — a
# SUBSTRING test, which FAILED OPEN. A `v1.7.0` pin accepted a tool reporting
# `v11.7.0`; a `v2.29.0` pin accepted `v12.29.0`. CI would run an unintended
# scanner version and print `ok`, defeating the exact reproducibility assertion
# the check was added to make. That is a check looser than the property it
# claims — the same defect class the change it belongs to is about, appearing
# inside the fix for it.
#
# So the comparison gets its own tests, and they include the near-misses. A
# test suite for a version check that only feeds it correct versions cannot
# fail for the reason the check exists.
#
# The fakes here print the REAL output formats, captured from the actual
# binaries rather than written from memory:
#
#	golangci-lint has version 2.12.2 built with go1.26.7 from (unknown, ...
#	Version: v2.29.0
#	Go: go1.26.7 / Scanner: govulncheck@v1.7.0
#
# govulncheck's is the one that matters most: its output's FIRST version-shaped
# token is the GO TOOLCHAIN's, so a generic "find something version-shaped"
# extractor would pin the wrong number. There is a case below that would catch
# exactly that.
#
# MUTATION: run with --mutate to loosen the comparison in a COPY of
# require-tool.sh back to the original substring test and re-run everything.
# The near-miss cases must go red. If they do not, these tests are not testing
# what they claim and the suite says so instead of reporting a pass.

set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
subject="${root}/.github/require-tool.sh"
mutate=""
[ "${1:-}" = "--mutate" ] && mutate=1

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/bin"
# PATH is REPLACED, not prepended. Prepending leaves the developer's real
# gosec/golangci-lint reachable, so the "tool is absent" case finds the real
# binary and reports accept — which is how the first run of this suite failed,
# correctly. A test for absence has to be able to make the tool absent.
# `go` is needed by the subject only on the github.com branch, which these
# tests never take; the rest is coreutils.
PATH="$work/bin:/usr/bin:/bin"
export PATH
# Never the github.com branch: these tests must never reach the network.
GITHUB_SERVER_URL="http://forge.internal"
export GITHUB_SERVER_URL

if [ -n "$mutate" ]; then
	# Reinstate the substring comparison the real script replaced.
	# shellcheck disable=SC2016  # a sed script: expansion here would be the bug
	sed -e 's|^if \[ "${got#v}" != "${pin#v}" \]; then$|if ! (case "$report" in *"${pin#v}"*) true;; *) false;; esac); then|' \
		"$subject" > "$work/subject.sh"
	chmod +x "$work/subject.sh"
	subject="$work/subject.sh"
	# shellcheck disable=SC2016  # a literal pattern, not an expansion
	if ! grep -q 'case "$report" in' "$subject"; then
		echo "MUTATION DID NOT APPLY — the line it rewrites has changed." >&2
		echo "These tests cannot claim to have been verified. Fix the mutation." >&2
		exit 1
	fi
	echo "### MUTATED: comparison loosened back to a substring test"
fi

fake() { # fake <name> <stdout...>
	name="$1"
	shift
	{
		echo '#!/bin/sh'
		echo 'cat <<'"'"'EOF'"'"''
		printf '%s\n' "$@"
		echo 'EOF'
	} > "$work/bin/$name"
	chmod +x "$work/bin/$name"
}

pass=0
fail=0
expect() { # expect <accept|reject> <label> <bin> <pin> <module>
	want="$1"
	label="$2"
	shift 2
	if "$subject" "$@" >"$work/out" 2>&1; then
		got=accept
	else
		got=reject
	fi
	if [ "$got" = "$want" ]; then
		printf '  PASS  %-58s (%s)\n' "$label" "$got"
		pass=$((pass + 1))
	else
		printf '  FAIL  %-58s want %s, got %s\n' "$label" "$want" "$got"
		sed 's/^/          /' "$work/out"
		fail=$((fail + 1))
	fi
}

GCL=github.com/golangci/golangci-lint/v2/cmd/golangci-lint
GOSEC=github.com/securego/gosec/v2/cmd/gosec
GOVULN=golang.org/x/vuln/cmd/govulncheck

echo "== real output, matching pin: must ACCEPT =="
fake golangci-lint 'golangci-lint has version 2.12.2 built with go1.26.7 from (unknown, modified: ?, mod sum: "h1:x") on (unknown)'
expect accept "golangci-lint 2.12.2 vs pin v2.12.2" golangci-lint v2.12.2 "$GCL"
fake gosec 'Version: v2.29.0' 'Git tag: ' 'Build date: '
expect accept "gosec v2.29.0 vs pin v2.29.0" gosec v2.29.0 "$GOSEC"
fake govulncheck 'Go: go1.26.7' 'Scanner: govulncheck@v1.7.0' 'DB: https://vuln.go.dev'
expect accept "govulncheck v1.7.0 vs pin v1.7.0" govulncheck v1.7.0 "$GOVULN"

echo "== NEAR MISS: the substring hole. Must REJECT =="
fake govulncheck 'Go: go1.26.7' 'Scanner: govulncheck@v11.7.0' 'DB: https://vuln.go.dev'
expect reject "govulncheck v11.7.0 vs pin v1.7.0  (prefix digit)" govulncheck v1.7.0 "$GOVULN"
fake gosec 'Version: v12.29.0' 'Git tag: ' 'Build date: '
expect reject "gosec v12.29.0 vs pin v2.29.0  (prefix digit)" gosec v2.29.0 "$GOSEC"
fake golangci-lint 'golangci-lint has version 12.12.2 built with go1.26.7 from (unknown) on (unknown)'
expect reject "golangci-lint 12.12.2 vs pin v2.12.2  (prefix digit)" golangci-lint v2.12.2 "$GCL"
fake gosec 'Version: v2.29.01' 'Git tag: ' 'Build date: '
expect reject "gosec v2.29.01 vs pin v2.29.0  (suffix digit)" gosec v2.29.0 "$GOSEC"
fake gosec 'Version: v2.29.0-rc1' 'Git tag: ' 'Build date: '
expect reject "gosec v2.29.0-rc1 vs pin v2.29.0  (prerelease)" gosec v2.29.0 "$GOSEC"

echo "== the real skew that took CI down: must REJECT =="
fake golangci-lint 'golangci-lint has version 2.13.2 built with go1.26.7 from (unknown, modified: ?, mod sum: "h1:x") on (unknown)'
expect reject "golangci-lint 2.13.2 vs pin v2.12.2  (runner image bump)" golangci-lint v2.12.2 "$GCL"

echo "== the WRONG-TOKEN trap: a generic extractor would take the Go version =="
# If the pin were ever the same shape as the toolchain version in the output, a
# loose extractor matches `go1.26.7` and reports a pass for a tool that is a
# completely different version.
fake govulncheck 'Go: go1.26.7' 'Scanner: govulncheck@v1.7.0' 'DB: https://vuln.go.dev'
expect reject "govulncheck vs pin v1.26.7  (must not match 'Go: go1.26.7')" govulncheck v1.26.7 "$GOVULN"

echo "== unparseable / unreadable: must REJECT, never fall back to looser =="
fake gosec 'Version: dev' 'Git tag: ' 'Build date: '
expect reject "gosec 'dev' vs pin v2.29.0  (the original #21 defect)" gosec v2.29.0 "$GOSEC"
fake gosec 'some format nobody documented'
expect reject "gosec output with no Version: line" gosec v2.29.0 "$GOSEC"
{
	echo '#!/bin/sh'
	echo 'exit 3'
} > "$work/bin/gosec"
chmod +x "$work/bin/gosec"
expect reject "gosec refuses to report a version at all" gosec v2.29.0 "$GOSEC"
fake staticcheck 'staticcheck 2025.1.1'
expect reject "a tool with NO documented format is not verified by guessing" staticcheck 2025.1.1 honnef.co/go/tools/cmd/staticcheck

echo "== absent tool on a self-hosted runner: must REJECT, never install =="
rm -f "$work/bin/gosec"
expect reject "gosec absent (must not silently network-install)" gosec v2.29.0 "$GOSEC"

echo ""
echo "passed ${pass}, failed ${fail}"

if [ -n "$mutate" ]; then
	if [ "$fail" -eq 0 ]; then
		echo "MUTATION SURVIVED: loosening the comparison to a substring broke" >&2
		echo "NOTHING. These tests do not test the property they claim to." >&2
		exit 1
	fi
	echo "mutation killed by ${fail} case(s) — the near-miss tests are real."
	exit 0
fi

[ "$fail" -eq 0 ] || exit 1
