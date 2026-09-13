#!/usr/bin/env bash
# dm-scope-guard-test.sh -- exercise the entrypoint's device-mapper guard.
#
# The guard lives in test/integration/Dockerfile, which builds /entrypoint.sh
# from a run of `echo` lines. That shape cannot be unit tested in place, and the
# guard it carries is the thing that decides whether the integration suite runs
# at all -- so it has been wrong twice: once refusing every LVM-root runner
# (#162), once refusing any host where a CONCURRENT run held a mapping (#178).
#
# So this reconstructs the entrypoint exactly as the image builds it, extracts
# the guard's decision, and drives it over the cases both defects were. It
# asserts the guard can say NO as well as YES: a guard that only ever proceeds
# would pass a test that checked proceeding alone.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="$root/test/integration/Dockerfile"
[ -f "$dockerfile" ] || { echo "no $dockerfile" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# FIRST: the Dockerfile's own RUN chain must be valid shell.
#
# This is a separate check from parsing the reconstructed entrypoint below, and
# it catches a class that one cannot. The entrypoint is built by a chain of
# `echo '...' >> /entrypoint.sh` commands, so an APOSTROPHE in any of those
# single-quoted payloads closes the quote early and breaks the RUN itself -- the
# image fails to build and /entrypoint.sh is never written, so there is nothing
# for a reconstruction to parse.
#
# Measured: "a sibling run's own mapping" in one comment line failed
# `docker build` with exit code 2 while the reconstructed entrypoint still passed
# `bash -n`, because the reconstruction only sees lines its regex matched and an
# unterminated quote simply drops out of it. That is why the comments in that
# block spell it "a runners own root".
# A precise diagnosis first, because dash reports the CONSEQUENCE: an
# unterminated quote shifts everything after it, so the error lands on whatever
# line happens to contain the next unquoted metacharacter -- 95, for a quote
# opened at 189 -- and names a line that is perfectly fine.
if ! python3 - "$dockerfile" <<'QUOTECHECK'
import sys
bad = [
	(n, line.rstrip())
	for n, line in enumerate(open(sys.argv[1]), 1)
	if "/entrypoint.sh" in line and line.count("'") % 2
]
if bad:
	print("FAIL: unbalanced single quotes in the entrypoint build:", file=sys.stderr)
	for n, line in bad:
		print("  %s: %s" % (n, line.strip()[:120]), file=sys.stderr)
	print("      An apostrophe inside a single-quoted echo payload closes the", file=sys.stderr)
	print("      quote early. Write it without one -- 'a runners own root'.", file=sys.stderr)
	sys.exit(1)
QUOTECHECK
then
	exit 1
fi

run_chain="$work/runchain.sh"
python3 "$root/scripts/extract-entrypoint-run.py" "$dockerfile" > "$run_chain"
if ! sh -n "$run_chain"; then
	echo "FAIL: the Dockerfile RUN chain that builds /entrypoint.sh is not valid shell." >&2
	echo "      The usual cause is an apostrophe inside one of the single-quoted" >&2
	echo "      echo payloads, which closes the quote early: docker build fails and" >&2
	echo "      the entrypoint is never written." >&2
	exit 1
fi

# Rebuild /entrypoint.sh from the Dockerfile's echo lines, the same way docker
# build does, so this tests the shipped text rather than a copy of it.
python3 - "$dockerfile" > "$work/entrypoint.sh" <<'PY'
import re, sys
out = []
for line in open(sys.argv[1]):
    m = re.match(r"\s*echo '(.*)' > /entrypoint\.sh", line)
    if m:
        out.append(m.group(1)); continue
    m = re.match(r"\s*echo '(.*)' >> /entrypoint\.sh", line)
    if m:
        out.append(m.group(1)); continue
    m = re.match(r'\s*echo "(.*)" >> /entrypoint\.sh', line)
    if m:
        out.append(m.group(1)); continue
print('\n'.join(out))
PY

# The reconstruction is worthless if it did not actually capture the guard.
for needle in 'itest_scope' 'REFUSING TO RUN' 'dmsetup ls'; do
	grep -q "$needle" "$work/entrypoint.sh" || {
		echo "FAIL: reconstructed entrypoint has no '$needle'; the Dockerfile's" >&2
		echo "      build shape changed and this test is no longer reading the guard." >&2
		exit 1
	}
done

bash -n "$work/entrypoint.sh" || { echo "FAIL: the entrypoint the image builds is not valid bash" >&2; exit 1; }

# The guard's decision, lifted verbatim from the reconstructed entrypoint so the
# cases below run the shipped logic.
sed -n '/^case "${dm_inventory}" in$/,/^esac$/p' "$work/entrypoint.sh" > "$work/decision.sh"
grep -q 'itest_scope' "$work/decision.sh" || {
	echo "FAIL: the guard's case statement no longer tests itest_scope, so it is" >&2
	echo "      not scoped to this container any more." >&2
	exit 1
}

cat > "$work/run.sh" <<'RUNNER'
#!/bin/bash
itest_scope="$1"; dm_inventory="$2"
source "$3"
echo PROCEED
RUNNER
chmod +x "$work/run.sh"

fail=0
check() { # check <want: proceed|refuse> <description> <scope> <inventory>
	local want="$1" desc="$2" scope="$3" inv="$4" out rc
	set +e
	out="$("$work/run.sh" "$scope" "$inv" "$work/decision.sh" 2>&1)"; rc=$?
	set -e
	if [ "$want" = proceed ] && { [ $rc -ne 0 ] || ! grep -q PROCEED <<<"$out"; }; then
		echo "FAIL ($desc): expected the run to proceed, got rc=$rc" >&2
		echo "$out" | sed 's/^/      /' >&2
		fail=1; return
	fi
	if [ "$want" = refuse ] && { [ $rc -eq 0 ] || ! grep -q 'REFUSING TO RUN' <<<"$out"; }; then
		echo "FAIL ($desc): expected a refusal, got rc=$rc" >&2
		echo "$out" | sed 's/^/      /' >&2
		fail=1; return
	fi
	echo "  ok -- $desc"
}

printf '\t%s\n' "--- the guard must PROCEED on what cannot collide"
check proceed "a concurrent run's own run-scoped mapping (#178)" \
	"abc123" "luks-multifile-def456-7071-dldmvo78hv64	(252:1)"
check proceed "the runner's own LVM root (#162)" \
	"abc123" "ubuntu--vg-ubuntu--lv	(252:0)"
check proceed "an empty device-mapper" "abc123" "No devices found"
check proceed "an unrelated host mapping" "abc123" "nvme0n1p3_crypt	(252:0)"
check proceed "a sibling plus the LVM root together" "abc123" "ubuntu--vg-ubuntu--lv	(252:0)
luks-x-zzz999-1-aaa	(252:1)"

printf '\t%s\n' "--- the guard must REFUSE on what this run could collide with"
check refuse "a mapping carrying this container's scope" \
	"abc123" "luks-multifile-abc123-7071-dldmvo78hv64	(252:1)"
check refuse "this container's scope among unrelated mappings" \
	"abc123" "ubuntu--vg-ubuntu--lv	(252:0)
luks-x-zzz999-1-aaa	(252:1)
test-keyring-abc123-9-bbb	(252:2)"

[ $fail -eq 0 ] || { echo "dm scope guard: FAILED" >&2; exit 1; }
echo "ok  the dm guard proceeds on other runs and refuses on its own scope"
