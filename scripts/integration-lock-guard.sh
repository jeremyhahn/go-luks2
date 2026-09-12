#!/bin/sh
# integration-lock-guard.sh — every privileged integration entry point must take
# the shared host lock.
#
# WHY THIS EXISTS. Per-invocation container names stopped two jobs killing each
# other, and in doing so allowed two suites to run at once — against a
# HOST-GLOBAL loop-device pool of eight, where one suite holds about five. The
# lock is what keeps that safe, and a lock is only as good as its coverage: one
# unlocked entry point restores the contention completely.
#
# The invariant was broken twice while being introduced, both times the same way:
# the author enumerated by MECHANISM (`docker run`) instead of by RESOURCE (the
# device pool), so the host-side `go test -tags=integration` targets — coverage,
# host-integration-test — were missed. Enumerating by the resource is the whole
# point, and a rule that must be remembered at the right moment has already
# failed. So it is checked.
#
# WHAT IT CHECKS
#   Makefile: every recipe containing a non-comment `tags=integration`
#             invocation must contain `flock "$(ITEST_LOCK)"` in the same recipe.
#   ci.yml:   the privileged `docker run` must be preceded by a `flock` on the
#             identical lock path — a second lock path serializes nothing.
#
# Run `--self-test` to prove it can say both yes and no before trusting a pass.
set -eu
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

# ONE BOUND, ONE PLACE. The lock path was restated here as a literal while the
# Makefile declared its own at ITEST_LOCK, which is two spellings of one fact --
# the drift this repository legislates against everywhere else. It is now READ
# from the Makefile, and a guard that cannot find it FAILS rather than falling
# back to a literal: a guard checking the wrong path would report `ok` while
# serializing nothing, which is worse than not running.
LOCK_PATH="$(sed -n 's/^ITEST_LOCK[[:space:]]*?*=[[:space:]]*//p' Makefile | head -1)"
[ -n "$LOCK_PATH" ] || {
	echo "integration-lock-guard: could not read ITEST_LOCK from Makefile." >&2
	echo "Refusing to guess: a guard comparing against the wrong lock path reports" >&2
	echo "clean while serializing nothing." >&2
	exit 1
}

scan_makefile() {
	python3 - "$1" "$LOCK_PATH" <<'PY'
import re, sys
p, lock = sys.argv[1], sys.argv[2]
lines = open(p).read().split("\n")
bad = []
for i, l in enumerate(lines):
    s = l.lstrip()
    # ENUMERATE BY THE RESOURCE, NOT BY A SPELLING. Two shapes touch the
    # host-global loop-device pool: a host-side `go test -tags=integration`, and
    # ANY privileged container -- including one that runs the suite through the
    # image default entrypoint, whose command line carries no tag expression at
    # all. Keying only on "tags=integration" missed that second shape, which is
    # the same partial-enumeration defect this guard exists to prevent, in the
    # guard itself.
    # THE COMMAND IS THE UNIT, NOT THE LINE. This test used to run against the
    # single line `l`, so a `docker run` broken across continuations --
    #
    #     docker run \\
    #       --privileged \\
    #       -v /x:/y img
    #
    # -- had no line carrying BOTH tokens, matched nothing, and the guard
    # printed `ok`. That is the partial-enumeration failure this script's own
    # header says it exists to prevent, in the script itself, and it is the
    # shape someone writes as soon as the command grows past one line.
    # Measured against this guard before the fix: rc=0 for the continued form
    # and rc=1 for the identical one-line form.
    #
    # The command is assembled FIRST -- backwards to the start of the
    # continuation chain and forwards to its end -- and every test below reads
    # that text. `i` is only the anchor for reporting.
    start = i
    while start > 0 and lines[start - 1].rstrip().endswith("\\"):
        start -= 1
    end_ln = i
    while end_ln < len(lines) - 1 and lines[end_ln].rstrip().endswith("\\"):
        end_ln += 1
    command = "\n".join(lines[start:end_ln + 1])
    # Report once per command, at its first line, rather than once per line of it.
    if start != i:
        continue

    touches_pool = ("tags=integration" in command) or ("docker run" in command and "--privileged" in command)
    if not touches_pool or s.startswith("#") or "@echo" in l:
        continue
    # PER-INVOCATION, not per-recipe. A recipe with a root branch and a sudo
    # branch has TWO invocations; checking the recipe body would pass when only
    # one is locked -- which is the very N-parallel-paths defect this guard
    # exists to prevent, and it was present here until a mutation exposed it.
    #
    # An invocation is locked if `flock` appears on its own line, or on any line
    # it continues from (backslash continuation), which covers the
    # `flock ... \` + `docker run ... \` + `go test ...` shape.
    # Walk to the START of the continued command FIRST, independent of where a
    # flock appears. Stopping at the first flock found leaves the chain too short
    # to see an enclosing `docker run` -- which is how the inner-flock case slipped
    # past the first version of this check, caught by a mutation.
    chain = command
    target = lines[max([x for x in range(i, -1, -1) if re.match(r'^[a-zA-Z0-9_.-]+:', lines[x])], default=0)].split(":")[0]
    # A flock AFTER `docker run` in the same command runs INSIDE the container,
    # against the container filesystem: it serializes nothing on the host and
    # fails outright when ITEST_LOCK names a host path the container lacks.
    # Covered is not the same as correct.
    after_docker = chain.split("docker run", 1)[1] if "docker run" in chain else ""
    # strip the invocation line itself when IT is the docker line, so a flock
    # before it is not misread as being inside the container
    if "docker run" in chain and "flock" in after_docker:
        bad.append((target, i + 1, "inner"))
        continue
    # THE PATH IS THE LOCK. `"flock" in chain` accepted a flock on ANY path, so
    # `flock /tmp/other.lock go test -tags=integration ./...` passed while the
    # failure message below claimed coverage by flock "$(ITEST_LOCK)". A second
    # lock path serializes nothing -- the workflow scanner has always checked
    # the path, and the two scanners disagreeing on what "locked" means left the
    # weaker one guarding the six Makefile call sites.
    #
    # Both spellings count: the recipe may write the literal path or the
    # $(ITEST_LOCK)/${ITEST_LOCK} variable that expands to it. Accepting the
    # variable is not a hole -- LOCK_PATH is checked against the Makefile's own
    # definition at startup, so the two cannot drift apart silently.
    if "flock" not in chain:
        bad.append((target, i + 1, "unlocked"))
    elif not (lock in chain or "$(ITEST_LOCK)" in chain or "${ITEST_LOCK}" in chain):
        bad.append((target, i + 1, "wrongpath"))
for t, n, kind in bad:
    if kind == "inner":
        print("%s:%d: `%s` takes a flock INSIDE the container -- it locks the container filesystem, not the host pool" % (p, n, t))
    elif kind == "wrongpath":
        print("%s:%d: `%s` takes a flock on a DIFFERENT path than %s -- a second lock path serializes nothing" % (p, n, t, lock))
    else:
        print("%s:%d: an integration invocation in `%s` is not covered by flock \"$(ITEST_LOCK)\"" % (p, n, t))
sys.exit(1 if bad else 0)
PY
}

scan_workflow() {
	f="$1"
	[ -f "$f" ] || return 0
	# the privileged run must have a flock on the same path within the 12 lines above it
	python3 - "$f" "$LOCK_PATH" <<'PY'
import sys
f, lock = sys.argv[1], sys.argv[2]
lines = open(f).read().split("\n")
bad = []
# THE COMMAND IS THE UNIT HERE TOO. This scanner used to test the literal
# substring `docker run --privileged` against a SINGLE line, so the equally
# ordinary continued form --
#
#     docker run \\
#       --privileged \\
#       --name x img
#
# -- was never inspected, and the guard reported clean over an unlocked
# privileged container. Same fail-open class as the Makefile scanner, and it
# survived the first fix because only the Makefile half was corrected; caught
# on review of that very commit, then reproduced against this scanner with a
# positive control (one-line form rc 1, continued form rc 0).
#
# Each command is assembled from its backslash-continuation chain and both
# tokens are sought in the assembled text, so the two spellings are one case.
for i, l in enumerate(lines):
    if l.lstrip().startswith("#"):
        continue
    # Only anchor at the START of a command, so one command is reported once.
    if i > 0 and lines[i - 1].rstrip().endswith("\\"):
        continue
    end_ln = i
    while end_ln < len(lines) - 1 and lines[end_ln].rstrip().endswith("\\"):
        end_ln += 1
    command = "\n".join(lines[i:end_ln + 1])
    if "docker run" not in command or "--privileged" not in command:
        continue
    # TWO PLACES A LEGITIMATE LOCK CAN BE, and the distinction is WHERE
    # relative to `docker run`, not whether the word appears:
    #
    #   flock <path> \\                 <- same command, BEFORE docker run:
    #     docker run --privileged        locks the HOST. This is the shape
    #                                    ci.yml actually uses.
    #
    #   docker run --privileged ... flock <path> ...
    #                                 <- same command, AFTER docker run: runs
    #                                    INSIDE the container, against the
    #                                    container filesystem. Serializes
    #                                    nothing, and fails outright when the
    #                                    path is a host path the image lacks.
    #
    # Splitting on the first `docker run` is what tells them apart. Requiring
    # the lock PATH as well as the word is what stops a second lock file from
    # counting -- two paths serialize nothing against each other.
    #
    # THE LOCK MUST BE PART OF THIS COMMAND. An earlier version also accepted a
    # flock anywhere in the preceding twelve lines, inherited from the original
    # line-based implementation. Review found that fails open on a SEPARATE
    # flock that has already exited:
    #
    #     flock <path> true            <- a complete command; the lock is
    #     docker run --privileged ...     released when it returns
    #
    # The window made `locked` true while nothing held the lock for the run
    # below it. A lock is held for the lifetime of the command that takes it,
    # so proximity in the file is not evidence of coverage. This is also the
    # rule scan_makefile uses, so the two scanners now agree on what "locked"
    # means -- they disagreed once before, and the weaker one was guarding the
    # more numerous call sites.
    before_docker = command.split("docker run", 1)[0]
    if not ("flock" in before_docker and lock in before_docker):
        bad.append(i + 1)
for n in bad:
    print("%s:%d: privileged docker run is not preceded by flock %s" % (f, n, lock))
sys.exit(1 if bad else 0)
PY
}

if [ "${1:-}" = "--self-test" ]; then
	tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM
	printf 'good:\n\t@flock "$(ITEST_LOCK)" go test -tags=integration ./...\n' > "$tmp/Makefile.good"
	printf 'bad:\n\t@go test -tags=integration ./...\n' > "$tmp/Makefile.bad"
	if ! scan_makefile "$tmp/Makefile.good" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: a locked recipe was reported unlocked, so the guard would be switched off" >&2; exit 1
	fi
	echo "  ok — a locked recipe passes"
	if scan_makefile "$tmp/Makefile.bad" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: an UNLOCKED recipe passed, so the guard cannot see the defect it exists for" >&2; exit 1
	fi
	echo "  ok — an unlocked recipe is flagged"

	# THE THREE FAIL-OPEN CASES, each of which this guard PASSED before the fix
	# that added it here. All three were measured against the guard as shipped:
	# it printed `ok` and exited 0 for every one of them, while correctly
	# rejecting the equivalent single-line spelling -- so the defect was in the
	# guard's reach, not in its verdict, which is the harder kind to notice.
	#
	# A self-test that only models the shapes the author already thought of
	# certifies the author, not the guard.
	printf 'bad:\n\tdocker run \\\n\t\t--privileged \\\n\t\t-v /x:/y img\n' > "$tmp/Makefile.multiline"
	if scan_makefile "$tmp/Makefile.multiline" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: a privileged docker run split across continuations passed -- no single line carries both tokens" >&2; exit 1
	fi
	echo "  ok — an unlocked privileged run split across continuations is flagged"

	printf 'bad:\n\t@flock /tmp/some-other.lock go test -tags=integration ./...\n' > "$tmp/Makefile.wrongpath"
	if scan_makefile "$tmp/Makefile.wrongpath" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: a Makefile flock on a DIFFERENT path passed -- a second lock path serializes nothing" >&2; exit 1
	fi
	echo "  ok — a Makefile flock on a different path is flagged"

	# The POSITIVE control for the pair above. Without it, both cases would also
	# be satisfied by a scanner that had regressed to rejecting everything, and
	# a guard that always fails gets switched off just as fast as one that never
	# does. The multi-line form here is LOCKED and must pass.
	printf 'good:\n\tflock "$(ITEST_LOCK)" \\\n\t\tdocker run \\\n\t\t--privileged -v /x:/y img\n' > "$tmp/Makefile.multiline-ok"
	if ! scan_makefile "$tmp/Makefile.multiline-ok" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: a LOCKED multi-line privileged run was reported unlocked" >&2; exit 1
	fi
	echo "  ok — a locked multi-line privileged run passes"

	# The guard has TWO scanners. Self-testing only the Makefile one leaves the
	# workflow scanner unverified: if it regressed to always succeeding, this
	# self-test would stay green and an unlocked privileged CI entry point would
	# merge. One control per path the instrument claims, not one per instrument.
	mkdir -p "$tmp/wf"
	cat > "$tmp/wf/good.yml" <<'WFGOOD'
jobs:
  t:
    steps:
      - run: |
          flock /var/tmp/go-luks2-itest-loopdev.lock \
            docker run --privileged --name x img
WFGOOD
	cat > "$tmp/wf/bad.yml" <<'WFBAD'
jobs:
  t:
    steps:
      - run: |
          docker run --privileged --name x img
WFBAD
	cat > "$tmp/wf/wrongpath.yml" <<'WFWRONG'
jobs:
  t:
    steps:
      - run: |
          flock /tmp/some-other.lock \
            docker run --privileged --name x img
WFWRONG
	if ! scan_workflow "$tmp/wf/good.yml" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: a locked workflow run was reported unlocked" >&2; exit 1
	fi
	echo "  ok — a locked workflow run passes"
	if scan_workflow "$tmp/wf/bad.yml" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: an UNLOCKED privileged docker run passed the workflow scanner" >&2; exit 1
	fi
	echo "  ok — an unlocked privileged docker run is flagged"
	if scan_workflow "$tmp/wf/wrongpath.yml" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: a flock on a DIFFERENT path was accepted -- a second lock path serializes nothing" >&2; exit 1
	fi
	echo "  ok — a flock on a different path is flagged"

	# THE CONTINUATION HOLE, IN THE WORKFLOW SCANNER. The first fix for this
	# class corrected scan_makefile ONLY, and this scanner kept testing the
	# literal `docker run --privileged` against a single line -- so the
	# continued form went uninspected and the guard reported clean over an
	# unlocked privileged container. Caught on review of that commit, then
	# reproduced here against a positive control: the one-line form was
	# rejected while the identical continued form passed.
	#
	# Fixing one of two scanners and calling the class closed is exactly the
	# partial enumeration this script exists to refuse.
	cat > "$tmp/wf/split.yml" <<'WFSPLIT'
jobs:
  t:
    steps:
      - run: |
          docker run \
            --privileged \
            --name x img
WFSPLIT
	if scan_workflow "$tmp/wf/split.yml" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: a privileged docker run split across continuations passed the workflow scanner" >&2; exit 1
	fi
	echo "  ok — an unlocked privileged run split across continuations is flagged (workflow)"

	# A flock AFTER `docker run` in the same command runs INSIDE the container,
	# against the container filesystem: it serializes nothing on the host. The
	# word being present is not the test; where it sits relative to `docker run`
	# is.
	cat > "$tmp/wf/inner.yml" <<'WFINNER'
jobs:
  t:
    steps:
      - run: |
          docker run --privileged --name x img \
            flock /var/tmp/go-luks2-itest-loopdev.lock true
WFINNER
	if scan_workflow "$tmp/wf/inner.yml" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: a flock INSIDE the container was accepted as host serialization" >&2; exit 1
	fi
	echo "  ok — a flock inside the container is flagged (workflow)"

	# A SEPARATE flock that has already exited does not cover what follows it.
	# The lock is held for the lifetime of the command that takes it, so a
	# completed `flock ... true` on an earlier line is proximity, not coverage.
	cat > "$tmp/wf/stale.yml" <<'WFSTALE'
jobs:
  t:
    steps:
      - run: |
          flock /var/tmp/go-luks2-itest-loopdev.lock true
          docker run --privileged --name x img
WFSTALE
	if scan_workflow "$tmp/wf/stale.yml" >/dev/null 2>&1; then
		echo "SELF-TEST FAILED: a SEPARATE, already-exited flock was accepted as covering a later privileged run" >&2; exit 1
	fi
	echo "  ok — a separate, already-exited flock does not cover a later run (workflow)"

	echo "self-test passed: both scanners can say yes and no"
	exit 0
fi

rc=0
scan_makefile Makefile || rc=1
# EVERY WORKFLOW, not one named file. This used to scan `ci.yml` alone, so an
# unlocked privileged `docker run` in any other workflow -- a nightly, a
# release, a new one added next week -- passed unexamined. Enumerating by the
# RESOURCE means enumerating every file that can reach it, and a hard-coded
# filename cannot do that by construction.
#
# The glob is guarded: `for f in *.yml` yields the literal pattern when nothing
# matches, and scan_workflow's own `[ -f ]` test then skips it. A directory with
# no workflows is not a finding.
for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
	scan_workflow "$wf" || rc=1
done
if [ "$rc" -ne 0 ]; then
	echo ""
	echo "Every privileged integration entry point must take the SAME host lock."
	echo "Enumerate by the RESOURCE (the host-global loop-device pool), not by the"
	echo "mechanism: a host-side 'go test -tags=integration' contends for it exactly"
	echo "as a privileged 'docker run' does."
	exit 1
fi
echo "ok  every integration entry point takes the shared host lock"
