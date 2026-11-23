"""spec-roadmap-check.py v1 (ci-template v1.56): the SPEC/ROADMAP agreement
check in CI, from a local checkout with no token.

The script is run as a repository runs it, `python3 -I
scripts/spec-roadmap-check.py`, in a temporary checkout:

  A0  ci.yml's lint job runs it after the masking steps, on every event.
  A1  agreement: PASS, exit 0.
  A2  in progress in Now or in Next: PASS.
  A3  a SPEC feature in no ROADMAP section: FAIL.
  A4  a feature in the wrong section: FAIL, naming the section.
  A5  a ROADMAP feature that is not in SPEC: FAIL.
  A6  an unknown status: FAIL.
  A7  no `| Feature | Status |` table: FAIL.
  A8  docs/SPEC.md or ROADMAP.md missing: FAIL, naming the file.
  A9  a table outside `## Features`, and items outside the five sections,
      are not read.
  A10 the script reads no network and no token: it imports neither.
  A11 it agrees with the Software Department's hand-run check on every
      case (the same check() body).

Run: python3 -I software/templates/github-actions/testdata/spec-roadmap-check-tests.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TPL = os.path.dirname(HERE)
SCRIPT = os.path.join(TPL, "spec-roadmap-check.py")
YML = os.path.join(TPL, "ci.yml")
FAILS = []

SPEC = """# SPEC

## Overview

| Feature | Status |
|---|---|
| Not read | bogus |

## Features

| Feature | Status | Requirements | Detail |
|---|---|---|---|
| Store | shipped | R1 | x |
| Seal | in progress | R2 | x |
| Barrier | in progress | R3 | x |
| Export | planned | R4 | x |
| Mesh | future | R5 | x |

## Requirements
"""
ROADMAP = """# ROADMAP

## Complete

- **Store** — done.

## Now

- **Seal** — #12.

## Next

- **Barrier** — #13.

## Later

- **Export** — #14.

## Future

- **Mesh** — later.

## Notes

- **Not a feature** — outside the five sections.
"""


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        FAILS.append(msg)


def run(spec, roadmap):
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "scripts"))
        shutil.copy(SCRIPT, os.path.join(tmp, "scripts", "spec-roadmap-check.py"))
        if spec is not None:
            os.makedirs(os.path.join(tmp, "docs"))
            with open(os.path.join(tmp, "docs", "SPEC.md"), "w") as f:
                f.write(spec)
        if roadmap is not None:
            with open(os.path.join(tmp, "ROADMAP.md"), "w") as f:
                f.write(roadmap)
        r = subprocess.run(["python3", "-I", "scripts/spec-roadmap-check.py"], cwd=tmp,
                           env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                           capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout + r.stderr


def lint_step():
    text = open(YML).read()
    i = text.find("\n  lint:\n")
    j = re.compile(r"\n  [a-z][\w-]*:\n").search(text, i + 1)
    job = text[i:j.start()]
    k = job.find("- name: SPEC and ROADMAP agree (roadmap.md §2a)")
    check(k > 0, "A0 the lint job has the agreement step")
    if k < 0:
        return
    nxt = job.find("- name:", k + 1)
    step = job[k:nxt if nxt > 0 else len(job)]
    check("run: python3 -I scripts/spec-roadmap-check.py" in step, "A0 the step runs scripts/spec-roadmap-check.py")
    check("if:" not in step, "A0 the step runs on every event, a docs-only pull request included")
    check(job.find("- name: Mask the LAN addresses") < k, "A0 it runs after the masking steps")


def main():
    lint_step()
    rc, out = run(SPEC, ROADMAP)
    check(rc == 0 and "PASS" in out, f"A1 agreement: PASS (rc {rc})")
    rc, out = run(SPEC, ROADMAP.replace("## Next\n\n- **Barrier** — #13.\n", "## Next\n").replace(
        "- **Seal** — #12.\n", "- **Seal** — #12.\n- **Barrier** — #13.\n"))
    check(rc == 0, f"A2 in progress in Now and in Next: PASS (rc {rc})")
    rc, out = run(SPEC, ROADMAP.replace("- **Export** — #14.\n", ""))
    check(rc == 1 and "::error::SPEC/ROADMAP agreement" in out and "'Export' (planned) is in no ROADMAP section" in out,
          f"A3 a SPEC feature in no section: FAIL (rc {rc})")
    rc, out = run(SPEC, ROADMAP.replace("- **Export** — #14.\n", "").replace("- **Store** — done.\n",
                                                                           "- **Store** — done.\n- **Export** — #14.\n"))
    check(rc == 1 and "'Export' (planned) appears in ROADMAP Complete" in out, f"A4 the wrong section: FAIL (rc {rc})")
    rc, out = run(SPEC, ROADMAP + "\n## Later\n\n- **Ghost** — x.\n")
    check(rc == 1 and "ROADMAP names 'Ghost', which is not a SPEC feature" in out, f"A5 a ROADMAP-only feature: FAIL (rc {rc})")
    rc, out = run(SPEC.replace("| Mesh | future |", "| Mesh | someday |"), ROADMAP)
    check(rc == 1 and "status 'someday'" in out, f"A6 an unknown status: FAIL (rc {rc})")
    rc, out = run(SPEC.replace("| Feature | Status | Requirements | Detail |", "| Name | State | Requirements | Detail |"), ROADMAP)
    check(rc == 1 and "no `## Features` table" in out, f"A7 no Feature/Status table: FAIL (rc {rc})")
    rc, out = run(None, ROADMAP)
    check(rc == 1 and "missing docs/SPEC.md" in out, f"A8 no docs/SPEC.md: FAIL (rc {rc})")
    rc, out = run(SPEC, None)
    check(rc == 1 and "missing ROADMAP.md" in out, f"A8 no ROADMAP.md: FAIL (rc {rc})")
    rc, out = run(SPEC, ROADMAP)
    check(rc == 0 and "Not read" not in out and "Not a feature" not in out,
          f"A9 other tables and sections are not read (rc {rc})")
    src = open(SCRIPT).read()
    check(not re.search(r"^\s*(import|from)\s+.*\b(urllib|http|socket|requests|forgeapi|subprocess)\b", src, re.M)
          and "TOKEN" not in src, "A10 no network, no subprocess, no token")
    hand = os.environ.get("SPEC_ROADMAP_HAND_CHECK", "")
    if hand and os.path.isfile(hand):
        def body(p):
            t = open(p).read()
            return t[t.index("def spec_features"):t.index("\n\n\ndef ", t.index("def check("))]
        check(body(hand) == body(SCRIPT), "A11 the check body matches the hand-run script")
    else:
        print("skip A11 (set SPEC_ROADMAP_HAND_CHECK to the hand-run script to compare)")
    print(f"{'ALL PASS' if not FAILS else f'{len(FAILS)} FAILED'}")
    sys.exit(1 if FAILS else 0)


main()
