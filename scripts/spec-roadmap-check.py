"""spec-roadmap-check.py v1 [DIR]: the agreement check between a project's
docs/SPEC.md and ROADMAP.md, in CI (ci-template v1.56, the Tenant Agent's
12:47Z order, 2026-11-22).

Copied into a repository as scripts/spec-roadmap-check.py; the lint job of
ci.yml runs it on every pull request and push. It reads the two files from the
checkout at DIR (default: the current directory), needs no token and no
network, and is the token-free port of the Software Department's hand-run
check. The rule is handbook roadmap.md §2a and project-spec.md §5: the
features named across ROADMAP.md's Complete, Now, Next, Later and Future
sections are exactly the features in SPEC.md's `## Features` table, each in
the section its status names:

  shipped -> Complete; in progress -> Now or Next; planned -> Later;
  future -> Future.

Prints PASS, or FAIL with one ::error line per mismatch, and exits 1 on any
mismatch or a missing file. testdata/spec-roadmap-check-tests.py holds the
cases.
"""
import os
import re
import sys

SECTIONS = {"shipped": {"Complete"}, "in progress": {"Now", "Next"}, "planned": {"Later"}, "future": {"Future"}}
ROADMAP_SECTIONS = {"Complete", "Now", "Next", "Later", "Future"}


def spec_features(text):
    feats, in_sec, in_table = {}, False, False
    for line in text.splitlines():
        if line.startswith("## "):
            in_sec, in_table = line.strip() == "## Features", False
            continue
        if not in_sec:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.lstrip().startswith("|") else None
        if cells is None:
            in_table = False
            continue
        if cells[:2] == ["Feature", "Status"]:
            in_table = True
            continue
        if in_table and not re.fullmatch(r"[-: ]*", "".join(cells)):
            feats[cells[0]] = cells[1].lower() if len(cells) > 1 else ""
    return feats


def roadmap_features(text):
    found, sec = {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            sec = line[3:].strip()
            continue
        m = re.match(r"\s*- \*\*(.+?)\*\*", line)
        if m and sec in ROADMAP_SECTIONS:
            found.setdefault(m.group(1).strip(), set()).add(sec)
    return found


def check(spec, roadmap):
    if spec is None or roadmap is None:
        return ["missing " + " and ".join(n for n, t in (("docs/SPEC.md", spec), ("ROADMAP.md", roadmap)) if t is None)]
    errs, feats, rm = [], spec_features(spec), roadmap_features(roadmap)
    if not feats:
        errs.append("SPEC.md has no `## Features` table with a `| Feature | Status |` header")
    for f, st in feats.items():
        if st not in SECTIONS:
            errs.append(f"SPEC '{f}': status '{st}' is not shipped, in progress, planned or future")
        elif f not in rm:
            errs.append(f"SPEC '{f}' ({st}) is in no ROADMAP section")
        elif rm[f] - SECTIONS[st]:
            errs.append(f"SPEC '{f}' ({st}) appears in ROADMAP {', '.join(sorted(rm[f] - SECTIONS[st]))}")
    for f in rm:
        if f not in feats:
            errs.append(f"ROADMAP names '{f}', which is not a SPEC feature")
    return errs


def read(root, path):
    p = os.path.join(root, path)
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8") as f:
        return f.read()


def main(argv):
    root = argv[0] if argv else "."
    errs = check(read(root, "docs/SPEC.md"), read(root, "ROADMAP.md"))
    if not errs:
        print("spec-roadmap-check: PASS (docs/SPEC.md and ROADMAP.md agree)")
        return 0
    print(f"spec-roadmap-check: FAIL, {len(errs)} mismatch(es)")
    for e in errs:
        print(f"::error::SPEC/ROADMAP agreement (handbook roadmap.md §2a): {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
