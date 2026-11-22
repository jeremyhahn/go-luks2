# Runner labels (ruling 633): the checker preflight's step `Runner labels
# (ruling 633)` in .github/workflows/ci.yml runs as
# `python3 -I .github/scripts/runner_labels.py` from the repository root. It
# reads every file under .github/workflows; its rules are in that step's
# comment. The step `Runner labels self-test` runs this file on every fixture
# test/ci/workflows/testdata/runnerlabels/manifest.txt lists. It lives
# here, out of ci.yml's run block, and carries the v1.51/v1.52
# logic: the `pull_request_target` HOSTED_CTX entries, the preflight
# `RO_ALLOW` fork clause, and the `not fork` guard on the overflow and unset
# exemptions.
import json, os, re, sys

# Resume 16: the line reader is the gate on its own. It reads a strict
# subset of YAML, the forms this repository's workflows use: one
# document (one optional opening `---`), a block mapping at column 0,
# block mappings and block sequences indented with spaces, plain,
# single-quoted or escape-free double-quoted scalars, one-line flow
# sequences of scalars, and `|`/`>` block scalars (no indentation
# indicator) except for runs-on. Anything else anywhere in the file
# fails closed (s): a tab, a `?` key, an anchor, alias or tag, a `<<`
# merge key, a flow mapping, a nested or multi-line flow sequence, a
# `\` in a double-quoted scalar, a key outside printable ASCII, a
# block-scalar runs-on, a second document. PyYAML, where installed,
# cross-checks (y); both must accept.

# Reads each file under .github/workflows as text (no YAML library): the
# top-level `on:` keys, and each job's `runs-on` and `if`. A job names
# `release` when that label appears in its runs-on, plain, in a list or as a
# quoted string in an expression. Its `if` passes only in the allow-listed
# form (ALLOWED, release_terms): no value is sampled or evaluated, so a
# condition built any other way (format(), case, ||) fails closed.
U = object()  # unknown value
OPEN = "$" "{{"  # split, so the runner does not read it as an expression
ALLOWED = ("a tag push: an `if:` whose top-level `&&` terms include `github.event_name == 'push'` and one of "
           "`startsWith(github.ref, 'refs/tags/')` or `github.ref_type == 'tag'`, with no top-level `||` or `!` "
           "(other terms only narrow it; branch and dispatch conditions are refused)")
PR = {"pull_request", "pull_request_target"}


def ctx_get(ev, ref, path, head="feature", base="main"):
    p = path.lower()
    name = ref.split("/", 2)[-1]
    known = {"github.event_name": ev, "github.ref": ref, "github.event.ref": ref,
             "github.ref_name": name,
             "github.ref_type": "tag" if ref.startswith("refs/tags/") else "branch",
             "github.head_ref": head if ev in PR else "",
             "github.base_ref": base if ev in PR else ""}
    if p in known:
        return known[p]
    if ev not in PR and (p == "github.event.pull_request" or p.startswith("github.event.pull_request.")):
        return None
    return U


def release_terms(toks):
    # The condition's top-level `&&` terms, each a token list (lex drops
    # whitespace and unquotes strings). A top-level `||` or `!` can widen
    # it, so it is refused, as are unbalanced brackets and empty terms.
    terms, cur, depth = [], [], 0
    for k, v in toks:
        if k == "op" and v in ("(", "["):
            depth += 1
        elif k == "op" and v in (")", "]"):
            depth -= 1
            if depth < 0:
                raise ValueError(f"an unbalanced {v!r}")
        elif k == "op" and depth == 0 and v in ("||", "!"):
            raise ValueError(f"a top-level {v}, which can widen it")
        elif k == "op" and depth == 0 and v == "&&":
            terms.append(cur)
            cur = []
            continue
        cur.append((k, v))
    terms.append(cur)
    if depth or not all(terms):
        raise ValueError("unbalanced brackets or an empty `&&` term")
    return terms


TOK = re.compile(r"\s*(?:(?P<s>'(?:[^']|'')*')|(?P<n>-?\d+(?:\.\d+)?)|(?P<op>&&|\|\||==|!=|<=|>=|[!<>()\[\],.])|(?P<id>[A-Za-z_][\w-]*|\*))")


def lex(s):
    out, i = [], 0
    while i < len(s):
        if s[i:].strip() == "":
            break
        m = TOK.match(s, i)
        if not m:
            raise ValueError(f"cannot read the expression at {s[i:i+20]!r}")
        i = m.end()
        if m.group("s"):
            out.append(("s", m.group("s")[1:-1].replace("''", "'")))
        elif m.group("n"):
            out.append(("v", float(m.group("n"))))
        elif m.group("op"):
            out.append(("op", m.group("op")))
        else:
            out.append(("id", m.group("id")))
    return out


# The allow-listed release terms, compared token by token (whitespace and
# quoting aside): the event, and a tag ref in one of two forms.
ALLOW_EVENT = lex("github.event_name == 'push'")
ALLOW_TAG = [lex("startsWith(github.ref, 'refs/tags/')"), lex("github.ref_type == 'tag'")]


def truthy(v):
    if v is U:
        return U
    if isinstance(v, float) and v != v:
        return False
    return v not in (None, False, 0, "", 0.0)


def num(v):
    if v is None or v is False:
        return 0.0
    if v is True:
        return 1.0
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip() or 0)
        except ValueError:
            return float("nan")
    return float("nan")


def eq(a, b):
    if a is U or b is U:
        return U
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    if type(a) is type(b) and not isinstance(a, (int, float)):
        return a == b
    return num(a) == num(b)


class P:
    def __init__(self, toks, get):
        self.t, self.i, self.get = toks, 0, get

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, want=None):
        k, v = self.peek()
        if want is not None and v != want:
            raise ValueError(f"expected {want!r}, found {v!r}")
        self.i += 1
        return k, v

    def parse(self):
        v = self.orx()
        if self.i != len(self.t):
            raise ValueError(f"unexpected {self.peek()[1]!r}")
        return v

    def orx(self):
        a = self.andx()
        while self.peek() == ("op", "||"):
            self.take()
            b = self.andx()
            ta = truthy(a)
            if ta is True:
                pass
            elif ta is False:
                a = b
            else:
                # GitHub returns the left operand whenever it is
                # truthy: an unknown one may be the value, so the
                # result is {unknown, b}, which is unknown.
                a = U
        return a

    def andx(self):
        a = self.cmp()
        while self.peek() == ("op", "&&"):
            self.take()
            b = self.cmp()
            ta = truthy(a)
            if ta is False:
                pass
            elif ta is True:
                a = b
            else:
                a = b if truthy(b) is False else U
        return a

    def cmp(self):
        a = self.unary()
        while self.peek()[0] == "op" and self.peek()[1] in ("==", "!=", "<", "<=", ">", ">="):
            op = self.take()[1]
            b = self.unary()
            if op == "==":
                a = eq(a, b)
            elif op == "!=":
                r = eq(a, b)
                a = U if r is U else not r
            elif a is U or b is U:
                a = U
            else:
                x, y = (a.lower(), b.lower()) if isinstance(a, str) and isinstance(b, str) else (num(a), num(b))
                a = {"<": x < y, "<=": x <= y, ">": x > y, ">=": x >= y}[op]
        return a

    def unary(self):
        if self.peek() == ("op", "!"):
            self.take()
            t = truthy(self.unary())
            return U if t is U else not t
        return self.primary()

    def primary(self):
        k, v = self.take()
        if k == "s" or k == "v":
            return v
        if (k, v) == ("op", "("):
            r = self.orx()
            self.take(")")
            return r
        if k != "id":
            raise ValueError(f"unexpected {v!r}")
        lv = v.lower()
        if lv in ("true", "false"):
            return lv == "true"
        if lv == "null":
            return None
        if self.peek() == ("op", "("):
            self.take()
            args = []
            if self.peek() != ("op", ")"):
                args.append(self.orx())
                while self.peek() == ("op", ","):
                    self.take()
                    args.append(self.orx())
            self.take(")")
            return self.call(lv, args)
        path, exact = v, True
        while self.peek() in (("op", "."), ("op", "[")):
            if self.take()[1] == ".":
                k2, v2 = self.take()
                if k2 != "id":
                    raise ValueError(f"unexpected {v2!r} after '.'")
                path += "." + v2
                exact = exact and v2 != "*"
            else:
                idx = self.orx()
                self.take("]")
                if isinstance(idx, str):
                    path += "." + idx
                else:
                    exact = False
        return self.get(path) if exact else U

    def call(self, f, a):
        if f == "always":
            return True
        if f in ("startswith", "endswith", "contains") and len(a) == 2:
            if U in a:
                return U
            if f == "contains" and isinstance(a[0], list):
                return any(eq(x, a[1]) is True for x in a[0])
            x, y = (str(s).lower() if s is not None else "" for s in a)
            return x.startswith(y) if f == "startswith" else x.endswith(y) if f == "endswith" else y in x
        if f == "fromjson" and len(a) == 1 and isinstance(a[0], str):
            try:
                return json.loads(a[0])
            except ValueError:
                return U
        if f == "format" and a and U not in a and isinstance(a[0], str):
            return re.sub(r"\{(\d+)\}", lambda m: str(a[int(m.group(1)) + 1]) if int(m.group(1)) + 1 < len(a) else m.group(0), a[0])
        return U  # success(), failure(), hashFiles(), ...: unknown


def unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] == "'":
        return s[1:-1].replace("''", "'")
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return json.loads(s)
    return s


def scan(s):
    # (s before a ` #` outside quotes, the quote still open at its end or None).
    # A '' escape closes and reopens a '...'; a \ escapes in a "...".
    q, i = None, 0
    while i < len(s):
        c = s[i]
        if q == '"' and c == "\\":
            i += 2
            continue
        if q:
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip(), None
        i += 1
    return s.rstrip(), q


def strip_comment(s):
    return scan(s)[0]


def ind(line):
    return len(line) - len(line.lstrip(" "))


def value_lines(lines, i):
    # Resume 21: the indices of the non-blank lines in the value of the key on
    # line i, comment lines too. Blank and comment lines are skipped before
    # the indentation test, so a comment never ends a value: a comment at or
    # left of the key's column belongs to it only when a value line follows
    # (a trailing one does not). After a plain key with no inline value, `- `
    # lines at the key's own column are its block list (YAML's compact
    # sequence), read as if indented.
    base, out, low = ind(lines[i]), [], []
    head = strip_comment(lines[i]).strip()
    compact = head.endswith(":") and not head.startswith("-")
    for j in range(i + 1, len(lines)):
        s = lines[j]
        if not s.strip():
            continue
        if s.lstrip().startswith("#"):
            (out if ind(s) > base else low).append(j)
            continue
        if ind(s) > base or (compact and ind(s) == base and re.match(r"-(?:[ \t]|$)", s.lstrip(" "))):
            out += low + [j]
            low = []
            continue
        break
    return sorted(out)


def body(lines, i, inline):
    """The value text of the key on line i: the inline part plus every value line (value_lines)."""
    parts = [strip_comment(lines[j]).strip() for j in value_lines(lines, i)
             if not lines[j].lstrip().startswith("#")]
    inline = strip_comment(inline).strip()
    if inline[:1] in ("|", ">"):
        return (" " if inline[0] == ">" else "\n").join(parts)
    return " ".join([inline] + parts).strip()


def deeper(lines, i):
    """The non-blank lines in the value of line i (value_lines), comment lines too."""
    return [lines[j] for j in value_lines(lines, i)]


MULTI = object()  # a value that is a block scalar or spans lines


def one_line(lines, i, inline):
    # A release job's `if:` (fails closed): the YAML scalar on line i alone,
    # its comment cut as YAML cuts it, or MULTI. A quoted scalar ends at its
    # closing quote ('' or \ escapes); a plain one at its first ` #`.
    v = inline.strip()
    if deeper(lines, i) or not v or v[0] in "|>":
        return MULTI
    if v[0] in "*&!":
        raise ValueError("it starts with a YAML alias, anchor or tag")
    if v[0] not in "'\"":
        m = re.search(r"(?:^|[ \t])#", v)
        return v[:m.start()].rstrip() if m else v
    k = 1
    while k < len(v):
        if v[0] == '"' and v[k] == "\\":
            k += 2
        elif v[k] == v[0] and v[0] == "'" and v[k + 1:k + 2] == "'":
            k += 2
        elif v[k] == v[0]:
            break
        else:
            k += 1
    if k >= len(v):
        raise ValueError("its quoted string is not closed on its line")
    if v[k + 1:].strip() and not re.match(r"[ \t]+#", v[k + 1:]):
        raise ValueError("text follows its quoted string")
    return v[:k + 1]


RO_MAP = re.compile(r"""['"]?(?:group|labels)['"]?[ \t]*:|.*?(?:^|[\s{,])['"]?labels['"]?[ \t]*:""")
RO_KEY = re.compile(r"""(?:^|[\s{,])['"]?[\w-]+['"]?[ \t]*:(?:[ \t]|$)""")


def ro_mapping(t):
    # Resume 20: a mapping runs-on (the text body() joins, one line) is one
    # `labels:` key; its value is read as a runs-on value is (a label, a flow
    # list, or a block list, which body() joins to `- a - b`). A block scalar,
    # `group:`, another key or no value raises (fails closed). No pattern
    # here crosses a line or a list item. Any other text is returned as is.
    if not RO_MAP.match(t):
        return t
    m = re.fullmatch(r"labels:[ \t]+([^\n]+)", t)
    v = m.group(1).strip() if m else ""
    if not v or v[:1] in "|>" or (OPEN not in v and RO_KEY.search(v)):
        raise ValueError(f"is a mapping that is not one `labels:` key holding a label, a flow list or a block list of one-line "
                         f"labels (a block scalar, `group:`, another key or no value): {t[:60]!r}")
    return v


def bad_label(t):
    # Resume 22: the first label item of a literal runs-on (no expression)
    # that is empty (a null `-` item, `''`, `[a, , b]`) or has leading or
    # trailing whitespace inside its quotes, or None. Nothing is trimmed.
    if OPEN in t:
        return None
    if t.startswith("["):
        items = re.split(r"\s*,\s*", t.strip("[] "))
        if items and not items[-1].strip() and len(items) > 1:
            items.pop()  # `[a, b,]`: YAML's trailing comma
        if items == [""]:
            return None  # `[]`: no item (the waiver refuses it)
    elif t == "-" or t[:2] in ("- ", "-\t"):
        items = re.split(r"\s*-\s+", " " + t + " ")[1:]
    else:
        items = [t]
    for x in items:
        try:
            u = unquote(x)
        except ValueError:
            continue  # an escape it cannot read: the waiver check refuses it
        if not u or u != u.strip():
            return x
    return None


def runs_on_form(lines, i, inline, ro):
    # Why a runs-on value is not in a form the check reads, or None. Fails
    # closed: a block scalar, a quoted string that spans lines (its comment
    # lines would hide text), or a YAML alias (its value is elsewhere).
    if strip_comment(inline).strip()[:1] in ("|", ">"):
        return "is a block scalar"
    # Resume 20: a non-ASCII character (`ſ` case-folds to `s`) and a
    # `labels:` value the reader cannot read exactly fail closed (a `group:`
    # has its own finding below).
    if any(ord(c) > 0x7E or (ord(c) < 0x20 and c not in "\t\n") for c in ro):
        return "has a character outside printable ASCII, which GitHub may case-fold to another label"
    # Resume 21: no value (YAML reads null) is no label to check or waive,
    # and a `Labels:`/`Group:` key, which YAML reads as another key, fails
    # as the runs-on/if/uses case variants do.
    if not ro.strip():
        return "has no value (YAML reads null), so it names no label the check can read"
    for m in re.finditer(r"""(?:^|[\s{,])['"]?(group|labels)['"]?[ \t]*:""", ro, re.I):
        if m.group(1) != m.group(1).lower():
            return f"has a `{m.group(1)}:` key, which differs from `{m.group(1).lower()}:` only in case"
    try:
        if not GROUP.search(ro):
            x = bad_label(ro_mapping(ro.strip()))
            if x is not None:
                return (f"has a label that is empty, null or padded with whitespace ({x!r}); GitHub may trim "
                        f"or drop it, so the label read is not the label run, and the check fails closed")
    except ValueError as e:
        return str(e)
    for s in [inline] + [x for x in deeper(lines, i) if not x.lstrip().startswith("#")]:
        if scan(s)[1]:
            return "has a quoted string that spans lines"
    if re.search(r"(?:^|[\s\[,{:])\*[^\s,\]}]", ro):
        return "is a YAML alias"
    # Resume 14: an anchor, tag or alias at the start of the value or of
    # a list item (`&a "rel\x65ase"`, `!!str ...`, `! ...`) hides the
    # label from the text; refused here and read by the YAML layer below.
    if (re.match(r"\s*[&!*]", ro) or re.search(r"(?:^|\s)-\s+[&!*]", ro)
            or (ro.lstrip()[:1] in ("[", "{") and re.search(r"[\[{,:]\s*[&!*]", ro))):
        return "starts a value or list item with a YAML anchor, tag or alias (`&`, `!`, `*`)"
    return None


def keys_under(lines, i):
    """(line, key) for each direct child key of the block opened on line i."""
    base, out, child = ind(lines[i]), [], None
    for j in range(i + 1, len(lines)):
        s = lines[j]
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        if ind(s) <= base:
            break
        child = ind(s) if child is None else child
        if ind(s) == child:
            m = re.match(r"\s*(?:-\s+)?(['\"]?)([^'\":#]+)\1\s*(?::\s*(.*))?$", s)
            if m:
                out.append((j, m.group(2).strip(), m.group(3) or ""))
    return out


def triggers(lines):
    for i, s in enumerate(lines):
        m = re.match(r"(['\"]?)(on|true)\1\s*:\s*(.*)$", s)
        if m:
            v = strip_comment(m.group(3)).strip()
            if v.startswith("{"):  # a flow mapping: its keys, nested ones too
                return set(re.findall(r"([A-Za-z_]+)['\"]?\s*:", v))
            if v:
                return {unquote(x) for x in re.split(r"[\s,\[\]]+", v) if x}
            return {k for _, k, _ in keys_under(lines, i)}
    return set()


# v1.43 (ruling 833): the standard GitHub-hosted images, free on a public
# repository; a larger runner (cores, large, xlarge, gpu) bills even there.
STANDARD = re.compile(r"(ubuntu-(latest|24\.04|22\.04)(-arm)?|ubuntu-slim)")
LARGER = re.compile(r"(cores|xlarge|large|gpu)", re.I)
WAIVER = re.compile(r"#\s*self-hosted:\s*(hardware|oversize|credential)\s*:\s*\S")
BARE = re.compile(r"#\s*self-hosted:")  # v1.46: a waiver whose reason names no category
# v1.47 (ruling 1007): a review-only label runs only in code-review.yml, and
# only with its own category; credential: is the codex job's alone.
REVIEW = {"codex": "credential", "qwen": "hardware"}
REVIEW_FILES = {"code-review.yml", "code-review.yaml"}
REVIEW_TOKEN = re.compile(r"(?<![\w.-])['\"]?(codex|qwen)['\"]?(?![\w-])", re.I)
GH = "https://github.com"
# v1.48 (ruling 1024): ci.yml's preflight runner selection (v1.54:
# `Balanced runner pool (ruling 1137)`) outputs runs-on JSON,
# "ubuntu-latest" or the Dells' self-hosted list ("overflow" below). In ci.yml only, a
# runs-on that reads exactly these outputs is checked under both: the
# default must be a standard image, as (c) asks of every job, and the
# overflow may also be exactly the list its output names. Any other
# self-hosted value still needs its waiver.
SEL_FILES = {"ci.yml", "ci.yaml"}
SEL_OUT = {"needs.preflight.outputs.runner": "bigdisk",
           "needs.preflight.outputs.runner_docker": "bigdisk-docker"}
OVERFLOW = [["self-hosted", "linux", "x64", v] for v in SEL_OUT.values()]
# v1.49: ci.yml's preflight job alone may read the
# repository variable CI_PREFLIGHT_RUNS_ON. Its runs-on is checked in
# two states of its own, in place of the selection's: unset, where
# exactly [self-hosted, linux, x64, bigdisk] passes too, and set to the
# fallback `"ubuntu-latest"`, where it must give a standard image on
# every event. Another job that reads the variable reads an unknown.
PRE_JOB = "preflight"
PRE_VAR = "vars.ci_preflight_runs_on"
PRE_READ = re.compile(r"(?<![\w.])vars\.CI_PREFLIGHT_RUNS_ON(?![\w-])", re.I)
HOSTED_CTX = [  # (event, ref, head repo) on github.com; o/r is this repository
    ("push", "refs/heads/main", None), ("push", "refs/heads/feature", None),
    ("pull_request", "refs/pull/1/merge", "o/r"), ("pull_request", "refs/pull/1/merge", "fork/r"),
    ("workflow_dispatch", "refs/heads/main", None), ("schedule", "refs/heads/main", None),
    # Resume 23 (ci-template v1.51): every runs-on is read under
    # pull_request_target too, where github.ref is the base branch.
    ("pull_request_target", "refs/heads/main", "o/r"), ("pull_request_target", "refs/heads/main", "fork/r"),
]


# Resume 15 (#494 round 4): a runs-on expression is evaluated only when its
# text, whitespace-normalised, is one this repository's workflows use
# (RO_ALLOW, with the jobs that use it); any other expression counts as
# reaching `release` and needs the tag-push `if:`. Nothing is sampled
# from its literals: head_ref, base_ref and event values are the
# attacker's, so no sample set of them is complete.
RO_ALLOW = {
    # Resume 23 (ci-template v1.52): a fork's pull request takes
    # ubuntu-latest before the variable is read.
    "github.server_url == 'https://github.com' && (!startsWith(github.event_name, 'pull_request') || "
    "github.event.pull_request.head.repo.full_name == github.repository) && fromJSON(vars.CI_PREFLIGHT_RUNS_ON || "
    "'[\"self-hosted\",\"linux\",\"x64\",\"bigdisk\"]') || 'ubuntu-latest'": "ci.yml: preflight",
    "github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk'": "code-review.yml: scope, gate",
    # ci-template v1.54: every other ci.yml job reads the pool that
    # preflight's `Balanced runner pool (ruling 1137)` step picks.
    "github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner_docker) || 'bigdisk'":
        "ci.yml: every job but preflight and CI Gate",
    "github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner || '\"ubuntu-latest\"') || 'ci-gate'":
        "ci.yml: ci-gate",
}
RO_EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)


def ro_unlisted(text):
    # The first expression in a runs-on text that is not allow-listed, or None.
    exprs = RO_EXPR.findall(text)
    if text.count(OPEN) != len(exprs):
        return text[:60]
    for e in exprs:
        if " ".join(e.split()) not in RO_ALLOW:
            return " ".join(e.split())[:60]
    return None


def hosted_cands(text):
    # (event, ref, head repo, head_ref, base_ref) on github.com: the
    # HOSTED_CTX samples alone (Resume 15: none from the text's literals).
    for ev, ref, head in HOSTED_CTX:
        yield ev, ref, head, "feature", "main"


def hosted_get(ev, ref, head, sel=None, hr="feature", br="main"):
    def get(path):
        p = path.lower()
        if sel and p in SEL_OUT:  # v1.48: the selection output, as JSON text
            # v1.52: the step outputs the hosted default for a fork's head.
            # Its case statement covers pull_request and pull_request_target,
            # so both are modelled here (the template models pull_request).
            fork_pr = ev in ("pull_request", "pull_request_target") and head == "fork/r"
            return json.dumps("ubuntu-latest" if sel == "default" or fork_pr else ["self-hosted", "linux", "x64", SEL_OUT[p]])
        if sel in ("unset", "set") and p == PRE_VAR:  # v1.49: unset, or the fallback switch
            return None if sel == "unset" else json.dumps("ubuntu-latest")
        if p == "github.server_url":
            return GH
        if p == "github.repository":
            return "o/r"
        if p == "github.event.pull_request.head.repo.full_name":
            return head if ev in PR else None
        if p == "github.event.pull_request.draft":
            return False if ev in PR else None
        return ctx_get(ev, ref, path, hr, br)
    return get


def labels(value):
    # A runs-on value's labels: a string, a list, or an expression's result.
    if value is U or value is None:
        return None
    if isinstance(value, list):
        return [str(x) for x in value]
    return [str(value)]


def runs_on_labels(text, ev, ref, head, sel=None, hr="feature", br="main"):
    t = ro_mapping(text.strip())
    m = re.fullmatch(r"\$\{\{(.*)\}\}", unquote(t), re.S)
    if m:
        return labels(P(lex(m.group(1)), hosted_get(ev, ref, head, sel, hr, br)).parse())
    if t.startswith("["):
        return [unquote(x) for x in re.split(r"\s*,\s*", t.strip("[] ")) if x]
    if t.startswith("- "):
        return [unquote(x) for x in re.split(r"\s*-\s+", " " + t) if x.strip()]
    return [unquote(t)]


def review_labels(text):
    # The review-only labels a runs-on names, in its text or in what an
    # expression there yields on any github.com event.
    found = {m.lower() for m in REVIEW_TOKEN.findall(text)}
    for ev, ref, head, hr, br in hosted_cands(text):
        try:
            got = runs_on_labels(text, ev, ref, head, hr=hr, br=br)
        except ValueError:
            continue
        found |= {g.lower() for g in got or [] if g.lower() in REVIEW}
    return sorted(found)


def review_finding(path, where, ro, ro_line):
    # v1.47 (ruling 1007): label and category together, whatever the waiver says.
    names = review_labels(ro)
    m = WAIVER.search(ro_line)
    cat = m.group(1) if m else None
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    if names and base not in REVIEW_FILES:
        return (f"{where}: (f) names the review-only label {', '.join(names)}; ruling 1007 reserves codex and "
                f"qwen to code-review.yml whatever the `# self-hosted:` waiver says")
    if names:
        wrong = [n for n in names if cat != REVIEW[n]]
        if len(names) > 1 or wrong:
            return (f"{where}: (f) runs on {', '.join(names)} with the category {cat or 'none'}; ruling 1007 pairs "
                    f"codex with `credential:` and qwen with `hardware:`, one review label per job")
        return None
    if cat == "credential":
        return (f"{where}: (f) uses the `credential:` category without the codex label; ruling 1007 keeps it "
                f"for code-review.yml's Codex review job alone")
    return None


def release_reason(text, sels=(None,)):
    # Why a runs-on may name `release`, or None: the label in the text,
    # an expression not in RO_ALLOW, or an allow-listed one that yields it
    # on a github.com event (an unknown value is (c)'s).
    # Resume 20: GitHub matches labels case-insensitively, so this does too.
    if re.search(r"(?<![\w.-])['\"]?release['\"]?(?![\w-])", text, re.I):
        return "names `release`"
    u = ro_unlisted(text)
    if u is not None:
        return (f"its runs-on expression is not allow-listed ({u!r}; only {', '.join(RO_ALLOW.values())} "
                f"are), so it may name `release`,")
    for ev, ref, head, hr, br in hosted_cands(text):
        for sel in sels:
            try:
                got = runs_on_labels(text, ev, ref, head, sel, hr=hr, br=br)
            except ValueError:
                continue
            if any(g.casefold() == "release" for g in got or []):
                return "names `release`"
    return None


# Resume 15: the `if:` scalar is the bare expression or one expression
# filling it, nothing else: text or a space around it makes it a string.
EDGE = "it has a space before or after it inside its quotes, which makes it a string, always true"


def condition(text):
    t = unquote(text) if text else ""
    if t != t.strip():
        raise ValueError(EDGE)
    m = re.fullmatch(r"\$\{\{(.*)\}\}", t, re.S)
    if m and OPEN not in m.group(1):
        return m.group(1)
    if OPEN in t:
        raise ValueError("text around the expression makes it a string, which is always true")
    return t


# Resume 13: forms YAML reads that the line reader above would not see,
# each refused (fails closed). ODD_TEXT: a BOM past the start, and line
# breaks other than LF and CR, which YAML 1.1 and 1.2 parsers split differently.
ODD_TEXT = "".join(map(chr, (0xFEFF, 0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029)))
TOP_KEY = re.compile(r"""(?:[A-Za-z_][\w-]*|'[A-Za-z_][\w-]*'|"[A-Za-z_][\w-]*")[ \t]*:(?:[ \t]|$)""")
# A job's key: plain, or quoted with no escape; or a block sequence item.
JOB_KEY = re.compile(r"""[ ]*(?:(?:<<|[A-Za-z0-9_][\w.-]*|'[\w.-]+'|"[\w.-]+")[ \t]*:(?:[ \t]|$)|-(?:[ \t]|$))""")
GROUP = re.compile(r"""(?:^|[{,\s])['"]?group['"]?\s*:""")
# Labels every self-hosted runner carries, the release runner too.
CASED = {"runs-on", "if", "uses"}  # Resume 15: a job key that differs from these only in case fails closed
GENERIC = {"self-hosted", "linux", "windows", "macos", "x64", "x86", "arm", "arm64"}


def top_level(lines):
    # Why the file is not one block mapping at column 0 (where the check
    # finds `on:` and `jobs:`), or None. One `---` may open it.
    first = True
    for n, s in enumerate(lines, 1):
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        if first and re.fullmatch(r"---[ \t]*(?:#.*)?", s):
            first = False
            continue
        if (first and ind(s)) or (not ind(s) and not TOP_KEY.match(s)):
            return f"line {n}: {s.strip()[:40]!r}"
        first = False
    return None


BLOCK_IND = re.compile(r"[|>][+-]?")  # no indentation indicator
PLAIN_KEY = re.compile(r"([^\s#'\"?&*!{}\[\]|>%@`,].*?)[ \t]*:(?=[ \t]|$)")
QUOTED_KEY = re.compile(r"('(?:[^']|'')*'|\"(?:[^\"\\\\]|\\\\.)*\")[ \t]*:(?=[ \t]|$)")


def quote_open(v):
    # Resume 17: whether a value (comment cut) leaves a quoted scalar open
    # at the end of its line. A quote starts one only at the start of the
    # value or of a flow list item (after `[` or `,`); elsewhere it is
    # plain text (`it's`). '' escapes in '...', \\ in "...".
    # Resume 18: also after `: ` or `? ` (a flow pair's value or key; in
    # block context a plain `: ` is not YAML), and after an anchor or tag
    # that starts a value, so `[run: &x "echo]` is open too.
    def after(j):
        return j + len(v[j:]) - len(v[j:].lstrip(" "))
    k, starts = 0, {0}
    while k < len(v):
        if k in starts and v[k] in "&!":
            j = k
            while j < len(v) and v[j] != " ":
                j += 1
            starts.add(after(j))
        elif k in starts and v[k] in "'\"":
            q, k = v[k], k + 1
            while k < len(v) and v[k] != q or v[k:k + 2] == "''" and q == "'":
                k += 2 if (q == '"' and v[k] == "\\") or v[k:k + 2] == "''" else 1
            if k >= len(v):
                return True
        elif v[0] == "[" and v[k] in "[," or v[k] in ":?" and v[k + 1:k + 2] == " ":
            starts.add(after(k + 1))
        k += 1
    return False


def flow_pair(v):
    # Resume 18: whether a one-line flow list `[...]` holds a flow pair
    # (`k: v`, `k:` at an item's end, `"k":v`) or an item starting `?`.
    # Quoted scalars are skipped whole; `a:b` stays a plain scalar.
    k, start, closed = 1, True, False
    while k < len(v):
        c = v[k]
        if c == " ":
            k += 1
            continue
        if start and c == "?":
            return True
        if start and c in "'\"":
            k += 1
            while k < len(v) and v[k] != c or v[k:k + 2] == "''" and c == "'":
                k += 2 if (c == '"' and v[k] == "\\") or v[k:k + 2] == "''" else 1
            k, start, closed = k + 1, False, True
            continue
        if c == ":" and (closed or v[k + 1:k + 2] in ("", " ", ",", "]")):
            return True
        k, start, closed = k + 1, c in "[,", False
    return False


def subset(lines):
    # Resume 16: the first line outside the strict subset (see the top),
    # as "line n: reason", or None. Lines inside a block scalar are text.
    # The whole file is read, so `on:` and `jobs:` are both covered.
    # Resume 17: a quoted scalar left open at the end of a line, and a
    # line indented between the columns of the nodes it would continue
    # (a column-0/1 line inside a quoted scalar), fail.
    scalar = None  # column a block scalar's text lines must exceed
    cols = []  # columns of the open nodes, increasing
    for n, s in enumerate(lines, 1):
        if scalar is not None:
            if not s.strip() or ind(s) > scalar:
                continue
            scalar = None
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        if "\t" in s:
            return f"line {n}: a tab"
        col, rest = ind(s), s.lstrip(" ")
        if cols and col <= cols[-1]:
            while cols and cols[-1] > col:
                cols.pop()
            if not cols or cols[-1] != col:
                return f"line {n}: a line indented less than the mapping key it would continue"
        else:
            cols.append(col)
        while re.match(r"-(?:[ ]|$)", rest):  # block sequence items
            col += 1 + len(rest[1:]) - len(rest[1:].lstrip(" "))
            rest = rest[1:].lstrip(" ")
            if rest:
                cols.append(col)
        rest = strip_comment(rest)
        if not rest:
            continue
        if re.fullmatch(r"---|\.\.\.", rest) and col == 0:
            continue  # top_level allows one opening `---` and refuses the rest
        if rest[0] == "?":
            return f"line {n}: a complex `?` key"
        m = QUOTED_KEY.match(rest) or PLAIN_KEY.match(rest)
        if m:
            key = m.group(1)
            if any(ord(c) > 126 or ord(c) < 32 for c in key):
                return f"line {n}: a key with a character outside printable ASCII"
            if key[0] == '"' and "\\" in key:
                return f"line {n}: an escape in a double-quoted key"
            if unquote(key) == "<<":
                return f"line {n}: a `<<` merge key"
            value, keycol, name = rest[m.end():].strip(), col, unquote(key)
        else:
            value, keycol, name = rest, col - 1, None  # a sequence item's scalar
        if not value:
            continue
        if quote_open(value):
            return f"line {n}: a quoted scalar left open at the end of its line"
        if value[0] in "&*!":
            return f"line {n}: a YAML anchor, alias or tag (`{value[0]}`)"
        if value[0] == "{":
            return f"line {n}: a flow mapping"
        if value[0] == "[" and (not value.endswith("]") or re.search(r"[\[,][ ]*[&*!{\[]", value)):
            return f"line {n}: a flow sequence over more than one line or holding an anchor, alias, tag or collection"
        if value[0] == "[" and flow_pair(value):
            return f"line {n}: a flow sequence holding a flow pair or a `?` item"
        if value[0] == '"' and "\\" in value:
            return f"line {n}: an escape in a double-quoted scalar"
        if value[0] in "|>":
            if not BLOCK_IND.fullmatch(value):
                return f"line {n}: a block scalar header the check cannot read"
            if name == "runs-on":
                return f"line {n}: a block scalar runs-on"
            scalar = keycol
    return None


def odd_key(lines, i):
    # The first direct child line of the job on line i that is not a
    # JOB_KEY (a `?` key, a tag, an anchor, an escape), or None: YAML may
    # read it as a runs-on or if the check does not see.
    base, child = ind(lines[i]), None
    for j in range(i + 1, len(lines)):
        s = lines[j]
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        if ind(s) <= base:
            break
        child = ind(s) if child is None else child
        if ind(s) < child or (ind(s) == child and not JOB_KEY.match(s)):
            return s.strip()[:40]
    return None


def waived_unsafe(ro):
    # Why a waived runs-on the text shows no `release` in may still reach
    # the release runner, or None: a value the check cannot know (a matrix,
    # input or variable, an escape), or only labels every runner carries.
    for ev, ref, head, hr, br in hosted_cands(ro):
        try:
            got = runs_on_labels(ro, ev, ref, head, hr=hr, br=br)
        except ValueError as e:
            return f"{ev}: it cannot be read ({e})"
        if got is None:
            return f"{ev}: an unknown label"
        # Resume 21: the waiver needs a label it read; an empty one is none.
        if not got or any(not g.strip() for g in got):
            return f"{ev}: no label, or an empty one ({', '.join(map(repr, got))})"
        if all(g.casefold() in GENERIC for g in got):
            return f"{ev}: only generic labels ({', '.join(got)})"
    return None


# Resume 14: a second layer. The workflow is loaded with PyYAML's safe
# loader (python3-yaml, which ubuntu-latest ships; nothing is installed),
# so anchors, tags, aliases, merge keys and escapes read as YAML reads
# them. Every job whose parsed runs-on is or may be `release` (a label
# that case-folds to it, only GENERIC labels, a value that is not a
# string, a group, or an expression that yields it, only GENERIC
# labels or an unknown on a github.com event) must
# have a parsed `if:` the allowlist above accepts. Both layers must
# accept; a file PyYAML cannot load fails closed (y). Resume 16: with
# no PyYAML (the bigdisk runner) the strict line reader decides alone.
def yaml_loader(yaml):
    class Loader(yaml.SafeLoader):  # `on`, `yes`, `no`, `off` stay strings, as in YAML 1.2
        pass
    B = "tag:yaml.org,2002:bool"
    Loader.yaml_implicit_resolvers = {k: [(t, r) for t, r in v if t != B]
                                      for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()}
    Loader.add_implicit_resolver(B, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF"))
    return Loader


def yaml_reach(ro, sels):
    # Why a parsed runs-on value is or may be `release`, or None.
    if isinstance(ro, dict):
        if "group" in ro or set(ro) - {"labels"}:
            return "is a mapping with a runner group or keys other than labels"
        ro = ro.get("labels")
    items = [ro] if isinstance(ro, str) else ro if isinstance(ro, list) else None
    if items is None:
        return f"is a {type(ro).__name__}, not a string or list"
    if not all(isinstance(x, str) for x in items):
        return "holds a value that is not a string"
    lits = [x for x in items if OPEN not in x]
    exprs = [x for x in items if OPEN in x]
    generic = "has only labels every self-hosted runner carries, the release runner too"
    if any(x.casefold() == "release" for x in lits):
        return "names `release`"
    if not exprs and all(x.casefold() in GENERIC for x in lits):
        return generic
    for x in exprs:
        m = re.fullmatch(r"\$\{\{(.*)\}\}", x, re.S)
        if not m or OPEN in m.group(1):
            return f"has text around an expression ({x[:40]!r})"
        if " ".join(m.group(1).split()) not in RO_ALLOW:
            return f"has an expression that is not allow-listed ({x[:60]!r}), so it may yield `release`"
        for ev, ref, head, hr, br in hosted_cands(x):
            for sel in sels:
                try:
                    got = labels(P(lex(m.group(1)), hosted_get(ev, ref, head, sel, hr, br)).parse())
                except ValueError as e:
                    return f"has an expression that cannot be read ({e})"
                if got is None:
                    return f"has an expression with an unknown value on {ev}"
                if any(str(g).casefold() == "release" for g in got):
                    return f"has an expression that yields `release` on {ev}"
                if all(str(g).casefold() in GENERIC for g in lits + got):
                    return f"{generic}, on {ev}"
    return None


def yaml_allowed(cond):
    # Whether a parsed `if:` is in the allow-listed form; ValueError if unreadable.
    if not isinstance(cond, str):
        raise ValueError("there is none" if cond is None else f"it is a {type(cond).__name__}, not a string")
    if cond != cond.strip():
        raise ValueError(EDGE)
    m = re.fullmatch(r"\$\{\{(.*)\}\}", cond, re.S)
    if m and OPEN not in m.group(1):
        expr = m.group(1)
    elif OPEN in cond:
        raise ValueError("text around the expression makes it a string, which is always true")
    else:
        expr = cond
    toks = lex(expr)
    P(toks, lambda p: U).parse()
    terms = release_terms(toks)
    return ALLOW_EVENT in terms and any(t in terms for t in ALLOW_TAG)


def yaml_check(path, yaml):
    try:
        data = yaml.load(open(path, encoding="utf-8").read(), Loader=yaml_loader(yaml))
    except Exception as e:  # any parse failure fails closed
        return [f"{path}: (y) PyYAML cannot load it ({type(e).__name__}: {str(e)[:120]}), so no job can be checked"]
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
        return [f"{path}: (y) parsed as YAML, it is not a mapping with a `jobs:` mapping, so no job can be checked"]
    on = data.get("on")
    on = {on} if isinstance(on, str) else set(map(str, on)) if isinstance(on, (list, dict)) else set(PR)
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    bad = []
    for job, j in data["jobs"].items():
        where = f"{path}:{job}"
        if not isinstance(j, dict):
            bad.append(f"{where}: (y) parsed as YAML, the job is not a mapping")
            continue
        cased = [k for k in j if isinstance(k, str) and k.lower() in CASED and k != k.lower()]
        if cased:
            bad.append(f"{where}: (y) parsed as YAML, the job has a key that differs from runs-on, if or uses "
                       f"only in case ({cased[0]!r}), so the check fails closed")
            continue
        if "runs-on" not in j:
            continue
        ro = j["runs-on"]
        # Resume 22: as the line reader, a label that is empty, null, not a
        # string or padded with whitespace is (c) whatever the `if:` says.
        items = ro.get("labels") if isinstance(ro, dict) else ro
        items = items if isinstance(items, list) else [items]
        odd = [x for x in items if not isinstance(x, str) or not x or x != x.strip()]
        if odd:
            bad.append(f"{where}: (c) parsed as YAML, its runs-on has a label that is empty, null or padded with "
                       f"whitespace, or is not a string ({odd[0]!r}); the check fails closed")
            continue
        sels = ("default", "overflow") if base in SEL_FILES else (None,)
        if sels[0] is not None and job == PRE_JOB and isinstance(ro, str) and PRE_READ.search(ro):
            sels = ("unset", "set")
        why = yaml_reach(ro, sels)
        if why is None:
            continue
        try:
            if yaml_allowed(j.get("if")):
                continue
            problem = "is not in the allow-listed form"
        except ValueError as e:
            problem = f"cannot be read ({e})"
        pr = " in a workflow with a " + " and ".join(sorted(on & PR)) + " trigger" if on & PR else ""
        bad.append(f"{where}: (y) parsed as YAML, its runs-on {why}{pr}, and its `if:` {problem}; it must be {ALLOWED}")
    return bad


def check(path):
    text = open(path, encoding="utf-8").read()
    text = text[1:] if text[:1] == ODD_TEXT[0] else text  # a BOM at the start, as YAML reads it
    if any(c in text for c in ODD_TEXT):
        return [f"{path}: (c) holds a byte-order mark or a line break other than LF or CR (U+000B, U+000C, "
                f"U+001C-U+001E, U+0085, U+2028, U+2029), which YAML parsers split differently, so the check fails closed"]
    lines = text.splitlines()
    top = top_level(lines)
    if top:
        return [f"{path}: (c) its top level is not a block mapping at column 0 ({top}), so no job can be checked; "
                f"write the workflow as one block mapping"]
    out = subset(lines)
    on = triggers(lines)
    # (s) fails the file on its own; the job checks below still run, for
    # their more precise findings.
    bad = [f"{path}: (s) {out} is outside the YAML subset the check reads (see the step's top), so it fails "
           f"closed; write it in that subset"] if out else []
    for i, s in enumerate(lines):
        m = re.match(r"(['\"]?)jobs\1\s*:(.*)$", s)
        if m and strip_comment(m.group(2)).strip():
            bad.append(f"{path}:jobs: (c) is not a block mapping, so no job's runs-on can be checked; write jobs: as a block mapping")
        elif m:
            jobs = keys_under(lines, i)
            # Resume 19: a `- ` line at a block's child column is an item of
            # the previous key's compact sequence, never one of the block's
            # own keys; one that comes first makes the block a sequence.
            if jobs and lines[jobs[0][0]].lstrip().startswith("-"):
                bad.append(f"{path}:jobs: (c) is a sequence, not a block mapping, so no job's runs-on can be checked; "
                           f"write jobs: as a block mapping")
            item = [lines[j].lstrip().startswith("-") for j, _, _ in jobs]
            for n, (j, job, jinline) in enumerate(jobs):
                if item[n]:
                    continue
                where = f"{path}:{job}"
                if strip_comment(jinline).strip():
                    bad.append(f"{where}: (c) is not a block mapping (a flow mapping or an alias), so its runs-on cannot be checked; "
                               f"write the job as a block mapping")
                    continue
                ro = cond = ro_line = None
                forms, seen = [], set()
                odd = odd_key(lines, j)
                if odd:
                    forms.append(f"has a key the check cannot read ({odd!r}: a `?` key, a tag, an anchor or an escape)")
                jkeys = keys_under(lines, j)
                if (jkeys and lines[jkeys[0][0]].lstrip().startswith("-")) or item[n + 1:n + 2] == [True]:
                    forms.append("is a sequence, not a block mapping")
                for k, key, inline in jkeys:
                    if lines[k].lstrip().startswith("-"):  # a sequence item's key is never the job's
                        continue
                    if key in seen:
                        forms.append(f"has a duplicate `{key}` key")
                    seen.add(key)
                    if key.lower() in CASED and key != key.lower():
                        forms.append(f"has a `{key}` key, which differs from `{key.lower()}` only in case")
                    elif key == "<<":
                        forms.append("has a `<<` merge key, so its runs-on or `if:` may come from elsewhere")
                    elif key == "uses" and not unquote(strip_comment(inline)).startswith("./"):
                        forms.append("calls a reusable workflow outside this repository, whose runs-on the check cannot see")
                    elif key == "runs-on":
                        ro, ro_line = body(lines, k, inline), lines[k]
                        f = runs_on_form(lines, k, inline, ro)
                        forms += [f"its runs-on {f}"] if f else []
                        if GROUP.search(ro):
                            forms.append("its runs-on names a runner group, which may hold the release runner")
                    elif key == "if":
                        try:
                            cond = one_line(lines, k, inline)
                        except ValueError as e:
                            cond = e
                if forms:
                    bad.append(f"{where}: (c) {'; '.join(forms)}; the check cannot read it, so it fails closed: write the job as a block "
                               f"mapping of plain keys, each once, runs-on on one line or as a block list of one-line labels")
                    continue
                rel = release_reason(ro) if ro is not None else None
                if ro is not None and not rel:
                    # v1.43 (ruling 833): hosted first.
                    if LARGER.search(ro) and re.search(r"ubuntu|windows|macos", ro):
                        bad.append(f"{where}: (d) names a larger GitHub-hosted runner ({ro}); it bills on a public repository")
                        continue
                    rf = review_finding(path, where, ro, ro_line)
                    if rf:
                        bad.append(rf)
                        continue
                    if WAIVER.search(ro_line):
                        why = waived_unsafe(ro)
                        if why:
                            bad.append(f"{where}: (c) its waived runs-on may name `release` ({why}); write its labels out, "
                                       f"with one the release runner does not carry")
                        continue
                    off = []
                    sels = ("default", "overflow") if path.replace("\\", "/").rsplit("/", 1)[-1] in SEL_FILES else (None,)
                    if sels[0] is not None and job == PRE_JOB and PRE_READ.search(ro):
                        sels = ("unset", "set")  # v1.49: its own two states, no selection output
                    for ev, ref, head, hr, br in hosted_cands(ro):
                        for sel in sels:
                            try:
                                got = runs_on_labels(ro, ev, ref, head, sel, hr=hr, br=br)
                            except ValueError as e:
                                off.append(f"{ev} ({ref}): cannot be read ({e})")
                                continue
                            # Resume 23 (ci-template v1.51, v1.52; the stricter
                            # kept): a fork's head, under pull_request or
                            # pull_request_target, gets neither exemption.
                            # Deliberately stricter than the template: this
                            # condition does not require the event to be one
                            # of the workflow's triggers (the template's
                            # `and ev in on`). With v1.54's selection step
                            # taken, hosted_get's `fork_pr` rule gives a
                            # fork's head the hosted default the step
                            # outputs, so an overflow for a fork is still
                            # refused here. The unset
                            # guard is unreachable while RO_ALLOW's only
                            # CI_PREFLIGHT_RUNS_ON form carries the fork clause
                            # (a fork gets ubuntu-latest first); it is kept so
                            # a fork-less form added there is still refused.
                            fork = head == "fork/r"
                            if got is not None and sel == "overflow" and got in OVERFLOW and not fork:
                                continue
                            if sel == "unset" and got == OVERFLOW[0] and not fork:
                                continue
                            if got is None or len(got) != 1 or not STANDARD.fullmatch(got[0]):
                                what = "an unknown label" if got is None else ", ".join(got)
                                note = ", runner selection overflow" if sel == "overflow" else ""
                                if sel in ("unset", "set"):
                                    note = ", CI_PREFLIGHT_RUNS_ON " + ("unset" if sel == "unset" else 'set to "ubuntu-latest"')
                                off.append(f"{ev} ({ref}{', fork' if head == 'fork/r' else ''}{note}): {what}")
                    if off and BARE.search(ro_line):
                        bad.append(f"{where}: (e) its `# self-hosted:` reason names no category; ruling 999 allows a self-hosted job "
                                   f"only as `# self-hosted: hardware: <reason>` or `# self-hosted: oversize: <reason>`; it runs on " + "; ".join(dict.fromkeys(off)))
                    elif off:
                        bad.append(f"{where}: (c) does not run on a standard GitHub-hosted image on github.com and its runs-on "
                                   f"line gives no `# self-hosted: hardware|oversize: <reason>`; it runs on " + "; ".join(dict.fromkeys(off)))
                    continue
                if ro is None:
                    continue
                if cond is None:
                    if on & PR:
                        bad.append(f"{where}: (a) {rel} in a workflow with a pull_request trigger, and has no `if:`")
                    bad.append(f"{where}: (b) {rel} and has no `if:` restricting it to {ALLOWED}")
                    continue
                try:
                    if cond is MULTI:
                        raise ValueError("it is a block scalar or spans lines; write the release if: on one line")
                    if isinstance(cond, ValueError):
                        raise cond
                    expr = condition(cond)
                    toks = lex(expr)
                    P(toks, lambda p: U).parse()  # it must be a readable expression
                    terms = release_terms(toks)
                except ValueError as e:
                    if on & PR:
                        bad.append(f"{where}: (a) {rel} in a workflow with a "
                                   + " and ".join(sorted(on & PR)) + " trigger and its `if:` cannot be read, so a "
                                   + " or ".join(sorted(on & PR)) + " event may run it")
                    bad.append(f"{where}: (b) {rel} and its `if:` cannot be read ({e}); it must be {ALLOWED}")
                    continue
                if ALLOW_EVENT in terms and any(t in terms for t in ALLOW_TAG):
                    continue
                if on & PR:
                    bad.append(f"{where}: (a) {rel} and its `if:` is not in the allow-listed form, so a "
                               + " or ".join(sorted(on & PR)) + " event may run it")
                bad.append(f"{where}: (b) {rel} and its `if:` does not restrict it to {ALLOWED}")
    return bad


# Resume 15: every entry under the workflows directory, dotfiles too: a
# .yml or .yaml name in any case is checked, anything else fails (z).
WF = ".github/workflows"
files, bad = [], []
try:
    entries = sorted(os.listdir(WF))
except OSError as e:
    entries = []
    bad.append(f"{WF}: (z) cannot be listed ({e})")
for n in entries:
    p = f"{WF}/{n}"
    if os.path.islink(p) or not os.path.isfile(p):
        bad.append(f"{p}: (z) is not a regular file; {WF} may hold only .yml or .yaml workflow files")
    elif not n.lower().endswith((".yml", ".yaml")):
        bad.append(f"{p}: (z) is not a .yml or .yaml file; {WF} may hold only workflow files, so the check fails closed")
    else:
        files.append(p)
try:
    import yaml
except ImportError:
    # Not a skip: the line reader is a strict-subset reader and is
    # the gate on its own; PyYAML, where present, only cross-checks.
    yaml = None
    print("NOTE: PyYAML not available; line reader only (strict subset)")
for f in files:
    try:
        bad += check(f)
        bad += yaml_check(f, yaml) if yaml else []
    except (OSError, UnicodeError) as e:
        bad.append(f"{f}: cannot be read ({e})")
for b in bad:
    print(f"::error::{b}")
if bad:
    print(f"{len(bad)} runner-label finding(s) in {len(files)} workflow file(s): a `release` job runs only on {ALLOWED}, never for a pull request (ruling 633); every other job runs on a standard GitHub-hosted image, or its runs-on line names a hardware or oversize reason (rulings 833, 999); codex and qwen run only in code-review.yml, with their own category (ruling 1007)")
    sys.exit(1)
print(f"OK: {len(files)} workflow file(s); every job that names `release` runs only on {ALLOWED}, and every other job on a standard GitHub-hosted image or with a hardware or oversize reason")
