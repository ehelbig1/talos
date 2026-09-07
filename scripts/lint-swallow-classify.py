#!/usr/bin/env python3
"""Enumerate awaited reads whose Result/Option is COLLAPSED INTO A DEFAULT.

This is the read-side companion to `scripts/lint-swallow-inventory.py` (which
enumerates `let _ = <expr>.await`, i.e. discarded WRITES). Here the value IS
used — what is discarded is the distinction between "the read answered" and
"the read failed", so a database fault becomes a count, a list, a verdict or a
"not found" that a caller reads and acts on.

It is STATEMENT-AWARE rather than a line grep, and that is why it reports more
than a `grep -n 'unwrap_or'` does:

  * comment and string-literal CONTENT is masked first (replaced by spaces of
    the same length, so byte offsets and line numbers are preserved), so a doc
    comment quoting the banned expression cannot self-report — check 73's trap;
  * after each `.await` the POSTFIX METHOD CHAIN is walked, so the house style's
    broken chain (`.await` on one line, `.unwrap_or_default()` on the next) is
    one statement, not two lines that a grep sees separately;
  * a collapse counts only if it precedes any `?` in that chain — a read that
    propagates its error is not collapsed however it is later defaulted.

Six spellings are recognised:

  chain    .unwrap_or_default()
  chain    .unwrap_or(<literal>)
  chain    .unwrap_or_else(..)
  chain    .ok()                       (incl. `.ok().flatten()`, `.ok()?` is NOT
                                        a collapse — the `?` propagates)
  block    match <read>.await { .. Err(_)/_ => <default> .. }
  binding  if let Ok(..) = <read>.await   /   let Ok(..) = <read>.await else

Usage:
  python3 scripts/lint-swallow-classify.py [ROOT] [--json] [--summary]
    ROOT defaults to '.'; the scanned roots default to the two protocol
    surfaces (talos-mcp-handlers/src, talos-api/src) and can be overridden with
    --roots a,b,c.

Output is one record per site: file, line, spelling, the awaited callee, and the
enclosing function. VERDICTS (claim / fail-open / fail-closed / decorative) are
NOT derived here — they are a human judgement about what the default CLAIMS, and
they live in `scripts/swallow-read-verdicts.py`.
"""
import json
import os
import re
import sys

DEFAULT_ROOTS = ["talos-mcp-handlers/src", "talos-api/src"]
SKIP_DIRS = {"target", ".git", "node_modules", ".claude"}


def is_test_file(path):
    p = path.replace(os.sep, "/")
    if "/tests/" in p or "/benches/" in p or "/examples/" in p:
        return True
    b = os.path.basename(p)
    return b.endswith("_tests.rs") or b in ("tests.rs", "test_support.rs")


def mask(src):
    """Replace comment and string/char-literal CONTENT with spaces.

    Newlines are preserved so line numbers survive. Handles //, /* */ (nested),
    "..." with escapes, r"..." / r#"..."#, and 'c' char literals (lifetimes like
    `&'a str` are left alone because they carry no closing quote)."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 0
            while i < n:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    if depth == 0:
                        break
                    continue
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        if c == "r" and i + 1 < n and src[i + 1] in '#"':
            j = i + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                close = '"' + "#" * hashes
                end = src.find(close, j + 1)
                end = n if end == -1 else end + len(close)
                for k in range(i, end):
                    if src[k] != "\n":
                        out[k] = " "
                i = end
                continue
        if c == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if src[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if c == "'":
            m = re.match(r"'(\\.|[^\\'])'", src[i:])
            if m:
                for k in range(i, i + m.end()):
                    out[k] = " "
                i += m.end()
                continue
        i += 1
    return "".join(out)


def cfg_test_spans(masked):
    """(start, end) char spans of `#[cfg(test)] mod ... }` blocks at column 0."""
    spans = []
    for m in re.finditer(r"(?m)^#\[cfg\(test\)\]", masked):
        rest = masked[m.end():]
        mm = re.search(r"(?m)^\s*(pub\s+)?mod\s", rest)
        if not mm or mm.start() > 200:
            continue
        close = re.search(r"(?m)^\}", rest[mm.end():])
        end = m.end() + mm.end() + (close.end() if close else len(rest) - mm.end())
        spans.append((m.start(), end))
    return spans


IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


def match_balanced(s, i, open_c="(", close_c=")"):
    """If s[i] == open_c, return index just past the matching close; else None."""
    if i >= len(s) or s[i] != open_c:
        return None
    depth = 0
    while i < len(s):
        if s[i] == open_c:
            depth += 1
        elif s[i] == close_c:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


LITERAL_ARG = re.compile(
    r"^\(\s*(0|0\.0|1|-1|false|true|None|Vec::new\(\)|String::new\(\)|"
    r"HashMap::new\(\)|serde_json::json!|\d+(\.\d+)?|\"|'|None\s*\))"
)


def walk_chain(masked, pos):
    """Walk the postfix chain starting at `pos` (just past `.await`).

    Returns (spelling, offset) for the first collapse, or None. A `?` before the
    collapse means the error propagates: not a collapse."""
    i = pos
    n = len(masked)
    while i < n:
        while i < n and masked[i] in " \t\r\n":
            i += 1
        if i >= n:
            return None
        if masked[i] == "?":
            return None
        if masked[i] != ".":
            return None
        j = i + 1
        while j < n and masked[j] in " \t\r\n":
            j += 1
        m = re.match(IDENT, masked[j:])
        if not m:
            return None
        name = m.group(0)
        k = j + m.end()
        args_end = match_balanced(masked, k)
        if args_end is None:
            args_end = k
        if name == "unwrap_or_default":
            return ("unwrap_or_default", i)
        if name == "unwrap_or":
            return ("unwrap_or_literal", i)
        if name == "unwrap_or_else":
            return ("unwrap_or_else", i)
        if name == "ok":
            nxt = args_end
            while nxt < n and masked[nxt] in " \t\r\n":
                nxt += 1
            if nxt < n and masked[nxt] == "?":
                return None
            return ("ok", i)
        i = args_end
    return None


def line_of(masked, off):
    return masked.count("\n", 0, off) + 1


def enclosing_fn(masked, off):
    """Name of the function containing `off`.

    Rebinding is gated on INDENTATION (check 74's fix): an inline helper defined
    mid-body must not steal the enclosing handler's name for everything below
    it, while a method inside an `impl` still starts a new function. A column-0
    `}` resets the tracker."""
    cur = None
    cur_indent = None
    for m in re.finditer(
        r"(?m)^([ \t]*)(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(" + IDENT + r")|^\}",
        masked,
    ):
        if m.start() > off:
            break
        if m.group(2) is None:
            cur, cur_indent = None, None
            continue
        indent = len(m.group(1).expandtabs(4))
        if cur_indent is None or indent <= cur_indent:
            cur, cur_indent = m.group(2), indent
    return cur or "?"


def callee(masked, off):
    """Best-effort name of the awaited call: the last `.ident(` before `.await`."""
    head = masked[max(0, off - 400):off]
    hits = re.findall(r"\.\s*(" + IDENT + r")\s*\(", head)
    if hits:
        return hits[-1]
    hits = re.findall(r"(" + IDENT + r")\s*\(", head)
    return hits[-1] if hits else "?"


def stmt_start(masked, off):
    """Scan back to the start of the enclosing statement (past ; { } at depth 0)."""
    i = off
    depth = 0
    while i > 0:
        c = masked[i - 1]
        if c in ")]}":
            depth += 1
        elif c in "([":
            if depth == 0:
                return i
            depth -= 1
        elif c == "{":
            if depth == 0:
                return i
            depth -= 1
        elif c == ";" and depth == 0:
            return i
        i -= 1
    return 0


# An arm that REFUSES or PROPAGATES is not a collapse.
#
# Deliberately NOT rejected: an arm that LOGS and then still substitutes a
# value. A logged default is still a default — the response says the same thing
# either way, and the response is what this inventory classifies. What IS
# rejected below (see `arm_yields_unknown`) is an arm whose value is an explicit
# UNKNOWN (`None`), because that is the three-valued shape #776 converted these
# sites INTO, and counting it would make the fix invisible to its own detector.
ARM_DEFAULT_REJECT = re.compile(
    r"\breturn\b|\?|\bbail!|\banyhow!|\bpanic!|\bunreachable!|\bErr\s*\(|"
    r"mcp_error|\.extend_safe|\bcontinue\b|\bbreak\b"
)


def arm_yields_unknown(arm):
    """True when the arm's VALUE is an explicit `None` — an UNKNOWN, not a default."""
    a = arm.strip().rstrip(",").strip()
    if a.startswith("{") and a.endswith("}"):
        a = a[1:-1]
    a = a.strip().rstrip(";").strip()
    last = a.split(";")[-1].strip() if ";" in a else a
    return last == "None"


def match_block_collapse(masked, off):
    """`match <read>.await { .. }` whose Err(_)/_ arm yields a value."""
    head = masked[stmt_start(masked, off):off]
    if not re.search(r"\bmatch\b", head):
        return None
    i = off
    n = len(masked)
    while i < n and masked[i] in " \t\r\n":
        i += 1
    if i >= n or masked[i] != "{":
        return None
    end = match_balanced(masked, i, "{", "}")
    if end is None:
        return None
    body = masked[i + 1:end - 1]
    # Arm headers must be at the TOP LEVEL of this match block. Without the
    # depth guard a `_ =>` inside a NESTED match in the `Ok` arm is read as this
    # match's default arm — measured as the dominant false positive (a run that
    # reported `analytics.rs` and eleven `ml.rs` sites whose real `Err` arms
    # return `internal(..)` / `mcp_error(..)`).
    tops = top_level_arm_spans(body)
    for start, stop in tops:
        head = body[start:stop].split("=>", 1)[0]
        if not re.match(r"\s*(Err\s*\(\s*(?:_|" + IDENT + r")\s*\)|_)\s*$", head):
            continue
        arm = body[start:stop].split("=>", 1)[1] if "=>" in body[start:stop] else ""
        if len(arm) > 2000:
            arm = arm[:2000]
        # A BRACELESS arm that binds the error and uses the binding is handling
        # it, not defaulting — `Err(e) => internal(req_id, "…", &e)` renders a
        # refusal as the match's tail expression, so there is no `return` for
        # ARM_DEFAULT_REJECT to see. Structural rather than a list of
        # error-builder names (check 74 records a hand-maintained name list as
        # its own rot mode). Restricted to braceless arms ON PURPOSE: a BRACED
        # `Err(e) => { warn!(error = %e, ..); false }` also uses the binding and
        # IS a collapse, so the unrestricted form silently dropped every
        # log-then-default site. Measured as the second dominant false positive:
        # eighteen sites, all `internal(..)` / `orchestration_error_to_response(..)`.
        bind = re.match(r"\s*Err\s*\(\s*(" + IDENT + r")\s*\)", head)
        braceless = not arm.strip().startswith("{")
        if bind and braceless and re.search(r"\b" + re.escape(bind.group(1)) + r"\b", arm):
            continue
        if arm_yields_unknown(arm):
            continue
        if not ARM_DEFAULT_REJECT.search(arm):
            return ("match_default", off)
    return None


def top_level_arm_spans(body):
    """(start, end) of each TOP-LEVEL arm of a match body (header + value)."""
    spans = []
    depth = 0
    start = 0
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            spans.append((start, i))
            start = i + 1
        i += 1
    if start < n and body[start:].strip():
        spans.append((start, n))
    return spans


def binding_collapse(masked, off):
    """`if let Ok(..) = <read>.await` / `let Ok(..) = <read>.await else`."""
    head = masked[stmt_start(masked, off):off]
    if re.search(r"\bif\s+let\s+Ok\s*\(", head):
        # `if let Ok(..) = read().await { .. } else { .. }` has classified the
        # failure; only the else-less form silently drops it.
        i = off
        n = len(masked)
        while i < n and masked[i] in " \t\r\n":
            i += 1
        if i < n and masked[i] == "{":
            end = match_balanced(masked, i, "{", "}")
            if end is not None:
                tail = masked[end:end + 40]
                if re.match(r"\s*else\b", tail):
                    return None
        return ("if_let_ok", off)
    if re.search(r"\blet\s+Ok\s*\(", head):
        tail = masked[off:off + 400]
        m = re.match(r"\s*else\s*\{", tail)
        if m:
            blk = match_balanced(masked, off + m.end() - 1, "{", "}")
            body = masked[off + m.end():blk - 1] if blk else tail
            if not ARM_DEFAULT_REJECT.search(body):
                return ("let_else", off)
    return None


def scan(path):
    src = open(path, encoding="utf-8", errors="replace").read()
    masked = mask(src)
    spans = cfg_test_spans(masked)
    sites = []
    for m in re.finditer(r"\.\s*await\b", masked):
        off = m.start()
        if any(a <= off < b for a, b in spans):
            continue
        hit = walk_chain(masked, m.end())
        if hit is None:
            hit = match_block_collapse(masked, m.end())
        if hit is None:
            hit = binding_collapse(masked, off)
        if hit is None:
            continue
        sites.append(
            {
                "file": path,
                "line": line_of(masked, off),
                "spelling": hit[0],
                "callee": callee(masked, off),
                "function": enclosing_fn(masked, off),
            }
        )
    return sites


def main():
    argv = sys.argv[1:]
    root = "."
    roots = DEFAULT_ROOTS
    as_json = "--json" in argv
    summary = "--summary" in argv
    rest = [a for a in argv if not a.startswith("--")]
    if rest:
        root = rest[0]
    for a in argv:
        if a.startswith("--roots="):
            roots = a.split("=", 1)[1].split(",")

    sites = []
    for r in roots:
        base = os.path.join(root, r)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in sorted(filenames):
                if not fn.endswith(".rs"):
                    continue
                p = os.path.join(dirpath, fn)
                if is_test_file(p):
                    continue
                sites.extend(scan(p))
    sites.sort(key=lambda s: (s["file"], s["line"]))

    if as_json:
        print(json.dumps(sites, indent=1))
        return
    counts = {}
    for s in sites:
        counts[s["spelling"]] = counts.get(s["spelling"], 0) + 1
    if not summary:
        for s in sites:
            print(
                "{}:{}\t{}\t{}\t{}".format(
                    s["file"], s["line"], s["spelling"], s["callee"], s["function"]
                )
            )
    print("--- {} sites".format(len(sites)))
    for k in sorted(counts, key=lambda k: -counts[k]):
        print("    {:20s} {}".format(k, counts[k]))


if __name__ == "__main__":
    main()
