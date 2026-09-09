#!/usr/bin/env python3
"""Statement-aware inventory of every `mcp_error(...)` construction site.

Written for package 35 because three line-based methods gave three different
counts (408 / 589 / 649): `mcp_error(` appears in doc comments, in prose, in
string literals and in test fixtures, and a regex that does not mask those
counts them.

Method, following `scripts/lint-swallow-classify.py` (the house precedent):

  * comment and string/char-literal CONTENT is masked first, replaced by
    spaces of the same length so byte offsets and line numbers survive — a doc
    comment quoting `mcp_error(-32000, ...)` therefore cannot self-report
    (check 73's trap);
  * a call site is an identifier `mcp_error` (optionally path-qualified)
    immediately followed by `(`, matched on the MASKED text, with the argument
    list walked by a paren matcher that is depth-aware and, because the mask
    removed string content, cannot be confused by a `)` inside a message;
  * arguments are then split at depth-0 commas, and the ORIGINAL (unmasked)
    source is sliced at those same offsets so the literal code and the message
    text can be read;
  * `#[cfg(test)] mod` regions at column 0 are recorded so test sites can be
    counted separately rather than silently included or silently dropped.

Usage:
  python3 scripts/mcp-error-inventory.py [--json] [--by-code] [--code -32000]
                                         [--roots a,b,c] [--include-tests]
"""
import argparse
import json
import os
import re
import sys

DEFAULT_ROOTS = ["talos-mcp-handlers/src", "talos-mcp/src", "talos-api/src", "controller/src"]
SKIP_DIRS = {"target", ".git", "node_modules", ".claude", "vendor"}


def mask(src):
    """Replace comment and string/char-literal CONTENT with spaces.

    Newlines preserved so line numbers survive. Handles //, /* */ (nested),
    "..." with escapes, r"..." / r#"..."#, and 'c' char literals (lifetimes
    carry no closing quote and are left alone)."""
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


def match_balanced(s, i):
    """s[i] == '(' -> index just past the matching ')', else None."""
    if i >= len(s) or s[i] != "(":
        return None
    depth = 0
    while i < len(s):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def split_args(masked_args, base):
    """Depth-0 comma split over the MASKED arg text; returns (start, end) offsets
    relative to `base` in the ORIGINAL source."""
    spans, depth, start = [], 0, 0
    for k, ch in enumerate(masked_args):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            spans.append((base + start, base + k))
            start = k + 1
    spans.append((base + start, base + len(masked_args)))
    return spans


def is_test_file(path):
    p = path.replace(os.sep, "/")
    if "/tests/" in p or "/benches/" in p or "/examples/" in p:
        return True
    b = os.path.basename(p)
    return b.endswith("_tests.rs") or b in ("tests.rs", "test_support.rs")


# Every constructor that builds an MCP tool-error response. They emit
# BYTE-IDENTICAL wire output and differ only in the `McpErrorKind` they carry,
# so the inventory must see all of them or its "unclassified" count is a lie.
CTORS = ("mcp_error", "mcp_error_kind", "mcp_denied", "mcp_not_found", "mcp_failed")
CALL = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*(" + "|".join(CTORS) + r")\s*\("
)
DEFN = re.compile(r"fn\s+(?:" + "|".join(CTORS) + r")\s*\($")


def enclosing_fn(masked, off):
    best = None
    for m in re.finditer(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)", masked):
        if m.start() > off:
            break
        best = m.group(1)
    return best or "?"


def scan_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()
    masked = mask(src)
    tspans = cfg_test_spans(masked)
    line_of = [0] * (len(src) + 1)
    ln = 1
    for i, ch in enumerate(src):
        line_of[i] = ln
        if ch == "\n":
            ln += 1
    line_of[len(src)] = ln
    out = []
    for m in CALL.finditer(masked):
        open_i = m.end() - 1
        if DEFN.search(masked[max(0, m.start() - 20): m.end()]):
            continue
        close = match_balanced(masked, open_i)
        if close is None:
            continue
        args_masked = masked[open_i + 1: close - 1]
        spans = split_args(args_masked, open_i + 1)
        raw = [src[a:b].strip() for a, b in spans]
        ctor = m.group(1)
        code = raw[1] if len(raw) > 1 else ""
        # `mcp_error_kind` takes (id, code, kind, msg); the rest take
        # (id, code, msg).
        msg = (raw[3] if len(raw) > 3 else "") if ctor == "mcp_error_kind" else (
            raw[2] if len(raw) > 2 else ""
        )
        kind = {
            "mcp_denied": "Denied",
            "mcp_not_found": "NotFound",
            "mcp_failed": "Failed",
            "mcp_error_kind": raw[2].split("::")[-1] if len(raw) > 2 else "?",
        }.get(ctor, "")
        in_test = any(a <= m.start() < b for a, b in tspans) or is_test_file(path)
        out.append({
            "file": path,
            "line": line_of[m.start()],
            "ctor": ctor,
            "kind": kind,
            "code": code,
            "msg": msg,
            "fn": enclosing_fn(masked, m.start()),
            "test": in_test,
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--roots", default=",".join(DEFAULT_ROOTS))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--by-code", action="store_true")
    ap.add_argument("--by-kind", action="store_true")
    ap.add_argument("--unclassified", action="store_true")
    ap.add_argument("--code")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--all-roots", action="store_true", help="scan the whole workspace")
    a = ap.parse_args()

    roots = ["."] if a.all_roots else a.roots.split(",")
    sites = []
    for root in roots:
        if os.path.isfile(root):
            sites += scan_file(root)
            continue
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in SKIP_DIRS]
            for f in fn:
                if f.endswith(".rs"):
                    sites += scan_file(os.path.join(dp, f))

    prod = [s for s in sites if not s["test"]]
    tests = [s for s in sites if s["test"]]
    sel = sites if a.include_tests else prod
    if a.code:
        sel = [s for s in sel if s["code"] == a.code]
    if a.unclassified:
        sel = [s for s in sel if not s["kind"]]

    if a.json:
        print(json.dumps(sel, indent=1))
        return
    if a.by_kind:
        from collections import Counter
        c = Counter(s["kind"] or "(unclassified)" for s in prod)
        for k, v in sorted(c.items(), key=lambda kv: -kv[1]):
            print(f"{v:6d}  {k}")
        print(f"{'-' * 6}")
        print(f"{len(prod):6d}  TOTAL production")
        return
    if a.by_code:
        from collections import Counter
        c = Counter(s["code"] for s in prod)
        for k, v in sorted(c.items(), key=lambda kv: -kv[1]):
            print(f"{v:6d}  {k}")
        print(f"{'-'*6}")
        print(f"{len(prod):6d}  TOTAL production")
        print(f"{len(tests):6d}  (test sites, excluded)")
        return
    for s in sel:
        msg = " ".join(s["msg"].split())
        print(f'{s["file"]}:{s["line"]}\t{s["code"]}\t{s["kind"] or "-"}\t{s["fn"]}\t{msg[:130]}')
    print(f"# {len(sel)} sites", file=sys.stderr)


if __name__ == "__main__":
    main()
