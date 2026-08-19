#!/usr/bin/env python3
"""Enumerate `.try_get(...).ok()` column reads — check 52's forbidden shape in a
spelling neither of its two passes can see.

`row.try_get("col").ok()` is IDENTICAL IN EFFECT to the
`row.try_get("col").unwrap_or(default)` that check 52 forbids workspace-wide: a
renamed / dropped / retyped column produces `Err`, `.ok()` turns it into `None`,
and the caller cannot distinguish that from a legitimate SQL NULL. Check 52's
regex mentions `.unwrap_or` only, and 52b's perl pass mentions it too, so this
spelling is invisible to both on one line or many.

The correct form for a genuinely NULLable column is
`.try_get::<Option<_>, _>("col")?` — NULL still yields `None`, drift still
errors.

Matching is BALANCED-PAREN over a comment-stripped, whitespace-collapsed view of
each file, so a chain broken across lines (the house style, and what made #660's
line-based count 59 when the truth was 109) is found the same as a one-liner.

Recorded per site:
  col        -- the literal column name, when the argument is a string literal
  tail       -- what immediately follows `.ok()` (`.flatten()`, `.and_then(`, ...)
  multiline  -- the `try_get(...)` and its `.ok()` are on different lines
  test_file / in_cfg_test -- excluded from the production count, same rules as
                            #660/#661

Usage:  python3 scripts/lint-tryget-ok-inventory.py [ROOT] > sites.json
"""
import os
import re
import sys
import json

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
SKIP_DIRS = {"target", ".git", "node_modules", ".claude", "dist", "build"}

TRY_GET = re.compile(r'\.try_get(?:_unchecked)?')
OK_CALL = re.compile(r'\A\s*\.\s*ok\s*\(\s*\)')


def skip_turbofish(s, i):
    """If s[i:] starts with `::<...>` (angle brackets may NEST — `::<Option<i64>,
    _>` is the common shape and a non-nesting `[^>]*>` regex stops at the FIRST
    `>`, which is how a first pass under-counted by one), return the index just
    past the closing `>`. Otherwise return i unchanged."""
    m = re.match(r'\s*::\s*<', s[i:])
    if not m:
        return i
    j = i + m.end() - 1  # index of '<'
    depth = 0
    while j < len(s):
        c = s[j]
        if c == '<':
            depth += 1
        elif c == '>':
            depth -= 1
            if depth == 0:
                return j + 1
        elif c in '(){};':
            return i  # not a turbofish after all
        j += 1
    return i


def is_test_file(path):
    p = path.replace(os.sep, "/")
    if "/tests/" in p or "/benches/" in p or "/examples/" in p:
        return True
    b = os.path.basename(p)
    return b.endswith("_tests.rs") or b == "tests.rs" or b == "test_support.rs"


def cfg_test_regions(lines):
    """(start,end) 0-based inclusive for column-0 `#[cfg(test)] mod` blocks.
    Conservative: ends at the first column-0 '}'. Over-stripping is the unsafe
    direction, so the region is allowed to end early."""
    regions, i, n = [], 0, len(lines)
    while i < n:
        if re.match(r'^#\[cfg\(test\)\]', lines[i]):
            j = i + 1
            while j < n and j < i + 4 and not re.match(r'^(pub\s+)?mod\s', lines[j]):
                j += 1
            if j < n and re.match(r'^(pub\s+)?mod\s', lines[j]):
                k = j + 1
                while k < n and not re.match(r'^\}', lines[k]):
                    k += 1
                regions.append((i, min(k, n - 1)))
                i = k + 1
                continue
        i += 1
    return regions


def blank_comments_and_strings(src):
    """Return src with line comments, block comments and string-literal BODIES
    replaced by spaces, preserving length and newlines so offsets still map to
    lines. String bodies are blanked so a `//` or `)` inside a literal cannot
    confuse the scan; the quotes themselves are kept so a column name can still
    be recovered from the ORIGINAL text by offset."""
    out = list(src)
    i, n = 0, len(src)
    state = None  # None | 'line' | 'block' | 'str' | 'raw'
    raw_hashes = 0
    while i < n:
        c = src[i]
        if state is None:
            if c == '/' and i + 1 < n and src[i + 1] == '/':
                state = 'line'
                out[i] = out[i + 1] = ' '
                i += 2
                continue
            if c == '/' and i + 1 < n and src[i + 1] == '*':
                state = 'block'
                out[i] = out[i + 1] = ' '
                i += 2
                continue
            if c == 'r' and i + 1 < n and src[i + 1] in '#"':
                j = i + 1
                h = 0
                while j < n and src[j] == '#':
                    h += 1
                    j += 1
                if j < n and src[j] == '"':
                    state, raw_hashes = 'raw', h
                    i = j + 1
                    continue
            if c == '"':
                state = 'str'
                i += 1
                continue
            if c == "'" and i + 2 < n and (src[i + 2] == "'" or (src[i + 1] == '\\')):
                # char literal; blank its body
                j = i + 1
                while j < n and src[j] != "'" and src[j] != '\n':
                    if src[j] == '\\':
                        j += 1
                    out[j] = ' '
                    j += 1
                i = j + 1
                continue
            i += 1
            continue
        if state == 'line':
            if c == '\n':
                state = None
            else:
                out[i] = ' '
            i += 1
            continue
        if state == 'block':
            if c == '*' and i + 1 < n and src[i + 1] == '/':
                out[i] = out[i + 1] = ' '
                state = None
                i += 2
                continue
            if c != '\n':
                out[i] = ' '
            i += 1
            continue
        if state == 'str':
            if c == '\\':
                out[i] = ' '
                if i + 1 < n and src[i + 1] != '\n':
                    out[i + 1] = ' '
                i += 2
                continue
            if c == '"':
                state = None
                i += 1
                continue
            if c != '\n':
                out[i] = ' '
            i += 1
            continue
        if state == 'raw':
            if c == '"':
                j = i + 1
                h = 0
                while j < n and src[j] == '#' and h < raw_hashes:
                    h += 1
                    j += 1
                if h == raw_hashes:
                    state = None
                    i = j
                    continue
            if c != '\n':
                out[i] = ' '
            i += 1
            continue
    return ''.join(out)


def match_paren(s, open_idx):
    """Index of the ')' matching the '(' at open_idx, or -1."""
    depth = 0
    for i in range(open_idx, len(s)):
        c = s[i]
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
            if depth == 0:
                return i
    return -1


def line_of(offsets, pos):
    """1-based line number for byte offset pos, via precomputed newline table."""
    lo, hi = 0, len(offsets) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if offsets[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


sites = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in sorted(filenames):
        if not fn.endswith(".rs"):
            continue
        path = os.path.join(dirpath, fn)
        rel = os.path.relpath(path, ROOT)
        try:
            src = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        if ".try_get" not in src:
            continue
        code = blank_comments_and_strings(src)
        lines = src.split("\n")
        regions = cfg_test_regions(lines)
        # newline offset table: offsets[k] = start offset of line k+1
        offsets = [0]
        for i, ch in enumerate(src):
            if ch == '\n':
                offsets.append(i + 1)

        for m in TRY_GET.finditer(code):
            after = skip_turbofish(code, m.end())
            om_open = re.match(r'\s*\(', code[after:])
            if not om_open:
                continue
            open_idx = after + om_open.end() - 1
            close_idx = match_paren(code, open_idx)
            if close_idx < 0:
                continue
            rest = code[close_idx + 1:close_idx + 40]
            om = OK_CALL.match(rest)
            if not om:
                continue
            arg = src[open_idx + 1:close_idx].strip()
            lit = re.fullmatch(r'"([^"]*)"', arg)
            col = lit.group(1) if lit else None
            ok_abs = close_idx + 1 + om.end()
            tail = src[ok_abs:ok_abs + 24].strip().split("\n")[0]
            l_try = line_of(offsets, m.start())
            # The line the `.ok` TOKEN sits on — NOT the line of the try_get's
            # closing paren. A first version measured the latter and reported
            # "0 multi-line" for a population that contains 7, because the house
            # style breaks the chain AFTER `("col")`, not inside it.
            l_ok = line_of(offsets, close_idx + 1 + om.start()
                           + len(om.group(0)) - len(om.group(0).lstrip()))
            idx0 = l_try - 1
            sites.append({
                "file": rel,
                "line": l_try,
                "ok_line": l_ok,
                "col": col,
                "arg": None if col else arg[:80],
                "tail": tail[:24],
                "multiline": l_ok != l_try,
                "test_file": is_test_file(rel),
                "in_cfg_test": any(a <= idx0 <= b for a, b in regions),
                "text": " ".join(src[m.start():ok_abs].split())[:160],
            })

sites.sort(key=lambda s: (s["file"], s["line"]))
print(json.dumps(sites, indent=1))
