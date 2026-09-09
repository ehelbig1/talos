#!/usr/bin/env python3
r"""Find mid-sentence WHITESPACE RUNS inside Rust string literals.

A MEASUREMENT tool, not a lint, and deliberately so — see the bottom of this
docstring for the numbers that reject a gate.

# The defect

The house style for a long literal is a `\`-continuation, which renders as ONE
space: the escape eats the newline AND the next line's indentation. A
continuation that LOSES its `\` keeps both, and the indentation reaches the
rendered string. That has now shipped into operator-facing output three times
(RFC 0012 P3's 27 lines; package 23's 4 literals; and, on 2026-09-08,
`get_platform_hygiene_report`'s cleanup recommendation, which rendered a run of
23 spaces mid-sentence to a live operator).

**The CAUSE, established 2026-09-08 by reproducing it twice while fixing it**: a
`\` at the end of a line inside a Python `'''…'''` string is a PYTHON line
continuation, so an edit script that writes Rust `\`-continuations through a
non-raw triple-quoted string silently eats them. Use a raw string.

# Why a line grep cannot see it

The run spans the continuation join, so the source line carries only part of it.
This walker resolves each literal instead: escapes applied (`\n` becomes a REAL
newline — without that, embedded WAT, Go and Python scaffolds read as prose),
char literals skipped (without that a `'"'` desyncs the scanner and it reports
~700 hits), raw strings handled, and a run that FOLLOWS a newline inside the
literal is EXCLUDED as the deliberate indentation of a multi-line literal.

# Why there is no lint (measured 2026-09-08, both trees)

|                     | ≥5-space runs | mid-sentence prose | distinct literals | defects |
|---------------------|---------------|--------------------|-------------------|---------|
| `origin/main` 1ded89ac | 200        | 14                 | 6                 | 5       |
| fixed                  | 185        | 1                  | 1                 | 0       |

A rule scoped by the run alone is ~2.5% precision. The mid-sentence narrowing
(the `--prose` filter below) still ships at ONE marker on correct code — an
aligned CLI help column in `talos-offhost-backup` — and telling prose from an
aligned SQL column or a help column is a judgement a grep cannot make. Package
23 reached the same conclusion from the same shape of numbers.

Usage:
    python3 scripts/lint-whitespace-runs.py [ROOT ...]      # every run
    python3 scripts/lint-whitespace-runs.py --prose [ROOT]  # mid-sentence only
"""
import os, re, sys

MINRUN = 5
SKIP_DIRS = {"target", ".git", "node_modules", ".claude", "vendor"}
roots = [a for a in sys.argv[1:] if not a.startswith("--")] or ["."]


def literals(src):
    """Yield (line, resolved_text, raw_slice) for each Rust string literal."""
    i, n = 0, len(src)
    line = 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 0
            while i < n:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1; i += 2; continue
                if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1; i += 2
                    if depth == 0: break
                    continue
                if src[i] == "\n": line += 1
                i += 1
            continue
        if c == "r" and i + 1 < n and src[i + 1] in '#"':
            j = i + 1; h = 0
            while j < n and src[j] == "#":
                h += 1; j += 1
            if j < n and src[j] == '"':
                close = '"' + "#" * h
                end = src.find(close, j + 1)
                end = n if end == -1 else end + len(close)
                body = src[j + 1:end - len(close)]
                yield (line, body, src[i:end], True)
                line += src.count("\n", i, end)
                i = end
                continue
        if c == "'":
            m = re.match(r"'(\\.|[^\\'])'", src[i:])
            if m:
                i += m.end()
                continue
            i += 1
            continue
        if c == '"':
            j = i + 1
            out = []
            start_line = line
            while j < n:
                if src[j] == "\\":
                    nxt = src[j + 1] if j + 1 < n else ""
                    if nxt == "\n":
                        line += 1
                        j += 2
                        while j < n and src[j] in " \t":
                            j += 1
                        continue
                    # Resolve the escapes that MATTER for this question: a
                    # `\n` is a real newline for the "is this run at the start
                    # of a line?" test, and treating it as two literal
                    # characters is what made the first run of this walker
                    # report ascii art and embedded WAT as prose.
                    out.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, "\\" + nxt))
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                if src[j] == "\n":
                    line += 1
                out.append(src[j])
                j += 1
            yield (start_line, "".join(out), src[i:j], False)
            i = j
            continue
        i += 1


run = re.compile(r"[^\S\n]{%d,}" % MINRUN)
hits = []
for root in roots:
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in sorted(fn):
            if not f.endswith(".rs"):
                continue
            p = os.path.join(dp, f)
            try:
                src = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for line, text, raw, is_raw in literals(src):
                for m in run.finditer(text):
                    # MID-LINE only. A run that FOLLOWS a newline inside the
                    # literal is deliberate indentation of a multi-line literal
                    # (SQL, a here-doc-style block) and is not this defect; the
                    # defect is indentation that survived a LOST `\` and now
                    # sits in the middle of a sentence.
                    before = text[:m.start()]
                    if before.endswith("\n") or before == "":
                        continue
                    ctx = text[max(0, m.start() - 45):m.end() + 45].replace("\n", "\\n")
                    hits.append((p, line, len(m.group(0)), ctx))
prose_only = "--prose" in sys.argv
prose = re.compile(r"([A-Za-z,\.\)`\u2014])\s{9,}([a-z`])")
shown = 0
for p, line, ln, ctx in hits:
    if prose_only and (ln < 9 or not prose.search(ctx)):
        continue
    shown += 1
    print("%s:%d  run=%d  \u2026%s\u2026" % (p, line, ln, ctx))
if prose_only:
    print("--- %d mid-sentence prose hits (of %d literals with a >=%d-space run)"
          % (shown, len(hits), MINRUN))
else:
    print("--- %d literals with a >=%d-space run" % (len(hits), MINRUN))
