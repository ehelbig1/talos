#!/usr/bin/env bash
# CANDIDATE LINT — BUILT, MEASURED and REJECTED (package 34, 2026-09-09).
# Kept, per #781's precedent, so the numbers can be re-derived rather than
# re-argued.
#
# THE RULE: "every Prometheus label value must come from a closed
# compile-time set" — the generalisation of this package's own security
# invariant (`actor_id` must never become a label; a caller-derived label
# value on a metric reachable from a NATS subject is an unbounded-cardinality
# DoS surface).
#
# THE DETECTOR: an argument inside `with_label_values(&[ … ])` that is neither
# a string literal nor an `Enum::variant.as_str()` / `x.as_str()` call.
#
# Usage:  bash scripts/lint-rpc-label-closure-candidate.sh [root]
set -uo pipefail
ROOT="${1:-.}"
python3 - "$ROOT" <<'PY'
import os, re, sys
root = sys.argv[1]
open_paren = re.compile(r'with_label_values\(&\[')
lit  = re.compile(r'^"[^"]*"$')
# "closed" spellings: a literal, anything ending in `.as_str()`, or a `&x` of one.
closed = re.compile(r'(^"[^"]*"$)|(\.as_str\(\)$)|(^&?[A-Za-z_][\w:]*\.as_str\(\)$)')
total = flagged = 0
rows = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in
                   {'.git', 'target', 'node_modules', 'vendor', '.claude'}]
    for fn in filenames:
        if not fn.endswith('.rs'):
            continue
        p = os.path.join(dirpath, fn)
        try:
            src = open(p, encoding='utf-8').read()
        except Exception:
            continue
        for m in open_paren.finditer(src):
            # balanced walk to the closing `]`
            i = m.end(); depth = 1; buf = ''
            while i < len(src) and depth > 0:
                c = src[i]
                if c == '[':
                    depth += 1
                elif c == ']':
                    depth -= 1
                    if depth == 0:
                        break
                buf += c; i += 1
            args, d, cur = [], 0, ''
            for c in buf:
                if c in '([{': d += 1
                elif c in ')]}': d -= 1
                if c == ',' and d == 0:
                    args.append(cur); cur = ''
                else:
                    cur += c
            if cur.strip():
                args.append(cur)
            for a in args:
                a = a.strip()
                total += 1
                if not closed.search(a):
                    flagged += 1
                    line = src[:m.start()].count('\n') + 1
                    rows.append(f"{p}:{line}: {a[:70]}")
print(f"label arguments inspected : {total}")
print(f"NOT provably closed       : {flagged}")
for r in sorted(rows):
    print("  " + r)
PY
