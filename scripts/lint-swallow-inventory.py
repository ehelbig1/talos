#!/usr/bin/env python3
"""Enumerate `let _ = <expr>.await` swallow sites across the workspace.

Handles multi-line statements: a `let _ =` line starts a statement that ends at
the first line whose trailing (comment-stripped) text ends in `;` at depth 0.
Classifies each site as TEST or NON-TEST:
  - file is a test file (tests/ dir, *_tests.rs, tests.rs, test_support.rs, benches/, examples/)
  - or the site sits inside a `#[cfg(test)] mod` region (col-0 `mod` ... to col-0 `}`)
Also flags whether the swallowed expression is raw sqlx (what check 10 sees).
"""
import os, re, sys, json

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
SKIP_DIRS = {"target", ".git", "node_modules", ".claude"}

def is_test_file(path):
    p = path.replace(os.sep, "/")
    if "/tests/" in p or "/benches/" in p or "/examples/" in p:
        return True
    b = os.path.basename(p)
    return b.endswith("_tests.rs") or b == "tests.rs" or b == "test_support.rs"

def cfg_test_regions(lines):
    """Return list of (start_idx, end_idx) 0-based inclusive for #[cfg(test)] mod blocks
    detected at column 0 (conservative; ends at first column-0 '}')."""
    regions = []
    i = 0
    n = len(lines)
    while i < n:
        if re.match(r'^#\[cfg\(test\)\]', lines[i]):
            # find the mod line
            j = i + 1
            while j < n and not re.match(r'^(pub\s+)?mod\s', lines[j]) and j < i + 4:
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

def strip_comment(s):
    # crude: drop // ... when not inside a string. good enough for statement-end detection
    out = []
    in_str = False
    esc = False
    i = 0
    while i < len(s):
        c = s[i]
        if in_str:
            if esc: esc = False
            elif c == '\\': esc = True
            elif c == '"': in_str = False
            out.append(c)
        else:
            if c == '"':
                in_str = True; out.append(c)
            elif c == '/' and i + 1 < len(s) and s[i+1] == '/':
                break
            else:
                out.append(c)
        i += 1
    return ''.join(out)

sites = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in filenames:
        if not fn.endswith(".rs"):
            continue
        path = os.path.join(dirpath, fn)
        rel = os.path.relpath(path, ROOT)
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
        except Exception:
            continue
        regions = cfg_test_regions(lines)
        for idx, line in enumerate(lines):
            ls = line.lstrip()
            if ls.startswith('//') or ls.startswith('*') or ls.startswith('///'):
                continue
            if not re.search(r'(^|[^\w.])let\s+_\s*=', line):
                continue
            # gather statement
            stmt_lines = [line]
            j = idx
            depth = 0
            while j < len(lines):
                s = strip_comment(lines[j])
                depth += s.count("(") + s.count("[") + s.count("{")
                depth -= s.count(")") + s.count("]") + s.count("}")
                if s.rstrip().endswith(";") and depth <= 0:
                    break
                j += 1
                if j - idx > 40:
                    break
                stmt_lines.append(lines[j] if j < len(lines) else "")
            stmt = "\n".join(stmt_lines)
            if ".await" not in stmt:
                continue
            in_cfg_test = any(a <= idx <= b for a, b in regions)
            sites.append({
                "file": rel,
                "line": idx + 1,
                "end_line": j + 1,
                "test_file": is_test_file(rel),
                "in_cfg_test": in_cfg_test,
                "raw_sqlx": bool(re.search(r'sqlx::query', stmt)),
                "stmt": stmt.strip(),
            })

sites.sort(key=lambda s: (s["file"], s["line"]))
print(json.dumps(sites, indent=1))
