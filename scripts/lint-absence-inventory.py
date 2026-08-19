#!/usr/bin/env python3
"""Enumerate error-as-absence sites: a fallible operation whose Err is converted
into `None` / an empty collection, so the caller cannot tell "absent" from
"could not tell".

Sibling of scripts/lint-swallow-inventory.py (#660), which covered the
*discard* shape (`let _ = <expr>.await`). This one covers the *absence* shape.

Anchors (the conversion itself):
  .unwrap_or(None)            Result<Option<T>,E> -> Option<T>
  .unwrap_or_else(|_| None)   same, closure form
  .ok()                       Result<T,E>         -> Option<T>
  .ok().flatten()             counted once, as .ok()
  .unwrap_or(<empty literal>) Result<Vec/Map,E>   -> empty collection
  .unwrap_or_else(|_| <empty literal>)

`unwrap_or_default()` is deliberately NOT an anchor (1127 sites, dominated by
legitimate config/Option handling — see docs/swallowed-results-inventory.md).

For each anchor the enclosing STATEMENT is reconstructed (the house style breaks
method chains across lines, which is what made #660's line-based count 59 when
the truth was 109), then two facts are recorded that the triage needs:

  io      -- the swallowed expression contains `.await` (DB / Redis / HTTP /
             NATS), i.e. an Err here is an infrastructure fault, not a
             malformed-input verdict.
  crypto  -- the expression names a decrypt/verify call.

Test files and `#[cfg(test)] mod` regions are excluded, same rules as #660.
"""
import os, re, sys, json

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
SKIP_DIRS = {"target", ".git", "node_modules", ".claude", "dist", "build"}

ANCHORS = [
    ("unwrap_or_none", re.compile(r'\.unwrap_or\(\s*None\s*\)')),
    ("unwrap_or_else_none", re.compile(r'\.unwrap_or_else\(\s*\|[^|]*\|\s*None\s*\)')),
    ("unwrap_or_empty", re.compile(
        r'\.unwrap_or(?:_else)?\(\s*(?:\|[^|]*\|\s*)?'
        r'(?:vec!\[\s*\]|Vec::new\(\)|HashMap::new\(\)|BTreeMap::new\(\)|'
        r'HashSet::new\(\)|String::new\(\)|""|Vec::with_capacity\(0\))\s*\)')),
    ("ok", re.compile(r'\.ok\(\)')),
]

# `.ok()` immediately followed by `;` is a pure DISCARD, not an absence
# conversion — that is #660's class, not this one. Recorded separately.
OK_DISCARD = re.compile(r'\.ok\(\)\s*;')


def is_test_file(path):
    p = path.replace(os.sep, "/")
    if "/tests/" in p or "/benches/" in p or "/examples/" in p:
        return True
    b = os.path.basename(p)
    return b.endswith("_tests.rs") or b == "tests.rs" or b == "test_support.rs"


def cfg_test_regions(lines):
    """(start,end) 0-based inclusive for column-0 `#[cfg(test)] mod` blocks.
    Conservative: ends at the first column-0 '}' (over-stripping would be the
    unsafe direction, so the region is allowed to end early)."""
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


def strip_comment(s):
    out, in_str, esc, i = [], False, False, 0
    while i < len(s):
        c = s[i]
        if in_str:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '"':
                in_str = False
            out.append(c)
        else:
            if c == '"':
                in_str = True
                out.append(c)
            elif c == '/' and i + 1 < len(s) and s[i + 1] == '/':
                break
            else:
                out.append(c)
        i += 1
    return ''.join(out)


def depth_delta(s):
    return (s.count("(") + s.count("[") + s.count("{")
            - s.count(")") - s.count("]") - s.count("}"))


def statement_bounds(lines, idx):
    """Reconstruct the statement containing line `idx`.

    Backwards: walk up while the running paren/bracket depth from the candidate
    start to `idx` is positive, or the previous line does not terminate a
    statement. Forwards: to the first line whose stripped text ends the
    statement at depth <= 0.
    """
    start = idx
    while start > 0:
        prev = strip_comment(lines[start - 1]).rstrip()
        if prev.endswith(";") or prev.endswith("{") or prev.endswith("}") or prev == "":
            break
        if prev.endswith("=>") or prev.lstrip().startswith("//"):
            break
        start -= 1
        if idx - start > 30:
            break
    end, depth = idx, 0
    for j in range(start, min(len(lines), idx + 40)):
        depth += depth_delta(strip_comment(lines[j]))
        s = strip_comment(lines[j]).rstrip()
        if j >= idx and depth <= 0 and (s.endswith(";") or s.endswith(",") or s.endswith("}")):
            end = j
            break
        end = j
    return start, end


sites = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in sorted(filenames):
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
            code = strip_comment(line)
            kinds = [k for k, rx in ANCHORS if rx.search(code)]
            if not kinds:
                continue
            # `.ok()` alone is only interesting when it is NOT a bare discard
            # and not shadowed by a stronger anchor on the same line.
            if kinds == ["ok"] and OK_DISCARD.search(code):
                kind = "ok_discard"
            else:
                kind = [k for k in kinds if k != "ok"][0] if len(kinds) > 1 else kinds[0]
            start, end = statement_bounds(lines, idx)
            stmt = "\n".join(lines[start:end + 1])
            sites.append({
                "file": rel,
                "line": idx + 1,
                "stmt_start": start + 1,
                "stmt_end": end + 1,
                "kind": kind,
                "test_file": is_test_file(rel),
                "in_cfg_test": any(a <= idx <= b for a, b in regions),
                "io": ".await" in stmt,
                "crypto": bool(re.search(r'decrypt|verify_|from_slice|from_str|parse', stmt)),
                "multiline": end > start,
                "stmt": stmt.strip(),
            })

sites.sort(key=lambda s: (s["file"], s["line"]))
print(json.dumps(sites, indent=1))
