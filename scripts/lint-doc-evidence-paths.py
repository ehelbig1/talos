#!/usr/bin/env python3
"""Check 92 (package BU): a code path cited as evidence in an auditor-facing
document must name a file that exists and holds the evidence.

Scope is DERIVED, not listed: every Markdown file under `docs/` carrying a
`**Classification:**` header line (the SOC 2 control mapping, the security
architecture, the threat models, the pentest scope). A citation is a
backticked repo-relative path with at least one directory and a source or
config extension, optionally suffixed `::<symbol>` and/or `:<line>` (the
`::<symbol>` form was invisible to the first draft, which left one moved path
in place).

Two findings:
  missing  — the path does not exist (code moved in the May-2026 workspace
             decomposition and the citation did not follow).
  shim     — the path is a `.rs` file whose every non-comment line is an
             attribute, `use` / `pub use`, `mod` or a brace: a re-export that
             holds none of the evidence it is cited for.
Measured 2026-09-16 on the tree before the repair, with the same scope: 120
findings (57 missing, 63 shim) over 150 citations in five documents; 0 after
over 155 citations.

Exit 1 on findings; exit 2 (loud) when no document is in scope or no
citation is found — a check over zero citations is a green tick over nothing.
Stated limits: existence and shape only — a cited file that exists but no
longer contains the named function, a stale `:<line>` suffix, and a wrong
claim in the prose beside a correct path all pass."""
import os, re, sys

root = sys.argv[1] if len(sys.argv) > 1 else '.'
CITE = re.compile(r'`((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.(?:rs|sql|sh|ya?ml|toml|md|ts|tsx|conf|py|json))(?:::[A-Za-z_][A-Za-z0-9_:]*)?(?::\d+(?:-\d+)?)?`')
SHIM_LINE = re.compile(r'^\s*(#!?\[.*\]|(pub(\([a-z]+\))? )?use [^;]*;|(pub )?mod \w+;|pub mod \w+ \{|\})\s*$')

def classified_docs():
    out = []
    for dirpath, _, names in os.walk(os.path.join(root, 'docs')):
        for n in names:
            if not n.endswith('.md'):
                continue
            p = os.path.join(dirpath, n)
            with open(p, encoding='utf-8') as fh:
                if any(l.startswith('**Classification:**') for l in fh):
                    out.append(os.path.relpath(p, root))
    return sorted(out)

def is_shim(path):
    if not path.endswith('.rs'):
        return False
    body = [l for l in open(os.path.join(root, path), encoding='utf-8')
            if l.strip() and not l.strip().startswith('//')]
    return bool(body) and all(SHIM_LINE.match(l) for l in body)

docs = classified_docs()
if not docs:
    print('✗ no docs/**/*.md carries a **Classification:** header — the check has nothing to read')
    sys.exit(2)
cites = findings = 0
for d in docs:
    for i, line in enumerate(open(os.path.join(root, d), encoding='utf-8'), 1):
        for m in CITE.finditer(line):
            cites += 1
            p = m.group(1)
            if not os.path.exists(os.path.join(root, p)):
                print(f'{d}:{i}: `{p}` does not exist'); findings += 1
            elif is_shim(p):
                print(f'{d}:{i}: `{p}` is a re-export shim — cite the file that holds the code'); findings += 1
if cites == 0:
    print(f'✗ {len(docs)} classified doc(s) and zero citations — the pattern matches nothing')
    sys.exit(2)
print(f'  {cites} citation(s) across {len(docs)} classified doc(s)')
sys.exit(1 if findings else 0)
