#!/usr/bin/env python3
"""Check 91 (package AU): a tracing macro that carries a vault key path
(`key_path` / `vault_path` / `secret_path` / `*_token_path` — and a bare
`path` inside `talos-secrets/` and `talos-oauth/`, where a path IS a vault path)
must render it through `talos_workflow_job_protocol::redact_vault_path_for_log`
(or `redact_oauth_provider_key_for_log`), named in the statement or within
the 8 lines above. An OAuth path's fourth segment is the provider key — for
gmail the account's email address — and the worker's `secret.resolve` line
fires on every secret a module resolves.

Statement-aware: the macro's parenthesised argument list is gathered whole,
string literals are blanked before the field scan (so `event_kind =
"…key_paths_failed"` cannot match), whole-line comments and column-0
`#[cfg(test)] mod` regions are blanked first. Opt-out
`// allow-raw-vault-path-log: <reason>` within 8 lines above.
Exit 1 on findings; exit 2 (loud) if the scan matched NO tracing statement
at all — a check over zero statements is a green tick over nothing."""
import re, subprocess, sys
root = sys.argv[1] if len(sys.argv) > 1 else '.'
files=[p for p in subprocess.run(['git','ls-files','*.rs'],cwd=root,capture_output=True,text=True).stdout.split()
       if '/tests/' not in '/'+p and not p.endswith('_tests.rs') and '/examples/' not in p
       and '/benches/' not in p and not p.startswith('module-templates/')]
MACRO=re.compile(r'\b(?:tracing::)?(?:trace|debug|info|warn|error)!\(')
FIELD=re.compile(r'(?<![\w.])(?:key_path|vault_path|secret_path|[a-z_]*_token_path)\b')
BARE_PATH=re.compile(r'(?<![\w.])path\b')
BARE_PATH_CRATES=('talos-secrets/','talos-oauth/')   # where a bare `path` IS a vault key path; the manager names its `key_path`
REDACTOR=re.compile(r'redact_vault_path_for_log|redact_oauth_provider_key_for_log')
# string literals — `re.S` so a `\`-newline continuation inside a message stays
# INSIDE the literal (without it the rest of the message leaked into the field
# scan and prose like "the key_path" matched: 31 false positives on the first run)
STR=re.compile(r'r#"(?:[^"]|"(?!#))*"#|"(?:\\.|[^"\\])*"', re.S)

def strip_test_mods(lines):
    out=list(lines); i=0
    while i < len(out):
        if out[i].startswith('#[cfg(test)]'):
            j=i+1
            while j < len(out) and out[j].strip()=='' : j+=1
            if j < len(out) and re.match(r'(pub(\(crate\))? )?mod\b', out[j]):
                k=j
                while k < len(out) and out[k] != '}': k+=1
                for x in range(i, min(k+1,len(out))): out[x]=''
                i=k
        i+=1
    return out

def statement(t, start):
    # gather from the macro's '(' to its matching ')' — skipping string literals
    i=t.index('(', start); depth=0; j=i
    while j < len(t):
        ch=t[j]
        if ch=='"':
            m=STR.match(t, j)
            if m: j=m.end(); continue
        if ch=='(': depth+=1
        elif ch==')':
            depth-=1
            if depth==0: return t[start:j+1]
        j+=1
    return t[start:start+600]

finds=[]; scanned=0
for p in files:
    raw=open(f'{root}/{p}',encoding='utf-8',errors='ignore').read()
    lines=raw.split('\n')
    lines=[re.sub(r'^(\s*)//.*$', r'\1', l) for l in lines]
    lines=strip_test_mods(lines)
    t='\n'.join(lines)
    bare_ok = p.startswith(BARE_PATH_CRATES)
    for m in MACRO.finditer(t):
        stmt=statement(t, m.start()); scanned+=1
        body=STR.sub('""', stmt)
        hit=FIELD.search(body) or (bare_ok and BARE_PATH.search(body))
        if not hit: continue
        ln=t[:m.start()].count('\n')+1
        window='\n'.join(raw.split('\n')[max(0,ln-9):ln+stmt.count('\n')+1])
        if REDACTOR.search(stmt) or REDACTOR.search('\n'.join(raw.split('\n')[max(0,ln-9):ln-1])): continue
        if 'allow-raw-vault-path-log' in window: continue
        finds.append(f"{p}:{ln}: log field `{hit.group(0)}` is a vault key path rendered raw — wrap it in talos_workflow_job_protocol::redact_vault_path_for_log")
if scanned == 0:
    print("  scan matched no tracing statement at all — the detector is broken, not the tree"); sys.exit(2)
for f in finds: print(f)
print(f"  {len(finds)} raw vault-path log field(s) over {scanned} tracing statement(s)")
sys.exit(1 if finds else 0)
