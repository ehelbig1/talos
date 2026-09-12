#!/usr/bin/env python3
"""Candidate check (package AN): an `env::var("X")` read compared inline against a
boolean literal must go through `talos_config::bool_env_or_default` (or carry
`// allow-inline-env-bool: <reason>` within 8 lines above)."""
import re, subprocess, sys
root = sys.argv[1] if len(sys.argv) > 1 else '.'
files=[p for p in subprocess.run(['git','ls-files','*.rs'],cwd=root,capture_output=True,text=True).stdout.split()
       if '/tests/' not in '/'+p and not p.endswith('_tests.rs') and '/examples/' not in p and not p.startswith('module-templates/') and not p.startswith('talos-config/')]
rd=re.compile(r'env::var\(\s*"([A-Z][A-Z0-9_]+)"\s*\)')
lit=re.compile(r'"(1|0|true|false|yes|no|on|off)"', re.I)
finds=[]
for p in files:
    raw=open(f'{root}/{p}',encoding='utf-8',errors='ignore').read()
    t=re.sub(r'(?m)^(\s*)//.*$', lambda m: m.group(1), raw)   # blank comment lines, keep line count
    lines=t.split('\n')
    for m in rd.finditer(t):
        seg=t[m.end():m.end()+400]
        for stop in (';','{'):                       # same expression chain only: stop at a block or statement end
            c=seg.find(stop)
            if c>0: seg=seg[:c]
        # `match env::var("X") … { Some("1") | … => … }` — the block form: look inside the
        # first brace block that follows the read, arms only (up to the matching `}`).
        if not (lit.search(seg) and re.search(r'==|!=|matches!|eq_ignore_ascii_case|Some\("', seg)):
            after=t[m.end():m.end()+600]
            b=after.find('{')
            if b>=0 and 'match' in t[max(0,m.start()-40):m.start()]:
                depth=0; end=None
                for i,ch in enumerate(after[b:]):
                    depth += ch=='{'; depth -= ch=='}'
                    if depth==0: end=b+i; break
                block=after[b:end] if end else after[b:]
                if re.search(r'Some\("(1|0|true|false|yes|no|on|off)"\)|matches!\([^)]*"(1|0|true|false|yes|no|on|off)"', block, re.I):
                    seg=block
        if lit.search(seg) and re.search(r'==|!=|matches!|eq_ignore_ascii_case|Some\("|Ok\("', seg):
            ln=t[:m.start()].count('\n')+1
            above='\n'.join(raw.split('\n')[max(0,ln-9):ln])
            if 'allow-inline-env-bool' in above: continue
            finds.append(f"{p}:{ln}: `{m.group(1)}` parsed inline against {sorted(set(l.lower() for l in lit.findall(seg)))} — route through talos_config::bool_env_or_default")
for f in finds: print(f)
print(f"  {len(finds)} inline env-boolean parser(s)")
sys.exit(1 if finds else 0)
