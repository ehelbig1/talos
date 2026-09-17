#!/usr/bin/env python3
"""Check 90 (packages AN, CB): an `env::var("X")` read compared inline against a
boolean literal must go through `talos_config::bool_env_or_default` (or carry
`// allow-inline-env-bool: <reason>` within 8 lines above)."""
import os, re, subprocess, sys

rd=re.compile(r'env::var\(\s*"([A-Z][A-Z0-9_]+)"\s*\)')
lit=re.compile(r'"(1|0|true|false|yes|no|on|off)"', re.I)
tok=r'(?:1|0|true|false|yes|no|on|off)'
alt=re.compile(r'"'+tok+r'"\s*\|\s*"'+tok+r'"', re.I)
cmpr=re.compile(r'(?:==|!=)\s*"'+tok+r'"|eq_ignore_ascii_case\("'+tok+r'"\)', re.I)
somecmp=re.compile(r'(?:==|!=)\s*Some\("(?:true|1)"\)', re.I)


def scan(sources):
    """sources: {path: raw text}. Returns the findings, one string each."""
    finds=[]
    for p, raw in sources.items():
        t=re.sub(r'(?m)^(\s*)//.*$', lambda m: m.group(1), raw)   # blank comment lines, keep line count
        lines=t.split('\n')
        for m in rd.finditer(t):
            seg=t[m.end():m.end()+400]
            # Same expression chain only: stop at the statement's `;` or at a block
            # `{` — except a closure body (`.map(|v| { … })`), whose `;`s belong to
            # the same expression. Package CB: stopping at that brace hid three
            # parsers of `.map(|v| { let v = …; matches!(…) })` shape.
            depth=0; cut=len(seg)
            for k,ch in enumerate(seg):
                if ch=='{':
                    # a closure over the VALUE (`|v| {`), not a fallback (`|_| {`)
                    if re.search(r'\|\s*[A-Za-z]\w*\s*\|\s*$', seg[:k]): depth+=1
                    elif depth==0: cut=k; break
                    else: depth+=1
                elif ch=='}' and depth>0: depth-=1
                elif ch==';' and depth==0: cut=k; break
            seg=seg[:cut]
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

    # Leg (b), package CB: a boolean token SET parsed anywhere outside talos-config —
    # the helper shape (`fn parse_opt_in(v: Option<&str>)`, `enabled != Some("true")`)
    # that leg (a) cannot see because the env read happens elsewhere. Fires on an
    # alternation of two tokens (`"1" | "true"`), a chain of comparisons naming two
    # distinct tokens within six lines, or an `== / != Some("true"|"1")` comparison.
    seen=set(f.split(': ',1)[0] for f in finds)
    for p, raw in sources.items():
        lines=[]; skip=False
        for l in raw.split('\n'):                       # drop column-0 #[cfg(test)] items, blank comment lines
            if not skip and l.startswith('#[cfg(test)]'): skip=True; lines.append(''); continue
            if skip:
                if l.startswith('}'): skip=False
                lines.append(''); continue
            lines.append(re.sub(r'^\s*//.*$','',l))
        rawl=raw.split('\n')
        for i,l in enumerate(lines):
            hit=alt.search(l) or somecmp.search(l)
            if not hit and cmpr.search(l):
                win='\n'.join(lines[max(0,i-6):i+7])
                hit=len(set(t.lower() for t in re.findall(r'(?:==|!=)\s*"('+tok+r')"|eq_ignore_ascii_case\("('+tok+r')"\)', win, re.I) for t in t if t))>=2
            if not hit: continue
            ln=i+1
            if f"{p}:{ln}" in seen: continue
            above='\n'.join(rawl[max(0,ln-9):ln])
            if 'allow-inline-env-bool' in above: continue
            seen.add(f"{p}:{ln}")
            finds.append(f"{p}:{ln}: a boolean token set parsed outside talos-config — route the env read through talos_config::bool_env / bool_env_or_default")

    return finds


def self_test():
    fixtures = {
        # must fire
        "a/closure_single_token.rs": 'fn f() -> bool {\n    std::env::var("X_A")\n        .map(|v| {\n            let v = v.trim();\n            v == "true"\n        })\n        .unwrap_or(false)\n}\n',
        "a/chain.rs": 'fn f() -> bool { std::env::var("X_B").map(|v| v == "1").unwrap_or(false) }\n',
        "a/match_block.rs": 'fn f() -> bool {\n    match std::env::var("X_C").ok().as_deref() {\n        Some("1") => true,\n        _ => false,\n    }\n}\n',
        "b/helper_set.rs": 'fn parse(v: &str) -> bool {\n    matches!(v, "1" | "true")\n}\n',
        "b/helper_chain.rs": 'fn parse(v: &str) -> bool {\n    v.eq_ignore_ascii_case("true")\n        || v == "1"\n}\n',
        "b/helper_some.rs": 'fn parse(v: Option<&str>) -> bool {\n    v != Some("true")\n}\n',
        # must stay silent
        "ok/fallback_closure.rs": 'fn f() -> String {\n    std::env::var("VERSION").unwrap_or_else(|_| {\n        let dirty = env!("GIT_DIRTY") == "true";\n        format!("{dirty}")\n    })\n}\n',
        "ok/marked.rs": 'fn parse(v: &str) -> bool {\n    // allow-inline-env-bool: fixture\n    matches!(v, "1" | "true")\n}\n',
        "ok/test_mod.rs": '#[cfg(test)]\nmod tests {\n    fn t(v: &str) -> bool { matches!(v, "1" | "true") }\n}\n',
        "ok/shared.rs": 'fn f() -> bool { talos_config::bool_env_or_default("X_D", false) }\n',
    }
    got = scan(fixtures)
    fired = {f.split(":", 1)[0] for f in got}
    ok = True
    for path in fixtures:
        want = not path.startswith("ok/")
        if (path in fired) != want:
            ok = False
            print(f"✗ self-test: {path} {'did not fire' if want else 'fired'}")
    print("✓ check 90 self-test passed" if ok else "✗ check 90 self-test failed")
    return 0 if ok else 1


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    files=[p for p in subprocess.run(['git','ls-files','*.rs'],cwd=root,capture_output=True,text=True).stdout.split()
           if '/tests/' not in '/'+p and not p.endswith('_tests.rs') and '/examples/' not in p and not p.startswith('module-templates/') and not p.startswith('talos-config/')]
    sources={}
    for p in files:
        # `git ls-files` lists TRACKED paths, so a file deleted but not yet
        # committed is listed and is not on disk. Skip it (package BP).
        if not os.path.exists(f'{root}/{p}'):
            continue
        sources[p]=open(f'{root}/{p}',encoding='utf-8',errors='ignore').read()
    finds=scan(sources)
    for f in finds: print(f)
    print(f"  {len(finds)} inline env-boolean parser(s)")
    return 1 if finds else 0


if __name__ == "__main__":
    sys.exit(main())
