#!/usr/bin/env python3
"""Check 89: a `docs/configuration-reference.md` Component cell must not claim a
process that cannot read the variable.

The Component column tells an operator which PROCESS needs a variable set.
`docs/configuration-reference.md` is the AUTHORITATIVE env-var list (the
2026-09-07 artefacts entry made it so), and on 2026-09-12 it said `both` for
108 variables the worker binary cannot read at all — `TALOS_MASTER_KEY`,
`JWT_SECRET`, `VAULT_ADDR`, `NEO4J_PASSWORD`, every scheduler knob, every
memory-loop knob. Read literally, that column told an operator to hand the
credential-free worker the master KEK and the JWT signing secret.

The rule is an IMPOSSIBILITY test, not a judgement:

  * `both` / `worker`   → some crate LINKED INTO THE WORKER BINARY must read
                          the variable (the `worker` crate itself or a crate in
                          `cargo tree -p worker`). If none does, the worker
                          process cannot read it, whatever the deployment sets.
  * `controller`        → the `worker` crate itself must NOT read it. (A read
                          in a SHARED crate is allowed and is left to the
                          author: `talos-worker-runtime` is linked into the
                          controller for the WIT inspector, and its host-side
                          env reads run only in the worker.)
  * `both` / `controller` → some crate linked into the controller must read it.
  * `talos-foo[ / talos-bar]` → at least one named crate must read it.

"Reads" means: the variable name appears as a WHOLE quoted string literal in
that crate's production `.rs` files (whole-line comments stripped, `tests/`, `*_tests.rs`,
`examples/`, `benches/` excluded), OR a `pub fn` in `talos-config` whose body
names the variable is CALLED from that crate. Everything else (`frontend
(build)`, `compose (shell)`, `—`, blank) is out of range and counted.

Limits, stated: TEXTUAL. A name assembled at runtime (`format!("{}_FILE", v)`)
is invisible; a read routed through a non-`talos-config` helper crate is
attributed to the helper's crate, which is correct for the impossibility test
(the helper is linked wherever its caller is) but cannot tell WHICH process
calls it; trailing `// comments` on code lines are not stripped, so a variable
named in prose beside unrelated code counts as read (false NEGATIVE for the
`worker cannot read it` arm — the safe direction). `cargo tree` resolves the
lockfile; it needs no build.

Two further rows-level legs (2026-09-12, package AL), both cheap because the
rows are already parsed:

  * a Default cell may not be a PLACEHOLDER (`bool default`, `flag`,
    `policy default`): it must say what happens when the variable is unset.
    Ten cells were, two of them security-posture switches
    (`TALOS_WRITE_CEILING_ENFORCED`, `TALOS_WRITE_CEILING_STRICT_EGRESS`) and
    one whose real default is `is_production()` (`ENABLE_HSTS`).
  * a `(+_FILE)` claim needs a reader — `read_env_or_file("VAR")` or the
    literal `"VAR_FILE"` in production Rust. `NATS_PASSWORD` claimed the
    Docker-secrets sibling while both its readers were a bare `env::var`.

Neither leg reads a DESCRIPTION: the 24 wrong descriptions the same package
fixed were found by a per-row human read against the reader code, and a
Default-VALUE comparison was measured and rejected (93 rows carry a literal
code default, 23 differ from the doc, 21 of those by vocabulary — `on` vs
`true` — or by matching a test fixture; ~9 % precision).

Usage: lint-config-reference-components.py [--report] [ROOT]
  exit 0 = every classifiable row is consistent; 1 = findings; 2 = cannot run.
"""
import collections
import os
import re
import subprocess
import sys

DOC = "docs/configuration-reference.md"
BINS = ("controller", "worker")
SKIP_COMPONENTS = {"", "—", "frontend (build)", "compose (shell)"}


def sh(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def tree_crates(root, pkg):
    r = sh(["cargo", "tree", "-p", pkg, "-e", "normal", "--prefix", "none", "-f", "{p}"], root)
    if r.returncode != 0:
        print(f"✗ cargo tree -p {pkg} failed:\n{r.stderr.strip()[:800]}", file=sys.stderr)
        sys.exit(2)
    names = {line.split()[0] for line in r.stdout.splitlines() if line.strip()}
    return {n for n in names if n.startswith("talos") or n in BINS}


def is_test_path(p):
    q = "/" + p
    return (
        "/tests/" in q
        or "/examples/" in q
        or "/benches/" in q
        or p.endswith("_tests.rs")
        or os.path.basename(p) in ("tests.rs", "test_support.rs")
        or p.startswith("module-templates/")
    )


COMMENT_LINE = re.compile(r"(?m)^\s*//.*$")


def load_sources(root):
    r = sh(["git", "ls-files", "*.rs"], root)
    if r.returncode != 0:
        print("✗ git ls-files failed", file=sys.stderr)
        sys.exit(2)
    out = {}
    for p in r.stdout.split():
        if is_test_path(p):
            continue
        try:
            with open(os.path.join(root, p), encoding="utf-8", errors="ignore") as fh:
                out[p] = COMMENT_LINE.sub("", fh.read())
        except OSError:
            continue
    return out


def parse_rows(root):
    rows = []
    heading_comp = ""
    comp_idx = None
    with open(os.path.join(root, DOC), encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if line.startswith("#"):
                heading_comp = ""
                m = re.search(r"\(([^)]*)\)", line)
                if m:
                    hm = re.search(r"\b(both|controller|worker)\b", m.group(1))
                    if hm:
                        heading_comp = hm.group(1)
                continue
            if line.startswith("| Variable"):
                hdr = [c.strip().lower() for c in line.strip().strip("|").split("|")]
                comp_idx = hdr.index("component") if "component" in hdr else None
                continue
            if not line.startswith("| `"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            m = re.match(r"`([A-Z][A-Z0-9_]*)`", cells[0])
            if not m or len(cells) < 3:
                continue
            if comp_idx is not None and comp_idx < len(cells):
                comp, src = cells[comp_idx], "cell"
            else:
                comp, src = heading_comp, "heading"
            default_cell = cells[1] if len(cells) > 1 else ""
            claims_file = bool(re.search(r"\(\+\s*`_FILE`", cells[0]))
            rows.append((lineno, m.group(1), comp, src, default_cell, claims_file))
    return rows


def accessors(sources):
    """var -> set of `pub fn` names in talos-config whose body names the var."""
    fnre = re.compile(r"^\s*pub\s+fn\s+([a-z_0-9]+)\s*[(<]", re.M)
    acc = collections.defaultdict(set)
    for p, t in sources.items():
        if not p.startswith("talos-config/src/"):
            continue
        idx = [(m.start(), m.group(1)) for m in fnre.finditer(t)]
        for i, (s, name) in enumerate(idx):
            e = idx[i + 1][0] if i + 1 < len(idx) else len(t)
            for v in re.findall(r"[\"']([A-Z][A-Z0-9_]{3,})[\"']", t[s:e]):
                acc[v].add(name)
    return acc


def main():
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    report = "--report" in sys.argv
    root = os.path.abspath(argv[0] if argv else ".")
    ctl = tree_crates(root, "controller")
    wrk = tree_crates(root, "worker")
    if not ctl or not wrk:
        print("✗ cargo tree resolved an empty crate set — the check would pass over nothing", file=sys.stderr)
        sys.exit(2)
    sources = load_sources(root)
    if len(sources) < 100:
        print(f"✗ only {len(sources)} production .rs files found — wrong root?", file=sys.stderr)
        sys.exit(2)
    rows = parse_rows(root)
    if len(rows) < 50:
        print(f"✗ only {len(rows)} rows parsed from {DOC} — the table format moved", file=sys.stderr)
        sys.exit(2)
    acc = accessors(sources)
    # One pass per crate: the set of SCREAMING_SNAKE tokens it names and the set
    # of function names it calls. Membership tests after that are O(1), which is
    # what keeps 274 rows x 140 crates under a second (a regex per pair was 35 s).
    tokens = collections.defaultdict(set)
    calls = collections.defaultdict(set)
    # A READ names the variable as a WHOLE string literal (`env::var("X")`,
    # `const K: &str = "X"`, `read_env_or_file("X")`). A name inside a longer
    # string is prose — a log line saying "set X" — and must not vouch for a
    # read: `worker/src/self_register.rs` names `TALOS_WORKER_PUBLIC_KEYS` in a
    # WARN message and never reads it.
    tok_re = re.compile(r"[\"']([A-Z][A-Z0-9_]{2,})[\"']")
    file_reads = collections.defaultdict(set)
    file_read_re = re.compile(r"read_env_or_file\(\s*[\"']([A-Z][A-Z0-9_]{2,})[\"']")
    call_re = re.compile(r"(?<![a-z0-9_])([a-z_][a-z0-9_]*)\s*\(")
    for p, t in sources.items():
        cr = p.split("/")[0]
        if cr == "talos-config":
            continue
        tokens[cr].update(tok_re.findall(t))
        file_reads[cr].update(file_read_re.findall(t))
        calls[cr].update(call_re.findall(t))
    crates = set(tokens) | set(calls)

    findings = []
    skipped = 0
    PLACEHOLDER_DEFAULTS = {"bool default", "flag", "policy default", "default", "tbd", "?"}
    for lineno, var, comp, src, default_cell, claims_file in rows:
        where0 = f"{DOC}:{lineno}"
        # (b) a Default cell must state the default, not name its type: `bool
        # default` / `flag` / `policy default` tell an operator nothing about
        # what happens when the variable is unset. 10 such cells on 2026-09-12,
        # including two security-posture switches (`TALOS_WRITE_CEILING_*`).
        if default_cell.replace("`", "").strip().lower() in PLACEHOLDER_DEFAULTS:
            findings.append(f"{where0}: `{var}` Default cell is the placeholder {default_cell.strip()!r} — state the real default")
        # (c) a `(+_FILE)` claim needs a reader: `read_env_or_file("VAR")` or the
        # literal `"VAR_FILE"` somewhere in production Rust. `NATS_PASSWORD`
        # claimed one on 2026-09-12 and both its readers were bare `env::var`.
        if claims_file:
            file_tok = var + "_FILE"
            if not any(file_tok in tokens[cr] or var in file_reads[cr] for cr in crates):
                findings.append(f"{where0}: `{var}` row claims a `_FILE` sibling but no production reader consults `{file_tok}` or `read_env_or_file(\"{var}\")`")
        c = comp.replace("`", "").strip()
        if c in SKIP_COMPONENTS or (not c.startswith("talos-") and c not in ("both", "controller", "worker")):
            skipped += 1
            continue
        readers = {cr for cr in crates if var in tokens[cr]}
        for fn in acc.get(var, ()):
            readers |= {cr for cr in crates if fn in calls[cr]}
        worker_can = bool(readers & (wrk | {"worker"}))
        controller_can = bool(readers & (ctl | {"controller"}))
        worker_bin_reads = "worker" in readers
        where = f"{DOC}:{lineno}"
        rd = ",".join(sorted(readers)) or "nothing"
        if report:
            print(f"{var:44} {c:14} worker_can={int(worker_can)} worker_bin={int(worker_bin_reads)} readers={rd}")
        if c in ("both", "worker") and not worker_can:
            findings.append(f"{where}: `{var}` Component={c} but no crate linked into the worker reads it (readers: {rd}) — the worker cannot read it; say `controller` (or the leaf crate)")
        if c == "controller" and worker_bin_reads:
            findings.append(f"{where}: `{var}` Component=controller but the worker binary itself reads it")
        if c in ("both", "controller") and not controller_can:
            findings.append(f"{where}: `{var}` Component={c} but no crate linked into the controller reads it (readers: {rd})")
        if c.startswith("talos-"):
            named = [n.strip() for n in c.split("/")]
            if not any(n in readers for n in named):
                findings.append(f"{where}: `{var}` Component names {c} but that crate does not read it (readers: {rd})")
    for f in findings:
        print(f)
    print(f"  checked {len(rows) - skipped} row(s) ({skipped} out of range); worker tree {len(wrk)} crates, controller tree {len(ctl)}; {len(findings)} finding(s)")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
