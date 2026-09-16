#!/usr/bin/env python3
"""Every container image this repository runs or builds from is digest-pinned,
and one `repository:tag` names one digest everywhere.

Package BX (2026-09-16). The SOC 2 control mapping claimed every image was
pinned by SHA-256 digest. Measured, it was not: the worker's runtime stage
(`FROM debian:trixie-slim` — the image that executes production WASM), the
CI integration runner's `docker run redis:7-alpine` / `pgvector/pgvector:pg17`
/ `nats:2.10-alpine`, the production compose file's nats and redis, the
observability stack, the chart's in-cluster Postgres (`digest: ""`) and the
kubectl image the Vault init job runs with the root token. A tag is a mutable
pointer: an upstream re-push changes what runs with no change in this tree.
Check 80 pins Postgres only, and only in assignment form — it could not see a
`docker run` argument, which is how the integration runner's pgvector image
escaped it.

What counts as a reference (git-tracked files only):
  * Dockerfile*: `FROM <ref>` and `COPY --from=<ref>` (stage names excluded).
  * YAML (compose, workflows, deploy/): an `image:` value.
  * Helm values files: a `repository:` block must carry a non-empty `digest:`.
  * Shell and Makefiles: image arguments of `docker|podman run|pull|create`
    (backslash continuations joined) and `*IMAGE*=` defaults.
A reference containing `$` / `{{` is resolved at runtime and is out of range.

Findings: an unpinned reference, and a `repository:tag` pinned to more than
one digest across the tree. Opt-out: `allow-unpinned-image: <reason>` on the
line or the line above — for an image built locally and never pulled.

Exit 1 on findings; exit 2 when no reference was found at all (a detector that
matches nothing is a green tick over nothing).
"""
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
REF = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:[:/][a-z0-9._-]+)*(?::[A-Za-z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?$")
MARK = "allow-unpinned-image:"


def tracked():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
    return [p for p in out.stdout.splitlines() if (ROOT / p).is_file()]


def opted_out(lines, i):
    return MARK in lines[i] or (i > 0 and MARK in lines[i - 1])


def dockerfile_refs(path, lines):
    stages = set()
    for i, raw in enumerate(lines):
        line = raw.strip()
        m = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line)
        if m:
            ref = m.group(1)
            if m.group(2):
                stages.add(m.group(2).lower())
            if ref.lower() in stages or ref == "scratch":
                continue
            yield i, ref
        for ref in re.findall(r"COPY\s+--from=(\S+)", line):
            if ref.lower() not in stages and (":" in ref or "/" in ref):
                yield i, ref


def yaml_refs(lines):
    for i, raw in enumerate(lines):
        m = re.match(r"^\s*-?\s*image:\s*[\"']?([^\"'#\s]+)", raw)
        if m and not raw.lstrip().startswith("#"):
            yield i, m.group(1)


def values_refs(lines):
    for i, raw in enumerate(lines):
        m = re.match(r"^(\s*)repository:\s*[\"']?([^\"'#\s]*)", raw)
        if not m or not m.group(2) or raw.lstrip().startswith("#"):
            continue
        indent = len(m.group(1))
        tag, digest = "", None
        for j in range(i + 1, min(i + 12, len(lines))):
            nxt = lines[j]
            if nxt.strip() and not nxt.lstrip().startswith("#") and len(nxt) - len(nxt.lstrip()) < indent:
                break
            t = re.match(r"^\s*tag:\s*[\"']?([^\"'#\s]*)", nxt)
            d = re.match(r"^\s*digest:\s*[\"']?([^\"'#\s]*)", nxt)
            if t:
                tag = t.group(1)
            if d:
                digest = d.group(1)
        ref = m.group(2) + (f":{tag}" if tag else "")
        if digest:
            ref += f"@{digest}" if digest.startswith("sha256:") else ""
            if not DIGEST.search(ref):
                # A placeholder the installer substitutes (our own images).
                if "PLACEHOLDER" in digest:
                    continue
        yield i, ref


def shell_refs(lines):
    joined, starts = [], []
    buf, start = "", 0
    for i, raw in enumerate(lines):
        if not buf:
            start = i
        buf += raw.rstrip("\\\n") + " "
        if not raw.rstrip().endswith("\\"):
            joined.append(buf)
            starts.append(start)
            buf = ""
    for i, stmt in zip(starts, joined):
        if stmt.lstrip().startswith("#"):
            continue
        m = re.search(r"\b(?:docker|podman)\s+(?:run|pull|create)\b(.*)", stmt)
        # A command quoted inside a message (`err "…you may need: docker run …"`)
        # is advice, not an executed pull: an odd number of double quotes before
        # the match means it sits inside a string literal.
        if m and stmt[: m.start()].count('"') % 2 == 1:
            m = None
        if m:
            toks = m.group(1).split()
            skip_next = False
            for tok in toks:
                tok = tok.strip("\"'")
                if skip_next:
                    skip_next = False
                    continue
                if tok.startswith("-"):
                    if "=" not in tok and tok in {"-p", "-v", "-e", "--name", "--network", "-w", "--entrypoint", "--platform", "--user", "-u", "--env-file", "--mount", "--memory", "--cpus", "--pids-limit", "--tmpfs", "--add-host", "--label", "--workdir", "--volume", "--publish", "--env", "--cap-add", "--cap-drop", "--security-opt", "--ulimit", "--log-driver", "--restart", "--hostname"}:
                        skip_next = True
                    continue
                if "$" in tok or "{" in tok:
                    break
                if REF.match(tok) and not tok.startswith("/"):
                    yield i, tok
                break
        for v in re.findall(r"\b[A-Z_]*IMAGE[A-Z_]*=\"?(?:\$\{[A-Z_]+:-)?([a-z0-9][^\"}\s]*)", stmt):
            if "$" not in v and REF.match(v):
                yield i, v


RENDERS = [
    [],
    ["--set", "postgres.enabled=true", "--set", "controller.autoscaling.enabled=false"],
]


def rendered_chart_refs():
    """Image references in the RENDERED chart. A values file can carry a digest
    that a template ignores — the Vault init Job printed `repository:tag` and
    rendered `alpine/k8s:1.31.4` whatever the values said — so the values scan
    alone cannot certify what the chart deploys. `None` when helm is absent."""
    import shutil
    if shutil.which("helm") is None:
        return None
    chart = ROOT / "deploy" / "helm" / "talos"
    out = []
    for extra in RENDERS:
        r = subprocess.run(["helm", "template", "t", str(chart), *extra], capture_output=True, text=True)
        if r.returncode != 0:
            out.append((f"helm template {' '.join(extra) or '(defaults)'}", 0, f"<render failed: {r.stderr.strip()[:120]}>"))
            continue
        lines = r.stdout.splitlines()
        for i, raw in enumerate(lines):
            m = re.match(r"^\s*-?\s*image:\s*(.*)$", raw)
            if not m:
                continue
            val = m.group(1).strip().strip("\"'")
            if not val and i + 1 < len(lines):
                val = lines[i + 1].strip().strip("\"'")
            if val:
                out.append((f"rendered chart {' '.join(extra) or '(defaults)'}", i + 1, val))
    return out


def main():
    refs = []
    for rel in tracked():
        name = Path(rel).name
        if rel.startswith(("docs/", "target/")) or "/tests/fixtures/" in rel:
            continue
        try:
            lines = (ROOT / rel).read_text(errors="replace").splitlines()
        except OSError:
            continue
        if name.startswith("Dockerfile"):
            found = dockerfile_refs(rel, lines)
        elif name.endswith((".yml", ".yaml")):
            if "/templates/" in rel:
                continue
            found = list(yaml_refs(lines))
            if name.startswith("values"):
                found += list(values_refs(lines))
        elif name.endswith(".sh") or name == "Makefile" or name.endswith(".mk"):
            # Shell scripts also carry YAML in heredocs (`image:` in a pod spec).
            found = list(shell_refs(lines)) + list(yaml_refs(lines))
        else:
            continue
        for i, ref in found:
            if "$" in ref or "{{" in ref:
                continue
            refs.append((rel, i + 1, ref, opted_out(lines, i)))

    if not refs:
        print("✗ no container image reference found — the detector matched nothing")
        return 2

    findings = []
    rendered = rendered_chart_refs()
    if rendered is None:
        print("  ⚠ helm not on PATH — the rendered-chart leg did not run (CI installs helm)")
    else:
        for where_, line, val in rendered:
            if not re.search(r"@sha256:(?:[0-9a-f]{64}|PLACEHOLDER_[A-Z_]+)$", val):
                findings.append(f"{where_} line {line}: {val} is not digest-pinned")
    digests = defaultdict(set)
    where = defaultdict(list)
    for rel, line, ref, out in refs:
        if DIGEST.search(ref):
            base = ref.split("@")[0]
            digests[base].add(ref.split("@")[1])
            where[base].append(f"{rel}:{line}")
        elif not out:
            findings.append(f"{rel}:{line}: {ref} is not digest-pinned")
    for base, ds in sorted(digests.items()):
        if len(ds) > 1:
            findings.append(f"{base} is pinned to {len(ds)} different digests: {', '.join(sorted(where[base]))}")

    for f in findings:
        print(f"  {f}")
    pinned = sum(1 for r in refs if DIGEST.search(r[2]))
    chart = "rendered-chart leg skipped" if rendered is None else f"{len(rendered)} rendered chart image(s)"
    print(f"  {len(refs)} image reference(s): {pinned} pinned, {sum(1 for r in refs if r[3])} opted out; {chart}; {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
