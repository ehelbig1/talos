#!/usr/bin/env python3
"""Check 97 — a documented env var with NO default must be TRANSPORTED.

`docs/configuration-reference.md` tells an operator to set a variable. On the
compose stack the controller service has no `env_file`: its `environment:` map
is an explicit `KEY: ${VAR}` list, so a variable NOT named there never reaches
the process. A documented "set this to turn the integration on" then silently
does nothing — the operator edits `.env`, restarts, and the feature stays off
with no error, no warning and no log line.

SCOPE IS NARROW ON PURPOSE, and the narrowing is what makes this shippable.
Measured 2026-09-23 over 302 documented-and-read variables, 143 (47%) are
transported by nothing — and nearly every one is a TUNABLE with a working
default (`WASM_CACHE_MAX_MODULES`, every `CIRCUIT_BREAKER_*`, `SCHEDULER_*`).
For those, no transport is the CORRECT state: you set them only to override.
Gating that population would be 143 findings on correct code.

What distinguishes a defect is the absence of a default: the docs' Default
cell reads `none`, so the feature is OFF until the operator sets it, so the
variable is the ONLY way to turn the feature on. That population is SIX, and
five of them could not be set at all.

Transport is inert when unset: `${VAR:-}` renders empty and `talos_config`
treats empty as unset (check 73), so adding a variable here cannot change the
behaviour of a deployment that does not set it.

Opt-out `allow-untransported-env: VAR — <reason>` in any deployment surface,
for a variable deliberately kept unreachable. One holder today:
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, which is check 69's decision — the
compose file carries a `DO NOT ADD JAEGER_ENDPOINT HERE` prohibition and this
is the same one.

STATED LIMITS. (a) TEXTUAL: a variable reached through a name assembled at
runtime, or transported by a surface not in SURFACES, is invisible. (b) It
proves the name APPEARS in a deployment surface, never that it reaches the
right process or carries a sane value — check 89(d) owns chart parity. (c) The
Default cell is prose, so a row that expresses "no default" some other way
than `none` is out of range.
"""
import re
import subprocess
import sys
from pathlib import Path

DOC = Path("docs/configuration-reference.md")
# TWO FAMILIES, checked SEPARATELY. The first version required transport by
# ANY surface, and a mutation removing `PLAID_SECRET` from docker-compose.yml
# SURVIVED it — the chart still named the variable, so one deployment vouched
# for another while the defect (an operator's `.env` reaching nothing on the
# compose stack) was fully restored. `.env` is the COMPOSE mechanism, so the
# compose family is checked on its own.
COMPOSE_FILES = [
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.observability.yml",
]
# The chart carries a variable either as a rendered env/Secret key OR through
# the installer, which stages some of them into the bootstrap Secret out of
# band (RFC 0010 worker trust: `TALOS_CONTROLLER_PUBLIC_KEY`,
# `TALOS_WORKER_PUBLIC_KEYS` are compose+installer and deliberately not in the
# chart YAML). Measured: 19 of 22 are in both families, 2 are compose+installer
# and 3 are opted out.
CLUSTER_FILES = ["deploy/helm/talos/values.yaml"]
CLUSTER_GLOBS = [("deploy/helm/talos/templates", "*.yaml"), ("deploy/k3s", "*.sh")]
NO_DEFAULT = {"none", "", "-", "required", "n/a"}
OPT_OUT = re.compile(r"allow-untransported-env:\s*([A-Z][A-Z0-9_]+)")


def documented_without_default(text):
    """Variable cell + Default cell of every table row whose default is none."""
    out = {}
    for line in text.split("\n"):
        m = re.match(r"\s*\|\s*`([A-Z][A-Z0-9_]+)`[^|]*\|([^|]*)\|", line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip("`").lower()
    return {v for v, d in out.items() if d in NO_DEFAULT}, len(out)


def read_in_production(names):
    """A name is READ when it appears as a whole quoted literal in src."""
    proc = subprocess.run(
        ["git", "grep", "-ohE", r'"[A-Z][A-Z0-9_]{2,}"', "--",
         "*/src/*.rs", "controller/src", "worker/src"],
        capture_output=True, text=True)
    seen = {tok.strip('"') for tok in proc.stdout.split()}
    return {n for n in names if n in seen}


def strip_comments(text):
    """A COMMENT IS NOT TRANSPORT.

    Found by this check's own first run: the compose NOTE explaining that
    `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is deliberately absent made the
    variable read as PRESENT, so the check shipped green over its own
    documented exemption — checks 73 and 87's self-report trap.

    The strip is line-level and deliberately blunt: a `#` inside a quoted
    YAML value loses the tail, which can only ADD findings (loud direction).
    """
    out = []
    for line in text.split("\n"):
        i = line.find("#")
        out.append(line if i < 0 else line[:i])
    return "\n".join(out)


def family(files, globs):
    """Returns (transport_text_without_comments, raw_text, file_count).

    Opt-out markers are read from the RAW text — they live in comments by
    construction, which is precisely what the transport scan must not see.
    """
    raw, n = "", 0
    for f in files:
        p = Path(f)
        if p.exists():
            raw += p.read_text() + "\n"
            n += 1
    for root, pat in globs:
        for p in Path(root).rglob(pat) if Path(root).exists() else []:
            raw += p.read_text() + "\n"
            n += 1
    return strip_comments(raw), raw, n


def scan():
    if not DOC.exists():
        print(f"✗ check 97: {DOC} is missing", file=sys.stderr)
        return 2, []
    no_default, total_rows = documented_without_default(DOC.read_text())
    if total_rows == 0:
        print("✗ check 97: parsed ZERO documented rows — the table format moved",
              file=sys.stderr)
        return 2, []
    read = read_in_production(no_default)
    if not read:
        print("✗ check 97: ZERO no-default variables are read by production code "
              "— the reader scan matched nothing", file=sys.stderr)
        return 2, []
    comp, comp_raw, n_comp = family(COMPOSE_FILES, [])
    clus, clus_raw, n_clus = family(CLUSTER_FILES, CLUSTER_GLOBS)
    if not n_comp or not n_clus:
        print("✗ check 97: a deployment-surface family is missing "
              f"(compose {n_comp} file(s), cluster {n_clus})", file=sys.stderr)
        return 2, []
    exempt = set(OPT_OUT.findall(comp_raw + clus_raw))
    findings = []
    for v in sorted(read):
        if v in exempt:
            continue
        w = r"\b" + v + r"\b"
        if not re.search(w, comp):
            findings.append((v, "compose"))
        if not re.search(w, clus):
            findings.append((v, "chart/installer"))
    return 0, (findings, len(read), len(exempt), n_comp + n_clus)


def self_test():
    """Each fixture flips exactly one leg."""
    cases = [
        ("a row with a default is out of range",
         documented_without_default("| `FOO_BAR` | 30 | controller | x | |")[0], set()),
        ("a row with default none is in range",
         documented_without_default("| `FOO_BAR` | none | controller | x | |")[0],
         {"FOO_BAR"}),
        ("an empty default cell counts as no default",
         documented_without_default("| `FOO_BAR` |  | controller | x | |")[0],
         {"FOO_BAR"}),
        ("a backticked default is unwrapped",
         documented_without_default("| `FOO_BAR` | `none` | controller | x | |")[0],
         {"FOO_BAR"}),
        ("a non-row line is ignored",
         documented_without_default("`FOO_BAR` is none")[0], set()),
    ]
    bad = [n for n, got, want in cases if got != want]
    opt = OPT_OUT.findall("# allow-untransported-env: FOO_BAR — because")
    if opt != ["FOO_BAR"]:
        bad.append("the opt-out marker does not parse")
    # A COMMENT IS NOT TRANSPORT — the leg this check's own first run needed.
    if "FOO_BAR" in strip_comments("      # NOTE: `FOO_BAR` is deliberately NOT here"):
        bad.append("a commented mention still counts as transport")
    if "FOO_BAR" not in strip_comments("      FOO_BAR: ${FOO_BAR:-}"):
        bad.append("a real env line was stripped")
    if bad:
        for b in bad:
            print(f"✗ check 97 self-test: {b}", file=sys.stderr)
        return 1
    print(f"  self-test ok: {len(cases) + 3} cases")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    if self_test():
        sys.exit(2)
    code, payload = scan()
    if code:
        sys.exit(code)
    findings, n_read, n_exempt, n_files = payload
    for v, fam in findings:
        print(f"✗ {v}: documented with no default and read by production code, "
              f"but the {fam} deployment surface does not transport it — "
              f"setting it there does nothing")
    print(f"  scanned {n_read} no-default documented variable(s) against "
          f"{n_files} deployment surface(s); {n_exempt} opt-out(s); "
          f"{len(findings)} finding(s)")
    sys.exit(1 if findings else 0)
