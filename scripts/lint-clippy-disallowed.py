#!/usr/bin/env python3
"""The structural side of the clippy `disallowed-methods` rules in clippy.toml.

Four "never call X outside Y" checks (29, 53, 63, 78) used to find their call
sites with grep. Clippy now finds them by TYPE — an alias, a re-export or a
UFCS call cannot hide one — and fails `cargo clippy -D warnings` in CI. What
clippy cannot know is WHICH files are allowed to call the method: it only sees
an `#[allow(clippy::disallowed_methods)]`, and that attribute silences EVERY
disallowed method on its item. This script owns that half:

  check <N>     rule N's entry is still in clippy.toml, the workspace-owned
                method it names still exists where the table says (a renamed
                method makes clippy's path unresolvable, which is only a
                warning), and every allow that names the rule's path sits in a
                file the rule sanctions.
  check-allows  every `allow`/`expect(clippy::disallowed_methods)` attribute
                carries `// disallowed-method: <path> — <reason>` within the
                three lines above it, naming a path this table knows, and
                every clippy.toml entry belongs to a rule here.

Called by scripts/lint-structural.sh (checks 7, 29, 53, 63, 78).
"""
import fnmatch
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLIPPY_TOML = ROOT / "clippy.toml"
SKIP_DIRS = {"target", "vendor", "node_modules", ".git", ".claude", "frontend"}

TESTS = ["*/tests/*", "*_tests.rs", "*/tests.rs", "*/test_support.rs"]

RULES = {
    29: {
        "path": "talos_workflow_engine::ParallelWorkflowEngine::set_actor_id",
        # The engine crate itself, the one actor-application path, and tests
        # (the grep check this replaced exempted every test the same way).
        "sanctioned": ["talos-workflow-engine/src/*", "talos-engine/src/actor_binding.rs"] + TESTS,
        "defined": ("talos-workflow-engine/src/engine_config.rs", r"pub fn set_actor_id\("),
    },
    53: {
        "path": "wasmtime::component::Component::new",
        "sanctioned": ["talos-worker-runtime/src/runtime.rs"],
        "defined": None,
    },
    63: {
        "path": "rhai::Engine::new",
        "sanctioned": ["talos-rhai-sandbox/src/lib.rs"],
        "defined": None,
    },
    78: {
        "path": "talos_workflow_engine_nats::NatsNodeDispatcher::new",
        "sanctioned": ["talos-engine/src/nats_run.rs", "talos-workflow-engine-nats/*"],
        "defined": ("talos-workflow-engine-nats/src/dispatcher.rs", r"impl NatsNodeDispatcher \{[\s\S]*?pub fn new\("),
    },
}

ATTR_RE = re.compile(r"#!?\[\s*(allow|expect)\s*\([^\]]*clippy::disallowed_methods")
MARKER_RE = re.compile(r"//\s*disallowed-method:\s*([A-Za-z0-9_:]+)")
TOML_PATH_RE = re.compile(r'path\s*=\s*"([^"]+)"')


def rs_files():
    # os.walk with in-place pruning: Path.rglob would descend into target/
    # (hundreds of thousands of files) before the filter could drop it.
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".rs"):
                p = Path(dirpath) / name
                yield p.relative_to(ROOT), p


def allow_sites():
    """[(rel, line_no, [named paths])] for every disallowed_methods allow."""
    sites = []
    for rel, p in rs_files():
        lines = p.read_text(errors="replace").splitlines()
        for i, line in enumerate(lines):
            if line.lstrip().startswith("//") or not ATTR_RE.search(line):
                continue
            window = lines[max(0, i - 3):i + 1]
            named = [m.group(1) for w in window for m in MARKER_RE.finditer(w)]
            sites.append((rel, i + 1, named))
    return sites


def toml_paths():
    """The `disallowed-methods` paths clippy will actually read — parsed as
    TOML, so a commented-out entry does not count (a regex over the raw text
    counted one, measured)."""
    try:
        text = CLIPPY_TOML.read_text()
    except OSError:
        return None
    try:
        import tomllib
        entries = tomllib.loads(text).get("disallowed-methods", [])
        return [e if isinstance(e, str) else e.get("path", "") for e in entries]
    except ImportError:  # Python < 3.11: strip comment lines, then match
        live = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        return TOML_PATH_RE.findall(live)


def sanctioned(rel: Path, globs) -> bool:
    s = rel.as_posix()
    return any(fnmatch.fnmatch(s, g) or fnmatch.fnmatch("/" + s, "*/" + g.lstrip("*/")) for g in globs)


def check_rule(n: int) -> int:
    rule = RULES.get(n)
    if rule is None:
        print(f"✗ no disallowed-methods rule for check {n}")
        return 2
    errors = []
    paths = toml_paths()
    if paths is None:
        errors.append("clippy.toml is missing")
    elif rule["path"] not in paths:
        errors.append(f"clippy.toml no longer disallows `{rule['path']}` — clippy stopped enforcing check {n}")
    if rule["defined"]:
        f, pat = rule["defined"]
        try:
            if not re.search(pat, (ROOT / f).read_text()):
                errors.append(f"`{rule['path']}` is no longer defined in {f} — clippy's path would stop "
                              "resolving (a warning, not an error); repoint clippy.toml and this table")
        except OSError:
            errors.append(f"{f} is gone — repoint the check {n} entry in scripts/lint-clippy-disallowed.py")
    allowed = 0
    for rel, ln, named in allow_sites():
        if rule["path"] not in named:
            continue
        allowed += 1
        if not sanctioned(rel, rule["sanctioned"]):
            errors.append(f"{rel}:{ln} allows `{rule['path']}` outside the files check {n} sanctions")
    for e in errors:
        print(f"✗ {e}")
    if errors:
        return 1
    print(f"✓ clippy disallows `{rule['path']}`; {allowed} sanctioned allow(s), all in permitted files")
    return 0


def check_allows() -> int:
    errors = []
    known = {r["path"] for r in RULES.values()}
    paths = toml_paths()
    if paths is None:
        errors.append("clippy.toml is missing")
        paths = []
    for p in paths:
        if p not in known:
            errors.append(f"clippy.toml disallows `{p}` but no structural check owns it — add it to "
                          "RULES in scripts/lint-clippy-disallowed.py with its sanctioned files")
    sites = allow_sites()
    for rel, ln, named in sites:
        if not named:
            errors.append(f"{rel}:{ln} allows clippy::disallowed_methods with no "
                          "`// disallowed-method: <path> — <reason>` marker in the 3 lines above")
        for p in named:
            if p not in known:
                errors.append(f"{rel}:{ln} marker names `{p}`, which clippy.toml does not disallow")
    for e in errors:
        print(f"✗ {e}")
    if errors:
        return 1
    print(f"✓ {len(sites)} clippy::disallowed_methods allow(s), each naming the rule it waives")
    return 0


def main(argv) -> int:
    if len(argv) == 2 and argv[1] == "check-allows":
        return check_allows()
    if len(argv) == 3 and argv[1] == "check" and argv[2].isdigit():
        return check_rule(int(argv[2]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
