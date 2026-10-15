#!/usr/bin/env python3
"""The one place that decides which CI runner runs each cargo test target.

Every `tests/<name>.rs` and `tests/<dir>/main.rs` in the workspace is a cargo
integration-test target. Until 2026-09-25 each runner kept a HAND-WRITTEN list
of them (quality.yml's DB-free `--test` lines; test-integration.sh's `TESTS`,
`CTRL_TESTS` and `TC_TESTS` arrays), so every PR that added a test appended to
the same lines as every other PR and parallel PRs conflicted there. The
classification below is derived from the file itself instead, so adding a test
file is the whole registration.

Categories (a target is in exactly one):

  ctrl         controller binary with `mod common;` — needs DATABASE_URL pointing
               at the migrated `talos_ctl` template (per-test isolated DB clones).
  ctrl-serial  controller binary marked `// ci-runner: integration-serial` — run
               in the same environment with `--test-threads=1` (env_vars).
  tc           controller binary with `mod test_helpers;` — self-provisions a
               testcontainer; single-threaded, no DATABASE_URL.
  store        any other crate's binary marked `// ci-store: <store>`, where
               <store> is one of migrated | selfcontained | redis | services.
               `services` = needs the NATS/Redis env the runner exports, no DB.
  ungated      marked `// ci-ungated: <reason>` — runs nowhere, and says why.
  dbfree       everything else — the unit job runs it with no services.

The one inference that is REFUSED rather than defaulted: a non-controller
binary that reads a `TALOS_TEST_{DATABASE,REDIS,NATS}…` variable but carries no
`ci-store`/`ci-ungated` marker. Defaulting it to `dbfree` would run it with no
service and let it early-return green — "a green check over zero assertions is
worse than an honest exclusion" (check 64).

The same refusal one directory level down (security review 2026-10-15, D2-2):
a LIBRARY test (a file under a crate's `src/`) that reads one of those
variables must be named by a `lib` / `lib-migrated` filter in
scripts/test-integration.sh, or carry `// ci-ungated: <reason>`. The unit job
runs every library test with no service, so an unnamed one returns green over
zero assertions — the guest-tenancy and state-write gates did, from the day
they were mutation-proved. "Named" is cargo's own rule: the filter is a
substring of a test path the file defines (its module path, an inline `mod`
in it, or a function in it).

Usage:
  ci_test_targets.py list <category>   crate<TAB>binary[<TAB>store] per line
  ci_test_targets.py grouped dbfree    crate<TAB>bin1 bin2 … (one line per crate)
  ci_test_targets.py check             validate every marker; non-zero on error
"""
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATEGORIES = ("ctrl", "ctrl-serial", "tc", "store", "ungated", "dbfree")
STORES = ("migrated", "selfcontained", "redis", "services")
SKIP_DIRS = {"target", "vendor", "frontend", "node_modules", ".claude", ".git"}
MIN_TARGETS = 50  # a walk that finds fewer is broken, not a small workspace

UNGATED_RE = re.compile(r"^\s*(//|#)\s*ci-ungated:", re.M)
STORE_RE = re.compile(r"^\s*//\s*ci-store:\s*([a-z]+)\b", re.M)
SERIAL_RE = re.compile(r"^\s*//\s*ci-runner:\s*integration-serial\b", re.M)
SERVICE_ENV_RE = re.compile(r"TALOS_TEST_(DATABASE|REDIS|NATS)[A-Z_]*")
# A library test READS the variable: the name as a string literal, not a
# mention in a doc comment.
SERVICE_ENV_READ_RE = re.compile(r'"TALOS_TEST_(DATABASE|REDIS|NATS)[A-Z_]*"')
LIB_FILTER_RE = re.compile(r'^\s*"(lib|lib-migrated)\|([^|]+)\|--lib(?: ([^|]*))?\|', re.M)
INLINE_MOD_RE = re.compile(r"^\s*(?:pub(?:\([a-z]+\))?\s+)?mod\s+(\w+)\s*\{", re.M)
FN_RE = re.compile(r"\bfn\s+(\w+)")
INTEGRATION_SCRIPT = ROOT / "scripts" / "test-integration.sh"


def crate_name(crate_dir: Path) -> str:
    try:
        for line in (crate_dir / "Cargo.toml").read_text().splitlines():
            m = re.match(r'^name\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    except OSError:
        pass
    return crate_dir.name


def tests_dirs():
    """Every directory named `tests` with no path component below ROOT in
    SKIP_DIRS, sorted.

    The walk does not enter a SKIP_DIRS directory. Until 2026-10-05 this was
    `ROOT.rglob("tests")` with SKIP_DIRS filtered out afterwards, which walked
    every file under target/ (about 150,000 in a developer checkout) and, run
    from the main checkout, every agent worktree under .claude/ — 1.4 s per
    call, and structural check 64 calls this script 12 times. The set is the
    same: a `tests` directory was kept exactly when no directory above it is
    in SKIP_DIRS, which is exactly what a pruned walk reaches. Symlinked
    directories are not descended into (rglob did not recurse through them
    either), and a symlink named `tests` pointing at a directory is still
    listed, as rglob listed it and `is_dir()` accepted it.
    """
    found = []
    for dirpath, dirnames, _files in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if "tests" in dirnames:
            found.append(Path(dirpath) / "tests")
    return sorted(found)


def test_files():
    for tests_dir in tests_dirs():
        if not tests_dir.is_dir():
            continue
        rel = tests_dir.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        crate_dir = tests_dir.parent
        if not (crate_dir / "Cargo.toml").is_file():
            continue
        for f in sorted(tests_dir.glob("*.rs")):
            yield crate_dir, f.stem, f
        for f in sorted(tests_dir.glob("*/main.rs")):
            yield crate_dir, f.parent.name, f


def classify():
    """Return (targets, errors); targets = [(category, crate, bin, store, path)]."""
    targets, errors = [], []
    for crate_dir, binary, path in test_files():
        crate = crate_name(crate_dir)
        text = path.read_text(errors="replace")
        rel = path.relative_to(ROOT)
        ungated = bool(UNGATED_RE.search(text))
        stores = STORE_RE.findall(text)
        serial = bool(SERIAL_RE.search(text))
        common = re.search(r"^mod common;", text, re.M) is not None
        helpers = re.search(r"^mod test_helpers;", text, re.M) is not None

        if len(stores) > 1:
            errors.append(f"{rel}: more than one `// ci-store:` marker")
        store = stores[0] if stores else ""
        if store and store not in STORES:
            errors.append(f"{rel}: unknown ci-store '{store}' (one of {', '.join(STORES)})")
        if ungated and (store or serial):
            errors.append(f"{rel}: `ci-ungated` together with a runner marker — pick one")

        if ungated:
            cat = "ungated"
        elif crate == "controller" and common and helpers:
            errors.append(f"{rel}: declares both `mod common;` and `mod test_helpers;`")
            cat = "ctrl"
        elif crate == "controller" and serial:
            cat = "ctrl-serial"
        elif crate == "controller" and common:
            cat = "ctrl"
        elif crate == "controller" and helpers:
            cat = "tc"
        elif store:
            cat = "store"
        else:
            cat = "dbfree"
            if crate != "controller" and SERVICE_ENV_RE.search(text):
                errors.append(
                    f"{rel}: reads a TALOS_TEST_* service variable but has no "
                    "`// ci-store: <migrated|selfcontained|redis|services>` or "
                    "`// ci-ungated: <reason>` marker — without one it would run in "
                    "the DB-free unit job and early-return green"
                )
        if crate == "controller" and store:
            errors.append(f"{rel}: controller binaries are classified by harness, not ci-store")
        targets.append((cat, crate, binary, store, rel))
    if len(targets) < MIN_TARGETS:
        errors.append(f"found only {len(targets)} test targets — the walk is broken")
    return targets, errors


def lib_filters():
    """{crate: [filter, …]} from test-integration.sh's `lib` / `lib-migrated`
    work items. An empty filter is the whole `--lib`."""
    out = {}
    try:
        text = INTEGRATION_SCRIPT.read_text()
    except OSError:
        return out
    for _kind, crate, flt in LIB_FILTER_RE.findall(text):
        out.setdefault(crate, []).append((flt or "").strip())
    return out


def src_files():
    """(crate_dir, path) for every .rs file under a crate's src/."""
    for dirpath, dirnames, files in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        here = Path(dirpath)
        if here.name != "src" or not (here.parent / "Cargo.toml").is_file():
            continue
        for sub, subdirs, subfiles in os.walk(here):
            subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS]
            for f in sorted(subfiles):
                if f.endswith(".rs"):
                    yield here.parent, Path(sub) / f
        dirnames[:] = []


def module_path(src_dir: Path, path: Path) -> str:
    parts = list(path.relative_to(src_dir).with_suffix("").parts)
    if parts and parts[-1] in ("lib", "main", "mod"):
        parts = parts[:-1]
    return "::".join(parts)


def unnamed_lib_tests():
    """Errors for library tests that read a service variable and that no
    test-integration.sh filter names."""
    filters = lib_filters()
    errors = []
    for crate_dir, path in src_files():
        text = path.read_text(errors="replace")
        if not SERVICE_ENV_READ_RE.search(text) or UNGATED_RE.search(text):
            continue
        crate = crate_name(crate_dir)
        base = module_path(crate_dir / "src", path)
        join = (lambda a, b: f"{a}::{b}" if a else b)
        candidates = {base} if base else set()
        for m in INLINE_MOD_RE.findall(text):
            candidates.add(join(base, m))
        for fn in FN_RE.findall(text):
            candidates.add(join(base, fn))
            for m in INLINE_MOD_RE.findall(text):
                candidates.add(join(join(base, m), fn))
        named = any(
            flt == "" or any(flt in c for c in candidates)
            for flt in filters.get(crate, [])
        )
        if not named:
            errors.append(
                f"{path.relative_to(ROOT)}: a library test reads a TALOS_TEST_* service "
                "variable but no `lib`/`lib-migrated` filter in scripts/test-integration.sh "
                "names it — the unit job runs it with no service and it returns green; "
                "name it there or mark the file `// ci-ungated: <reason>`"
            )
    return errors


def self_test():
    """The library-test leg over a fabricated tree: a file that reads a
    service variable is an error until a filter names it or it is marked."""
    import tempfile
    global ROOT, INTEGRATION_SCRIPT
    saved = (ROOT, INTEGRATION_SCRIPT)
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        crate = root / "talos-x"
        (crate / "src" / "deep").mkdir(parents=True)
        (crate / "Cargo.toml").write_text('[package]\nname = "talos-x"\n')
        (crate / "src" / "lib.rs").write_text("pub fn f() {}\n")
        reader = 'let u = std::env::var("TALOS_TEST_DATABASE_URL");\n'
        (crate / "src" / "deep" / "db_tests.rs").write_text(
            "#[tokio::test]\nasync fn lands() {\n" + reader + "}\n"
        )
        (crate / "src" / "other.rs").write_text(
            "#[cfg(test)]\nmod live_redis {\n#[test]\nfn t() {\n"
            'let u = std::env::var("TALOS_TEST_REDIS_URL");\n}\n}\n'
        )
        (crate / "src" / "doc.rs").write_text("/// skips without `TALOS_TEST_DATABASE_URL`\n")
        script = root / "test-integration.sh"
        ROOT, INTEGRATION_SCRIPT = root, script

        def flagged():
            return sorted(e.split(":", 1)[0] for e in unnamed_lib_tests())

        script.write_text("WORK+=(\n)\n")
        if flagged() != ["talos-x/src/deep/db_tests.rs", "talos-x/src/other.rs"]:
            failures.append(f"unnamed readers not both flagged: {flagged()}")
        script.write_text(
            'WORK+=(\n    "lib-migrated|talos-x|--lib deep::db_tests|x [migrated]"\n'
            '    "lib|talos-x|--lib live_redis|y [redis]"\n)\n'
        )
        if flagged():
            failures.append(f"named readers still flagged: {flagged()}")
        script.write_text('WORK+=(\n    "lib|talos-y|--lib|other crate"\n)\n')
        if len(flagged()) != 2:
            failures.append("a filter for another crate must not name these files")
        script.write_text('WORK+=(\n    "lib|talos-x|--lib|whole lib"\n)\n')
        if flagged():
            failures.append(f"a bare --lib names the whole crate: {flagged()}")
        script.write_text("WORK+=(\n)\n")
        (crate / "src" / "other.rs").write_text(
            "// ci-ungated: needs a broker no runner has\n"
            'let u = std::env::var("TALOS_TEST_REDIS_URL");\n'
        )
        if flagged() != ["talos-x/src/deep/db_tests.rs"]:
            failures.append(f"a ci-ungated file must not be flagged: {flagged()}")
    ROOT, INTEGRATION_SCRIPT = saved
    for f in failures:
        print(f"✗ {f}")
    if not failures:
        print("✓ ci_test_targets self-test")
    return 1 if failures else 0


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) < 2 or argv[1] not in ("list", "grouped", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    targets, errors = classify()
    if argv[1] == "check":
        errors = errors + unnamed_lib_tests()
        for e in errors:
            print(f"✗ {e}")
        counts = {c: sum(1 for t in targets if t[0] == c) for c in CATEGORIES}
        summary = ", ".join(f"{c} {n}" for c, n in counts.items())
        print(f"{len(targets)} test targets: {summary}")
        return 1 if errors else 0
    if errors:
        for e in errors:
            print(f"✗ {e}", file=sys.stderr)
        return 1
    if len(argv) != 3 or argv[2] not in CATEGORIES:
        print(f"category must be one of {', '.join(CATEGORIES)}", file=sys.stderr)
        return 2
    chosen = [t for t in targets if t[0] == argv[2]]
    if argv[1] == "list":
        for _cat, crate, binary, store, _rel in chosen:
            print("\t".join(x for x in (crate, binary, store) if x))
    else:
        by_crate = {}
        for _cat, crate, binary, _store, _rel in chosen:
            by_crate.setdefault(crate, []).append(binary)
        for crate in sorted(by_crate):
            print(f"{crate}\t{' '.join(by_crate[crate])}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
