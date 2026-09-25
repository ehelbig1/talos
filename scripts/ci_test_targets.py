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

Usage:
  ci_test_targets.py list <category>   crate<TAB>binary[<TAB>store] per line
  ci_test_targets.py grouped dbfree    crate<TAB>bin1 bin2 … (one line per crate)
  ci_test_targets.py check             validate every marker; non-zero on error
"""
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


def crate_name(crate_dir: Path) -> str:
    try:
        for line in (crate_dir / "Cargo.toml").read_text().splitlines():
            m = re.match(r'^name\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    except OSError:
        pass
    return crate_dir.name


def test_files():
    for tests_dir in sorted(ROOT.rglob("tests")):
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


def main(argv):
    if len(argv) < 2 or argv[1] not in ("list", "grouped", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    targets, errors = classify()
    if argv[1] == "check":
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
