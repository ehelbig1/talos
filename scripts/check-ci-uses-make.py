#!/usr/bin/env python3
"""CI's gates are Makefile targets.

A command that decides whether a change is good is defined once, in the
Makefile, and `.github/workflows/quality.yml` runs `make <target>`. Measured
2026-10-06, before this rule: of the workflow's gate steps, 6 called make and
31 ran cargo, npm or a repository script directly. The lint job ran
`scripts/lint-structural.sh` itself, so two checks added to `make lint` ran on
a developer's machine and never in CI; `make ci` claimed to match CI and ran
under half of it; and 15 script tests had no local command at all.

    check-ci-uses-make.py [ROOT]     exit 1 and name each step that bypasses make
    check-ci-uses-make.py --self-test

What a `run:` step in quality.yml may not do directly:

    cargo <anything but install>     npm run …     npx …
    bash <a script in this repository>     python3 <a script in this repository>

except the runner's own setup, which means nothing on a developer's machine:
SETUP below (free disk, keep one toolchain, classify the diff). `npm ci`,
`cargo install`, apt, psql, helm and docker are setup too and are not matched.

It also holds the one command this rule left in two places identical: the
clippy invocation of `make clippy` (streams, for a CI log) and of structural
check 7 (captures, for `make lint-full`).
"""

from __future__ import annotations

import os
import re
import sys

WORKFLOW = ".github/workflows/quality.yml"

# Runner setup: allowed to be called directly, with the reason.
SETUP = {
    "scripts/ci-free-disk.sh": "frees space on a GitHub runner",
    "scripts/ci-only-pinned-rust.sh": "removes the runner image's other toolchains",
    "scripts/ci-changed-areas.sh": "classifies the diff to decide which jobs run",
}

_DIRECT = re.compile(
    r"(?<![\w./-])(?:"
    r"(?P<cargo>cargo\s+(?!install\b)[a-z][\w-]*)"
    r"|(?P<npm>npm\s+run\s+[\w:-]+|npx\s+[\w@/.-]+)"
    r"|(?:bash|python3|sh)\s+(?:\.\./)*(?P<script>[\w][\w./-]*\.(?:sh|py))(?![\w-])"
    r")"
)

CLIPPY = "cargo clippy --workspace --all-targets --no-deps -- -D warnings"


def run_steps(text: str) -> list[tuple[int, str, str]]:
    """(line number, step name, shell text) of every `run:` in a workflow."""
    lines = text.split("\n")
    out = []
    name = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^\s*-\s+name:\s*(.*)$", line)
        if m:
            name = m.group(1).strip().strip("'\"")
        m = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", line)
        if not m:
            i += 1
            continue
        indent, value = len(m.group(1)), m.group(2).strip()
        start = i + 1
        if value[:1] in ("|", ">"):
            body = []
            i += 1
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                body.append(lines[i])
                i += 1
            out.append((start, name, "\n".join(body)))
        else:
            out.append((start, name, value))
            i += 1
    return out


def code_only(shell: str) -> str:
    """The step's commands, without comment lines and without the text of
    echo/printf messages (which quote commands when they explain a failure)."""
    kept = []
    for raw in shell.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"""(?:echo|printf)\s+(?:"(?:[^"\\]|\\.)*"|'[^']*')""", "echo", line)
        kept.append(line)
    return "\n".join(kept)


def bypasses(text: str) -> list[str]:
    found = []
    for line_no, name, shell in run_steps(text):
        for m in _DIRECT.finditer(code_only(shell)):
            script = m.group("script")
            if script and script in SETUP:
                continue
            what = m.group("cargo") or m.group("npm") or script
            found.append(f"{WORKFLOW}:{line_no}: step {name!r} runs `{what}` directly")
    return found


def problems(root: str) -> list[str]:
    try:
        with open(os.path.join(root, WORKFLOW), encoding="utf-8") as fh:
            workflow = fh.read()
    except OSError:
        return [f"{WORKFLOW}: not found"]
    out = bypasses(workflow)
    if not run_steps(workflow):
        out.append(f"{WORKFLOW}: no `run:` step was read — has the file's shape changed?")
    if not re.search(r"(?<![\w-])make\s+[a-z]", workflow):
        out.append(f"{WORKFLOW}: no step runs `make` at all")
    for rel in ("Makefile", "scripts/lint-structural.sh"):
        try:
            with open(os.path.join(root, rel), encoding="utf-8") as fh:
                if CLIPPY not in fh.read():
                    out.append(f"{rel}: the clippy command is no longer `{CLIPPY}` — `make clippy` and structural check 7 must run the same one")
        except OSError:
            out.append(f"{rel}: not found")
    return out


def self_test() -> int:
    def wf(*steps: str) -> str:
        return "jobs:\n  j:\n    steps:\n" + "".join(steps)

    def step(name: str, run: str, block: bool = True) -> str:
        if not block:
            return f"      - name: {name}\n        run: {run}\n"
        body = "".join(f"          {l}\n" for l in run.split("\n"))
        return f"      - name: {name}\n        # a comment\n        run: |\n{body}"

    def expect(needle: str | None, text: str) -> None:
        got = bypasses(text)
        if needle is None:
            assert got == [], got
        else:
            assert len(got) == 1 and needle in got[0], (needle, got)

    expect(None, wf(step("lint", "make lint", block=False)))
    expect(None, wf(step("lint", "make lint\nmake check-lockfile")))
    # Setup is not a gate.
    expect(None, wf(step("disk", "bash scripts/ci-free-disk.sh", block=False)))
    expect(None, wf(step("deps", "npm ci", block=False)))
    expect(None, wf(step("tool", "cargo install cargo-deny --locked", block=False)))
    expect(None, wf(step("db", 'psql "$URL" -c "CREATE DATABASE x;"\nhelm version\nsudo apt-get install -y -qq jq')))
    expect(None, wf(step("classify", 'out="$(bash scripts/ci-changed-areas.sh "$A" "$B")"')))
    # A gate wrapped in annotations is still a make call.
    expect(None, wf(step("audit", 'if make audit; then exit 0; fi\necho "::error::run cargo deny check yourself"\nexit 1')))
    expect(None, wf(step("say", "# cargo test would be wrong here\nmake test-unit")))
    expect(None, wf(step("say", "printf 'fix with: cargo fmt --all\\n'\nmake lint")))
    # Each way of bypassing it.
    expect("`cargo nextest`", wf(step("unit", "cargo nextest run --workspace", block=False)))
    expect("`cargo test`", wf(step("doc", "set -e\ncargo test --workspace --doc")))
    expect("`cargo clippy`", wf(step("clippy", "cargo clippy --workspace -- -D warnings 2>&1 | tee x.log")))
    expect("`cargo update`", wf(step("lock", "cargo update --workspace --locked", block=False)))
    expect("`npm run lint`", wf(step("fe", "npm run lint", block=False)))
    expect("`npx tsc`", wf(step("fe", "npx tsc --noEmit", block=False)))
    expect("scripts/lint-structural.sh", wf(step("lint", "bash scripts/lint-structural.sh", block=False)))
    expect("scripts/tests/x-test.sh", wf(step("t", "bash scripts/tests/x-test.sh", block=False)))
    expect("scripts/check-x.py", wf(step("t", "python3 scripts/check-x.py --self-test", block=False)))
    expect("scripts/gate.py", wf(step("t", "cd frontend\nprintf '%s' \"$out\" | python3 ../scripts/gate.py --x")))
    expect("deploy/k3s/tests/x-test.sh", wf(step("t", "bash deploy/k3s/tests/x-test.sh", block=False)))
    expect(None, wf(step("t", 'bash "$RUNNER_TEMP/generated.sh"\npython3 -c "print(1)"\nbash -c "true"')))
    expect("`cargo deny`", wf(step("a", "if ! cargo deny check; then exit 1; fi")))
    # Two bypasses in one step are both named; the step is named by line.
    both = bypasses(wf(step("ok", "make lint", block=False), step("two", "cargo test\nnpm run test")))
    assert len(both) == 2 and all("'two'" in b for b in both), both
    assert both[0].startswith(f"{WORKFLOW}:"), both
    # The reader sees block and inline forms, and where a block ends.
    steps = run_steps(wf(step("a", "one\ntwo"), step("b", "three", block=False)))
    assert [(n, s.split()) for _, n, s in steps] == [("a", ["one", "two"]), ("b", ["three"])], steps
    print("check-ci-uses-make self-test: ok")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = problems(root)
    if found:
        print(f"✗ {len(found)} CI step(s) run a gate without the Makefile:", file=sys.stderr)
        for line in found:
            print(f"  {line}", file=sys.stderr)
        print("  give the command a target in the Makefile and run `make <target>` in the step", file=sys.stderr)
        return 1
    print("✓ every gate in quality.yml is a make target")
    return 0


if __name__ == "__main__":
    sys.exit(main())
