#!/usr/bin/env python3
"""Check 107: a secret map is a `SecretMap` of `Zeroizing` values, never a
`HashMap<String, String>`.

Security review 2026-10-15 (C-10 carried; round 2, "one undocumented hop").
The controller resolved secrets into `talos_workflow_engine_core::SecretMap`
(`HashMap<String, Zeroizing<String>>`) and sealed them from it, but on the
worker side every envelope and every sealed claim opened into a plain
`HashMap<String, String>` that then travelled through `TalosContext::new`,
each `execute_*` entry point and `PipelineStepSpec` (cloned per attempt), and
was wrapped in `Zeroizing` only at the provider's constructor — after it had
lived as long as the job. A standalone run had a declared plaintext exit
(`into_runtime_secrets`) for the same reason. The type is now one end to end;
this check keeps it so.

Rule. In production Rust under each of `ROOTS` (their `src/`; test code
skipped as below), a line whose code names a secret — the word `secret`,
any case, outside a comment — and the type `HashMap<String, String>` (any
spacing, with or without `std::collections::`) fails. The type a secret map
has is `talos_workflow_job_protocol::SecretMap`; a function that only reads
keys is generic over the value type.

Skipped: `/tests/` directories, `*_tests.rs`, `tests.rs`, and each item
marked `#[cfg(test)]` — that item only (braces matched), never the rest of
the file. A comment is not code: the text after `//` on a line is dropped
before matching, so a doc line that explains the old shape is not a finding.

Opt-out: `// plain-secret-map: <reason>` on the line or one of the three
above it.

Limits: textual and per line. A secret map declared through an alias that
is not `SecretMap`, or a `HashMap<String, String>` whose line does not say
`secret` (a return type on its own line under a `fn …_secrets(` line — three
such on main before the fix), is not seen; the compile-time types pin the
rest, since a `SecretMap` cannot be assigned from a plain map.

`--self-test` drives the rule over a fabricated tree.
"""

import os
import re
import sys

MARKER = "plain-secret-map:"
ROOTS = (
    "talos-workflow-job-protocol",
    "talos-envelope-seal",
    "talos-secrets",
    "talos-worker-runtime",
    "worker",
    "talos-oauth",
    "talos-replay-service",
    "talos-mcp-handlers",
    "talos-api",
    "talos-workflow-engine",
    "talos-engine",
    "talos-execution-orchestration",
    "talos-webhooks",
    "talos-integration-helpers",
    "talos-secrets-manager",
)
TYPE_RE = re.compile(r"HashMap\s*<\s*String\s*,\s*String\s*>")
SECRET_RE = re.compile(r"secret", re.IGNORECASE)
SKIP_DIRS = {"target", "node_modules", ".git", ".claude", "frontend", "vendor"}


def files(root):
    """Production `.rs` files under `<root>/<crate>/src` for each crate in
    ROOTS that exists (a fabricated tree in the self-test has one crate)."""
    for crate in ROOTS:
        base = os.path.join(root, crate, "src")
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, names in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d != "tests"]
            for name in sorted(names):
                if name.endswith(".rs") and not name.endswith("_tests.rs") and name != "tests.rs":
                    yield os.path.join(dirpath, name)


def blank_test_items(lines):
    """`lines` with each `#[cfg(test)]` item blanked: from the attribute to
    the end of the item it marks (a `{ … }` block, braces matched, or a `;`
    line). The same walk as scripts/lint-compile-gate.py."""
    out = list(lines)
    i = 0
    while i < len(out):
        if out[i].strip().startswith("#[cfg(test)]"):
            j, depth, opened = i, 0, False
            while j < len(out):
                code = out[j].split("//", 1)[0]
                depth += code.count("{") - code.count("}")
                opened = opened or "{" in code
                done = (opened and depth <= 0) or (not opened and j > i and code.rstrip().endswith(";"))
                out[j] = ""
                if done:
                    break
                j += 1
            i = j + 1
            continue
        i += 1
    return out


def check(root):
    hits, scanned = [], 0
    for path in files(root):
        with open(path, encoding="utf-8", errors="replace") as f:
            raw = f.read().split("\n")
        scanned += 1
        lines = blank_test_items(raw)
        for idx, line in enumerate(lines):
            code = line.split("//", 1)[0]
            if not (TYPE_RE.search(code) and SECRET_RE.search(code)):
                continue
            if any(MARKER in raw[k] for k in range(max(0, idx - 3), idx + 1)):
                continue
            hits.append(f"{os.path.relpath(path, root)}:{idx + 1}: {line.strip()}")
    return hits, scanned


def self_test():
    import tempfile

    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, ROOTS[0], "src")
        os.makedirs(src)
        body = "\n".join(
            [
                "/// A doc line about the old `HashMap<String, String>` of secrets is prose.",
                "pub fn a(secrets: HashMap<String, String>) {}  // flagged: a param",
                "pub fn b() -> Result<std::collections::HashMap<String,String>, E> { secret() }  // flagged: spacing + path",
                "pub struct S { pub secrets: HashMap < String , String > }  // flagged: a field",
                "pub fn headers(h: HashMap<String, String>) {}  // not a secret",
                "pub fn ok(secrets: SecretMap) {}",
                "// plain-secret-map: a legacy reader, removed with #0",
                "pub fn marked(secrets: HashMap<String, String>) {}",
                "#[cfg(test)]",
                "mod t {",
                "    fn z(secrets: HashMap<String, String>) {}",
                "}",
                "pub fn after_tests(secrets: HashMap<String, String>) {}  // flagged",
            ]
        )
        with open(os.path.join(src, "lib.rs"), "w") as f:
            f.write(body + "\n")
        with open(os.path.join(src, "lib_tests.rs"), "w") as f:
            f.write("fn t(secrets: HashMap<String, String>) {}\n")
        os.makedirs(os.path.join(tmp, "talos-unrelated", "src"))
        with open(os.path.join(tmp, "talos-unrelated", "src", "lib.rs"), "w") as f:
            f.write("fn u(secrets: HashMap<String, String>) {}\n")
        hits, scanned = check(tmp)
        got = sorted(int(h.split(":")[1]) for h in hits)
        want = [2, 3, 4, 13]
        if got != want:
            failures.append(f"flagged lines {got}, want {want}")
        if scanned != 1:
            failures.append(f"scanned {scanned} files, want 1 (the tests file and the unlisted crate are skipped)")
    for f in failures:
        print(f"✗ {f}")
    if not failures:
        print("✓ lint-plain-secret-map self-test")
    return 1 if failures else 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    hits, scanned = check(root)
    for h in hits:
        print(h)
    if hits:
        print(f"✗ {len(hits)} line(s) type a secret map as HashMap<String, String> ({scanned} files read)")
        return 1
    print(f"✓ 0 plain secret maps ({scanned} files read)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
