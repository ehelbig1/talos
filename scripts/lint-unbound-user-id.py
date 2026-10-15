#!/usr/bin/env python3
"""Check 104: a repository function that takes `user_id` binds it.

The defect class "a tenant bind a lint cannot see": a repository method takes
the caller's `user_id`, runs SQL, and never binds it — every test passes,
because a single-tenant fixture cannot tell a scoped read from an unscoped one
(security review 2026-10-14, D-8).

Rule. In `talos-*-repository/src/**/*.rs`, a `pub async fn` (or
`pub(crate) async fn`) whose parameters include `user_id: Uuid` and whose body
builds a statement (`sqlx::query`, `query_as`, `query_scalar`,
`sqlx::raw_sql`) must bind it: `.bind(user_id)`, `.bind(&user_id)`,
`.bind(scope.user_id)`, or pass `user_id` on to a call (another method that is
held to the same rule, or `begin_user_scoped(…, user_id)`).

Opt-out: `// allow-unbound-user-id: <reason>` on the `fn` line or one of the
three above it.

Skipped: test code (`/tests/`, `*_tests.rs`, `tests.rs`, and everything after
the first `#[cfg(test)]` line in a file).

Limits: textual. A body is found by brace counting with string and char
literals and comments skipped; raw strings `r"…"`/`r#"…"#` are skipped too. A
bind under another name (`let uid = user_id; … .bind(uid)`) is not seen and
needs the marker. "Passes user_id on" is a call whose argument list names
`user_id`; it does not prove that callee binds it.
"""

import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
MARKER = "allow-unbound-user-id:"
FN_RE = re.compile(r"^\s*pub(?:\(crate\))?\s+async\s+fn\s+(\w+)")
STATEMENT_RE = re.compile(r"\bsqlx::(?:query|query_as|query_scalar|raw_sql)\b|\bquery_as::<|\bquery_scalar::<")
BIND_RE = re.compile(r"\.bind\(\s*&?\s*(?:[a-z_]+\.)?user_id\s*\)")
PASS_ON_RE = re.compile(r"\w\s*\((?:[^()]|\([^()]*\))*\buser_id\b(?:[^()]|\([^()]*\))*\)")


def strip_code(text):
    """Blank out string/char literals and comments, keeping offsets."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        m = re.match(r'r(#*)"', text[i:])
        if m and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            close = '"' + m.group(1)
            j = text.find(close, i + len(m.group(0)))
            j = n if j < 0 else j + len(close)
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            for k in range(i, min(j + 1, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
            continue
        if c == "'" and i + 2 < n and (text[i + 2] == "'" or (text[i + 1] == "\\" and "'" in text[i + 2:i + 5])):
            j = text.find("'", i + 2)
            for k in range(i, j + 1):
                out[k] = " "
            i = j + 1
            continue
        i += 1
    return "".join(out)


def scan(path):
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    cut = raw.find("#[cfg(test)]")
    if cut >= 0:
        raw = raw[:cut]
    code = strip_code(raw)
    lines = raw.split("\n")
    hits = []
    offset = 0
    starts = []
    for line in code.split("\n"):
        starts.append(offset)
        offset += len(line) + 1
    for idx, line in enumerate(code.split("\n")):
        m = FN_RE.match(line)
        if not m:
            continue
        sig_start = starts[idx]
        brace = code.find("{", sig_start)
        if brace < 0:
            continue
        signature = code[sig_start:brace]
        if not re.search(r"\buser_id\s*:\s*(?:uuid::)?Uuid\b", signature):
            continue
        depth, j = 0, brace
        while j < len(code):
            if code[j] == "{":
                depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body_code = code[brace:j]
        body_raw = raw[brace:j]
        if not STATEMENT_RE.search(body_code):
            continue
        if BIND_RE.search(body_code) or PASS_ON_RE.search(body_code):
            continue
        above = "\n".join(lines[max(0, idx - 3):idx + 1])
        if MARKER in above:
            continue
        hits.append(f"{path}:{idx + 1}: pub async fn {m.group(1)} takes user_id and binds it nowhere")
        del body_raw
    return hits


def main():
    hits, scanned = [], 0
    for crate in sorted(os.listdir(ROOT)):
        if not (crate.startswith("talos-") and crate.endswith("-repository")):
            continue
        src = os.path.join(ROOT, crate, "src")
        for dirpath, _, files in os.walk(src):
            if "/tests" in dirpath:
                continue
            for name in sorted(files):
                if not name.endswith(".rs") or name.endswith("_tests.rs") or name == "tests.rs":
                    continue
                scanned += 1
                hits.extend(scan(os.path.join(dirpath, name)))
    for h in hits:
        print(h)
    print(f"scanned {scanned} file(s); {len(hits)} unbound user_id function(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
