#!/usr/bin/env python3
"""Check 104: a data-access function that takes `user_id` binds it.

The defect class "a tenant bind a lint cannot see": a repository method takes
the caller's `user_id`, runs SQL, and never binds it — every test passes,
because a single-tenant fixture cannot tell a scoped read from an unscoped one
(security review 2026-10-14, D-8).

Rule. In the `src/` of every workspace crate whose manifest depends on `sqlx`
(until 2026-10-15 only `talos-*-repository`), a `pub async fn` (or
`pub(crate) async fn`) whose parameters include `user_id: Uuid` and whose body
builds a statement (`sqlx::query`, `query_as`, `query_scalar`,
`sqlx::raw_sql`, the `query!` macros) must bind THAT parameter:
`.bind(user_id)`, `.bind(&user_id)`, `.bind(Some(user_id))`, or name it as a
`query!`-family macro argument — or pass it on to a named scoping helper
(`KNOWN_PASS_ON`) or to another function held to this rule. Until 2026-10-15
(D2-5) `.bind(ctx.user_id)` passed for an unbound parameter, and so did
passing `user_id` to any call at all.

Opt-out: `// allow-unbound-user-id: <reason>` on the `fn` line or one of the
three above it.

Skipped: test code (`/tests/`, `*_tests.rs`, `tests.rs`, and everything after
the first `#[cfg(test)]` line in a file).

Limits: textual. A body is found by brace counting with string and char
literals and comments skipped; raw strings `r"…"`/`r#"…"#` are skipped too. A
bind under another name (`let uid = user_id; … .bind(uid)`) is not seen and
needs the marker. A function "held to this rule" is matched by name across
the scanned set, so a same-named function elsewhere counts.

`--self-test` drives the rule over a fabricated crate.
"""

import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
MARKER = "allow-unbound-user-id:"
FN_RE = re.compile(r"^\s*pub(?:\(crate\))?\s+async\s+fn\s+(\w+)")
STATEMENT_RE = re.compile(r"\bsqlx::(?:query|query_as|query_scalar|raw_sql)\b|\bquery_as::<|\bquery_scalar::<")
# The bind names THE PARAMETER: `.bind(user_id)`, `.bind(&user_id)`,
# `.bind(Some(user_id))`. Until 2026-10-15 (D2-5) `.bind(ctx.user_id)` passed
# for a function whose `user_id` parameter was never bound.
BIND_RE = re.compile(r"\.bind\(\s*(?:Some\(\s*)?&?\s*user_id\s*\)")
# A call that names `user_id` among its arguments, with its (possibly
# path-qualified) callee: `begin_user_scoped(pool, user_id)`,
# `TenantReadScope::new(user_id, orgs)`, `self.list_for(user_id, …)`.
CALL_RE = re.compile(
    r"((?:\w+::)*\w+)\s*(?:::<[^>]*>)?\s*\((?:[^()]|\([^()]*\))*\buser_id\b(?:[^()]|\([^()]*\))*\)"
)
# The helpers that scope a transaction or a statement to the user they are
# given: passing `user_id` to one of these IS the bind. A bare name matches a
# call by its last path segment; a qualified one only as written.
KNOWN_PASS_ON = {
    "begin_user_scoped",
    "begin_tenant_read_scoped",
    "begin_user_scoped_on",
    "UnitOfWork::begin_user",
    "TenantReadScope::new",
    "OrgScope::new",
}


# The compile-checked macros bind their trailing arguments positionally:
# `sqlx::query!("… WHERE user_id = $1", user_id)` IS the bind.
MACRO_RE = re.compile(r"\bquery(?:_as|_scalar)?(?:_unchecked)?!\s*\(")


def macro_binds(body_code):
    for m in MACRO_RE.finditer(body_code):
        depth, j = 0, m.end() - 1
        while j < len(body_code):
            if body_code[j] == "(":
                depth += 1
            elif body_code[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if re.search(r"\buser_id\b", body_code[m.end():j]):
            return True
    return False


def passes_on(body_code, held):
    """Whether the body hands `user_id` to a known scoping helper or to a
    function that is itself held to this rule (`held`: the names of every
    scanned function that takes `user_id`)."""
    for m in CALL_RE.finditer(body_code):
        callee = m.group(1)
        last = callee.rsplit("::", 1)[-1]
        if callee in KNOWN_PASS_ON or last in KNOWN_PASS_ON or last in held:
            return True
    return False


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


def functions(path):
    """(name, line_no, takes_user_id, body_code, lines) for each pub async fn."""
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    cut = raw.find("#[cfg(test)]")
    if cut >= 0:
        raw = raw[:cut]
    code = strip_code(raw)
    lines = raw.split("\n")
    offset = 0
    starts = []
    for line in code.split("\n"):
        starts.append(offset)
        offset += len(line) + 1
    out = []
    for idx, line in enumerate(code.split("\n")):
        m = FN_RE.match(line)
        if not m:
            continue
        sig_start = starts[idx]
        brace = code.find("{", sig_start)
        if brace < 0:
            continue
        signature = code[sig_start:brace]
        takes = bool(re.search(r"\buser_id\s*:\s*(?:uuid::)?Uuid\b", signature))
        depth, j = 0, brace
        while j < len(code):
            if code[j] == "{":
                depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((m.group(1), idx, takes, code[brace:j], lines))
    return out


def sqlx_crates(root):
    """Every workspace crate whose manifest depends on `sqlx`."""
    out = []
    for crate in sorted(os.listdir(root)):
        manifest = os.path.join(root, crate, "Cargo.toml")
        if not os.path.isfile(manifest) or not os.path.isdir(os.path.join(root, crate, "src")):
            continue
        with open(manifest, encoding="utf-8") as f:
            if re.search(r"^sqlx\s*[.=]", f.read(), re.M):
                out.append(crate)
    return out


def source_files(root):
    for crate in sqlx_crates(root):
        src = os.path.join(root, crate, "src")
        for dirpath, _, files in os.walk(src):
            if "/tests" in dirpath:
                continue
            for name in sorted(files):
                if not name.endswith(".rs") or name.endswith("_tests.rs") or name == "tests.rs":
                    continue
                yield os.path.join(dirpath, name)


def check(root):
    parsed = [(path, functions(path)) for path in source_files(root)]
    held = {name for _, fns in parsed for (name, _, takes, _, _) in fns if takes}
    hits = []
    for path, fns in parsed:
        for name, idx, takes, body_code, lines in fns:
            if not takes or not STATEMENT_RE.search(body_code):
                continue
            if (
                BIND_RE.search(body_code)
                or macro_binds(body_code)
                or passes_on(body_code, held - {name})
            ):
                continue
            above = "\n".join(lines[max(0, idx - 3):idx + 1])
            if MARKER in above:
                continue
            hits.append(f"{path}:{idx + 1}: pub async fn {name} takes user_id and binds it nowhere")
    return hits, len(parsed)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    hits, scanned = check(ROOT)
    for h in hits:
        print(h)
    print(f"scanned {scanned} file(s); {len(hits)} unbound user_id function(s)")
    return 1 if hits else 0


def self_test():
    import tempfile

    cases = {
        # (body, expected flagged)
        "bound": ("sqlx::query(\"\").bind(user_id)", False),
        "bound_ref": ("sqlx::query(\"\").bind(&user_id)", False),
        "bound_some": ("sqlx::query(\"\").bind(Some(user_id))", False),
        "other_field": ("sqlx::query(\"\").bind(ctx.user_id)", True),
        "scoped": ("let tx = begin_user_scoped(&self.pool, user_id).await?; sqlx::query(\"\")", False),
        "scope_new": ("let s = TenantReadScope::new(user_id, v); sqlx::query(\"\")", False),
        "unrelated_call": ("log(user_id); sqlx::query(\"\")", True),
        "held_callee": ("self.bound(user_id).await; sqlx::query(\"\")", False),
        "no_statement": ("let _ = user_id;", False),
        "macro": ("sqlx::query!(\"\", key_id, user_id)", False),
        "macro_other": ("sqlx::query_as!(T, \"\", key_id)", True),
    }
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        crate = os.path.join(tmp, "talos-x")
        os.makedirs(os.path.join(crate, "src"))
        with open(os.path.join(crate, "Cargo.toml"), "w") as f:
            f.write('[package]\nname = "talos-x"\n[dependencies]\nsqlx.workspace = true\n')
        other = os.path.join(tmp, "talos-y")
        os.makedirs(os.path.join(other, "src"))
        with open(os.path.join(other, "Cargo.toml"), "w") as f:
            f.write('[package]\nname = "talos-y"\n')
        with open(os.path.join(other, "src", "lib.rs"), "w") as f:
            f.write("pub async fn y(user_id: Uuid) { sqlx::query(\"\"); }\n")
        src = []
        for name, (body, _) in cases.items():
            src.append(f"pub async fn {name}(&self, user_id: Uuid) {{ {body} }}")
        src.append("// allow-unbound-user-id: a stated reason")
        src.append("pub async fn marked(user_id: Uuid) { sqlx::query(\"\"); }")
        with open(os.path.join(crate, "src", "lib.rs"), "w") as f:
            f.write("\n".join(src) + "\n#[cfg(test)]\nmod t { pub async fn z(user_id: Uuid) { sqlx::query(\"\"); } }\n")
        hits, _ = check(tmp)
        flagged = {h.split("pub async fn ")[1].split(" ")[0] for h in hits}
        for name, (_, want) in cases.items():
            if (name in flagged) != want:
                failures.append(f"{name}: flagged={name in flagged}, want {want}")
        for name in ("marked", "z", "y"):
            if name in flagged:
                failures.append(f"{name} must not be flagged")
    for f in failures:
        print(f"✗ {f}")
    if not failures:
        print("✓ lint-unbound-user-id self-test")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
