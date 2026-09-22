"""Read Rust sources the way they are WRITTEN — one home.

WHY THIS EXISTS, measured rather than asserted. The house style breaks SQL
strings and method chains across lines with `\\` continuations:

    "UPDATE workflow_executions \\
     SET status = 'failed', ... \\
     WHERE id = $1 AND status NOT IN (...)"

A single-line grep cannot see that statement, so a check written as one is
green over a population it never reads. On 2026-09-22, measured on this tree:

  * check 39 (`workflow_executions` status writes must carry a status guard)
    matched **0** lines while **19** such statements exist — 0 % of its own
    population, and its own comment already admitted "multi-line SQL are out
    of scope".
  * the `talos-execution-finalizer` source pins asserted
    `!src.contains("UPDATE workflow_executions SET status = 'failed'")` over
    five files. That needle is one contiguous string, so in the house style
    it can never match: the assertion was provably unfireable, and five such
    statements existed in two of the five files.

Both are the "a check that matches nothing is a green tick over nothing"
shape (checks 64/65) applied to the SCANNER rather than the runner.

CONTRACT. `string_literals` yields every Rust string literal with `\\`-newline
continuations JOINED (so the text reads as the statement Postgres receives)
and the 1-based line the literal STARTS on. Comments outside literals are
skipped, so a commented-out statement is not a finding. Test modules are
removed by `strip_test_modules`, the same column-0 rule check 58 uses — and
for the same reason: a detector that reads its own fixtures reports on
itself.

STATED LIMITS.
  * Line numbers are the literal's START, not the matched clause's. A
    statement spanning ten lines reports the first; that is what a reader
    needs to find it, and tracking per-character lines through a joined text
    would be precision nobody consumes.
  * `strip_test_modules` blanks a column-0 `#[cfg(test)]` only when the NEXT
    line opens a `mod`, and ends the region at the first column-0 `}`. Both
    choices err the same way: a region not recognised, or ended early, leaves
    test code IN the haystack and OVER-reports. Blanking too much would HIDE
    a real finding, which is why `#[cfg(test)]` on a lone `fn` is left alone
    — check 58's rule, and the reason this is the one shape the shared
    primitive does not make configurable.
  * A statement assembled with `format!` or `concat!`, or reached through a
    `const`, is not a literal here and is invisible. `lint-sql-prepare.py`
    resolves those for its own purpose; this module deliberately does not,
    because a resolver that is wrong is worse than a gap that is stated.
  * This is a LEXER, not a parser: it knows string, raw-string, byte-string
    and char literals and comments, and nothing else about Rust.

No subprocess, no network, no `eval`; one linear pass per file.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, NamedTuple

__all__ = [
    "Literal",
    "string_literals",
    "strip_test_modules",
    "normalized",
    "rust_sources",
]


class Literal(NamedTuple):
    """One Rust string literal: its CONTENT, and the line it starts on."""

    text: str
    line: int


def strip_test_modules(src: str) -> str:
    """Blank column-0 `#[cfg(test)]` modules, preserving line numbering.

    Lines are replaced by empty ones rather than deleted so every caller's
    reported line still matches the file on disk.
    """
    lines = src.split("\n")
    out: list[str] = []
    in_test = False
    for i, line in enumerate(lines):
        if (
            not in_test
            and line.startswith("#[cfg(test)]")
            and i + 1 < len(lines)
            and lines[i + 1].startswith("mod ")
        ):
            in_test = True
        if in_test:
            out.append("")
            if line == "}":
                in_test = False
            continue
        out.append(line)
    return "\n".join(out)


def _skip_char_literal(src: str, i: int, n: int) -> int:
    """Return the index just past a char literal starting at `i` ('), or `i`
    itself when this is a LIFETIME (`'static`, `'a`) rather than a literal.

    Needed because a char literal may contain a double quote — `'"'` — which
    would otherwise open a phantom string and desynchronise everything after
    it.
    """
    if i + 1 >= n:
        return i
    if src[i + 1] == "\\":
        j = i + 2
        while j < n and src[j] != "'":
            if src[j] == "\\":
                j += 1
            j += 1
        return j + 1 if j < n else n
    if i + 2 < n and src[i + 2] == "'":
        return i + 3
    return i


def string_literals(src: str) -> Iterator[Literal]:
    """Yield every string literal in `src`, continuations joined."""
    i = 0
    n = len(src)
    line = 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            end = n if end < 0 else end + 2
            line += src.count("\n", i, end)
            i = end
            continue
        if c == "'":
            j = _skip_char_literal(src, i, n)
            if j > i:
                line += src.count("\n", i, j)
                i = j
                continue
            i += 1
            continue
        # r"..", r#".."#, b"..", br#".."# — the prefix is consumed with the
        # literal so a raw string's backslashes are never read as escapes.
        raw = False
        start = i
        j = i
        while j < n and src[j] in "br":
            if src[j] == "r":
                raw = True
            j += 1
        if j > i and j < n and (src[j] == '"' or (raw and src[j] == "#")):
            i = j
        elif j > i:
            i += 1
            continue
        if raw and i < n and (src[i] == "#" or src[i] == '"'):
            hashes = 0
            while i < n and src[i] == "#":
                hashes += 1
                i += 1
            if i >= n or src[i] != '"':
                i = start + 1
                continue
            closer = '"' + "#" * hashes
            end = src.find(closer, i + 1)
            end = n if end < 0 else end
            body = src[i + 1 : end]
            yield Literal(body, line)
            line += src.count("\n", start, end)
            i = end + len(closer)
            continue
        if i < n and src[i] == '"':
            j = i + 1
            buf: list[str] = []
            begin = line
            while j < n:
                d = src[j]
                if d == "\\" and j + 1 < n:
                    if src[j + 1] == "\n":
                        # Continuation: the newline and the next line's
                        # leading whitespace are not part of the string.
                        line += 1
                        j += 2
                        while j < n and src[j] in " \t":
                            j += 1
                        continue
                    buf.append(d)
                    buf.append(src[j + 1])
                    j += 2
                    continue
                if d == '"':
                    break
                if d == "\n":
                    line += 1
                buf.append(d)
                j += 1
            yield Literal("".join(buf), begin)
            i = j + 1
            continue
        i += 1


_WS = re.compile(r"\s+")


def normalized(text: str) -> str:
    """Collapse whitespace so a clause can be matched without caring how the
    author wrapped it."""
    return _WS.sub(" ", text).strip()


def rust_sources(root: Path, globs: list[str], skip_tests: bool = True) -> Iterator[Path]:
    """Production `.rs` files under `root` matching `globs`.

    `skip_tests` drops `tests/` directories and `*_tests.rs`; in-file
    `#[cfg(test)]` modules are the CALLER's job via `strip_test_modules`,
    because some callers legitimately want them.
    """
    for pattern in globs:
        for path in sorted(root.glob(pattern)):
            rel = path.as_posix()
            if skip_tests and ("/tests/" in rel or path.name.endswith("_tests.rs")):
                continue
            yield path


def _self_test() -> int:
    """Every shape this lexer has to survive, and the two it must not be
    fooled by. Run unconditionally by the lint, so a regression here cannot
    hide behind a check that happens to report zero."""
    cases: list[tuple[str, str, list[str]]] = [
        (
            "continuation joined",
            'let q = "UPDATE t \\\n     SET a = 1 \\\n     WHERE id = $1";',
            ["UPDATE t SET a = 1 WHERE id = $1"],
        ),
        ("plain", 'let q = "SELECT 1";', ["SELECT 1"]),
        ("escaped quote", r'let q = "say \"hi\"";', [r'say \"hi\"']),
        (
            "escaped backslash then newline is NOT a continuation",
            'let q = "a\\\\\nb";',
            ["a\\\\\nb"],
        ),
        ("raw string", 'let q = r"C:\\path";', ["C:\\path"]),
        ("raw hashed", 'let q = r#"he said "hi""#;', ['he said "hi"']),
        ("byte string", 'let q = b"bytes";', ["bytes"]),
        ("line comment is not a literal", '// "UPDATE t SET x = 1"\nlet a = 1;', []),
        ("block comment is not a literal", '/* "UPDATE t" */ let a = 1;', []),
        # The two that desynchronise a naive lexer.
        ("char literal holding a quote", "let c = '\"'; let q = \"real\";", ["real"]),
        ("lifetime is not a char literal", "fn f<'a>(x: &'a str) {} let q = \"real\";", ["real"]),
    ]
    failures = 0
    for name, src, expected in cases:
        got = [lit.text for lit in string_literals(src)]
        if got != expected:
            print(f"  self-test FAILED [{name}]: expected {expected!r}, got {got!r}")
            failures += 1

    # Line numbers point at the literal's START.
    src = 'fn a() {}\n\nlet q = "UPDATE t \\\n     SET x = 1";\n'
    lits = list(string_literals(src))
    if len(lits) != 1 or lits[0].line != 3:
        print(f"  self-test FAILED [line number]: got {lits!r}")
        failures += 1

    # `#[cfg(test)]` on something that is NOT a `mod` is left ALONE. Blanking
    # it would hide a real finding, which is the unsafe direction; the
    # mutation run caught nothing here until this case existed, because no
    # file on the tree currently has the shape.
    lone = '#[cfg(test)]\nfn helper() { let q = "keep-me"; }\n'
    if [lit.text for lit in string_literals(strip_test_modules(lone))] != ["keep-me"]:
        print("  self-test FAILED [cfg(test) on a lone fn must not be stripped]")
        failures += 1

    # Test modules are blanked, and line numbering survives it.
    src = 'let a = "keep";\n#[cfg(test)]\nmod t {\n    let b = "drop";\n}\nlet c = "keep2";\n'
    kept = [lit.text for lit in string_literals(strip_test_modules(src))]
    if kept != ["keep", "keep2"]:
        print(f"  self-test FAILED [test strip]: got {kept!r}")
        failures += 1
    if len(strip_test_modules(src).split("\n")) != len(src.split("\n")):
        print("  self-test FAILED [test strip changed the line count]")
        failures += 1

    if failures:
        print(f"  ruststmt self-test: {failures} failure(s)")
        return 1
    print(f"  ruststmt self-test ok: {len(cases) + 4} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
