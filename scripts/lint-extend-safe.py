#!/usr/bin/env python3
"""Structural check 14: a talos-api `async_graphql::Error::new(` call must be
marked `.extend_safe()`, carry an opt-out, or have a whitelisted message.

The SPECIFICATION — why, which sites, the opt-out marker, the history of the
seed pattern (MCP-916/917/918, MCP-963, MCP-1048, MCP-1051, MCP-1200) — is
the comment block above check 14 in scripts/lint-structural.sh, and the seed
`grep` that chooses the sites stays there. This file is only the per-site
decision, which until 2026-10-05 was a bash loop that spawned `sed`, `echo`
and `grep` for every line it looked at: about 67 of the lint's 194 seconds
for 601 sites.

stdin: the seed's `<file>:<line>:<text>` lines. Prints each violating line,
two-space indented, exactly as the bash loop did; prints nothing when there
is none. A site is NOT a violation when any of these holds:

  1. `.extend_safe()` appears on the site's line, or on a later line before
     the next `async_graphql::Error::new(` — scanning at most 20 lines on,
     and skipping empty lines. On a line holding both, whichever comes first
     decides: a new call before the marker means the marker is the new
     call's, and the site is bare;
  2. `allow-unsafe-error` appears on the site's line or the 8 lines above it;
  3. one of the scrubber's whitelisted substrings appears on the site's line
     or the 5 lines after it (case-sensitive; must match
     `talos_api::schema::SAFE_ERROR_SUBSTRINGS`).

Lines are numbered from 1 as `sed -n Np` numbers them; a line past the end of
the file is empty.

Usage:  … | python3 scripts/lint-extend-safe.py
        python3 scripts/lint-extend-safe.py --self-test
"""
import re
import sys

LOOKAHEAD = 20
OPT_OUT_ABOVE = 8
MESSAGE_LINES = 5
EXTEND_SAFE = b".extend_safe()"
NEW_CALL = b"async_graphql::Error::new("
OPT_OUT = b"allow-unsafe-error"
WHITELIST = re.compile(rb"Authentication|Access denied|Not found|Invalid|Validation|Unauthorized")


def violations(seed_lines, read_file):
    """`seed_lines`: bytes lines `<file>:<line>:<text>`. `read_file(path)` ->
    bytes or None. Returns the violating seed lines, in order."""
    cache = {}

    def file_lines(path):
        if path not in cache:
            data = read_file(path)
            cache[path] = data.split(b"\n") if data is not None else []
        return cache[path]

    out = []
    for raw in seed_lines:
        line = raw.rstrip(b"\n")
        if not line:
            continue
        parts = line.split(b":", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            # The bash loop would have run `sed` with a non-number and
            # matched nothing, so such a line was always reported.
            out.append(line)
            continue
        path, lineno = parts[0], int(parts[1])
        lines = file_lines(path)

        def at(k):
            return lines[k - 1] if 1 <= k <= len(lines) else b""

        if EXTEND_SAFE in at(lineno):
            continue
        found = False
        for k in range(lineno + 1, lineno + LOOKAHEAD + 1):
            text = at(k)
            if not text:
                continue
            i_new, i_safe = text.find(NEW_CALL), text.find(EXTEND_SAFE)
            if i_new != -1 and (i_safe == -1 or i_new < i_safe):
                break
            if i_safe != -1:
                found = True
                break
        if found:
            continue
        if any(OPT_OUT in at(k) for k in range(max(lineno - OPT_OUT_ABOVE, 1), lineno + 1)):
            continue
        if any(WHITELIST.search(at(k)) for k in range(lineno, lineno + MESSAGE_LINES + 1)):
            continue
        out.append(line)
    return out


def read_path(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def self_test():
    """One file per case, so no case can cover another."""
    call = b'    Err(async_graphql::Error::new("boom"))'
    cases = [
        # (name, file lines, seed line number, violation?)
        ("bare", [call], 1, True),
        ("same line", [b'    Err(async_graphql::Error::new("x").extend_safe())'], 1, False),
        ("later line, blank between", [b"    Err(async_graphql::Error::new(", b"", b'        "y",',
                                       b"    ).extend_safe())"], 1, False),
        ("next call first", [call, b'    Err(async_graphql::Error::new("second"))', b".extend_safe()"], 1, True),
        # Until 2026-10-05 a later line holding BOTH a new call and
        # `.extend_safe()` covered the current call: the MCP-1200 blind spot
        # (a sibling's marker covering a bare call), on one line.
        ("next line holds both, call first", [call, b'    Err(async_graphql::Error::new("b").extend_safe())'], 1, True),
        ("next line holds both, marker first",
         [b"    Err(async_graphql::Error::new(", b'        "a",', b'    ).extend_safe()) } else { Err(async_graphql::Error::new("b").extend_safe()) }'],
         1, False),
        ("marker 21 lines on", [call] + [b"x"] * 20 + [b".extend_safe()"], 1, True),
        ("marker 20 lines on", [call] + [b"x"] * 19 + [b".extend_safe()"], 1, False),
        ("runs past the end of the file", [call], 1, True),
        ("opt-out 8 lines above", [b"// allow-unsafe-error: x"] + [b"x"] * 7 + [call], 9, False),
        ("opt-out 9 lines above", [b"// allow-unsafe-error: x"] + [b"x"] * 8 + [call], 10, True),
        ("whitelisted 5 lines on", [b"    Err(async_graphql::Error::new("] + [b"x"] * 4 + [b'"Not found"'], 1, False),
        ("whitelisted 6 lines on", [b"    Err(async_graphql::Error::new("] + [b"x"] * 5 + [b'"Not found"'], 1, True),
        ("whitelist is case-sensitive", [b'    Err(async_graphql::Error::new("not found"))'], 1, True),
    ]
    files, seed, want = {}, [], []
    for i, (name, lines, lineno, bad) in enumerate(cases):
        path = b"case%d.rs" % i
        files[path] = b"\n".join(lines) + b"\n"
        seed.append(path + b":%d:" % lineno + lines[lineno - 1])
        if bad:
            want.append(name)
    seed.append(b"missing.rs:3:    Err(async_graphql::Error::new(")
    want.append("an unreadable file")
    names = {b"case%d.rs" % i: c[0] for i, c in enumerate(cases)}
    names[b"missing.rs"] = "an unreadable file"
    got = [names[v.split(b":", 1)[0]] for v in violations(seed + [b""], files.get)]
    if got != want:
        print("self-test FAILED\n  want %r\n  got  %r" % (want, got))
        return 1
    print("self-test ok: %d cases, %d violations" % (len(cases) + 1, len(want)))
    return 0


def main():
    if "--self-test" in sys.argv:
        return self_test()
    for line in violations(sys.stdin.buffer.read().split(b"\n"), read_path):
        sys.stdout.buffer.write(b"  " + line + b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
