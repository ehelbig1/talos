#!/usr/bin/env python3
"""CANDIDATE lint for package 35, BUILT, MEASURED and REJECTED. Kept so the
numbers can be re-derived rather than re-argued.

The rule: *a refusal must not be constructed with the unclassified
constructor* — i.e. an `mcp_error(...)` whose message reads as a refusal
should be `mcp_denied` / `mcp_not_found`.

It reuses `scripts/mcp-error-inventory.py`'s statement-aware machinery, so it
is not a line grep: comment and string CONTENT is masked before the call sites
are located, and the argument list is walked with a depth-aware paren matcher.

Run with no arguments for the counts; `--list` to see the sites.
"""
import importlib.util, os, re, sys

spec = importlib.util.spec_from_file_location(
    "inv", os.path.join(os.path.dirname(__file__), "mcp-error-inventory.py")
)
inv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inv)

# The refusal vocabulary an operator would recognise in a reply.
REFUSAL = re.compile(
    r"access denied|not owned|belongs to a different user|unauthorized|"
    r"requires .*(admin|privileg|capabilit|identity|context)|ceiling|"
    r"not permitted|not allowed|forbidden|is archived|is terminated|"
    r"is suspended|not a (writable )?member|limit reached|reached its .*limit|"
    r"terminal state|is disabled|is paused|not public|not found",
    re.I,
)
# Messages that name a FAILURE, checked first: "Could not verify actor
# ownership … NOT a statement that the actor is absent" contains "not found"-ish
# refusal words while being a failure.
FAILURE = re.compile(
    r"^\W*(failed|could not|unable|database error)|failed\b|unavailable|"
    r"not available|not configured|is NOT a statement",
    re.I,
)


def main():
    roots = ["talos-mcp-handlers/src"]
    hits = []
    for root in roots:
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in inv.SKIP_DIRS]
            for f in sorted(fn):
                if not f.endswith(".rs"):
                    continue
                p = os.path.join(dp, f)
                for s in inv.scan_file(p):
                    if s["test"] or s["ctor"] != "mcp_error":
                        continue
                    msg = " ".join(s["msg"].split())
                    if FAILURE.search(msg):
                        continue
                    if REFUSAL.search(msg):
                        hits.append((p, s["line"], s["code"], msg[:110]))
    if "--list" in sys.argv:
        for p, l, c, m in hits:
            print(f"{p}:{l}\t{c}\t{m}")
    print(f"{len(hits)} site(s) reported")


if __name__ == "__main__":
    main()
