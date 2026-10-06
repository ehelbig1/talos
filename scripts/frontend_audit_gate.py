#!/usr/bin/env python3
"""The frontend dependency-advisory gate's decision, given `npm audit --json`.

Fails (exit 1) when any moderate-or-worse advisory remains after the reviewed,
unexpired exceptions in frontend/audit-exceptions.json. Exceptions name ONE
advisory URL each and carry an expiry date; an expired one fails the gate
again, which forces a re-review rather than a permanent waiver.

The decision is per ADVISORY, not per package: npm lists every package that
depends on a vulnerable one as a vulnerability of its own (with `via` naming
that package), so a single advisory in `braces` appears as ten entries. Only
the `via` objects carry an advisory URL.

The transport cases (no answer, unparseable output, an `error` object) stay in
the workflow step: they are UNKNOWN, not clean, and are reported there.

    npm audit --json | python3 scripts/frontend_audit_gate.py --exceptions frontend/audit-exceptions.json
    python3 scripts/frontend_audit_gate.py --self-test
"""
import argparse
import datetime as dt
import json
import sys

GATED = ("critical", "high", "moderate")


def advisories(audit: dict) -> dict:
    """{url: (severity, title, package)} for every moderate+ advisory."""
    found = {}
    for pkg, v in (audit.get("vulnerabilities") or {}).items():
        for via in v.get("via") or []:
            if isinstance(via, dict) and via.get("severity") in GATED:
                url = via.get("url") or f"{pkg}:{via.get('title', '?')}"
                found.setdefault(url, (via["severity"], via.get("title", ""), pkg))
    return found


def decide(audit: dict, exceptions: list, today: dt.date):
    """(blocking, excepted, expired) — each a sorted list of advisory URLs."""
    found = advisories(audit)
    active, expired = set(), set()
    for e in exceptions:
        url, until = e.get("advisory"), e.get("expires")
        if not url or not until:
            raise ValueError(f"an exception needs 'advisory' and 'expires': {e}")
        if dt.date.fromisoformat(until) >= today:
            active.add(url)
        else:
            expired.add(url)
    blocking = sorted(u for u in found if u not in active)
    excepted = sorted(u for u in found if u in active)
    return blocking, excepted, sorted(u for u in expired if u in found), found


def whose(deps_changed: str) -> str:
    """What a blocking advisory has to do with the change under test.

    Measured over 150 runs of quality.yml (2026-10-01..06): four of nine
    failures were an advisory published since the last run, on a pull request
    that touched no dependency. The message used to end "so these are newly
    introduced", which reads as "introduced by this change".
    """
    if deps_changed == "no":
        return ("This change touches no dependency file, so it did not introduce them: the advisory "
                "database changed, and main has the same advisories. Fix them in a pull request of "
                "their own (docs/ci.md, 'A new advisory'); this one stays red until that merges.")
    if deps_changed == "yes":
        return ("This change touches dependency files: check whether it introduced them. If it did "
                "not, the advisory database changed and main has them too.")
    return ("Either the advisory database changed or a dependency change introduced them; main is "
            "kept at zero, so they are new since its last green run.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--deps-changed", choices=("yes", "no", "unknown"), default="unknown",
                    help="whether the change under test touches frontend dependency files")
    ap.add_argument("--exceptions", required=False)
    ap.add_argument("--today", help="ISO date; default is today (UTC)")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    audit = json.load(sys.stdin)
    exceptions = []
    if a.exceptions:
        with open(a.exceptions) as f:
            exceptions = json.load(f).get("exceptions", [])
    today = dt.date.fromisoformat(a.today) if a.today else dt.datetime.now(dt.timezone.utc).date()
    blocking, excepted, expired, found = decide(audit, exceptions, today)
    by_url = {e["advisory"]: e for e in exceptions}
    for u in excepted:
        sev, title, pkg = found[u]
        print(f"::warning title=Frontend advisory EXCEPTED until {by_url[u]['expires']}::{sev} {pkg}: {title} ({u}) — {by_url[u].get('reason', '')}")
    for u in expired:
        print(f"::warning title=Frontend advisory exception EXPIRED::{u} expired {by_url[u]['expires']}; it blocks again until re-reviewed")
    print(f"Frontend advisories — {len(found)} moderate+ advisory(ies), {len(excepted)} excepted, {len(blocking)} blocking")
    if blocking:
        for u in blocking:
            sev, title, pkg = found[u]
            print(f"  {sev}\t{pkg}\t{title}\t{u}")
        print(f"::error title=Frontend dependency advisories::{len(blocking)} moderate+ advisory(ies) not covered by an unexpired, reviewed exception. {whose(a.deps_changed)}")
        return 1
    return 0


def self_test() -> int:
    def audit(*vias):
        vulns = {}
        for pkg, via in vias:
            vulns.setdefault(pkg, {"severity": "high", "via": []})["via"].append(via)
        return {"vulnerabilities": vulns}
    adv = lambda url, sev="high": {"url": url, "severity": sev, "title": "t"}
    A, B = "https://github.com/advisories/GHSA-a", "https://github.com/advisories/GHSA-b"
    day = dt.date(2026, 10, 3)
    cases = [
        ("no advisories", audit(), [], ([], [])),
        ("one advisory, no exception", audit(("braces", adv(A))), [], ([A], [])),
        ("transitive entries are one advisory", audit(("braces", adv(A)), ("micromatch", "braces"), ("globby", "micromatch")), [], ([A], [])),
        ("an unexpired exception covers it", audit(("braces", adv(A))), [{"advisory": A, "expires": "2026-11-03"}], ([], [A])),
        ("the expiry day still covers", audit(("braces", adv(A))), [{"advisory": A, "expires": "2026-10-03"}], ([], [A])),
        ("an expired exception blocks again", audit(("braces", adv(A))), [{"advisory": A, "expires": "2026-10-02"}], ([A], [])),
        ("an exception covers only its advisory", audit(("braces", adv(A)), ("busboy", adv(B))), [{"advisory": A, "expires": "2026-11-03"}], ([B], [A])),
        ("low is not gated", audit(("x", adv(A, "low"))), [], ([], [])),
    ]
    failed = 0
    for name, a, exc, (want_block, want_exc) in cases:
        blocking, excepted, _, _ = decide(a, exc, day)
        ok = (blocking, excepted) == (want_block, want_exc)
        failed += not ok
        print(("ok  " if ok else "FAIL"), name, "" if ok else f"got {blocking} {excepted}")
    for flag, must, must_not in (
        ("no", "did not introduce them", "check whether it introduced"),
        ("yes", "check whether it introduced them", "did not introduce them"),
        ("unknown", "Either the advisory database changed", "This change touches"),
    ):
        text = whose(flag)
        ok = must in text and must_not not in text
        failed += not ok
        print(("ok  " if ok else "FAIL"), f"--deps-changed {flag} says whose the advisories are")
    try:
        decide(audit(("braces", adv(A))), [{"advisory": A}], day)
        print("FAIL an exception without an expiry is refused"); failed += 1
    except ValueError:
        print("ok   an exception without an expiry is refused")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
