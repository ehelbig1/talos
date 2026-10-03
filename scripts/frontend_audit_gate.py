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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
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
        print(f"::error title=Frontend dependency advisories::{len(blocking)} moderate+ advisory(ies) not covered by an unexpired, reviewed exception. The backlog is kept at ZERO on main, so these are newly introduced.")
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
    try:
        decide(audit(("braces", adv(A))), [{"advisory": A}], day)
        print("FAIL an exception without an expiry is refused"); failed += 1
    except ValueError:
        print("ok   an exception without an expiry is refused")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
