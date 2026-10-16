#!/usr/bin/env python3
"""Write a catalog template, and check it the way CI will.

    make new-template SLUG=<slug> ROLE=<role> [HOST=<host>]
        scripts/template.py new <slug> --role <role> [--host <host>] [--display-name ...] [--description ...]
    make record-template TEMPLATE=<slug>
        scripts/template.py record <slug>
    make template TEMPLATE=<slug>
        scripts/template.py check <slug>
    scripts/template.py --self-test

`new` copies the skeleton for the role (talos-catalog-tests/skeletons/) into
module-templates/<slug>/ and names it: a working template that already
passes every gate, in the safe shape for its role. A reader is GET-only and
bounded; a sender is POST-only with DRY_RUN on by default; a decider, keeper
and composer reach no network. It never grants `*`, never a secret path, and
grants only the one host you name.

`record` writes the template's recorded run (fixtures/) from the test that
calls `talos_module_testkit::recorded_run::keep`, then scans what it wrote.

`check` runs every gate CI runs on a template, in the order that fails
fastest, and stops at the first one that fails with what to do:

  1. no identifiers (this repository is public);
  2. the catalog's tests: the template's own, and every gate
     (the compile lint, role and grants, hosts used = hosts granted,
     config read = config declared, failure kinds, planted faults);
  3. it compiles for the sandbox, with only the crates it declares;
  4. its recorded run fits the fuel it declares (printing a budget to
     paste when it declares none).
"""
import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "module-templates"
SKELETONS = ROOT / "talos-catalog-tests" / "skeletons"
ROLES = ("reader", "decider", "keeper", "composer", "sender")
# The roles that reach a network, and so name the one host they reach.
NETWORK_ROLES = ("reader", "sender")
SKELETON_HOST = "api.example.com"
SLUG_RE = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*")
# A host as allowed_hosts names one: lower-case labels, at least one dot, no
# scheme, port, path or wildcard.
HOST_RE = re.compile(r"(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


class Refused(Exception):
    """The command cannot go ahead. The message says what to change."""


def slug_ok(slug):
    return bool(SLUG_RE.fullmatch(slug)) and len(slug) <= 64 and not slug.startswith("skeleton-")


def host_ok(host):
    return bool(HOST_RE.fullmatch(host))


def snake(slug):
    return slug.replace("-", "_")


def rendered(role, slug, host, display_name, description):
    """The files of a new template: `{relative path: text}`. Writes nothing."""
    if role not in ROLES:
        raise Refused(f"ROLE must be one of {', '.join(ROLES)}")
    if not slug_ok(slug):
        raise Refused("SLUG must be lower-case words joined by single hyphens (for example acme-invoice-reader), "
                      "and not start with skeleton-")
    if role in NETWORK_ROLES:
        if not host:
            raise Refused(f"a {role} reaches one service: give HOST=<its API host>, for example api.acme.example")
        if not host_ok(host):
            raise Refused("HOST is a host name only (api.acme.example): no scheme, port, path or *")
    elif host:
        raise Refused(f"a {role} reaches no network, so it takes no HOST")
    skeleton = SKELETONS / f"skeleton-{role}"
    names = {
        f"skeleton-{role}": slug,
        f"skeleton_{role}": snake(slug),
        f"Skeleton {role.title()}": display_name or slug.replace("-", " ").title(),
    }
    if host:
        names[SKELETON_HOST] = host
    files = {}
    for path in sorted(skeleton.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text()
        for old, new in names.items():
            text = text.replace(old, new)
        files[str(path.relative_to(skeleton))] = text
    manifest = json.loads(files["talos.json"])
    if description:
        manifest["description"] = description
    files["talos.json"] = json.dumps(manifest, indent=2) + "\n"
    # What a copy must never carry, whatever a skeleton holds.
    if any(h == "*" for h in manifest.get("allowed_hosts", [])) or manifest.get("requires_secrets"):
        raise Refused("a skeleton grants * or a secret; a new template starts with neither")
    if role in NETWORK_ROLES and manifest.get("allowed_hosts") != [host]:
        raise Refused(f"a new {role} is granted exactly its one host")
    return files


def new(args):
    target = TEMPLATES / args.slug
    if target.exists():
        raise Refused(f"{target} already exists")
    files = rendered(args.role, args.slug, args.host, args.display_name, args.description)
    for relative, text in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    print(f"wrote module-templates/{args.slug}/ from the {args.role} skeleton: {', '.join(sorted(files))}")
    print()
    print("next:")
    print(f"  1. write the logic and its tests in module-templates/{args.slug}/template.rs (the TODOs say where),")
    print("     and say in talos.json what it does (description, config_schema, setup_instructions);")
    if args.role != "keeper":
        print(f"  2. make record-template TEMPLATE={args.slug}   (writes fixtures/ from the test that keeps its run)")
    print(f"  {'3' if args.role != 'keeper' else '2'}. make template TEMPLATE={args.slug}          (every gate CI runs; prints a fuel budget to paste)")
    return 0


def run(cmd, env=None):
    """Run a step; return (ok, output)."""
    import os
    full_env = dict(os.environ, **(env or {}))
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=full_env)
    return proc.returncode == 0, proc.stdout + proc.stderr


def relevant(output, slug, limit=60):
    """The lines of a failure worth reading: each failing test's whole message
    (from `panicked at` to the note after it), then any other line about this
    template; when there is neither, the error lines, then the tail."""
    lines = [l for l in output.splitlines() if "SCCACHE" not in l]
    picked, inside = [], False
    for line in lines:
        if "panicked at" in line:
            inside = True
        elif inside and (line.startswith(("note:", "stack backtrace", "failures:", "---- ")) or line.startswith("test ")):
            inside = False
        if inside:
            picked.append(line)
    if not picked:
        quiet = ("Compiling", "Finished", "Running", "Checking", "Downloaded", "Blocking")
        noisy = [l for l in lines if l.strip() and not l.lstrip().startswith(quiet)]
        picked = [l for l in noisy if slug in l or snake(slug) in l] \
            or [l for l in noisy if any(w in l for w in ("error", "FAILED", "refused", "❌"))] or noisy
    return "\n".join(picked[-limit:])


def template_dir(slug):
    if not slug_ok(slug):
        raise Refused("TEMPLATE is a template's directory name (lower-case words joined by hyphens)")
    target = TEMPLATES / slug
    if not (target / "talos.json").is_file() or not (target / "template.rs").is_file():
        raise Refused(f"module-templates/{slug}/ has no talos.json and template.rs: `make new-template` writes one")
    return target


def record(args):
    template_dir(args.slug)
    ok, out = run(["cargo", "test", "-q", "-p", "talos-catalog-tests", "--lib", f"{snake(args.slug)}::"], {"TALOS_RECORD_RUNS": "1"})
    if not ok:
        print(relevant(out, args.slug), file=sys.stderr)
        raise Refused("the template's tests failed, so nothing was recorded from them")
    fixtures = TEMPLATES / args.slug / "fixtures"
    if not (fixtures / "http.json").is_file():
        raise Refused("no test kept a run: end one test with "
                      f'talos_module_testkit::recorded_run::keep("{args.slug}", &envelope)')
    ok, out = run([sys.executable, "scripts/promote-module.py", "--scan", "--slug", args.slug])
    if not ok:
        print(out, file=sys.stderr)
        raise Refused("the recording holds an identifier: make the test's data made-up, then record again")
    print(f"recorded module-templates/{args.slug}/fixtures/ from its test. Read the diff before committing it.")
    return 0


def check(args):
    target = template_dir(args.slug)
    steps = [
        ("no identifiers", [sys.executable, "scripts/promote-module.py", "--scan", "--slug", args.slug], None,
         "replace each with a made-up value: an address at example.com, a Google project named example-…"),
        ("its tests and every catalog gate", ["cargo", "test", "-q", "-p", "talos-catalog-tests"], None,
         "the message above says what is wrong and what to change"),
        ("it compiles for the sandbox", ["bash", "scripts/check-catalog.sh"], {"TEMPLATE": args.slug},
         "the compile error above is from the platform's own compile path"),
    ]
    if (target / "fixtures" / "http.json").is_file():
        steps.append(("its recorded run fits its fuel", ["cargo", "test", "-q", "-p", "talos-catalog-tests", "--test", "fuel_fixtures", "--", "--nocapture"],
                      {"TALOS_TEST_CATALOG_FUEL": "1", "TEMPLATE": args.slug},
                      "declare the recommended_fuel printed above in talos.json, sized for the largest payload it should handle"))
    for n, (title, cmd, env, fix) in enumerate(steps, 1):
        print(f"[{n}/{len(steps)}] {title} … ", end="", flush=True)
        ok, out = run(cmd, env)
        if not ok:
            print("✗", flush=True)
            print(relevant(out, args.slug), file=sys.stderr)
            print(f"\n→ {fix}", file=sys.stderr)
            return 1
        print("✓")
    if not (target / "fixtures" / "http.json").is_file():
        role = (json.loads((target / "talos.json").read_text()).get("block") or {}).get("role")
        if role == "keeper":
            print("note: a keeper has no recorded run (the rehearsal has no memory); declare recommended_fuel from its bounds.")
        else:
            print(f"✗ no recorded run, so its fuel is unchecked: `make record-template TEMPLATE={args.slug}`", file=sys.stderr)
            return 1
    print(f"module-templates/{args.slug} passes every gate CI runs on a template.")
    return 0


def self_test():
    failures = []

    def expect(name, condition, detail=""):
        if not condition:
            failures.append(f"{name}: {detail}")

    def refused(*a):
        try:
            rendered(*a)
        except Refused as r:
            return str(r)
        return None

    # Every role renders, named, with its role's grants and nothing more.
    for role in ROLES:
        host = "api.acme.example" if role in NETWORK_ROLES else None
        files = rendered(role, f"acme-{role}", host, None, "What it does.")
        manifest = json.loads(files["talos.json"])
        text = "\n".join(files.values())
        expect(f"{role}: named", manifest["name"] == f"acme-{role}" and "skeleton" not in text.lower(), manifest["name"])
        expect(f"{role}: role", manifest["block"]["role"] == role, str(manifest["block"]))
        expect(f"{role}: description", manifest["description"] == "What it does.")
        expect(f"{role}: no secret grant", manifest.get("requires_secrets") == [], str(manifest.get("requires_secrets")))
        if role in NETWORK_ROLES:
            expect(f"{role}: one host", manifest["allowed_hosts"] == ["api.acme.example"], str(manifest["allowed_hosts"]))
            expect(f"{role}: the host is in the source", "https://api.acme.example" in files["template.rs"] and SKELETON_HOST not in text)
        else:
            expect(f"{role}: no network", manifest["allowed_hosts"] == [] and manifest["allowed_methods"] == [], str(manifest))
        expect(f"{role}: keeps its run under its own name", "recorded_run::keep" not in files["template.rs"] or f'keep("acme-{role}"' in files["template.rs"])
    reader = json.loads(rendered("reader", "acme-reader", "api.acme.example", None, None)["talos.json"])
    sender = json.loads(rendered("sender", "acme-sender", "api.acme.example", None, None)["talos.json"])
    expect("reader is GET only", reader["allowed_methods"] == ["GET"], str(reader["allowed_methods"]))
    expect("sender is POST only and dry-runs by default", sender["allowed_methods"] == ["POST"]
           and sender["config_schema"]["properties"]["DRY_RUN"]["default"] is True, str(sender))
    # What it refuses.
    for host in ["*", "*.acme.example", "https://api.acme.example", "api.acme.example/v1", "api.acme.example:443", "localhost", "API.ACME.EXAMPLE", "", "a..b.example"]:
        expect(f"host {host!r} refused", refused("reader", "acme-reader", host, None, None) is not None)
    for slug in ["Acme", "acme_reader", "acme--reader", "-acme", "acme-", "../acme", "skeleton-reader", "a" * 65]:
        expect(f"slug {slug!r} refused", refused("decider", slug, None, None, None) is not None)
    expect("unknown role refused", refused("fetcher", "acme-x", None, None, None) is not None)
    expect("a network role needs its host", refused("sender", "acme-x", None, None, None) is not None)
    expect("an offline role takes no host", refused("decider", "acme-x", "api.acme.example", None, None) is not None)
    # It never overwrites a template.
    with tempfile.TemporaryDirectory() as scratch:
        global TEMPLATES
        saved, TEMPLATES = TEMPLATES, pathlib.Path(scratch)
        try:
            (TEMPLATES / "acme-decider").mkdir()
            try:
                new(argparse.Namespace(slug="acme-decider", role="decider", host=None, display_name=None, description=None))
                expect("no overwrite", False, "it wrote over an existing template")
            except Refused:
                pass
        finally:
            TEMPLATES = saved
    if failures:
        print("template.py self-test FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("template.py self-test passed")
    return 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    n = sub.add_parser("new", help="a new template from its role's skeleton")
    n.add_argument("slug")
    n.add_argument("--role", required=True, choices=ROLES)
    n.add_argument("--host")
    n.add_argument("--display-name")
    n.add_argument("--description")
    r = sub.add_parser("record", help="write the template's recorded run from its test")
    r.add_argument("slug")
    c = sub.add_parser("check", help="every gate CI runs on a template")
    c.add_argument("slug")
    args = parser.parse_args(argv)
    try:
        return {"new": new, "record": record, "check": check}[args.command](args)
    except Refused as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
