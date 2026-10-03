#!/usr/bin/env python3
"""Promote a module written in the authoring lane to a catalog template.

    scripts/promote-module.py <module-dir> --description "<what it does>" [options]
    scripts/promote-module.py <module-dir> ... --dry-run     say what would be written
    scripts/promote-module.py --self-test                    prove the refusals still hold

<module-dir> is a module as it is kept while it is being written and proven
on a platform:

    module.json        name, capability_world, allowed_hosts, allowed_methods,
                       allowed_secrets, dependencies (and module_id / max_fuel,
                       which belong to that platform and are not carried)
    module.rs          the source
    tests.rs           its tests (optional; `use super::*;` at the top)
    fixtures/          the recorded run it was rehearsed against:
                       http.json, and optionally config.json / input.json

It writes `module-templates/<slug>/`:

    talos.json         the catalog manifest
    template.rs        the source, with the tests as a `#[cfg(test)]` module
    fixtures/          the recorded run, copied

What it will NOT carry, because this repository is public and a catalog
template is shared by every user of every deployment:

  * a secret grant that names one user's secret. `allowed_secrets` on a
    platform holds paths such as `oauth/<provider>/<user-id>/<connection-id>/…`;
    a template's grant is a pattern the installer narrows. Pass the pattern
    with `--secret` (repeatable). A module.json grant that holds an
    identifier is refused, never rewritten.
  * an identifier in anything it copies. The source, the tests and every
    fixture are scanned for UUIDs and for e-mail addresses outside the
    reserved example domains, and the promotion is refused with the list. A
    capture is a real response; scrub it where it lives, then promote.

This is a filter over shapes, not a guarantee. Read what it wrote before
committing it.

After it runs:

    make check-catalog-fuel TEMPLATE=<slug>

builds the template the way the platform does, runs it against the recorded
run, and prints the fuel it used. Until `recommended_fuel` is declared in
`talos.json` that command fails with the figure to size it from. See
docs/module-promotion.md.
"""
import argparse
import json
import pathlib
import re
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "module-templates"
SLUG_RE = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*")
WORLDS = {
    "minimal-node", "http-node", "secrets-node", "network-node", "agent-node",
    "messaging-node", "database-node", "automation-node", "governance-node",
}
FIXTURE_FILES = ("http.json", "config.json", "input.json", "grants.json")

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
NIL_UUID = "00000000-0000-0000-0000-000000000000"
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")
# RFC 2606 / RFC 6761 reserved names: an address there belongs to nobody.
RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost")
RESERVED_DOMAINS = ("example.com", "example.org", "example.net")
# Addresses that are part of a provider's API, not a person.
SERVICE_DOMAINS = ("resource.calendar.google.com", "group.calendar.google.com")


class Refused(Exception):
    """The promotion cannot go ahead. The message says what to change."""


def reserved(domain):
    domain = domain.lower()
    return (
        domain in RESERVED_DOMAINS
        or domain in SERVICE_DOMAINS
        or any(domain.endswith(suffix) for suffix in RESERVED_SUFFIXES)
        or any(domain.endswith("." + d) for d in RESERVED_DOMAINS)
    )


def identifiers(text):
    """UUIDs and non-reserved e-mail addresses in `text`, in order, deduplicated."""
    found = []
    for match in UUID_RE.finditer(text):
        if match.group(0).lower() != NIL_UUID:
            found.append(match.group(0))
    for match in EMAIL_RE.finditer(text):
        if not reserved(match.group(1)):
            found.append(match.group(0))
    return list(dict.fromkeys(found))


def read_json(path):
    try:
        return json.loads(path.read_text())
    except ValueError as error:
        raise Refused(f"{path}: not valid JSON ({error})") from error


def string_list(record, key, where):
    value = record.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise Refused(f"{where}: `{key}` must be a list of strings")
    return value


MACRO_MARKERS = (
    "wit_bindgen::generate!", "#[talos_node", "talos_sdk_macros::talos_node",
    "#[talos_module", "talos_sdk_macros::talos_module",
)
RUN_FN_RE = re.compile(r"^[ \t]*(pub[ \t]+)?fn[ \t]+run[ \t]*\(", re.M)


def with_module_macro(source, world):
    """Authored source carries no module macro: the platform adds it above
    `fn run(` when it compiles one (`wrap_rust_code_with_talos_module`, whose
    markers and pattern these are). A catalog template is compiled as
    written, so it must carry the macro itself."""
    if any(marker in source for marker in MACRO_MARKERS):
        return source
    match = RUN_FN_RE.search(source)
    if not match:
        raise Refused("module.rs has no `fn run(`: a module's entry point is `pub fn run(input: String)`")
    return (
        source[: match.start()]
        + f'#[talos_sdk_macros::talos_module(world = "{world}")]\n'
        + source[match.start():]
    )


def template_source(module_rs, tests_rs, world):
    """The module source as a template carries it: the module macro on its
    entry point, and its tests as an inline `#[cfg(test)]` module — the shape
    `talos-catalog-tests` discovers."""
    module_rs = with_module_macro(module_rs, world)
    source = module_rs.rstrip("\n") + "\n"
    if tests_rs is None:
        return source
    if "#[cfg(test)]" in module_rs:
        raise Refused(
            "the module has both a tests.rs and a #[cfg(test)] module in module.rs; "
            "keep the tests in one place"
        )
    body = "\n".join(("    " + line) if line.strip() else "" for line in tests_rs.rstrip("\n").split("\n"))
    return f"{source}\n#[cfg(test)]\nmod tests {{\n{body}\n}}\n"


def plan(module_dir, args):
    """Everything the promotion would write, as `{relative path: text}`, or
    raise `Refused`. Reads only; writes nothing."""
    module_dir = pathlib.Path(module_dir)
    record_path = module_dir / "module.json"
    source_path = module_dir / "module.rs"
    for required in (record_path, source_path):
        if not required.exists():
            raise Refused(f"{required} not found")
    record = read_json(record_path)
    if not isinstance(record, dict):
        raise Refused(f"{record_path}: must be a JSON object")

    slug = args.slug or record.get("name") or module_dir.name
    if not isinstance(slug, str) or not SLUG_RE.fullmatch(slug) or len(slug) > 48:
        raise Refused(f"slug {slug!r} must be kebab-case (a-z, 0-9, '-'), at most 48 characters; pass --slug")

    world = record.get("capability_world")
    if world not in WORLDS:
        raise Refused(
            f"{record_path}: capability_world {world!r} is not one of {sorted(WORLDS)}. "
            "A template states its world; nothing is assumed."
        )
    description = (args.description or record.get("description") or "").strip()
    if not description:
        raise Refused("a catalog template needs a description: pass --description")

    # Secret grants: the template's own patterns, never one platform's paths.
    # `--secret` REPLACES what module.json holds; without it, module.json's
    # grant is carried only if it names nobody.
    stored = string_list(record, "allowed_secrets", record_path)
    if args.secret:
        for pattern in args.secret:
            if identifiers(pattern):
                raise Refused(f"--secret {pattern!r} holds an identifier; a template's grant must not")
        secrets = list(dict.fromkeys(args.secret))
    else:
        personal = [path for path in stored if identifiers(path)]
        if personal:
            raise Refused(
                "module.json grants secrets that name one user's connection:\n  "
                + "\n  ".join(personal)
                + "\nA template's grant is a pattern the installer narrows. Pass it with --secret "
                "(for example --secret 'oauth/google_calendar/*'); the paths above are not carried."
            )
        secrets = list(dict.fromkeys(stored))

    source = source_path.read_text()
    tests_path = module_dir / "tests.rs"
    tests = tests_path.read_text() if tests_path.exists() else None
    files = {"template.rs": template_source(source, tests, world)}

    fixtures_dir = module_dir / "fixtures"
    for name in FIXTURE_FILES:
        path = fixtures_dir / name
        if path.exists():
            read_json(path)
            files[f"fixtures/{name}"] = path.read_text()
    readme = fixtures_dir / "README.md"
    if readme.exists():
        files["fixtures/README.md"] = readme.read_text()

    manifest = {
        "name": slug,
        "version": args.version,
        "display_name": args.display_name or slug.replace("-", " ").title(),
        "description": description,
        "category": args.category,
        "capability_world": world,
        "allowed_hosts": string_list(record, "allowed_hosts", record_path),
        "allowed_methods": string_list(record, "allowed_methods", record_path),
        "allowed_secrets": secrets,
        "requires_approval_for": string_list(record, "requires_approval_for", record_path),
        "config_schema": record.get("config_schema") or {"type": "object", "properties": {}},
    }
    dependencies = record.get("dependencies")
    if dependencies:
        if not isinstance(dependencies, dict):
            raise Refused(f"{record_path}: `dependencies` must be an object of crate to version")
        manifest["dependencies"] = dependencies
    if isinstance(record.get("recommended_fuel"), dict):
        manifest["recommended_fuel"] = record["recommended_fuel"]
    files["talos.json"] = json.dumps(manifest, indent=2) + "\n"

    leaks = []
    for relative, text in sorted(files.items()):
        for found in identifiers(text):
            leaks.append(f"{relative}: {found}")
    if leaks:
        raise Refused(
            "what would be copied holds identifiers. This repository is public; replace them "
            "with made-up values where the module is kept, then promote again:\n  "
            + "\n  ".join(leaks[:40])
            + ("" if len(leaks) <= 40 else f"\n  … and {len(leaks) - 40} more")
        )

    notes = []
    if "fixtures/http.json" not in files:
        notes.append(
            "no fixtures/http.json: the template has no recorded run, so its fuel limit will "
            "not be checked. Record one before publishing a module that makes requests."
        )
    if "recommended_fuel" not in manifest:
        notes.append(
            f"talos.json declares no recommended_fuel. Run `make check-catalog-fuel TEMPLATE={slug}`: "
            "it fails with the fuel the recorded run used, which is what to size it from."
        )
    if not manifest["config_schema"].get("properties"):
        notes.append("config_schema is empty: describe the config keys the module reads in talos.json.")
    if tests is None and "#[cfg(test)]" not in source:
        notes.append("the module has no tests; a catalog template's tests run in CI (docs/module-testing.md).")
    return slug, files, notes


def write(templates_dir, slug, files, force):
    target = pathlib.Path(templates_dir) / slug
    if target.exists() and not force:
        raise Refused(
            f"{target} already exists. A promotion does not overwrite a template; "
            "pass --force to replace the files it writes (others are left alone)."
        )
    for relative, text in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return target


def run(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("module_dir", nargs="?")
    parser.add_argument("--slug", help="template directory name (default: module.json `name`)")
    parser.add_argument("--display-name")
    parser.add_argument("--description")
    parser.add_argument("--category", default="Utilities")
    parser.add_argument("--version", default="v1.0.0")
    parser.add_argument("--secret", action="append", help="a secret-grant pattern for the template (repeatable)")
    parser.add_argument("--templates-dir", default=str(TEMPLATES), help=argparse.SUPPRESS)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.module_dir:
        parser.error("module_dir is required")
    try:
        slug, files, notes = plan(args.module_dir, args)
        if args.dry_run:
            print(f"would write module-templates/{slug}/:")
            for relative, text in sorted(files.items()):
                print(f"  {relative}  ({len(text.encode())} bytes)")
        else:
            target = write(args.templates_dir, slug, files, args.force)
            print(f"wrote {target}/ ({', '.join(sorted(files))})")
    except Refused as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return 1
    for note in notes:
        print(f"note: {note}")
    if not args.dry_run:
        print(f"next: read what was written, then `make check-catalog-fuel TEMPLATE={slug}`")
    return 0


# ── self-test ────────────────────────────────────────────────────────────────

PROBE_SOURCE = """\
use serde::Deserialize;

#[derive(Deserialize)]
struct Cfg {
    #[serde(rename = "URL")]
    url: String,
}

pub fn label(cfg: &str) -> Result<String, String> {
    let cfg: Cfg = serde_json::from_str(cfg).map_err(|e| e.to_string())?;
    Ok(cfg.url)
}

pub fn run(input: String) -> Result<String, String> {
    label(&input)
}
"""
PROBE_TESTS = """\
use super::*;

#[test]
fn reads_the_url() {
    assert_eq!(label(r#"{"URL":"https://api.example.test/x"}"#).unwrap(), "https://api.example.test/x");
}
"""
PROBE_USER = "5f0c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e5f"


def probe(directory, *, secrets=(), http_body=None, source=PROBE_SOURCE):
    directory.mkdir(parents=True)
    (directory / "module.json").write_text(json.dumps({
        "name": "promotion-probe",
        "capability_world": "http-node",
        "allowed_hosts": ["api.example.test"],
        "allowed_methods": ["GET"],
        "allowed_secrets": list(secrets),
        "dependencies": {"chrono": "0.4"},
        "max_fuel": 12345678,
        "module_id": PROBE_USER,
    }))
    (directory / "module.rs").write_text(source)
    (directory / "tests.rs").write_text(PROBE_TESTS)
    (directory / "fixtures").mkdir()
    (directory / "fixtures" / "http.json").write_text(json.dumps([
        {"url_contains": "api.example.test", "status": 200,
         "body": http_body if http_body is not None else {"items": [{"owner": "pat@corp.example"}]}}
    ]))
    (directory / "fixtures" / "config.json").write_text(json.dumps({"URL": "https://api.example.test/x"}))
    return directory


def self_test():
    failures = []

    def check(name, condition, detail=""):
        if not condition:
            failures.append(f"{name}: {detail}")

    def attempt(module_dir, templates, *extra):
        argv = [str(module_dir), "--templates-dir", str(templates), *extra]
        parser_args = argparse.Namespace(
            slug=None, display_name=None, description=None, category="Utilities",
            version="v1.0.0", secret=None, force=False,
        )
        index = 0
        while index < len(extra):
            if extra[index] == "--description":
                parser_args.description = extra[index + 1]
                index += 2
            elif extra[index] == "--secret":
                parser_args.secret = (parser_args.secret or []) + [extra[index + 1]]
                index += 2
            elif extra[index] == "--force":
                parser_args.force = True
                index += 1
            else:
                raise AssertionError(argv)
        try:
            slug, files, notes = plan(module_dir, parser_args)
            write(templates, slug, files, parser_args.force)
            return None, files, notes
        except Refused as refusal:
            return str(refusal), None, None

    with tempfile.TemporaryDirectory() as scratch:
        scratch = pathlib.Path(scratch)
        templates = scratch / "templates"

        # 1. A clean module is promoted, and what belongs to one platform is dropped.
        clean = probe(scratch / "clean", secrets=["api/example/key"])
        refusal, files, notes = attempt(clean, templates, "--description", "A probe.")
        check("clean module", refusal is None, refusal or "")
        if files:
            manifest = json.loads(files["talos.json"])
            check("module_id not carried", "module_id" not in manifest, str(manifest))
            check("max_fuel not carried", "max_fuel" not in manifest, str(manifest))
            check("grants carried", manifest["allowed_hosts"] == ["api.example.test"]
                  and manifest["allowed_methods"] == ["GET"]
                  and manifest["allowed_secrets"] == ["api/example/key"], str(manifest))
            check("dependencies carried", manifest.get("dependencies") == {"chrono": "0.4"}, str(manifest))
            check("module macro added above run",
                  '#[talos_sdk_macros::talos_module(world = "http-node")]\npub fn run(' in files["template.rs"],
                  files["template.rs"])
            check("macro added once", files["template.rs"].count("talos_module(") == 1)
            check("tests inlined", "#[cfg(test)]\nmod tests {\n    use super::*;" in files["template.rs"],
                  files["template.rs"][-200:])
            check("fixtures copied", {"fixtures/http.json", "fixtures/config.json"} <= set(files), str(sorted(files)))
            check("no-fuel note", any("recommended_fuel" in n for n in notes), str(notes))
            check("written", (templates / "promotion-probe" / "talos.json").exists())

        # 2. It does not overwrite a template.
        refusal, _, _ = attempt(clean, templates, "--description", "A probe.")
        check("no overwrite", refusal is not None and "already exists" in refusal, str(refusal))

        # 3. A grant naming one user's connection is refused, not rewritten…
        personal = probe(scratch / "personal",
                         secrets=[f"oauth/example/{PROBE_USER}/{PROBE_USER}/access_token"])
        refusal, _, _ = attempt(personal, scratch / "t3", "--description", "A probe.")
        check("personal grant refused", refusal is not None and "--secret" in refusal, str(refusal))
        check("nothing written on refusal", not (scratch / "t3").exists())
        # …and an explicit pattern replaces it.
        refusal, files, _ = attempt(personal, scratch / "t3", "--description", "A probe.",
                                    "--secret", "oauth/example/*")
        check("pattern accepted", refusal is None, refusal or "")
        if files:
            check("pattern stored", json.loads(files["talos.json"])["allowed_secrets"] == ["oauth/example/*"])
        refusal, _, _ = attempt(personal, scratch / "t3b", "--description", "A probe.",
                                "--secret", f"oauth/example/{PROBE_USER}/*")
        check("identifier in --secret refused", refusal is not None and "identifier" in refusal, str(refusal))

        # 4. An identifier in a fixture or in the source is refused, with its location.
        leaky = probe(scratch / "leaky", http_body={"account": PROBE_USER, "owner": "pat@corp.example"})
        refusal, _, _ = attempt(leaky, scratch / "t4", "--description", "A probe.")
        check("uuid in fixture refused",
              refusal is not None and f"fixtures/http.json: {PROBE_USER}" in refusal, str(refusal))
        address = "someone" + "@" + "mail" + ".corp-domain.io"
        mailed = probe(scratch / "mailed", http_body={"owner": address})
        refusal, _, _ = attempt(mailed, scratch / "t5", "--description", "A probe.")
        check("address in fixture refused", refusal is not None and address in refusal, str(refusal))
        sourced = probe(scratch / "sourced", source=PROBE_SOURCE + f"\n// account {PROBE_USER}\n")
        refusal, _, _ = attempt(sourced, scratch / "t6", "--description", "A probe.")
        check("uuid in source refused",
              refusal is not None and f"template.rs: {PROBE_USER}" in refusal, str(refusal))
        check("nothing written on a leak", not any((scratch / t).exists() for t in ("t4", "t5", "t6")))

        # 5. A description and a stated world are required.
        refusal, _, _ = attempt(probe(scratch / "bare"), scratch / "t7")
        check("description required", refusal is not None and "--description" in refusal, str(refusal))
        worldless = probe(scratch / "worldless")
        record = json.loads((worldless / "module.json").read_text())
        del record["capability_world"]
        (worldless / "module.json").write_text(json.dumps(record))
        refusal, _, _ = attempt(worldless, scratch / "t8", "--description", "A probe.")
        check("world required", refusal is not None and "capability_world" in refusal, str(refusal))

        # 6. Source that already carries the macro is left as written; source
        #    with no entry point is refused.
        annotated = PROBE_SOURCE.replace("pub fn run(", '#[talos_module(world = "http-node")]\npub fn run(')
        check("existing macro kept", with_module_macro(annotated, "http-node") == annotated)
        headless = probe(scratch / "headless", source=PROBE_SOURCE.split("pub fn run(")[0])
        refusal, _, _ = attempt(headless, scratch / "t9", "--description", "A probe.")
        check("no entry point refused", refusal is not None and "fn run(" in refusal, str(refusal))

        # 7. Reserved example addresses are not identifiers; a real-looking one is.
        check("example addresses pass", identifiers("a@corp.example b@example.com c@x.test") == [])
        check("nil uuid passes", identifiers(NIL_UUID) == [])

    if failures:
        print("promote-module self-test FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("promote-module self-test passed")
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
