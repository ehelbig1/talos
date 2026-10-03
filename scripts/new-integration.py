#!/usr/bin/env python3
"""Start a new OAuth integration from the scaffold.

    scripts/new-integration.py <id> "<Display Name>"      write the crate
    scripts/new-integration.py <id> "<Display Name>" --dry-run
    scripts/new-integration.py --self-test                prove the scaffold still builds

<id> is kebab-case (`acme-crm`). It becomes the crate `talos-acme-crm`, the
provider string and table prefix `acme_crm`, the type prefix `AcmeCrm`, the
environment-variable prefix `ACME_CRM` and the routes `/api/acme-crm/*`.

What it writes: the crate (`Cargo.toml`, `src/lib.rs`, `src/handlers.rs`,
`SCAFFOLD.md`), a migration for its table, the controller re-export shim, and
one line in the workspace member list. Everything that touches a shared file
is listed in `SCAFFOLD.md` instead of being edited: those edits need a reader.

`--self-test` generates a throwaway crate, runs clippy (`-D warnings`) and its
unit tests, and removes it again. CI runs it, so a change to a shared crate
that breaks the scaffold is found there and not by the next person to use it.
"""
import argparse
import datetime
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = pathlib.Path(__file__).resolve().parent / "integration-scaffold"
ID_RE = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*")
PROBE_ID = "scaffold-probe"
# The one generated test that is MEANT to fail until a person has filled in
# the provider's endpoints.
PLACEHOLDER_TEST = "the_provider_endpoints_were_filled_in"


def names(ident, display):
    snake = ident.replace("-", "_")
    return {
        "__ID__": ident,
        "__SNAKE__": snake,
        "__PASCAL__": "".join(part.capitalize() for part in ident.split("-")),
        "__UPPER__": snake.upper(),
        "__NAME__": display,
    }


def render(template, subs):
    text = (TEMPLATES / template).read_text()
    for token, value in subs.items():
        text = text.replace(token, value)
    left = sorted(set(re.findall(r"__[A-Z]+__", text)))
    if left:
        raise SystemExit(f"{template}: unreplaced placeholders {left}")
    return text


def refuse_unusable(ident, display):
    if not ID_RE.fullmatch(ident) or len(ident) > 32:
        raise SystemExit(
            f"'{ident}' is not usable as an id: lower-case letters and digits in "
            "kebab-case, starting with a letter, at most 32 characters"
        )
    # The display name is written into Rust string literals and SQL comments.
    if not display.strip() or len(display) > 60 or re.search(r'["\\\n\r`{}]|--', display):
        raise SystemExit(
            "the display name must be 1-60 characters with no quote, backslash, "
            "brace, backtick, newline or '--'"
        )
    if (ROOT / f"talos-{ident}").exists():
        raise SystemExit(f"talos-{ident}/ already exists")
    registry = (ROOT / "talos-integrations/src/provider_config.rs").read_text()
    if re.search(rf'id:\s*"{re.escape(ident)}"', registry):
        raise SystemExit(f"'{ident}' is already a provider in talos-integrations")
    snake = ident.replace("-", "_")
    if list((ROOT / "migrations").glob(f"*_{snake}_integrations.sql")):
        raise SystemExit(f"a migration for {snake}_integrations already exists")


def planned_files(ident, display, with_wiring):
    """{path: text} for everything generation writes, and the migration name."""
    subs = names(ident, display)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    migration = f"{stamp}_{subs['__SNAKE__']}_integrations.sql"
    subs_all = dict(subs, __MIGRATION__=migration)
    crate = ROOT / f"talos-{ident}"
    files = {
        crate / "Cargo.toml": render("Cargo.toml.tmpl", subs),
        crate / "src/lib.rs": render("lib.rs.tmpl", subs),
        crate / "src/handlers.rs": render("handlers.rs.tmpl", subs),
    }
    if with_wiring:
        files[crate / "SCAFFOLD.md"] = render("SCAFFOLD.md.tmpl", subs_all)
        files[ROOT / "migrations" / migration] = render("migration.sql.tmpl", subs)
        files[ROOT / "controller/src" / subs["__SNAKE__"] / "mod.rs"] = render("shim.rs.tmpl", subs)
    return files, migration


def with_member(manifest, ident):
    """The workspace manifest with `talos-<ident>` added to `members`."""
    match = re.search(r"(?ms)^members = \[\n(.*?)^\]", manifest)
    if not match:
        raise SystemExit("could not find the workspace member list in Cargo.toml")
    line = f'    "talos-{ident}",\n'
    if line in match.group(1):
        return manifest
    return manifest[: match.end(1)] + line + manifest[match.end(1):]


def generate(ident, display, dry_run):
    refuse_unusable(ident, display)
    files, migration = planned_files(ident, display, with_wiring=True)
    for path in sorted(files):
        print(("would write " if dry_run else "wrote ") + str(path.relative_to(ROOT)))
    if dry_run:
        print("would add talos-%s to the workspace members" % ident)
        return
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    manifest = ROOT / "Cargo.toml"
    manifest.write_text(with_member(manifest.read_text(), ident))
    print(f"added talos-{ident} to the workspace members")
    print(f"\nNext: talos-{ident}/SCAFFOLD.md lists what is left (migration: {migration}).")


def self_test():
    """Generate the probe crate, hold it to clippy and its tests, remove it."""
    crate = ROOT / f"talos-{PROBE_ID}"
    if crate.exists():
        raise SystemExit(f"{crate.name}/ exists; remove it and run the self-test again")
    manifest, lock = ROOT / "Cargo.toml", ROOT / "Cargo.lock"
    saved = (manifest.read_bytes(), lock.read_bytes())
    files, _ = planned_files(PROBE_ID, "Scaffold Probe", with_wiring=False)
    # Every template renders, including the ones the probe does not build.
    planned_files(PROBE_ID, "Scaffold Probe", with_wiring=True)
    package = f"talos-{PROBE_ID}"
    try:
        for path, text in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        manifest.write_text(with_member(manifest.read_text(), PROBE_ID))
        steps = [
            ["cargo", "clippy", "-p", package, "--all-targets", "--no-deps", "--", "-D", "warnings"],
            ["cargo", "test", "-p", package, "--", "--skip", PLACEHOLDER_TEST],
        ]
        for step in steps:
            print("+", " ".join(step), flush=True)
            if subprocess.run(step, cwd=ROOT).returncode != 0:
                print("\nintegration scaffold self-test FAILED: the generated crate no longer "
                      "builds clean. Fix scripts/integration-scaffold/*.tmpl.", file=sys.stderr)
                return 1
        # The placeholder test must exist and must FAIL on an unedited
        # scaffold: it is what tells a person the endpoints are still fake.
        probe = subprocess.run(
            ["cargo", "test", "-p", package, "--", PLACEHOLDER_TEST],
            cwd=ROOT, capture_output=True, text=True,
        )
        if probe.returncode == 0 or PLACEHOLDER_TEST not in probe.stdout:
            print(f"\nintegration scaffold self-test FAILED: {PLACEHOLDER_TEST} did not "
                  "fail on an unedited scaffold.", file=sys.stderr)
            return 1
        print("integration scaffold self-test ok")
        return 0
    finally:
        shutil.rmtree(crate, ignore_errors=True)
        manifest.write_bytes(saved[0])
        lock.write_bytes(saved[1])


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("id", nargs="?")
    parser.add_argument("display_name", nargs="?")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        if args.id or args.display_name or args.dry_run:
            parser.error("--self-test takes no other argument")
        return self_test()
    if not args.id or not args.display_name:
        parser.error('usage: new-integration.py <id> "<Display Name>" [--dry-run]')
    generate(args.id, args.display_name, args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
