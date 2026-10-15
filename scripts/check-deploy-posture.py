#!/usr/bin/env python3
"""The deployment artefacts keep the posture the 2026-10-14 review asked of them.

Each rule below closed a finding of `docs/security-review/2026-10-14/`
(A-3, H-2..H-7) in a file no compiler reads. Without a check, the next edit
to the compose file, the chart or a workflow undoes it silently.

    check-deploy-posture.py [ROOT]     exit 1 and name each rule that fails
    check-deploy-posture.py --self-test

1. `docker-compose.prod.yml` trusts its own proxies (A-3): the controller
   declares `TRUSTED_PROXY_CIDRS`, and its default is the `talos-network`
   `ipam` subnet's default — otherwise the frontend nginx's address is every
   client's and the login limiter is one bucket for the whole deployment.
2. The controller's external-egress NetworkPolicy `except` list equals the
   worker's (H-2): the controller holds the database credentials, so SSRF
   space the worker may not reach (RFC 6598 included) is closed to it too.
3. Every proxied nginx `location` names a `client_max_body_size` (H-3), in
   `frontend/nginx.conf` and the chart's frontend ConfigMap, so the proxy's
   answer is a stated one and not nginx's compiled-in 1 MiB.
4. `talos.secretChecksum` hashes no `.data` (H-4): a pod annotation is
   readable by anyone who can list pods, and a hash of the Secret's values
   was a fingerprint of the credential set.
5. A workflow other than `main-publish.yml` / `release.yml` that holds
   `id-token: write` carries a `# signing-identity: <why>` comment within the
   three lines above it (H-5); and the image-admission identity regexp in
   `deploy/k3s/install.sh` and the chart's `values.yaml` names those two
   workflows, never `workflows/.+@`.
6. `frontend/.dockerignore` excludes `.env*` (H-7): the frontend build
   context is `frontend/`, so the root file's rule does not apply there.
7. Every `TALOS_*` switch the chart sets on the controller or the worker is
   set the same way on that service in `docker-compose.prod.yml` (security
   review 2026-10-15, H2-1). The list is the chart's own `controller.env` /
   `worker.env` — enumerated, not hand-kept — so a switch added to the chart
   is a failure here until the compose file states it; a boolean is compared
   by its truth value, an empty chart value (a secret placeholder) is
   skipped, and a non-security switch is exempted by name with its reason.
   The compose file runs `RUST_ENV=staging`, so a switch whose production
   default the chart relies on is stated there too
   (`TALOS_REPLAY_FAIL_CLOSED`). Before this rule the compose file, used on
   its own as its header says, ran with the write ceiling unenforced, row
   security's role switch off and no fleet-wide replay guard.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile

COMPOSE = "docker-compose.prod.yml"
NP_CONTROLLER = "deploy/helm/talos/templates/controller/networkpolicy.yaml"
NP_WORKER = "deploy/helm/talos/templates/worker/networkpolicy.yaml"
NGINX_FILES = ("frontend/nginx.conf", "deploy/helm/talos/templates/frontend/configmap.yaml")
HELPERS = "deploy/helm/talos/templates/_helpers.tpl"
WORKFLOWS = ".github/workflows"
SIGNING_WORKFLOWS = ("main-publish.yml", "release.yml")
IDENTITY_FILES = ("deploy/k3s/install.sh", "deploy/helm/talos/values.yaml")
DOCKERIGNORE = "frontend/.dockerignore"
VALUES = "deploy/helm/talos/values.yaml"
PARITY_SERVICES = ("controller", "worker")
# Chart switches that are not a security posture, each with why.
PARITY_EXEMPT = {
    "TALOS_DISABLE_POOLING": "the wasmtime pooling allocator's memory layout, chosen for pod limits",
}
# Switches the chart leaves to RUST_ENV=production's default, which the
# compose file (RUST_ENV=staging) must state, with the value it must have.
STAGING_MUST_STATE = {"TALOS_REPLAY_FAIL_CLOSED": "true"}
_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}
_ENV_LINE = re.compile(r"^(?P<indent> *)(?P<key>TALOS_[A-Z0-9_]+):\s*(?P<value>.*?)\s*(?:#.*)?$")

_TRUSTED = re.compile(r"^\s*TRUSTED_PROXY_CIDRS:\s*(\S.*?)\s*(?:#.*)?$", re.M)
_SUBNET = re.compile(r"^\s*-\s*subnet:\s*(\S.*?)\s*(?:#.*)?$", re.M)
_ENV_DEFAULT = re.compile(r"^\$\{[A-Z_]+:-([^}]*)\}$")
_EXCEPT_ITEM = re.compile(r"^\s*-\s*([0-9a-fA-F:.]+/[0-9]+)")
_LOCATION = re.compile(r"^\s*location\s+(?:=\s+|~\*?\s+)?(\S+)\s*\{")
_CHECKSUM = re.compile(r'\{\{-?\s*define\s+"talos\.secretChecksum"\s*-?\}\}(.*?)\{\{-?\s*end\s*-?\}\}\s*$', re.S | re.M)
_ID_TOKEN = re.compile(r"^\s*id-token:\s*write\b")
_REGEX_LINE = re.compile(r"certIdentityRegex:\s*\"([^\"]*)\"")


def _read(root: str, rel: str) -> str | None:
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _default(value: str) -> str:
    m = _ENV_DEFAULT.match(value.strip().strip('"').strip("'"))
    return m.group(1) if m else value.strip().strip('"').strip("'")


def compose_trusts_its_proxies(root: str) -> list[str]:
    text = _read(root, COMPOSE)
    if text is None:
        return [f"{COMPOSE}: not found"]
    trusted = _TRUSTED.findall(text)
    if not trusted:
        return [f"{COMPOSE}: the controller declares no TRUSTED_PROXY_CIDRS — every client is rate-limited as the proxy's address"]
    subnets = _SUBNET.findall(text)
    if not subnets:
        return [f"{COMPOSE}: talos-network has no fixed `ipam` subnet, so TRUSTED_PROXY_CIDRS cannot name it"]
    want = {_default(s) for s in subnets}
    out = []
    for value in trusted:
        if _default(value) not in want:
            out.append(f"{COMPOSE}: TRUSTED_PROXY_CIDRS defaults to {_default(value)!r}, the network's subnet is {sorted(want)}")
    return out


def _except_sets(text: str) -> list[frozenset[str]]:
    sets: list[frozenset[str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].strip() == "except:":
            items = []
            j = i + 1
            while j < len(lines):
                m = _EXCEPT_ITEM.match(lines[j])
                if not m:
                    break
                items.append(m.group(1))
                j += 1
            sets.append(frozenset(items))
            i = j
        else:
            i += 1
    return sets


def egress_except_parity(root: str) -> list[str]:
    out = []
    found: dict[str, list[frozenset[str]]] = {}
    for rel in (NP_CONTROLLER, NP_WORKER):
        text = _read(root, rel)
        if text is None:
            out.append(f"{rel}: not found")
            continue
        sets = _except_sets(text)
        if not sets:
            out.append(f"{rel}: no `except:` list — has the external-egress rule moved? Update this check with it")
        found[rel] = sets
    if out:
        return out
    reference = found[NP_WORKER][0]
    for rel, sets in found.items():
        for s in sets:
            if s != reference:
                missing = sorted(reference - s)
                extra = sorted(s - reference)
                out.append(f"{rel}: an external-egress `except` list differs from the worker's (missing {missing}, extra {extra})")
    return out


def nginx_body_limits(root: str) -> list[str]:
    out = []
    for rel in NGINX_FILES:
        text = _read(root, rel)
        if text is None:
            out.append(f"{rel}: not found")
            continue
        blocks: list[tuple[str, list[str]]] = []
        for line in text.splitlines():
            m = _LOCATION.match(line)
            if m:
                blocks.append((m.group(1), []))
            elif blocks:
                blocks[-1][1].append(line)
        proxied = 0
        for name, body in blocks:
            # A location's body ends at the next location; nested blocks do not occur here.
            if any(l.strip().startswith("proxy_pass") for l in body):
                proxied += 1
                if not any(l.strip().startswith("client_max_body_size") for l in body):
                    out.append(f"{rel}: `location {name}` proxies to the controller and names no client_max_body_size")
        if proxied == 0:
            out.append(f"{rel}: no proxied location found — has the proxy moved? Update this check with it")
    return out


def checksum_hashes_no_data(root: str) -> list[str]:
    text = _read(root, HELPERS)
    if text is None:
        return [f"{HELPERS}: not found"]
    m = _CHECKSUM.search(text)
    if not m:
        return [f"{HELPERS}: no `talos.secretChecksum` define — has it moved? Update this check with it"]
    if re.search(r"\.data\b", m.group(1)):
        return [f"{HELPERS}: talos.secretChecksum reads the Secret's `.data` — a pod annotation must not fingerprint secret values"]
    return []


def signing_identity_is_named(root: str) -> list[str]:
    out = []
    wf_dir = os.path.join(root, WORKFLOWS)
    try:
        names = sorted(n for n in os.listdir(wf_dir) if n.endswith((".yml", ".yaml")))
    except OSError:
        return [f"{WORKFLOWS}: not found"]
    for name in names:
        if name in SIGNING_WORKFLOWS:
            continue
        lines = (_read(root, f"{WORKFLOWS}/{name}") or "").splitlines()
        for i, line in enumerate(lines):
            if _ID_TOKEN.match(line):
                above = lines[max(0, i - 3):i + 1]
                if not any("# signing-identity:" in l for l in above):
                    out.append(
                        f"{WORKFLOWS}/{name}:{i + 1}: `id-token: write` with no `# signing-identity: <why>` "
                        "marker — a workflow that can mint a Sigstore identity must say why it is not an image signer"
                    )
    for rel in IDENTITY_FILES:
        text = _read(root, rel)
        if text is None:
            out.append(f"{rel}: not found")
            continue
        regexes = _REGEX_LINE.findall(text)
        if not regexes:
            out.append(f"{rel}: no certIdentityRegex — has the image policy moved? Update this check with it")
        for rx in regexes:
            if "workflows/.+" in rx or "workflows/.*" in rx:
                out.append(f"{rel}: certIdentityRegex admits ANY workflow in the repository ({rx})")
            elif "main-publish" not in rx or "release" not in rx:
                out.append(f"{rel}: certIdentityRegex does not name main-publish.yml and release.yml ({rx})")
    return out


def frontend_context_excludes_env(root: str) -> list[str]:
    text = _read(root, DOCKERIGNORE)
    if text is None:
        return [f"{DOCKERIGNORE}: not found"]
    if ".env*" not in (l.strip() for l in text.splitlines()):
        return [f"{DOCKERIGNORE}: does not exclude `.env*` — a frontend/.env.production enters the build context"]
    return []




def _service_env(text: str, path: tuple[str, ...]) -> dict[str, str] | None:
    """The `TALOS_*` entries of the mapping at `path` (each step one level of
    two-space indentation deeper), or `None` when the path is absent."""
    lines = text.splitlines()
    start, depth = 0, 0
    for step in path:
        pat = re.compile(rf"^{' ' * (2 * depth)}{re.escape(step)}:\s*(?:#.*)?$")
        for i in range(start, len(lines)):
            line = lines[i]
            if pat.match(line):
                start, depth = i + 1, depth + 1
                break
            stripped = line.strip()
            if depth and stripped and not stripped.startswith("#"):
                if len(line) - len(line.lstrip(" ")) < 2 * depth:
                    return None
        else:
            return None
    out: dict[str, str] = {}
    for line in lines[start:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent < 2 * depth:
            break
        m = _ENV_LINE.match(line)
        if m and len(m.group("indent")) == 2 * depth:
            out[m.group("key")] = _default(m.group("value"))
    return out


def _truth(value: str) -> bool | None:
    v = value.strip().lower()
    return True if v in _TRUTHY else False if v in _FALSY else None


def security_switch_parity(root: str) -> list[str]:
    chart = _read(root, VALUES)
    compose = _read(root, COMPOSE)
    if chart is None:
        return [f"{VALUES}: not found"]
    if compose is None:
        return [f"{COMPOSE}: not found"]
    out: list[str] = []
    for svc in PARITY_SERVICES:
        chart_env = _service_env(chart, (svc, "env"))
        compose_env = _service_env(compose, ("services", svc, "environment"))
        if chart_env is None:
            out.append(f"{VALUES}: no `{svc}.env` mapping")
            continue
        if compose_env is None:
            out.append(f"{COMPOSE}: no `services.{svc}.environment` mapping")
            continue
        wanted = {k: v for k, v in chart_env.items() if v != "" and k not in PARITY_EXEMPT}
        wanted.update(STAGING_MUST_STATE)
        for key, value in sorted(wanted.items()):
            if key not in compose_env:
                out.append(
                    f"{COMPOSE}: the {svc} does not set {key}, which the chart sets to "
                    f"{value!r} — the compose stack runs without that posture"
                )
                continue
            want, got = _truth(value), _truth(compose_env[key])
            if want is not None and want != got:
                out.append(
                    f"{COMPOSE}: the {svc}'s {key} defaults to {compose_env[key]!r}; the chart "
                    f"sets {value!r}"
                )
    return out


RULES = (
    compose_trusts_its_proxies,
    egress_except_parity,
    nginx_body_limits,
    checksum_hashes_no_data,
    signing_identity_is_named,
    frontend_context_excludes_env,
    security_switch_parity,
)


def problems(root: str) -> list[str]:
    out: list[str] = []
    for rule in RULES:
        out.extend(rule(root))
    return out


def self_test() -> int:
    # The chart's values file carries rule 5's identity line AND rule 7's env
    # blocks: one fixture, built from both halves.
    chart_env = (
        "controller:\n  replicaCount: 2\n  env:\n"
        "    TALOS_WRITE_CEILING_ENFORCED: \"1\"   # both sides\n"
        "    TALOS_AUDIT_SIGNING_KEY: \"\"\n"
        "    # TALOS_ALLOW_LEGACY_FLEET_HMAC: \"rpc\"\n"
        "    TALOS_DISABLE_POOLING: \"true\"\n"
        "  ports: []\n"
        "worker:\n  env:\n"
        "    TALOS_WRITE_CEILING_ENFORCED: \"1\"\n"
    )
    good: dict[str, str] = {
        COMPOSE: (
            "services:\n  controller:\n    environment:\n"
            "      TRUSTED_PROXY_CIDRS: ${TALOS_COMPOSE_SUBNET:-172.29.0.0/24}\n"
            "      TALOS_WRITE_CEILING_ENFORCED: \"1\"\n"
            "      TALOS_REPLAY_FAIL_CLOSED: ${TALOS_REPLAY_FAIL_CLOSED:-true}\n"
            "  worker:\n    environment:\n"
            "      TALOS_WRITE_CEILING_ENFORCED: \"true\"\n"
            "      TALOS_REPLAY_FAIL_CLOSED: \"1\"\n"
            "networks:\n  talos-network:\n    ipam:\n      config:\n"
            "        - subnet: ${TALOS_COMPOSE_SUBNET:-172.29.0.0/24}\n"
        ),
        NP_CONTROLLER: "            except:\n              - 169.254.0.0/16   # metadata\n              - 100.64.0.0/10\n      ports:\n",
        NP_WORKER: (
            "            except:\n              - 169.254.0.0/16\n              - 100.64.0.0/10    # CGNAT\n"
            "      ports:\n            except:\n              - 100.64.0.0/10\n              - 169.254.0.0/16\n"
        ),
        NGINX_FILES[0]: (
            "server {\n    location /graphql {\n        client_max_body_size 5m;\n        proxy_pass http://c;\n    }\n"
            "    location / {\n        try_files $uri /index.html;\n    }\n}\n"
        ),
        NGINX_FILES[1]: "        location = /auth/csrf {\n            client_max_body_size 2m;\n            proxy_pass http://c;\n        }\n",
        HELPERS: (
            '{{- define "talos.secretChecksum" -}}\n{{- $secret := lookup "v1" "Secret" .ns .name -}}\n'
            '{{ printf "%s/%s" $secret.metadata.uid $secret.metadata.resourceVersion | sha256sum }}\n{{- end -}}\n'
            '{{/* x */}}\n{{- define "talos.other" -}}\n{{ $s.data }}\n{{- end -}}\n'
        ),
        f"{WORKFLOWS}/main-publish.yml": "permissions:\n  id-token: write\n",
        f"{WORKFLOWS}/template-publish.yml": "permissions:\n  # signing-identity: templates only\n  id-token: write   # cosign\n",
        f"{WORKFLOWS}/quality.yml": "permissions:\n  contents: read\n",
        IDENTITY_FILES[0]: '    certIdentityRegex: "^https://x/\\\\.github/workflows/(main-publish\\\\.yml|release\\\\.yml)@refs/heads/main$"\n',
        IDENTITY_FILES[1]: chart_env + '    certIdentityRegex: "^https://x/\\.github/workflows/(main-publish\\.yml|release\\.yml)@refs/(heads/main|tags/v.+)$"\n',
        DOCKERIGNORE: "node_modules/\n.env*\n",
    }

    def tree(**override: str | None) -> str:
        files: dict[str, str | None] = dict(good)
        files.update(override)
        root = tempfile.mkdtemp(prefix="deploy-posture-")
        for rel, body in files.items():
            if body is None:
                continue
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        return root

    def expect(needle: str | None, **override: str | None) -> None:
        got = problems(tree(**override))
        if needle is None:
            assert got == [], got
        else:
            assert len(got) == 1 and needle in got[0], (needle, got)

    expect(None)
    # 1. compose
    expect("declares no TRUSTED_PROXY_CIDRS", **{COMPOSE: good[COMPOSE].replace("TRUSTED_PROXY_CIDRS", "OTHER_VAR")})
    expect("no fixed `ipam` subnet", **{COMPOSE: good[COMPOSE].split("networks:")[0]})
    expect("defaults to '10.0.0.0/8'", **{COMPOSE: good[COMPOSE].replace("CIDRS: ${TALOS_COMPOSE_SUBNET:-172.29.0.0/24}", "CIDRS: ${X:-10.0.0.0/8}")})
    # 2. NetworkPolicy parity: the controller without RFC 6598.
    expect("missing ['100.64.0.0/10']", **{NP_CONTROLLER: "            except:\n              - 169.254.0.0/16\n      ports:\n"})
    expect("no `except:` list", **{NP_CONTROLLER: "egress: []\n"})
    # 3. nginx
    expect("`location /graphql` proxies", **{NGINX_FILES[0]: good[NGINX_FILES[0]].replace("        client_max_body_size 5m;\n", "")})
    expect("no proxied location", **{NGINX_FILES[1]: "location / {\n}\n"})
    # 4. checksum
    expect("reads the Secret's `.data`", **{HELPERS: good[HELPERS].replace("$secret.metadata.uid $secret.metadata.resourceVersion", "$secret.data")})
    expect("no `talos.secretChecksum` define", **{HELPERS: "{{- define \"x\" -}}{{- end -}}\n"})
    # 5. signing identity
    expect("quality.yml:2: `id-token: write` with no", **{f"{WORKFLOWS}/quality.yml": "permissions:\n  id-token: write\n"})
    expect("template-publish.yml:2", **{f"{WORKFLOWS}/template-publish.yml": "permissions:\n  id-token: write\n"})
    expect(None, **{f"{WORKFLOWS}/release.yml": "permissions:\n  id-token: write\n"})
    expect("admits ANY workflow", **{IDENTITY_FILES[0]: '    certIdentityRegex: "^https://x/\\\\.github/workflows/.+@refs/heads/main$"\n'})
    expect("does not name", **{IDENTITY_FILES[1]: chart_env + '    certIdentityRegex: "^https://x/\\.github/workflows/main-publish\\.yml@refs/heads/main$"\n'})
    # 7. switch parity: a chart switch the compose service lacks, or states
    #    the other way; the staging-stated switch; a new chart switch.
    expect("the worker does not set TALOS_WRITE_CEILING_ENFORCED", **{COMPOSE: good[COMPOSE].replace('      TALOS_WRITE_CEILING_ENFORCED: "true"\n', "")})
    expect("controller's TALOS_WRITE_CEILING_ENFORCED defaults to '0'", **{COMPOSE: good[COMPOSE].replace('ENFORCED: "1"', 'ENFORCED: "0"')})
    expect("the controller does not set TALOS_REPLAY_FAIL_CLOSED", **{COMPOSE: good[COMPOSE].replace("      TALOS_REPLAY_FAIL_CLOSED: ${TALOS_REPLAY_FAIL_CLOSED:-true}\n", "")})
    expect("the worker does not set TALOS_DISTRIBUTED_REPLAY", **{VALUES: good[VALUES] + '    TALOS_DISTRIBUTED_REPLAY: "true"\n'})
    expect("no `worker.env` mapping", **{VALUES: good[VALUES].replace('worker:\n  env:\n    TALOS_WRITE_CEILING_ENFORCED: "1"\n', "")})
    # 6. dockerignore
    expect("does not exclude `.env*`", **{DOCKERIGNORE: ".env\n.env.local\n"})
    expect("not found", **{DOCKERIGNORE: None})
    print("check-deploy-posture self-test: ok")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = problems(root)
    if found:
        print("✗ a deployment artefact lost a posture the 2026-10-14 review fixed:", file=sys.stderr)
        for line in found:
            print(f"  {line}", file=sys.stderr)
        return 1
    print("✓ deployment posture: compose proxy trust, egress parity, nginx body limits, secret checksum, signing identity, .env exclusion, chart/compose switch parity")
    return 0


if __name__ == "__main__":
    sys.exit(main())
