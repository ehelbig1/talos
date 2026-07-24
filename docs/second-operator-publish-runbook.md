# Second-Operator Publish & Deploy Runbook

Talos's canonical release path is the **CI OIDC publish** — the
`main-publish.yml` workflow, run manually via `workflow_dispatch` (there is
still no auto-triggered image build; that's a deliberate project decision).
The workflow builds all three images on GitHub-hosted runners, pushes to
GHCR with the built-in `GITHUB_TOKEN`, and cosign-signs each digest with the
**workflow's OIDC identity** (Fulcio keyless). Because the signature binds to
the workflow URI — not to any human's GitHub account — a second operator
needs **no laptop state, no GHCR PAT, no personal identity in the cluster's
trust chain**. The local script (`scripts/publish-images.sh`) remains the
documented fallback.

## Recommended path: CI publish (any collaborator)

What you need: **write access to the repo** (enough to run
`workflow_dispatch`). That's it.

```bash
# 1. Confirm the commit you want to ship has a green quality.yml run
#    (quality.yml runs on every push to main, so merged commits have one):
gh run list --workflow quality.yml --commit "$(git rev-parse origin/main)"

# 2. Dispatch the publish (from main):
gh workflow run main-publish.yml --ref main

# 3. Watch it, then open the run's summary page:
gh run watch
```

The workflow itself re-checks the quality gate (`ci-gate` job): it refuses to
build unless a **green `quality.yml` run exists for the exact SHA** being
published. Deliberate bypass (don't, for production): re-dispatch with the
`skip_ci_check` input set to `true` — the CI mirror of the local script's
`--skip-ci-check`.

The run summary ends with the three `TALOS_*_DIGEST=…` lines — copy them into
`/etc/talos/install.env` on the cluster host (same contract as the local
script's terminal output).

### Verifying a CI-published image

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/<owner>/talos/\.github/workflows/main-publish\.yml@' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/<owner>/talos-controller@<digest>
```

The trailing `@` after the workflow filename is **load-bearing** — without it
a fork workflow named `main-publish.yml-evil.yml` would also match. Append
`refs/heads/main$` to additionally pin the ref. This same workflow-URI form is
what the cluster's Sigstore admission policy should pin
(`security.sigstore.certIdentityRegex` in the chart / the regexp `install.sh`
generates) — it never changes when the humans do.

## Fallback path: local publish (`scripts/publish-images.sh`)

Use only when GitHub Actions is unavailable. A second operator needs:

1. **GHCR push access** to `ghcr.io/<owner>/talos-{controller,worker,frontend}`.
   - Either `docker login ghcr.io` already done interactively, or a PAT with
     `write:packages` exported as `GHCR_TOKEN` (the script will `docker login`
     for you).
   - `TALOS_GHCR_OWNER` is parsed from `git remote get-url origin`; override it
     explicitly if your remote differs.
2. **`gh` CLI authenticated** (`gh auth status`). The publish gate calls
   `gh run list --commit HEAD` to require a green `quality.yml` run before
   pushing. Without it you'd have to `--skip-ci-check` (don't, for production).
3. **A clean tree on a pushed commit.** Dirty publishes are refused;
   `--allow-dirty` tags `-dirty` and must never reach production.
4. **`cosign`** (bundled/pinned in the worker Dockerfile version, or install
   from sigstore.dev). Signing is **on by default**.

```bash
# From a clean checkout of the exact commit you want to ship:
gh run list --workflow quality.yml --commit "$(git rev-parse HEAD)"   # confirm it's green
bash scripts/publish-images.sh --update-env /etc/talos/install.env
```

This builds (linux/amd64 by default — mandatory when publishing from Apple
Silicon to an x86_64 cluster), pushes `:main-<sha>` + `:main-latest`,
cosign-signs all three images in **one** OAuth browser flow, and patches the
`TALOS_*_DIGEST=` lines into your `install.env`.

If you truly need to skip signing (dev / a cluster with Sigstore enforcement
off): `--no-sign`.

### The signing-identity gotcha (why the CI path is preferred)

Local `cosign sign --yes` binds the signature to **your** GitHub OAuth
identity via Fulcio — **not** a workflow URI — and the OIDC issuer becomes
`https://github.com/login/oauth` instead of the Actions issuer. If the target
cluster enforces Sigstore, its identity regexp must match **your** email
pattern, or the cluster will reject an image you signed even though the
signature is valid.

So a second operator publishing locally must either:

- **Widen the identity regexp** in the cluster's config to match their email
  as well as the original operator's — e.g.
  `'^(alice|bob)@example\.com$'`
  (with issuer `https://github.com/login/oauth`), then re-run `install.sh` so
  the policy updates; **or**
- Publish from a shared service identity both operators can authenticate as;
  **or — the actual fix —**
- **Use the CI path above**, whose workflow-URI identity requires no
  per-operator changes at all.

Verify a locally-published image before rolling it out:

```bash
cosign verify \
  --certificate-identity-regexp '<your-email-pattern>' \
  --certificate-oidc-issuer 'https://github.com/login/oauth' \
  ghcr.io/<owner>/talos-controller@<digest>
```

## Deploy

```bash
# On the cluster host, with install.env carrying the new TALOS_*_DIGEST lines:
sudo -E bash deploy/k3s/install.sh
```

`install.sh` is idempotent and digest-pinned; §9.1 runs `scripts/smoke.sh`
against your `BASE_URL` at the tail (a failure warns but doesn't abort).
Secret-rotation auto-bounce (checksum annotations) rolls dependent pods on the
next `helm upgrade` when bootstrap/postgres/neo4j secrets change.

## Rotating the operator set

With the CI path there is nothing to rotate: grant the new operator repo
write access (to run `workflow_dispatch`) and revoke the old one's. The
cluster's workflow-URI identity pin never changes.

If you must take over the **local** path cleanly:
1. Get GHCR `write:packages` on the owner org.
2. `gh auth login` as yourself.
3. Widen the cluster's identity regexp (above) and re-run `install.sh`.
4. From then on, publish exactly as above — nothing is tied to the previous
   operator's laptop.
