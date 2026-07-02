# Second-Operator Publish & Deploy Runbook

Talos's canonical release path is **local-build** (`scripts/publish-images.sh`) — there is no auto-triggered CI image build. This runbook lets an operator *other than the original one* produce a production image the cluster will admit. It exists because the publish path otherwise assumes one specific person's GitHub identity, GHCR login, and laptop state.

## What a second operator needs

1. **GHCR push access** to `ghcr.io/<owner>/talos-{controller,worker,frontend}`.
   - Either `docker login ghcr.io` already done interactively, or a PAT with `write:packages` exported as `GHCR_TOKEN` (the script will `docker login` for you).
   - `TALOS_GHCR_OWNER` is parsed from `git remote get-url origin`; override it explicitly if your remote differs.
2. **`gh` CLI authenticated** (`gh auth status`). The publish gate calls `gh run list --commit HEAD` to require a green `quality.yml` run before pushing. Without it you'd have to `--skip-ci-check` (don't, for production).
3. **A clean tree on a pushed commit.** Dirty publishes are refused; `--allow-dirty` tags `-dirty` and must never reach production.
4. **`cosign`** (bundled/pinned in the worker Dockerfile version, or install from sigstore.dev). Signing is **on by default**.

## Publish

```bash
# From a clean checkout of the exact commit you want to ship:
gh run list --workflow quality.yml --commit "$(git rev-parse HEAD)"   # confirm it's green
bash scripts/publish-images.sh --update-env /etc/talos/install.env
```

This builds (linux/amd64 by default — mandatory when publishing from Apple Silicon to an x86_64 cluster), pushes `:main-<sha>` + `:main-latest`, cosign-signs all three images in **one** OAuth browser flow, and patches the `TALOS_*_DIGEST=` lines into your `install.env`.

If you truly need to skip signing (dev / a cluster with Sigstore enforcement off): `--no-sign`.

## The signing-identity gotcha (the reason this runbook exists)

Local `cosign sign --yes` binds the signature to **your** GitHub OAuth identity via Fulcio — **not** a workflow URI. If the target cluster enforces Sigstore (`TALOS_SIGSTORE_REQUIRED=true`), its `TALOS_SIGSTORE_IDENTITY_REGEXP` must match **your** email pattern, or the cluster will reject an image you signed even though the signature is valid.

So a second operator must either:

- **Widen the identity regexp** in the cluster's `install.env` to match their email as well as the original operator's — e.g.
  `TALOS_SIGSTORE_IDENTITY_REGEXP='^(alice|bob)@example\.com$'`
  (the OIDC issuer pin stays `https://github.com/login/oauth` for locally-signed images), then re-run `install.sh` so the policy updates; **or**
- Publish from a shared service identity both operators can authenticate as.

Verify a published image before rolling it out:

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

`install.sh` is idempotent and digest-pinned; §9.1 runs `scripts/smoke.sh` against your `BASE_URL` at the tail (a failure warns but doesn't abort). Secret-rotation auto-bounce (checksum annotations) rolls dependent pods on the next `helm upgrade` when bootstrap/postgres/neo4j secrets change.

## Rotating the operator set

If the original operator is unavailable and you need to take over cleanly:
1. Get GHCR `write:packages` on the owner org.
2. `gh auth login` as yourself.
3. Widen `TALOS_SIGSTORE_IDENTITY_REGEXP` (above) and re-run `install.sh`.
4. From then on, publish exactly as above — nothing is tied to the previous operator's laptop.
