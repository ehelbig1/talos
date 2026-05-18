# Talos k3s Runbook — Phase 1

Single-node k3s deployment for the first-user phase. Targets ~$60-90/mo
running cost with external Postgres (Neon) + Redis (Upstash) + everything
else in-cluster. Designed so the same chart + manifests deploy unchanged
to managed Kubernetes in Phase 2.

## Cost reference

| Component                     | Service                | Monthly |
|-------------------------------|------------------------|--------:|
| VM (4 vCPU / 8 GB / 160 GB)   | Hetzner CPX31          |   $22   |
| Postgres + pgvector           | Neon Free/Launch       | $0-19   |
| Redis                         | Upstash pay-per-request|  $0-10  |
| Neo4j, NATS, Vault, MinIO     | self-host on VM        |    $0   |
| Frontend CDN                  | Cloudflare Pages       |    $0   |
| DNS + TLS                     | Cloudflare + LE        |    $0   |
| Observability                 | Grafana Cloud free     |    $0   |
| Backups (snapshots)           | Hetzner snapshots      |   ~$5   |
| **Total**                     |                        | **~$50-80** |

## Pre-install checklist

1. **Provision a VM**. 4 vCPU / 8 GB RAM / 80+ GB NVMe. Ubuntu 22.04 or
   24.04. Hetzner CPX31, DO Premium 4GB + 2 extra, Linode Dedicated 4GB,
   or equivalent. Enable the provider's automated snapshots.

2. **DNS + firewall.** Point an A record (e.g. `talos.example.com`) at
   the VM's public IPv4. Open inbound 80/tcp and 443/tcp. Restrict
   6443/tcp (k3s API) to your home IP or VPN.

3. **Provision external data services:**
   - **Postgres** — create a Neon project with the `pgvector` extension
     enabled. Capture the full connection string including `sslmode=require`.
   - **Redis** — create an Upstash database (regional, not global).
     Capture the `rediss://` connection string.

4. **Build + publish signed images.** You need
   `ghcr.io/OWNER/talos-controller`, `-worker`, `-frontend` available
   and signed via Cosign. The existing `.github/workflows/release.yml`
   does this — tag a release to produce them. If you haven't yet,
   disable Sigstore enforcement in step 6 below.

5. **SSH to the VM** and clone the repo:
   ```bash
   sudo apt-get update && sudo apt-get install -y git curl openssl
   sudo git clone https://github.com/OWNER/talos.git /opt/talos
   cd /opt/talos
   ```

## Install

### 1. Configure install.env

You need image digests for all three services. Get them with:

```bash
# Pulled images report their own digest:
docker buildx imagetools inspect ghcr.io/OWNER/talos-controller:latest --format '{{.Manifest.Digest}}'
docker buildx imagetools inspect ghcr.io/OWNER/talos-worker:latest      --format '{{.Manifest.Digest}}'
docker buildx imagetools inspect ghcr.io/OWNER/talos-frontend:latest    --format '{{.Manifest.Digest}}'
```

Then write the env file:

```bash
sudo mkdir -p /etc/talos
sudo tee /etc/talos/install.env >/dev/null <<'EOF'
# Required
TALOS_HOST=talos.example.com
TALOS_ACME_EMAIL=you@example.com
TALOS_POSTGRES_URL=postgres://...@neon.tech/talos?sslmode=require
TALOS_REDIS_URL=rediss://default:TOKEN@HOST.upstash.io:6379
TALOS_GHCR_OWNER=your-github-user-or-org
TALOS_CONTROLLER_DIGEST=sha256:0000...  # 64 hex chars
TALOS_WORKER_DIGEST=sha256:0000...
TALOS_FRONTEND_DIGEST=sha256:0000...

# Optional (defaults shown)
# TALOS_API_HOST=api.${TALOS_HOST}            # controller ingress hostname
# TALOS_FRONTEND_HOST=${TALOS_HOST}           # frontend ingress hostname
# TALOS_GHCR_REPO=talos                       # for sigstore identity regex
# TALOS_DISABLE_SIGSTORE=yes                  # admit unsigned images (first deploy)
# TALOS_IMAGE_PULL_SECRET=ghcr-pull           # if your ghcr packages are private

# Optional — LLM provider keys. Empty = controller skips that provider.
# ANTHROPIC_API_KEY=
# OPENAI_API_KEY=

# Optional — embedding provider. Pick ONE provider; the four vars must agree.
# (See controller/src/mcp/search.rs::EmbeddingConfig for the full provider list.)
# OpenAI:  EMBEDDING_API_URL=https://api.openai.com/v1/embeddings
#          EMBEDDING_API_KEY=sk-...   EMBEDDING_MODEL=text-embedding-3-small
#          EMBEDDING_DIMENSIONS=1536
# Voyage:  EMBEDDING_API_URL=https://api.voyageai.com/v1/embeddings
#          EMBEDDING_API_KEY=...      EMBEDDING_MODEL=voyage-3
#          EMBEDDING_DIMENSIONS=1024  EMBEDDING_MAX_RPM=3   # free tier; raise for paid
# EMBEDDING_API_URL=
# EMBEDDING_API_KEY=
# EMBEDDING_MODEL=
# EMBEDDING_DIMENSIONS=
# EMBEDDING_MAX_RPM=                  # default 60; lower for tight free tiers

# Optional — OAuth clients per integration. Empty = integration disabled.
# GOOGLE_CLIENT_ID=    GOOGLE_CLIENT_SECRET=
# GMAIL_CLIENT_ID=     GMAIL_CLIENT_SECRET=
# SLACK_CLIENT_ID=     SLACK_CLIENT_SECRET=
# ATLASSIAN_CLIENT_ID= ATLASSIAN_CLIENT_SECRET=
# OKTA_DOMAIN= OKTA_CLIENT_ID= OKTA_CLIENT_SECRET=
# SNYK_CLIENT_ID=      SNYK_CLIENT_SECRET=
EOF
sudo chmod 600 /etc/talos/install.env
```

### 2. Run the installer

```bash
sudo /opt/talos/deploy/k3s/install.sh
```

Expect ~8 minutes. The script is idempotent — safe to re-run after
fixing any pre-flight error.

### 3. Back up the bootstrap secret immediately

**This is the most important step in the entire runbook.** The
`TALOS_MASTER_KEY` inside this Secret is the master key for every DEK
in the database. Losing it means losing every encrypted column
(actor_memory, module_executions payloads, workflow_executions output,
all secrets). Vault transit can survive its unseal key being in the
Kubernetes API only because Vault's data is PVC-backed — if the VM
disk dies, you still need this.

```bash
DATE=$(date +%Y%m%d)
sudo k3s kubectl -n talos get secret talos-bootstrap -o yaml \
    > ~/talos-bootstrap.backup.$DATE.yaml
sudo k3s kubectl -n talos get secret talos-neo4j -o yaml \
    > ~/talos-neo4j.backup.$DATE.yaml
chmod 600 ~/talos-*.backup.*.yaml
```

Move that file off the VM (to 1Password, a hardware token, or a cold
backup) within minutes of install. Do NOT commit it to git. Do NOT
email it to yourself.

## Verification

`install.sh` runs `scripts/smoke.sh` at the tail of every deploy (§9.1)
which probes every nginx-fronted path end-to-end. If the install
output ends with `✓ smoke OK`, the public surface is healthy. Re-run
on demand any time:

```bash
make smoke BASE_URL=https://talos.example.com
# Or for the full Phase-B encryption round-trip leg too:
SMOKE_AGENT_TOKEN=talos_mcp_… SMOKE_ACTOR_ID=<uuid> \
    make smoke BASE_URL=https://talos.example.com
```

Manual checks worth running once on a fresh deploy:

```bash
# Pods all running
sudo k3s kubectl -n talos get pods

# Ingress has a TLS cert
sudo k3s kubectl -n talos get certificate
# Should show READY=True within 2-3 minutes of DNS + ACME completion

# Vault is unsealed (key lives on the PVC, unseal survives pod restart)
sudo k3s kubectl -n talos exec statefulset/talos-vault-0 -- \
    vault status -format=json | jq '.sealed'

# End-to-end: load the UI
curl -I https://talos.example.com/
```

## Day-2 operations

### Backups

**Nightly automated (set this up before you serve traffic):**

```bash
sudo tee /etc/cron.daily/talos-backup >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
BACKUP_DIR=/var/backups/talos
mkdir -p "$BACKUP_DIR"
DATE=$(date +%Y%m%d)

# Postgres → dump from Neon via pg_dump
pg_dump "$(grep DATABASE_URL /etc/talos/install.env | cut -d= -f2-)" \
    --format=custom --compress=9 \
    > "$BACKUP_DIR/pg-$DATE.dump"

# Vault transit keys (file storage PVC snapshot)
k3s kubectl -n talos exec statefulset/talos-vault-0 -- \
    tar -czf - /vault/file \
    > "$BACKUP_DIR/vault-$DATE.tar.gz"

# Neo4j graph data
k3s kubectl -n talos exec statefulset/talos-neo4j-0 -- \
    neo4j-admin database dump neo4j --to-stdout \
    > "$BACKUP_DIR/neo4j-$DATE.dump"

# Keep 14 days locally, rsync to off-site
find "$BACKUP_DIR" -mtime +14 -delete
# rsync -az "$BACKUP_DIR/" backup-server:/srv/talos-backups/
EOF
sudo chmod +x /etc/cron.daily/talos-backup
```

Test restore quarterly. A backup you haven't restored is a hypothesis.

### Rotating or adding secret keys

Bootstrap secrets are intentionally *not* managed by Helm so rotation is
decoupled from chart upgrades. `install.sh` is "create-once" — re-running
it after the first install does NOT update the secret (re-creating it would
rotate `TALOS_MASTER_KEY` and orphan every encrypted DEK). To add a new key
or rotate an existing one, use the helper:

```bash
# Add embedding provider config (multiple keys at once):
sudo scripts/patch-bootstrap-secret.sh \
    EMBEDDING_API_URL=https://api.voyageai.com/v1/embeddings \
    EMBEDDING_MODEL=voyage-3 \
    EMBEDDING_DIMENSIONS=1024

# Pipe a sensitive value from an env var so the key never lands in shell history:
echo -n "$VOYAGE_KEY" | sudo scripts/patch-bootstrap-secret.sh EMBEDDING_API_KEY=-

# Rotate JWT_SECRET (random new value):
NEW=$(openssl rand -hex 32)
echo -n "$NEW" | sudo scripts/patch-bootstrap-secret.sh JWT_SECRET=-
```

The helper handles namespace + secret name defaults, base64 encoding (via
`stringData`), value masking in stdout, and the rolling controller restart
so the new env values take effect. See `scripts/patch-bootstrap-secret.sh`
for the full env override list (custom namespace, skip-restart mode, etc.).

**Never rotate `TALOS_MASTER_KEY` without a migration plan** — every
DEK in the database is AES-GCM-wrapped by the current KEK. Rotation
requires the `rewrap_deks_to_vault` tool to be adapted for env→env
rotation first.

### Upgrading

Match the upgrade tier to what actually changed in the new commits:

| Tier | When to use | What it does |
|---|---|---|
| **Tier 1 — chart only** | New commits only touched `deploy/`, `migrations/`, or docs | `git pull` + `install.sh` → helm upgrade picks up new chart values, the `pre-upgrade` migrations Job applies pending SQL, no image rebuild |
| **Tier 2 — code + chart** | New commits touched `controller/`, `worker/`, `frontend/`, or any `Cargo.toml`/lockfile | Rebuild the affected images, push to ghcr, update `TALOS_*_DIGEST` in `install.env`, then `install.sh` |

Most upgrades are Tier 1. The deploy memory and CHANGELOG.md flag
which release lines required a rebuild.

#### Tier 1 — chart-only upgrade

```bash
cd /opt/talos && sudo git pull
sudo /opt/talos/deploy/k3s/install.sh   # idempotent
sudo k3s kubectl -n talos rollout status deploy/talos-controller --timeout=3m
```

The installer re-runs `helm upgrade` which triggers the migrations Job
as a `pre-upgrade` hook. If the Job fails, the release does not
upgrade — check `kubectl -n talos logs job/talos-migrations`. §8.5
re-applies the Traefik `externalTrafficPolicy: Local` patch
idempotently. §9.1 runs the public-path smoke test (`scripts/smoke.sh`)
at the tail.

**Frontend ConfigMap edits auto-roll the pod.** The frontend Deployment
carries a `checksum/config` annotation hashing the rendered ConfigMap,
so any nginx route addition (e.g. a new `location /xxx`) triggers a
pod rotation on the next `helm upgrade`. No manual
`kubectl rollout restart deploy/talos-frontend` needed.

#### Tier 2 — code-change upgrade (rebuild new images)

**The digest in `install.env` is what gets deployed — not `:latest`.**
Re-running `install.sh` with stale digests is a silent no-op (Helm
sees no field change and keeps the previous pod). Always update the
digest BEFORE running `install.sh` after a rebuild.

From your dev machine:

```bash
cd ~/projects/talos
docker buildx build --platform linux/amd64 \
  --file controller/Dockerfile \
  --build-context workflow_engine=../talos-workflow-engine \
  --tag ghcr.io/OWNER/talos-controller:latest --push .
docker buildx build --platform linux/amd64 \
  --file frontend/Dockerfile \
  --tag ghcr.io/OWNER/talos-frontend:latest --push ./frontend
docker buildx build --platform linux/amd64 \
  --file worker/Dockerfile \
  --build-context workflow_engine=../talos-workflow-engine \
  --tag ghcr.io/OWNER/talos-worker:latest --push .

# Print the new digests — paste into install.env on the VM.
for img in talos-controller talos-frontend talos-worker; do
  printf "%-20s " "$img"
  docker buildx imagetools inspect ghcr.io/OWNER/$img:latest \
    --format '{{.Manifest.Digest}}'
done
```

On the VM, update ONLY the lines for images you actually rebuilt:

```bash
sudo nano /etc/talos/install.env   # update TALOS_*_DIGEST lines
sudo /opt/talos/deploy/k3s/install.sh
kubectl -n talos rollout status deploy/talos-controller --timeout=5m
kubectl -n talos rollout status deploy/talos-frontend   --timeout=3m
kubectl -n talos rollout status deploy/talos-worker     --timeout=5m
```

Verify the rollout actually picked up the new digest (the most common
deploy mistake is forgetting to update install.env, then puzzling at
unchanged behavior):

```bash
kubectl -n talos describe pod -l app.kubernetes.io/component=controller \
  | grep 'Image:' | head -1
# ↑ must match the new digest you printed above
```

**Don't run buildx in parallel** — controller + worker share Cargo
registry and target cache mounts; concurrent builds thrash and either
fail or silently produce stale artifacts. Build sequentially.

### Templates: disk-bundled vs OCI registry

The controller catalog has two source-of-truth modes, **mutually exclusive**:

| Mode | When | Trade-off |
|---|---|---|
| **Disk-bundled** | `TALOS_REGISTRY_URL` unset | Templates baked into the controller image. No external dependency. To update a template, rebuild + redeploy the controller. Right for single-VM dev / first-deploy. |
| **OCI registry** | `TALOS_REGISTRY_URL` set | Templates live as OCI artifacts (`ghcr.io/OWNER/talos-tools/{name}:{tag}`). Updates ship without redeploying the controller. Workers pull WASM from the registry at execution. Right for production multi-instance. |

#### Switching to OCI mode

Disk-bundled is fine for single-VM Phase 1 — the only downside is "to
update a template, rebuild + redeploy the controller". Flip to OCI when
template updates start outpacing controller releases, or when you go
multi-instance.

##### Pre-conditions

Before flipping, verify all four are true:

```bash
# 1. Controller image includes the OCI sync code (the deleted default
#    http://registry:5000 is gone).
sudo k3s kubectl -n talos logs deploy/talos-controller --since=10m \
  | grep 'http://registry:5000'   # must be EMPTY

# 2. Worker image includes cosign (only needed if you'll also enable
#    Sigstore enforcement — recommended).
sudo k3s kubectl -n talos exec deploy/talos-worker -- cosign version
# Expect: GitVersion: v2.4.x

# 3. The publish workflow has been wired up.
ls -la .github/workflows/template-publish.yml

# 4. ghcr.io packages allow your image-pull (public packages by default;
#    private requires OCI_REGISTRY_USERNAME/PASSWORD — see below).
```

If (1) or (2) fails, rebuild + push controller / worker first (see
*Rolling out new images*), update digests in `install.env`, and re-run
`install.sh` before continuing.

##### Procedure

1. **Trigger the publish workflow** to populate the registry. The workflow
   uses the controller image's `publish-templates` subcommand to compile
   every template under `module-templates/`, then `oras push`es each as
   an OCI artifact plus a discovery index at
   `ghcr.io/OWNER/talos-tools/_index:latest`, then `cosign sign --yes`es
   each artifact via GitHub Actions keyless OIDC. Public package by
   default — no auth required for pulls.

   ```bash
   gh workflow run template-publish.yml --repo OWNER/talos
   gh run watch --repo OWNER/talos      # waits until the run finishes
   ```

   Confirm the index landed:

   ```bash
   curl -sI https://ghcr.io/v2/OWNER/talos-tools/_index/manifests/latest \
     | head -5
   # Expect: HTTP/2 200 (or 401 if private — supply -u OWNER:PAT)
   ```

2. **Add `TALOS_REGISTRY_URL` to `/etc/talos/install.env`** on the VM:

   ```bash
   TALOS_REGISTRY_URL=https://ghcr.io
   # Optional — defaults to ${TALOS_GHCR_OWNER}/talos-tools:
   # TALOS_REGISTRY_NAMESPACE=OWNER/talos-tools
   ```

3. **Re-run `install.sh`** — Helm sees no image change so the rollout is
   trivial; the controller picks up the new env var on restart, skips
   disk seeding, pulls the `_index` artifact, and populates `modules`
   from OCI:

   ```bash
   sudo /opt/talos/deploy/k3s/install.sh
   ```

##### Verification

```bash
# A. Controller logs the OCI sync, not the disk-seed.
sudo k3s kubectl -n talos logs deploy/talos-controller --since=2m \
  | grep -iE 'oci registry sync|seed_templates|discovered.*templates'
# Expect: "Starting OCI registry sync from https://ghcr.io"
#         "discovered N templates" then "{N} succeeded, 0 failed"
# Should NOT contain: "Templates will be served from the disk-seeded set only"

# B. Catalog rows now have oci_url populated.
export PGURL=$(sudo k3s kubectl -n talos get secret talos-bootstrap \
                 -o jsonpath='{.data.DATABASE_URL}' | base64 -d)
psql "$PGURL" -P pager=off -c "
SELECT kind, count(*),
       count(*) FILTER (WHERE oci_url IS NOT NULL) AS from_oci
FROM modules GROUP BY kind ORDER BY kind;"
# Expect: catalog row with from_oci = count.
# from_oci = 0 means disk seeding is still active — TALOS_REGISTRY_URL
# wasn't picked up. Restart the controller and re-check.

# C. End-to-end — execute a workflow that uses a catalog module and watch
# the worker pull WASM bytes from GHCR with the digest verification step.
sudo k3s kubectl -n talos logs deploy/talos-worker --since=5m \
  | grep -iE 'oci pull|verify_oci_layer|digest match'
```

##### When sync fails

| Symptom | Cause | Fix |
|---|---|---|
| Log: `_index manifest 404` | Workflow hasn't run, or wrong namespace | Trigger `template-publish.yml`; verify `TALOS_REGISTRY_NAMESPACE` matches `OWNER/talos-tools` |
| Log: `unauthorized` (401/403) | Private package, missing creds | See *Private templates package* below |
| Log: `0 discovered, OCI sync disabled` | `TALOS_REGISTRY_URL` not actually set in pod env | `kubectl exec deploy/talos-controller -- env \| grep TALOS_REGISTRY` — confirm the install.sh re-render landed |
| Catalog rows present but `from_oci = 0` | Pod restarted on the OLD image | Pod predates the env-var change; `kubectl rollout restart deploy/talos-controller` |
| Sync logs success but UI still shows old templates | Controller's 5-min sync loop hasn't fired yet OR frontend cache | Wait 5 min, hard-refresh the UI |

##### Rolling back to disk seeding

```bash
sudo nano /etc/talos/install.env   # comment out TALOS_REGISTRY_URL
sudo /opt/talos/deploy/k3s/install.sh
sudo k3s kubectl -n talos rollout restart deploy/talos-controller
```

On next boot the controller logs `TALOS_REGISTRY_URL not set — OCI
registry sync disabled. Templates will be served from the disk-seeded
set only.` and re-populates `modules` from the image-bundled set. Rows
that existed only via OCI become stale (still in the table, but with
`oci_url` set to a registry the controller no longer talks to) — clean
them up with `psql -c "DELETE FROM modules WHERE kind='catalog' AND
oci_url IS NOT NULL AND name NOT IN (<disk-bundled set>);"` or just
leave them; they're inert until something tries to fetch.

#### Authoring + publishing new templates

Add a directory under `module-templates/{name}/` with `talos.json`
(manifest) + `template.rs` (Rust source). Push to `main`. The
`template-publish.yml` workflow auto-runs and republishes the index. The
controller's 5-min sync loop picks up the new template within 10 minutes
of the workflow completing.

To publish a new version of an existing template, bump `version` in
`talos.json` (semver tag) and push. Both `:VERSION` and `:latest` tags
are pushed by the workflow.

#### Trust model: Sigstore signing

The publish workflow signs every artifact (each template + the discovery
index) via `cosign sign --yes` using GitHub Actions keyless OIDC. The
worker (and optionally controller) can be configured to verify these
signatures BEFORE pulling/executing — defense against a compromised
registry pushing a malicious WASM under a known template tag.

To enable enforcement, add to `install.env`:

```bash
TALOS_SIGSTORE_REQUIRED=true
TALOS_SIGSTORE_IDENTITY_REGEXP='^https://github\.com/OWNER/talos/\.github/workflows/template-publish\.yml@'
```

Three modes:

| `TALOS_SIGSTORE_REQUIRED` | Behaviour | When |
|---|---|---|
| `""` / `false` | No verification | Dev / first-deploy / when templates aren't signed yet |
| `audit` | Verify, log on failure, continue | Migration window — signed and unsigned templates coexist |
| `true` | Verify, refuse to execute on failure | Production |

The identity regexp **must** match the SAN URI of the signing
certificate. For GitHub Actions keyless, the SAN is the fully-qualified
workflow URL plus `@<git ref>`. The trailing `@` in the pattern is
critical — it prevents a fork-named workflow (`template-publish.yml-evil.yml`)
from matching.

After enabling, redeploy the worker and watch the first WASM execution:

```bash
sudo /opt/talos/deploy/k3s/install.sh
kubectl logs -n talos deploy/talos-worker --tail=100 \
  | grep -iE 'sigstore|cosign'
# Expect: "sigstore_verify_ok" event on each fresh pull.
```

Cosign is bundled in the worker image so no external binary install is
needed. Verification uses the public Fulcio CA and Rekor transparency
log (no operator-managed keys).

#### Private templates package

Templates default to public on GHCR (templates aren't secrets). For
private packages, add to `install.env`:

```bash
OCI_REGISTRY_USERNAME=your-github-username
OCI_REGISTRY_PASSWORD=ghp_yourPATwith_packages_read_scope
```

Both controller (catalog sync) and worker (WASM pull) need these; they're
auto-propagated via the chart `controller.env` / `worker.env` blocks if
you add them under those keys in `values-deploy.yaml`. PAT works as the
password for GHCR's Basic auth path.

### Monitoring

k3s ships Traefik; point Grafana Cloud's free hosted metrics at the
Traefik `/metrics` endpoint. Also wire the controller's
`/metrics` (Prometheus format) and Vault's audit log output into
Grafana Loki for query.

Alerts to set up day 1:
- Disk > 75% on the VM (Vault + Neo4j grow silently)
- Any pod in `CrashLoopBackOff` for > 5 min
- Certificate expiry < 14 days
- controller p99 latency > 2 s
- Vault sealed

### Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| `__memory_write__ persist failed: decrypt_dek active provider failed` | Vault key generation drift (PVC restored from backup, etc.) | `kubectl -n talos logs statefulset/talos-vault-0` |
| Migrations Job fails on upgrade | Schema conflict, or wrong-arch image (see below) | `kubectl -n talos logs job/talos-migrations`; reconcile `migrations/*.sql`. **If logs are gone:** see "Migration recovery" below. |
| `BackoffLimitExceeded` on migrations job + no pod logs | Pod was GC'd by job-controller after backoff. Almost always means container failed to exec (wrong-arch image). See recovery below. |
| Certificates stuck `READY=False` | ACME HTTP-01 challenge can't reach the ingress | DNS propagation? firewall open on :80? |
| All pods `Pending` | k3s disk pressure eviction | `df -h`; prune images: `sudo k3s crictl rmi --prune` |
| Worker can't reach controller | NetworkPolicy too restrictive | `kubectl -n talos describe networkpolicy` |

### Migration recovery

When `helm upgrade` fails with `pre-upgrade hooks failed: ... job talos-migrations failed: BackoffLimitExceeded`, the failed pod is often deleted by the K8s job-controller (event: `SuccessfulDelete pod: talos-migrations-XXXXX`) before `kubectl logs` can read it. By then `kubectl logs job/talos-migrations` returns `error: timed out waiting for the condition` and you have no idea what failed.

The fix is to delete the failed Job and re-run install while tailing logs in real time. The next attempt produces a fresh pod whose logs you can `-f`:

```bash
kubectl -n talos delete job talos-migrations --ignore-not-found
sudo /opt/talos/deploy/k3s/install.sh > /tmp/install.log 2>&1 &
INSTALL_PID=$!
while ! kubectl -n talos get pods -l job-name=talos-migrations --no-headers 2>/dev/null | grep -q .; do sleep 1; done
kubectl -n talos logs -f -l job-name=talos-migrations --tail=200
kubectl -n talos get events --sort-by=.lastTimestamp | tail -15
wait $INSTALL_PID
echo "install exit: $?"
```

**Most common root causes once logs are visible:**

1. **`exec /usr/local/cargo/bin/sqlx: exec format error`** — wrong CPU architecture. The image is arm64 but the cluster is amd64 (or vice versa). Almost always happens when `docker compose build` was used on Apple Silicon instead of `make release` (which forces `linux/amd64` via buildx). Fix: rebuild with `make release VERSION=1.0.0-rNNN` and re-pin the digests in `/etc/talos/install.env`.
2. **`migration ... was previously applied but has been modified`** — a previously-applied migration file's checksum changed. NEVER edit applied migrations; ship a new one that corrects the prior. See CLAUDE.md "Migration Rules".
3. **Postgres auth/host failure** — `kubectl -n talos get secret talos-bootstrap -o jsonpath='{.data.DATABASE_URL}' | base64 -d` (CAREFUL: don't paste anywhere). Verify connectivity via `psql` from the host.

## Phase 2 migration — graduating to managed Kubernetes

The chart is the same; only values change. Rough procedure:

1. **Provision managed K8s** (GKE Autopilot or EKS). Install cert-manager
   + Sigstore policy-controller (same as `install.sh` steps 3-4).
2. **Provision managed RDS Postgres** (with `pgvector`) and managed
   Redis (ElastiCache), or keep Neon/Upstash if they meet SLA.
3. **Migrate Postgres** — use Neon's logical replication or plain
   pg_dump/pg_restore during a maintenance window.
4. **Dump + restore Neo4j** — `neo4j-admin database dump`, move to
   AuraDB, `neo4j-admin database load` (or deploy Neo4j StatefulSet
   same as Phase 1 if staying self-hosted).
5. **Dump + restore Vault** — tar of `/vault/file` PVC. The DEKs in the
   new Postgres must match the Vault instance. If you're migrating both
   Vault and Postgres, do them together and validate with
   `cargo run --example verify_phase_b`.
6. **Install Talos chart on new cluster** with `values-phase2.yaml`:
   ```bash
   helm install talos ./deploy/helm/talos \
       -f values-phase2.yaml \
       -n talos --create-namespace
   ```
7. **Cutover DNS.** Traffic shifts to the new cluster when the A record
   TTL expires.
8. **Decommission Phase 1 VM** after a 72-hour soak and a verified
   backup restore drill against the old disk image.

If you're disciplined about step 0 (snapshot the VM right before
starting), the rollback is always a DNS switch back.

## See also

- `deploy/helm/talos/README.md` — chart value reference + secret inventory
- `docs/security/operational-runbook.md` — incident response, KEK rotation
- `docs/compliance/soc2-control-mapping.md` — audit evidence per control
- `CHANGELOG.md` — security-relevant release notes
