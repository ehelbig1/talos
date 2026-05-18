# Talos Helm Chart

A starter Helm chart for the Talos workflow automation platform.

- **controller** — Rust/Axum GraphQL + REST + MCP API server
- **worker** — credential-free wasmtime runtime
- **frontend** — React/TS SPA (nginx-served)
- **nats** — JetStream, self-hosted in-cluster
- **neo4j** — graph RAG (in-cluster Phase 1; AuraDB optional Phase 2)
- **vault** — KEK backend (in-cluster Phase 1; HCP Vault optional Phase 2)
- **minio** — S3-compatible audit-log + artifact storage
- **postgres** — **external** (Neon → RDS)
- **redis** — **external** (Upstash → ElastiCache)

The chart is designed for two deployment shapes:

| Phase | Target | Overlay |
|-------|--------|---------|
| 1 | k3s single-node, mostly-external SaaS | `values-phase1.yaml` |
| 2 | managed K8s, multi-AZ, HA | `values-phase2.yaml` |

---

## 1. Required external services (per phase)

### Phase 1
| Service | Provider | URI shape |
|---------|----------|-----------|
| Postgres (pgvector) | Neon Serverless (Scale plan) | `postgres://USER:PASS@ep-xxx.aws.neon.tech/talos?sslmode=require` |
| Redis | Upstash (Regional, `rediss://`) | `rediss://default:TOKEN@usw2-xxx.upstash.io:6379` |

Create the Neon project with the `vector` extension enabled
(`CREATE EXTENSION IF NOT EXISTS vector;`) before running the first
install — the sqlx migrations assume pgvector is available.

### Phase 2
| Service | Provider | Notes |
|---------|----------|-------|
| Postgres | AWS RDS, Aurora PG, or GCP AlloyDB | Enable `pgvector` via `CREATE EXTENSION vector`. IAM auth optional. |
| Redis | AWS ElastiCache (cluster mode disabled) | TLS required. |
| Neo4j | Optional AuraDB (`neo4j.enabled: false`) | AuraDB Pro tier minimum for production workloads. |
| Vault | Optional HCP Vault (`vault.enabled: false`, `vault.addrOverride: …`) | Use AppRole auth; supply the derived token via `bootstrapSecret.data.VAULT_TOKEN`. |

---

## 2. Secrets

Every sensitive value the controller/worker needs is keyed into the
`bootstrapSecret` defined by this chart (`talos-controller-secrets`
by default). For first-install convenience the chart can create this
Secret from values.yaml; for production, pre-create the Secret via
[external-secrets.io](https://external-secrets.io/) or
[sealed-secrets](https://github.com/bitnami-labs/sealed-secrets)
and set `bootstrapSecret.enabled: false`.

| Key | Purpose | Generate / Source | Rotate |
|-----|---------|-------------------|--------|
| `DATABASE_URL` | Postgres (pgvector) connection | From managed provider | When provider credentials rotate; update and restart controller |
| `REDIS_URL` | Redis connection | From managed provider | As above |
| `NATS_USER` / `NATS_PASSWORD` | NATS basic auth | `openssl rand -hex 24` each | Rotate via `kubectl rollout restart deploy/…controller` + `deploy/…worker` after updating the secret |
| `NEO4J_USER` / `NEO4J_PASSWORD` | Graph DB auth | Choose; min 32 chars | Rotate Neo4j user, update secret, restart |
| `TALOS_MASTER_KEY` | AES-256-GCM key for envelope encryption (KEK_PROVIDER=env OR legacy-read fallback for Vault mode) | `openssl rand -base64 32` | Rotate via the documented dual-write migration (see `talos-memory/src/rotation.md`) |
| `VAULT_TOKEN` | Vault transit-engine client token | In-cluster: created by vault-init (`dev-root`). HCP: AppRole-derived | When AppRole rotates, or yearly for the dev-root token |
| `JWT_SECRET` | HS256 JWT signing secret | `openssl rand -hex 48` | Rotate; the controller accepts both `JWT_ALGORITHM` + `JWT_ALGORITHM_PREVIOUS` during transition |
| `WORKER_SHARED_KEY` | HMAC shared between controller ↔ worker (signs every NATS-RPC and Job) | `openssl rand -hex 32` | **Rotate annually.** Update secret; redeploy controller + worker together — mixed deploys fail signature verification |
| `TALOS_AUDIT_SIGNING_KEY` | Tamper-evident audit-event signing | `openssl rand -hex 32` | Rotate annually; append to audit tooling's historical key set |
| `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` | MinIO superuser | Random strings; 24+ chars | Rotate; restart minio statefulset |
| `MINIO_CONTROLLER_USER` / `MINIO_CONTROLLER_PASSWORD` | Least-privilege write-only user for audit-logs bucket | Random strings | Rotate; update and restart controller |
| `MINIO_WORKER_USER` / `MINIO_WORKER_PASSWORD` | Least-privilege worker writer | Random strings | As above |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | Tier-2 LLM provider keys | From provider console | Rotate in provider; the LlmClient's 60s cache propagates to both controller scaffolding and worker sandbox |
| `EMBEDDING_API_URL` / `EMBEDDING_API_KEY` | Hosted embeddings | From provider console | Leave blank to use in-cluster Ollama |
| `GOOGLE_CLIENT_ID/SECRET`, `GMAIL_*`, `SLACK_*`, `ATLASSIAN_*`, `OKTA_*`, `SNYK_*` | OAuth clients | Provider developer consoles | Per provider policy |
| `ADMIN_SECRET_KEY` | Admin-only operator endpoints gate | `openssl rand -hex 32` | Leave empty in production; set only during active ops work |
| `TOTP_ISSUER` | Shown on TOTP provisioning QR codes | Any string | Rarely |

### Generating all keys at once

```bash
cat <<EOF > phase1-secrets.env
DATABASE_URL=...
REDIS_URL=...
NATS_USER=$(openssl rand -hex 24)
NATS_PASSWORD=$(openssl rand -hex 24)
NEO4J_USER=neo4j
NEO4J_PASSWORD=$(openssl rand -hex 32)
TALOS_MASTER_KEY=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -hex 48)
WORKER_SHARED_KEY=$(openssl rand -hex 32)
TALOS_AUDIT_SIGNING_KEY=$(openssl rand -hex 32)
MINIO_ROOT_USER=$(openssl rand -hex 12)
MINIO_ROOT_PASSWORD=$(openssl rand -hex 32)
MINIO_CONTROLLER_USER=$(openssl rand -hex 12)
MINIO_CONTROLLER_PASSWORD=$(openssl rand -hex 32)
MINIO_WORKER_USER=$(openssl rand -hex 12)
MINIO_WORKER_PASSWORD=$(openssl rand -hex 32)
EOF
```

Then patch those into a local `phase1-overrides.yaml` for the install.

---

## 3. Install

Replace `OWNER` in all image repositories (`ghcr.io/OWNER/talos-*`) and the
sigstore identity regex with your GitHub org/repo before first install.

### Phase 1 (k3s)

```bash
kubectl create namespace talos

# PodSecurityAdmission "restricted" — the chart's pod/container security
# contexts already conform.
kubectl label namespace talos \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# (Optional but recommended) install the sigstore policy-controller:
#   helm install policy-controller sigstore/policy-controller \
#     --namespace cosign-system --create-namespace

helm install talos ./deploy/helm/talos \
  --namespace talos \
  -f ./deploy/helm/talos/values-phase1.yaml \
  -f ./phase1-overrides.yaml
```

### Phase 2 (EKS / GKE / AKS)

```bash
# Same namespace labelling as Phase 1.
helm install talos ./deploy/helm/talos \
  --namespace talos \
  -f ./deploy/helm/talos/values-phase2.yaml \
  -f ./phase2-overrides.yaml
```

### Images

All images are digest-pinned. Replace the three application image digests
before install (search values.yaml for `PLACEHOLDER_`):

```yaml
controller:
  image:
    repository: ghcr.io/YOURORG/talos-controller
    digest: "sha256:abcdef..."
worker:
  image:
    repository: ghcr.io/YOURORG/talos-worker
    digest: "sha256:abcdef..."
frontend:
  image:
    repository: ghcr.io/YOURORG/talos-frontend
    digest: "sha256:abcdef..."
```

---

## 4. Upgrade procedure

`helm upgrade` runs the migrations Job again (idempotent — sqlx skips
already-applied migrations). The Vault init Job re-runs as a
`post-upgrade` hook and is idempotent.

```bash
helm upgrade talos ./deploy/helm/talos -n talos \
  -f ./deploy/helm/talos/values-phase2.yaml \
  -f ./phase2-overrides.yaml \
  --atomic --timeout 10m
```

If a migration fails, the upgrade aborts before the controller rolls out
against an unmigrated schema. Inspect with:

```bash
kubectl -n talos logs job/talos-migrations
```

**Never edit an already-applied migration.** Follow-up migrations only.

---

## 5. Secret rotation

All rotations follow the same pattern: update the Secret, then
restart the workloads that read it.

### WORKER_SHARED_KEY (annual)

Mixed deployments (old controller + new worker, or vice-versa) fail HMAC
verification. Roll the secret, then restart controller + worker together:

```bash
NEW_KEY=$(openssl rand -hex 32)
kubectl -n talos patch secret talos-controller-secrets \
  --type=json -p='[{"op":"replace","path":"/data/WORKER_SHARED_KEY","value":"'$(printf %s $NEW_KEY | base64)'"}]'
kubectl -n talos rollout restart deploy/talos-controller deploy/talos-worker
kubectl -n talos rollout status  deploy/talos-controller deploy/talos-worker
```

### TALOS_MASTER_KEY (AES-256-GCM)

Use the controller's dual-write rotation migration flow
(`KEK_DISABLE_LEGACY=false` during window; document in your runbook).

### Vault root/dev-root token

In-cluster: delete the dev-root token via `vault token revoke dev-root`
and re-run the vault-init Job:

```bash
kubectl -n talos delete job/talos-vault-init
kubectl -n talos apply -f ./deploy/helm/talos/templates/vault/init-job.yaml
```

HCP Vault: rotate the AppRole, update `VAULT_TOKEN` in the Secret,
restart the controller.

### OAuth client secrets

Update the provider's console, patch the Secret, restart the controller.
No worker restart is required (worker never holds OAuth credentials).

---

## 6. Disabling sigstore enforcement

If you publish unsigned dev images (pre-GitHub-Actions-release), disable
the policy before `helm install`:

```yaml
security:
  sigstore:
    enabled: false
```

Later, once CI signs releases, flip it back on and re-install the
`policy-controller` webhook; the ClusterImagePolicy resource will apply
on the next `helm upgrade`.

If you prefer to keep enforcement on but allow unsigned internal builds,
tighten the `imageGlobs` list to only include your signed path:

```yaml
security:
  sigstore:
    imageGlobs:
      - "ghcr.io/YOURORG/talos-controller"
      - "ghcr.io/YOURORG/talos-worker"
      - "ghcr.io/YOURORG/talos-frontend"
```

---

## 7. Phase 1 → Phase 2 migration checklist

1. **Provision external services**
   - RDS Postgres (or Aurora) with `pgvector`. Whitelist your VPC.
   - ElastiCache Redis with TLS.
   - (Optional) AuraDB. Generate a `neo4j+s://` URI.
   - (Optional) HCP Vault cluster. Mint an AppRole with a transit-only policy.

2. **Postgres data migration (Neon → RDS)**
   ```bash
   # Capture source
   pg_dump --no-owner --no-acl --format=c \
     "$NEON_URL" > talos-neon.dump
   # Restore to target
   pg_restore --no-owner --no-acl --dbname="$RDS_URL" \
     --create talos-neon.dump
   # Confirm pgvector is enabled on target
   psql "$RDS_URL" -c "CREATE EXTENSION IF NOT EXISTS vector;"
   # Verify row counts
   psql "$RDS_URL" -c "SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 20;"
   ```

3. **Neo4j data export (in-cluster → AuraDB)**
   ```bash
   # Export from in-cluster Neo4j
   kubectl -n talos exec -it sts/talos-neo4j -- \
     neo4j-admin database dump --to-path=/tmp talos
   kubectl -n talos cp talos-neo4j-0:/tmp/talos.dump ./talos.dump
   # Upload to AuraDB via the admin console (push-to-cloud flow)
   ```

4. **Vault data migration (in-cluster → HCP Vault)**
   ```bash
   # Transit keys cannot be exported. Instead:
   #   - Enable HCP Vault transit with a NEW named key.
   #   - Set KEK_DISABLE_LEGACY=false and deploy.
   #   - The controller will decrypt legacy DEKs with TALOS_MASTER_KEY
   #     and re-wrap with the HCP transit key on next write.
   #   - Once the rotation background task completes, set
   #     KEK_DISABLE_LEGACY=true and rotate TALOS_MASTER_KEY out.
   ```

5. **Switch values files**
   ```bash
   helm upgrade talos ./deploy/helm/talos -n talos \
     -f ./deploy/helm/talos/values-phase2.yaml \
     -f ./phase2-overrides.yaml \
     --atomic
   ```

6. **DNS cutover**
   - Point `api.talos.example.com` and `talos.example.com` at the new
     Phase 2 cluster's ingress LB.
   - Observe for 24h; keep Phase 1 k3s online as hot rollback.

7. **Decommission Phase 1**
   - `helm uninstall talos` on the k3s node.
   - Delete the Neon + Upstash resources (keep dumps for 90 days).

---

## 8. Known TODOs / Gaps

- **Ollama GPU**: GPU node selectors / `nvidia.com/gpu` requests are not
  wired up. Add when Phase 2 adds GPU nodes.
- (Resolved 2026-05-14, MCP-797) Worker /healthz endpoint added; helm
  probes switched from `/` to `/healthz`.
- **KEDA ScaledObject**: CPU-only HPA for worker is a placeholder.
  Replace with KEDA-based NATS-queue-depth scaling in production.
- **cert-manager ClusterIssuer**: assumed present. Chart annotations
  reference `letsencrypt-prod` — change or remove as appropriate.
- **NetworkPolicy egress CIDRs**: default `0.0.0.0/0` minus RFC1918.
  Tighten to exact cloud egress ranges for tighter SSRF defense.
- **Sigstore policy-controller**: not bundled. Install separately.

---

## 9. Reference: Environment variable fidelity

Every env var name the controller/worker read is sourced from
`controller/src/` and `worker/src/`. The chart's Deployment templates
mirror the names used in `docker-compose.yml`. If you add a new env var
to the application, update:

1. The appropriate `.env` block in values.yaml (non-sensitive) OR
2. `bootstrapSecret.data` + the `secretKeys` list in
   `templates/controller/deployment.yaml` (sensitive).

Do **not** invent config the application doesn't consume; grep
`controller/src/` and `worker/src/` for `env::var("FOO")` before adding.
