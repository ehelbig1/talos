# Talos deployment

Two supported deployment targets. Both use the same Helm chart — only
value overlays differ, so the Phase 1 → Phase 2 migration is a `helm
upgrade` with a different `-f` file, not a rewrite.

## Phase 1 — single-node k3s (first-user, ~$60-90/mo)

Single VM, k3s, external managed Postgres (Neon) + Redis (Upstash),
everything else in-cluster. Designed for solo development and pilot
customers. No HA, single point of failure.

- **Install guide:** [`k3s/README.md`](k3s/README.md)
- **Installer script:** [`k3s/install.sh`](k3s/install.sh) (idempotent)
- **Helm values:** [`helm/talos/values-phase1.yaml`](helm/talos/values-phase1.yaml)

## Phase 2 — managed Kubernetes (enterprise SaaS, ~$800-1400/mo)

GKE Autopilot or EKS with managed RDS Postgres, ElastiCache Redis,
Neo4j AuraDB, and self-hosted NATS + Vault + MinIO on the cluster.
Multi-replica with pod anti-affinity, multi-AZ database, HPA/PDB
configured.

- **Helm values:** [`helm/talos/values-phase2.yaml`](helm/talos/values-phase2.yaml)
- **Migration from Phase 1:** see [`k3s/README.md`](k3s/README.md) §
  *Phase 2 migration*

## Shared artifacts

- **Helm chart:** [`helm/talos/`](helm/talos/) — the single source of
  truth for all Kubernetes manifests. Read its
  [`README.md`](helm/talos/README.md) for value-by-value docs, secret
  inventory, and rotation procedures.
- **Chart values — defaults:** [`helm/talos/values.yaml`](helm/talos/values.yaml)
  documents every tunable with inline comments.

## Choosing a phase

Start in Phase 1 unless one of these is true **today**:
- A paying customer has signed a contract with an SLA > 99%.
- You have > 3 engineers who share on-call rotation.
- You process regulated data (PHI, PCI card data, GDPR personal data at
  scale) that requires multi-AZ by contract.

Otherwise Phase 1 is the right place. Upgrade when customer #2 signs,
or when disk/CPU on the single VM crosses 70% steady state.

## Non-goals of this deploy scaffolding

- **Terraform / OpenTofu modules.** The Helm chart deploys everything
  in-cluster; the external data services (Neon, RDS, etc.) you
  provision by hand the first time. Write IaC when customer #3 arrives.
- **Multi-region.** Single region is correct for Phase 2 SaaS baseline.
  Cross-region failover is a Phase 3 concern that needs app-level
  changes too (clock sync for NATS, DEK replication across Vaults).
- **Managed-SaaS multi-tenancy isolation.** The chart installs ONE
  Talos instance per namespace. Cell-based multi-tenancy (one
  Talos-per-customer) is a Phase 3 pattern.
