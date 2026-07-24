# Talos docs index

One-line map of everything under `docs/`. Split into **Current** (consult these
when building) and **Historical** (dated audits, one-off handoffs, completed
plans — kept for the record, not maintenance targets). Files that look
superseded are flagged inline. Nothing has been moved; this is an index only.

Last indexed: 2026-07-24.

## Current

### Architecture & platform reference

| Doc | What it is |
|---|---|
| [configuration-reference.md](configuration-reference.md) | Authoritative inventory of every environment variable, with duplicate/drift pairs |
| [deployment.md](deployment.md) | Production deployment guide — service-level env-var reference |
| [api-reference.md](api-reference.md) | GraphQL API reference (`/graphql` + `/ws` subscriptions) |
| [architecture/managed-cloud.md](architecture/managed-cloud.md) | Managed-cloud (multi-tenant SaaS) design document |
| [SECRETS_MANAGEMENT.md](SECRETS_MANAGEMENT.md) | Secrets management architecture (envelope encryption, vault paths) |
| [WEBHOOK_ARCHITECTURE.md](WEBHOOK_ARCHITECTURE.md) | Inbound webhook listener architecture |
| [graph-rag.md](graph-rag.md) | Per-actor Neo4j knowledge graph fed by actor-memory writes |
| [smart-actor-context.md](smart-actor-context.md) | Bounded, node-scoped `__actor_context__` assembly (smart memory context) |
| [adaptive-memory-ranking.md](adaptive-memory-ranking.md) | Per-actor learned ranking for the smart-context retriever |
| [memory-reflection.md](memory-reflection.md) | Autonomous per-actor memory-reflection background loop (Phase 3) |
| [split-brain-fencing-design.md](split-brain-fencing-design.md) | Crash-recovery epoch fencing design (resume-path fence landed) |
| [module-entity-consolidation.md](module-entity-consolidation.md) | Module-entity consolidation design (status: not-yet-scheduled implementation) |
| [platform-primitive-checklist.md](platform-primitive-checklist.md) | MANDATORY pre-flight checklist before adding any new signed-NATS-RPC primitive |
| [delivery-node-pattern.md](delivery-node-pattern.md) | Canonical compose(memory)/send(network) two-node split for external delivery |
| [backlog.md](backlog.md) | Living engineering backlog — open, unscheduled tasks |
| [mcp-probe-backlog.md](mcp-probe-backlog.md) | Living backlog of open MCP-probe observations |

### Module development & WASM runtime

| Doc | What it is |
|---|---|
| [module-authoring.md](module-authoring.md) | Module authoring guide — WIT worlds, capabilities, fuel |
| [runtime-enforced-best-practices.md](runtime-enforced-best-practices.md) | Runtime-enforced WASM best practices (dated 2026-02-17 — verify against current lint set) |
| [wasm-automatic-logging.md](wasm-automatic-logging.md) | WASM automatic-logging architecture (dated 2026-02-17) |
| [wasmtime-version-tracking.md](wasmtime-version-tracking.md) | Policy for tracking wasmtime releases/CVEs (sandbox trust anchor) |

### Integration guides

| Doc | What it is |
|---|---|
| [adding-an-integration.md](adding-an-integration.md) | THE authoritative guide + checklist for any third-party integration |
| [integration-pattern.md](integration-pattern.md) | Ten-file push-notification integration pattern (gcal/gmail reference impls) |
| [OAUTH_SETUP.md](OAUTH_SETUP.md) | Google OAuth 2.0 + Okta OIDC login configuration |
| [GITHUB_APP_SETUP.md](GITHUB_APP_SETUP.md) | GitHub App registration + connect/install flow wiring |
| [GMAIL_INTEGRATION.md](GMAIL_INTEGRATION.md) | Gmail OAuth integration setup (config-form data population) |
| [gmail-push-setup.md](gmail-push-setup.md) | Gmail push notifications (Pub/Sub watch) operator setup |
| [gcp-push-setup.md](gcp-push-setup.md) | GCP Cloud Monitoring push-notification setup |
| [gcp-impersonation-setup.md](gcp-impersonation-setup.md) | GCP service-account impersonation (Phase D) setup |
| [integrating-external-apps.md](integrating-external-apps.md) | Pushing workflow results into a sister application |
| [local-public-url.md](local-public-url.md) | ngrok auto-tunnel for push integrations against a local stack |
| [examples/ai-pr-review.md](examples/ai-pr-review.md) | Worked end-to-end example: AI pull-request reviewer |

### Runbooks & operations

| Doc | What it is |
|---|---|
| [security/operational-runbook.md](security/operational-runbook.md) | Operational security runbook (incident response, key handling) |
| [worker-shared-key-rotation.md](worker-shared-key-rotation.md) | Zero-downtime rolling `WORKER_SHARED_KEY` rotation |
| [rfc-0010-enforcement-flip-runbook.md](rfc-0010-enforcement-flip-runbook.md) | RFC 0010 P4 production enforcement flip (WSK retirement) runbook |
| [second-operator-publish-runbook.md](second-operator-publish-runbook.md) | Second-operator image publish & deploy runbook |
| [dev-backup.md](dev-backup.md) | Full-stack dev-environment backup procedure |

### Security & compliance

| Doc | What it is |
|---|---|
| [THREAT_MODEL.md](THREAT_MODEL.md) | STRIDE threat model **v2.0** — the current one |
| [security/threat-model.md](security/threat-model.md) | Threat model **v1.0** — ⚠ likely superseded by the top-level v2.0 `THREAT_MODEL.md`; verify before citing |
| [security/architecture.md](security/architecture.md) | Security architecture document (v1.0) |
| [security/pentest-scope.md](security/pentest-scope.md) | Penetration-test scope document |
| [compliance/soc2-control-mapping.md](compliance/soc2-control-mapping.md) | SOC 2 Type II control mapping |

### RFCs ([rfcs/README.md](rfcs/README.md) is the canonical index)

| Doc | What it is |
|---|---|
| [rfcs/0001-multi-tenancy.md](rfcs/0001-multi-tenancy.md) | Multi-tenancy — ⚠ data model **superseded** by RFC 0004 |
| [rfcs/0002-extract-compilation-service.md](rfcs/0002-extract-compilation-service.md) | Extract compilation service (Draft) |
| [rfcs/0003-durable-execution.md](rfcs/0003-durable-execution.md) | Durable workflow execution (Phases 1–2 landed) |
| [rfcs/0004-tenant-equals-organization.md](rfcs/0004-tenant-equals-organization.md) | Tenant = Organization (in progress) |
| [rfcs/0005-tenant-isolation-target-architecture.md](rfcs/0005-tenant-isolation-target-architecture.md) | Tenant-isolation target architecture (staged) |
| [rfcs/0006-org-scoped-write-isolation-pins-org-not-user.md](rfcs/0006-org-scoped-write-isolation-pins-org-not-user.md) | Org-scoped write isolation pins `org_id` (decided 2026-06-08) |
| [rfcs/0007-native-github-integration.md](rfcs/0007-native-github-integration.md) | Native GitHub integration (Phase A complete) |
| [rfcs/0008-github-app-authentication.md](rfcs/0008-github-app-authentication.md) | GitHub App authentication (Draft, Phase B of 0007) |
| [rfcs/0009-migration-baseline-squash.md](rfcs/0009-migration-baseline-squash.md) | Migration baseline squash (Draft) |
| [rfcs/0010-asymmetric-worker-trust-boundary.md](rfcs/0010-asymmetric-worker-trust-boundary.md) | Asymmetric worker-trust boundary (P1–P3 landed) |
| [rfcs/0011-ml-models-as-platform-primitives.md](rfcs/0011-ml-models-as-platform-primitives.md) | ML models as platform primitives (Draft) |

### Workflow engine

| Doc | What it is |
|---|---|
| [workflow-engine/graph-json-schema.md](workflow-engine/graph-json-schema.md) | `graph_json` v0 wire-shape schema (source of the engine's `SCHEMA_DOC`) |
| [workflow-engine/production-stack.md](workflow-engine/production-stack.md) | Assembling a production engine stack (ties the cookbook guides together) |
| [workflow-engine/custom-dispatcher.md](workflow-engine/custom-dispatcher.md) | Implementing a custom `NodeDispatcher` |
| [workflow-engine/workflow-graph-store.md](workflow-engine/workflow-graph-store.md) | Implementing a `WorkflowGraphStore` for sub-workflow loading |
| [workflow-engine/sub-workflow-composition.md](workflow-engine/sub-workflow-composition.md) | Judge / Ensemble / AgentLoop sub-workflow composition |
| [workflow-engine/checkpoint-lifecycle.md](workflow-engine/checkpoint-lifecycle.md) | Checkpoint pause/resume lifecycle |
| [workflow-engine/benchmarking.md](workflow-engine/benchmarking.md) | Criterion scheduler benchmarks + regression detection |

## Historical

Dated audits, one-off test logs, handoffs, and plans that have been executed
(or overtaken by events). Read for context; do not treat as current guidance.

| Doc | What it is |
|---|---|
| [security/review-2026-07-19.md](security/review-2026-07-19.md) | Full-application security review, 2026-07-19 (point-in-time findings) |
| [security/ai-injection-audit-2026-07-20.md](security/ai-injection-audit-2026-07-20.md) | Prompt-injection least-ceiling audit of live workflows, 2026-07-20 |
| [reviews/codebase-review-2026-07-03.md](reviews/codebase-review-2026-07-03.md) | Full-codebase review, 2026-07-03 (follow-ups tracked + burned down) |
| [reviews/security-hardening-followups-2026-07-03.md](reviews/security-hardening-followups-2026-07-03.md) | Companion follow-up tracker to the 2026-07-03 review |
| [functional-audit-2026-06-25.md](functional-audit-2026-06-25.md) | Live end-to-end functional/governance audit, 2026-06-25 |
| [wasm-security-review-2026-05-22.md](wasm-security-review-2026-05-22.md) | WASM sandbox security review, 2026-05-22 |
| [security/agent-memory-encryption-plan.md](security/agent-memory-encryption-plan.md) | `actor_memory` at-rest encryption plan — **COMPLETE** (shipped 2026-04) |
| [engine-builder-refactor-plan.md](engine-builder-refactor-plan.md) | `EngineBuilder::for_workflow` refactor plan (2026-04-28) — ⚠ likely overtaken by the May-2026 workspace decomposition; verify before executing |
| [mcp-test-fixes-handoff.md](mcp-test-fixes-handoff.md) | MCP test-fix handoff notes, 2026-04-20 |
| [gcal-live-test.md](gcal-live-test.md) | One-off Google Calendar live-integration verification log |
| [execution-logging-integration.md](execution-logging-integration.md) | Execution-logging integration guide (2026-02-17) — ⚠ predates the May-2026 decomposition; verify paths before use |
| [workflow-engine/announcements/v0.2.0.md](workflow-engine/announcements/v0.2.0.md) | talos-workflow-engine 0.2.0 release announcement |
