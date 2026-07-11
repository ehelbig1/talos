# RFC 0011 — Models as first-class platform primitives

**Status:** Draft
**Author:** Platform
**Date:** 2026-07-11

## Motivation

Every AI decision in a Talos workflow today is an LLM call. That is the
right tool for zero-shot reasoning and the wrong tool for the steady
state: the inbox organizer classifies ~15 emails per run at ~7s and
~12M fuel through qwen3.6 when the underlying task — after a few
thousand labeled examples exist — is a three-class text classification
that classical architectures solve in microseconds at higher
reliability.

The immediate driver is the **hybrid distillation pattern**: use an LLM
to bootstrap a labeled dataset (zero-shot reasoning up front), review
it, train a fast local model on it, and swap the LLM out of the
production path — keeping it only as a low-confidence fallback whose
answers grow the dataset (active learning). But the platform gap is
more general. There is no way to:

- train **any** model in or alongside a workflow (classical ML,
  fine-tuned encoders, deep learning, tabular ML,
  statistical/sequential models);
- version, evaluate, and promote a trained model as a governed
  artifact;
- call a trained model from workflow nodes with the same ergonomics as
  `llm::complete`.

This RFC makes **datasets** and **models** first-class platform
objects — registered, versioned, evaluated, tenant-isolated — and adds
a uniform inference surface so any workflow node can consume any
architecture. The email classifier is the first consumer, not the
feature.

## Design overview

Four new nouns, one new WIT interface, one new crate.

```
Dataset ──> Trainer (per backend) ──> ModelVersion (artifact + metrics)
   ^                                        │
   │  active learning / corrections        promote
   │                                        v
Workflow node ──> model::predict ──> Model (name → production version)
        └─ low confidence ──> llm fallback ──> append to Dataset
```

### 1. Datasets (`ml_datasets`, `ml_examples`)

A dataset is a named, schema'd, org-scoped collection of examples.

```sql
ml_datasets: id, org_id, user_id, name (unique per org), task_type,
             schema_json, created_at, updated_at
ml_examples: id, dataset_id, features_enc (per-org AEAD v4 — examples
             built from email/user content are as sensitive as
             actor_memory), label_json, embedding vector(768) NULL,
             source text ('llm_bootstrap'|'correction'|'llm_fallback'|
             'import'|'synthetic'), split text NULL ('train'|'holdout'),
             example_key text NULL (dedupe/upsert key, e.g. gmail msg
             id), created_at
```

Embeddings are computed at append time by the existing
`talos_memory::embedding` pipeline (local nomic, LRU + herd-dedupe) for
text-feature datasets; NULL for tabular/sequential datasets. Writers:
MCP (`append_examples`), workflows (a `dataset-append` module), the
active-learning hook. This retires the interim "classifier actor whose
semantic memory is the dataset" design — datasets are platform tables,
not actor-memory tenants, so they get real schemas, splits, dedupe
keys, and bulk operations without straining recall semantics.

**Growth is bounded by policy, not by hope.** Active learning appends on
every low-confidence prediction, forever; unbounded datasets bloat the
vector index and eval cost (the cap-resource-consumption rule).
`ml_datasets.schema_json` carries a `max_examples` policy (P1b default
50k) enforced at append time: over the cap, eviction removes oldest
`llm_bootstrap`/`llm_fallback` rows first — `correction` rows are
pinned (human labels are the dataset's most valuable asset).

**Deletion lifecycle.** Deleting a dataset that a PROMOTED model version
depends on is refused (the dataset IS a lazy backend's artifact —
deleting it would silently lobotomize the model into 100% LLM
fallback). Retire or re-point the model first. A model whose
`dataset_id` is NULL serves `not-available` from `predict` (a loud,
distinct error), never a silent abstain-and-fallback.

### 2. Model registry (`ml_models`, `ml_model_versions`)

```sql
ml_models:  id, org_id, user_id, name (unique per org), task_type
            ('classification'|'regression'|'forecasting'|'ranking'),
            dataset_id, production_version_id NULL, config_json
            (backend-specific: k, confidence_threshold, fallback…)
ml_model_versions: id, model_id, version int, backend text,
            artifact bytea NULL, artifact_sha256 text NULL,
            metrics_json (per-class P/R/F1, latency, eval dataset
            fingerprint), trained_at, status
            ('trained'|'promoted'|'retired')
```

A model NAME is what workflows reference; the registry maps it to the
**promoted version**. Names are unique only PER SCOPE (personal / each
org), so resolution precedence is deterministic and personal-first
(`ORDER BY (org_id IS NULL) DESC, org_id`): an org member creating a
same-named org model cannot shadow a caller's own model, and repeated
calls always resolve the same row. Promotion is explicit (`promote_model`), gated on
eval metrics, and auditable. Artifacts are content-addressed
(sha256 verified on every load — same posture as OCI WASM digests).

### 3. Backend taxonomy (the pluggable part)

| backend | covers | artifact | trainer |
|---|---|---|---|
| `llm` | zero/few-shot prompting; also the TRAINER for distillation | none (prompt in config) | n/a |
| `knn-pgvector` | lazy/instance-based; hybrid distillation default | none (dataset+embeddings ARE the model) | n/a (index maintenance only) |
| `classical` | linear/logistic, trees, naive bayes, tabular ML | serialized params or ONNX | Tier A (in-platform Rust: linfa/smartcore) |
| `statistical` | EWMA/ARIMA-class, HMM, sequential scoring | params JSON | Tier A |
| `onnx` | **the universal escape hatch**: fine-tuned encoders (BERT-class), deep learning, anything trained anywhere that exports ONNX | .onnx bytes | Tier B (containerized job) or external import |

The `onnx` backend is what makes "support multiple architectures" a
closed problem instead of an open-ended one: any framework that exports
ONNX is served by ONE embedded runtime (`tract` — pure Rust, no Python,
no network at inference). New architectures usually mean a new
*trainer*, not a new *serving path*.

### 4. Training executors

- **Tier A — in-platform (controller crate `talos-ml`)**: classical +
  statistical training on datasets up to ~100k examples. Rust
  (linfa/smartcore), resource-capped (time + memory), runs as a job in
  the controller (same operational shape as embedding backfills). No
  new infrastructure.
- **Tier B — containerized training jobs**: Python-ecosystem training
  (fine-tuned encoders, deep learning) in a sandboxed container,
  reusing the compilation-service container invariants (rootless,
  `--network=none` after dependency fetch, resource caps, fail-closed
  in production without a runtime). Output contract: an ONNX artifact
  + metrics JSON. Phase 3; the interface (`train_model` returns a job,
  artifacts land in the registry) is fixed in Phase 1 so Tier B slots
  in without API changes.
- **Tier C — LLM-as-trainer (workflow composition)**: bootstrap
  labeling, distillation loops, active learning. Not an executor at
  all — ordinary workflows writing to datasets. Ships first.

### 5. Inference surface

New WIT interface, mirroring `llm`'s ergonomics:

```wit
interface model {
    record prediction {
        /// JSON: label/score/vector per task_type
        output: string,
        confidence: option<f32>,
        model-version: u32,
        /// backend that served it (observability + fallback logic)
        backend: string,
    }
    enum error { not-found, not-promoted, invalid-input,
                 artifact-corrupt, not-available }
    predict: func(model: string, input: string)
        -> result<prediction, error>;
    predict-batch: func(model: string, inputs: list<string>)
        -> result<list<prediction>, error>;
}
```

Host-side execution in the worker:
- `knn-pgvector` → signed NATS-RPC to the controller (same
  trust-boundary pattern as `talos.memory.op`; worker stays
  credential-free) — embed query locally, vector search, majority vote,
  margin as confidence.
- `classical`/`statistical`/`onnx` → **local in-worker inference**:
  artifact fetched once from the registry (sha256-verified, cached),
  executed via tract / native param evaluation. No egress at all.

Because inference is host-local (or controller-RPC), `model::predict`
is **Tier-1-clean by construction**: an actor pinned tier-1 can use any
trained model. This resolves the tier-vs-fetch conflict from the
interim design — the privacy boundary lives at the inference surface,
not on the actor that happens to host a dataset.

Node-level access: `capability_world` gains `model` in the same worlds
that carry `llm` (llm-node and above), plus a catalog module
(`Model_Predict`) so no-code workflows consume models without custom
Rust.

### 6. Eval harness (the backend selector)

`eval_model(model, backends[], holdout_fraction)`: stratified split,
run every candidate backend **plus the llm baseline** on the holdout,
persist per-class precision/recall/F1 + p50/p95 latency into
`metrics_json`. Promotion policy is explicit config: e.g. "promote iff
accuracy ≥ baseline − 1pt AND p95 < 100ms". The backend is chosen per
problem by measurement — the platform doesn't privilege an
architecture. (This automates the manual model bake-off pattern already
proven twice on the inbox classifier.)

### 7. Lifecycle MCP surface

`create_dataset`, `append_examples`, `dataset_stats`, `sample_examples`
(review/spot-check), `create_model`, `train_model`, `eval_model`,
`promote_model`, `list_models`, `get_model_card` (metrics + provenance:
which LLM/prompt labeled the data, correction counts). Writes are
org-scoped txs (lint checks 25/42 discipline); GraphQL surface can
follow via the cross-protocol service pattern.

## The hybrid distillation pattern, expressed on this substrate

1. **Bootstrap**: workflow pages history → LLM (`PROVIDER: ollama`)
   labels batches → `dataset-append` module writes examples
   (`source='llm_bootstrap'`).
2. **Review**: `sample_examples` digest for spot-checks; the
   organizer's existing correction harvest appends
   `source='correction'` examples that supersede bootstrap rows with
   the same `example_key`.
3. **Train/select**: `eval_model` runs `knn-pgvector` + `classical`
   + llm baseline; winner promoted if it clears the gate (inbox gate:
   ≥ the 95.8% few-shot LLM baseline).
4. **Deploy**: classify node swaps to `Model_Predict`; confidence
   below threshold → llm fallback → answer appended
   (`source='llm_fallback'`) → periodic re-eval/promote closes the
   loop.

Steady state: ~20ms/email locally instead of ~7s/batch, LLM invoked
only on genuinely ambiguous items, and the model improves from every
correction without a manual retrain step (knn) or with a scheduled one
(parametric backends).

## Security & tenancy

- **Example content is encrypted at rest** (per-org AEAD v4, same
  rationale as `actor_memory`: email-derived features are user
  content). Embeddings stored plaintext-vector (same posture as
  `actor_memory.embedding` today).
- **RLS org-scoping** on all four tables (RFC 0004/0005 discipline);
  creates go through org-scoped txs.
- **Artifact integrity**: sha256 pinned at train time, verified on
  every worker load (registry-poisoning defense, mirrors OCI digest
  verification). Tier B containers follow compilation-service sandbox
  invariants.
- **No new egress**: training Tier A/C and all inference are
  in-platform; Tier B containers get network only during dependency
  install, never with dataset mounted (datasets stream in read-only
  after network drop).
- **Dataset-derived LLM calls are locality-pinned.** "No new egress"
  must hold for the LLM legs too: the eval baseline and the production
  fallback both feed DECRYPTED example content to an LLM, and eval runs
  as a controller job with no owning actor — so `max_llm_tier` never
  applies (the PR #461 unbound-principal gap, one layer up). Guard:
  `config_json.fallback.provider` and the eval-baseline provider are
  validated against LOCAL providers (`ollama`) by default; configuring
  an external provider for either requires an explicit
  `allow_external_llm: true` on the model config, is refused for
  datasets whose owning workflow/actor is tier-1-pinned, and is
  audit-logged at WARN on every eval/fallback invocation.
- **Model cards** record provenance (labeler model + prompt hash,
  source mix, eval fingerprint) — auditability for "why did the model
  say X".

## Phasing

- **P1 (ship the pattern)**: `ml_datasets`/`ml_examples`/`ml_models`/
  `ml_model_versions` migrations; `talos-ml` crate (dataset service +
  registry + knn-pgvector + llm backends + eval harness); MCP surface;
  `dataset-append` + `Model_Predict` catalog modules (predict via
  controller RPC — WIT host fn deferred to P2 so P1 needs no
  worker/WIT change); inbox classifier end-to-end on it.
- **P2 (native inference)**: WIT `model` interface + worker host fn,
  tract-embedded ONNX + classical param evaluation in-worker, Tier A
  trainers (linfa linear/trees + statistical), `predict-batch`,
  capability-world wiring + lint coverage. **Gate: the knn predict RPC
  (`talos.ml.predict`) is a new signed-RPC primitive — walk
  `docs/platform-primitive-checklist.md` end-to-end before building it
  (pattern-copying `memory_rpc` is NOT a substitute: zombie semaphore
  permits, verify-once discipline, canonical bytes, and shutdown
  orphaning all bite here).**
- **P3 (heavy training + ops)**: Tier B containerized training (ONNX
  out), artifact signing (cosign, mirroring template publishing), drift
  monitoring (rolling agreement between fast path and sampled LLM
  audits), scheduled re-train/re-eval, GraphQL surface.

## Alternatives considered

- **Dataset-as-actor-memory (interim design, superseded here)**: reuses
  recall plumbing but abuses semantics — no schema/splits/bulk ops,
  entangles dataset tenancy with actor tier ceilings (the tier-1 actor
  couldn't even fetch the mail it was classifying), and recall
  filtering carries a poisoning-risk burden that a dedicated table
  simply doesn't have.
- **Per-architecture serving paths** (a BERT service, a sklearn
  service, …): unbounded maintenance; rejected in favor of ONNX as the
  universal serving contract with tract embedded in the worker.
- **External MLOps platform** (MLflow et al.): violates the
  local-first/tier-1 posture, adds an unmanaged trust boundary, and
  duplicates governance Talos already has (registry, RLS, audit,
  artifact verification).

## Prior art in-repo

`inbox_classifier_model_ab` (manual bake-offs this automates),
`talos_memory::embedding` (reused wholesale), compilation-service
container invariants (Tier B template), OCI digest + signing posture
(artifact integrity), RFC 0004/0005 tenancy discipline.
