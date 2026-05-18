# MCP Probe Backlog — Open Observations

**Date:** 2026-05-07 (last updated)
**Source:** End-to-end MCP probe session, originally culminating at `83ee094`,
extended through `4cbc9cb`. Captures observations from the session that didn't
rise to "ship a fix" but are worth addressing later.

The fixes that DID ship are tracked in the commit log; this document is the
leftover punch list.

Items are ordered by likely impact. Each entry has: how to reproduce, the actual
behavior, why it's not yet fixed (cost/scope/priority), and a suggested fix shape.

---

## Resolved this session (closed for future readers)

Ten commits closed two original backlog items and surfaced eight new findings,
seven of which shipped fixes; the remaining four (MCP-10, MCP-11, MCP-12, MCP-13)
are documented below, with three new ones (MCP-15, MCP-16, MCP-17) added at the
bottom of P3.

**Closed (originally tracked elsewhere):**
- `8b2c3f3` — security(executions): canonicalized 6 cross-user existence-leak
  sites in `executions.rs` (`get_execution_status`, `cancel_execution`,
  `analyze_execution_failure`, `get_execution_lineage`, `tail_worker_logs`,
  `submit_workflow_approval`, `list_executions`); also bundled the
  `talos-engine/src/rhai_helpers.rs` HTML-entity decode (5 unit tests). The
  decode fix verified live: `daily-brief` synthesize node has stored
  `"retry_condition": "status != 401 &amp;&amp; status != 403 &amp;&amp; status != 400"`
  — pre-fix the safe-default ("retry on any error") was firing because the parse
  failed; post-fix `test_condition` correctly returns `true` for status=500 and
  `false` for status=401.
- `e93befd` — fix(list_workflows): `status='published'` was in the validator's
  allowlist but not in the schema enum; operators following the (also-wrong)
  docstring got silent empty lists. Removed `'published'` from VALID_STATUSES;
  docstring now references migration `20260318000000`.
- `76a81c0` — fix(patterns): `workflow-integration-test.json` was the only
  template across 17 patterns whose `alternatives[].replacements[]` deviated
  from the canonical shape (object `config_delta` instead of string, missing
  `module_name`, non-canonical `description` field, display-name `catalog_name`).
- `6b9a40e` — fix(mcp): `get_module_compatibility` docstring listed 5 worlds
  out of 12 (added missing llm/agent/governance/etc. tier);
  `find_unreferenced_modules` `.clamp(1, 365)` migrated to N-J explicit -32602
  validation.
- `4cbc9cb` — security(workflows): canonicalized 4 more cross-user
  existence-leak sites (`export_yaml_workflow`, `rename_workflow`,
  `swap_node_module`, `get_workflow`). All hit user_id-scoped queries already;
  text alignment only.
- `89f3914` — fix(hygiene + marketplace): two silent-zero bugs surfaced by
  probe. (1) `get_platform_hygiene_report.idle_actors` checked execution
  recency only; mis-flagged memory-holder personas (`aegix-vps` with 11
  memories + 2 wired workflows) as "should terminate" — following the
  recommendation would have destroyed actor memory. Added two NOT EXISTS
  guards (actor_memory + workflows). (2) `get_marketplace_top_modules`
  used `try_get::<i64>` against an INT4 column; decode failed and the
  `.unwrap_or(0)` masked every download count to 0 (probe showed
  total_downloads=3 but every top-5 entry reported 0). Fixed with explicit
  `::bigint` cast in projection + ORDER BY, plus deterministic name ASC
  tie-break.
- `55a75a9` — fix(marketplace): same i32→i64 silent-zero in
  `list_published_modules` (sibling of the `get_marketplace_top_modules`
  fix above). Sweep verified the broader workspace is clean —
  `usage_count` and `max_fuel` are both BIGINT in the modules table.
- `8b13df8` — fix(executions): label-resolve `compare_executions` +
  `get_execution_diff`. Probe of `compare_executions` returned per-node
  entries with raw SHA256-derived UUIDs ("node":
  "03823045-d386-d04b-f60a-70ed2611efd9") and no human-readable
  identifier. Other surfaces (`get_node_failure_breakdown`, `get_node_io`,
  `get_node_execution_history`) got the label resolver in `51a2e65` /
  `7acb619`; these two were missed. Both handlers now add `node_label`
  alongside the existing `node` field — additive, no wire-format break.

**Non-bugs (documented to prevent re-investigation):**
- **`get_schedule_health.stats_24h: 0` for first 24h after a schedule
  provenance-stamping change.** The scheduler's provenance stamp shipped in
  `357d7e4` (2026-05-06); pre-stamp scheduler runs have `provenance->>'trigger_type' IS NULL`
  and don't match the `provenance->>'trigger_type' = 'scheduled'` filter in
  `get_scheduled_24h_execution_stats`. Stats self-populate as new scheduled runs
  fire on the new code. Verified by inspecting today's `daily-brief` execution
  via `get_execution_lineage` (`trigger_type: "manual"` because that exec
  predated the deploy at 16:26 UTC).

---

## P2 — UX / observer surface

### MCP-1: ~~`validate_workflow` and `get_all_readiness_scores` disagree~~ — closed in `d5b963c`

**Status:** Closed `d5b963c`. Root cause: each surface had its own inlined
formula, and they drifted. Pre-fix:
| Component | validate_workflow | get_readiness_breakdown |
|---|---|---|
| Reliability | max 40, saturates at 100 runs | max 50, saturates at 10 runs |
| Documentation | max 30 (10/10/10) | max 20 (10/5/5) |
| Freshness | max 20 | max 20 |
| Risk | max 10 | max 10 |

Both formulas now go through pure helpers in `talos-analytics-repository`
(`compute_reliability_score`, `compute_documentation_score`,
`compute_freshness_score`, `compute_risk_score`). 8 unit tests pin the
formulas including a regression test named after the original MCP-1 daily-brief
observation (7 perfect runs → 35.0 reliability).

---

### MCP-2 / MCP-17: ~~`get_workflow_quickstart.ready_to_run` and `session_start.unconfigured_node_count` disagree~~ — closed

**Status:** Closed. Both surfaces are intentionally kept on distinct
cost models (session_start: cheap data-presence batch over 5 drafts;
quickstart: strict per-schema required-fields plus per-secret check
on a single workflow), but the divergence is now visible to operators:

- session_start per-draft entries now carry
  `"unconfigured_check_mode": "data_presence_only"`.
- get_workflow_quickstart now carries
  `"ready_check_mode": "schema_required_fields_and_secrets"`.
- Both tool descriptions cross-reference each other so the
  divergence surfaces in the schema discovery output (no operator
  has to read the docs to find the modes).
- The cheap predicate is extracted as `count_nodes_with_empty_data`
  (pure helper on `&[serde_json::Value]`); both `session_start` and
  `is_substantive_workflow` route through it. 6 unit tests pin
  the contract including the documented divergence case (a node
  with no schema-required fields and empty data: quickstart=ready,
  session_start=1 unconfigured — both correct in their own mode).

A truly-shared "strict" predicate would require session_start to
do per-draft template lookups (5 drafts × ~5 modules each). The
labeling approach is the right cost/benefit trade.

---

### MCP-3: ~~`get_module_history` shows no-op entries~~ — closed in `e6e0f05`

**Status:** Closed `e6e0f05`. `get_module_history` now stamps
`unchanged: true` on entries where `previous_hash == new_hash`, additive
to the existing fields. Write-time dedup intentionally NOT applied —
hot_update is a legitimate "fresh audit row even when bytes match" op
in some flows. Same commit also fixed the empty-case to return `[]`
instead of the bare string "No update history found for this module."

---

### MCP-4: `get_workflow_sla_report` doesn't warn on noisy sample sizes

**Repro:**
```
get_workflow_sla_report(workflow_id: <daily-brief>, days: 30)
# 13 executions over 30 days, default target_success_rate=99.0
# → success_rate.met=false because 76.92 < 99.0
```

**Actual:** Returns a clean failure verdict against the 99% default target. With 13
samples, a single failure is 7.7% — 99% is statistically unmeetable in this regime.

**Why:** Defaults are tuned for high-traffic workflows; low-traffic ones produce
"failing SLA" verdicts that aren't actionable.

**Fix shape:** Add a `sample_size_warning` field when `total_executions < 100` (or
similar threshold) so callers know the verdict is statistically noisy. Optionally
suggest a reasonable target based on observed traffic.

---

### MCP-5: ~~`search_workflows_semantic` echoes `min_score_applied` per result~~ — closed in `d79c82c`

**Status:** Closed `d79c82c`. Per-row `min_score_applied` removed from
`SemanticSearchRow`; envelope-level field is the single source of truth.
For 1000-result calls that's 1000 redundant copies eliminated. Per-row
`match_method` preserved because the fallback chain CAN return a mix
(vector + trigram rows). 2 unit tests updated to assert per-row absence
+ envelope presence.

---

### MCP-10: ~~Silent-clamp pattern survives across analytics/secrets/schedules handlers~~ — closed in `cc80514`

**Status:** Closed `cc80514`. Three shared validators added to
`talos-mcp-handlers/src/utils.rs` (`validate_range_i64`,
`validate_range_u64`, `validate_range_f64`); ~30 user-input clamp
sites across 14 handler files migrated to the N-J pattern. Out-of-
range typos now return `-32602` with `"Invalid 'days' value 1000:
must be in [1, 90]"` instead of silently coercing. Internal
arithmetic clamps (chart layout, score computation, fuel rounding,
env-var defaults) intentionally left as-is — they aren't user
input. The f64 variant rejects NaN/Inf which the old
`.clamp()` propagated silently.

---

### MCP-11: ~~HTML-encoded Rhai expressions are stored as-is in `graph_json`~~ — closed

**Status:** Closed. Two-tier fix shipped:

1. **Shared crate.** `decode_html_entities` lifted from
   `talos-engine/src/rhai_helpers.rs` into `talos-text-util` (the one
   place every consumer agrees on). Engine-side now delegates. Plus
   a new helper `decode_rhai_in_graph(&mut Value) -> usize` that
   walks a parsed `graph_json` and decodes every Rhai-expression
   field (top-level + nested `data` + edge `condition`). Field set
   exposed as `RHAI_EXPRESSION_FIELDS` const so the migration and
   the runtime decoder can never drift. 9 unit tests on
   `decode_rhai_in_graph` (top-level/data/edge/idempotent/non-Rhai-passthrough/etc).

2. **Write-time decode at the persistence bottleneck.** Every MCP
   handler that mutates `graph_json` flows through
   `save_graph_json` / `save_graph_json_unchecked` in
   `talos-mcp-handlers/src/graph.rs`. Both now route through
   `canonicalise_rhai_in_graph_json(&str) -> Cow<str>` which
   parses, calls `decode_rhai_in_graph`, and re-serialises only
   when something changed (allocation-free fast path when the
   input is already canonical). 3 unit tests pin the fast path,
   the decode-on-encoded-input path, and the invalid-JSON
   passthrough. Covers `update_node_config`, `add_node_to_workflow`,
   `add_skip_condition`, `add_synthesize_node`, every system-node
   setter, `update_node_positions`, `remove_node`, etc. — none of
   them needed a per-handler change.

3. **One-shot data migration.**
   `migrations/20260507100000_decode_html_entities_in_rhai_fields.sql`
   walks `workflows.graph_json` (TEXT) and
   `workflow_versions.graph_json` (JSONB) using PL/pgSQL helpers
   that mirror `talos_text_util::decode_rhai_in_graph` field-for-field.
   Per-row error isolation via nested `BEGIN/EXCEPTION` blocks so one
   malformed graph_json doesn't abort the batch. Cheap pre-filter
   (`graph_json LIKE '%&%'`) skips rows with no ampersand at all,
   so the migration is O(rows-with-`&`) not O(all-rows). Risk per
   the original backlog item (literal `&amp;` inside a
   string-literal Rhai context) is bounded — only the canonical
   Rhai-expression key set is rewritten, never arbitrary
   description / name strings.

---

### MCP-12: `export_yaml_workflow` emits verbose `null` fields

**Repro:**
```
export_yaml_workflow(workflow_id: <daily-brief>)
# Each node entry includes capability_world: null, rust_code: null,
# js_code: null, python_code: null, node_type: null, skip_condition: null,
# version: null. Each edge: condition: null, type: null. settings:
# execution_timeout_secs: null, priority: null, concurrency_limit: null.
```

**Actual:** Half the YAML body is `field: null` lines. Operators reading the
export to understand the workflow have to mentally filter the noise. Also makes
diffs across exports noisier than they need to be.

**Why:** The serializer uses default `serde_yaml` settings without
`#[serde(skip_serializing_if = "Option::is_none")]` on the optional fields.

**Fix shape:** Add `#[serde(skip_serializing_if = "Option::is_none")]` to the
`Option<T>` fields on the YAML export structs (in `talos-mcp-handlers/src/workflows.rs`
and the workflow-engine YAML types). For round-trip safety, verify that
`import_yaml_workflow` accepts both the omitted and explicit-null forms.

**Bonus:** YAML export embeds module IDs as UUIDs (`module: 32d060ef-...`),
which aren't portable across instances. Adding `module_name` alongside
(`module: 32d060ef-...` / `module_name: compute-context-v1`) would make the
YAML usable as a "share this workflow" artifact. Out of scope for the null-field
cleanup but related.

---

### MCP-13: `list_module_catalog` dual-emits `requires_secrets` AND `required_secrets`

**Repro:**
```
list_module_catalog(installed_only: true)
# Each module entry has BOTH:
#   "requires_secrets": [...],
#   "required_secrets": [...]   # same value
```

**Actual:** Two response fields with the same value, on every module entry,
in a paginated list response. Bandwidth + reader confusion.

**Why:** Backwards-compat shim at `talos-mcp-handlers/src/modules.rs:2172,2175`.
The template files use `requires_secrets`; the canonical API name everywhere
else (`workflows.rs`, `talos-workflow-creation-helpers`, GraphQL) is
`required_secrets`. The dual-emit was added so old MCP clients reading either
name still work.

**Fix shape:** Risk-balanced — pick one of:
1. Drop `requires_secrets` from the response (operators have to follow the
   docstring, which already says `required_secrets`). Wire-format break for
   any client that only reads `requires_secrets`.
2. Drop `required_secrets`, keep `requires_secrets` (since template files
   already use that name; aligns the read API with the storage). Wire-format
   break for clients reading `required_secrets`.
3. Keep both, document the duplication explicitly in the docstring with a
   "deprecated, use X" note on whichever name is being phased out.

Recommend (1) — `required_secrets` is the canonical name everywhere else in
the system; consolidating brings the catalog response into line.

---

## P3 — Polish / consistency

### MCP-6: ~~`list_actors[].last_active: null` reads as "broken" instead of "never used"~~ — closed in `d6acdb7`

**Status:** Closed `d6acdb7`. Both `list_actors` and
`get_platform_hygiene_report.idle_actors[]` now emit a sibling
`last_active_label` field that's always a string — either the RFC3339
timestamp or the literal `"never"`. The raw `last_active` Option is
preserved for programmatic null-check, so callers reading either field
work without changes. Ops dashboards render the label without
type-testing.

---

### MCP-7: ~~`get_recent_alerts_summary` could dedupe near-identical fingerprints~~ — closed

**Status:** Closed. `get_recent_alerts_summary` now emits both the literal
`alerts` array AND a `groups` rollup that collapses by
`fingerprint_error_message` — the same helper used by `get_workflow_stats`
and `get_error_report`. Each group surfaces:
`fingerprint`, `first_message` (literal preview), `workflow_names`
(BTreeSet — alphabetised, deduped), `alert_count` (distinct messages),
`occurrence_count` (sum across the group), `last_occurred_at` (max),
`fully_acknowledged` (every alert in the group is acked). Sort is
descending by `occurrence_count` (most-impactful first). 5 unit
tests cover dedup, partial-acknowledgement, distinct-workflow
aggregation, empty-input, and sort order. Wire format is additive
— callers reading only `alerts` are unaffected.

---

### MCP-8: ~~`search_workflows_semantic` misses obvious matches at default threshold~~ — closed (documentation)

**Status:** Closed as documentation-only. This is an
embedding-quality observation, not a code bug — the
default `min_score=0.40` is calibrated for nomic-embed-text's
score distribution. The proposed "exhaustive mode" feature is
already available: pass `min_score=0.0` per request to get the
top-N ranked-by-cosine list with no threshold filter (caller
filters themselves). The schema description for `search_workflows_semantic`
now spells this out explicitly:

> "...lower to see best-effort results for unfamiliar queries —
> pass min_score=0.0 for exhaustive ranked-by-score output
> (caller filters themselves). The applied threshold is echoed in
> the response envelope as min_score_applied."

If the team migrates embedding providers or wants to re-tune the
default, the existing `SEMANTIC_SEARCH_MIN_SCORE` env var is the
single dial.

---

### MCP-9: `validate_workflow_input` field semantics inversion

**Status:** Already shipped in `5ff8366` but documenting here for future-readers
who may see the new shape and want context.

The pre-fix shape returned `valid: true` for schema-less workflows, which would
forward unvalidated input through any defensive `if (response.valid)` gate. The
post-fix shape returns `valid: false, unvalidated: true, schema_present: false`
so callers wanting to opt into schema-less acceptance must explicitly check
`unvalidated === true`.

**Open question:** Are there any internal callers that depend on the OLD `valid:
true` shape? `git grep` shows no callers in this repo, but third-party MCP clients
following the previous docstring might break. Worth a heads-up note in release
notes if/when the platform formally publishes a v2 MCP wire format.

---

### MCP-15: Same-actor LLM workflows hit the synthetic-output recall trap

**Repro:**
```
preview_actor_context(actor_id: <aegix-ceo>, max_memories: 5)
# Returns 5 memories, ALL of which are daily_brief/<date> entries from
# the past week. The aegix-ceo actor has 19 memories total but the most
# recent are all the briefs the daily-brief workflow itself wrote.
```

**Actual:** The daily-brief workflow's `compute-context` node calls a generic
`agent_memory::search`. Because the workflow persists each day's brief into the
SAME actor's memory, the next day's run reads its own prior outputs as
"context." The brief content shows the recursion explicitly: "Every brief since
2026-04-30 has named this blocker; nothing in memory shows it moved." The LLM
is citing itself as a source of truth.

**Why:** This is the failure mode CLAUDE.md's "metadata.kind for synthetic
outputs" rule is designed to prevent. The convention exists
(`metadata.kind: daily_brief` IS being stamped on the persisted briefs), but
the read path doesn't filter by it. `talos_memory::recall_semantic_filtered`
+ `agent_memory::search_filtered(exclude_kinds: [...])` are wired through the
DB layer (see CLAUDE.md "metadata.kind convention") but the workflow's
compute-context node uses bare `search`.

**Fix shape:** Three layers, partially shipped:
1. **Discoverability (shipped `1ab5d83`):** `describe_capability_world(agent-node)`
   now documents `search-filtered(query, options)` alongside `search(query,
   limit)`. The example shows the self-recall guard pattern inline, so
   workflow authors see the recommended approach at the right discovery point.
2. **Workflow-level fix (operator action, NOT platform):** the
   `compute-context-v1` module config for `daily-brief` should call
   `agent_memory::search_filtered(SearchOptions { exclude_kinds: ["daily_brief"], ... })`
   instead of bare `agent_memory::search`. The platform side (WIT,
   host_impl, talos_memory::recall_semantic_filtered) is already wired —
   the workflow's compute-context module just doesn't use it yet.
3. **Platform-level safety net (still pending):** auto-detect the case in
   `preview_actor_context` and warn when the rendered payload is dominated
   by a single `metadata.kind` (>50% of memories share one kind) — a strong
   signal of self-recall pollution. Not shipped; would be a small additive
   `warnings: ["self-recall: 5/5 memories carry kind='daily_brief'..."]`
   field on the response.

---

### MCP-16: `get_workflow_input_schema` docstring overstates analysis scope

**Repro:**
```
get_workflow_input_schema(workflow_id: <daily-brief>)
# response: based_on_executions: 2
# But daily-brief has 13 successful executions.
```

**Actual:** The docstring says "analyzing the last 10 successful executions'
trigger input data." For daily-brief (13 successful executions), only 2 were
analyzed. The unmentioned filter: `WHERE input_data IS NOT NULL`. Scheduled
runs have NULL input (no trigger payload), so only manual `test_workflow`
runs feed the inference.

**Why:** Reasonable behavior — inferring a schema from `null` doesn't help —
but the docstring sets up the wrong expectation, so operators get confused
when `based_on_executions` is much smaller than `succeeded` count from
`get_workflow_summary`.

**Fix shape:** Update the docstring to clarify:
> Infers a JSON schema from the last 10 successful executions **with non-null
> input_data**. Scheduled runs (which have no trigger payload) are excluded;
> only `test_workflow`, `trigger_workflow`, and webhook-triggered runs feed
> the inference.

Bonus: surface the filter in the response too, e.g.
`based_on_executions: 2, total_successful_executions: 13, no_input_count: 11`
so the gap is self-explanatory.

---

### MCP-17: ~~`get_workflow_quickstart` and `session_start` still disagree (MCP-2 still live)~~ — closed (see MCP-2)

**Status:** Closed. Bundled with MCP-2 above — both surfaces now
self-label their readiness check mode (`unconfigured_check_mode` /
`ready_check_mode`) and cross-reference each other in their tool
descriptions so the divergence is visible at discovery time. The
cheap predicate is shared (`count_nodes_with_empty_data`); the
strict per-schema predicate stays in quickstart only because the
DB cost is per-workflow and session_start runs in batch.

---

### MCP-19: ~~Percentage fields are inconsistent — strings in 5 places, numbers in 1~~ — closed in `37b6c6f`

**Status:** Closed `37b6c6f`. Extracted `talos_analytics_repository::format_percent(f64) -> f64`
that rounds to 1 decimal place. All 5 string-formatted call sites
(`success_rate_percent`, `failure_rate_percent`, `rolling_success_rate_pct`,
`utilization_p95_pct`, `sla_report.success_rate.actual`) now route through
it. Bonus: `get_execution_cost.avg_node_time_ms` / `compute_units` were
also format!-strings (different fields, same problem) — switched to a
2-decimal inline `round_2dp` helper. 2 unit tests pin the rounding +
non-finite handling.

---

### MCP-18: `compare_executions` surfaces synthetic engine-internal trace nodes

**Repro:**
```
compare_executions(execution_id_a: <run-A>, execution_id_b: <run-B>)
# Among the real workflow nodes ("compute-context", "synthesize"), the
# response includes 2 extra entries:
#   { "node": "e3cd9682-...", "node_label": null,
#     "comparison": "only_in_b", "value_a": null, "value_b": {} }
#   { "node": "f05e567f-...", "node_label": null,
#     "comparison": "only_in_a", "value_a": {}, "value_b": null }
```

**Actual:** Each compare/diff response carries 2 extra entries beyond the
workflow's real nodes — synthetic engine-internal trace artifacts that
get assigned a different per-execution UUID and resolve to no graph label.
Their values are always `{}` so they contribute zero diff signal but add
noise that confuses operators reading the comparison.

**Why:** Surfaced visibly only after `8b13df8` added `node_label` resolution
(pre-fix everything was raw UUIDs so the synthetic nodes blended in).
Now that real nodes resolve to readable labels, the unresolved trace UUIDs
stand out. Likely an engine trace placeholder ("__trigger__" or per-run
synthetic node) that gets recorded into `output_data` but isn't part of
the workflow graph — so `build_node_label_map` legitimately returns None.

**Fix shape:** Two options:
1. **Filter at the handler:** in both `compare_executions` and
   `get_execution_diff`, skip entries where `node_label is None && both
   values are empty objects {}` (or both null). That's an unambiguous
   "synthetic placeholder, no signal" — no operator-facing diff loss.
2. **Skip at the source:** stop writing these zero-payload synthetic
   entries into `output_data` from the engine. Cleaner long-term but a
   wider blast radius (other consumers may rely on the placeholder).

Option 1 is the pragmatic choice — same handler, tiny filter, observable
fix in the next probe response.

---

## P-N — Out of scope, environment-driven

### ENV-1: `security_audit` warns on `JWT_ALGORITHM=HS256`

Recommendation is RS256/ES256 for microservice deployments. Operator decision —
key-rollout, public-key infrastructure, downstream consumer migration. Not a
code fix.

### ENV-2: `get_agent_card` placeholder behavior is now safe but `TALOS_BASE_URL` should be set

After `51e2335`, calling `get_agent_card` without `TALOS_BASE_URL` (or `base_url`
arg) returns `shareable: false` with a setup hint. To unlock the documented
"share endpoint_url with another A2A agent" workflow, the controller env needs
`TALOS_BASE_URL` set or callers need to pass `base_url:` explicitly each time.
Operator action, not a code fix.

### ENV-3: Marketplace has 1 module published

`get_marketplace_stats.total_listings: 59` (catalog templates) but
`list_published_modules` shows only 1 (`Constitutional Refinement`) with
`downloads: 0, star_count: 0`. Healthy state for a freshly-deployed instance —
documenting so future sessions don't mistake this for a regression.

---

## Verified-clean surfaces (probed, no issues found)

For future probe sessions, these surfaces returned correct data and don't need
re-probing unless the underlying code changes:

- `validate_workflow`, `validate_all_workflows`
- `test_condition` (Rhai sandbox correctly rejects `eval()` etc.)
- `actor_recall` (3-state response: never_set / expired / found)
- `actor_recall_semantic` (vector_cosine working post-r306 vault wiring)
- `actor_recall_hyde` (post-`29bf493` distinguishes no-embedding vs no-match)
- `describe_capability_world`, `get_my_capability_ceiling`
- `get_execution_cost` (post-`d3cf29a` event-fallback)
- `get_execution_waterfall`, `get_execution_timeline`
- `get_execution_lineage`, `get_execution_replay_chain`
- `tail_worker_logs` (structured per-node)
- `get_module_dependents`, `get_module_compatibility` (post-`83ee094`)
- `find_module_alternatives`, `find_unreferenced_modules`, `find_similar_workflows`
- `list_modules`, `list_module_catalog`, `list_published_modules`,
  `search_marketplace`, `list_workflow_patterns`
- `check_semantic_cache`
- `get_secret_access_log` (admin-RBAC enforced)
- `get_webhook_security_stats` (admin-IP-list-hidden enforced)
- `list_secret_usage` (post-`290c7fc` host_consumers)
- `get_module_info` (post-`34297cd` host_managed_access)
- `validate_workflow_input` (post-`5ff8366` valid-on-no-schema fix)
- `list_workflow_triggers`, `list_schedules`, `list_webhooks`, `list_actors`,
  `list_actor_approval_policies`, `list_pinned_executions`,
  `list_archived_executions`, `get_archive_policy`, `get_queue_status`
- `get_workflow_topology`, `get_workflow_dependency_map`,
  `get_workflow_call_tree`, `get_workflow_dependencies`,
  `get_workflow_risk_assessment`, `get_workflow_audit_trail`,
  `get_workflow_changelog`, `get_workflow_health` (post-`a42fdf2`),
  `get_workflow_summary`, `get_workflow_quickstart`, `get_workflow_input_schema`,
  `get_workflow_raw_json`, `get_workflow_sla_report` (post-`5bd588d`),
  `get_workflow_performance_report` (post-`5bd588d`), `get_workflow_stats`,
  `get_all_workflow_stats`, `get_all_readiness_scores` (post-`af1ac30`),
  `get_workflow_reuse_stats`, `get_workflow_dependency_map`
- `get_node_failure_breakdown` (label-resolved correctly post-`51a2e65`)
- `get_node_io` (post-`7acb619` UUID-key lookup)
- `get_node_execution_history` (post-`51a2e65` label resolver)
- `analyze_execution_failure` (post-`4d223b1` OUTPUT_SCHEMA classifier)
- `compare_executions`, `get_execution_diff` (post-`51a2e65` payload caps)
- `get_few_shot_examples`, `preview_actor_context`, `get_actor_summary`,
  `get_actor_action_log`, `get_actor_budget`, `graph_stats` (post-`f73ff72`),
  `get_agent_card` (post-`51e2335`)
- `suggest_actor_for_task`, `suggest_capabilities`, `suggest_retry_config`
  (post-`cb9fba3` deterministic-failure classifier)
- `security_audit`, `check_secret_health`, `list_secrets`,
  `list_secret_namespaces`, `list_expiring_secrets`, `get_unused_secrets`,
  `get_module_rate_limit`, `list_workflow_sla_thresholds`
- `get_health_dashboard`, `get_daily_digest`, `get_recent_alerts_summary`,
  `list_alerts`, `get_error_report` (post-`9be62dd` fingerprint dedup),
  `get_fuel_usage_report`, `get_module_unification_status`,
  `get_marketplace_stats`, `get_session_context`, `get_platform_info`,
  `get_platform_hygiene_report`, `get_system_status`
