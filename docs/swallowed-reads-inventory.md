# Inventory — awaited reads COLLAPSED into a default (production code)

Produced on `0c962874` (= `origin/main`, 2026-09-07) by
`scripts/lint-swallow-classify.py`; verdicts in
`scripts/swallow-read-verdicts.py`. Re-derive with:

```sh
python3 scripts/lint-swallow-classify.py . --summary
python3 scripts/swallow-read-verdicts.py --render > docs/swallowed-reads-inventory.md
```

This is the READ-side companion to `docs/swallowed-results-inventory.md`,
which inventories discarded WRITES (`let _ = <expr>.await`). Here the value
IS used; what is discarded is the distinction between "the read answered"
and "the read failed".

Scope: `talos-mcp-handlers/src` + `talos-api/src`, non-test files, with
`#[cfg(test)] mod` regions excluded.

The table below is PINNED to `0c962874`: it records what was measured there,
including line numbers, and the disposition sections say what has been repaired
since. The LIVE count on the current tree is **121** (2026-09-08, package 32),
of which **zero** carry the `claim` verdict; re-derive it with the classifier
command above.

**196 sites**, closed and classified: **63 claim**, **5 fail-open**, **37 fail-closed**, **60 decorative**, **31 false-positive**.

**claim** — the default becomes a count, a list, a verdict or a "not found" that a caller reads and acts on.
**fail-open** — the default LIFTS an enforcement bound. Ranked first: these are not misleading reports, they are gates that stop gating.
**fail-closed** — the default costs the caller a refusal rather than granting anything. These are CORRECT and are listed so the population is visible rather than rediscovered.
**decorative** — a label or a hint beside untouched real numbers.
**false-positive** — the detector is wrong; the arm refuses, propagates, or yields an explicit UNKNOWN.

## Disposition (2026-09-07)

**18 of the 193 were repaired in this change** — 4 of the 5 `fail-open`, 13
`claim`, and 1 the detector had wrong. Three of the claims were reported by
**check 74b** after the first two adopted a `Readings` ledger, which is the
leg working as designed: its scope is DERIVED from the code, so a handler
enrols itself by adopting the pattern.

Sites:

* `talos-mcp-handlers/src/search.rs::handle_tag_workflow` — fail-open: the 100-tag cap. The repair exposed that `get_tag_count` decoded an INT4 projection into `i64` and therefore failed on EVERY call — the cap had never once been evaluated
* `talos-mcp-handlers/src/webhooks.rs::handle_create_webhook` — fail-open: the webhook-name uniqueness pre-flight, which nothing downstream backs (`webhook_triggers.name` carries no unique index)
* `talos-mcp-handlers/src/workflows.rs::handle_add_node_to_workflow` — fail-open ×2: the module-world half of the capability-ceiling gate, and the only pre-flight validation a node config gets
* `talos-api/src/schema/subscriptions.rs::dlq_updates` — fail-open: a failed permission refresh kept the prior (possibly revoked) org set
* `talos-mcp-handlers/src/executions.rs::handle_get_execution_cost` — claim: a failed fuel-rollup read rendered `total_fuel_consumed: 0` — "this execution cost nothing"
* `talos-mcp-handlers/src/executions.rs::build_execution_trace_json` — claim: `sub_execution_count: 0` on a failed child read, in three surfaces at once
* `talos-mcp-handlers/src/executions.rs::handle_submit_workflow_approval` — claim: a failed approval WRITE rendered "No pending approval found … It may have already been decided", the one diagnosis that stops a retry
* `talos-mcp-handlers/src/modules.rs::handle_get_module_dependents` — claim: `indirect_count: 0` — "nothing depends on this" — on the tool an operator consults before deleting a module
* `talos-mcp-handlers/src/platform.rs::handle_whoami` — claim ×4: a failed ceiling read rendered the hardcoded literal `http-node` as this user's authorization ceiling, and a failed admin read rendered `false`
* `talos-mcp-handlers/src/workflows.rs::handle_export_workflow` — claim: a bundle carrying `modules: []` with no flag — a corrupt backup indistinguishable from a module-less workflow
* `talos-mcp-handlers/src/workflows.rs::handle_import_workflow` — claim: a failed existence read marked EVERY referenced module missing and recompiled each from the bundle
* `talos-mcp-handlers/src/sandbox.rs::handle_run_sandbox` — false-positive: the lint pre-flight is duplicated by the full compile, so it was not a gate; the SILENCE was the defect and it now WARNs

The fifth `fail-open` (`subscriptions.rs::dlq_updates`) was repaired too; it
still appears in the table because the fix substitutes the NARROWEST
permission set rather than propagating, so the detector — correctly — still
sees a default. Its verdict on the fixed tree is `fail-closed`.

## What this detector CANNOT see

The binding leg is scoped to `if let Ok(..)` / `let Ok(..) … else`. Three
`if let Some(..)` sites over an Option-returning read were the most severe
fail-open members of this class and are **structurally invisible** to it —
they were found by reading the gate, not by the grep:

* `talos-mcp-handlers/src/sandbox.rs::handle_run_sandbox`
* `talos-mcp-handlers/src/sandbox.rs::handle_compile_custom_sandbox`
* `talos-mcp-handlers/src/workflows.rs::handle_add_node_to_workflow`

all three reading the actor capability-world ceiling through the LENIENT
`talos_actor_repository::get_actor_max_world`, which answers `None` on a
database error, so the whole ceiling gate was skipped. All three are fixed.

**Widening the leg to `Some(..)` was BUILT, MEASURED and REJECTED.** On
pristine main it takes the binding leg from **20 to 69** sites — 49 more, of
which **3** are these gates, i.e. ~6% precision. An Option-returning read is
the ordinary shape across both crates and `None` is its measured answer
nearly everywhere, so the widened leg would be enforcement-shaped noise. The
structural guard for these three is instead that they now route through the
single `crate::utils::read_actor_ceiling_or_refuse`, and that
`controller/tests/fail_open_gate_tests` drives two of them.

Other stated limits: the walk is TEXTUAL over masked source, so a collapse
reached through a helper in another crate, or applied to an
already-resolved local one statement later, is invisible; `.map_or` and a
default applied inside a service crate are out of range; and a verdict is a
judgement about the RESPONSE, so it can be wrong where the response shape
is not obvious from the call site.

Corroboration: run against the tree at `38175869` (the commit before #776,
i.e. the tree package 23 measured) this detector reports **208** sites
against package 23's reported **210**. Package 23's detector was lost with
its worktree; the rebuild agrees with it to within 1%.

## Disposition (2026-09-08)

**Eleven more collapses removed**, measured by running the classifier over the
tree before and after: **175 sites -> 164**, 11 removed and 0 added. They are the
five highest-ranked `claim` sites the table above still carried, plus the two
ENTITY lookups inside those same handlers and the four sibling reads that
adopting a `Readings` ledger enrolled in check 74b.

Sites:

* `talos-mcp-handlers/src/analytics.rs::handle_get_workflow_audit_trail` — claim x2: a failed version read removed every `version_published` event and a failed execution read every `execution_triggered` one, so a tool NAMED for auditability read as "never published" / "never ran" — and `count` / `event_count` reported the shortened list as the total. `list_executions_for_audit` carries a comment recording that this same swallow once hid a query naming a column that does not exist; the QUERY was fixed in May 2026 and the SWALLOW was left
* `talos-mcp-handlers/src/executions.rs::handle_get_execution_lineage` — claim: a failed ROOT lookup substituted the execution's own id, the tree query then matched `id = $1` and came back NON-empty, so the degraded flag stayed false and the response rendered the standalone-run claim #771 built `lineage_note` to remove
* `talos-mcp-handlers/src/executions.rs::handle_watch_execution` — claim x2: `events: [], events_count: 0` on a failed read, beside a `current_status` that WAS measured, on the tool an operator polls during an incident — a poller reads 0 as "no progress"
* `talos-mcp-handlers/src/modules.rs::handle_list_module_catalog` — claim: a failed visibility read made every entry read `needs_install` — an instruction to install modules the caller already has — and with `installed_only: true` the whole listing rendered as `[]`
* `talos-mcp-handlers/src/ml.rs::handle_get_model_card` — claim: `has_pending_disagreements: false` — "no human corrections are waiting" — immediately before a promotion decision; plus its model ENTITY lookup, which answered a failed registry read with "Model not found", and the four sibling reads that adopting a ledger enrolled in check 74b

`handle_get_execution_lineage`'s root lookup still appears in the table, for
the same reason `dlq_updates` does: the fix SUBSTITUTES a value (it still walks
from the anchor, because there is no better anchor) and DISCLOSES the
substitution — `root_execution_id: null` plus a new first arm in `lineage_note`
— so the detector correctly still sees a default. Its verdict on the fixed tree
is `false-positive`: the arm yields an explicit UNKNOWN.

The same 2026-09-08 change added ONE TEST PER SITE for the nine fixes #779
shipped with none (`controller/tests/unguarded_gate_survivor_tests`), and moved
the hand-copied test `McpState` constructor into `controller/tests/common/mcp.rs`
so the four binaries that build one cannot drift apart.

**What remains, with counts, so the next pass starts from a number rather than
a sweep.** 164 sites: **46 claim**, 55 decorative, 37 fail-closed, 25
false-positive, and the 1 nominal fail-open that is #779's repaired
`dlq_updates` narrowing. One of the 46 is the lineage-root row above, whose
verdict on this tree is `false-positive`, so 45 claims are genuinely open. By
file: `advanced.rs` 5, `analytics.rs` 5, `executions.rs` 5, `modules.rs` 5,
`workflows.rs` 5, `platform.rs` 4, `actor.rs` 3, `configuration.rs` 3,
`graph.rs` 3, `search.rs` 3, and 5 in `talos-api`. The highest-severity
members still open are:
`executions.rs::handle_get_execution_timeline` and
`handle_get_execution_waterfall` (the same `list_execution_events` swallow this
change repaired in `watch_execution`, in two more surfaces),
`modules.rs::handle_list_module_catalog`'s SECOND site (a `spawn_blocking`
`JoinError` defaulting the disk walk to an empty catalog — and it is cached in a
process-wide `OnceCell`, so one failure is permanent for the pod's lifetime),
and `actor.rs::handle_suggest_actor_for_task` ("No active actors found. Create
actors with create_actor first." from a failed listing).

## Disposition (2026-09-08, package 31)

**Thirteen more collapses removed**, measured by running the classifier over
the tree before and after: **164 sites -> 153**, 13 removed and 2 ADDED. The
two added are both in `handle_list_module_catalog` and are detector artefacts
of the fix: `get_or_try_init(...).await` followed by a `match` whose `Err` arm
REFUSES reads to the walker as a binding collapse. Their verdict on this tree
is `false-positive`, the same reason `dlq_updates` and the lineage root still
appear — saying so is cheaper than a detector exception that would hide a real
one later.

The ten sites were chosen by BLAST RADIUS over the 46 the table still
carried, not by position in it: a decision above a count an operator pages on,
above a list that feeds a next step, above a label. Two of the ten are WRITES
misreported as benign counts, and one of those (`compress_actor_context`) is
the only member of this class found so far whose swallow survived into a
COMMIT.

Sites:

* `talos-api/src/schema/auth/queries.rs::me` — claim: ONE unreadable column flipped BOTH security-gating booleans to their permissive reading. `is_2fa_enabled` collapsing to `false` made `is_two_factor_verified`'s `.unwrap_or(!totp_enabled)` fallback default to `true`, so a DB fault answered 'no 2FA, and you are verified'. MCP-877 LOGGED this in May 2026 and left the collapse; it now propagates
* `talos-mcp-handlers/src/actor.rs::handle_compress_actor_context` — claim: the ONLY swallow in this file that survived into a COMMIT. A failed measure-and-forget defaulted to (0, 0) and fell through to `tx.commit()`, so the condensed replacements landed AND the originals stayed — memory GREW — under `status: "compressed", keys_retired: 0`. Now rolls back and refuses
* `talos-mcp-handlers/src/search.rs::handle_bulk_tag_workflows` — claim x2: `bulk_add_tag` is a WRITE whose `rows_affected()` becomes `tagged_count`, and `already_tagged_count` is derived from it — so a failed UPDATE reported every owned workflow as ALREADY CARRYING the tag. The owned-count probe MCP-152 added to stop that conflation defaulted to 0, rendering `not_found_count = total` and accusing the operator of bad UUIDs
* `talos-mcp-handlers/src/platform.rs::handle_get_agent_card` — claim x2: `.unwrap_or(None)` answered 'Actor not found or access denied' on a database fault, and an unread workflow list shipped a `shareable: true` A2A card advertising an agent that can do nothing, under a note telling the operator to register it in a discovery registry
* `talos-mcp-handlers/src/executions.rs::handle_get_execution_comparison_report` — claim: an empty map sent every requested id down `not_found_ids` and rendered 'No matching executions found (check IDs and ownership)' — a database failure reported as the caller's typo, inside the comment block (MCP-355) written to keep those causes apart
* `talos-mcp-handlers/src/executions.rs::handle_get_node_io` — claim: NOT the label prettification its twelve siblings are — `node_uuid` is RESOLVED through this map, so an empty one silently resolved to a DIFFERENT node's uuid and rendered `input: null, output: null` for it
* `talos-mcp-handlers/src/executions.rs::handle_get_execution_timeline` — claim: an empty `--- Event Sequence ---` on a tool called 'timeline' reads as 'nothing happened during this execution'. Text response, so the disclosure is a line in the report rather than a `Readings` attachment
* `talos-mcp-handlers/src/executions.rs::handle_get_execution_waterfall` — claim: the same read, second surface — and here the empty vec reached the literal 'No node timing data available for this execution.'
* `talos-mcp-handlers/src/actor.rs::handle_suggest_actor_for_task` — claim: 'No active actors found. Create actors with create_actor first.' — not merely a false count but a DIRECTIVE to create actors that may already exist
* `talos-mcp-handlers/src/modules.rs::handle_list_module_catalog` — claim: the disk walk's `JoinError` defaulted to an empty catalog INSIDE `OnceCell::get_or_init`, so one panicked blocking task made every later call in the pod's lifetime report 'this image ships no templates'. `get_or_try_init` leaves the cell uninitialised on `Err`, so the failure is no longer memoized, and the handler refuses

Nine are pinned by `controller/tests/claim_read_disclosure_tier4_tests` (11
tests, CTRL_TESTS per check 64b), which drives the REAL MCP dispatch over a
real `McpState` — and, for the `me` resolver, the REAL compiled GraphQL schema
— with each read made to fail deterministically. Every test carries its
CONTROL in the same run, and the two whose pre-fix path ALSO refused
(`get_agent_card` on an absent actor, `suggest_actor_for_task` for a user with
none) carry that half explicitly, because "the tool refused" is not evidence
when the pre-fix path refused too with the wrong diagnosis.

Two failures could not be injected by dropping a relation and are said so
rather than implied. `me`'s 2FA read shares the `users` row with
`AuthService::get_user`, which projects `totp_enabled` too and would refuse
first, so the failure is injected as a POOL that cannot connect — which is
the shape this defect takes in production. `compress_actor_context`'s failing
DELETE and the replacement INSERT it must not outlive share ONE relation, so
the injection is a `BEFORE DELETE` trigger that raises; the assertion is on
ROWS rather than on the reply, because a refusal that arrives after the write
is not a rollback and the whole defect was a commit.

**What remains: 153 sites — 34 claim**, 55 decorative, 37 fail-closed, 24
false-positive, the 1 nominal fail-open that is #779's repaired `dlq_updates`
narrowing, and the 2 new detector artefacts above. The 34 claims by file:
`advanced.rs` 5, `analytics.rs` 5, `workflows.rs` 5, `modules.rs` 4,
`configuration.rs` 3, `graph.rs` 3, `platform.rs` 2, `lib.rs` 2, `talos-api`
2, `actor.rs` 1, `executions.rs` 1, `search.rs` 1. Ranked highest among them:
`analytics.rs::handle_get_workflow_performance_report` (three reads, one
compounding the next, emptying the node-timing breakdown for a workflow that
ran nodes), `configuration.rs::handle_get_session_context` (three lists an
agent reads as 'this user has no ready workflows and ran none recently', which
pushes it to build a duplicate), `graph.rs::handle_preview_capability_dispatch`
(the tool's whole purpose is answering which workflows match, and a failed
read answers none), and `workflows.rs::handle_get_workflow_quickstart` (every
referenced secret rendered unprovisioned, flipping `ready_to_run` false and
listing blockers for credentials that are already configured).

## Disposition (2026-09-08, package 32) — the class closes at zero

**The remaining 34 `claim` sites are all closed**, measured by running the
classifier over the tree before and after: **153 sites -> 121**, 32 removed and 0
added. Thirty-two were REPAIRED and two were RECLASSIFIED — and the two
reclassifications are stated with the field they feed, because the goal is a
claim count of zero by MEASUREMENT and not by relabelling:

* `executions.rs::handle_get_execution_lineage`'s root lookup was repaired by
  #782 and never re-verdicted. Its `Err` arm still substitutes the anchor —
  there is no better id to walk from — but it sets `root_unreadable`, which
  renders `root_execution_id` as `null` and takes `lineage_note`'s FIRST arm.
  The substitution is DISCLOSED, so no field claims anything.
* `workflows.rs::handle_import_workflow`'s `upsert_wasm_module` write still
  pushes the module onto `still_missing` — it genuinely is not importable — but
  it now carries its REASON, one of five, and the refusal renders it. The
  one-sentence-for-five-causes claim ("no source in bundle", said about a
  DATABASE WRITE that failed) is gone; what is left is a classified list.

Sites repaired:

* `talos-api/src/schema/actors/mutations.rs::clone_actor` — `memories_copied` is an `Option`, matching the MCP twin fixed on 2026-09-02. `Some(0)` is a source with nothing to copy; `None` is a copy that could not be MEASURED. The mutation returns an `ActorSummary` with no field for it, so the difference lands where an operator actually reads it — the action-log line, which said "(0 memories copied)" for a copy that failed. An UNKNOWN count now also RUNS the embedding backfill (bounded at the cap) instead of skipping it, so rows that did land are not left permanently invisible to semantic recall.
* `talos-api/src/schema/security/mutations.rs::rotate_encryption_key` — the post-rotation key count PROPAGATES. A bare `i32` return has no disclosure slot — the position `me`'s `UserInfo` was in — and `1` is not a placeholder here, it is the version number the toast prints and an operator tracks. `0` would be worse: the frontend's `if (data.rotateEncryptionKey)` renders no toast at all. The error names the half that SUCCEEDED so nobody re-rotates.
* `talos-mcp-handlers/src/actor.rs::handle_actor_recall` — `reason` is three-valued. `never_set` is a determinate negative about an actor's whole memory history and an unreadable probe produced it; `unknown` is now its own answer, named on the ledger.
* `talos-mcp-handlers/src/advanced.rs::handle_run_scratch_session` — an unreadable session is no longer reported as absent. The REFUSAL direction was always right — running possibly-stale code is worse — but "not found" is the one diagnosis that sends an operator to re-create work that is still there.
* `talos-mcp-handlers/src/advanced.rs::handle_get_marketplace_stats` — `top_modules` is null, never `[]`. The swallow was worse than a bare default here: `top_modules_note` told the reader in so many words that an empty list means nothing has been downloaded, "a real signal, not an error" — the response affirmatively vouched for an emptiness it could not measure. The note is now conditional on its own field.
* `talos-mcp-handlers/src/advanced.rs::handle_star_module` — `star_count` is null, never `0`. Zero reads as "nobody has starred this" on the one branch that is reached only because this caller already has.
* `talos-mcp-handlers/src/advanced.rs::handle_get_config_suggestions` — TWO sites. The node-template read is LOAD-BEARING — the module name, its canonical `allowed_secrets`, its schema and therefore `missing_fields` all come from it — and an unread map made the very next block answer "No missing required fields for this node." on a tool whose whole job is naming what is unset; it REFUSES. The vault listing makes `provisioned` three-valued instead of marking every already-held credential missing and telling the operator to create it again.
* `talos-mcp-handlers/src/analytics.rs::handle_get_workflow_changelog` — the ownership read is three-valued through the new shared `utils::workflow_lookup_unreadable_error`, so "not found or access denied" — false on BOTH clauses during a database incident — is no longer the answer to a read that did not happen.
* `talos-mcp-handlers/src/analytics.rs::handle_get_workflow_call_tree` — the same read one tool over, rendered per NODE: a database fault while walking the tree told the operator their sub-workflow had been deleted or un-shared, which starts a hunt for a change nobody made. The node now carries `unreadable: true`.
* `talos-mcp-handlers/src/analytics.rs::handle_get_workflow_performance_report` — THREE reads, each COMPOUNDING the next: a failed output read emptied the node-timing breakdown, the rollup fallback that exists to repair exactly that was skipped on its own failed read, and the extremes query rendered slowest/fastest null beside a NONZERO `total_completed_executions`. The breakdown is null only when BOTH sources failed — one working source is a real measurement — and the two failures name the field ONCE, so an unreadable pair does not look like two.
* `talos-mcp-handlers/src/configuration.rs::handle_get_session_context` — THREE lists an agent reads as an inventory of what the user already has. This tool renders PLAIN TEXT and has no `measurement` object, so the ledger is the same `Readings` every JSON report uses and only the RENDERING differs: the unread sections are NAMED in a DEGRADED line, and the response says not to conclude from it that a workflow must be created.
* `talos-mcp-handlers/src/graph.rs::handle_add_capability_dispatch_node` — the capability pre-flight is three-valued: `[]` is "nothing matches", an `Err` is "the pre-flight could not run". The warning no longer tells an author that runtime dispatch WILL fail hard on the strength of a query that did not answer.
* `talos-mcp-handlers/src/graph.rs::handle_add_error_handler` — the handler-module lookup is three-valued; a pool timeout used to refuse with "not found" AND a list of near-miss names, sending the author to rename a module that was there all along.
* `talos-mcp-handlers/src/graph.rs::handle_preview_capability_dispatch` — REFUSES. This tool's entire output is the answer to "which workflows match", and `match_count: 0` is read — by the `dispatch_note` directly below it — as "dispatch fails hard unless a fallback is set".
* `talos-mcp-handlers/src/lib.rs::create_router` — TWO sites. `/mcp/local` REFUSES when no dev identity resolves. The comment that stood here NAMED the consequence without preventing it: "tools appear to succeed but nothing persists" — reported-success-on-a-failed-read for EVERY tool on the endpoint at once. `Ok(None)` from the first read is still a genuinely fresh database and still creates the user; the notification check moved ABOVE the resolution so a refusal cannot put a body on a notification.
* `talos-mcp-handlers/src/modules.rs::handle_find_module_alternatives` — FOUR sites, two pairs. The trigram-to-fallback shape is honest — a deployment without `pg_trgm` really does have a second, worse way to answer — but the FALLBACK's own failure rendered `count: 0` and a tip pointing at `list_module_catalog`, i.e. "there is nothing else like this module", from two queries neither of which answered. When both fail there is no answer left, so both branches refuse.
* `talos-mcp-handlers/src/platform.rs::handle_get_platform_info` — TWO sites, both understating. A failed catalog listing rendered `catalog_tool_count: 0` and `total_mcp_tools` silently equal to the static count, beside a note asserting the three numbers add up. The world-override read is subtler: a blank map measures every non-`minimal` template against the literal world `unknown`, so the count shrinks quietly rather than obviously. Both counts are null and named; `static_tool_count` is untouched.
* `talos-mcp-handlers/src/search.rs::handle_find_similar_workflows` — REFUSES. The comparison set IS the answer, and "no similar workflows" is what an agent uses to justify building a duplicate.
* `talos-mcp-handlers/src/workflows.rs::handle_dispatch_to_actor` — the candidate listing is read only to tell "0 workflows" from "2+", and an unread one rendered the ZERO message — "Actor X owns no active workflows. Create one" — for an actor that may own several, which is why the branch was entered.
* `talos-mcp-handlers/src/workflows.rs::handle_instantiate_workflow_pattern` — TWO sites. The compiled-template lookup is three-valued, so a failed catalog read no longer tells the operator to INSTALL a module it could not establish is absent. The post-create schema fetch cannot refuse — the workflow already exists — so `ready_to_run` becomes null rather than a verdict computed from an empty schema map, which made every pattern look ready as instantiated.
* `talos-mcp-handlers/src/workflows.rs::handle_get_workflow_quickstart` — `provisioned` is three-valued and an unread vault fabricates no `missing_secret` blocker; `ready_to_run` is null rather than `false`. Pre-fix a workflow whose credentials were all in place reported not-ready with one blocker per secret, each telling the operator to provision what they already had.

Fourteen of them are pinned by
`controller/tests/claim_read_disclosure_tier5_tests` (CTRL_TESTS per check 64b),
which drives the REAL MCP dispatch over a real `McpState`. The injection is
`ALTER TABLE … DROP COLUMN` rather than a table drop at almost every site,
because these handlers need one read of a table to SUCCEED and the NEXT read of
the SAME table to FAIL — a column named by the second statement and not the
first is the only instrument that separates them, and it is what makes the
tests prove a per-FIELD disclosure rather than a blanket refusal. Every test
carries its CONTROL in the same run.

**Falsification: 12 main-vocabulary twins were run against a `git worktree` of
`origin/main` (1ded89ac) with its own migrated database, and 12 of 12 FAILED BY
ASSERTION** — none by compile error. Main answered, verbatim: `"Scratch session
'p32-scratch' not found"` for a session it could not read; `"Workflow not found
or access denied"` for a workflow whose ownership row it could not read;
`star_count: 0` on the branch reached only because somebody had starred it;
`top_modules: []` beside a note calling the emptiness "a real signal, not an
error"; `catalog_tool_count: 0` with `total_mcp_tools` silently equal to the
static count; `node_timing_breakdown: []` for a workflow with a completed run;
a bare `=== Top Workflows ===` header with nothing under it; `match_count: 0`
from `preview_capability_dispatch`; `count: 0` with a tip pointing at
`list_module_catalog`; `"Actor … owns no active workflows"` for an actor that
owns two; and `ready_to_run: false` with a fabricated `missing_secret` blocker.

**Six sites have no round trip and are said so rather than implied.**
`get_config_suggestions` (2) refuses at its top for want of an LLM client;
`import_workflow`'s write needs a real compile; `instantiate_workflow_pattern`
(2) needs an installed AND compiled built-in pattern; `create_router`'s
`/mcp/local` identity resolution is a closure inside the router builder. Those
carry a SOURCE pin, which proves the expression is present and never that it
produces the right answer. `talos-api`'s two sites have no injection either:
`clone_actor`'s copy and `rotateEncryptionKey`'s count both read the same
relation as the operation that must succeed before them.

**Leg B — the CLAIM verdict as a lint leg was BUILT, MEASURED and REJECTED;
`--count` stays 88.** On the fixed tree it reports **0 claim and 0
unclassified**, which is the zero baseline check 52's rule demands, and on
pristine main it reports **32 of the 34** (the two misses are the sites whose
verdict row now describes the REPAIRED expression). It fails on three
independent measurements. (i) A revert at a site this package reclassified is
**completely green** — the key is `(file, function, callee, spelling)`, which
cannot tell the pre-fix expression from the post-fix one at the same call site.
(ii) The two mutations it DOES catch (`unwrap_or_default`, `if let Ok`) are
caught only because the table still carries the PRE-fix verdict for the 32
repaired rows; simulated with those rows maintained — which is what "what the
default CLAIMS" means once the default is gone — the `unwrap_or_default`
mutation SURVIVES with a fully green report. (iii) A `.ok()` revert never
reaches the CLAIM arm at all, because the spelling is part of the key. What is
left is the ratchet arm, which fires on every NEW collapsed read whatever its
verdict: packages 29 and 31 each ADDED two detector artefacts on correct code,
so it would have fired four times across the two most recent changes in this
family, against a 196-row hand-maintained table — check 74's own recorded rot
mode and check 64's "a sweep is a snapshot, not a gate", one level up.

What guards the class instead is what already guards it: sub-leg **74b**, whose
scope is DERIVED (any function constructing a `Readings`), so the eight
handlers that adopted a ledger in this change enrolled themselves; the
`#[must_use]` three-valued lookups; and the DB tests above.

**What remains: 121 sites — 0 claim**, 60 decorative, 37 fail-closed, 31
false-positive (which now includes the three detector artefacts packages 29 and
31 left unrowed, plus this change's two reclassifications), and the 1 nominal
`fail-open` that is #779's repaired `dlq_updates` narrowing. By file:
`executions.rs` 18, `sandbox.rs` 15, `actor.rs` 12, `workflows.rs` 11,
`analytics.rs` 9, `modules.rs` 8, `graph.rs` 8, `advanced.rs` 8,
`configuration.rs` 5, `platform.rs` 4, and 20 across fourteen more files. None
of them makes a claim; every one is a label, a fail-closed refusal or a
disclosed substitution.


## claim — 63 sites

### `talos-api/src/schema/actors/mutations.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1081 | `clone_actor` | `clone_actor_memories` | `match_default` | memories_copied response field | DB error defaults memories_copied to 0, reported to the caller as the actual copy count rather than unknown/failed. |

### `talos-api/src/schema/auth/queries.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 51 | `me` | `is_2fa_enabled` | `match_default` | two_factor_enabled / is_two_factor_verified fields | DB error renders 2FA as disabled and, absent middleware data, marks verification true, misleading frontend security gating. |

### `talos-api/src/schema/security/mutations.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 630 | `rotate_encryption_key` | `count_encryption_keys` | `unwrap_or_literal` | dek_count / rotation toast | DB failure renders hardcoded count=1 in the "Key rotated to version N" toast, potentially showing a lower DEK count than reality. |

### `talos-mcp-handlers/src/actor.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 3957 | `handle_actor_recall` | `unwrap_or_default` | `unwrap_or_literal` | actor_recall "reason" field | exists_at_all defaults to false on read failure, so a DB hiccup reports reason:"never_set" instead of the possibly-true "expired". |
| 5558 | `handle_suggest_actor_for_task` | `list_active_actors_basic` | `unwrap_or_default` | "actors"/"note" fields (suggest_actor_for_task) | Empty actor list on read failure renders "No active actors found. Create actors with create_actor first." even when active actors exist. |
| 6150 | `handle_compress_actor_context` | `measure_and_forget_keys_in_tx` | `unwrap_or_literal` | "keys_retired"/"status" (compress_actor_context) | A failed forget-and-measure CTE reports keys_retired:0 while the response still claims status:"compressed", hiding that archive_keys were never actually retired. |

### `talos-mcp-handlers/src/advanced.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1481 | `handle_run_scratch_session` | `get_scratch_session` | `unwrap_or_literal` | "Scratch session not found" error (run_scratch_session) | A failed session read renders "Scratch session 'X' not found" even though the session may exist; direction is safe (refuses to run possibly-stale code) but the claim is false. |
| 2551 | `handle_get_marketplace_stats` | `get_marketplace_top_modules` | `unwrap_or_default` | "top_modules" list (get_marketplace_stats) | A failed top-modules query renders an empty top_modules list in the stats report, indistinguishable from "no modules have downloads". |
| 2783 | `handle_star_module` | `get_star_count` | `unwrap_or_literal` | "star_count" field (star_module) | get_star_count failure renders star_count:0 for an already-starred listing that may actually carry a nonzero count. |
| 2920 | `handle_get_config_suggestions` | `get_node_templates_for_config` | `unwrap_or_default` | "target_allowed_secrets"/"missing_fields" (get_config_suggestions) | Failed template-schema fetch yields empty required-fields and canonical-secret lists, so the tool reports nothing missing/no canonical paths when fields may in fact be required. |
| 3064 | `handle_get_config_suggestions` | `get_user_secret_paths` | `unwrap_or_default` | "provisioned" boolean (get_config_suggestions) | A failed provisioned-secret-paths fetch makes every already-provisioned secret report provisioned:false in the suggestion payload. |

### `talos-mcp-handlers/src/analytics.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1277 | `handle_get_workflow_changelog` | `get_workflow_for_analytics` | `unwrap_or_literal` | workflow_not_found_error (changelog) | A DB failure on the ownership check renders as "Workflow not found or access denied", false on both clauses, via workflow_not_found_error. |
| 1970 | `handle_get_workflow_audit_trail` | `list_workflow_versions_audit` | `unwrap_or_default` | audit trail "events" list | A failed version-history read silently omits all version_published events from the audit trail, reading as "no versions ever published". |
| 1995 | `handle_get_workflow_audit_trail` | `list_executions_for_audit` | `unwrap_or_default` | audit trail "events" list | A failed execution-history read silently omits all execution_triggered events from the audit trail, reading as "workflow never ran". |
| 2973 | `handle_get_workflow_call_tree` | `get_workflow_for_analytics` | `unwrap_or_literal` | call-tree node "error" field | A DB failure while walking the sub-workflow call tree renders that node as {"error":"Workflow not found or access denied"}, false on both clauses. |
| 5172 | `handle_get_workflow_performance_report` | `get_completed_executions_output` | `unwrap_or_default` | node_timing_breakdown | A failed per-execution output read empties the node timing breakdown, reading as "no per-node timing data" for a workflow that ran nodes. |
| 5221 | `handle_get_workflow_performance_report` | `get_workflow_node_timing_breakdown` | `if_let_ok` | node_timing_breakdown (rollup fallback) | The rollup fallback for node timing is silently skipped on read failure (if let Ok), compounding the primary read's empty node_timing_breakdown claim. |
| 5240 | `handle_get_workflow_performance_report` | `get_extreme_executions` | `if_let_ok` | slowest_execution / fastest_execution | A failed extremes query renders slowest/fastest execution as null beside a nonzero total_completed_executions, indistinguishable from "no extremes exist". |

### `talos-mcp-handlers/src/configuration.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 946 | `handle_get_session_context` | `list_top_workflows_by_readiness` | `unwrap_or_default` | session-context "Top Workflows" list | DB failure renders an empty top-readiness list, which an agent reading session context could take as "user has no ready workflows". |
| 953 | `handle_get_session_context` | `list_recently_used_workflows` | `unwrap_or_default` | session-context "Recently Used" list | DB failure renders an empty recently-used list, letting an agent believe no workflow was recently run. |
| 1022 | `handle_get_session_context` | `match_workflows_by_keyword` | `unwrap_or_default` | session-context keyword-match list | DB failure renders "no matches" for the task keyword, which could push an agent to create a duplicate workflow instead of reusing one. |

### `talos-mcp-handlers/src/executions.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 2368 | `handle_get_execution_timeline` | `list_execution_events` | `unwrap_or_default` | execution timeline event sequence | A failed events read collapses the entire timeline's event sequence to empty, rendering as "nothing happened during this execution". |
| 3637 | `handle_watch_execution` | `list_execution_events_since` | `unwrap_or_default` | watch_execution events list | A failed events-since read empties the watched execution's event list, reading as "no progress since <since>" when the read simply failed. |
| 3642 | `handle_watch_execution` | `list_execution_events` | `unwrap_or_default` | watch_execution events list | A failed events read empties the watched execution's full event list, reading as "nothing has happened" rather than a DB failure. |
| 4697 | `handle_get_execution_cost` | `list_execution_events` | `unwrap_or_default` | node_count / timing_source (execution cost) | A failed events fallback read leaves node_count at 0 and per-node timing empty in the cost report, though timing_source is separately marked "unavailable". |
| 4759 | `handle_get_execution_cost` | `get_execution_node_fuel` | `ok` | total_fuel_consumed / compute_units | A failed fuel-rollup read renders total_fuel_consumed and compute_units as 0, a false "this execution cost nothing" claim. |
| 4840 | `handle_get_execution_waterfall` | `list_execution_events` | `unwrap_or_default` | execution waterfall chart | A failed events read (with no output_data fallback) renders "No node timing data available for this execution", indistinguishable from a genuine empty run. |
| 5153 | `handle_get_execution_comparison_report` | `get_executions_by_ids` | `match_default` | "No matching executions found" / not_found_ids | Batch-fetch DB error empties the exec map; every requested id is reported as not-found-or-unowned instead of a DB failure. |
| 5324 | `build_execution_trace_json` | `list_execution_events` | `unwrap_or_default` | per-node trace (node_traces) | On a LIVE (non-archived) execution a failed events read empties the per-node trace with no disclosure, reading as "this workflow ran no nodes". |
| 5438 | `build_execution_trace_json` | `get_execution_node_fuel` | `ok` | per-node fuel_consumed / wall_time_ms (trace) | A failed fuel-rollup read leaves every node's fuel_consumed and wall_time_ms fields absent in the execution trace, understating real cost. |
| 5629 | `build_execution_trace_json` | `list_child_executions` | `ok` | sub_executions / sub_execution_count | A failed child-executions read renders sub_execution_count as 0, a false "this execution has no children" claim in the trace summary. |
| 6611 | `handle_submit_workflow_approval` | `update_execution_approval_decision` | `match_default` | "No pending approval found" refusal message | DB write failure defaults db_rows_updated to 0, misreported to the caller as "no pending approval" rather than a DB error. |
| 6790 | `handle_get_node_io` | `get_workflow_graph_for_user` | `ok` | node_uuid resolution (get_node_io) | Graph read also drives functional label-to-UUID resolution, not just display; on failure a label-based lookup silently mis-resolves and returns empty/wrong node I/O. |

### `talos-mcp-handlers/src/graph.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 4381 | `handle_add_capability_dispatch_node` | `find_workflows_for_capability_dispatch_preview` | `unwrap_or_default` | capability-dispatch preflight_warning | Failed read renders "no workflows currently match capabilities" even if matches exist, prompting unnecessary fallback_workflow_id setup. |
| 4678 | `handle_add_error_handler` | `find_template_id_by_name_ci` | `unwrap_or_literal` | handler_module_name resolution / not-found | DB failure collapses to None, identical to a genuinely unknown module name, so add_error_handler refuses citing a false "not found". |
| 5121 | `handle_preview_capability_dispatch` | `find_workflows_for_capability_dispatch_preview` | `unwrap_or_default` | preview_capability_dispatch matches | Tool's entire purpose is answering which workflows match; failure renders empty matches, falsely claiming no workflow would be dispatched. |

### `talos-mcp-handlers/src/lib.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 485 | `create_router` | `find_first_user_id` | `ok` | dev_user_id / local MCP endpoint | Comment documents that on failure every subsequent user-scoped write/read for the dev session silently no-ops while reporting success. |
| 493 | `create_router` | `ensure_dev_user` | `ok` | dev_user_id / local MCP endpoint | Fallback dev-user creation failing leaves user_id None, same silent-success-but-nothing-persists outcome documented in the surrounding comment. |

### `talos-mcp-handlers/src/ml.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1173 | `handle_get_model_card` | `pending_disagreements` | `unwrap_or_literal` | has_pending_disagreements (model card) | A failed pending-disagreements read renders has_pending_disagreements:false, a confident wrong claim that no corrections need review. |

### `talos-mcp-handlers/src/modules.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 2571 | `handle_get_module_dependents` | `find_workflows_referencing_workflows` | `if_let_ok` | indirect_via_sub_workflows / indirect_count | DB failure renders indirect_count:0, understating a module's real dependents on a tool used before deciding it's safe to change/delete a module. |
| 3075 | `handle_list_module_catalog` | `unwrap_or_else` | `unwrap_or_default` | catalog entry installed/module_id fields | Empty visible-module map on failure makes every catalog entry report installed:false/module_id:null, even for already-installed modules. |
| 3181 | `handle_list_module_catalog` | `cmp` | `unwrap_or_default` | list_module_catalog entries/total_before_filter | If the cached disk-catalog spawn_blocking task fails, the whole catalog renders as empty, falsely claiming no templates exist. |
| 4193 | `handle_find_module_alternatives` | `find_template_alternatives_trgm` | `match_default` | find_module_alternatives count/alternatives | Trigram-search failure falls back to a category query whose own failure defaults to empty, rendering count:0 "no alternatives" when some may exist. |
| 4206 | `handle_find_module_alternatives` | `find_template_alternatives_by_category` | `unwrap_or_default` | find_module_alternatives count/alternatives | Category-fallback read failure defaults to an empty alternatives list, same false "no alternatives found" claim as the trigram path above. |
| 4259 | `handle_find_module_alternatives` | `find_templates_by_capability_trgm` | `match_default` | find_module_alternatives count/alternatives (capability) | Capability-trigram failure falls back to ilike search; that search's own failure defaults to empty, rendering a false "no modules matched" tip. |
| 4266 | `handle_find_module_alternatives` | `find_templates_by_capability_ilike` | `unwrap_or_default` | find_module_alternatives count/alternatives (capability) | Ilike fallback failure defaults to empty results, rendering count:0 and "No modules matched" even if matches exist. |

### `talos-mcp-handlers/src/platform.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 275 | `handle_whoami` | `get_user_email` | `ok` | whoami user.email | Identity-diagnostic tool renders email:null on a failed lookup, indistinguishable from the user genuinely having no email, misleading tenancy debugging. |
| 276 | `handle_whoami` | `get_user_org_summary` | `ok` | whoami organization | Same diagnostic tool renders organization:null on failure, falsely implying the user belongs to no organization. |
| 279 | `handle_whoami` | `get_user_max_capability_world` | `ok` | whoami capability_ceiling | Ceiling lookup failure renders "http-node" as the user's capability ceiling, which may misstate a stricter or looser real ceiling. |
| 283 | `handle_whoami` | `is_platform_admin` | `unwrap_or_literal` | whoami is_platform_admin | Admin-status lookup failure renders is_platform_admin:false in the identity report, a false status claim (though not itself a privilege gate here). |
| 1239 | `handle_get_platform_info` | `list_templates` | `if_let_ok` | get_platform_info catalog_count/tool_count | list_templates failure renders catalog_count:0, understating the platform's total advertised tool count. |
| 1244 | `handle_get_platform_info` | `list_template_world_overrides` | `unwrap_or_default` | get_platform_info catalog_count/tool_count | World-override read failure blanks the world map, undercounting catalog templates visible to non-admin agents in the reported tool_count. |
| 1560 | `handle_get_agent_card` | `get_actor_card_info` | `unwrap_or_literal` | get_actor_card_info / actor not-found | DB failure collapses to None, identical to a genuinely absent actor, so the A2A agent-card tool falsely reports "Actor not found or access denied". |
| 1575 | `handle_get_agent_card` | `list_published_workflows_for_actor` | `unwrap_or_default` | agent_card published workflows list | Failure renders an empty workflow list on the A2A agent card, indistinguishable from an actor that truly publishes nothing. |

### `talos-mcp-handlers/src/search.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 493 | `handle_bulk_tag_workflows` | `bulk_add_tag` | `unwrap_or_literal` | bulk_tag_workflows tagged_count | bulk_add_tag failure renders tagged_count:0, which downstream math turns into a false "already tagged" or not-found breakdown for the whole batch. |
| 508 | `handle_bulk_tag_workflows` | `count_owned_workflows_in_set` | `unwrap_or_literal` | bulk_tag_workflows not_found_count | count_owned_workflows_in_set failure defaults owned_count to 0, making not_found_count report every requested id as missing/not-owned even if tagging succeeded. |
| 586 | `handle_find_similar_workflows` | `list_workflows_for_similarity` | `unwrap_or_default` | find_similar_workflows similarities | Failure renders other_rows empty, falsely reporting "no similar workflows" when the comparison set may exist. |

### `talos-mcp-handlers/src/workflows.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 3003 | `handle_dispatch_to_actor` | `list_active_workflows_for_actor_brief` | `unwrap_or_default` | "candidates" listing / error text (dispatch_to_actor) | Failed candidate listing renders "Actor owns no active workflows" even when 2+ active workflows exist (that ambiguity is why this branch was reached). |
| 5696 | `handle_export_workflow` | `get_module_export_metadata` | `match_default` | exported bundle "modules" array | DB error empties modules_meta; the export bundle silently ships with zero modules and no error flag, an incomplete backup reported as success. |
| 5797 | `handle_import_workflow` | `modules_exist` | `unwrap_or_default` | "missing" modules list (import_workflow) | A failed modules_exist check marks every referenced module "missing", triggering needless recompilation or an "Import failed: modules missing" refusal for modules that actually exist. |
| 9125 | `handle_instantiate_workflow_pattern` | `find_compiled_template_by_name` | `unwrap_or_literal` | "missing_modules" list (instantiate_workflow_pattern) | A failed per-node template lookup marks a module "not installed (or not yet compiled)" and refuses to instantiate the pattern even when the module is actually installed and compiled. |
| 9244 | `handle_instantiate_workflow_pattern` | `get_templates_by_ids` | `unwrap_or_default` | "missing_config"/"required" fields (instantiate_workflow_pattern) | Failed post-create schema fetch yields empty required-field lists, so the quickstart-style response reports nothing missing when required config may in fact be unset. |
| 9724 | `handle_get_workflow_quickstart` | `get_provisioned_secrets` | `unwrap_or_default` | "ready_to_run"/"missing_secret" blockers (get_workflow_quickstart) | Failed provisioned-secrets fetch marks every referenced secret unprovisioned, flipping ready_to_run to false and listing missing_secret blockers for secrets that are already configured. |


## fail-open — 5 sites

### `talos-api/src/schema/subscriptions.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 407 | `dlq_updates` | `list_user_org_ids` | `match_default` | accessible_org_ids used by dlq_event_visible_to | Periodic refresh failure keeps the stale, possibly broader org list, so a revoked org's visibility is not withdrawn from the live subscription. |

### `talos-mcp-handlers/src/search.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 364 | `handle_tag_workflow` | `get_tag_count` | `unwrap_or_literal` | tag_workflow 100-tag cap | get_tag_count failure defaults to 0, so the per-workflow 100-tag cap check always passes, letting an unbounded number of tags be added. |

### `talos-mcp-handlers/src/webhooks.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 355 | `handle_create_webhook` | `name_exists_for_user` | `unwrap_or_literal` | create_webhook unique-name pre-flight | name_exists_for_user failure defaults to false, silently skipping the duplicate-name check and letting a same-named webhook be created. |

### `talos-mcp-handlers/src/workflows.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 2322 | `handle_add_node_to_workflow` | `get_module_capability_worlds` | `if_let_ok` | capability-world ceiling check, module_id path (add_node_to_workflow) | if let Ok(world_map) silently skips the actor's capability-ceiling check for an existing module's world on any DB error, letting a node above the actor's ceiling be added; same fail-open class already patched for the sibling actor-ceiling read in this same function. |
| 2419 | `handle_add_node_to_workflow` | `get_templates_by_ids` | `if_let_ok` | config-schema/pattern validation pre-flight (add_node_to_workflow) | if let Ok(templates) silently skips the only pre-flight validation of node config against its schema on any DB error, letting invalid config be persisted to fail opaquely inside the WASM guest at runtime instead. |


## fail-closed — 37 sites

### `talos-api/src/schema/mod.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 386 | `user_accessible_org_ids` | `list_user_org_ids` | `match_default` | user_accessible_org_ids authorization scope | DB error yields an empty org list; reader is restricted to personally-owned resources, a refusal not a grant. |
| 432 | `user_writable_org_ids` | `list_user_writable_org_ids` | `match_default` | user_writable_org_ids authorization scope | DB error yields an empty writable-org list; writer is denied on org-shared resources rather than granted access. |

### `talos-api/src/schema/types.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 775 | `load` | `list_user_org_ids` | `match_default` | latest_execution DataLoader org scope | DB error yields empty org_ids; loader falls back to personally-owned executions only, a refusal not a grant. |

### `talos-api/src/schema/workflows/mutations.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1298 | `test_workflow` | `resolve_effective_actor` | `ok` | test_effective_actor binding | On resolution failure the test runs actor-less, which binds the engine to the Tier-1 fail-safe ceiling rather than the actor's own (possibly looser) tier. |

### `talos-mcp-handlers/src/actor.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 4707 | `handle_grant_capability_ceiling` | `is_platform_admin` | `unwrap_or_literal` | is_platform_admin gate (grant_capability_ceiling) | Unreadable admin status defaults to false, refusing the cross-user grant rather than permitting it. |
| 4909 | `handle_revoke_capability_ceiling` | `is_platform_admin` | `unwrap_or_literal` | is_platform_admin gate (revoke_capability_ceiling) | Unreadable admin status defaults to false, refusing the cross-user revoke rather than permitting it. |
| 5016 | `handle_list_capability_grants` | `is_platform_admin` | `unwrap_or_literal` | is_platform_admin gate (list_capability_grants) | Unreadable admin status defaults to false, refusing the platform-admin-only listing. |

### `talos-mcp-handlers/src/advanced.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 931 | `handle_query_paginated` | `is_platform_admin` | `unwrap_or_literal` | is_platform_admin gate (query_paginated) | Unreadable admin status defaults to false, refusing the arbitrary cross-tenant SELECT tool. |
| 1922 | `handle_set_archive_policy` | `is_platform_admin` | `unwrap_or_literal` | is_platform_admin gate (set_archive_policy) | Unreadable admin status defaults to false, refusing the deployment-wide archive-policy change; comment explicitly documents this as the correct fail-closed shape. |
| 3362 | `handle_create_approval_gate` | `check_workflow_ownership` | `unwrap_or_literal` | check_workflow_ownership gate (create_approval_gate) | Unreadable ownership check defaults to false, refusing continuation_workflow_id as "not found or access denied" rather than accepting it. |
| 4640 | `handle_publish_built_in_templates` | `is_platform_admin` | `unwrap_or_literal` | is_platform_admin gate (publish_built_in_templates) | Unreadable admin status defaults to false, refusing the deployment-wide marketplace-listing mutation. |
| 5150 | `handle_create_workflow_suspension` | `check_workflow_ownership` | `unwrap_or_literal` | check_workflow_ownership gate (create_workflow_suspension) | Unreadable ownership check defaults to false, refusing continuation_workflow_id as "not found or access denied" rather than accepting it. |

### `talos-mcp-handlers/src/executions.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 2707 | `handle_pause_executions` | `is_platform_admin` | `unwrap_or_literal` | platform-admin gate (pause_executions) | Canonical is_platform_admin(uid).await.unwrap_or(false); a failed read refuses the deployment-wide pause rather than granting it. |
| 2765 | `handle_resume_executions` | `is_platform_admin` | `unwrap_or_literal` | platform-admin gate (resume_executions) | Canonical is_platform_admin(uid).await.unwrap_or(false); a failed read refuses the deployment-wide resume rather than granting it. |

### `talos-mcp-handlers/src/lib.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1194 | `handle_tools_list` | `list_template_world_overrides` | `unwrap_or_default` | tools/list capability-gated visibility | Failure blanks the world map so every non-"minimal" template's world becomes "unknown", hiding it from non-admin agents' tool list rather than over-exposing it. |

### `talos-mcp-handlers/src/ml.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 848 | `handle_eval_model` | `class_counts` | `ok` | policy_decision (eval_model) | A failed class_counts read yields PolicyJudgement::Unreadable, so no policy verdict is stored or a promotion gate honored; the read costs a refusal, not a pass. |

### `talos-mcp-handlers/src/modules.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 2771 | `handle_set_module_rate_limit` | `is_platform_admin` | `unwrap_or_literal` | set_module_rate_limit admin gate | is_platform_admin defaults false on failure, refusing the elevated catalog-wide rate-limit write rather than granting it. |
| 2893 | `handle_share_module_with_org` | `is_org_member_writable` | `unwrap_or_literal` | share_module_with_org writable gate | is_org_member_writable defaults false on failure, refusing the org-share write. |
| 2938 | `handle_list_org_modules` | `check_org_membership` | `unwrap_or_literal` | list_org_modules membership gate | check_org_membership defaults false on failure, refusing to expose the organization's modules. |

### `talos-mcp-handlers/src/ollama.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 151 | `handle_pull_model` | `is_platform_admin` | `unwrap_or_literal` | ollama_pull_model admin gate | is_platform_admin defaults false on failure, refusing the shared-Ollama-instance pull rather than granting it. |
| 244 | `handle_delete_model` | `is_platform_admin` | `unwrap_or_literal` | ollama_delete_model admin gate | is_platform_admin defaults false on failure, refusing the cross-tenant model-delete rather than granting it. |

### `talos-mcp-handlers/src/platform.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 444 | `handle_set_wasm_config` | `is_platform_admin` | `unwrap_or_literal` | set_wasm_config admin gate | is_platform_admin defaults false on failure, refusing the deployment-wide WASM resource-cap write rather than granting it. |
| 2121 | `handle_get_secret_access_log` | `is_platform_admin` | `unwrap_or_literal` | get_secret_access_log admin gate | is_platform_admin defaults false on failure, refusing the cross-tenant secret-access audit log rather than granting it. |

### `talos-mcp-handlers/src/resources.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 104 | `handle_resources_read` | `module_execution_owned_by` | `unwrap_or_literal` | execution-log resource ownership gate | module_execution_owned_by defaults false on failure, refusing to return the execution's logs rather than granting access. |

### `talos-mcp-handlers/src/sandbox.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1759 | `handle_run_sandbox` | `get_secrets_by_paths` | `unwrap_or_default` | secrets map (run_sandbox) | Failed secrets fetch yields an empty map, so the sandboxed module gets fewer secrets than declared, never more; vault:// refs then explicitly error out downstream. |
| 1770 | `handle_run_sandbox` | `get_llm_vault_keys` | `if_let_ok` | LLM vault keys (run_sandbox) | Failed LLM-key fetch just means no LLM provider keys are added to the secrets map; module ends up with less access, never more. |
| 1814 | `handle_run_sandbox` | `find_actor_for_user` | `unwrap_or_literal` | find_actor_for_user ownership check (run_sandbox) | Ownership check defaults to not-owned on failure, refusing with "Actor not found or not owned by you." |
| 1846 | `handle_run_sandbox` | `get_actor_max_llm_tier` | `ok` | llm_tier default (run_sandbox) | Explicitly documented: an unreadable actor tier defaults to the most-restrictive Tier1, never widening LLM egress access. |
| 3110 | `handle_test_module` | `find_actor_for_user` | `unwrap_or_literal` | find_actor_for_user ownership check (test_module) | Ownership check defaults to not-owned on failure, refusing the actor_id as not owned by the caller. |
| 3252 | `handle_test_module` | `get_secrets_by_paths` | `unwrap_or_default` | secrets map (test_module) | Failed secrets fetch yields an empty map, mirroring run_sandbox: the test module gets fewer secrets than declared, never more. |
| 3267 | `handle_test_module` | `get_llm_vault_keys` | `if_let_ok` | LLM vault keys (test_module) | Failed LLM-key fetch just means no provider keys are merged in; module ends up with less access, never more. |
| 3309 | `handle_test_module` | `get_actor_max_llm_tier` | `ok` | llm_tier default (test_module) | Explicitly documented: an unreadable actor tier defaults to Tier1, preventing a back door into Tier-2 external LLM egress via the dev-test surface. |
| 3335 | `handle_test_module` | `get_actor_max_write_ceiling` | `match_default` | test_module write-ceiling gate | DB error fails closed to WriteCeiling::ReadOnly and sets ceiling_unreadable=true, restricting rather than granting write. |

### `talos-mcp-handlers/src/webhooks.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 320 | `handle_create_webhook` | `module_accessible_by_user` | `unwrap_or_literal` | create_webhook module-access gate | module_accessible_by_user defaults false on failure, refusing webhook creation against that module rather than granting access. |
| 784 | `handle_get_webhook_security_stats` | `is_platform_admin` | `unwrap_or_literal` | webhook_security_stats blocked_ips disclosure | is_platform_admin defaults false on failure, hiding the deployment-wide blocked-IP list rather than exposing cross-tenant data. |
| 840 | `handle_reset_webhook_circuit_breaker` | `is_platform_admin` | `unwrap_or_literal` | reset_webhook_circuit_breaker admin gate | is_platform_admin defaults false on failure, refusing the deployment-wide circuit-breaker reset rather than granting it. |

### `talos-mcp-handlers/src/workflows.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 2936 | `handle_dispatch_to_actor` | `find_actor_for_user` | `unwrap_or_literal` | find_actor_for_user ownership check (dispatch_to_actor) | Ownership check defaults to not-owned on failure, refusing the dispatch rather than permitting it. |


## decorative — 60 sites

### `talos-api/src/schema/ml/queries.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 221 | `ml_model_disagreements` | `label_vocabulary` | `unwrap_or_default` | label_vocabulary buttons | Best-effort suggestion list for correct-label buttons; documented fallback to observed labels, claims nothing about model/dataset state. |

### `talos-api/src/schema/platform/queries.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 103 | `capability_ceiling_detail` | `get_user_email` | `unwrap_or_literal` | granted_by_email | Documented display-only enrichment; a failed lookup shows no granter email but makes no claim about the grant itself. |

### `talos-mcp-handlers/src/actor.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 2692 | `handle_set_actor_llm_tier_ceiling` | `get_actor_max_llm_tier` | `ok` | audit log "previous_tier" field | Previous-tier lookup is explicitly best-effort audit context only; the tier update itself proceeds and applies correctly regardless. |
| 2800 | `handle_set_actor_egress_scope` | `get_actor_egress_scope` | `ok` | audit log "previous_egress_scope" field | Comment states capture is best-effort; the egress-scope change itself proceeds and applies correctly regardless of this read. |
| 2905 | `handle_set_actor_write_ceiling` | `get_actor_max_write_ceiling` | `ok` | audit log "previous_ceiling" field | Previous-ceiling lookup only feeds the audit "old -> new" transition text; the write-ceiling change itself is unaffected. |

### `talos-mcp-handlers/src/advanced.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 2658 | `handle_list_published_modules` | `clone` | `unwrap_or_default` | "modules[].refs" pattern index (list_published_modules) | Filesystem template-scan failure only drops the "referenced by patterns" hint list; listing rows and star counts are untouched. |
| 3246 | `handle_agent_session_start` | `get_ids_without_embedding` | `unwrap_or_default` | background embedding-heal spawn (agent_session_start) | Fire-and-forget self-heal task; failure just skips this round's auto-embed with no effect on the returned report. |
| 3259 | `handle_agent_session_start` | `get_ids_without_capabilities` | `unwrap_or_default` | background capability-heal spawn (agent_session_start) | Fire-and-forget self-heal task; failure just skips this round's auto-suggest-capabilities with no effect on the returned report. |

### `talos-mcp-handlers/src/analytics.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 85 | `compute_capability_suggestions` | `get_capability_worlds_for_modules` | `unwrap_or_default` | capability tag suggestions | A failed capability-world read just yields fewer auto-tag suggestions on an opt-in background tagging pass; no claim about workflow state. |
| 118 | `compute_capability_suggestions` | `get_template_categories_lower` | `unwrap_or_default` | capability tag suggestions | A failed template-category read just yields fewer auto-tag suggestions on an opt-in background tagging pass; no claim about workflow state. |
| 725 | `handle_get_workflow_stats` | `get_error_messages` | `unwrap_or_default` | top error fingerprints list | Fingerprint list goes empty beside the accurate failed/succeeded counts computed separately; a diagnostic addendum, not the report's real numbers. |
| 3307 | `handle_get_error_report` | `get_workflow_graph_json` | `unwrap_or_literal` | node_label display in error report | Explicitly marked allow-benign-default: graph read used only to turn node UUIDs into display labels; failure counts stay untouched. |
| 4974 | `handle_get_workflow_dependency_map` | `list_module_and_template_names` | `unwrap_or_default` | module display names in dependency map | Module names fall back to the literal string "unknown" per id; the real module ids and usage relationships stay accurate and untouched. |
| 7018 | `handle_suggest_capabilities` | `get_capability_worlds_for_modules` | `unwrap_or_default` | suggested capability tags | Suggest_capabilities is an advisory tag recommendation tool; a failed read just yields fewer suggested tags, not a claim about the workflow. |
| 7045 | `handle_suggest_capabilities` | `get_template_categories_lower` | `unwrap_or_default` | suggested capability tags | Suggest_capabilities is an advisory tag recommendation tool; a failed read just yields fewer suggested tags, not a claim about the workflow. |

### `talos-mcp-handlers/src/configuration.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 372 | `handle_get_workflow_graph_render` | `list_template_names_by_ids` | `unwrap_or_else` | graph render module_names labels | Node display-name map for workflow-graph text rendering; failure falls back to raw ids, doesn't alter node/edge counts or structure. |
| 380 | `handle_get_workflow_graph_render` | `list_wasm_module_names_by_ids_unscoped` | `unwrap_or_else` | graph render module_names labels | Same node-label map (wasm module names half); failure just leaves labels unresolved in the rendered graph text. |
| 394 | `handle_get_workflow_graph_render` | `list_template_world_overrides` | `unwrap_or_else` | graph render module_worlds labels | Capability-world annotation shown next to node labels in graph render; failure omits the annotation only. |
| 404 | `handle_get_workflow_graph_render` | `list_wasm_module_worlds_by_ids` | `unwrap_or_else` | graph render module_worlds labels | Direct wasm-module world annotation for graph render text; failure omits annotation only, no structural claim. |
| 441 | `handle_get_workflow_graph_render` | `get_workflow_name_by_id` | `unwrap_or_else` | sub_workflow node label | Sub-workflow display name in graph render; failure falls back to printing the raw sub-workflow id string. |

### `talos-mcp-handlers/src/executions.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1456 | `handle_get_execution_logs` | `get_workflow_graph_for_user` | `ok` | node_id display label (execution logs) | Graph read feeds only build_node_label_map; on failure the raw node UUID is shown instead of a friendly label, no claim about system state. |
| 1962 | `handle_get_node_output` | `get_workflow_graph_for_user` | `ok` | labeled_keys in "node not found" message | Graph read only resolves display labels for the not-found error's suggestion list; the real output-key lookup logic is unaffected. |
| 2199 | `handle_compare_executions_summary` | `get_workflow_graph` | `ok` | node_label display (compare_executions diff) | Graph read feeds only the UUID-to-label map used to make the node diff readable; the diff content itself is untouched. |
| 2359 | `handle_get_execution_timeline` | `get_workflow_graph_for_user` | `ok` | node_label display (execution timeline) | Graph read feeds only build_node_label_map; on failure raw node UUIDs are shown in the timeline text instead of labels. |
| 3585 | `handle_watch_execution` | `get_workflow_graph_for_user` | `ok` | node_label / redacted config map (watch_execution) | Graph read feeds only display labels and a redacted per-node config map for error context; the real event data is untouched. |
| 3825 | `handle_get_execution_output` | `get_workflow_graph_for_user` | `ok` | node_label display (execution output) | Graph read feeds only display labels and a synthetic-node filter; on failure extra synthetic nodes may show rather than real output being hidden. |
| 3969 | `handle_get_execution_diff` | `get_workflow_graph` | `ok` | node_label display (execution diff) | Graph read feeds only the UUID-to-label map used to make the node diff readable; the diff content itself is untouched. |
| 4557 | `resolve_rf_id_from_label` | `get_workflow_name_and_graph` | `ok` | rf_id label resolution (best-effort) | Best-effort alternate label lookup for a single named node; failure just means the label search cannot try, no claim about system state. |
| 4598 | `resolve_rf_id_from_label` | `list_template_names_by_ids` | `if_let_ok` | rf_id label resolution (best-effort) | Best-effort module-name resolution inside the label lookup; a failed read just skips this resolution attempt with no false claim. |
| 4605 | `resolve_rf_id_from_label` | `list_wasm_module_names_by_ids_unscoped` | `if_let_ok` | rf_id label resolution (best-effort) | Best-effort module-name resolution inside the label lookup; a failed read just skips this resolution attempt with no false claim. |
| 4702 | `handle_get_execution_cost` | `get_workflow_graph_for_user` | `ok` | node_label display (execution cost) | Graph read feeds only display labels for the reconstructed per-node timing rows; the timing data itself is unaffected. |
| 4847 | `handle_get_execution_waterfall` | `get_workflow_graph_for_user` | `ok` | node_label display (execution waterfall) | Graph read feeds only display labels for the waterfall's node bars; on failure raw UUIDs are shown instead of labels. |
| 5316 | `build_execution_trace_json` | `get_workflow_graph_for_user` | `ok` | node_label display (execution trace) | Graph read feeds only build_node_label_map; on failure raw node UUIDs are shown in the per-node trace instead of labels. |

### `talos-mcp-handlers/src/graph.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 2563 | `handle_update_node_config` | `get_templates_by_ids` | `match_default` | blocked-vault-refs advisory warning | Advisory pre-flight text only; real secret-allowlist enforcement happens in the worker at runtime regardless of this read's outcome. |
| 2569 | `handle_update_node_config` | `find_template_id_via_wasm_module` | `ok` | blocked-vault-refs advisory warning | Template-id resolution fallback for the same advisory warning; failure just falls back to the unresolved id, warning may be omitted. |
| 2577 | `handle_update_node_config` | `get_templates_by_ids` | `if_let_ok` | blocked-vault-refs advisory warning | Comment states the check is deliberately skipped silently on read failure; validate_workflow remains the real backstop. |
| 4688 | `handle_add_error_handler` | `suggest_template_names_like` | `unwrap_or_default` | module-name suggestion list | "Did you mean" suggestion list shown beside the not-found error; absence just yields fewer suggestions. |
| 4701 | `handle_add_error_handler` | `suggest_template_names_like` | `unwrap_or_default` | module-name suggestion list (word match) | Second-pass word-level suggestion list; failure just yields fewer/no suggestions in the hint text. |
| 4719 | `handle_add_error_handler` | `suggest_template_names_trgm` | `unwrap_or_default` | module-name suggestion list (trigram) | Trigram-similarity suggestion fallback; failure just yields fewer suggestions in the hint text. |
| 4728 | `handle_add_error_handler` | `list_template_names_alphabetical` | `unwrap_or_default` | module-name suggestion list (alphabetical) | Final alphabetical fallback suggestion list; failure yields "Call list_modules" generic hint instead of names. |

### `talos-mcp-handlers/src/ml.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1141 | `handle_get_model_card` | `stats` | `ok` | dataset_stats block (model card) | Stats read failure renders dataset_stats null on an informational model-card block; absence is not a determinate claim about the model. |
| 1152 | `handle_get_model_card` | `shadow_epoch` | `ok` | shadow epoch number (model card) | Epoch read failure is explicitly disclosed in the rendered text as "current epoch (number unavailable)" rather than a false claim. |
| 1161 | `handle_get_model_card` | `shadow_agreement` | `ok` | shadow agreement block (model card) | Shadow-agreement read failure renders the whole shadow block null; an informational card field, not a verdict acted upon. |
| 1167 | `handle_get_model_card` | `shadow_agreement_lifetime` | `ok` | shadow_lifetime block (model card) | Lifetime shadow-agreement read failure renders the block null; an informational card field, not a verdict acted upon. |
| 1178 | `handle_get_model_card` | `unwrap_or` | `ok` | teacher_audit block (model card) | Teacher-audit read failure renders the field null, identical to "audit never run"; an informational card block, not an acted-upon verdict. |
| 1687 | `handle_disagreements` | `label_vocabulary` | `unwrap_or_default` | label_vocabulary hint (disagreements digest) | Explicitly best-effort per its own comment: a missing dataset or read failure just omits the labelling hint, never fails the review. |

### `talos-mcp-handlers/src/modules.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 4116 | `handle_find_module_alternatives` | `insert` | `unwrap_or_default` | display_to_slug install-hint map | Install-slug lookup used only to enrich "alternatives" results with a catalog install hint; absence just omits the hint. |

### `talos-mcp-handlers/src/platform.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1782 | `handle_call_a2a_agent` | `as_u16` | `unwrap_or_literal` | a2a call response body relay | Bounded JSON body read of a caller-specified external agent's HTTP response; failure just relays {} for that remote payload, not a Talos state claim. |

### `talos-mcp-handlers/src/sandbox.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1127 | `handle_compile_custom_sandbox` | `find_compiled_sandbox_template` | `ok` | "existing_template" compile-dedup cache (compile_custom_sandbox) | Failed dedup-cache lookup just causes a normal fresh compile instead of a cache hit; no security or correctness effect, only lost time savings. |
| 2622 | `handle_update_module_secrets` | `get_multiplexed_async_connection` | `if_let_ok` | Redis wasm-bytes cache invalidation (update_module_secrets) | Best-effort DEL of a WASM-bytes cache key; allowed_secrets is always read fresh from Postgres at dispatch, so a failed invalidation changes no enforced behaviour. |
| 2784 | `handle_update_module_hosts` | `get_multiplexed_async_connection` | `if_let_ok` | Redis wasm-bytes cache invalidation (update_module_hosts) | Same best-effort cache DEL; allowed_hosts is read fresh from Postgres at dispatch regardless of this cache's state. |
| 2924 | `handle_update_module_methods` | `get_multiplexed_async_connection` | `if_let_ok` | Redis wasm-bytes cache invalidation (update_module_methods) | Same best-effort cache DEL; allowed_methods is read fresh from Postgres at dispatch regardless of this cache's state. |

### `talos-mcp-handlers/src/search.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 628 | `handle_find_similar_workflows` | `list_template_names_by_ids` | `ok` | shared_modules name enrichment | Module-id-to-name map used only to prettify shared_modules with human-readable labels; failure falls back to bare UUIDs. |

### `talos-mcp-handlers/src/workflows.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 2408 | `handle_add_node_to_workflow` | `find_template_id_via_wasm_module` | `ok` | resolved_tid id-resolution (add_node_to_workflow) | Failed wasm_modules-to-template_id FK lookup just falls back to using the given id verbatim for the subsequent template fetch, same net effect as a legitimate not-found. |
| 2636 | `handle_add_node_to_workflow` | `get_max_fuel` | `ok` | "applied_max_fuel" confirmation field (add_node_to_workflow) | Display-only confirmation number in the response checklist; the node's config/fuel was already persisted successfully before this read. |
| 2871 | `handle_trigger_workflow` | `build_execution_trace_json` | `match_default` | fallback trigger-status text | Trace-render failure falls back to an honest status line with the real execution_id/status, pointing to get_execution_status. |
| 3700 | `handle_get_workflow_full` | `get_module_names` | `match_default` | module_name display label | Err empties the name map; only the cosmetic module_name label falls back to "unknown", the real module_id is untouched. |
| 8182 | `handle_get_workflow_summary` | `get_module_names` | `unwrap_or_default` | "module_names" display names (get_workflow_summary) | Already carries an explicit allow-benign-default marker: display names only, the ids and every count beside them are untouched. |
| 10365 | `handle_swap_node_module` | `get_templates_by_ids` | `unwrap_or_default` | "_old_schema_keys" (swap_node_module) | Computed value is never read anywhere else in the function (dead, underscore-prefixed variable); a failed read has no observable effect on the response. |
| 12059 | `handle_write_semantic_cache` | `clone` | `if_let_ok` | background embedding fill (write_semantic_cache) | Fire-and-forget embedding backfill for the semantic cache; failure only means this entry stays findable by exact-hash, not fuzzy match — the cache write itself already succeeded. |


## false-positive — 31 sites

### `talos-api/src/schema/modules/mutations.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 489 | `create_module_from_template` | `join_all` | `if_let_ok` | orphaned watch-channel cleanup | join_all awaits best-effort cleanup tasks whose own errors are already logged per-task; not a benign-default collapse of a decision-relevant read. |

### `talos-api/src/schema/subscriptions.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 64 | `refresh_dlq_permissions` | `list_user_org_ids` | `match_default` | the returned DlqPermissions | #783 extracted the refresh into a pure function whose Err arm NARROWS to own-events-only. The detector sees a substituted value; the value is the most restrictive one available, so it grants nothing — fail-closed by outcome and a false positive as a claim. |

### `talos-mcp-handlers/src/actor.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1906 | `handle_get_actor_summary` | `get_actor_ceilings` | `match_default` | ceilings error object | Err arm returns an explicit "NOT MEASURED" disclosure object naming the DB problem, not a benign default ceiling. |
| 2001 | `handle_suspend_actor` | `get_actor_status` | `unwrap_or_literal` | suspend_actor terminal-state check | DB UPDATE carries AND status NOT IN ('archived','terminated'); Ok(0) arm re-renders the same terminal-state error, so a swallowed pre-check read cannot bypass enforcement. |
| 2273 | `handle_update_actor_status` | `get_actor_status` | `unwrap_or_literal` | update_actor_status terminal-state check | Same defense-in-depth SQL guard (status NOT IN archived/terminated) as suspend_actor; Ok(0) arm surfaces the correct refusal even if the handler-side read failed. |
| 5579 | `handle_suggest_actor_for_task` | `generate_embedding` | `ok` | "method" field (suggest_actor_for_task) | Embed failure is the documented no-embedding branch; method is then correctly reported as keyword_fallback, matching what actually ran. |
| 5599 | `handle_suggest_actor_for_task` | `find_actors_by_memory_similarity` | `if_let_ok` | "method"/"suggestions" (suggest_actor_for_task) | Vector-search Err falls through to the keyword-overlap loop below and method stays accurately "keyword_fallback"; no false claim rendered. |
| 6690 | `handle_get_few_shot_examples` | `generate_embedding` | `ok` | "method" field (get_few_shot_examples) | Same documented best-effort embed-then-keyword fallback as the sibling generate_embedding site; keyword fallback answer is accurate. |

### `talos-mcp-handlers/src/analytics.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 4780 | `handle_get_node_failure_breakdown` | `get_node_failure_details` | `if_let_ok` | node_failure_breakdown response | Full match properly propagates Err via mcp_error("Failed to query node failure breakdown"); nothing is collapsed into a default. |
| 7354 | `handle_get_fuel_usage_report` | `get_node_fuel_headroom` | `match_default` | headroom_rows / Readings ledger | Err arm marks the Readings field derived and returns an explicit note that the empty list is not evidence of safety. |

### `talos-mcp-handlers/src/executions.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 6119 | `handle_get_execution_lineage` | `get_execution_lineage_root` | `match_default` | root_execution_id / lineage_note | RECLASSIFIED 2026-09-08: repaired by #782. The Err arm still substitutes the anchor (there is no better id to walk from) but it sets root_unreadable, which renders root_execution_id as null and takes lineage_note's FIRST arm — an explicit "could not be read" that outranks every other. The substitution is DISCLOSED, so no field claims anything; the detector correctly still sees a default. Same shape as dlq_updates. |
| 6145 | `handle_get_execution_lineage` | `get_execution_lineage_tree` | `match_default` | tree_degraded flag consumed by lineage_note | Err arm sets tree_degraded=true, which lineage_note renders as an explicit "could not be read" disclosure, not a claim. |
| 6176 | `handle_get_execution_lineage` | `list_for_parent` | `match_default` | child_runs (None) / child_runs_error consumed by child_runs_note | Err arm yields None (never []) plus an explicit error string, rendered as UNKNOWN via child_runs_note, not a claim. |

### `talos-mcp-handlers/src/graph.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 4121 | `handle_duplicate_workflow` | `copy_input_schema` | `match_default` | input_schema_copied boolean | Err correctly sets input_schema_copied=false, the accurate outcome of the failed copy, disclosed via a warn log. |

### `talos-mcp-handlers/src/modules.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 3184 | `handle_list_module_catalog` | `unwrap_or_default` | `if_let_ok` | CATALOG_CACHE get_or_init clone | get_or_init returns the cached Vec directly (no Result at this line); the only fallible collapse is the inner unwrap_or_default already counted at 3181. |
| 3238 | `handle_list_module_catalog` | `cmp` | `if_let_ok` | the catalog listing | #784 moved the disk walk to get_or_try_init so a failure is no longer MEMOIZED; the following match REFUSES. The binding leg reads the sort comparator inside the initialiser as a collapse. |
| 3241 | `handle_list_module_catalog` | `map_err` | `if_let_ok` | the catalog listing | The other half of the same get_or_try_init artefact: the Err arm refuses, so nothing is defaulted. |
| 3771 | `handle_install_module_from_catalog` | `pin_user_module` | `match_default` | pinned flag + pin_warning text | Err correctly sets pinned=false and returns an explicit pin_warning message disclosing the pin failure. |
| 3957 | `handle_restore_pinned_modules` | `update_template_precompiled_wasm` | `match_default` | failed[] entry with reason string | Err arm pushes a failed-module entry naming "compilation succeeded but failed to save", an explicit disclosed failure. |

### `talos-mcp-handlers/src/ops_alerts.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 256 | `handle_correct` | `correct_severity` | `match_default` | database_error response | Err arm returns crate::utils::database_error, a proper propagated refusal, not a substituted default value. |
| 293 | `handle_digest` | `digest` | `match_default` | database_error response | Err arm returns database_error; no benign default digest is substituted for the caller. |
| 326 | `handle_cleanup` | `delete_resolved_older_than` | `match_default` | database_error response | Err arm returns database_error rather than fabricating a "deleted" count. |

### `talos-mcp-handlers/src/platform.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 983 | `read_audit_chain_candidate` | `latest_verifiable_ledger_target` | `match_default` | AuditChainCandidate::Unreadable variant | Err arm yields the explicit Unreadable variant, distinct from NoneEligible, an honest three-way classification. |

### `talos-mcp-handlers/src/sandbox.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1249 | `handle_compile_custom_sandbox` | `sandbox_template_name_exists` | `unwrap_or_literal` | name-collision pre-check (compile_custom_sandbox) | modules_user_name_uniq is a real DB unique index enforced on INSERT; a swallowed pre-check only wastes a compile and returns a generic DB error instead of the friendly duplicate message. |
| 1640 | `handle_run_sandbox` | `lint_code` | `if_let_ok` | lint pre-flight (run_sandbox) | compile_to_wasm_with_config re-runs the identical analyze::lint_source_code pass and is the actual enforcing gate; the pre-flight is advisory-only per the surrounding comment. |
| 2114 | `handle_compile_template` | `wasm_module_name_exists` | `unwrap_or_literal` | name-collision pre-check (compile_template) | Same modules_user_name_uniq DB constraint backs this check; store_module_fresh has no ON CONFLICT so a real duplicate name still errors out cleanly instead of silently succeeding. |

### `talos-mcp-handlers/src/schedules.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 609 | `handle_get_schedule_health` | `get_scheduled_24h_execution_stats` | `match_default` | schedule health stats (total/succeeded/failed) | Zeroed stats are pushed with an explicit data_warnings note that "zeros below are not authoritative", disclosing the failure. |
| 651 | `handle_get_schedule_health` | `list_recent_scheduled_execution_statuses` | `match_default` | execution-status streak list | Empty status list is pushed with an explicit data_warnings note that the streak is unavailable due to a query failure. |

### `talos-mcp-handlers/src/workflows.rs`

| line | function | read | spelling | consumer | what a failed read produces |
|---|---|---|---|---|---|
| 1677 | `handle_create_workflow` | `get_templates_by_ids` | `match_default` | template_max_retries_map fallback (create_workflow) | Empty map on read failure falls through to the engine's own documented method-aware absent-policy default at dispatch time; no fleet-wide retry-disabling regression. |
| 5863 | `handle_import_workflow` | `upsert_wasm_module` | `match_default` | the per-module reason in the "could not be reconstituted" refusal | RECLASSIFIED 2026-09-08: the arm still pushes onto still_missing — the module genuinely is not importable — but it now carries its REASON, and the refusal renders "<id> (compiled successfully, but the module could not be WRITTEN (database failure) — the bundle is fine)". The one-sentence-for-five-causes claim is gone; what is left is a classified failure list, not a claim. |
| 11919 | `handle_check_semantic_cache` | `unwrap_or_default` | `ok` | outgoing JSON serialization (check_semantic_cache) | unwrap_or_default sits on to_string_pretty of a hard-coded json! literal for the response body, not on a collapsed data read at all. |

