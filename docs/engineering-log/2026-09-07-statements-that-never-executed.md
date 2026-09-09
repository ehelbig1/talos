<!-- Archived narrative, moved VERBATIM out of CLAUDE.md. Do not reword: the
     digest in CLAUDE.md's "Engineering log" section points here, and
     `scripts/check-engineering-log.py` proves every removed line still
     appears here. New decisions go in CLAUDE.md first. -->

## A statement that has never once executed, rendered as "nothing here" (2026-09-07)

Three surfaces asserted a determinate negative — the misleading-report class
(checks 74, 76, 79/79b, 81) — with a cause none of those checks can see: **the
SQL never ran.** `sqlx::query("…")` takes a runtime `&str`, so a statement
naming a renamed column is invisible to rustc, to clippy and to CI's sqlx
offline cache (which covers only the `query!` MACRO forms). The population is
now measured and gated by **check 88**.

**(Y1) `webhooks: []` from a statement that cannot PREPARE.**
`AnalyticsRepository::list_workflow_webhooks` asked `webhook_triggers` for
`endpoint_path` and `is_enabled`. That table's flag column is `enabled`, and
there has never been an `endpoint_path` column **at all** — the endpoint is
DERIVED from the id (`/webhooks/{id}`), which is why the statement could not be
repaired by a rename and why `webhook_endpoint_path` now has ONE home. Its
caller `get_workflow_dependencies` did `.unwrap_or_default()`, so `webhooks: []`
and `webhook_count: 0` were a determinate negative on every call. **The brief
named one statement; there were two** — `list_webhooks_for_modules` is
byte-identical in its column list and feeds `list_workflow_triggers`, which DOES
route the read through a `Readings` ledger, so that tool has been honestly
reporting `webhooks: not_measured` forever. Both now bind `user_id` as well:
the callers do gate ownership upstream, but `workflow_id` is not the tenant half
and check 70's lesson is that a statement should not rely on caller discipline.
All three reads in `handle_get_workflow_dependencies_list` now go through a
`Readings` ledger, and each COUNT is marked derived exactly when ITS OWN source
read failed — not whenever anything failed, because `module_count` comes from
the graph and is still measured when the NAME lookup is not.

**(Y2) A filter on a status the schema does not have.** `workflows_needing_schema`
filtered `w.status = 'published'`. The lifecycle enum is `draft | active |
archived` (migration `20260318000000`) and `handle_list_workflows` **refuses
`published` as a filter value in so many words** — *"the schema has no rows with
that value so accepting it would silently return an empty list"* — so the
hygiene check reported `[]` and `count: 0` for every operator on every run.
**The brief said nothing has ever written that value; that is refuted.** Exactly
one writer does — `insert_published_internal_workflow`, used by
`plan_and_execute_workflow` — and it writes `workflow_type = 'internal'` in the
SAME INSERT, which the predicate's very next clause EXCLUDES. So the filter was
not merely unmatched, it was **self-contradictory**: the only rows the status
clause admits are rows the type clause rejects. (Live fleet: 0 at
`status='published'`, 0 at `workflow_type='internal'`; 17 active / 11 draft / 8
archived.) The same literal was in a SECOND reader the brief did not name —
`ActorRepository::list_published_workflows_for_actor`, the **A2A agent card**,
so every actor's card advertised ZERO workflows and an empty card was
indistinguishable from an actor that owns none. Both now read
`talos_workflow_liveness::live_sql`.

**And the writer itself could never have written a row.** Driving
`insert_published_internal_workflow` in a DB test fails `23502`: it omits
`workflows.module_uri`, which is `NOT NULL` with no default, while every other
graph-workflow INSERT in that file binds `''`. So `plan_and_execute_workflow`
failed at its first write. **A PREPARE probe cannot see this** — the statement
parses and plans perfectly and only a real INSERT trips the constraint — which
is the sharpest statement of check 88's limits, and it was found by a test
rather than by the probe.

**(Y3) Three trigger paths, three different answers.** `trigger_workflow`
refused `is_enabled = false` and nothing else; `bulk_trigger_workflow` and
`enqueue_workflow` applied **no liveness predicate at all**. So an ARCHIVED
workflow was dispatchable from all three and a DISABLED one from two — check
78's "three of four entry points refused", one tool over. Archiving does **not**
clear `is_enabled` (none of the five `SET status = 'archived'` statements touch
that column), so on the reference fleet **all 8 archived workflows are
`is_enabled = true`** and nothing protected them incidentally. The decision is
`talos_workflow_liveness::is_dispatchable` — **deliberately NOT
`not_live_reason`**, which the brief named: a DRAFT must stay dispatchable
(`trigger_workflow` has always run one, a parent dispatches a child's draft
`graph_json` with no status predicate, and 11 of 36 workflows here are drafts,
4 with enabled schedules), so gating on LIVENESS would refuse those and create a
NEW disagreement in place of the one this closes. `not_live_reason` answers a
REPORTING question; a trigger gate is a DISPATCH question.
`OrchestrationError::WorkflowNotLive` is a new variant rather than a reuse, and
the exhaustive matches made the compiler name all four mapping sites — including
`talos-evaluation`'s, whose `_` arm would have rendered a deliberate policy
refusal as *"execution dispatch failed"* and sent an operator to look at NATS
(check 81(c)'s shape). `WorkflowDisabled` is KEPT for `replay`, which asks the
narrower question off a boolean it reads directly.

**Two behaviour changes, both new refusals, both stated plainly**: an archived
workflow can no longer be triggered from any of the three paths (it could from
all three), and a disabled one can no longer be bulk-triggered or enqueued. Both
gates sit ABOVE the graph load and the per-input loop, so a refusal costs no
dispatch and no partial batch an operator has to cancel.

**What was measured and NOT done.** The `is_enabled` gate is functional but
LATENT on this fleet — nothing is currently disabled — so the only refusal this
change can produce today is the archived one. The scheduler / webhook /
capability-resolution dispatch paths are deliberately untouched. And no live
trigger was fired against an archived workflow to demonstrate the pre-fix
behaviour, because doing so would EXECUTE it on the operator's only
environment; the evidence is the code (no path reads `status`, and
`WorkflowRecord` has carried it the whole time), the schema, and the fleet
counts above.

**One finding recorded and NOT fixed**: `controller/tests/common`'s
`create_test_organization` omits the `NOT NULL` `slug`, so it fails on every
call. It is the same class inside the harness; its other callers are outside
this change and `dead_statement_tests` seeds its own row instead.
