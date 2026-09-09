<!-- Archived narrative, moved VERBATIM out of CLAUDE.md. Do not reword: the
     digest in CLAUDE.md's "Engineering log" section points here, and
     `scripts/check-engineering-log.py` proves every removed line still
     appears here. New decisions go in CLAUDE.md first. -->

## 2026-09-07 — the population behind checks 74 / 76 / 79 / 81: 210 collapsed reads, 110 of them claims

Every prior entry in this family repaired a SITE and named a class. This one
MEASURED the class. `talos-mcp-handlers/src` + `talos-api/src` hold **210**
awaited repository/service reads collapsed into a default, and **110 of them
are CLAIMS** — the default becomes a count, a list, a verdict or a "not found"
that a caller reads and acts on. The full per-site table (file, line, function,
spelling, verdict, the field it feeds) is in the branch's `AGENT_NOTES.md`; the
counts and the decisions are here so nobody re-measures.

**The inventory is statement-aware, and that is why it is bigger than a grep.**
Comment and string content is masked first (so a doc comment quoting the banned
expression cannot self-report — check 73's trap), then the POSTFIX METHOD CHAIN
after each `.await` is walked, so the house style's broken chain is one
statement; a collapse counts only if it precedes any `?`. Per spelling:
`.unwrap_or_default()` **66**, `.unwrap_or(<literal>)` **55**, `.ok()` **32**,
`match … { Err(_)/_ => <default> }` **26**, `if let Ok(..) = ….await` /
`let Ok(..) = … else` **24**, `.unwrap_or_else(…)` **7**.

**Classification: 110 claim / 67 decorative / 32 fail-closed / 1 detector false
positive.** `fail-closed` is dominated by ONE shape —
**15** of the 32 are `is_platform_admin(uid).await.unwrap_or(false)`, which
check 74's opt-out already names as correct. The false positive is
`handle_trigger_workflow_as_actors`, a correct three-way match whose INNER
`actor.status` arm the window matched: stated rather than dropped, because a
detector's limits are worth as much as its findings.

**ELEVEN sites were fixed, in three SHAPES, and 99 claim sites were not.**
Saying so plainly is the point — a fix set chosen as a prefix of a list teaches
nothing, and half-fixing a class to satisfy a gate is how the glob got its
blind spot.

* **A refusal that asserts NON-EXISTENCE on a read that failed.**
  `actor::resolve_actor_via_repo` is the ownership gate behind **20+** actor
  tools and its `Err(_)` arm rendered *"Actor not found or access denied"* —
  false on both clauses while the database is the broken thing. The correct
  three-way shape was already in the same crate
  (`evaluation::ensure_actor_owner` splits `Err(_) => "actor ownership check
  failed"`), so this is a rule that failed to REPLICATE, exactly as check 79
  records about the four integration handlers.
  `knowledge_graph::require_owned_actor` is the byte-identical twin.
  `ml::require_dataset_owner` needed the CALLEE fixed first — check 79's leg (b)
  verbatim: `DatasetService::dataset_tenancy` folds absence INTO `Err`, so
  `Ok(None)` was structurally unreachable and no call-site split was possible.
  `lookup_dataset_tenancy` is the three-way read; `dataset_tenancy` stays as a
  documented FLATTENING projection because its eight in-crate callers propagate
  with `?`, i.e. FAIL rather than claim.
* **A swallowed read driving a DESTRUCTIVE or inventory decision.**
  `handle_cleanup_module_versions` read `refs.is_empty()` as "nothing points at
  this module → deletable", and its reference read was `.unwrap_or_default()` —
  so with `dry_run: false` an IRREVERSIBLE delete was decided by a query that
  did not answer (check 86's shape on a path that deletes rather than
  recommends). Held-back modules are excluded from `deletable` AND disclosed
  under `unknown_references`, with the sentence saying why its count is short.
  `handle_batch_delete_modules`'s classification default is fail-closed for the
  DELETE and NOT for the REPORT — it told the caller, by name, that each of
  their modules does not exist — and now refuses. `handle_list_templates` /
  `handle_list_modules` refuse too: an empty listing is the premise of every
  next step an operator takes, and there is no partial answer to give.
* **A COUNT or LIST rendered as a report field.**
  `handle_get_workflow_summary` answered a database failure with the four most
  reassuring numbers it can produce — `total: 0`, `versions: 0`,
  `active_schedules: 0`, `active_webhooks: 0`, i.e. *never run, never published,
  nothing triggers it*, which is the reading an operator uses to decide a
  workflow is safe to retire. **That handler already had a DOCUMENTED case of
  this swallow hiding a real bug**: `get_workflow_schedule_count`'s own comment
  records that the query named a column that does not exist (`is_active` vs
  `is_enabled`) and *"handler `unwrap_or(0)` swallowed the column-not-found
  error and `get_workflow_summary` reported `active_schedules: 0` for every
  workflow, including ones with active schedules"* — the QUERY was fixed in May
  2026 and the SWALLOW was left in place, the sixth local repair of a class with
  no population sweep behind it. `handle_list_executions` fell back to
  `rows.len()` — the PAGE LENGTH — so an unreadable count over 4 000 executions
  rendered `total: 20, has_more: false` and a caller paging on that envelope
  stops at the first page believing it has everything.
  `handle_get_catalog_status` is a DIFF, so an unreadable `list_catalog_rows`
  put every disk template in `on_disk_not_in_db` and emitted *"restart the
  controller to seed"* — specific, actionable, wrong advice about a healthy
  catalog. `handle_get_execution_replay_chain`'s empty `ancestors` /
  `descendants` are the same determinate negatives #771 removed from
  `get_execution_lineage`'s "standalone run" sentence one tool over.

**Three of the eleven are pinned by a DB test that drives the REAL
`McpState` and the production `dispatch`**
(`controller/tests/swallowed_read_disclosure_tests`, CTRL_TESTS per check 64b —
it is a `mod common` binary). The failure mechanism is package 22's: the
RELATION the read names is DROPPED in the per-test isolated database, so the
statement cannot run. It builds a real state rather than a stand-in because the
defect is what the handler BODY renders — checks 74b and 79b both state, as
their own limit, that a guard at the READ cannot see an answer classified
correctly and discarded further down. Every test carries its CONTROL in the same
run (a fresh user really does have zero modules; a workflow with no schedules
really does report `0`; an actor that is genuinely absent keeps the not-found
sentence), because a healthy response must stay byte-identical and only a
degraded one may change shape. Three mutations reinstating main's expressions
are all RED — and M2's response was literally `{"count": 0, "modules": []}` with
the view DROPPED.

**The lint candidate was BUILT, MEASURED and REJECTED — `--count` stays 87.**
Widening check 74 from its name glob to EVERY handler for
`.unwrap_or_default()` / `.unwrap_or(Vec::new())` / `.unwrap_or(0)` over an
awaited read reports **73 on pristine main, 61 of them claims — 83.6 %
precision**, which sits between check 74's #730 group (81.8 %) and its
2026-09-02 group (94.1 %). Precision is not the problem. It would ship at
**62** on this tree, i.e. as a ratchet with a baseline, and "do NOT re-add a
baseline" is check 52's own rule (#760: *"a check cannot ship at 21"*). The
twelve false positives are the same shape every time — a display name or a
suggestion list beside untouched counts. **What ships instead costs no check
number: sub-leg 74b covers the three repaired report handlers AUTOMATICALLY**,
because its scope is DERIVED ("any function constructing a `Readings`") and they
enrolled themselves by adopting the ledger. That is not a theoretical
convenience — **74b fired on the first lint run after the fixes**, at
`handle_get_catalog_status`'s disk scan, where a `JoinError` defaulted to an
EMPTY template list that reads as "this image carries no catalog templates". A
filesystem read inside a catalog tool is exactly what a hand-maintained glob
would never have looked at. The way to extend the coverage is to fix a handler,
not to widen a regex.

**Two fail-OPEN gates are RECORDED and not fixed**, and they outrank the
remaining report sites for whoever takes the next pass:
`search::handle_tag_workflow` skips the 100-tag cap when the count read fails,
and `sandbox::handle_run_sandbox` skips the LINT step entirely on
`if let Ok(lint_errors)`. (**Both CLOSED 2026-09-07 — see the fail-OPEN entry
below, which also refutes the second one's framing: the lint step is duplicated
by the full compile and was never a gate.**) And
`analytics::handle_get_workflow_dependencies_list`
(`schedules`, `webhooks`) is deliberately untouched: it is the site the sibling
PR #775 fixes.

### 2026-09-07 — the fail-OPEN half: eight gates that stopped gating, and one that had never gated at all

The entry above closed eleven CLAIM sites and recorded two fail-OPEN gates as
"not fixed". Both were wrong about what they were, and the class was bigger than
two. **A gate that cannot read its rule must REFUSE; it must never GRANT.**

**The inventory was REBUILT as a checked-in artefact**, because package 23's
detector and its classification table were lost with its worktree and a
CLAUDE.md sentence must not cite an artefact the merge discards.
`scripts/lint-swallow-classify.py` (statement-aware: comment and string CONTENT
masked first — check 73's trap — then the postfix chain after each `.await`
walked, a collapse counted only before any `?`) plus
`scripts/swallow-read-verdicts.py` render `docs/swallowed-reads-inventory.md`,
the read-side companion to `docs/swallowed-results-inventory.md`. Run against
`38175869` — the tree package 23 measured — the rebuild reports **208** against
its reported **210**, so the two independent detectors agree to within 1%. On
`origin/main` `0c962874` it reports **193** sites: **65 claim, 60 decorative,
37 fail-closed, 5 fail-open, 26 false-positive**.

**The lint pre-flight was NOT a security gate, and the measurement changed the
fix.** `handle_run_sandbox`'s `if let Ok(lint_errors) = …lint_code(..)` was
carried as "the sandbox runs unlinted". It does not:
`compile_to_wasm_with_config`, which runs immediately afterwards, executes the
IDENTICAL `analyze::lint_source_code` static pass at its step 0a and refuses on
its errors, and it alone enforces the dependency allowlist and cargo-audit. So
nothing `lint_code` checks is unique to it, and refusing would take
`run_sandbox` off the air on the most likely `Err` this call produces — "Lint
queue full. Try again shortly.", the 60 s compilation-semaphore timeout — for a
request the full compile would have served. What was wrong is the SILENCE:
`talos_inline_compile_service` already reached this conclusion for the same call
and logs it (its L-32 arm), while this site and `talos_workflow_creation::spec`
did not. One function, three call sites, one disclosing. Both now WARN.

**The real fail-open the brief did not name is the CAPABILITY-WORLD CEILING, and
it is MCP-545 unswept.** `talos_actor_repository::get_actor_max_world` returns
`Option<String>` and answers `None` on a database error; its own body logs
*"caller may default to permissive ceiling — wire try_get_actor_max_world to
fail closed"*, and the strict sibling's doc says *"New code that gates
authorisation on the ceiling should call this"*. MCP-545 wired the two RUNTIME
gates in `talos-workflow-authorization` and never reached the three
authoring/compile-time siblings, each of which wrapped the whole gate in
`if let Some(max_world) = …`: `run_sandbox` (which COMPILES AND EXECUTES
caller-supplied Rust at the requested world — the highest blast radius in the
package), `compile_custom_sandbox`, and `add_node_to_workflow`. One home now:
`crate::utils::read_actor_ceiling_or_refuse`. `Ok(None)` deliberately keeps
today's behaviour, **matching MCP-545's own decision** —
`actors.max_capability_world` is `TEXT NOT NULL DEFAULT 'minimal-node'`, so
`Ok(None)` can only mean "no such actor row", and refusing it would make the
authoring gate stricter than the runtime one, which is the same defect in the
other direction.

**All EIGHT fail-open sites are fixed**: the three ceilings above, plus
`add_node_to_workflow`'s module-world read (the OTHER half of the same gate) and
its `get_templates_by_ids` read (which gates the ONLY pre-flight a node config
gets — schema, patterns, vault grants and the template's retry policy),
`tag_workflow`'s 100-tag cap, `create_webhook`'s name-uniqueness pre-flight
(nothing downstream backs it: `webhook_triggers.name` carries no unique index,
and the per-user CAP three lines below already fails closed under MCP-367 — two
gates in one function disagreeing), and `dlq_updates`'s periodic permission
refresh, which on a failed read KEPT the prior org set, so a subscriber whose
access had just been revoked went on receiving another org's DLQ events. That
last one now NARROWS to own-events-only rather than terminating the stream, and
self-heals on the next successful tick.

**The tag cap had never once been evaluated, and its own swallow is why.** With
the swallow removed, the CONTROL arm of the new DB test failed on an INTACT
schema. Measured: `get_tag_count` selects `coalesce(array_length(tags, 1), 0)`,
which is INT4, into an `i64`, so it returns
`ColumnDecode { "Rust type `i64` (as SQL type `INT8`) is not compatible with SQL
type `INT4`" }` **on every call that finds a row**. `fetch_optional` answers
`Ok(None)` when nothing matches, so a nonexistent workflow looked healthy; the
statement PREPAREs and PLANs perfectly, so **check 88 cannot see it**. This is
check 88's `COUNT(*) … FOR UPDATE` finding in a second shape: a swallow hiding a
query that could never run. Fixed on both sides (`::bigint` in the repository,
refusal at the handler). No sibling: every other `array_length` in the workspace
sits in a boolean predicate or a `COUNT(*)`.

**Thirteen CLAIM sites were fixed on top, chosen by BLAST RADIUS rather than by
position in the list.** Ranked: `submit_workflow_approval` answered a failed
approval WRITE with *"No pending approval found for this execution. It may have
already been decided"* — the one diagnosis that stops a retry, on a
human-approval gate; `export_workflow` shipped a bundle carrying `modules: []`
with no flag, a corrupt backup byte-indistinguishable from a module-less
workflow that `import_workflow` would reconstitute without the modules;
`import_workflow` marked EVERY referenced module missing on a failed existence
read and recompiled each from the bundle (the correct handling of that exact
read is 4300 lines up in the same file); `get_module_dependents` answered
`indirect_count: 0` — "nothing depends on this" — on the tool an operator
consults before deleting a module; `whoami` rendered the hardcoded literal
`http-node` as the user's authorization ceiling and `false` for admin;
`get_execution_cost` rendered `total_fuel_consumed: 0`, "this execution cost
nothing"; and `build_execution_trace_json` rendered `sub_execution_count: 0` in
three surfaces at once. **Check 74b then found three more in the two functions
that had just adopted `Readings`, which is the leg working exactly as its own
entry describes** — a handler enrols itself by adopting the ledger, so the way
to extend the coverage is to fix a handler rather than widen a regex. Two are
the execution-EVENT reads that `nodes` and every `summary` count are derived
from ("this execution ran no nodes"); the third is per-node fuel enrichment. The
two graph reads beside them are label prettification and carry
`allow-benign-default` with the reason, which is the marker's documented second
clause. The report sites use the `Readings` ledger and render
`null`, never `0`; the decision sites refuse.

**What is LEFT, with counts, so the next pass starts from a number rather than a
sweep.** 175 sites remain: **52 claim**, 60 decorative, 37 fail-closed, 25
false-positive, and 1 nominal fail-open that is the repaired `dlq_updates`
narrowing (the detector correctly still sees a default; its verdict on the fixed
tree is fail-closed). The 52 claims by file: `analytics.rs` 7,
`executions.rs` 7, `modules.rs` 6, `advanced.rs` 5, `workflows.rs` 5,
`platform.rs` 4, `actor.rs` 3, `configuration.rs` 3, `graph.rs` 3, `search.rs`
3, `lib.rs` 2, `ml.rs` 1, and 3 in `talos-api`. Ranked highest among them by the
inventory: `analytics.rs`'s workflow AUDIT TRAIL (a failed read silently drops
every version-published and execution-triggered event, so a workflow reads as
never published and never run on a tool named for auditability),
`executions.rs`'s `get_execution_lineage_root` (a failed root lookup
substitutes the execution's own id, so the tree read comes back empty and
renders the false-standalone-run claim #771 built `lineage_note` to remove),
`executions.rs`'s `watch_execution` events, `modules.rs`'s catalog listing, and
`ml.rs`'s `has_pending_disagreements`.

**No lint check was added and `--count` stays 88.** The candidate — "an
enforcement decision may not be taken from a defaulted read" — cannot be spelled
textually: the three most severe members of this class were `if let Some(..)`
over an Option-returning read, and widening the detector's binding leg to
`Some(..)` was BUILT and MEASURED: it takes that leg from **20 to 69** sites on
pristine main, of which **3** are the gates — ~6% precision, enforcement-shaped
noise. The structural answer is stronger and is what shipped: one
`read_actor_ceiling_or_refuse`, and `controller/tests/fail_open_gate_tests`
(CTRL_TESTS per check 64b) drives `run_sandbox`, `compile_custom_sandbox`,
`tag_workflow` and `get_execution_cost` through the production dispatch with the
relation each gate's read names removed — one test per distinct SHAPE, each
carrying its own CONTROL, because the pre-fix tag path ALSO refused, just with
the wrong diagnosis.

### 2026-09-08 — the nine fixes nothing guarded, and the five claims that outranked the rest

Two halves, and the first is about the SHAPE of a guard rather than about any
new defect. #779 fixed eight fail-OPEN gates and thirteen claim sites and
recorded, in its own notes, that reverting NINE of them left every test in the
workspace green. Its rule was one test per SHAPE; "the shape is pinned
elsewhere" is exactly the reasoning that let `cleanup_module_versions` survive
package 23's mutation, so the rule here is **one test per SITE whose
consequence is irreversible or authorizing**.

**Leg A — `controller/tests/unguarded_gate_survivor_tests` (10 tests,
CTRL_TESTS per check 64b).** Nine of the ten sites are driven through the
production `dispatch` over a real `McpState` with the relation the read names
removed (package 22's mechanism), each carrying its CONTROL in the same run.
For a GATE the control is the half that matters: a healthy gate must still
refuse *for the right reason*, because "the tool refused" is not evidence when
the pre-fix path also refused. Two tests assert on **ROWS** rather than on the
reply — the stored `graph_json` after a refused `add_node_to_workflow`, and the
`webhook_triggers` count before and after a refused `create_webhook` — for the
reason `archived_dispatch_gate_tests` records: a gate whose refusal arrives
after the write is not a gate, and an earlier version of #754's write-ceiling
test passed because the INSERT would have failed anyway.

**Ten mutations, ten results, and one of them is the point.** MA1 (the actor
capability-world ceiling back to the lenient `None`), MA2 (the module-world
half back to `unwrap_or_default`), MA3 (the approval WRITE back to
`unwrap_or(0)`), MA4/MA5 (export metadata / module existence), MA6 (webhook
name uniqueness), MA7a (the dependents DIRECT scan), MA8 (`whoami`'s ceiling
back to the hardcoded `http-node`) and MA9 (the trace's child list) are all
**RED**. **MA7b — the dependents INDIRECT scan back to a silent empty —
SURVIVES this binary and is caught by check 74b**, at `modules.rs:2579`,
verified by running that leg against the mutated tree rather than assumed. The
reason it cannot be driven here is structural and worth recording:
`find_workflows_referencing_module` and `find_workflows_referencing_workflows`
read the SAME table through the SAME columns (`id`, `name`, `graph_json`,
`status`, `updated_at`), so no schema-level failure breaks the second without
breaking the first — and the first already refuses several lines above.

**`dlq_updates` gets NO test, stated rather than implied.** Its permission
refresh is three lines of local-variable assignment inside an `async_stream!`
in a GraphQL subscription resolver driven by a `PERM_REFRESH_INTERVAL_SECS =
60` ticker; reaching it needs a subscription held open past a real minute with
the org read failing mid-stream, and there is no seam short of restructuring
the resolver. **Leg C's second candidate was NOT taken for a one-sentence
reason**: the three `scheduler_readiness_*` publish sites live inside the
private `SchedulerService::hold_or_degrade`, which no integration test can
call, and they write through the process-global `talos_metrics::global()`
`OnceLock` that sibling tests in one binary race — check 82's own objection
about `DISTILL_CONTEXT`. **Leg C's FIRST candidate WAS taken and is closed**:
RFC 0012 P3 recorded that `get_workflow_sla_report`'s handler can pass
`child_runs: None` / `ledger_since: None` and every test stays green, and left
"the live read after deploy" as its honest guard. That mutation (MC1) is now
**RED** — a workflow with three recorded `sub_workflow_runs` and zero
execution rows must report them, with a barren workflow as the control so the
test cannot pass by making everything look measured.

**Leg B — `controller/tests/claim_read_disclosure_tier3_tests` (7 tests).** The
five sites `docs/swallowed-reads-inventory.md` ranked highest among its 52
remaining claims. Every one reproduced RED under a mutation reinstating the
collapse.

* **The workflow AUDIT TRAIL.** Two `.unwrap_or_default()` history reads on a
  tool named for auditability: a failed version read removed every
  `version_published` event, a failed execution read every
  `execution_triggered` one, and `count` / `event_count` reported the shortened
  list as the total — while `workflow_created`, synthesised from the row
  already loaded, kept the response looking well-formed. **This one has form**:
  `list_executions_for_audit` carries a comment recording that this exact
  swallow once hid a query naming a column that does not exist, so the trail
  returned ZERO execution events for EVERY workflow on the platform. The QUERY
  was fixed in May 2026 and the SWALLOW was left — the same
  fixed-the-path-not-the-population shape check 74's #730 group records for
  `get_workflow_schedule_count`. Now a `Readings` ledger, with `events`,
  `count` and `event_count` marked DERIVED and one extra sentence
  (`events_incomplete`) saying that an absent class of event is not evidence
  that it never happened — because `Readings::note` promises a null and what
  fails here shortens a LIST.
* **`get_execution_lineage`'s ROOT lookup.** A failed
  `get_execution_lineage_root` substituted the execution's own id; the tree
  query then matched `id = $1` and came back NON-empty, so `tree_degraded`
  stayed FALSE and the single-node arm rendered "This execution has no parent
  or child EXECUTION rows" — the determinate negative #771 built `lineage_note`
  to remove, reintroduced one read earlier. `root_execution_id` is now `null`
  (never the anchor's own id: an id there is read as "this is the top of the
  tree", which is precisely what an unreadable root cannot establish) and
  `lineage_note` gains a FIRST arm that outranks every other. The narrow shape
  the defect took in production — root read fails, tree read succeeds — is not
  separable by relation (both statements name the same two columns of the same
  two tables), so it is pinned by unit test and the DB test covers the wiring;
  saying which instrument covers what matters more than implying one covers
  both.
* **`watch_execution`.** `events: [], events_count: 0` from a failed read,
  beside a `current_status` that WAS measured, on the tool an operator polls
  during an incident — a poller comparing `events_count` against its last value
  reads 0 as "no progress". Both are now `null` with the read named; the status
  half is untouched, so this is a per-field disclosure and not a refusal.
* **`list_module_catalog`.** A failed visibility read made every entry read
  `installed: false, module_id: null, availability: "needs_install"` — an
  instruction to run `install_module_from_catalog` for modules the caller
  already has — and with `installed_only: true` the whole listing rendered as
  `[]`. REFUSES, matching the two sibling listings in the same file.
* **`ml_get_model_card`.** `has_pending_disagreements: false` is a PROMOTION
  CLEARANCE, and it was defaulted; it is now three-valued. The same read
  reached its model ENTITY lookup, which answered a failed registry read with
  "Model not found" (check 79's shape, and the correct split
  `require_dataset_owner` already makes 800 lines above it) — `Ok(None)` keeps
  the exact pre-fix wording, pinned. Adopting a ledger enrolled the handler in
  **check 74b**, so its four sibling `.ok()` reads (`shadow`,
  `shadow_lifetime`, `shadow.epoch`, `teacher_audit`, `dataset_stats`) are on
  the ledger too — leaving them beside a ledger that publishes "complete: every
  field in this report was measured" is the FALSE-COMPLETENESS shape 74b exists
  for.

**Re-measured, not estimated.** `scripts/lint-swallow-classify.py` over the
tree before and after: **175 sites → 164**, 11 removed and 0 added, no site
added anywhere. The verdict split on the fixed tree is **46 claim** (one of
which is the lineage-root row, now a `false-positive` by verdict because the
fix discloses rather than propagates — so 45 are genuinely open), 55
decorative, 37 fail-closed, 25 false-positive, and the 1 nominal fail-open that
is #779's repaired `dlq_updates` narrowing.
`docs/swallowed-reads-inventory.md` is re-rendered with a 2026-09-08
disposition, the per-file remainder and the three highest-severity sites still
open — including `list_module_catalog`'s SECOND site, a `spawn_blocking`
`JoinError` defaulting the disk walk to an empty catalog and CACHING it in a
process-wide `OnceCell`, so one failure is permanent for the pod's lifetime.

**A THIRD defect was found by measuring the lint candidate rather than by
reading the code, and it is this entry's own subject one level up.**
`handle_get_catalog_status` — the handler #779's notes name as check 74b's
first live catch — built a `Readings`, recorded the disk scan into it, and then
constructed a SECOND ledger fifty lines later that SHADOWED the first. So a
failed disk scan nulled `disk` in the body while the surviving ledger published
*"complete: every field in this report was measured"*: the disclosure mechanism
making the false-completeness claim it exists to prevent. **74b cannot see it**
— it detects a defaulted read BESIDE a ledger, not a ledger discarded by a
shadow — and neither can a test: the arm needs `/app/module-templates` to exist
AND the `spawn_blocking` walk to return a `JoinError`. One ledger per report;
the second construction is deleted. Measured population of "a function
constructing more than one `Readings`": **1 on this tree before the fix, 0
after**, which is the population-of-one this repo does not ship a check at, so
the guard is the comment at the site and this paragraph.

**One home for the test `McpState`.** `swallowed_read_disclosure_tests` and
`fail_open_gate_tests` each carried a hand-copied ~130-line struct literal and
this package would have made it four. Moved (not copied) to
`controller/tests/common/mcp.rs`, included with
`#[path = "common/mcp.rs"] mod mcp_common;` only by the binaries that need it,
so no other test target pays for it. A copy that falls BEHIND fails to compile;
a copy that constructs a DIFFERENT service fails silently and makes its
binary's assertions prove nothing about production — that second failure is the
one a shared home removes.

**No lint check was added and `--count` stays 88.** Two candidates were
measured first. (i) *"a function may construct at most ONE `Readings`"* — the
shadowing defect above. Measured across every non-test `.rs` in the workspace:
**1 site on this tree, 0 after**, a population of one, which is the bar #765's
own numbers set and this repo does not ship at. Its sibling *"a ledger must be
attached"* is worse: **30** constructions against **29** `attach` calls, and
the one difference is legitimate (`AnalyticsRepository::get_hygiene_report`
builds the ledger and hands it to `talos-hygiene-service`, which attaches it a
crate away), so the rule reports 1 false positive and 0 real ones. (ii) *"a `mod common`-harness test binary must not hand-roll an
`McpState`"* — population FOUR, all in one directory, and the structural answer
is stronger than a grep: there is now exactly one `pub async fn mcp_state`, and
a second copy would have to be written from scratch against a struct with 30
fields.

### 2026-09-08 — the column that already had its fix, and the next ten claims

Two halves. The first is a REFUTATION of its own brief, which matters more than
the code it produced.

**`module_executions.error_type` was already fixed, four days earlier.** The
brief for this package described a column with "one writer whose callers pass
nothing" and asked for the classification to be given one home. Measured on
pristine `origin/main` before anything was touched: `a04dbf4d` (#744,
2026-09-04, **37 commits behind HEAD**) had already built
`talos_engine::module_error_type::derive_error_type` over
`talos_failure_analysis_service::classify_error` — the SAME vocabulary
`analyze_execution_failure` shows an operator — and bound it into
`ModuleExecutionStore::record_completed`. And the column has **FOUR** writers,
not one: two take an `Option<String>` and two stamp SQL literals (`'timeout'`,
`'stuck'`).

**The live numbers the brief quoted were real and HISTORICAL, and reading them
is what settled it.** `failed` rows split `NULL 61 / timeout 1` over all time —
but the newest `failed` row is 2026-09-04 10:53, and the two rows of that minute
are #744's own live verification probes: a positive path that stored `timeout`
and a negative control (`probe-744: deterministic module failure`) that stored
NULL because the classifier fell through, which is the designed behaviour. So
the deployed controller carries the fix, the writer works, and **no production
module failure has occurred since**; the 61 NULLs are rows no forward-only fix
can reach. A distribution is not a defect until you read the newest row.

**What WAS left, and #744's own limits section does not name it**: two callers
of `fail_execution_from_worker` still passed `None`.
`talos-webhooks/src/router.rs` finalizes a MODULE-bound webhook dispatch with no
engine anywhere in its path, so nothing else ever closes that row;
`controller/src/bootstrap/background.rs`'s `talos.results.*` observer stamped a
hardcoded `"timeout"` for `JobStatus::TimedOut` and nothing otherwise. Both now
route through the ONE home — no new crate, no move, and no inverted edge, which
was measured rather than assumed: `derive_error_type` is already `pub` and
`talos-webhooks` already depends on `talos-engine` with no edge back. The
observer's `TimedOut` arm names a new `TIMEOUT_BUCKET` constant instead of
re-spelling the literal, and `the_timeout_bucket_spelling_is_the_classifiers`
drives `classify_error` to prove the two agree rather than comparing two
literals.

**Both remainder sites are LATENT and that is stated rather than dressed up**:
`webhook_triggers` holds ONE row with `module_id IS NULL`, so the webhook module
path has no live population, and the observer's own comment records that "every
NATS-dispatched code path uses request-reply, so this subscriber is mostly
dormant". What the change buys is that the vocabulary has one home for every
writer that can reach it.

**And the failure-analysis service still recomputes, for a sharper reason than
the brief gave.** It is not that 61 historical rows have nothing stored — it is
that `FailureAnalysisService::analyze` reads `execution_events` (`node_failed`
rows) and never touches `module_executions` at all. Different table, different
grain; there is no join to switch to. The shared vocabulary is what keeps the
stored column and the report an operator opens next from naming one cause twice.

**Guard.** `controller/tests/module_execution_error_type_tests` gains a round
trip through `fail_execution_from_worker` (a SECOND UPDATE from
`record_completed`'s, so binding is proved separately) with an unclassifiable
control, plus a SOURCE pin over the two call sites — neither is reachable from
an integration test (`background.rs` is `mod bootstrap` inside `main.rs`; the
webhook one needs a module-bound webhook this fleet has no row for), which is
the shape `task_supervision_wiring_tests` answers. Four mutations, all RED:
either call site back to `None`, the shared constant renamed to a spelling the
classifier does not use, and `derive_error_type` gutted.

**The second half: ten more CLAIM sites, ranked by blast radius.** The read
inventory carried **46** open claims on this tree. The ten taken are a decision
above a count an operator pages on, above a list that feeds a next step — not a
prefix of the list. Re-measured with `scripts/lint-swallow-classify.py`:
**164 sites -> 153**, 13 removed, 2 added, **46 claims -> 34**.

Two of the ten are WRITES misreported as benign counts, and one of those is the
sharpest member of this class found so far: **`compress_actor_context`'s swallow
survived into a COMMIT.** The loop above it rolls back on a failed write, while
`.unwrap_or((0, 0))` let a failed measure-and-forget CTE reach `tx.commit()`, so
the committed state was the condensed replacements written AND the originals
still present — memory GREW — under a response reading `status: "compressed",
keys_retired: 0`. The other write is `bulk_tag_workflows`, where `tagged_count`
IS `rows_affected()` and `already_tagged_count` is derived from it, so a failed
UPDATE reported every owned workflow as ALREADY CARRYING the tag, while the
owned-count probe MCP-152 added to stop exactly that conflation defaulted to 0
and accused the operator of typing bad UUIDs.

`talos-api`'s `me` is the one refusal that is a SECURITY posture: one unreadable
`users.totp_enabled` collapsed to `false`, and `is_two_factor_verified`'s
`.unwrap_or(!totp_enabled)` fallback then defaulted to `true`, so a DB fault
answered *"no 2FA, and you are verified"* — the most permissive pair the
resolver can emit. MCP-877 diagnosed this correctly in May 2026 and LOGGED it; a
warning in a log the browser cannot read does not stop a frontend gate. It now
propagates, which is forced rather than chosen: `UserInfo` is a typed
`SimpleObject` with no disclosure slot and `talos-api` carries no
`talos-measurement` dependency.

`get_agent_card` takes the remedy the handler already had: a card whose
CAPABILITY LIST could not be read is `shareable: false` with `available_workflows:
null`, the same branch a card rendered against a placeholder host takes — pre-fix
it shipped `shareable: true` advertising an agent that can do nothing, under a
note telling the operator to register it in a discovery registry.
`get_node_io`'s graph read is the one member of the twelve-site
`build_node_label_map` family that is NOT label prettification, because
`node_uuid` is RESOLVED through that map: an empty one silently answered about a
DIFFERENT node's uuid and rendered `input: null, output: null` for it.
`list_module_catalog`'s disk walk moves to `get_or_try_init`, so a failed walk is
no longer MEMOIZED — one panicked blocking task used to make every later call in
the pod's lifetime report an empty catalog.

**The two sites the detector ADDED are the fix, not a regression.** Both are in
`handle_list_module_catalog`: a `get_or_try_init(...).await` followed by a
`match` whose `Err` arm REFUSES reads to the walker as a binding collapse. Their
verdict on this tree is `false-positive`, the same reason `dlq_updates` and the
lineage root still appear; saying so is cheaper than a detector exception that
would hide a real one later.

**Guard, and the two failures a relation drop cannot inject.**
`controller/tests/claim_read_disclosure_tier4_tests` (11 tests, CTRL_TESTS per
check 64b) drives the REAL MCP dispatch over a real `McpState` — and, for `me`,
the REAL compiled GraphQL schema — with the relation each read names removed.
Every test carries its control, and the two whose pre-fix path ALSO refused
(`get_agent_card` on an absent actor, `suggest_actor_for_task` for a user with
none) carry that half explicitly, because "the tool refused" is not evidence when
the pre-fix path refused too with the wrong diagnosis. `me`'s 2FA read shares the
`users` row with `AuthService::get_user`, which projects `totp_enabled` and would
refuse ABOVE it, so the failure is injected as a POOL that cannot connect — the
shape this defect takes in production. `compress_actor_context`'s failing DELETE
and the INSERT it must not outlive share ONE relation, so the injection is a
`BEFORE DELETE` trigger that raises, and the assertion is on ROWS rather than on
the reply: a refusal that arrives after the write is not a rollback, and the
whole defect was a commit.

**Ten mutations, ten RED, and the first six had to be re-run.** The first
attempt wrapped each reverted expression in scaffolding to keep the surrounding
code alive; six of the ten then failed to COMPILE, which proves nothing (the
project's own "a green mutation over an edit that never landed" lesson, in the
opposite direction — a mutation that cannot build is not a survivor OR a
catch). Re-run as EXACT reverse replacements of the pre-fix source, all ten are
red by assertion.

**One out-of-scope defect found and NOT fixed**, recorded so it is not
rediscovered: `handle_get_execution_waterfall`'s bar renderer does
`bar_len.clamp(1, chart_width - bar_start)`, which PANICS with `min > max`
whenever a node's `start_ms` equals the run's `total_ms` — reproduced with a
fixture whose `node_started` and `node_completed` share a timestamp. A panic in
an MCP handler unwinds the tokio task, so the caller sees a dropped request
rather than an error. The test fixture here uses distinct timestamps and says
why at the seeding helper.

**No lint check was added and `--count` stays 88.** Two candidates were measured
and both fail on the same ground the last four passes recorded. (i) *"a report
handler must not default an awaited read"* is the widening #782 already built,
measured and rejected at 83.6% precision and a baseline of 62 — nothing here
moves those numbers, and this change takes the population from 46 to 34 without
changing its shape. (ii) *"a caller of `fail_execution_from_worker` must derive
`error_type`"* has a population of **two**, both in different crates, which is
the bar this repo does not ship at (#765's numbers); the structural answer is
that the vocabulary has one `pub` home and the two call sites are pinned by a
source assertion in the DB binary that already covers the column.

### 2026-09-08 — nothing could say which operator surface is slow, and the two things that were

Every prior entry in this file is about a report that says the wrong thing.
This one is about a report that does not exist: **no per-tool latency series,
no per-tool error series, no per-call line, no per-statement attribution.**
Measured live, read-only, before anything was written: `/metrics/prometheus`
is **61 128 bytes / 567 lines / 445 series**, and the only `talos_*` names
matching `mcp|tool|handler|request|graphql|query|db|pool` are the four
`talos_db_pool_*` gauges and `talos_dlq_db_errors_total`; the controller log
holds **one** line matching `talos_mcp|tools/call|mcp_tool_call` in 1 675, and
it is the BOOT line `MCP local endpoint ENABLED`; and `SHOW
shared_preload_libraries` answers with the empty string, so there is no
`pg_stat_statements` either. "Performant by default" was unverifiable for a
single operator surface.

**The chokepoint is `handle_tools_call`, and it is a CHAIN, not a table.**
Twenty-one domain `dispatch` functions, each an `Option`-returning `match`
over its own tool names, tried in order, with a `-v1` catalog-template
fallback at the tail — so there is no dispatch table further in to hang a
measurement off. Three call sites reach it (the SSE message endpoint and the
two POST transports) and nothing else dispatches a tool, so one measurement
covers the whole surface and a NEW transport inherits it. It is now a thin
wrapper over `handle_tools_call_inner`: resolve the label, time the inner
call, classify the response, record, log one line. It OBSERVES and never
alters — `the_instrument_leaves_the_response_byte_identical` compares its
answer with the domain dispatch's own.

**`talos_mcp_tool_duration_seconds{tool,outcome}` +
`talos_mcp_tool_calls_total{tool,outcome}`, and CARDINALITY is the whole
design.** `params.name` arrives from the wire; a `CounterVec` keyed on it
grows one series per distinct value, so anyone who can reach `/mcp` could mint
unbounded series in the controller's registry and in every Prometheus that
scrapes it. `tool_labels::canonical_tool_label` therefore resolves the name
against `tool_hints::declared_tool_params()` — the `&'static` map built once
from the `tool_schemas()` functions — and returns a `&'static str` **borrowed
from that map's own key**, so no interning table and no `Box::leak` is needed
and the set cannot grow at runtime. Two `const` sentinels: `catalog_template`
for any `*-v1` name (the catalog is DATA — rows, not literals in this binary —
so a catalog name is as caller-influenced as any other string) and `unknown`.
The guard is POINTER equality, not string equality: three invented names must
return the SAME pointer, which is what bounds the whole unrecognised
population at one series. `outcome` is an ENUM (`McpToolOutcome`), so that
half of the label set is closed by the compiler, and it is decided from the
RESPONSE SHAPE — 21 dispatch functions and ~320 arms would be 320 places to
forget. `-32602` is `refused` and everything else is `error` because a client
looping on a typo'd argument and a database outage must not move the same
series (census: `-32602` 411 sites, `-32000` 409, `-32603` 5, `-32004` 2,
`-32003` 2).

**Buckets are `exponential_buckets(0.001, 2.0, 16)` — 1 ms … 32.768 s.** The
house style in this file is `(0.001, 2.0, 15)`, which tops out at **16.384 s,
below the 30 s target**, so every call slower than 16 s would land in `+Inf`
with no upper bound at all.

**NOT pre-seeded, and the decision is measured rather than asserted.**
`the_mcp_instrument_costs_the_lines_the_no_preseed_decision_assumes` pins the
premise: **19 lines per histogram series** (16 finite buckets + `+Inf` +
`_sum` + `_count`), **2 356 bytes for the first `(tool, outcome)` pair**
(which pays both families' HELP/TYPE preamble) and **1 656 for each
additional** one. The full ~320 × 4 product is ≈ 1 280 pairs ≈ **2.1 MB and
~25 600 lines — a 35× scrape**; even seeding only the pairs a live call site
can reach (~960) is ≈ 1.6 MB. Nothing alerts on these two series, so the
absent-≠-zero argument that seeds `dispatch_refused_total` does not apply: an
absent `(tool, outcome)` here means "this tool has not been called since
boot", which is what a seeded 0 would have said. Realistic growth on a
controller that has served the nine tools below is 61 KB → **77 KB (+25 %)**.
If an alert is ever written on these, seed the pairs THAT alert selects, never
the product.

**The instrument costs 619 ns, measured rather than asserted.** Release
build, 200 000 iterations, with a `tracing` fmt layer actually formatting and
writing the line (a no-subscriber measurement would understate it): **619 ns**
for the whole wrapper, **108 ns** without the log line, **40 ns** for the label
lookup alone. The fastest tool on this surface (`whoami`) measures 2.3 ms, so
the instrument is **0.027 %** of it; the slowest measured is 189 ms. Most of
the cost is the log line, i.e. the half an operator reads.

**The per-call line carries `tool`, `outcome`, `duration_ms` and the request
id, and nothing else** — never the arguments, never the response, never a
token. The request id is caller-controlled, so it is capped at 64 chars on a
char boundary and an absent one renders `-`.

**Stated blind spot, measured rather than implied.** The registry is the
ADVERTISED set. **29** identifier-shaped names appear in a `dispatch` body and
in no schema — the deprecated `agent_*` aliases (`agent_recall`,
`create_agent`, `list_agents`, …) and unadvertised siblings
(`bulk_tag_workflows`, `get_workflow_summary`, `get_workflow_topology`, …).
Those calls ARE instrumented, under `unknown` rather than their own name. The
alternative is a hand-maintained alias list, which is the rot mode check 74's
name glob and check 64's runner list already cost this repo; a client that
discovered its tools from `tools/list` can reach none of the 29.

#### The baseline the instrument bought, and what it says

Driven ONCE each through the real chokepoint against an isolated clone of a
fleet-shaped scratch template (36 workflows 17/11/8, 112 modules, 10 500
executions with one at 5 540 — the live fleet's shape, read read-only).
**Statements are counted from sqlx's own `sqlx::query` tracing events**, one
per executed statement including a scoped transaction's `BEGIN`/`COMMIT`, so
they are ROUND TRIPS; there is no `pg_stat_statements` to ask (see below).
Background spawns are drained and counted SEPARATELY — the first run
attributed `session_start`'s heal statements to whichever tool ran next.

| tool | ms | statements | background |
|---|---|---|---|
| **get_platform_hygiene_report** | **189.0** | 21 | 0 |
| session_start | 41.5 | 26 | **27** |
| get_system_health | 26.3 | **17** | 0 |
| get_all_readiness_scores | 19.1 | 7 | 0 |
| get_workflow_performance_report | 17.6 | 6 | 0 |
| list_executions | 15.5 | 9 | 0 |
| get_workflow_health | 10.6 | 7 | 0 |
| security_audit | 8.5 | 3 | 0 |
| *whoami (control)* | 2.3 | 4 | 0 |

**The slowest surface has no N+1 and no unbounded read**, which is worth
saying because it is the opposite of what a 189 ms report invites you to
assume. `get_platform_hygiene_report` issues 21 statements, constant in fleet
size, every list LIMITed; its cost is four individually slow statements inside
`tokio::join!` batches — the `uncapabilized` list at **53.0 ms**, the
`undescribed` list at **52.9 ms**, the idle-actor scan at **25.9 ms** and the
dormant `WITH last_run AS (…)` at **24.0 ms**. Neither fix this change is
allowed to make (`= ANY($1)` batching, a disclosed cap) addresses a statement
that is slow on its own, so it is RECORDED with its four statements named
rather than half-fixed.

**Two things were fixed.**

**(1) `session_start`'s capability heal was a real N+1.**
`for wf_id in ids { auto_suggest_capabilities(…).await }` over
`get_ids_without_capabilities` (`LIMIT 100`), four statements each — one
graph+capabilities read, one world read, one kind read and one UPDATE — run
serially inside a background `tokio::spawn` against the same pool a live
request is competing for. **Before: 27 statements for N = 6, worst case 401.
After: 6, and CONSTANT** — 6 at N = 100 too. Three new `AnalyticsRepository`
methods (`get_workflow_graphs_and_capabilities` and
`get_module_worlds_and_kinds`, both `= ANY($1)`, and
`set_capabilities_if_empty_bulk`, one `UPDATE … FROM jsonb_array_elements`
because ragged per-row arrays cannot ride `UNNEST`). **The DECISION did not
move**: `capability_suggestions_from` is now a PURE function called by both
paths and `module_ids_in_graph` is one reader of the
`node.type`-is-a-module-uuid convention, so the two cannot come to disagree
about which modules a workflow uses. The test asserts the tags are IDENTICAL
to the per-workflow path's own answer on an identical population — a
count-only assertion passes over a batched path that tags everything `[]` —
and a second test pins that an operator's explicit tag set between the read
and the write still survives.

**Batching changed a BLAST RADIUS, and the batched path answers for it.** The
per-workflow path swallowed its module reads (`.unwrap_or_default()`) and, on
failure, wrote the graph-STRUCTURE tags alone. One workflow at a time that is
an accident; batched, one failed read does it to the WHOLE PAGE, and the
`if empty` guard makes it PERMANENT — a structure-only-tagged workflow is no
longer uncapabilized, so the heal never revisits it. The batched path ABORTS on
that read with a WARN and writes nothing; the page stays uncapabilized and the
next `session_start` retries. Pinned by a test that renames the column the read
names (leaving `workflows` untouched, so the healthy control is meaningful);
the mutation that restores the swallow fails it with
`[["parallel"], ["parallel"], ["parallel"]]` in the assertion output — the
degraded tag set, in so many words. The per-workflow path's own swallow is
pre-existing and deliberately untouched: not this change's to rewrite, and its
blast radius is one row.

**(2) `get_system_health` issued the SAME statement twice**, once discarded to
`.is_ok()` under the comment *"Use a simple repo call as DB connectivity
check"* and once for its value, and that statement carries an unbounded
`(SELECT COUNT(*)::bigint FROM workflow_executions WHERE user_id = $1)`:
**10.3 ms + 5.7 ms of the tool's 31.9 ms**. One read now answers both
questions — **17 → 14 statements** (the statement plus its scoped
transaction's BEGIN and COMMIT). Not a cache: same statement, same binds, same
request. The only behavioural difference is a TRANSIENT failure where the
first read failed and the second succeeded, which used to render a report
stamped `database_connected: false` from a read that had in fact succeeded.

**The apparent byte difference in that response was checked, not waved away.**
`get_system_health`'s body measured 566 bytes before and 565 after — and two
consecutive runs of the SAME post-fix code render
`recent_failure_rate.total_executions` as **92** then **90**, because the seed
spreads executions over a rolling window and that field counts the last hour.
Seed drift, not a behaviour change.

**What was measured and NOT changed.** The embedding half of the same heal has
the identical N+1 shape and a ready-made fully batched sibling
(`handle_generate_workflow_embeddings` = one read + `generate_embeddings_batch`
+ `bulk_set_workflow_embeddings_from_str`), and it is left alone: it needs a
live embedding provider to exercise, this environment has none (the spawn does
not even fire — `provider_status: "unavailable"`), and an unexercised rewrite
of an HTTP fan-out is worse than the N+1 it replaces. **Both heal loops are
LATENT on the reference fleet**, stated plainly: `embedding IS NULL` = **0**
and `capabilities = '{}'` = **0** today. They fire on freshly created or
imported workflows — the state immediately after `create_workflow` — not on
this fleet. And `get_system_health` / `list_executions` each carry an unbounded
`COUNT(*)` over the user's execution partition; neither is a collection held in
memory, so neither is the unbounded-collection shape, and capping a COUNT
changes its meaning.

#### `pg_stat_statements`, and the guard whose premise was false

`docker-compose.yml`'s postgres gains
`command: [postgres, -c, shared_preload_libraries=pg_stat_statements]` (the
image and its pinned digest are untouched — check 80), and migration
`20260908120000` creates the extension where that preload is present.

**The obvious guard — "catch the error `CREATE EXTENSION` raises without the
preload" — was refuted by measuring it.** On this server (PG 17.10,
`shared_preload_libraries` empty) `CREATE EXTENSION pg_stat_statements`
**succeeds**. What fails is the first READ:
`SELECT count(*) FROM pg_stat_statements` →
`ERROR: pg_stat_statements must be loaded via "shared_preload_libraries"`. So
an unguarded migration leaves every non-preloaded deployment carrying an
extension whose only view raises on every query — a catalog entry that lies
about a working instrument, which is this file's usual subject. The gate is
therefore on the GUC itself, and the EXCEPTION block is kept for the SECOND
measured failure mode: a non-superuser migration role gets
`permission denied to create extension … Must be superuser` (measured with a
plain LOGIN role — the extension is not `trusted`), which is exactly the shape
a managed Postgres takes, and a migration that ERRORS there stops the whole
chain including every migration after it.

**Both arms proved, on the same pinned image.** No preload: the full
`sqlx migrate run` applies it at exit 0, a direct psql apply prints one
`NOTICE … skipping` and `DO`, `pg_extension` count is **0**, and the
`_sqlx_migrations` row is present with `success = t`. With the preload (a
throwaway container started with the exact `command:` the compose change adds):
`NOTICE: pg_stat_statements is enabled.`, `pg_extension` count **1**, and
`SELECT count(*) >= 0 FROM pg_stat_statements` actually READS. The positive arm
matters as much as the negative one — a guard that skips everywhere is a no-op
that proves nothing.

**The Helm chart is deliberately NOT changed, with the cost stated.**
`shared_preload_libraries` is a POSTMASTER GUC, so adding it to the in-cluster
Postgres ConfigMap takes effect only on a server RESTART — on that chart's
single-replica StatefulSet, a full database outage for the length of a pod
restart — and the extension takes a fixed shared-memory allocation
(`pg_stat_statements.max` × ~1 KB, default 5 000 entries) out of a deployment
tuned there for a 4 GiB VM. An operator's decision, not a migration's side
effect.

#### Guards, and no lint

`controller/tests/mcp_tool_instrument_tests.rs` (7 tests, CTRL_TESTS per check
64b) drives the REAL `handle_tools_call`: the counter and the histogram each
move exactly once; three invented names mint exactly ONE `unknown` series and
none of the three strings reaches the label set; the response is byte-identical
to the domain dispatch's own; a missing required argument records `refused`;
the capability heal is constant in page size AND answers identically; an
operator tag survives the bulk heal; `get_system_health` reads the status
counts once. **Cardinality assertions read the registry's own `gather()`
output, never `with_label_values(..).get()`** — that method CREATES the series
it is asked about, so a cardinality test written that way manufactures the
evidence it then checks.

**No lint check was added and `--count` stays 88.** Two candidates were
measured first. (i) *"a metric label value must be `&'static`"* is not
expressible: `Box::leak` yields `&'static str` from a request string, so the
type is not the property — the guard is the pointer-equality test, and the
population is ONE label pair. (ii) *"a new `tools/call` transport must call the
instrument"* has a population of THREE call sites in one file, all of which
already funnel through the one `pub` wrapper — the structural answer (an inner
function nothing else calls, and a wrapper that cannot be bypassed without
deleting it) is stronger than a grep over three lines. What is NOT guarded, and
is said rather than implied: nothing stops a future edit from computing the
right label and then passing a different one to `record_mcp_tool_call`; that is
a dataflow question, and the honest guard for it is the live read of
`/metrics/prometheus` after deploy.

### 2026-09-09 — the instrument counted the platform's authorization as a server error, and the two instruments spoke two vocabularies

**The first thing the MCP instrument ever recorded on this fleet was a
refusal, filed as a fault.** Minutes after #786 deployed, `get_system_health`
without the admin capability was refused (`-32003`, "Unauthorized:
get_system_health requires admin capability") and the registry recorded
`talos_mcp_tool_calls_total{outcome="error",tool="get_system_health"} 1` in
33 µs. Nothing was wrong with the refusal; the LABEL was wrong. Read live
again 2026-09-09, unchanged, and it is one of THREE calls in the instrument's
entire history — so `error` is 33 % of every MCP call this platform has ever
recorded and the one `error` is the platform working as designed. The
matching log line reads `"MCP tool call served" … outcome="error"`: fixed
prose asserting the call was served, beside a field saying it was not.

**The population is not what the shipped comment says, and the correction is
the reason a lot of this was invisible.** `tool_labels.rs` claimed "411 of
this crate's `mcp_error` sites" use `-32602` and "-32000 (409 sites)". A
STATEMENT-AWARE inventory (`scripts/mcp-error-inventory.py`, new: comment and
string CONTENT masked first — check 73's trap — then the argument list walked
by a depth-aware paren matcher so a `)` inside a message cannot end it) counts
**1590 production call sites**, of which **883** are `-32602` and **648** are
`-32000`. The shipped numbers come from a single-line regex
(`grep -c "mcp_error(.*-32602"` returns 412, `-32000` returns 410) and the
house call style breaks the call across lines, so they saw 46.6 % and 63.3 %
of their own populations. Cross-checked in the safe direction: a raw
`grep -o` over the same tree returns 1602 against the inventory's 1595
including test sites, the seven-site difference being occurrences inside
comments and literals.

**`-32000` cannot classify itself, and neither can three other codes.** Of the
648 `-32000` sites, roughly **250 are refusals** — `"Workflow not found or
access denied"` and its family alone is **123** — beside `"Failed to fetch
workflow"`. Worse and not previously noticed: **11 of the 12 `-32601` sites
are platform-admin refusals** (`query_paginated`, `pause_executions`,
`ollama_pull_model`, `set_wasm_config`, `get_secret_access_log`, …), recorded
as `unknown_tool`, so a non-admin looping on an admin-gated tool moved the
series an operator reads as "clients are calling tools that do not exist";
**7 of 15 `-32603` sites** are capability-ceiling refusals recorded as
`error`; and **both `-32004` sites** are one call carrying BOTH arms of
`evaluation::ensure_actor_owner`.

**The constraint that shaped the design: the OPERATOR needs the split and the
CALLER must not get it.** `"Actor not found or access denied"` is one sentence
on purpose — a reply distinguishing "no such actor" from "not yours" is an
existence oracle for anyone who can guess a uuid, an argument this file
already records at `resolve_actor_via_repo`, at `caller_facing_unauthorized`
and at #754's collapsed `write_ceiling_unreadable`. Re-assigning wire codes is
out too: the reply bytes are an interface MCP clients may depend on. **So the
meaning travels OUT OF BAND on the response value.**
`talos_mcp::JsonRpcResponse` gains `error_kind: Option<McpErrorKind>` with
`#[serde(skip)]`, and `McpErrorKind::{Denied, NotFound, Failed}` says what the
site meant. `None` is a real third state — *no site said* — and classifies
from the code exactly as before.

**Three storage locations exist and the other two rest on discipline.** A
`tokio::task_local` is lost by any `tokio::spawn` (a silent miss) and
MISLABELS when a site constructs a refusal and discards it. A reserved key
inside `result`, stripped at the chokepoint, rests on the strip running — and
a leak IS the invariant being broken. With `#[serde(skip)]` a leak is not
expressible, and the marker travels with the VALUE so construct-and-discard
cannot mislabel and a decorated response keeps it. **That option was nearly
rejected on a bad number**: `grep -rn "JsonRpcResponse {"` reports 398, which
counts `-> JsonRpcResponse {` RETURN TYPES; masked and excluding those, the
workspace holds **31** struct literals. A line grep over Rust is not a
population — the same lesson as the `-32602` count above, twice in one change.

**The byte-identity is STRUCTURAL, not a promise.** `mcp_error`,
`mcp_error_kind`, `mcp_denied`, `mcp_not_found` and `mcp_failed` share ONE
private `build_error` body, so there is no second literal to drift.
`mcp_error_kind_matches_mcp_error_byte_for_byte` drives all three kinds
through `serde_json::to_string` and compares; `the_kind_never_crosses_the_wire`
asserts the rendered string carries neither the field name nor the value AND
that a parsed response carries `None`. **The reply-byte snapshot was written
BEFORE the refactor** and passed on the pre-change tree, so it proves the
bytes did not move rather than describing where they landed.

**Six outcomes, three classes, and the class is one TYPE across both
surfaces.** `talos_metrics::mcp` is the new table (the `rpc.rs` macro shape):
`ok | refused | unknown_tool | denied | not_found | error`, with #786's four
spellings byte-identical so no log filter breaks. `denied` is the platform
refusing a WELL-FORMED request (authorization, capability ceiling, org
membership, a lifecycle or policy state, and the deliberately collapsed "not
found or access denied"); the line against `refused` is the REQUEST — *your
arguments are wrong* versus *your arguments were fine and the answer is no*.
`not_found` is its own outcome and folds into `Declined` on #787's own ground
(`RpcOutcome::NotFound => Declined`: a `get` on a key never written is the
normal path). #787's `RpcOutcomeClass` was **MOVED, not copied**, to
`talos_metrics::outcome_class::OutcomeClass` and lost its `Rpc` prefix — 20
references, 3 files — so `served|declined|finding` is ONE type with ONE
`as_str` on both surfaces and the three spellings cannot drift. The
per-surface OUTCOME vocabularies stay legitimately different.

**`class` is a third label and it adds NO series — verified, not assumed**
(the brief's instruction, and #787's omission), in two places: over the table
(`the_class_label_adds_no_series` asserts the `(outcome, class)` pair count
equals the outcome count) and over a REAL registry after a real dispatch
(`the_exported_series_carry_one_class_per_outcome`), which is where a future
hand-written `with_label_values(&[tool, outcome, "finding"])` would surface.
Measured scrape cost: the first `(tool, outcome)` pair moves 2356 → 2941 bytes
and each marginal pair 1656 → 1996, ~19 bytes per rendered line, so the
no-pre-seed argument gets ~24 % STRONGER; the pin carries the new numbers and
the reason.

**What was fixed, ranked by blast radius rather than taken as a prefix.**
*Tier 0, the CODE table — zero site edits, zero reply bytes moved*: `-32003`
(13 sites), `-32001` (2), `-32002` (1) and `-32600` (1) were verified
site-by-site to be refusals in their WHOLE population, so one match arm covers
17 sites and C1's exact case. *Tier 1, the shared funnels*:
`trigger_auth_error_to_response` and `creator_auth_error_to_response` (behind
every trigger and every `create_*`), `database_error` (**50 call sites**, the
canonical failure funnel, now saying so at one home),
`actor::resolve_actor_via_repo` (behind 20+ actor tools) and
`knowledge_graph::require_owned_actor` — **both of which already had #782's
three-way read, with a refusal arm and a failure arm rendering the SAME
`-32000`; the two arms separated for the operator's PROSE landed on one
series** — plus `ml::require_dataset_owner` (9 call sites) and
`evaluation::ensure_actor_owner` (2), which returned `Result<_, String>` and
now return a typed refusal carrying the kind AND the unchanged message.
*Tier 2*: the 11 `-32601` admin refusals (the one genuine unknown-tool site is
untouched). *Tier 3*: 7 `-32603` ceiling refusals. *Tier 4*: the 124
tenancy-collapsed `-32000` sites. *Tier 5*: 44 more `-32000` policy and
lifecycle refusals. *Tier 6*: 17 `not_found` sites, and the criterion is
narrow on purpose — only IN-MEMORY lookups (`"Node 'x' not found in
workflow"`), where the value is already in hand so no read could have failed.
196 `Denied`, 18 `NotFound`, 4 `Failed`, 2 through the typed gates.

**What was measured and deliberately NOT changed.** The ~363 `-32000` genuine
FAILURES were not marked `mcp_failed`: their default is already `error`, so it
is 363 lines of diff for no behaviour change. **The nine remaining `"Model not
found"` sites in `ml.rs` were NOT marked `NotFound`, and this is the sharpest
limit of the package**: they are written `let Ok(Some(m)) = … else { … }`,
which routes a READ FAILURE into the not-found branch, so marking them would
assert a determinate negative in the instrument — the class checks 74 / 76 /
79 / 81 exist for — in a new place. **The instrument cannot be more precise
than the handler's own read**, so the sites where classification is blocked
are exactly the sites #782's read-splitting has not reached, and that is a
better criterion for the next pass than the next N lines of a list. The 11
`e.jsonrpc_code()` sites build their code from a service-error enum at
runtime; routing them through the kind is a per-enum change in five service
crates and is counted rather than attempted.

**The remainder, so the next pass starts from a number.** 1363 constructor
sites remain unclassified, of which 883 are `-32602` (already correct via the
code arm), 363 are failures (correct as `error`), 14 are `denied` via the pure
codes and 1 is the genuine `unknown_tool`. **102 are OPEN** — 25 not-founds,
10 refusals, and 67 whose message is a runtime variable (`msg`, `err_str`,
`hint`) — by file: `workflows.rs` 21, `ml.rs` 19, `sandbox.rs` 13,
`executions.rs` 11, `actor.rs` 10, `advanced.rs` 7, `versions.rs` 5,
`modules.rs` 4, `graph.rs` 3, `search.rs` 3, `utils.rs` 3, `analytics.rs` 2,
`evaluation.rs` 1.

**The LOG LEVEL was measured and deliberately NOT partitioned.** #787's shape
is one predicate under BOTH the `talos_rpc` log level and the `class` label;
here `class` joins the log line as a FIELD and the level stays INFO for every
call. The argument that made #787 change a level does not transfer: there, a
designed state was 53 % of the controller's entire WARN volume, so the level
was fixing NOISE. The MCP line is one per call at one level by #786's
deliberate choice — a per-call trace, not an alert — and an operator who wants
the failures now filters `class=finding` on the field rather than on the
level. Promoting `finding` to WARN is defensible and is a log-volume decision
of its own; it is recorded rather than smuggled in.

**NO alert, argued.** Nothing selects on this instrument today
(`grep -rn "talos_mcp_tool" observability/ deploy/helm/talos/files/` is empty),
which is exactly why the partition had to be fixed BEFORE a rule was built on
a label whose meaning would then have to change under it. But the instrument's
entire live population is THREE calls, and a rule with no baseline either
fires forever or never — check 69's harm in both directions, and #787 declined
an alert on `unauthorized` for the same reason two days earlier. What the
partition buys is that the eventual rule is `class="finding"` rather than an
outcome alternation a seventh outcome would silently fall outside of. Still
NOT pre-seeded: ~320 tools × 6 outcomes is almost entirely unreachable, so
seeding it is check 58's own defect.

**Mutations, worst first, with the survivor and the no-op reported as such.**
Reclassifying `denied` to `Finding` — the QUIET direction — is RED on the
name-pinned partition. Leaking the kind to the wire is RED twice, printing the
leaked payload. Deleting the chokepoint increment is RED seven times. Making
`classify_outcome` ignore the kind is RED three times; honouring it BEFORE the
success-shape check is RED on
`a_kind_on_a_success_response_is_ignored`; dropping the pure-code arm and
hardcoding the class label are RED. **M1b — reverting
`resolve_actor_via_repo`'s refusal arm — SURVIVED on its first run**, because
the round-trip test drove an INLINE site; that is what
`the_actor_ownership_funnel_records_denied` was then written for, and the
mutation is red. **M9 SURVIVES and is left stated**: reverting one of the
eleven `-32601` admin refusals is invisible to every test here, because
driving those needs a non-`*` `AgentIdentity` plus platform-admin state. With
196 classified sites the guard is one test per SHAPE plus one per the
highest-leverage FUNNEL, and the honest guard for the rest is the live read
after deploy — #767, #769 and #771's position about their own changes. **M8 is
a NO-OP, not a survivor**: `mcp_failed` at a `-32000` site changes nothing,
because that code's default already IS `error`, which is true of all four
`Failed` sites — the variant is DEFENCE IN DEPTH so a future addition to the
pure-code arm cannot silently reclassify a failure. And one limit was found BY
a mutation rather than reasoned: `the_exported_series_carry_one_class_per_outcome`
does NOT catch a hardcoded `"finding"` — it proves PURITY, never CORRECTNESS,
which is what the two delta tests assert.

**A flake this change introduced and closed.** The new class-purity probe
calls `whoami` and `get_workflow`, which two pre-existing tests measure
"exactly once" deltas on through the process-global registry; one run in three
turned a sibling red. Relaxing to `>= 1.0` was REJECTED — "exactly once" is
what proves ONE record site writes both series — so a `SHARED_SERIES` mutex
serialises the five tests that share a `(tool, outcome)`, recovering from
poison so a panicking sibling fails on its own assertion. Five consecutive
full runs green. Also corrected in the same file:
`a_caller_fault_records_refused_and_a_server_fault_records_error` never drove a
server fault; it is renamed to what it does, and the other half is a real
injected read failure in Leg D.

**No lint check was added and `--count` stays 88.** The candidate — *"a
refusal must not be constructed with the failure constructor"* —
was BUILT (`scripts/lint-mcp-refusal-constructor-candidate.py`, kept so the
numbers can be re-derived) and MEASURED on both trees in a real `git
worktree` of `origin/main`: **258 sites there, ~225 of them real (≈ 87 %,
the band checks 74 and 87 shipped at) — and 68 on the FIXED tree**, of which
43 are false positives by construction (`-32602`, `-32003`, `-32001` are codes
the classifier's own arm already handles). So it ships as a ratchet with a
baseline, which is check 52's rule. And narrowing it to the codes the table
does not classify still leaves ~28, **which are precisely the sites this
package deliberately left alone** — the `ml.rs`-style two-valued reads. A
check demanding a classification there would push a future author into
asserting a determinate negative in the instrument: **a gate that pressures
you toward the defect it is named after is worse than no gate.** The
structural alternative was priced too — making the kind a REQUIRED parameter
of the only constructor is **1583 call sites**, 883 of them `-32602` where the
author would be inventing a kind to satisfy a signature. What ships
structurally instead: a closed `McpErrorKind`, an exhaustive `const fn`
mapping with no wildcard, `#[must_use]` on the classified constructor, and one
private body behind all four spellings.

### The whitespace-run artefact, and why no lint guards it

Four operator-facing string literals carried mid-sentence runs of up to 22
spaces — a `\`-continuation that lost its `\` and kept the indentation. All
four are from #771's dispatch-attempt work and all say the same thing in four
places: an audit-ledger WARN read during a tamper investigation, a Prometheus
**HELP** string, and two `security_audit` disclosure sentences. A line grep
cannot see the shape (the run spans the continuation join), so the measurement
used a literal-aware walker: **9 literals with a ≥5-space run on main, 3 SQL
column alignments, 6 prose, 4 of them defects; 0 defects after.** The two
surviving prose hits are the CLI's aligned help columns and are correct.

**Both candidate guards were measured and rejected.** A grep scoped to literals
with no SQL keyword reports 6 on main (66.7 % precision) and **2 on the fixed
tree**, both legitimate — it would ship above zero with markers on correct code,
and adding a prose-punctuation clause does not separate an aligned help column
from a sentence (`"… List the DB worker-identity registry."` has a full stop).
A render-time collapse at `mcp_text`'s JSON boundary is rejected on two grounds,
one of them measured: it hides the defect rather than preventing it (the source
literal stays wrong and the next reader copies it), and **it would have covered
two of these four at most** — the Prometheus HELP text and the tracing WARN
never pass through `mcp_text`.

### `remove_member` refused every caller, and that is why the mutation survived

The brief for this package recorded a redundant last-owner arm in
`talos_organizations::remove_member` and asked for the reachability enumerated.
It is enumerable and the second arm was DEAD: `check_org_access(.., Admin)`
admits only Admin or Owner; the rank rule refuses a caller below the target and
`Owner` is the maximum, so a target of Owner implies a caller of Owner; two
DIFFERENT owner rows make `owner_count >= 2`. So the guard is reachable only
when `caller_id == user_id`, which the first arm already answers — the second
was a strict subset behind a `return`.

**But the enumeration is not why the mutation survived.** Writing the test for
the surviving arm turned it RED with `Failed to count owners`:

    SELECT COUNT(*) FROM organization_members
    WHERE org_id = $1 AND role = 'owner' FOR UPDATE
    -- ERROR:  FOR UPDATE is not allowed with aggregate functions

Postgres refuses the statement outright, so **`remove_member` failed for EVERY
caller and every target** — the member-removal path has been entirely
non-functional since MCP-996 added the TOCTOU hardening in May 2026, and
NEITHER last-owner arm was ever reachable. No test could have distinguished the
arms however it was written. The same statement appears a second time in
`update_member_role`'s demotion guard, where it fires only when demoting an
Owner. Both now put the aggregate OUTSIDE the locking subquery
(`SELECT COUNT(*) FROM (SELECT 1 … FOR UPDATE) locked_owners`), which takes the
same row locks. **LATENT on this deployment**: the live database holds 1
`organization_members` row and 0 non-personal organizations.
`organization_tests::the_sole_owner_cannot_remove_themselves` asserts the
MESSAGE and not merely the refusal — asserting `is_err()` is precisely what let
the dead arm stand in for the live one — with a control proving the guard keys
on the owner COUNT rather than on self-removal.

### A harness helper that had never once executed

`controller/tests/common::create_test_organization` issued
`INSERT INTO organizations (name) VALUES ($1) RETURNING id`, omitting **two**
NOT NULL columns (`slug` and `owner_id`), so it failed on every call. Nothing
noticed because its only caller, `create_authenticated_org_client`, had zero
callers: three helpers deep, all dead, so the first test to reach for the
harness would have failed on the harness rather than on its subject. It now
routes through the production `OrganizationService::create_org` (the Testing
Conventions rule — and it had drifted), `add_user_to_organization` became an
UPSERT because `create_org` already inserts the owner's membership row, and
`api_auth_integration_test::org_scoped_client_helper_actually_provisions_an_org`
drives the chain end to end. Reinstating main's helper body is RED.

### 2026-09-08 — the class closes at ZERO, and the gate that would have guarded it does not work

The swallowed-READ family ends here. Package 31 left **34** `claim` sites — a
read whose default becomes a count, a list, a verdict or a "not found" that a
caller acts on. All 34 are closed: **32 repaired, 2 reclassified**, and the
classifier now reports **121 sites, 0 claim** (from 153). The count is by
MEASUREMENT, not by relabelling — both reclassifications quote the field they
feed and why nothing there claims anything any more.

**Falsification first.** Twelve main-vocabulary twins were run in a real
`git worktree` of `origin/main` (`1ded89ac`) against its own migrated database:
**12 of 12 FAILED BY ASSERTION, none by compile error.** Main answered, verbatim
— `"Scratch session 'p32-scratch' not found"` for a session it could not read;
`"Workflow not found or access denied"` for a workflow whose ownership row it
could not read; `star_count: 0` on the branch reached only because this caller
had already starred it; `top_modules: []` beside a note calling the emptiness
*"a real signal, not an error"*; `catalog_tool_count: 0` with `total_mcp_tools`
silently equal to the static count; `node_timing_breakdown: []` for a workflow
with a completed run; a bare `=== Top Workflows ===` header with nothing under
it; `match_count: 0` from `preview_capability_dispatch`; `count: 0` with a tip
pointing at `list_module_catalog`; `"Actor … owns no active workflows. Create
one"` for an actor that owns two; and `ready_to_run: false` with a fabricated
`missing_secret` blocker for a credential that was provisioned.

**Three repairs are worth carrying, because each is the class in a shape the
earlier passes did not have.**

**(a) A note that VOUCHED for the emptiness.** `get_marketplace_stats` rendered
`top_modules: []` from `.unwrap_or_default()` under
`top_modules_note: "…Empty if no module has been downloaded yet — that is a real
signal, not an error."` That is worse than a bare default: the response
affirmatively certified the one thing the failed read could not establish. The
note is now conditional on its OWN field (a free `top_modules_unmeasured`
helper, not an inline `!readings.complete()`, so a future second read on the
same ledger cannot silently rewrite this sentence).

**(b) A load-bearing read whose failure produced an ALL-CLEAR.**
`get_config_suggestions`' node-template read feeds the module name, its
canonical `allowed_secrets`, its schema and therefore `missing_fields` — and the
very next block returns *"No missing required fields for this node."* on a tool
whose entire job is naming what is unset. An EMPTY result stays a legitimate
answer (a node whose `type` is not a template id); only the `Err` refuses.

**(c) A report that had ALREADY admitted the ambiguity in prose.**
`get_workflow_performance_report`'s `NODE_TIMING_BREAKDOWN_NOTE` said an empty
list means the rollup fallback *"had no rows or its query failed, which this
surface does not distinguish"*. Now it does: `null` when BOTH sources failed,
`[]` when they were read and there was nothing. One working source is a real
measurement and stays a list, and the two failures name the field ONCE — a
second `record` would make one unreadable breakdown look like two. Note the
three reads COMPOUNDED: the primary emptied the breakdown, the rollup fallback
that exists to repair exactly that was skipped by its own `if let Ok`, and the
extremes query rendered slowest/fastest `null` beside a NONZERO
`total_completed_executions`.

**A refusal that had no field to disclose into, twice, and the answers differ.**
`talos-api` has no `talos-measurement` dependency and both its sites return a
typed value. `rotateEncryptionKey` returns a bare `i32` and now PROPAGATES — the
position `me`'s `UserInfo` was in one package ago, and the same answer. `1` was
never a placeholder: it is the version number the toast prints and an operator
tracks, so an unreadable count silently REWOUND that history; `0` would have
been worse still, because `SecretsManager.tsx` does
`if (data.rotateEncryptionKey)` and a falsy value renders no toast at all. The
error names the half that SUCCEEDED so nobody re-rotates. `clone_actor` does
NOT propagate — the actor is already committed — so `memories_copied` becomes an
`Option` and the difference lands where an operator actually reads it, the
action-log line that said *"(0 memories copied)"* for a copy that failed. That
fix also closes a second, silent gap the MCP twin had already closed: an UNKNOWN
count now RUNS the embedding backfill (bounded at the cap) instead of skipping
it, so rows that DID land before the error are not left permanently invisible to
semantic recall.

**A plain-text report gets the same ledger.** `get_session_context` renders text
and has no `measurement` object, so an earlier draft hand-rolled a
`Vec<&'static str>` of unread sections. That was replaced by
`talos_measurement::Readings` with only the RENDERING different — one home for
the disclosure sentence and for the `report_field_not_measured` log event. Its
three lists are what an agent reads as an inventory of what the user already
has, and three empty ones say *"no ready workflows, nothing run recently,
nothing matches"*, which is what pushes it to BUILD instead of REUSE.

**`/mcp/local` now REFUSES, and the comment that stood there is why.** It read:
*"a fresh database leaves agent.user_id = None, causing every user-scoped INSERT
to write NULL and every user-scoped SELECT to return zero rows — tools appear to
succeed but nothing persists."* The consequence was NAMED and not prevented —
reported-success-on-a-failed-read for EVERY tool on the endpoint at once, which
is the widest blast radius in this whole family. `Ok(None)` from the first read
is still a genuinely fresh database and still creates the dev user; an `Err` from
either read, or a creation that produced no user, refuses. The JSON-RPC
notification check moved ABOVE the resolution so a refusal cannot put a body on a
notification.

**Two RECLASSIFICATIONS, stated with the field.** `get_execution_lineage`'s root
lookup was repaired by the 2026-09-08 package and never re-verdicted: its `Err`
arm still substitutes the anchor — there is no better id to walk from — but it
sets `root_unreadable`, which renders `root_execution_id` as `null` and takes
`lineage_note`'s FIRST arm. `import_workflow`'s `upsert_wasm_module` write still
pushes the module onto `still_missing`, because it genuinely is not importable,
but it now carries its REASON: FOUR of that list's five push sites are something
other than "no source in bundle", and the sharpest is a DATABASE WRITE failure
after a successful compile, which sent the operator to fix a bundle that was
fine.

**The DB tests are per-COLUMN, not per-table, and that is the design.**
`controller/tests/claim_read_disclosure_tier5_tests` (14 tests, CTRL_TESTS per
check 64b) drives the REAL MCP dispatch over a real `McpState`. Almost every
site here needs one read of a table to SUCCEED and the NEXT read of the SAME
table to FAIL, so the injection is `ALTER TABLE … DROP COLUMN <c>` where `<c>` is
named by the second statement and not the first — `module_marketplace.name`
(the leaderboard, not the aggregate), `module_marketplace.star_count`,
`workflows.is_enabled` (the ownership read, not the version history),
`workflows.readiness_score` (one session-context section, not the other two),
`workflows.name` (the comparison set, not the source graph; the candidate
listing, not the solo probe), `modules.category` (the two fallbacks, not the
target lookup, which spells it `kind AS category`), `modules.config_schema` (the
catalog listing, not the static tool count). That is a sharper instrument than a
table drop and it is what makes these tests prove a per-FIELD disclosure rather
than a blanket refusal. Every test carries its CONTROL in the same run, and the
quickstart fixture asserts that its `vault://` reference actually REACHES the
secrets branch, because a conditional assertion over a branch nobody entered
proves nothing.

**Six sites have no round trip and are said so rather than implied.**
`get_config_suggestions` (2) refuses at its top for want of an LLM client;
`import_workflow`'s write needs a real compile; `instantiate_workflow_pattern`
(2) needs an installed AND compiled built-in pattern; `create_router`'s
`/mcp/local` resolution is a closure inside the router builder. Those carry a
SOURCE pin, which proves the expression is present and never that it produces
the right answer. `talos-api`'s two have no injection either: `clone_actor`'s
copy and `rotateEncryptionKey`'s count each read the same relation as the
operation that must succeed before them. And `actor_recall`'s `key_exists_at_all`
probe names NO column `recall_exact` does not, so no drop separates them — its
two MEASURED arms are pinned and the `unknown` arm is not reachable from a
relation-level injection.

**Leg B — the CLAIM verdict as a lint leg was BUILT, MEASURED and REJECTED;
`--count` stays 88.** On the fixed tree the candidate reports **0 claim and 0
unclassified**, which is the zero baseline check 52's rule demands, and on
pristine main it reports **32 of the 34**. It still fails, on three independent
measurements. **(i)** A revert at a site this package RECLASSIFIED is completely
green: the opt-out key is `(file, function, callee, spelling)`, which cannot tell
the pre-fix expression from the post-fix one at the same call site — a verdict is
a property of the CODE and the table can only name a LOCATION. **(ii)** The two
mutations it does catch (`unwrap_or_default`, `if let Ok`) are caught ONLY
because the table still carries the PRE-fix verdict for the 32 repaired rows.
Simulated with those rows maintained — which is what *"what the default CLAIMS"*
means once the default is gone — the `unwrap_or_default` mutation SURVIVES with a
fully green report. **(iii)** A `.ok()` revert never reaches the CLAIM arm at all,
because the spelling is part of the key; it lands in the ratchet arm. And the
ratchet arm is the whole cost: it fires on every NEW collapsed read whatever its
verdict, and packages 29 and 31 each ADDED two detector artefacts on CORRECT code,
so it would have fired four times across the two most recent changes in this
family against a 196-row hand-maintained table — check 74's own recorded rot mode
and check 64's "a sweep is a snapshot, not a gate", one level up.

What guards the class instead is what already guards it, and it is stronger than
the grep would have been: sub-leg **74b**, whose scope is DERIVED (any function
constructing a `Readings`), so the eight handlers that adopted a ledger here
enrolled themselves; the `#[must_use]` three-valued lookups; the shared
`utils::workflow_lookup_unreadable_error` so the "we could not read it" sentence
has ONE home; and the DB tests above.

**The whitespace-run artefact, third occurrence, and the mechanism is now
known.** `get_platform_hygiene_report` rendered, live, *"A further 8 dormant
workflow(s) are EXCLUDED from this list and this&nbsp;&nbsp;…&nbsp;&nbsp;count
because an operator has already retired them"* with runs of 23 spaces — the
`\`-continuation that lost its `\` and kept the indentation. The literal-aware
walker is CHECKED IN as `scripts/lint-whitespace-runs.py` — a MEASUREMENT tool,
not a lint, shipped because the previous two occurrences of this class each lost
their detector with a worktree and a CLAUDE.md sentence must not cite an
artefact the merge discards (the same reason `lint-swallow-classify.py` exists).
It (escapes resolved, `\n` treated as a newline so
embedded WAT and ASCII art do not read as prose, runs that FOLLOW a newline
excluded as deliberate multi-line indentation) reports, on pristine
`origin/main`, **200 literals carrying a ≥5-space run**, of which **14 hits fall
on 6 DISTINCT literals that are mid-sentence prose** — **5 genuine defects**:
this one, two in `talos-scheduler`'s `record_dispatch` call-site assertions, and
two in the 2026-09-08 `compress_actor_context` test messages — and **1
legitimate**, `talos-offhost-backup`'s aligned CLI help column. All five fixed;
on the fixed tree the walker reports **185 literals and exactly 1 mid-sentence
candidate**, which is that help column. **The CAUSE, found by making it twice in this very
change**: a `\` at the end of a line inside a Python `'''…'''` string is a Python
line continuation, so an edit script that writes Rust `\`-continuations through a
non-raw triple-quoted string silently EATS them. Use a raw string. That is the
first time this class has had a mechanism rather than a description, and it is
why CLAUDE.md's earlier entries could only say "a continuation that lost its
`\`". **No lint**: the measurement says the same thing package 23's did — 200
literals carry a run and only 5 of them are defects, so a rule scoped by the run
alone is ~2.5% precision, and even the mid-sentence narrowing ships at 1 marker
on correct code. Telling prose from an aligned column is a judgement a grep
cannot make.

**`summary.note` renders as no key when there is nothing to say.** It was
observed live as `"note": ""` — a field a reader cannot tell apart from a note
the report failed to build, which is the shape this whole family removes.
Verified before changing it: the hygiene report is MCP-only (no frontend
consumer at all) and the single Rust reader is the degraded-path unit test,
where the note is non-empty by construction. Both halves are pinned, and both
mutations (re-emitting the key unconditionally; reinstating the broken literal)
are RED.

**What was measured and NOT changed.** The 121 remaining sites are 60
decorative, 37 fail-closed, 31 false-positive and the 1 nominal `fail-open` that
is the 2026-09-07 `dlq_updates` narrowing. None makes a claim. The detector's
stated limits are unchanged and still bound what "zero" means: it is TEXTUAL, so
a collapse reached through a helper in another crate or applied to an
already-resolved local one statement later is invisible; `if let Some(..)` over
an Option-returning read is structurally out of range (measured at ~6% precision
when widened, and it is the shape the three worst fail-open gates took); and a
verdict is a judgement about the RESPONSE, so it can be wrong where the response
shape is not obvious from the call site. "Zero claims" means zero of the
population this detector can see.
