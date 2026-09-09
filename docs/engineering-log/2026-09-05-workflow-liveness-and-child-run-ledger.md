<!-- Archived narrative, moved VERBATIM out of CLAUDE.md. Do not reword: the
     digest in CLAUDE.md's "Engineering log" section points here, and
     `scripts/check-engineering-log.py` proves every removed line still
     appears here. New decisions go in CLAUDE.md first. -->

## Two columns for one fact; a child that leaves no trace

Two operator-facing reports asserted a determinate negative for a state the
reader could not represent — the misleading-report class (checks 74, 76, 79/79b,
81) in two fresh shapes, both measured live 2026-09-05.

**"Unscored" over a score written an hour ago.** `workflows` carries TWO
readiness timestamps and TWO writers that each stamp only their own: the hourly
recompute in `controller/src/bootstrap/background.rs` writes
`readiness_computed_at`; the on-demand `get_readiness_breakdown` write-back
(`AnalyticsRepository::set_workflow_readiness_score`) writes
`readiness_scored_at`. Every reader anchored on the second, so with
`readiness_computed_at` set on 36 of 36 dev-fleet rows and `readiness_scored_at`
on **1**, `get_all_readiness_scores` answered `unscored_count: 27` of 28 and
per-row `score_state: "unscored"` **beside a `readiness_score` of 87**, telling
the operator to run a tool to compute a score that already existed; the flagship
reported `score_age_hours: 986` against a score recomputed that afternoon. The
previous fix here (MCP-1211) collapsed a two-STATEMENT write into one atomic
UPDATE — correct, and it left the predicate intact because it never saw the
**second writer**. The decision now has ONE home,
`talos_analytics_repository::readiness_state::classify_readiness_state`, which
reads BOTH columns, returns the EFFECTIVE (more recent) timestamp and NAMES the
scorer. **The columns are deliberately NOT collapsed**, and the reason is
measured rather than assumed: the two scorers are not the same function — the
arithmetic is shared (`compute_reliability_score` IS the background loop's
inline expression) but `get_readiness_exec_data` adds
`AND NOT (status = 'failed' AND acknowledged_at IS NOT NULL)`, so the background
number is the lower one on any workflow with an acknowledged failure in the
window. One timestamp cannot say which scorer produced the stored number, and a
`readiness_scored_at = COALESCE(...)` migration would relabel 35 background
scores as breakdown scores. So the READER was taught to read both, and
`readiness_population`'s `unscored` predicate now requires BOTH to be NULL.

**A daily sub-workflow "recommended for deletion".** `execute_subworkflow_graph`
runs a child IN-PROCESS and records no `workflow_executions` row — measured:
ZERO rows carrying `parent_execution_id` across the live table AND the archive,
platform-wide. `get_platform_hygiene_report`'s dormant query read that table
alone, so 3 of its 13 findings were children of ENABLED parents
(`cos-team-recall` — the flagship `pa-chief-of-staff`'s daily `team_gather`
sub-workflow — `pa-quality-judge`, and `pa-ask`), listed under *"Consider
disabling or deleting them with `batch_delete_workflows`"*. The row now carries
`runs_as_child_of: [parent names]` plus the note that `last_execution: null`
means NO EVIDENCE, and is EXCLUDED from the recommendation's count with the
exclusion disclosed (`excluded_child_workflows`, and the deletable names
enumerated) — it stays in the LIST, because an operator asking "what has no
executions?" should still see it. The exclusion is graph-derived and keyed on an
ENABLED parent; a self-reference does not protect a workflow, or every recursive
one would be permanently immune. The same query now reads
`workflow_executions_archive` too: the dormant window and `ARCHIVE_AFTER_DAYS`
are both 30 by default, so a live-only read is right by COINCIDENCE, and at
`ARCHIVE_AFTER_DAYS=7` every workflow that ran 8 days ago reads as never-run.

**The child-reference set has ONE implementation**, moved (not copied) into
`talos_workflow_engine_core::child_workflow_refs`, which
`talos_workflow_validation::collect_subworkflow_references` now re-exports. The
move closed the gap that function's own doc comment declared: the
`*_workflow_id` suffix convention covers seven of the engine's EIGHT
child-naming sites and structurally cannot see the eighth — `llm_dispatch`'s
`data.routes`, whose arbitrary class labels key the workflow ids — so
`get_workflow_risk_assessment` was blind to every route target too.
`child_workflow_ids_checked` is three-valued: `None` = the graph did not parse
(UNKNOWN), `Some(vec![])` = parsed and names nobody. A report that suppresses a
DELETE recommendation on the strength of "this is somebody's child" must not
read an unparseable parent as one that references nothing, so unreadable parents
are NAMED in `summary.child_workflow_exclusion.unreadable_parents` and in the
recommendation's own prose.

**What was measured and NOT changed** (stated so the population is visible
rather than rediscovered — the same discipline as the write-ceiling entry
above). A graph-blind execution read misleads **26** surfaces, not one. Two more
are DESTRUCTIVE and share the exact blindness: `stale_draft_workflows` (whose
`fix_all confirm=true` DELETES) and `session_start`'s `archive_stale_drafts`
(which ARCHIVES without confirmation), both keyed on
`status='draft' AND NOT EXISTS (SELECT 1 FROM workflow_executions …)`.

**That "latent today (no draft child on the fleet)" claim was refuted by this
report's own output, in the first run after it deployed** (2026-09-05 17:20Z).
`cos-team-recall` is `status = 'draft'`, and it appeared TWICE in one response:
in `dormant_workflows` annotated `runs_as_child_of: ["pa-chief-of-staff"]` and
excluded from the delete count, and two sections down in `stale_draft_workflows`
with no annotation, under *"1 draft workflow(s) have never been published or
executed in 7+ days — likely scaffolding leftovers … delete with
`batch_delete_workflows`"*. The graph scan that produced the first was scoped to
the DORMANT candidate list; nothing widened it. **A latency claim about a
population is only as good as the query that measured it, and the query used
was the one already fixed.**

Corrected severity, because "a `confirm=true` `fix_all` would have deleted the
flagship's child" is ALSO not what was measured. On the live fleet the preview
showed `stale_draft_workflows_to_delete: []` and
`substantive_drafts_skipped: [cos-team-recall]` — spared by
`is_substantive_workflow`, an authored-INTENT predicate that asks whether a
human shaped the draft and knows nothing about who runs it. So the delete was
blocked by COINCIDENCE, and a child with a bare graph was fully exposed:
verified against a pristine `origin/main` tree, where the same fixture with a
one-node empty-`data` graph puts the child in `draft_ids` with
`substantive_drafts_skipped` EMPTY. What WAS live and unconditional:
`session_start(auto_archive_stale_days: 7)` archived it, and
`batch_delete_workflows` removed it with no refusal of any kind.

Now: the same graph scan runs over dormant ∪ stale-draft candidates, the draft
row carries `runs_as_child_of` + `excluded_from_cleanup_reason`, the
recommendation's count excludes it with the exclusion disclosed
(`excluded_child_workflows`, `summary.child_workflow_exclusion
.excluded_stale_drafts_count`, and prose saying why count and list disagree),
`fix_all` gains a THIRD bucket `child_drafts_skipped` ahead of both existing
ones, and `archive_stale_drafts_excluding_children` SELECTs candidates → scans
→ UPDATEs **by id**, so the write is a subset of what was scanned by
construction. **The scan has ONE implementation** in the leaf crate
`talos-child-workflow-refs` (moved out of `talos-analytics-repository`, which
re-exports it): its three consumers — the hygiene report, the auto-archive, and
the delete-time guard — sit in three crates with no edge between them.

**REPORT and DECISION are different rules, and conflating them is how #758
stopped one section short.** A report row stays LISTED with its parents named;
a decision EXCLUDES it. They also disagree on the UNKNOWN case, deliberately:
`ChildReferenceScan::parents_of` (report) names only parents whose graph
PARSED, while `protection_for` (decision) additionally holds back a candidate
whose id merely appears in the text of a parent nobody could read — the scan is
scoped by a mention prefilter, so such a parent demonstrably mentions it, and
"I could not read the parent" is not "no parent dispatches into it". #758's
`octet_length(graph_json) <= $3` filter DROPPED an oversized parent from the
scan entirely, so its children read as unreferenced and it was not even named
under `unreadable_parents`; the row is now returned with a NULL body and
classified unreadable.

**Second finding, and it is the last line of defence: `delete_workflows` had no
reference guard at all.** It blocked only on running/queued executions — which
a sub-workflow never has — so every guard in this class lived in a report that
RECOMMENDS calling the tool, and the tool itself would remove a live child
without comment. The reference lives inside `workflows.graph_json` as TEXT, so
no foreign key can express it. `delete_workflows_checked` returns
`WorkflowDeleteOutcome { deleted, blocked_running, blocked_referenced }` — the
type change is the point, since it forces all three call sites to notice the
new refusal — and a parent that is ITSELF in the delete set does not block
(deleting a retired tree in one call must stay possible). `fix_all` consults it
even though its `draft_ids` were already filtered upstream: the preview an
operator confirmed may be minutes old, and a `sub_workflow` node added in
between is exactly what a graph-derived exclusion cannot see.

**Does a child's `draft` status mean anything at runtime? No, and this is worth
knowing before anyone "fixes" it by publishing.** `execute_subworkflow_graph` →
`WorkflowGraphStore::get_graph` reads the child's DRAFT `graph_json` column with
no version join, so `publish_version` changes nothing about how the parent runs
it and the "publish or delete" advice is half no-op and half destructive. That
half of the paragraph stands.

**Its other half was TRUE UNTIL 2026-09-07 and is now FALSE — it is rewritten
rather than left.** It read: *"ARCHIVING a child does not break dispatch either
(status is not read there), which is why the archive path is the least severe of
the three even though it is the only unattended one"*. The narrow dispatch gate
below closed exactly that: `get_graph` now returns `GraphLookup::Archived` and
the parent node FAILS naming the child and the word "archived". So **archiving a
child DOES stop it being dispatched**, and the auto-archive sweep is no longer
the least severe of the three destructive draft paths — it is now the one that
can take a live sub-workflow off the air unattended. The child-reference
exclusions #758/#760/#764 added to that sweep are what keep it from doing so,
and they are load-bearing in a way they were not when this paragraph was
written.

**What was measured and NOT changed here.** `AdvancedRepository::get_draft_workflows`
shares the same blind predicate and is left as-is: its only consumer is
`session_start`'s draft DISPLAY, which takes no destructive action (its
reasoning is in that method's doc comment, along with why it carries no lint
marker). And `__ops_alert__` / `__ml_distill__` remain ungated — no longer a
remainder but a DECISION, argued and reported above.

**The auto-archive remainder is now CLOSED (2026-09-05).** #758 recorded that
`session_start`'s auto-archive "still archives SUBSTANTIVE drafts — the exact
contradiction M-I fixed for `fix_all` in 2026-05" and left it, because it is a
behaviour change to an existing opt-in flag and archiving is reversible.
Measured on pristine `origin/main` before it was fixed, driving the REAL
`SessionBriefService`: the brief listed a shaped draft under
`unpublished_substantive_drafts` with `next_step: "publish_version with
workflow_id=…"` and reported `auto_archived_stale_drafts: 1` for that same row,
**in one response** — because `get_draft_workflows` was read BEFORE the sweep.
Both halves are fixed: the sweep now refuses a shaped draft, and the display
read moved BELOW the sweep, so neither list can name a row the same call
archived (that second half matters on its own — a STUB was listed with
`next_step: get_workflow_quickstart` moments after being archived, and no
substantive-ness rule would have closed that).

The predicate MOVED (not copied) to the leaf crate `talos-draft-heuristics`
(`serde_json` only), the reason `talos-child-workflow-refs` exists: the archive
sweep lives in `talos-advanced-repository`, which must not depend on a service
crate that pulls in four repositories. Three consumers, three crates, no edge
between them: `fix_all`'s auto-DELETE partition, the auto-ARCHIVE sweep, and
the draft DISPLAY. **The old home's doc comment claimed *"Both `session_start`
… AND `get_platform_hygiene_report fix_all` consult this helper so the two
surfaces never disagree"*, and it was FALSE — `session_start` carried an INLINE
COPY of the same 20-line walk.** Behaviourally identical, which is why nothing
caught it; an ALL-sites claim is worth only as much as the sites being unable
to drift.

`DraftIntent` is THREE-valued and `is_substantive_workflow` is a thin two-valued
view over it, byte-for-byte the old behaviour. The third value is for the paths
that WRITE: `is_substantive_workflow` answers `false` for "no markers" and for
"`graph_json` would not parse" alike, and on a sweep those are not the same
answer — `graph_json` is `text NOT NULL`, so an unparseable graph is storable,
and it is now held back under its own distinct reason. Same UNKNOWN-is-not-NO
rule the parent scan applies. Both exclusions run at the ONE chokepoint,
child-FIRST (matching `fix_all`'s partition — publishing a draft retires the
substantive reason and leaves the child reason standing), each skipped id
reported under its own reason (`auto_archive_skipped_children` /
`auto_archive_skipped_substantive`, with the `substantive_drafts_skipped`
wording `fix_all` already prints), and the UPDATE stays by-id over what was
classified.

**Deliberately NO force flag**, mirroring `fix_all`, which has had this
exclusion since 2026-05 with no override: the escape hatch is an EXPLICIT
operator action (`publish_version`, or `archive_workflow` /
`batch_delete_workflows` naming the workflow). An `include_substantive: true`
would re-enable an unattended destructive sweep over exactly the population the
rule exists to protect. The skip is disclosed in every response, so a draft
cannot quietly acquire permanent immunity, and the tool schema now says so
instead of promising to "archive draft workflows that have never been published
or executed".

**Blast radius, measured on the dev fleet 2026-09-05: ZERO additional skips
today.** 36 workflows, 11 drafts, 2 with no execution row; at any window ≥7 days
there is exactly ONE candidate, `cos-team-recall`, and #760's child rule already
spares it. So the substantive rule is LATENT on this fleet — stated plainly
rather than dressed up, since "latent is not live" cuts both ways and the
previous entry in this section was written the same way one day before the
condition it called latent went live.

**What was measured and NOT changed here.** The hygiene REPORT's stale-draft
recommendation counts a substantive draft as `deletable` and names
`batch_delete_workflows`, while `fix_all` — the DECISION built on the same rows
— excludes it. That is the report/decision split running the other way from the
child case (where the report lists and the decision excludes), it is advice a
human reads rather than an unattended write, and the sentence already offers
`publish_version` first; changing it would move a count an operator may have
wired up, so it is recorded. And a NON-substantive draft is still listed under
`in_progress_drafts` and swept in the same session — that is the flag doing
exactly what it was asked to do, and the ordering change means it is no longer
listed and archived in the same RESPONSE.

**No lint check was added, and the numbers are here so a future session need not
re-measure.** A "the substantive predicate has one home" detector — a file
naming both `retry_delay_expression` and `"SYSTEM_PROMPT"` outside the leaf
crate — reports exactly the duplicate on pristine `origin/main` and 0 on the
fixed tree: 1/1, trivially 100% precision, population ONE. That is a
single-instance historical class already answered structurally (one `pub` home,
`#[must_use]` on every entry point, and a DB test that drives both surfaces over
the same rows), so it is left unwritten rather than shipped as a check that has
never had anything to say. Note what that DB test does and does not cover,
because it was proven by mutation and not by reasoning: reducing the DISPLAY
half to branch 1 alone SURVIVED the first version of it, since every seeded row
agreed on both branches — the test now seeds a branch-1-only and a
branch-2-only shape, and the branch-2-only one (`data: {}` plus `retry_count`)
is the shape the live fleet's only stale-draft candidate actually has.

**#762 — the SCORING half: a child's reliability and freshness are UNMEASURABLE,
not zero.** #758/#760 fixed the DESTRUCTIVE readers; the same blindness also fed
three readiness scorers, the reuse report and a dead schedule-suggestion filter,
and those are fixed here. Reliability (50 pts) and freshness (20 pts) are read
from `workflow_executions` and from nothing else, so 70 of a child's 100 points
were scored from a table that is structurally silent about it. Measured on the
reference fleet 2026-09-05 — the WHOLE population of children, not a sample:
`cos-team-recall` 19 (the flagship's daily team gather), `pa-ask` 19 (runs per
inbound email), `pa-quality-judge` 19 (judge of three workflows),
`stress-05-child` 14, against a fleet otherwise at 40–87. The hourly loop
PERSISTS those numbers and `get_all_readiness_scores` sorts ascending, so the
flagship's own daily sub-workflow read as the least production-ready workflow on
the platform and `below_50_count` counted it.

**The DENOMINATOR shrinks; the score is not renormalised.** Two renderings were
rejected before this one and the rejection is the design: scoring the two
components 0 out of 100 is the determinate negative this whole class is about;
scoring the measurable 30 and SCALING IT UP to 100 fabricates — a documented,
low-risk child would report **100/100, fully production-ready** on zero execution
evidence, which is worse than the zero it replaces because it is confident in the
reassuring direction. So a child scores *N of `CHILD_MEASURABLE_MAX` (=30)*, its
unmeasurable components are NAMED, and `comparable_to_fleet` is false. The
shrunken denominator is what tells a reader the two numbers are not on one scale;
a number out of 100 does not, however it was derived. ONE home:
`talos_analytics_repository::readiness_basis::{ReadinessBasis, score_readiness}`,
called by all three scorers — what is unified is the BASIS, deliberately NOT the
reliability INPUT (the breakdown excludes acknowledged failures, the loop counts
them; #758 chose to disclose that and that decision stands). Child-ness comes
from `parents_of` (REPORT semantics), so an UNREADABLE parent leaves the workflow
on the full scale and the incompleteness travels by NAME
(`unreadable_parent_graphs` / `readiness_unreadable_parent_graphs`) rather than
silently. **Nothing to say ⇒ no key**: a full-scale workflow's response is
byte-identical to the pre-#762 one, except `get_all_readiness_scores`, which
emits `max_possible` on EVERY row — that list exists to rank rows against each
other, and a denominator present on some rows and absent on others is read as
"the others are out of 100" by exactly the caller who needs telling otherwise.
`below_50_count` EXCLUDES children with the exclusion disclosed
(`below_50_count_raw`, names, `measured`, `complete`), because a child is below
50 by construction; `avg_score` is deliberately NOT adjusted (it is a
population-wide SQL mean that the page cannot correct) and says so. The
page-scoped exclusion's COMPLETENESS is checked, not assumed: a child is ≤30, the
page is the ascending prefix, so a page reaching past 30 has already swallowed
every child — `child_exclusion_is_complete` computes that condition and the
summary says PARTIAL when it does not hold.

**Cost, measured rather than assumed.** The scan is one `LIKE`-prefiltered parent
read: **0.40 ms** at one candidate (the breakdown / `validate_workflow` path) and
**3.8–4.6 ms** with the whole 36-workflow fleet as candidates. The hourly loop
runs ONE scan per USER per tick — the 500-row batch is grouped by `user_id` and
each group's ids are the candidate list — against a loop that already issues
THREE queries per workflow; a per-workflow scan would have been 36 of these. A
failed scan falls back to full-scale (the pre-#762 answer) and is logged, never
aborts the tick.

**`get_workflow_reuse_stats` INNER-JOINs executions**, so `pa-ask` — dispatched
per inbound email, 0 rows live and archived — was ABSENT from the reuse tool, not
shown as zero. It now carries a SECOND list, `parent_dispatched`, with
`total_invocations: null` and `runs_as_child_of`: folding those rows into the
main list with a count of 0 was rejected because that list is RANKED by the count
they do not have. Bounded by `REUSE_ZERO_INVOCATION_SCAN_LIMIT` with truncation
disclosed.

**`get_frequently_executed_unscheduled`'s sub-workflow exclusion was DEAD for two
years and its own comment recorded the wrong lesson twice.** r242 wrote
`node.kind` / `data.sub_workflow_id`; r243 "corrected" it to
`module_id = 'system:sub_workflow'` / `config.sub_workflow_id` and wrote down
*"the lesson: verify the actual JSON shape via `get_workflow`"* — having done
exactly that and landed on a second shape the engine also does not write; r244
then fixed a real `::jsonb` cast on top, which made the query RUN, which is why
nothing looked broken. Measured live, both predicates as SQL against the real
column: r243's matched **0** nodes, the engine's `type` / `data.*_workflow_id`
shape matched **6** across 5 parents. The real lesson is that a hand-written
`graph_json` predicate is a SECOND IMPLEMENTATION of a question the engine
already answers — reading one workflow's JSON tells you one node kind's shape,
and the engine names a child through EIGHT keys, one of which
(`llm_dispatch`'s `routes`) is keyed by arbitrary class labels no key-name rule
can see at all. The exclusion now runs through the ONE scan, in Rust over a
widened page so removing a child does not under-fill the list of ten, and
`child_reference_shape_tests` pins it against the engine's parser rather than
against a string. Stated rather than sold: this exclusion is **vacuous on the
reference fleet today** — `HAVING COUNT(we.id) >= 3` already excludes every pure
child, so it bites only a HYBRID (dispatched AND directly triggered ≥3), of
which there are currently zero.

**`get_workflow_risk_assessment`'s cascading-failure check is DISCLOSED, not
fixed.** It `continue`s on a zero-row population, so on this fleet the
HIGH-severity check can never fire for any child. No risk entry is pushed (an
`info` row on every parent with a judge node would be noise on three of this
fleet's workflows); the population is emitted as
`cascading_failure_check.sub_workflows_unmeasurable` so "no cascading-failure
risk found" is legible as a statement about what was measurable. **The background
SLA-breach monitor is RECORDED and NOT changed**: it is an ALERTER with no
operator-facing field to disclose into, its `stats.total >= 3` gate can never
pass for a child, and the honest fix is a per-run record it does not have. So
`set_workflow_sla_threshold` on a child is silently inert. **BOTH sentences are
SUPERSEDED by the RFC 0012 P3 entry below (2026-09-07)**: the per-run record now
exists, the check reads it, and the alerter both reads it and has a channel to
say when it could not measure. Read them as the state before that entry, not as
current behaviour.

**What #762 could NOT guard, stated rather than implied.**
`controller/src/bootstrap/background.rs` is `mod bootstrap` inside `main.rs`,
i.e. bin-private, so no integration test can call its loop: deleting the loop's
`child_scans` lookup leaves every test green. What is covered by construction is
the shared decision — all three scorers call `score_readiness`, so removing the
classification from it turns three tests red (mutation-proved). The handler-level
wiring of the reuse list and the risk disclosure likewise has no test; the
repository methods and pure renderers behind them do.

**A lint for this class was BUILT, MEASURED and REJECTED — count stays 86.** The
candidate rule was *"a reader that scores or counts from `workflow_executions`
must consult the child scan"*. File-scoped, it reports **23 of 27** non-test
files on the FIXED tree and nearly all are legitimate (`checkpoint_store`,
`fence`, `stale_sweep`, `approval_gate`, the audit ledger, the secrets manager) —
those read execution rows for durability, authorization and crypto, not to make a
claim about use. Narrowed to an alternation of the five per-workflow reader
methods it reaches **7 call sites**, ~71% precision against pristine main, and
would ship at 2 with opt-out markers on the two surfaces deliberately left
disclosed — but its recall against the ~26 graph-blind surfaces is **27%**, the
alternation is the hand-maintained name list check 74 records as its own rot mode
(there is no derived method family here — the six readers have six unrelated
names in three crates), and, decisively, **it does not see the background loop at
all**: that scorer reads executions with raw `sqlx::query_as`, not a repository
method, so the lint would be green over the one writer whose number every other
reader reads back. A gate blind to the most consequential site in its own class
is the gate-that-doesn't-gate shape (#624, checks 64/65). The population is
recorded here instead. **The structural question these all share is
whether `execute_subworkflow_graph` should record a child `workflow_executions`
row** (`parent_execution_id` / `root_execution_id` exist and are written only by
replay today). Measured before deciding: ~225 estimated child runs/day, 98.6% of
them one workflow; **163** `FROM workflow_executions` occurrences across 28
non-test files, of which exactly **2** carry a `parent_execution_id IS [NOT]
NULL` filter — so recording children would silently double-count in 161 places,
including every fleet total, error rate and cost aggregate. That is a
platform-wide change, not a report fix, and it is recorded here rather than
attempted.

**2026-09-07 — a third pair, and the report read one half of it: `workflows.status`
vs `workflows.is_enabled`.** `get_platform_hygiene_report` recommended *"10 enabled
workflow(s) have had no executions in 30+ days. Consider disabling or deleting them
with `batch_delete_workflows`"* and listed them under `deletable`. **EIGHT of the ten
were `status = 'archived'`** — the operator it was advising had already retired them.

**The mechanism is the readiness-timestamp one exactly.** `is_enabled`
(`20260314001600`) is the OPERATOR's pause toggle; `status` (`20260318000000`) is
the LIFECYCLE. Two writers, and neither touches the other's column: the six
`UPDATE workflows SET status = 'archived'` sites
(`talos-workflow-repository/src/workflows.rs:963,1346,1357`,
`talos-advanced-repository/src/lib.rs:1880,2362`,
`talos-actor-repository/src/lib.rs:1071`) never clear `is_enabled`, and
`set_workflow_enabled` never moves `status`. Measured on the reference fleet
2026-09-07: `active/t 17, archived/t 8, draft/t 11` — **every archived row still
reads `is_enabled = true`**. The dormant query predicated `w.is_enabled = true`
with NO status clause; reproduced verbatim against the live database it returns 13
rows, 8 of them archived, and minus #760's three child exclusions that is the 10
the recommendation named.

**The columns are deliberately NOT collapsed and there is NO migration flipping
`is_enabled` on archived rows** — the readiness-timestamp argument applies
unchanged: the two writers record two different operator acts, one column cannot
say which happened, and a backfill would relabel eight archives as pauses that
never occurred. The READER changed.

**The predicate has ONE home**, the leaf crate `talos-workflow-liveness`
(no dependencies), and it is TWO predicates rather than one, because the second is
not a weaker version of the first:
* `is_live` = `status = 'active' AND is_enabled` — published and not paused.
* `is_dispatchable` = `status <> 'archived' AND is_enabled` — what the PLATFORM can
  still run. A DRAFT counts: a parent dispatches a child's `graph_json` column with
  no version join and no status predicate (the "does a child's `draft` status mean
  anything at runtime?" entry above), and **4 draft workflows on this fleet carry
  enabled schedules and fire today**, so folding draft into "not live" for an
  operational population would be wrong in the loud direction.

The Rust predicates are EXACT twins of `live_sql` / `dispatchable_sql` /
`retired_sql`, including on an unrecognised `status` — the column has **no CHECK
constraint**, so `WorkflowLifecycle::Unknown` is a real state (one live query still
filters `status = 'published'`, a value nothing writes, and the pre-existing
`dormant_child_workflow_tests` seeds exactly that). An unknown status is NOT live
and IS dispatchable on both sides; `rust_and_sql_agree_on_every_status` EVALUATES
the rendered fragment rather than comparing strings, so the asymmetry is pinned as
the SQL's rather than quietly fixed on one side.

**Five sites now read it**, and the count is the point: the analytics file already
spelled the same predicate correctly FOUR times
(`is_enabled = true AND (status IS NULL OR status != 'archived')` — the `status IS
NULL` arm dead, since the column is `NOT NULL`, verified against the live catalog)
while the fifth, the dormant query, forgot. `scan_child_parents` and
`list_enabled_graph_json_for_boot_warmup` were right too and spelled it a fifth and
sixth way (`!=` and `<>`, in two crates). Six correct sites, three spellings, one
defect between them.

**EXCLUDED is not DROPPED.** `summary.archived_excluded` carries the count, up to 25
names, `names_truncated` and a note; the cleanup recommendation's sentence names
them and says why its list is shorter; `affected_count` now equals what `deletable`
contains. The read is a SEPARATE statement over the SAME window and the SAME
dormancy test with `status = 'archived'` instead — a subset of what the list
scanned, by construction — and `count(*) OVER ()` carries the true total past the
name cap. A FAILED read renders **null, never 0**: `archived_excluded: 0` claims the
operator has retired nothing, which is one word away from the sentence this
exclusion exists to stop the report making. That arm is unreachable from a DB test,
so `an_unreadable_archived_exclusion_is_null_not_zero` drives the pure renderer with
a ledger that marks the field unmeasured — it was a **measured SURVIVOR** of the DB
suite before that test existed.

**What was measured and NOT changed, and it is the severity of the whole class.**
No execution path in this workspace filters on `workflows.status` at all. Proved
with a scratch row — an archived workflow with `is_enabled = true`, an enabled
schedule due one minute ago and an enabled webhook — driven through the VERBATIM
production SQL: the scheduler due query (`talos-scheduler/src/lib.rs:1104`), the
post-due workflow load (`:1584`), the webhook dispatch read
(`talos-webhooks/src/router.rs:1763`), `resolve_by_capabilities` and
`WorkflowGraphStore::get_graph` **ALL returned it**. So archiving does not stop a
workflow being scheduled, webhook-triggered, capability-dispatched,
chain-dispatched, sub-workflow-dispatched, called, triggered or enqueued;
`is_enabled` is the only execution-path gate and it is enforced in RUST, never in
SQL, at four places (`trigger.rs:203`, `call_workflow`, `trigger_workflow_as_actors`,
`is_workflow_enabled` for retry/replay), while `bulk_trigger_workflow` and
`enqueue_workflow` have none. The SCHEDULER reads neither `workflows` column, so
`disable_workflow` does not stop a scheduled run either — the schedule's own
`is_enabled` is the pause control there. **LATENT on this fleet**, stated plainly:
the 8 archived rows have 0 enabled schedules and 0 enabled webhooks. Closing it is a
fleet-wide behaviour change with its own blast radius (those 4 draft schedules among
them), not a report fix, and it is recorded rather than attempted. `fix_all` and
`session_start`'s draft sweep were checked and are unaffected: both key on
`status = 'draft'`, a lifecycle filter that excludes archived rows by construction.

**Check 87 was BUILT, MEASURED and SHIPPED, and the numbers say why it is
window-scoped.** *"A `workflows` liveness predicate must name the shared home."*
FILE-scoped it reports **6** on pristine main of which **3** are the
`workflow_schedules.is_enabled` false positive (50% precision, shipping at 3 markers
on correct code) — and worse, it would have been GREEN over the defect once any one
of the four correct siblings in the same file named the home, which is check 86(a)'s
stated limit becoming fatal. WINDOW-scoped (1400 chars back, 400 forward, whole-line
comments stripped, `workflow_schedules` windows excluded) it reports **SEVEN on
pristine main, every one a real `workflows` liveness predicate, 0 false positives,
and 0 on the fixed tree**. Stated honestly: **7-of-7 against the RULE, 1-of-7 as a
BUG detector** — the other six were correct and merely unrouted (check 85(b)'s
framing). `--count` moves to **87**.

Three mutations, all red: reinstating the dormant defect reports it at that exact
line; a COMMENTED-OUT gate does not vouch (whole-line comments are stripped first —
check 73's trap, which cost this check one false finding on its own doc block before
the strip went in); and a tree where the shape has vanished FAILS LOUDLY rather than
passing. That third one needed a two-part tripwire and the first version got it
wrong in the reassuring direction: once a site is ROUTED the literal
`is_enabled = true` disappears from it, so a raw-literal-only tripwire reported
"found nothing" on the fully-fixed tree — measured, not imagined. It now counts raw
windows PLUS rendered `*_sql(` call sites.

### "Archived" must mean "will not run" — the NARROW dispatch gate (2026-09-07)

**The entry above closed the REPORT half and recorded the other half without
fixing it**: *"No execution path in this workspace filters on `workflows.status`
at all"*, proved with a scratch row that an archived workflow with an enabled
schedule and an enabled webhook was returned by all five verbatim production
reads. This closes it. The operator's decision is the NARROW gate and nothing
wider: **every dispatch path refuses `status = 'archived'`, and nothing else
changes.** A DRAFT still dispatches — 4 drafts on the reference fleet carry
enabled schedules and fire today — and `is_enabled` keeps exactly the meaning
each path already gave it, including the paths that have never consulted it.
`dispatchable_sql` is deliberately NOT the predicate used here: it also requires
`is_enabled`, which would have been a second, unauthorised behaviour change
wearing a one-word diff. The gate is `talos_workflow_liveness::not_retired_sql`
/ `is_not_retired`, and `not_retired_is_weaker_than_dispatchable` pins the two
apart so a future edit cannot quietly promote one to the other.

**The five paths that entry named were not the population; there are 35, and
two of its five descriptions were wrong.** The due query
(`talos-scheduler:1103`) reads `workflow_schedules` ALONE and never joins
`workflows`, so there was no predicate to add there and the gate had to sit at
the post-due load; and the named `talos-schedule-repo` join is a LISTING, not
the due query. More importantly, **"no execution path filters on `status`" was
itself false by one site**: `ActorRepository::get_workflow_graph_for_user`
(`talos-actor-repository/src/lib.rs:2050`) has carried
`AND (status IS NULL OR status != 'archived')` in SQL all along, and its only
caller is `handoff_to_actor`. So handoff was the one dispatch surface that
refused — while REPORTING the refusal as *"Workflow not found or access denied"*,
false on both clauses, because the filtered read returned `None` and the caller
had nothing else to say. That claim is corrected in the crate's own module doc,
in check 87's entry, and the read now returns the status so the caller can
classify it (`HandoffError::WorkflowArchived`).

**One gate covers seven surfaces because the enum forces it to.** The scheduler,
the webhook router, `trigger_workflow`, `call_workflow`, `bulk_trigger_workflow`,
`trigger_workflow_as_actors` and `enqueue_workflow` all mint their execution row
through `create_execution_under_concurrency_limit` (or its batch twin), whose
`SELECT … FOR UPDATE` on `workflows` was already there — so `status` rides along
on that read, the gate costs **no extra query**, and it is atomic with the INSERT
it guards. `ConcurrencyAdmission::WorkflowArchived` is a NEW VARIANT rather than
a boolean, and that is the point: the enum is matched exhaustively at all seven
sites, so the compiler asked each of them how it renders the refusal. Same move
`WorkflowDeleteOutcome` made in #758. The batch twin gets a `archived: bool`
FIELD instead, and the asymmetry is argued rather than sloppy: there
`inserted == 0` already refuses whether or not the caller reads the flag, so the
flag buys the caller the ability to say WHY — "throttled" invites a wait for
capacity that will never arrive.

**The paths that mint no row, or mint it elsewhere, carry their own gate.**
`retry` and `replay` reuse an existing row; the continuation trigger (approval
resumes, suspension resumes, and the Gmail push-notification WORKFLOW branch)
writes elsewhere; the sub-workflow child dispatch mints none by design. Those
read `WorkflowRepository::dispatch_lifecycle` — one PK read of `workflows`, the
same shape and cost as #754's `read_actor_write_ceiling` — returning
`WorkflowDispatchLookup::{Dispatchable, Retired, Absent}`, `#[must_use]`, with no
`Into<bool>`: a boolean gate is one `unwrap_or(true)` from fail-open, and its
caller could not tell a retired workflow from a deleted one when it renders the
refusal. Note `replay` already read `is_workflow_enabled` — the OTHER column —
directly above, and would have passed a retired workflow on the strength of it.

**CLASSIFY where there is one named workflow; FILTER IN SQL where there are
candidates.** `get_graph` is classified (`GraphLookup::{Found, Archived, Absent}`,
the `ExecutionLookup` shape from #748) so a parent node fails with a message
naming the child and the word "archived" instead of "not found", which would send
its author hunting a deletion that never happened. The chain fan-out,
`resolve_by_capabilities`, `resolve_by_name` and the `get_graphs` cache prefill
filter in SQL, and each has a reason: the fan-out's `LIMIT` must be applied over
real candidates or retired rows displace live ones from the chain set; the two
resolvers are `ORDER BY … LIMIT 1`, so a read-then-refuse would let a retired
candidate SHADOW a live one; and the cache prefill is only a warm-up, so an
archived child misses it and falls through to `get_graph`, which reports the
refusal once, with one wording.

**`resolve_by_capabilities` is the one site here that is NOT latent, and it is
the reason this shipped as more than tidying.** Measured on the reference fleet
2026-09-07: all 8 archived rows carry non-empty `capabilities`
(`email-delivery`, `sub-workflow`, `world-http`, `actor-memory-read`, …), and
that resolver is `WHERE capabilities @> $2 ORDER BY updated_at DESC, id DESC
LIMIT 1` with no lifecycle predicate — so a retired workflow was not merely a
candidate for capability dispatch and A2A, it could be the WINNING one. The DB
test seeds the retired row with the NEWER `updated_at` for exactly that reason,
and the main-vocabulary twin fails on pristine main by returning it.

**Everything else is latent, and saying so plainly is the point.** The 8 archived
rows have **zero schedule rows** (not merely zero enabled ones) and **zero
webhook triggers**. And the child question the brief asked to measure: **ZERO
archived children under enabled parents** — in fact zero archived workflows are
mentioned in ANY workflow's `graph_json`, whatever the parent's status. That was
measured WITH A CONTROL, because a query that finds nothing proves nothing until
it is shown able to find something: dropping the archived filter returns 6 real
parent→child mentions (`cos-team-recall`, `pa-ask`, `pa-quality-judge` ×3,
`stress-05-child`). So the sub-workflow half of this change can alter no live
behaviour today.

**Refusals are VISIBLE to the OPERATOR and OPAQUE to an unauthenticated caller.**
`talos_dispatch_refused_total{path, reason="archived"}` is pre-seeded at 0 for
all 12 paths that classify in Rust, incremented at one helper
(`talos_metrics::record_dispatch_refusal`) taking a TYPED
`DispatchPath` so a new surface cannot spell a label the constructor never
seeded. **Nothing alerts on it**: a refusal is the policy working, and an alert
here would train operators to ignore the one series that answers *a schedule
stopped firing — is the platform refusing it, or is the scheduler broken?* The
scheduler's per-tick line is **DEBUG**, not WARN, for check 69's reason (an ERROR
that fires forever on a healthy fleet trains operators to ignore ERROR); its
durable signal is the counter plus `scheduler_dispatches_total{outcome="denied"}`
— **`DENIED`, not `SKIPPED`, and the existing partition already made that call**:
that label's own doc says it is for a fire "refused by POLICY … chronic
configuration states that are unchanged by how many schedules came due at once",
which is this exactly, and folding it into `SKIPPED` would put a permanent
configuration state inside the startup-herd alert.

**The scheduler DOES NOT disable the schedule row, and that was a decision.**
Option (b) in the brief was to disable it on first refusal with a WARN. Rejected:
archiving is REVERSIBLE, so a self-disabling schedule would make un-archiving
silently not resume — a second, invisible operator act the platform performs on
the operator's behalf, which is the same two-columns-disagreeing asymmetry this
whole class is about. A permanently-firing WARN is check 69's shape. So option
(a), with the per-tick line at DEBUG.

**The webhook tells the caller nothing.** It answers exactly what it answers for
a workflow that is not there — `404 "Workflow not found"`, byte-identical — and
that is the one place in this change where a refusal is deliberately rendered as
an absence: an inbound webhook caller is unauthenticated with respect to the
workflow, and a reply that distinguishes "archived" from "no such workflow" is an
existence oracle for anyone who can guess a trigger id (the
`caller_facing_unauthorized` argument, and #754's collapsed
`write_ceiling_unreadable` reply). The operator keeps the distinction in the
counter and a WARN — WARN rather than the scheduler's DEBUG because a webhook
refusal is one inbound request rather than a recurring tick, so it cannot become
permanent noise. **There was no paused-workflow response to mirror, and that was
MEASURED rather than assumed**: the webhook path consults `workflows.is_enabled`
NOWHERE, in SQL or in Rust, so a disabled workflow still fires by webhook today.
The narrow gate does not change that — it is the other column.

**Sites deliberately NOT gated, argued rather than omitted.** (1) **Resume and
crash recovery** (`claim_stuck_execution_for_resume`,
`claim_waiting_execution_for_resume`, the resume auth gate): these FINISH a run
that was already admitted, and refusing would strand a waiting approval gate the
moment an operator archived the workflow — turning a reversible lifecycle change
into permanent loss for an in-flight run. The gate is about what the platform
will START. (2) **`test_workflow`, `test_workflow_draft`, GraphQL
`testWorkflow`**: an operator explicitly asking to test ONE named workflow is not
the platform deciding to run it, and refusing would remove the only way to check
a workflow before un-archiving it. This is the place a reader might reasonably
expect a refusal and not find one, so it is stated rather than left to be
discovered. (3) **Module replay**: replays a MODULE against recorded inputs; the
graph is read to rebuild a node's config, not to run the workflow.

**The chain fan-out's refusal is SILENT, and that is a stated limit rather than
an oversight.** `talos_dispatch_refused_total` has no `chain` label because that
site is a capped SET read, not a per-request refusal — there is no one workflow
being refused to count, and seeding a label nothing increments is the defect
check 58 exists for. The same applies to the two resolvers and the cache
prefill. Four of the sixteen gate sites are therefore uncounted, by construction.

**Guard, and what it does and does not cover.**
`controller/tests/archived_dispatch_gate_tests` (8 tests, CTRL_TESTS) drives the
REAL admission chokepoint, the REAL `WorkflowGraphStore` reads, the REAL
`dispatch_lifecycle` and the REAL handoff read. Two properties are deliberate:
it asserts on **ROWS**, not just on the returned variant — an earlier version of
#754's write-ceiling test passed because the INSERT would have failed anyway and
survived the gate being deleted, and the first draft of THIS file reproduced that
exactly (passing `actor_id: None` made both CONTROLS die on a NOT NULL constraint
while the archived case "passed") — and every test carries an **ACTIVE and a
DRAFT control**, so a gate widened to `status = 'active'` fails here rather than
looking like a stricter version of the same thing.

**Measured RED on pristine `origin/main`, by assertion and not by compile
error**: six main-vocabulary twins were run in a real `git worktree` of `1a13ad6b`
against its own migrated database, and **6 of 6 FAILED BY ASSERTION** — the
admission gate admitted an archived workflow and wrote the row, the batch twin
queued 3, `get_graph` handed back the archived child's graph, the capability
resolver returned the RETIRED workflow as the winner, name resolution resolved
it, and the handoff read hid the row. Zero failed by compile error. The twins are
a scratch artefact and are not committed.

**No lint check was added and `--count` stays 87.** The candidate — *"a
`workflows` read that feeds dispatch must name the liveness home"* — was measured
before it was written and REJECTED twice over. It cannot be scoped by SQL shape:
the 35 dispatch reads share no predicate (`WHERE id = $1 AND user_id = $2` is
also how ~40 report and authoring reads spell themselves), so a shape-scoped rule
is ~50% precision at best. Scoped instead to the FILES that dispatch, it reports
the 33 files carrying any `FROM workflows` and would ship at ~25 markers on
correct code. And decisively, it would be **green over the very defect it is for**:
every gate site in this change now names `talos_workflow_liveness`, so a
file-scoped rule is satisfied by ONE gated read vouching for every other read in
the same file — check 86(a)'s stated limit, which check 87 already had to
window-scope around. Check 87 does not cover this either: its window looks for a
LIVENESS predicate over both columns, and the dispatch gate is one column. The
structural answers that ARE stronger than a grep: `ConcurrencyAdmission` and
`GraphLookup` and `WorkflowDispatchLookup` are exhaustively-matched enums, so a
new dispatch surface cannot be added without the compiler asking what it does
with a retired workflow; `record_dispatch_refusal` takes a typed `DispatchPath`;
and the DB tests carry a DRAFT control at every site.

**2026-09-06 — the ANSWER: `sub_workflow_runs`, the child-run ledger (RFC 0012 P1).**
Everything above this line teaches a reader to say *"no evidence"* instead of
*"never ran"*. None of it can ANSWER the question, and the structural question
#762 recorded — *should `execute_subworkflow_graph` write a `workflow_executions`
row?* — is answered NO for the reasons measured there (161 of 163 reads carry no
`parent_execution_id` filter; `budget_precheck` counts execution rows, so a
parent with a child would be billed twice; the retention sweep would split one
tree across two tiers). RFC 0012 takes shape B: a separate, narrow table written
at the dispatcher chokepoint, with no payload columns, RLS from its first
migration, and its own retention tier in the existing pass at
`archive_after_days + purge_after_days` (no FK, because archival is a DELETE plus
an INSERT and a CASCADE would erase the ledger at day 30 while the parent lives
to day 60).

**P1 covers**: the migration + RLS, `ChildRunRecorder` in
`talos-workflow-engine-core`, the leaf repo `talos-child-run-ledger`, the ONE
chokepoint write, retention, `since()`, and the two smallest honest consumers —
`get_execution_lineage` gains `child_runs` under the anchor, and
`get_workflow_reuse_stats.parent_dispatched` gains `child_runs_since_ledger`
beside `ledger_since`. **P2** is the four uncovered dispatch kinds plus
readiness / hygiene / the dormant lists; **P3** the SLA monitor and the
cascading-failure check.

**The RFC's own premise was REFUTED before anything was written, and the
correction is the part to remember.** `execute_subworkflow_graph` is NOT the one
path every child takes. Enumerating every `AdapterSet::into_engine_with_graph`
site — the only way a child graph becomes a running engine — finds THREE: the
chokepoint, `run_dispatched_subworkflow` (`dispatch`, `capability_dispatch`) and
the agent-loop body's per-iteration hydration. So P1 records five node kinds
(`sub_workflow`, `judge`, `ensemble`, `reflective_retry`, `llm_dispatch`) and is
structurally blind to four. On the reference fleet those four are LATENT — of 36
workflows the only child-dispatching node kinds present are `sub_workflow` (3)
and `judge` (3) — and *"latent is not live"* cuts both ways, so the gap is NAMED
in `talos_child_run_ledger::UNRECORDED_DISPATCH_KINDS` and DISCLOSED by both
consumers rather than left to read as "this child never ran". The table's CHECK
admits exactly the five kinds that have a writer: `agent_loop` was in the RFC's
draft list and is deliberately absent, because a value nothing writes is the same
defect as a seeded metric label nothing increments.

**2026-09-07 — P2: the readers learn to read the ledger, and the four blind
dispatch kinds are closed.** P1 could ANSWER "did this child run"; nothing
asked it. Four readiness surfaces and two hygiene lists now do.

**Readiness.** `ReadinessBasis` gains `LedgerMeasured`. A child with ≥
`LEDGER_MIN_RUNS` (**3**) recorded runs in the 30-day window is scored on the
FULL 100 with reliability = the ledger's success rate and freshness = the age
of its newest recorded run, both through the SAME `compute_reliability_score` /
`compute_freshness_score` the fleet uses — the INPUT moves, the arithmetic does
not. Below the floor the child KEEPS the 30-point denominator and the shortfall
is disclosed with the count and `ledger_since`; it is NEVER scaled up, which is
#762's second rejected rendering and stays rejected. **Why 3, argued from
#762's own reasoning**: 1 promotes on one observation, so a single failure
reports reliability `0/50` as a fleet-comparable fact — the determinate
negative in a new shape; 10 (the ramp's saturation point) keeps a child that has
demonstrably run nine times on a denominator whose stated reason is "nothing can
measure this"; 3 is the smallest number from which a success RATE is a rate, and
the ramp already discounts it (a perfect child at n=3 earns 15 of 50). The floor
protects the DENOMINATOR claim, not the arithmetic. **`ReadinessBasis::from_scan`
was DELETED**: it had zero production callers by the end of P2 and exactly one
behaviour — silently scoring every child on 30 — so a scorer that FORGOT the
ledger would have been indistinguishable from one that could not READ it.
Callers pass an explicit `Option<ChildLedgerEvidence>`; `None` STATES "not
consulted", the same reason P1 made `ChildRunSite` an enum and not an `Option`.
All FOUR surfaces read it — the three `score_readiness` callers plus
`get_all_readiness_scores`, which derives `max_possible` from the basis instead
— and the `below_50` exclusion follows the BASIS
(`ReadinessBasis::is_unmeasurable_child`), not child-ness: a ledger-measured
child scoring 47 is a REAL below-50 finding, and excluding it would hide the
platform's most-used sub-workflows from the one count that would notice them
degrading.

**Hygiene.** The dormant and stale-draft child rows gain `last_child_run_at`,
`child_runs_since_ledger` (null, never 0, before `ledger_since`) and the
`ChildRunEvidence::note` that refutes the stale-draft list's own "never
executed" premise. The `execution_cost_rollup` proxy is **KEPT and DEMOTED, not
deleted**, and the reason is a measurement: it is the only thing that can speak
for the period BEFORE the ledger's first row, which was **~11 h old against a
30-day window** the day this shipped. Its caveat now records the number that
supersedes it — measured 2026-09-07, the worst case is **0%** recall and not the
~5% P1 recorded: one child whose parent ran **5085** times in 30 days (461 of
them in 48 h) has ZERO rollup rows in the whole window and a proxy timestamp 45
days old. Once `ledger_since` is older than the 30-day window the proxy adds
nothing and can be removed — an operator loses nothing then, and everything
before the floor now.

**The four uncovered dispatch kinds are RECORDED, and the "different shape" the
RFC predicted was the shape the file already used.** `dispatch` /
`capability_dispatch` (`run_dispatched_subworkflow`) and the per-iteration
`agent_loop` / `react_loop` body now write. `execution_id` was already in scope
at all three reactor call sites, so threading was never the obstacle; the
obstacle was that the loop body's `async move` captures the adapter set and NOT
`self`. `ChildRunReporter` — a small `Clone` value carrying the recorder, the
sanitizer, the parent workflow id, the RESOLVED node label and the depth — is
built from `&self` and captured beside `sub_binding`, which the same function
had been doing for the same reason since #504. **The INSERT is still in exactly
one function**; what moved is where its inputs come from. The loop records ONE
ROW PER ITERATION (five iterations are five child runs; folding them would make
the ledger disagree with `iterations_run` and with the fuel those iterations
burned), and `ReActLoop` records `react_loop` even though it shares
`try_dispatch_agent_loop` — the ledger records what the AUTHOR wrote.
`UNRECORDED_DISPATCH_KINDS` is now EMPTY and is **kept rather than deleted**: an
empty list is a CLAIM, and deleting the constant removes the only place that
claim can be contradicted when a tenth kind arrives without a writer. Migration
`20260907020000` widens the CHECK to nine values (a NEW migration, never an edit
of the applied one).

**Cost, measured rather than assumed.** The hourly loop adds **two queries per
USER per tick** — a cached floor read and one grouped `= ANY($1)` count over
that user's child ids, narrowed to rows the child scan already calls somebody's
child, so a batch with no children costs no query at all. Against a loop already
issuing THREE queries per workflow (108 for the 36-workflow fleet) that is ~2%
more statements. On a standalone replica carrying P1's three indexes: at 13 500
rows (60 days at ~225 runs/day) the batched count is 0.96–1.17 ms and
`since()` is **1.7–1.9 ms as a SEQ SCAN**; at 135 000 rows they are 9.0 ms and
**14.4–15.5 ms**. None of the three P1 indexes leads with `started_at`, so
`MIN(started_at)` is linear in the table — and P2 takes that read's callers from
two to five. The migration therefore adds `(started_at)`, measured at
**0.036–0.045 ms** (Index Only Scan) on the same 135 000 rows, i.e. ~400x, for
one more b-tree on an append-only table.

**What is NOT covered, measured rather than implied.** (SUPERSEDED for the two
write sites by the P3 entry below — the mutation named here is now CAUGHT by
`talos-workflow-engine/tests/child_run_dispatch_recording.rs`, and it was
re-run against the pre-existing suite to confirm this paragraph was true when
written.) Deleting the `record`
call at the tail of `run_dispatched_subworkflow` leaves every
`talos-workflow-engine` unit test AND both ledger DB binaries GREEN — a measured
SURVIVOR, not a hypothetical. That function is private and the loop body sits
inside a `tokio::time::timeout`'d `async move`, so driving either needs a full
reactor run over a graph with a `dispatch` or `agent_loop` node, which the P1
harness does not build. What IS covered by construction is the SHARED write site
every path now routes through: gutting `ChildRunReporter::record` turns four
`child_run_ledger_tests` red. The reference fleet has **zero** nodes of those
four kinds, so there is nothing to read live yet either — both halves stated
rather than left to look like coverage. **No lint was added and `--count` stays
86**: the candidate ("a readiness scorer must consult the ledger") has a
production population of FOUR and the structural answer is stronger than a grep
over them — `from_scan` no longer exists, so the forgetful spelling does not
compile.

**Two non-negotiables, recorded so nobody "fixes" them.** (1) A child run is NOT
charged to the actor's hourly execution budget — the parent's run was budgeted
when it was created, and `budget_precheck` counts `workflow_executions` rows,
which this adds none of (pinned by a DB round trip, not a comment). (2) UNKNOWN
is not zero: the table has a first row, so a count of 0 for a period before
`ChildRunLedger::since()` is *nobody was recording*, and every consumer renders
`null` with the reason rather than `0`. `since()` is deliberately NOT user-scoped
— the question is a deployment fact, and a per-user `MIN` would render UNKNOWN
forever for a user who has legitimately never dispatched a child, turning a real
zero into a permanent "we cannot tell".

**Three implementation facts the code forced, all measured first.** The engine
has NO `execution_id` field (it is a parameter of `run_inner`, and nodes dispatch
concurrently), so `ChildRunSite { execution_id, node_id }` is threaded from the
reactor loop through the five `dispatch_*` handlers — an ENUM with an explicit
`Untracked` variant, not an `Option`, so a sixth handler cannot be added without
the compiler asking; the WRITE still happens in one place. `org_id` was DROPPED
from the RFC's table: the engine has no org handle, and the RLS policy joins
`workflows` for the org exactly as `20260904210000` does, so the column would
have been decorative and wrong. And `status` is CLASSIFIED with check 77's
`output_reports_error`, never `.as_bool()` — a child whose engine returned `Ok`
can still have failed, and the ledger must not disagree with the run about it.

**this change (2026-09-06) — the two smallest consumers say what they measured.** Two report
surfaces asserted a determinate negative for a state the reader could not
represent — checks 74/76/79's class again, in the two places RFC 0012 P1 had
just made representable.

**(B) `get_execution_lineage` contradicted itself in one response.** Its note
read *"This execution has no parent or child executions — it is a standalone
run."* fourteen lines below `child_runs_count`, which since #766 can be ≥ 1.
Both halves were true: the note is a statement about `workflow_executions` ROWS
and was worded as a statement about the RUN, and "standalone" is exactly the
reading the ledger exists to remove. `lineage_note` is now a pure function of
the four facts it may speak about, and the single-node arm is three-valued like
`child_runs_note` beside it: a measured zero, a count with the reason `lineage`
cannot show it, and UNKNOWN for an unreadable or not-yet-started ledger — never
zero, never "standalone". **Latent on this fleet at the time of writing, and the
brief's own observation could not be re-run**: `sub_workflow_runs` holds exactly
ONE row, its parent execution row and both workflow rows were deleted (the
ledger has no FK, by design), so no live execution can currently exhibit
`count ≥ 1` beside that sentence. The defect is pinned by unit test rather than
reproduced live, which is worth saying rather than implying otherwise.

**(D) `get_archive_policy` reported one of the two retention windows and
re-derived it itself.** An execution's readable lifetime is
`ARCHIVE_AFTER_DAYS` (live → archive) PLUS `EXECUTION_RETENTION_DAYS` (archive →
gone), 30 + 30 = **60 days** on the default this deployment runs — kept
deliberately (decision 2026-09-06). The tool rendered the archive tier alone,
so the purge window and the lifetime were invisible in every tool response,
while `EXECUTION_RETENTION_DAYS`' NAME reads like the total it is not.
`docs/configuration-reference.md` explained the 30 + 30 and nothing
machine-readable did. The handler ALSO carried its own
`talos_config::archive_after_days()` read, its own JSON parse and its own
`d > 0` filter — a second implementation of `resolve_retention_windows`, whose
own doc comment claims to be *"the ONLY place that decides which configured
number governs which tier"* — and the two had drifted. It now renders from
`talos_advanced_repository::resolve_retention_policy`, of which
`resolve_retention_windows` is a projection, so the REPORT and the SWEEP cannot
answer differently; every pre-existing key keeps its name and value, and
`set_archive_policy` now states in its response and its description that it
moves ONE of two windows. **The drift shape was narrower than it looked and the
first test for it was green over the mutation** — serde strips the JSON
delimiters, so `'"45"'::jsonb` reaches `as_str()` as `45` and the handler's
`trim_matches('"')` is a no-op there; it bites only on a jsonb string whose
CONTENT carries quote characters (`'"\"45\""'::jsonb` → `"45"`), which the
resolver rejected and the handler accepted. Live population of ANY override on
the reference fleet 2026-09-06: **ZERO** — `system_settings` held no rows at all
— so the drift was latent, and the fix is that there is now one parse rather
than that a live row was wrong. An unreadable setting still REFUSES (#730)
rather than rendering the windows as null: it makes both reported sources wrong
at once, and the one number still producible (the env default) is precisely the
misleading one.

**No lint check was added and `--count` stays 86.** The candidate for (D) —
*"`talos_config::archive_after_days()` may be read only inside the resolver"* —
was measured in both directions before it was written: on pristine `origin/main`
it reports **2** non-test production sites outside `talos-advanced-repository`,
of which **1** is the real defect and **1** is legitimate
(`talos_workflow_validation::history_window_days`, which CAPS a display window
at the archive boundary and decides no retention), i.e. 50% precision over a
population of two, shipping at one-with-a-marker. Below the bar #765's own
numbers set, and the structural answer is already stronger: one `pub` resolver,
the projection above it, and a DB test driving BOTH entry points over the same
rows. For (A) the guard already exists and is check 56 itself; for (B) the
population is one.

**What is NOT guarded, stated rather than implied.** The chokepoint's own
`redact_str` on `error_class` is defence in depth on the `Ok` branch —
`run_scheduler_loop` DLP-scrubs the whole results map on its way out, so
removing the chokepoint's call does NOT turn the DB test red (measured). It is
the ONLY pass on the `Err` branch, where the text is an engine error string that
never met the sanitizer. **No lint check was added and the count stays 86**: the
one write site is a chokepoint the compiler already funnels every caller
through, so a "the ledger must be written" detector would have a population of
ONE and nothing to say.

**2026-09-07 — P3: the ALERTER and the ASSESSOR read the ledger, and the two P2
write sites get a test.** P2 taught the READERS; the two surfaces #762 recorded
as "disclosed, not fixed" and "recorded and NOT changed" are the ones a person
is paged by, and they are closed here.

**The cascading-failure check was blind to a child failing 100% of its runs, and
that was MEASURED before anything was written.** Driving the real reads against
a scratch database: a child with THREE recorded runs inside the check's own
7-day window, ALL FAILED, returns an EMPTY map from
`get_risk_exec_counts_for_ids` while `child_run_stats_since` returns
`runs: 3, failed: 3`. The check took its `None =>` arm, listed the id under
`sub_workflows_unmeasurable` and pushed no risk — indistinguishable from a child
that never ran. The read is now `child_ledger_evidence_since`, which is P2's
readiness read **SPLIT, not copied** (the 30-day entry point is a one-line
projection over it), so the floor arithmetic — read `since()`, clamp the window
to `max(window, floor)`, turn an ABSENT key into a zero-WITH-a-floor — keeps ONE
home while the WINDOW moves to the check's seven days. The decision is the pure
`talos_analytics_repository::cascading_risk::classify_sub_workflow_risk`.

A HYBRID child is judged over the UNION of both tables with the split disclosed
(`measured_over`), because both hold real runs of one workflow and the check
renders ONE `description` per child — two rates under one category would have to
be recombined by the reader with no denominator to do it on.
`LEDGER_MIN_RUNS` gates the CHILD-ONLY population and nothing else: where
execution rows exist the check already had a population it was willing to judge,
so a floor there would be a NEW refusal on a finding that fires today.
`sub_workflows_unmeasurable` changes SHAPE — id strings become objects carrying
`reason`/`child_runs`/`child_runs_failed`/`ledger_since`/`window_start`/`note` —
and every reader was checked (there is exactly one, and none in the frontend).
`UnmeasurableReason` is FOUR-valued: `ledger_not_consulted` is a statement about
the CODE PATH and stays distinct so a wiring regression cannot render as a fact
about the workflow. That distinction earns its keep below.

**"This workflow's SLA-window stats" had FOUR implementations and they
DISAGREED** — check 85's class, and the disagreement moves a verdict. The 5-min
breach monitor's inline SQL and `get_sla_window_stats` (the 15-min degradation
loop) ask the identical question over the identical 24-hour window; only the
first filters `completed_at IS NOT NULL`, so an execution still IN FLIGHT sat in
the second's denominator and never in its numerator, making its success rate
systematically LOWER. One stored threshold row, two loops, opposite verdicts on
one tick. `sla_window::read_sla_window_sources` is now the one read: BOTH
populations in ONE statement, a `UNION ALL` with `GROUP BY ROLLUP(src)` so the
per-source split and the COMBINED percentile come from one pass (a p95 over a
union is not a function of the two sub-p95s and must never be averaged).
`get_sla_window_stats` and its `SlaWindowStats` are DELETED rather than kept as
a projection, for the reason P2 deleted `ReadinessBasis::from_scan`: they
returned `Option`, so a failed read and an empty window were one value, and a
future caller reaching for the convenient name would silently re-acquire the
collapse this change removes. Its one caller reads the new function and handles
three outcomes — **a behaviour change to the 15-min loop, and it is the fix**: the unified definition is the monitor's (runs that
SETTLED in the window), the direction is strictly fewer false success-rate
alerts, and it gains a `user_id` it never had (its docstring called SLA alerting
"platform-wide"; its caller already reads `w.user_id`). `get_latency_percentiles_ms`
and `get_performance_metrics` are deliberately NOT collapsed in: they answer the
latency DISTRIBUTION of SUCCESSFUL runs over a days-window, and folding a failed
run's duration into `duration.p50` would move a number an operator reads without
being asked.

The BREACH DECISION is the pure `decide_sla_breaches`; the loop keeps only
wiring, which is the only thing that makes it testable —
`controller/src/bootstrap/background.rs` is `mod bootstrap` inside `main.rs`, so
no integration test can reach the loop itself (#762 recorded the same fact for
the readiness loop). `LEDGER_MIN_RUNS` gates BOTH metrics when child runs are
the only evidence, and the p95 argument is not weaker than the success-rate one:
a p95 over n=1 IS that one run's latency, so one slow cold start would page
somebody. `not_evaluated` is three-valued, so "no breach" and "could not judge"
are different log lines. The webhook keeps every key AND its per-metric
rendering and gains `sources: {execution_rows, child_runs, child_runs_since,
window_hours}` — counts, a timestamp and an integer, the kinds of value it has
always carried.

**An alerter that cannot measure must say so.** `Err(_) => continue` became a
WARN with `event_kind = "sla_stats_unreadable"` and an error CLASS
(`sla_read_error_class`), once per threshold per tick, full chain at DEBUG; the
same treatment went to the 15-min loop's `_ => continue`, which
`docs/swallowed-results-inventory.md` records as fails-OPEN and which folded
THREE states (read failed / empty window / 1–2 runs) into one silent skip.
**No metric was added, and that is a measurement rather than an omission**: that
function has no `TalosMetrics` handle, so a series would mean threading the
registry into `spawn_late_background_tasks` for a loop that is LATENT on this
fleet. Declined, which means the unreadable-window signal is prose-only and
cannot be alerted on.

**A NULL webhook KILLED the monitor, and the documented configuration is what
produced one.** The threshold row was decoded with `sqlx::Row::get::<String, _>`;
the column is nullable by design (`20260404000001`) and
`set_workflow_sla_threshold` stores NULL for an omitted webhook — its tool
description advertises that as the API-polling configuration. `Row::get` PANICS
on a decode failure and this loop is a spawned task, so ONE such row ended the
SLA monitor for the whole process lifetime, silently. Every column now decodes
through `try_get` in one closure and a bad row skips ITSELF with
`event_kind = "sla_threshold_row_undecodable"`. Also corrected in the same
block: a comment claiming the task "issues per-threshold INSERTs into
`workflow_sla_alerts`". There is no such INSERT and no such table — the 15-min
sibling writes `workflow_alerts` — and a comment asserting a side effect the
code does not have is #732's class.

**`get_workflow_sla_report` measures a child.** `success_rate` is the union
(floored when the ledger is the only evidence), so a workflow that only ever
runs as a sub-workflow stops reporting `not_measurable` however often it ran.
`total_executions` keeps its name's meaning, p50/p95/p99 stay EXECUTION-ONLY and
`duration.population` says so, and `child_runs` appears only when the ledger
contributed or when there are no execution rows at all. Note one disagreement
KEPT and disclosed: this report's denominator includes runs still IN FLIGHT (a
considered decision, pinned by `sla_absence_disclosure_tests`) while the alerter
must not fire on an open run — two different questions, and the response says
which it is answering. The compiler forced all 7 pre-existing tests to state
`child_runs: None` ("not consulted"), which is P2's `from_scan` shape for the
same reason; all 7 pass unchanged.

**Leg C: the two P2 write sites now have a reactor-driven test, and P2's own
mutation was re-run rather than assumed.**
`talos-workflow-engine/tests/child_run_dispatch_recording.rs` drives
`run_with_transport` over `dispatch`, `capability_dispatch`, `agent_loop` and
`react_loop` nodes against a hand-written capturing `ChildRunRecorder` (the
workspace has exactly ONE recorder impl and test-utils has none). Deleting the
`record` call at the tail of `run_dispatched_subworkflow` — P2's M8 — still
SURVIVES the pre-existing engine suite (exit 0, re-measured) and is CAUGHT by
the new binary. Also caught: recording once instead of once per agent-loop
iteration, a `ReActLoop` filed as `agent_loop`, and a `CapabilityDispatch` filed
as `dispatch`. **No LLM stub was needed and that was measured**: the loop body is
the body workflow's graph run through the ordinary `NodeDispatcher`, so a fixed
output controls the iteration count exactly. **One expectation of mine was wrong
and the code was right**: a dispatch child whose terminal MODULE returns
`{"__error": "…"}` is recorded `Completed`, because a dispatch envelope is a
LABEL-KEYED map rather than the collapsed terminal value — and the PARENT node
applies `output_reports_error` to the identical envelope and reaches the
identical answer, which is exactly the invariant the write site claims.

**TWO measured SURVIVORS, both handler-body call sites, and they are not equally
silent.** Setting the SLA report's `child_runs`/`ledger_since` to `None`, and
passing `None` instead of the ledger evidence in the risk check, both leave every
test green — the shape checks 74b and 79b already state as their own limit: the
DB tests drive the repository read, the unit tests drive the pure decision and
the pure renderer, and none can see a call site that computes the right answer
and discards it. The RISK one SELF-DISCLOSES (every entry then reads
`reason: "ledger_not_consulted"` and says so in words, which is why that variant
exists); the REPORT one is SILENT and is left open, with the live read after
deploy as its honest guard — the position #767 and #769 took about their own
call sites. No lint: the population is TWO, and "the handler must pass the read
it just recorded" is a dataflow question, not a textual one.

**A cosmetic defect that reached operator-facing JSON, swept.** The house style
for a long literal is a `\`-continuation, which renders as ONE space because
`\<newline>` skips the newline AND the next line's indentation. Twenty-seven
lines had lost the `\` and kept the indentation, so runs of up to 30 spaces
reached the rendered string — including the cascading check's own note, five of
the SLA report's disclosure strings and four of P2's child-run notes. Measured
workspace-wide with a literal-aware walker: **44 lines**, of which **17 are
legitimate** (aligned `println!` columns, embedded code samples, tests matching
source text, one SQL literal) and 27 were prose. All 27 fixed.
**A lint was BUILT, MEASURED and REJECTED**: the brief's candidate rule (a `\`
continuation followed by ≥2 spaces) describes the CORRECT house style and would
fire everywhere; the rule that does describe the defect still reports the 17
legitimate sites on the fixed tree, i.e. 0% precision at zero and 17 markers on
correct code. Telling prose from an aligned column is a judgement a grep cannot
make. `--count` stays **86**.

**What was measured and NOT changed.** `set_workflow_sla_threshold` still
accepts a row with BOTH thresholds NULL (the invariant lives in the handler and
the tool description, not in a CHECK), and such a row is now evaluated and fires
nothing rather than being a special case. The report's in-flight denominator
stays as it is, disclosed. And the two latency-percentile readers stay separate,
for the reason above.

**2026-09-07 — the report contradicted itself the moment child runs crossed the
floor.** P3 gave `get_workflow_sla_report` a population that spans both tables;
`sample_size_warning` was left keyed on `total_executions == 0`. Two decisions, one
response. Measured live on `pa-quality-judge` (0 execution rows, 3 ledger runs,
floor 3) and reproduced against the real pure renderer: `success_rate.actual: 100.0`,
`met: true`, `child_runs.counted_in_success_rate: true`, and fourteen lines below,
*"No executions at all in the trailing 30 day(s), so nothing about this workflow's
SLA was measured. The success rate, the latency percentiles and the compliance
verdict are all null"* — then, appended, *"The RFC 0012 child-run ledger DOES hold 3
run(s)"*. Below the floor (n = 2) the same sentence is CORRECT, because
`rate_total` is 0 there by construction, which is why nothing looked wrong.

The warning is now derived from `rate_total`, the success-rate block's own
denominator. `sample_n == 0` keeps today's wording **byte-identical**; `sample_n > 0
&& total_executions == 0` gets a new sentence saying the rate WAS measured over N
child runs, that the LATENCY half is what the empty execution table costs, and what
`compliance_status` is — every clause derived from the values actually rendered
(`p99_ms`, `in_compliance`), never asserted, so a caller who passes a p99 with no
execution rows is not told a falsehood about it.

**A second defect of the same keying, found by the same measurement**: `total_u == 0`
short-circuited the whole `else if` chain, so at n = 3 against a 99% target the
STATISTICAL qualification (`min_n_for_meaningful_target` = 100) was unreachable — the
one measured verdict on the surface was rendered with no sufficiency qualification at
all. The sufficiency sentence now has ONE home, a local closure consulted by both
branches, and its denominator is `sample_n`; where that is wider than
`total_executions` the population is NAMED, and where they are equal the sentence is
byte-identical to the pre-fix one (pinned by
`an_execution_only_report_keeps_the_pre_fix_sufficiency_sentence`, which asserts the
whole string).

**The rest of the response was grepped against the basis**, per the brief. Four other
sites read `reads.total == 0`: `ledger_below_floor` (the population decision itself),
the `child_runs` block's emission condition, and the two `population` strings — each
states its OWN population and is correct. `compliance_note` keys on
`in_compliance.is_none()`, i.e. on the basis, and at the floor it correctly reports
the LATENCY component as the unmeasured one. Nothing else changed.

Four mutations, all red: keying the first branch on `total_u == 0` again; keying it
on `child.total == 0`; passing `total_u` to the sufficiency closure; emitting the
wider-population clause unconditionally. **No lint** — the population is one renderer
and the guard is four unit tests over the real pure function; `--count` moves to 87
for leg X1's check only.
