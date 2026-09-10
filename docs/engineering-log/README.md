# Engineering log

Narrative archive for `CLAUDE.md`. Each file below was moved out VERBATIM; the
DECISIONS those narratives recorded — every rejected lint with its numbers, every
`latent on this fleet` claim, every `deliberately NOT`, every measured population
— stay in `CLAUDE.md`'s "Engineering log — the decisions, kept" section, which
points at these files.

**The split is by KIND, not by age.** Do not archive an entry because it is old:
archive the STORY and keep the DECISION. An age-based sweep would take the
decisions with it, and the record of what has already been tried and rejected is
the only thing that stops the next session redoing it.

**Adding an entry.** Write the decisions into the CLAUDE.md digest that owns the
class and the narrative into that class's file here (or a new file plus a row
below). If you cannot tell whether a paragraph is a rule or a story, it is a
rule — leave it in `CLAUDE.md`.

**The guard.** `python3 scripts/check-engineering-log.py` proves two things
mechanically: every line removed from `CLAUDE.md` still appears verbatim in some
file here, and every decision-marker line in the archive is named by the digest
that replaced it. Run it after any move.

| File | Class | What it holds |
|---|---|---|
| [`2026-09-05-workflow-liveness-and-child-run-ledger.md`](2026-09-05-workflow-liveness-and-child-run-ledger.md) | misleading reports over `workflows` | two readiness timestamps; `status` vs `is_enabled`; the narrow archived-dispatch gate; RFC 0012 `sub_workflow_runs` P1/P2/P3 |
| [`2026-09-07-swallowed-reads-and-fail-open-gates.md`](2026-09-07-swallowed-reads-and-fail-open-gates.md) | a defaulted read that becomes a claim | the 210→0 claim burn-down; eight fail-OPEN gates; the MCP per-tool instrument and its outcome/class partition |
| [`2026-09-06-audit-chain-verifier-identity.md`](2026-09-06-audit-chain-verifier-identity.md) | presence is not function, at the identity layer | the WORM verifier that used the writer's write-only credentials, and the id space it enumerated |
| [`2026-09-07-dispatch-attempt-chain-partition.md`](2026-09-07-dispatch-attempt-chain-partition.md) | one prefix, two chains | `JobRequest.dispatch_attempt` as a partition key, and the deploy ordering it forces |
| [`2026-09-07-artefacts-describing-a-system-that-does-not-exist.md`](2026-09-07-artefacts-describing-a-system-that-does-not-exist.md) | config and docs that drifted from the code | a credential for a principal that does not exist; four misattributed env vars; a stale GraphQL snapshot; a self-contradicting improvements list |
| [`2026-09-07-statements-that-never-executed.md`](2026-09-07-statements-that-never-executed.md) | SQL nothing checks | the statements behind check 88, and the three trigger paths that answered differently |
| [`2026-09-07-failures-nobody-can-see.md`](2026-09-07-failures-nobody-can-see.md) | a missing report rather than a wrong one | the dangling push channel; background-task supervision; the signed-RPC data-plane instrument |
| [`2026-09-09-a-documented-knob-whose-range-is-inert.md`](2026-09-09-a-documented-knob-whose-range-is-inert.md) | a documented tunable whose advertised range cannot be reached | `ADAPTIVE_RANK_LOOKBACK_DAYS`: 30 days configured, 6.56 fitted, and a disclosure denominated in the wrong unit |
| [`2026-09-09-the-timeout-that-was-not-per-call.md`](2026-09-09-the-timeout-that-was-not-per-call.md) | a per-call budget spent on somebody else's work | the 12:00 UTC LLM herd: where the serialization actually is (`OLLAMA_NUM_PARALLEL:1`, on a host process Talos does not ship), the dose-response curve, and why a bound beat jitter |
| [`2026-09-10-the-collection-nobody-read.md`](2026-09-10-the-collection-nobody-read.md) | a collection turned on with no reader | `pg_stat_statements`: what it does and does not normalise, why `talos_guest` is not the tenancy axis, the five availability states, and the cost that is not the reason |
| [`2026-09-10-whole-codebase-review.md`](2026-09-10-whole-codebase-review.md) | the classes above, at the sites the per-class sweeps had not reached | fourteen domain reviews + eight fix packages: the verification log, the consolidated pre-fix findings, and every package summary verbatim |
