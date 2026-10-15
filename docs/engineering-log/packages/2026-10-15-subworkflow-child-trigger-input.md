# 2026-10-15 — a sub_workflow node may start its child with what it relays

**Context.** #1283 (2026-10-14) made every child run keep the OUTER run's trigger
as `__trigger_input__`, wherever its `sub_workflow` node sits. Before it, a node
after another node handed its child that upstream's output as the trigger, and two
workflows in talos-workflows were written against exactly that: a relay node puts a
request at the top of its output and a `sub_workflow` node starts a workflow written
to be started by that request.

* `pa-ticket-gaps` → `relay` (brief_request) → `brief` (the build-brief workflow).
* The Reviews' `relay_post` (post_request) → `post_auto` (the posting workflow).

After #1283 both children saw the outer trigger instead. Found on AXP-2315: the gap
report named three gaps and the brief workflow drafted "the run named no uncovered
criterion". Auto-post had not run yet (no autonomy granted), so it was latent.

**Decided.** An opt-in on the node: `"child_trigger": "input"` in a `sub_workflow`
node's data makes its child's trigger the node's own input, stripped of every `__`
key as the child's seed is (`subworkflow_trigger_from_input`, `engine_config.rs`;
read in `try_dispatch_sub_workflow`). Absent, or any other value, is #1283's outer
trigger. #1283's record already says a child that needs something other than the
outer trigger should be given it explicitly; this is that, for `sub_workflow`.

**Why the opt-in is safe.** A module still cannot author an engine key: the forged
`__trigger_input__` is stripped from every module output (unchanged), and the
relayed input loses every `__` key. What the opt-in allows is what the workflow's
author chose by setting it: the upstream output becomes the child's request, and
the child validates it as it validates any trigger (the brief workflow refuses gaps
whose fingerprints do not match the ticket; the posting workflow refuses a draft
that is not the one shown).

**Tests.** `sub_workflow_trigger_input.rs`: the opt-in starts the child with the
relayed input; without it, the outer trigger. Mutation-proved: ignoring the opt-in,
and keeping the input's `__` keys (an upstream output carrying `__fuel_consumed__`
and a forged trigger), each fail it. Whole `talos-workflow-engine` suite green.
