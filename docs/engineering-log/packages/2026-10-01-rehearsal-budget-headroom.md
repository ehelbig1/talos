# 2026-10-01 — a rehearsal's reply says how much of the actor's budget is left

**Context.** `test_workflow` and `test_workflow_draft` create real execution
rows under the actor the workflow runs as. They count toward that actor's
hourly cap, and their model calls toward its daily token cap. Under
`on_budget_exceeded = suspend`, a start refused on the hourly cap suspends
the actor — and with it every scheduled workflow bound to it.

**Measured on the reference deployment, 2026-10-01.** Building two workflows
in one afternoon took the live assistant actor to 30 of 40 executions in the
hour and 341 K of 500 K tokens in 24 hours (its seven-day peak). Nothing in
any reply said so; it was found by querying the tables before a go-live.

**Change.**
- `talos_actor_budget_refusal::actor_budget_headroom(pool, actor_id)`: the
  policy's mode and, for each cap the policy carries, its limit and current
  count. `Ok(None)` is "no policy"; `Err` is "could not be read".
- The per-minute and fuel-per-hour counts were inline in the admission check;
  they are now `executions_last_minute` / `fuel_last_hour`, beside the three
  that already had a home, and both the admission and the report call them.
- `test_workflow` (both its finished and its still-running reply) and
  `test_workflow_draft` carry an `actor_budget` block: `mode`, `caps`
  (`limit`, `used`, `remaining`, `percent_used`), and a `warning` once any
  cap is 80 % spent, naming the cap and what the mode does.

**Decided.**
- Three answers are kept apart in the reply: caps, `policy: "none"`,
  `unreadable: true`. An unreadable budget never renders as "no caps".
- 80 % is the warning threshold: at 40 an hour it leaves eight runs, enough
  to stop. A constant, not a knob.
- The report takes no lock. It is not an admission; the counts can move.
- Cost: one policy read plus one count per cap set (at most five indexed
  statements), after the run. The lifetime count, which reads the archive
  too, runs only for an actor with a lifetime cap.

**Deliberately not changed.**
- `call_workflow`: its `{execution_id, status, output}` body is a contract
  for programmatic callers, and it is not a rehearsal tool.
- `test_module`: it creates no execution row and writes no usage row, so it
  spends none of these caps.
- The budget itself. Whether rehearsals should run under a separate budget
  is an operator decision; this only makes the spend visible.

**Tests.** Unit: cap arithmetic (bounded, no overflow at fuel-sized counts);
the rendered block (below and at the threshold, per mode, no policy,
unreadable); both tool descriptions. Database: the report against a real
clone — only the caps the policy carries, in admission order, archive
counted for the lifetime cap only, another actor's spend excluded.

**Stated limit.** The handler wiring (which actor is passed, that the block
is attached) is not driven by a test; the live call after deploy checks it.
