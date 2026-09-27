# 2026-09-26 — the yield test had zero margin

**Why.** `worker::kill_switch_tests::a_compute_bound_guest_yields_its_thread_to_the_executor`
(added by #959) failed 2 of the 3 completed `quality.yml` runs after it
landed: on `main` (run 36240936156) and on #961 (run 36263363259). That blocks
every PR in the merge queue.

**Measured.** The failures read `heartbeat beat 4 times in 1.14s` against a
floor of `beats >= 5`. Locally (16-core Mac), with the floor raised so the
count is printed: 5 of 5 runs gave exactly 5 beats in ~1.1 s idle, and 5 of 5
gave exactly 5 under 16 CPU burners. So the floor equals the steady state and
has no margin. The guest yields once per 100 ms epoch tick, but the heartbeat
beats about once per ~220 ms. The current-thread runtime polls its timer
driver less often than the self-waking guest task is rescheduled. One late
tick on a shared CI runner fails the test.

**Decided.** The floor is 2. The assertion is about YIELDING, not throughput.
Under a `Continue` epoch extension the guest's future never returns `Pending`,
so the heartbeat is never polled (0 beats); two beats prove repeated yields.
The rationale is written at the assertion. The other assertions are unchanged:
the 1 s outer timeout must win, and within 5 s.

**Proof.** The fixed test passes 3/3. The mutation that the test exists to
catch, `update_for_continue` returning `UpdateDeadline::Continue`, still fails
it: the guest never yields, and the `finish_within` 20 s guard trips. The unit
test in `epoch_budget.rs` separately pins `Yield`.

**Deliberately NOT done.** Retrying, quarantining or `#[ignore]`-ing the test;
lengthening the window to buy more beats. That is still a timing bet, only a
larger one.
