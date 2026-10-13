# Four decisions the 2026-10-13 records left to the operator, answered (2026-10-13)

Four records from this date each stated a question as the operator's, with
options and a recommendation. All four were answered the same day. This file
is the answer; the options and the reasoning are in the record each line
names. No code changed for the first three.

Do not re-propose the alternatives below without new facts.

| Question | Decided | Asked in |
|---|---|---|
| When a node fails with no `continue_on_error` and no error edge, drain or finish what is in flight before failing the run? | **No. Fail-fast stays**: the reactor returns at once and the in-flight siblings' rows are cancelled. | `2026-10-13-forwarded-parent-failure.md` |
| Should a passing `confidence_gate` or `inline_judge` carry a continued-failure parent's envelope through as a pass? | **No. The gates stay as they are**: they fail on a failed parent's envelope, and the message names the node that failed first. | `2026-10-13-forwarded-parent-failure.md` |
| A per-link flag that hides an action link's label on the page shown after use? | **Not built.** The label is shown; a deployment that needs it kept off the public address sets `TALOS_ACTION_LINKS_BASE_URL`. | `2026-10-13-action-links-address.md` |
| Should an asynchronous webhook run be claimed, fenced and recorded, which makes it crash-recoverable? | **Yes** (option 1). Merged as the change that record describes. | `2026-10-13-webhook-runs-are-finalized.md` |

## What would count as new facts

* **Fail-fast**: a measured case where a run failed, a sibling that was
  cancelled had work worth keeping, and marking the failing node
  `continue_on_error` or giving it an error edge was not the right way to
  say so. Before draining is built, measure whether a retry of a run that
  was recorded failed after a send landed sends again; that was not
  measured.
* **The gates**: a workflow whose author deliberately continues past a
  failure and needs a quality gate downstream to pass on what is left. The
  engine already gives a verdict the means to see it (`inputs_degraded`,
  `degraded_inputs`), so the first question is whether the verdict should
  say so itself.
* **The label**: a deployment that cannot set an address of its own and
  whose labels are sensitive.
