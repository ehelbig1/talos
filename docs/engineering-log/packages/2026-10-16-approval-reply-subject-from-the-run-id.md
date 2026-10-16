# An approval decision goes where the run's id says (2026-10-16)

The follow-up R11 named (security review 2026-10-15, E2-6). Package R12.

## The defect

When a governance module asked for human approval, the worker:
1. waited on `talos.approvals.wait.<job id>`;
2. wrote that subject into Redis as `approval:<run id>`.

When the owner approved, the controller (the REST approval handler and the
MCP `submit_workflow_approval`) read the subject back from Redis and
published the decision to it. The only check was that the subject was
printable and had no wildcards.

So anything that could write `approval:*` chose where a decision was
published: a compromised worker under its own Redis user (R11 left the family
writable), or anything else with Redis access. A worker with no run id also
waited on `talos.approvals.wait.unknown`, a subject every such job shared.

## Decided

- **One function names the subject on both sides.**
  `talos_workflow_job_protocol::subjects::approval_reply_subject(run)` is
  `talos.approvals.wait.<workflow_execution_id>`. The run id is signed in the
  `JobRequest`, and it is the id both controller paths are given.
  `approval_publish_subject(run, marker)` is what the controller publishes
  to: that subject when a waiter left its marker, nothing when none did. The
  marker's value is never read as a destination.
- **The worker waits on the run's subject** and writes `approval:<run>` =
  `pending`. A job with no run id refuses (returns false) instead of waiting
  on a shared subject.
- **Both controller paths** key the marker by the run id's canonical
  spelling, and publish to `approval_publish_subject`. The subject validation
  they carried is deleted: the subject is built from a parsed UUID.
- **Behaviour change:** two approvals pending in ONE run, at the same time,
  now share a subject, and one decision answers both. Before, the second
  overwrote the first's Redis row, so the first could not be reached and
  timed out. An approval is decided per run in both surfaces.
- **Deploy:** the controller and the worker roll together. An old worker
  waits on its job-id subject, which a new controller never publishes to;
  such an approval would time out (treated as denied).

## Tests

- `talos-workflow-job-protocol::subjects::an_approval_decision_goes_where_the_run_id_says_not_where_redis_says`:
  - a marker holding `pending`, another run's subject, an unrelated subject,
    or an empty string all publish to the run's own subject;
  - no marker publishes nothing.
- The frozen wire format: `approval_reply_subject` equals `approvals_wait_for`.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| the marker is never a destination | `approval_publish_subject` returns the marker | `an_approval_decision_goes_where_the_run_id_says_not_where_redis_says` | FAIL / PASS restored |

## Stated limits

The two controller handlers are not driven end to end with Redis and NATS.
The seam they call is the tested function, and nothing else reads the
marker's value (measured with `git grep`).
