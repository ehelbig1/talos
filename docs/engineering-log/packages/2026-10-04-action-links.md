# Action links: a link in a message that starts a workflow

2026-10-04

First of three builds toward Talos as the operator's control centre: the
"control" half needs a way for a message to carry an action.

## The gap

The only link that acted was the approval link, which resumes one suspended
execution and can do nothing else. Every other action in a composed message
("done 12", "keep 12", "hold this time") was a `mailto:` link: two taps, a
mail-client round trip, and an effect only when a capture workflow next read
the inbox, up to half an hour later. Workflow-building pain point 39.

## What was added

* **Token store** (`workflow_action_tokens`, migration `20261004120000`) and
  `talos_execution_repository::action_links`: mint (batched, ownership JOIN,
  expired rows swept in the same statement), lookup, single-use claim,
  release, record. Hash-only at rest.
* **`action_links` system node.** The compose module asks for links in its
  output (`__action_links__`) and marks where each belongs
  (`talos-action:<id>`); the node mints them through the injected
  `ActionLinkMinter` port and passes the output on with placeholders
  replaced, the request removed and `__action_links_report__` written.
  Planning and substitution are pure functions in
  `talos_workflow_engine_core::action_links`.
* **Public endpoints** `/action-links/{token}`: GET renders a confirmation
  page, POST claims the token and calls
  `ExecutionOrchestrationService::trigger`.
* **`add_action_links_node`** MCP tool.

## Decisions

**A node, not an output protocol.** The hook that handles `__memory_write__`
and `__ops_alert__` is synchronous, sees an immutable output and spawns its
work; it cannot mint and substitute before the next node reads the output. A
node in the graph also makes the capability visible: a message can carry
links only where the author put a node that says which workflows they may
start.

**The author lists the targets; the module names one.** `targets` in the
node's config maps a name to a workflow id. A module's request names a
target. Anything else is `unknown_target`. A request that carries its own
`workflow_id` is still resolved by `target` alone.

**Ownership is checked at the mint, every time.** The node cannot vouch for
its own configuration, so `mint_action_tokens` JOINs `workflows` on the
running user. The tool also checks at add time, for a readable refusal.

**Claim before start; release only when nothing can have started.** A link
starts its workflow at most once. Refusals known to precede any execution
(paused platform, disabled or retired workflow, authorization, input
validation, concurrency limit) give the claim back. `DispatchFailed`,
`GraphLoadFailed`, `Internal` and the rest keep it: an execution may exist,
and starting twice is the worse outcome.

**GET does nothing.** Same reasoning as the approval links: scanners and
previewers open links. So an email link is tap-then-confirm. The one-tap form
is a push notification action that POSTs; that channel does not exist yet.

**Placeholder is `talos-action:<id>`, not `{{…}}`.** Module source containing
Handlebars syntax is rendered at compile time, so a `{{action:…}}` literal in
a module would be consumed by the compiler.

**A fallback is restricted.** It is module-authored text that lands in an
`href`: only `mailto:` and `https:`, bounded, no quotes, spaces, angle
brackets or control characters.

**The node never fails the run.** No minter, no tenant identity, a failed or
timed-out mint: every placeholder falls back and the report says why. The
message is worth more than its links.

**Outside the write ceiling, and not an ambient protocol.** Minting writes a
platform row, not the actor's data plane, and the workflow a link starts runs
under its own actor's gates. Unlike `__ops_alert__` and `__ml_distill__`,
nothing happens unless the author placed the node, so it is not added to
`UNGATED_OUTPUT_PROTOCOLS`.

**The payload is stored as the trigger input will be** (plain jsonb, like
`workflow_executions.input_data`), bounded to 8 KB by a CHECK.

**nginx writes no access-log line for `/action-links/`.** The token is the
last path segment and the default log format records the path.

## Tests

* `talos_workflow_engine_core::action_links` (6): a module names a target and
  never a workflow; bounds, duplicates and unusable ids; placeholders
  replaced everywhere with the longer id first, the request never survives, a
  module cannot author the report; everything falls back when nothing can be
  minted; fallback restrictions; target parsing.
* `talos_execution_repository::action_links` (4): label cleaning, lifetime
  clamp, request shape, URL.
* `talos-webhooks` (1): which refusals release a claim.
* `controller/tests/action_links_tests.rs` (3), real database: the node in a
  real engine with the real minter (one row, hash only, foreign workflow
  refused, confirmation page escapes the label and a GET changes nothing);
  eight concurrent claims yield one; release and its limit; unknown,
  malformed and expired are one answer; the apply page gives a link back when
  the workflow is switched off and not when no service is wired.
* Mutations, each killed: ownership JOIN removed from the mint; the
  single-use condition removed from the claim; release ignoring a recorded
  execution.

## Not exercised

A successful start through the apply page: `trigger` needs NATS, which the
test harness has none of. The start itself is `trigger_workflow`'s path.
First live use is the proof.

## Not done

* No workflow uses the node yet. The morning message's `done`/`keep`/`drop`
  links are the first adopter, in the consolidation that follows.
* No metric. A minted or applied link is visible as a token row
  (`triggered_execution_id`) and a `talos_action_links` log line.
* The existing approval and correction link endpoints still log their token
  paths in nginx; not changed here.
