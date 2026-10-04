# For-each-connection: one node reads every connected account

2026-10-04

The second half of the multi-bank reader. `2026-10-04-connections-node.md`
let a workflow LIST what is connected; this lets it READ each connected
account without a node per account.

## The gap, measured

`money-summary` holds three hand-wired nodes of one module, differing in two
config keys (`ACCESS_TOKEN`, a `vault://plaid/access_token/<item>` reference,
and `INSTITUTION`), then a `collect`. Three banks are connected. A fourth
connected from Settings is not read until the graph is edited. The same
shape holds for the two calendars in `pa-morning`.

Two engine facts were in the way: a module receives a secret only for a
reference in its node's CONFIG, and there was no node that runs a module
once per item of a list.

## What was added

* **`SystemNodeKind::ForEachConnection { provider, bind, max_connections }`**,
  set on a MODULE node (`kind: "for_each_connection"` beside `type: <module
  id>`; settings in `data.for_each_connection`). The engine lists the running
  user's connections of `provider`, and for each one dispatches the node's
  module with the bound config keys set from the connection.
* **`RunVariation`** — an optional last argument to
  `run_single_node_dispatch`: a config overlay and an iteration index.
  Applied after the module/node config merge and before the idempotency key,
  the vault-path extraction and the input envelope are derived.
* **`apply_output_protocols`** — extracted from `handle_node_success`
  (sanitise, strip engine-authored input keys, write-ceiling gate with its
  refusal notification, completion hook). Called per node as before and now
  per run.
* **Pure planning and assembly** in
  `talos_workflow_engine_core::connections_reader`: `parse_for_each_connection`,
  `plan_connection_runs`, `for_each_output`, `for_each_error`.
* **`set_for_each_connection`** MCP tool: sets or removes the setting on an
  existing module node, and reports what would run right now from the same
  planner the engine uses.

## Decisions

**Each run is a single-node dispatch, not a fourth job builder.** There were
three hand-built `DispatchJob` literals (single, loop, pipeline), and the
loop's copy skipped the capability ceiling, the approval gate and the retry
budget until 2026-09-25. A fan-out that assembled its own job would be a
fourth. Instead the node calls `run_single_node_dispatch` once per
connection, so every gate that function applies, applies; what varies is an
argument.

**The secrets pipeline is unchanged.** The earlier record said this design
"touches the secrets pipeline (`build_dispatch_secrets_for`)". It does not.
That function already takes the vault paths to fetch; the single-dispatch
path derives them from the run's config with `extract_vault_paths`. Writing
the connection's reference into the run's config is therefore enough: the
existing extraction asks for exactly that path. Verified by a recording
resolver: each run asks for one token path, its own.

**Where the reference may come from.** From the controller's listing of the
running user's connections, by `self.user_id`. Not from node config (the
provider is, the references are not), and not from any node's input — the
overlay is built before inputs are looked at, and a bound key that starts
with `__` is dropped at parse and refused by the tool, so an engine-authored
input key cannot be bound either.

**The module's grant is checked before dispatch, and again by the worker.**
`plan_connection_runs` takes the grant check as a closure
(`vault_path_permitted` over the module's `allowed_secrets`); a connection it
does not admit is reported `not_granted` and never dispatched. The worker's
`check_secret_allowlist` is unchanged. With a prefix grant
(`plaid/access_token/*`) nothing is prefetched on the grant alone, so a run's
secrets map holds the node's static references and that run's token.

**A kind on a module node, not a system node pointing at a body node.** The
`loop` node names a body node, which is also an ordinary graph node and so
also runs on its own. Here the module node IS the fan-out, so there is
nothing left over to run twice, and every per-node setting (`max_fuel`,
`timeout_secs`, `retry_count`, `continue_on_error`, `requires_fresh`) is read
from the one place it already is.

**A separate kind from any general for-each.** An input-driven map node
would be useful and is not built. It must be a different kind: its overlay
would come from module output, and it must never be able to set a `vault://`
value. Keeping the two apart keeps "a reference reaches a module only from
node config or from the controller's connection listing" a rule with two
named sites.

**Failure is per account.** A failed run is an error item naming its account
and the node completes; the node fails (reactor failure path: error edges,
`continue_on_error`, DLQ) only when the listing cannot be read or
connections exist and none was read. An unreadable listing is an error
rather than `available: false`: this node's job is the read, and "could not
list" must not look like "no banks".

**Batches of four.** Runs are independent. `join_all` over batches of
`FAN_OUT_CONCURRENCY` rather than a sliding window: a stream combinator over
borrowed runs did not satisfy the reactor future's `Send` bound, and a
batch is simpler than fighting that. With three banks the difference is nil.

## Measured

* Statements for the node itself: the connections UNION and one batched
  vault existence read, both by the user; one module fetch (cached per
  execution).
* Per run: exactly what one module node costs.
* Bounds: 16 connections per node (default 8), 8 bound keys, 4 in flight,
  10 s for the listing, the node output limit on each run and on the whole.

## Tests

* Core (6): planning, skip reasons, the limit, a binding with no credential,
  settings parse, output assembly.
* Engine (`tests/for_each_connection.rs`, 7): each run's config and vault
  asks carry its own connection only; a not-granted connection is never
  dispatched; nothing granted fails the node; another user's run reads
  nothing; one failure is a gap, all failing fails; each run's memory write
  reaches the hook, and a `readonly` ceiling removes each one and reports
  each refusal; engine-authored keys cannot be bound.
* Controller, real database (`connections_node_tests`): the real listing is
  what the planner reads; a bank the vault does not hold is `not_stored`;
  a second user lists, runs and names nothing of the owner's.
* Handlers: argument refusals; what the tool writes is what the engine's
  parser reads back.

Mutations, each killed and restored:

| Mutation | Tests that failed |
|---|---|
| grant check always true | `a_connection_the_modules_grant_does_not_admit_is_never_dispatched`, `nothing_is_granted_so_nothing_runs_and_the_node_fails` |
| per-run `apply_output_protocols` skipped | `each_runs_output_is_handled_as_a_nodes_output_is` |
| listing read for a fixed user id | five of seven |

## Stated limits

* `clear_module_dispatch` runs per run, so a module that requires approval
  asks once per connection.
* A run's `node_input` event carries its iteration index; the events the
  dispatcher emits (retries) do not.
* The loop node's body dispatch is still its own job builder. Found while
  reading it and NOT changed here: it calls `build_dispatch_secrets` with the
  body's MODULE id where `node_configs` is keyed by NODE id, so a loop
  body's config `vault://` references look not to be extracted. Unverified;
  to be confirmed and fixed on its own.

## Not verified

Not deployed; no workflow was triggered. `money-summary` is unchanged.
