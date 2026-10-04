# Connections node: a workflow reads which services are connected

2026-10-04

Third of three builds toward Talos as the operator's control centre: a
reader that follows what is connected, starting with banks. This package is
the read half. The half that would let a workflow READ each connected
account without a node per account is an open decision, recorded below.

## The gap

`money-summary` holds one hand-wired reader node per bank, each naming its
own `vault://plaid/access_token/<item>` reference. A bank connected from
Settings afterwards is not read until someone edits the graph, and nothing in
the summary says so. The same shape holds for calendars and mail accounts.
The only listing of connections was the `list_connections` MCP tool, which a
workflow cannot call.

## What was added

* **`talos_integrations::connections`**: `connection_token_path`,
  `rendered_connection` and the new `list_rendered(pool, secrets, user_id,
  provider)`, moved out of `talos-mcp-handlers/src/secrets.rs`. The tool and
  the node now share one rendering, so they cannot name different references
  for one connection.
* **`connections` system node** (`SystemNodeKind::Connections { provider }`),
  executed in the controller through the injected
  `talos_workflow_engine_core::ConnectionsReader` port; Postgres impl in
  `talos-engine`, wired in `build_controller_engine` (the layer that holds
  the `SecretsManager`). Output: `{available, count, truncated,
  stored_checked, connections: [...]}`, or `{available: false, reason}` when
  the reader is absent, the execution has no identity, the read fails or it
  exceeds 10 s.
* **`add_connections_node`** MCP tool.

## Decisions

**References, never credentials.** The node emits the `vault://` string a
credential is stored at. That string is already shown to the owner by
`list_connections`; it names an account, and it is the owner's own data.

**The node grants nothing.** The engine ships a secret to a module only for
a reference in that node's own CONFIGURATION (`extract_vault_paths`), under
the module's `allowed_secrets` grant. A reference arriving in a node's
INPUT is a string. So adding this node to a graph does not let any module
read a credential it could not read before. Stated in the tool description,
the schema doc and the port's module docs, because the output looks like it
should be usable and is not.

**One provider-id shape rule.** `connections_reader::provider_id_usable` is
used by the graph parser (an unusable value is read as "no filter") and
checked against the provider registry by a test. The first version of the
parser's rule refused `-`, which two registry ids contain
(`google-calendar`, `google-health`); the registry test caught it before it
shipped. Because the parser widens on an unusable value, the tool REFUSES an
unknown provider instead of storing it.

**Degrade, do not fail.** Same contract as `pending_approvals` and
`ops_alerts_digest`. A composer reading `available: false` can say the
listing was unavailable; a failed node would take the whole message with it.

## Measured

* Statements per node run: 2 (the connections UNION, one batched
  `key_path = ANY($1)` existence read), both filtered by the user.
* The listing is bounded at `MAX_LISTED_CONNECTIONS` (500) BEFORE the
  provider filter, so a filtered listing reports `truncated` for the whole
  listing. A user holds a handful; not changed.

## Tests

* `controller/tests/connections_node_tests.rs` (real engine, real reader,
  real database): the owner's banks are listed with their references and
  `stored: false` when the vault holds nothing; a second user running the
  same graph gets `count: 0` and none of the owner's item ids; the provider
  filter keeps one service; no reader and no identity both degrade.
* `graph_builder`: round trip, and five unusable provider values each parse
  as no filter.
* `talos-mcp-handlers`: an unknown provider is refused; every registry id
  passes the shared shape rule.
* The tenancy filter itself is the existing `list_user_connections`
  statement (`WHERE user_id = $1` in every branch) and
  `existing_secret_key_paths` (`created_by = $2`); neither was changed, and
  no mutation was run against them here.

## Open decision: reading every connected account

**Decided 2026-10-04: the per-connection fan-out, built in
`2026-10-04-for-each-connection.md`.** The paragraphs below are kept as the
options that were put to the operator; the claim that it "touches the secrets
pipeline" turned out to be wrong, and that record says why.

Two engine facts stand between this node and a reader that follows
connections on its own:

1. Secrets are shipped for references in node configuration only. A
   per-connection reference produced at run time cannot be resolved.
2. There is no data-driven for-each. `loop` re-dispatches one body node while
   a condition holds; `ensemble` runs N copies of a child on one input.

Options, in the order recommended:

* **A per-connection fan-out node.** Config names a provider and a body
  module. The controller lists the user's connections of that provider and
  dispatches the body once per connection, supplying that connection's
  secret paths itself. The paths come from the controller's own registry of
  the running user's connections, never from module output, and the body
  module's `allowed_secrets` grant must still cover them (a prefix grant such
  as `plaid/access_token/*`). Changes: one new system node, one new input to
  `build_dispatch_secrets_for` (engine-supplied paths), a bound on fan-out
  width. This touches the secrets pipeline, so it needs the operator's
  decision and a security review of that one function.
* **A prefix reference in configuration** (`vault://plaid/access_token/*`),
  expanded by the engine to every matching secret the user owns, used with
  the existing `loop`. Smaller change, but every matching credential is
  shipped to every iteration, which is wider than each run needs.
* **Regenerate the nodes.** A script that rewrites the bank nodes from
  `list_connections`. No platform change; the graph is still stale between
  runs of the script, and this node is what would report it.

Not built. Until one is chosen, the use of this node is reporting: a summary
can compare the connected banks against the banks it read and name any it
did not.

## Not verified

Not run on the live stack: the node is not deployed. No workflow was
triggered.
