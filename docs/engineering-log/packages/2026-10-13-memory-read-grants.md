# Memory read grants: one document for a session, as a fact and not an instruction

2026-10-13

## The question, and the decision

A coding session was meant to read exactly one approved document, held in
one actor's memory under one key. It read it over MCP, which can recall any
key of any actor the user owns, read every execution's outputs, write memory
and change workflows. Investigated the same day: an MCP agent token carries
no tool list, no read-only flag, no actor, no key prefix and no expiry; the
capability ceiling bounds the world a user may assign to an actor and
nothing about tools; the one `tools/call` chokepoint observes and enforces
nothing.

Three options were put to the operator (scoped MCP keys; a single-purpose
read with its own narrow key; documenting that the local endpoint is
operator-equivalent). The operator asked for the choice to be made on best
practice, security, performance and fit. **Chosen: the single-purpose read**,
with the isolation rule written down.

Why this one:
* **It is the house pattern.** Approval links and action links are already
  capabilities bound at mint to one thing, hash-only at rest, expiring,
  checked every time they are used. A grant is that pattern for a read.
* **The scope cannot be got wrong per tool.** Scoping MCP keys to "one actor
  and a key prefix" needs every one of 368 tools to be classified by which
  arguments name an actor or a key, and several expose memory indirectly
  (execution outputs, search, context previews). One row and one statement
  have no such surface.
* **Least privilege by construction.** The request has no parameter.

## Decided

* **The scope is the row** (`memory_read_grants`: user, actor, exact key).
  Not a prefix.
* **The token travels in the `Authorization` header only.** The capability
  links carry theirs in the path because a person taps them; nginx had to be
  told not to log that path, and a third-party tunnel still sees it. A
  program can set a header, so this one is never in a URL.
* **One statement enforces everything** (`read_grants::claim_read`): live,
  not revoked, reads left, the actor still the minting user's; it counts the
  read in the same UPDATE.
* **One answer** for every request that reads nothing, including a key with
  nothing stored.
* **Lifetime always set**: 24 h default, 168 h at most. Out-of-range values
  are refused by the tool, not clamped. Optional `max_reads` (1 to 1000).
  50 live grants per user.
* **Minting and revoking are recorded in `admin_event_log`** in the
  transaction that makes the change, with the key. Reads are `read_count` /
  `last_read_at` on the grant, and a `talos_audit` line with the grant id.
  A row is kept 30 days past expiry so its use can still be seen.
* **Not redacted, and allowed for any actor**, including one whose model
  tier keeps its data on the host. The use this was built for is handing a
  tier-1 actor's approved document to an outside session; the mint is that
  decision and is recorded. The tool's description says so in those words.
* **`talos_admin_read` gets no grant on the table**, and it is in
  `BLOCKED_TABLES_LIST`, like the other token tables.
* **Minted over MCP.** MCP is read-only for SECRETS (MCP-1201) because a
  bearer token must not write the vault. A grant gives nothing its minter
  could not already read, to someone with less.

## Deliberately NOT done

* **No scoped MCP keys.** Expiry and a tool allow-list on agent tokens are
  worth having for their own sake (the threat model lists non-expiring
  tokens as a residual risk) and are a separate change.
* **No prefix or multi-key grants, no write grants.**
* **No switch that turns `/mcp/local` off on a development stack.** The
  deploy and drill scripts use it. Isolation is where the session runs.
* **No per-read row.** A count and a last-read time on the grant, plus the
  log line.
* **No metric.** A grant that is read shows on its row.

## Tests

* `talos-actor-memory-service` `read_grants::tests` (5): the header rule,
  the token's shape, the lifetime bounds, the label, a grant's state.
* `controller/tests/memory_read_grant_tests.rs` (2), real database, the real
  tools and the endpoint as mounted. See the file's header for the list.

Mutations, each caught and then restored (the binary sets
`TALOS_RLS_SET_ROLE` off, so it is the predicates that are tested):

| Mutation | Caught by |
|---|---|
| mint: the actor need not be the caller's | `only_the_owner_of_an_actor_can_make_a_grant…` |
| read: a revoked grant still reads | `a_grant_reads_its_one_key_and_nothing_else` |
| read: an expired grant still reads | same |
| read: the read limit is ignored | same (the two-read grant and the raced one-read grant) |
| read: the actor may have changed hands | same |
| revoke: anyone's grant | same (a stranger's revoke) |
| token: any `Authorization` scheme accepted | same ("another scheme") and the unit test |

## Stated limits

* A grant narrows a token. It does not remove what a session can otherwise
  reach; on the controller's machine `/mcp/local` answers.
* The document is in the response body in the clear over whatever carries
  the request. Use the https address.
* The read is counted before the memory is read, so a read of a key with
  nothing stored uses one of `max_reads`.

## One home

`talos_actor_memory_service::read_grants` (store, scope, audit);
`talos_webhooks::memory_grants` (the endpoint). `docs/memory-read-grants.md`.
