# A bound is loosened only with a second factor (2026-10-14)

Security review 2026-10-14, package 11: findings **A-1**, **G-3**, **G-4**,
**G-5**, **A-2** (Medium) and **A-8**, **G-16**, **G-18**, **G-23**, **G-24**,
**A-7** (Low).

## The rule

A security bound is TIGHTENED from any surface and LOOSENED only by a caller
that proved a second factor. `talos_capability_world::ChangeAuthority` names
who is asking — `SecondFactorSession` (a GraphQL mutation behind
`require_second_factor`) or `BearerCredential` (an MCP agent token, an API
key) — and the writer that holds the row lock decides from the value it
replaces. A handler names its authority; it does not classify the change.

## Measured on the reference deployment (read-only)

- Personal organizations: 1, with 0 members other than its owner.
- `user_capability_grants`: 1 row (`automation-node`, the top of the lattice),
  1 user. Every gate below that reads the user's ceiling therefore passes for
  that user.
- Agent roles: 4; 1 agent, on `System Administrator` (every world).
- Modules: 191. `*` in `allowed_secrets`: 0; `*` in `allowed_hosts`: 7 (left as
  they are — the rule governs writes). Secret grant entries: 92, of which 12
  fail `talos_registry::validate_allowed_secrets`' character rule (11 carry `.`
  or `@`, 1 an uppercase letter). Host entries: 109, 0 failing
  `validate_allowed_hosts`. Largest lists: 3 secrets, 4 hosts.
- `require_2fa` call sites in `talos-api`: 58; `require_second_factor`: 22.

## Decided

- **A-1.** `OrganizationService::add_member` and `transfer_ownership` read
  `is_personal … FOR SHARE` in their transaction and refuse
  (`PERSONAL_ORG_REFUSAL`). Migration `20261015090000` adds two triggers so no
  other writer can: a personal org takes no member but its owner, and its owner
  never changes. `inviteMember` was NOT moved to `require_second_factor`: a
  shared org's invitation crosses no bound the triggers do not already hold.
- **G-4.** `ActorRepository::delete_capability_grant` takes the authority: a
  revoke that WIDENS another user's ceiling (withdrawing `minimal-node` or
  `governance-node`) is `WideningNeedsSecondFactor` for a bearer. Over MCP that
  is a `-32003`. The GraphQL resolver tries as a bearer and, only on that
  answer, asks `require_second_factor` and tries once more — so a narrowing
  revoke stays on `require_2fa`, quick in an incident, as the source pin
  decided for revocations. The self-revoke refusal is unchanged.
- **A-8.** `revokeCapabilityCeiling` requires the Admin scope of every caller,
  before the self branch. The source pin
  (`the_privileged_tier_calls_the_second_factor_gate`) now states the resolver
  is both tiers by branch and that the scope precedes the branch.
- **G-5 (operator decision D-1; the narrow option built).** The four per-actor
  setters take the authority; `set_actor_ceiling_recorded` refuses a loosening
  for a bearer (`CeilingWrite::LooseningRefused`), logged
  `actor_ceiling_loosening_refused` on `talos_audit`. The GraphQL twin is
  `setActorCeiling(actorId, ceiling, value)` behind `require_second_factor`.
  Ranks per axis: tier `tier1 < tier2`; write `readonly < write`; egress
  `local < (cleared) < public`; verb override `readonly < (cleared) < write`.
  An unrecognised stored value ranks lowest, as the fail-closed parser reads
  it. Clearing an explicit `local`/`readonly` therefore counts as loosening.
  The digest paragraph is in "The actor write ceiling".
- **G-18.** A self-grant of the world already held changes and records nothing,
  so the admin's `granted_by`, `granted_at` and `notes` stay.
- **G-16.** `require_2fa` is documented, not renamed (58 call sites and the
  source pins read the name), and CLAUDE.md carries a correction. Decided to
  stay on `require_2fa`: the revocations and `setConcurrencyLimit` (bounds one
  of the caller's own workflows, 1..100, crosses no tenant or bound).
- **G-3 (a), (b).** `registerMcpAgent` refuses a role whose capabilities
  exceed the caller's ceiling (`talos_capability_world::role_capabilities_above`;
  `*`/`admin` read as every world, an unknown name refuses) unless the caller is
  a platform admin. Every MCP surface that compiles, installs or runs a module
  at a world — `compile_custom_sandbox`, `run_sandbox`, `compile_template`,
  `hot_update_module`, `test_module`, `install_module_from_catalog`,
  `install_from_marketplace`, the scratch sessions, inline compiles in
  `create_workflow_from_spec` — goes through ONE gate,
  `sandbox::require_world_permitted` (the role AND the user ceiling; the read
  fails closed), which replaced `require_agent_role_permits_world`. The GraphQL
  `createModuleFromTemplate` checks the template's world against the ceiling.
- **A-2 (the narrow part).** A `*` in `allowed_secrets` or `allowed_hosts` is
  refused for a bearer at the repository writer
  (`WildcardGrantRefused`, the error of `update_module_allowed_*`) and on the
  compile and `run_sandbox` arguments (`sandbox::refuse_bearer_grant`). Every
  write that adds an entry is logged `module_grant_widened` on `talos_audit`
  with the entries added (paths and hosts, never a value).
- **G-23.** An edit of a stored module's grants passes the module's world
  through `require_world_permitted`; secrets lists are held to 50 entries of
  200 characters (`talos_registry::validate_allowed_secrets_bounds`, new) and
  hosts lists to `validate_allowed_hosts`.
- **G-24.** A marketplace install refuses `*` from a bearer, a `/*` prefix on a
  listing not published by `SYSTEM_PUBLISHER_ID`, and an installer at the
  500-module quota (`modules::refuse_over_module_quota`, now shared with the
  catalog install). Publishing refuses a `*` host and runs the host validator
  over the snapshot that every installer inherits.

## Operator decisions surfaced

- **D-5 (not built).** The default actor stays exempt from the ceiling
  re-check, so for an actor-less run the user grant bounds what is compiled and
  installed (G-3 (b)) but not what an already-stored module runs. Recorded:
  the grant is advisory for actor-less runs of modules that predate it.
  Recommendation: stamp the default actor's `max_capability_world` from the
  grant when a grant row exists.
- **D-6 (documented).** An agent role scopes worlds only; it is not a
  read/write boundary. `registerMcpAgent`'s description says so.
  Recommendation: add a `read_only` capability gated once in
  `handle_tools_call_inner` from the tool list's `readOnlyHint` if a read-only
  reporting agent is wanted.
- **New, A-2 closure (not built).** An MCP token may still grant an exact
  stored path to a module (or to a `run_sandbox` call) and name a host to send
  it to. The review's per-path rule — refuse widening to a path the module's
  template does not declare unless a second factor is proven — would also end
  MCP authoring of every custom module that reads a secret, which is how this
  deployment's modules are built. Recommendation: adopt it together with a
  dashboard path for declaring a module's secret grant, so authoring moves
  rather than stops.

## Corrections to the review

- G-23's "route both the compile and the update paths through the registry
  validators": the secrets validator's character rule refuses 12 of the 92
  entries held today. The size bounds were applied, the character rule was not.
- A-2's fix list names `update_module_secrets` and the compile writers; a
  `run_sandbox` call carries its own grant on each call and resolves stored
  secrets for the caller, so it was gated too.
- G-16 says "150-odd" call sites are not the count — there are 58.

## Mutation proof

See the table in the PR body: every refusal above was broken in turn and its
test went red, then green again on restore. A migration mutation was run after
`scripts/dev-test-db.sh rebuild`.

## Stated limits

- `module_grant_widened` is a log line on `talos_audit`, not the hash-chained
  ledger; the `admin_event_log` row the writer already commits is the durable
  record.
- The repository `*` refusal is checked before the row lock: it depends only on
  the new list, not the row.
- No frontend form calls `setActorCeiling` yet; it is reachable from the
  GraphQL endpoint with a second-factor session.
