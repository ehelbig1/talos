# Building blocks

A workflow is built from small modules that each do ONE job and say which job
it is. The next workflow is then mostly blocks that already exist, joined by
shapes that already exist, and the review of a new block is a review against
the rules of its role rather than of everything a module could do.

This page is the standard. It does not repeat the rules it builds on; it
points at them: the module rules in `CLAUDE.md` ("WASM Module Development
Rules"), `docs/module-authoring.md`, `docs/module-testing.md`,
`docs/module-promotion.md`, `docs/delivery-node-pattern.md`,
`docs/adding-an-integration.md`.

## The five roles

Every block is one of these. The three verbs of the platform — take data in,
decide, act — are reader, decider, sender; keeper and composer sit between.

| Role | Its one job | World | Grants | Memory | Model |
|---|---|---|---|---|---|
| **reader** | Read one service; change nothing there | `http-node` (`secrets-node` if it signs) | One service's hosts; GET/HEAD (POST only where the service reads by POST, stated) | none | none |
| **decider** | Compute over its input: classify, extract, summarise, transform | `minimal-node`, `secrets-node` (a model), `agent-node` (reads memory) | no host, no verb | read only | only where judgement is needed |
| **keeper** | Be the ONE writer of a memory key | `agent-node` | no host, no verb | writes its own key, through `__memory_write__` | none |
| **composer** | Render one surface (an email, a `notification`) from its inputs | `minimal-node`, `agent-node` | no host, no verb | read only | none (it renders what a decider decided) |
| **sender** | Make one effect at one service | `http-node` | One service; the verbs the effect needs | none | none |

### Rules by role

**Reader.**
* Returns a neutral shape where one exists (`docs/capture-contract.md`), or
  the service's data reduced to typed fields — never the raw body.
* Bounded: a page size, a window, a cap, a `truncated`/`ignored` count.
* A refusal fails the node with the host and the status, never the body.
* Recorded run in `fixtures/http.json`, fuel declared and checked.

**Decider.**
* Deterministic first. A model only where judgement is needed, local
  (tier 1) for anything personal or work, and the model PROPOSES while code
  VERIFIES (the model returns the exact quote; the code checks it is present).
* Its output says what it decided and enough of why to audit it.
* Never a network call of its own: a model is reached through the host's
  `llm` interface, not HTTP.

**Keeper.**
* The only module that writes its key. Writes carry `metadata.kind` and, for a
  store written often and changed rarely, `skip_if_unchanged: true` (so a
  freshness contract reads "checked" rather than "stale").
* Idempotent: remembers the ids it has applied, bounded; a per-run cap counts
  only what is not yet applied.
* A source weaker than authenticated mail (a reply box, a webhook) may only
  ADD, never close, drop or move (`docs/capture-contract.md`).
* An unreadable store is an error, never an empty store that overwrites it.

**Composer.**
* Renders; does not decide. Escapes every model-written string. Says when an
  input was stale (`__staleness__`) or degraded (`__degraded_inputs__`).
* Returns `skip: true` when there is nothing worth sending.
* For a phone, the neutral `notification` (`docs/notification-contract.md`):
  no service vocabulary — no topic, entity, device.

**Sender.**
* Reads a contract shape, not another module's private fields.
* A boolean `DRY_RUN` that sends nothing and reports what would have been sent.
* Honours `skip: true`. Only https links. Retries only when the effect is
  idempotent (a `tag` that replaces, an idempotency key).
* One adapter per service, interchangeable through a contract
  (`notify-*`, `control-*`).

## Contracts

When two kinds of block meet across a service boundary, the shape between
them is written down once:

* a document (`docs/<name>-contract.md`): the shape, the rules every adapter
  applies, what the consumer must and must not do, the adapter list;
* the rules as ONE block of source, copied byte for byte into every adapter
  between `// ── <name> contract ──` markers;
* a test in `talos-catalog-tests/tests/<name>_contract.rs`: the copies are
  identical, every adapter's output obeys the rules for the same input, every
  `<prefix>-*` template is listed, and every adapter installs with no host and
  no secret.

Contracts today: `notification` (`notify-*`), `home-control` (`control-*`),
`captured` (`capture-*`), and action links (`docs/action-links.md`).

Write a new one when a second block would otherwise read a first block's
private fields, or when a service is likely to be replaced.

## Wiring blocks into a workflow

* **Gate a send with a conditional EDGE, not a skip.** A node skipped by its
  own `skip_condition` still hands its children an envelope and they run; an
  inactive edge skips the child and everything below it, and an expression
  that fails to evaluate means the branch is not taken. Use it for "only when
  something failed" and "only when the search found something".
* **Optional sources fail soft.** `continue_on_error: true` on a reader whose
  absence the workflow can survive, into a `collect`; the consumer reads
  `items[]` by what each entry carries.
* **A module that gathers ids from upstream gets a workflow of its own**
  (`Gmail: Modify Labels` unions `messages[].id` from every upstream node):
  its only upstream is then its own search.
* **One writer per key.** If two workflows would write the same key, one of
  them is wrong.
* **Freshness on every memory reader that reports**: `requires_fresh`, and a
  composer that names a stale input.
* **Bind the workflow to the actor whose data it handles**, at the narrowest
  tier and egress that work (`tier1` + `egress_scope=public` for a private
  reader of a public API).
* **Rehearse before going live**: `test_module` with `http_fixtures`, then
  `test_workflow` with `dry_run: true`, then one real run you can see.

## Where a block lives

* **Your own blocks** — a private repository with the shared test kit
  (`talos-module-testkit`), pushed with your own tooling. Start here.
* **The catalog** — `module-templates/`, for a block general enough that
  someone else could use it, with nothing of yours in it.
  `scripts/promote-module.py` moves one across; `docs/module-promotion.md`
  is the procedure.

A catalog template is self-contained: it cannot share code with another
template except through a contract block. In your own repository, code two
blocks need is kept once and COPIED into each between marked lines, with a
check that the copies match — the same idea as a contract block.

## When to split a block

Split when any of these is true:

* it switches on a `MODE` between jobs of different roles (a keeper and a
  composer in one module);
* two of its jobs need different grants or worlds — the module then holds the
  union, and every job runs with permissions only one needs;
* a change to one job means re-proving the others.

Split by role, keep each output byte-identical to what the old module
produced for the same input, and prove it with a test that runs both before
the old one is retired.

## Checklist for a new block

Security
- [ ] One role, declared in `talos.json` as `"block": {"role": …}`.
- [ ] The narrowest world; hosts and verbs exactly what the role needs; a
      catalog template grants no host or secret of its own when the installer
      supplies them.
- [ ] Credentials only as `vault://` references; never logged, never in an
      error.
- [ ] Error text names the host and status, never a response body.
- [ ] Every model-written or service-written string escaped where it is shown.
- [ ] No real identifiers in source, tests or fixtures (the repository is
      public).

Performance
- [ ] Typed structs, never a top-level `serde_json::Value` over a response.
- [ ] Bounded: fields asked for, page size, cap, window.
- [ ] A recorded run and a declared `recommended_fuel`, checked by
      `make check-catalog-fuel` (or `test_module` + `http_fixtures` in your
      own repository).

Correctness
- [ ] Config validated before anything is sent, each missing key named.
- [ ] Tests through `talos-module-testkit`, including the failure paths:
      refusal, unexpected shape, empty answer, over-cap input.
- [ ] Idempotent where it can be re-run (ids, tags, `skip_if_unchanged`).
- [ ] Version bumped on change.

## What enforces this

| Check | Where |
|---|---|
| Every new template declares a role, and the role fits its grants | `talos-catalog-tests/tests/block_roles.rs` |
| Adapters of a contract agree | `talos-catalog-tests/tests/{notification,capture}_contract.rs` |
| A recorded run fits its declared fuel | `make check-catalog-fuel` (`tests/fuel_fixtures.rs`) |
| A template's own tests run in CI | `make test-templates` |
| Promotion refuses identifiers and per-user secret paths | `scripts/promote-module.py` |

`block_roles.rs` holds templates written before this standard on a list that
only shrinks: declaring a role takes a template off it. On 2026-10-09, 17 of
86 templates declared one. A template that cannot yet fit its role (for
example `send-gmail`: no `DRY_RUN`) stays on the list until it is fixed.
