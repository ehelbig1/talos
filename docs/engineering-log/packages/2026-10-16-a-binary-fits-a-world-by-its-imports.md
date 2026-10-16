# A binary fits a world by its import set, not by a classified world (2026-10-16)

## The break

The deploy of 2026-10-16 02:05 UTC (main at #1339) refused every agent-world
module that read actor memory without orchestrating. Within fifteen minutes
pa-ask-email (the inbox channel, 4 of 4 runs), talos-ci-watch and
talos-alerts-to-phone had failed on

    capability-world-exceeded: declared=agent, actual=trusted.
    Imported interfaces: talos:core/agent-memory

Cause. `talos_wit_inspector::classify_world` named a world for a binary with a
hand-written match over seven booleans; a binary importing `agent-memory`
without `agent-orchestration` matched no arm and fell to "anything else is
Trusted". Until #1325 the `agent-node` sentinel the SDK embeds overrode that
name. #1325 (right for E2-7: the sentinel is author-steerable) made the
sentinel unable to narrow the classified world, and #1289's dispatch-time
check then asked "is the classified world a subset of the row's world" and
refused. No test covered a memory-reading agent module with no orchestration
import. Compiling such a module declared `agent-node` would have been refused
by the same comparison in `reconcile_declared_world`.

## Decided

- **The fit test is on the import set.** `talos_wit_inspector::world_imports`
  is the `talos:core/*` import list of each WIT world;
  `imports_outside_world(imports, world)` is the one predicate. A binary fits
  a world when that list is empty. `validate_capability_level` (hence
  `link_world` at dispatch), `talos_compilation::reconcile_declared_world`
  (via `declaration_verdict`), `check_interpreted_component` and
  `world_to_record` all ask it. Two worlds can be incomparable (`agent-node`
  and `database-node` both import `agent-memory`), so a world-to-world subset
  test refused binaries that fit; the import test does not.
- **The classifier is a NAME, found by set cover.** `classify_world` now
  returns the narrowest world of `WORLDS_NARROW_TO_WIDE` whose imports cover
  the binary's; `agent-node` is tried before `database-node` (the WIT file's
  preferred world, no raw SQL). An interface no world imports is `Trusted`.
  The sentinel stands when the imports fit it (`sentinel_never_narrows` now
  takes the imports), so a memory-only binary with the database sentinel is
  named `database`.
- **`world_to_record` records the request when the binary fits it but is
  named incomparably** (a memory-only binary built for `database-node` is
  named `agent`, recorded `database`); the binary's own world when that is
  within the request; a refusal only for an import outside the request or an
  unknown world on either side.
- **The tables are held equal to `wit/talos.wit`** by
  `world_imports_match_the_wit_file`, which parses the file at test time.
- `talos_capability_world::classify_world_declaration` and its tests are
  deleted: it had no caller left and was the second rule. `WorldDeclaration`
  stays (the compile service's verdict type).

## Deliberately NOT done

- A pre-deploy audit of the installed modules against the candidate worker
  (the class of break this was). It is the next package, not this fix.
- Changing `is_subset_of` on `CapabilityWorld`: it is the ceiling lattice
  (which world a role or an actor may compile at), a different question from
  "does this binary fit that world".
- Re-recording the `capability_world` of existing module rows. A row's world
  is what its gates checked; the dispatcher now fits the binary to it.

## Measured

Live stack, `modules` rows with bytes by kind/world before the fix: 32 rows
labelled `agent-node` (4 catalog, 4 extracted, 28 sandbox); the three
workflows above failed within 15 minutes of the deploy, the morning message
would have at 08:00. Inspector tests 40 → 45; compilation lib tests 190 → 191
plus two cases rewritten; capability-world tests 35 after the deletion.

## Mutation proof

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| import fit at link and in the classifier | `imports_outside_world` returns `vec![]` | `a_binary_wider_than_its_hint_is_refused`, `a_memory_reading_module_links_at_agent_and_at_database`, `classification_is_the_narrowest_covering_world` and nine more | FAIL ×12 / PASS restored (45 ok) |

## Stated limits

- `wasi:` imports are not part of the fit: raw sockets are a runtime grant
  decided by the stored world, unchanged.
- The fit says nothing about a row whose world was recorded wider than its
  binary needs; the ceiling checks at compile time still bound that.
