# A standard for building blocks; the capture contract (2026-10-09)

The operator asked for a standard of small, modular, repeatable blocks so
that future workflows are easier to build, with best practice, performance
and security held. Surveyed first: 86 catalog templates, no field saying what
kind of module each is; the rules for modules were spread over `CLAUDE.md`,
five docs and two contract docs.

## Decided

* **Five roles** — reader, decider, keeper, composer, sender — each with its
  world, grants, memory and model rules (`docs/building-blocks.md`). The
  page points at the existing rules rather than repeating them.
* **Declared in the manifest**, `"block": {"role", "contract"?,
  "reads_by_post"?}`, because the manifest is what an installer reads to
  decide whether to trust a module. `CatalogManifest::parse` reads fields by
  name and ignores the rest, so the field is checked in CI and stored nowhere.
* **Enforced by `talos-catalog-tests/tests/block_roles.rs`**: a declared role
  must fit the grants (a reader never PUT/PATCH/DELETE and POST only with a
  stated reason; a sender has a boolean `DRY_RUN`; decider/keeper/composer
  reach no network; keeper is agent-node); a contract is carried by the
  matching prefix and role; a new template must declare a role. A test of
  the rules themselves proves each one refuses what it is for.
* **Ratchet, not a big bang.** 16 existing templates were classified (every
  one fitted its role) and the capture adapter declares on arrival: 17 of 86.
  The other 69 are on `UNDECLARED`, which only shrinks.
* **The capture contract** (`docs/capture-contract.md`): the neutral
  `captured` shape, a contract block, `tests/capture_contract.rs` (identical
  blocks, the rules over the same input, a manifest that only reads), and the
  consumer rule that a captured line may only ADD.
* **`capture-home-assistant` promoted** from the operator's own repository
  with `scripts/promote-module.py`, from a copy whose grants were emptied
  first: the script catches UUIDs, e-mail addresses and per-user secret
  paths, not a host name, and the live module's grant names the operator's
  Home Assistant host. Ids are unchanged (`phone:<epoch ms>`), so swapping the
  live node to the catalog copy does not re-add a line already kept.
  Behaviour change on promotion: a duplicate line now counts in `ignored`
  (the contract says so); the private module did not count it.

## Deliberately NOT done

* **Classifying all 86 templates now.** Each needs its grants read against
  its role; done in passing, the list shrinks as templates are touched.
* **Fixing `send-gmail`.** It cannot declare `sender`: no `DRY_RUN`, and a
  `network-node` world where `http-node` would do. Recorded, left on the list.
* **A lint over module SOURCE** (that a composer makes no HTTP call, say).
  The world and grants already bound what a module can do at run time; the
  manifest check holds the declaration to them.

## Measured

* `make check-catalog-fuel TEMPLATE=capture-home-assistant`: 623,040 of
  3,786,000 (16.5%) for a recorded day of twenty replies; a live run with
  nothing new used about 90 K (2026-10-09).
* `cargo test -p talos-catalog-tests`: the template's 4 tests,
  `capture_contract` 5, `block_roles` 3.

## Stated limits

* A role says what a block may do; it does not prove the source does only
  that. The world and grants are what is enforced at run time.
* One capture adapter: the "identical blocks" test has nothing to compare yet.
