# 2026-10-01 — a freshness contract can be seen, and a broken one is said

**Context.** A node's freshness contract is two keys in its config:
`requires_fresh` (memory key → max age in hours) and `on_stale`
(`annotate` | `fail`). The engine reads them at dispatch and hands the node a
`__staleness__` report.

**What was wrong.**
- No tool schema or description mentioned either key; the contract was
  documented only in CLAUDE.md.
- Nothing echoed a contract back. `validate_workflow` was silent about it,
  and `get_node_io` cannot show `__staleness__` — engine-supplied keys are
  never in the stored input. Building `pa-week-ahead`, the only way to see
  the contract had been understood was to set a 0.01-hour bound and read the
  warning in the node's output.
- The parser drops what it cannot use without a word (rightly — a run must
  not fail over an authoring slip): a `requires_fresh` that is not an object,
  a bound that is `"6"` or `0`, and an `on_stale` it does not know, which
  reads as `annotate`. So `"on_stale": "error"` — an author asking for a stale
  input to STOP the node — gave a node that annotates and carries on.

**Change.**
- `talos_workflow_engine_core::reserved_keys::freshness_contract_problems`
  and `FreshnessContractProblem`, beside the parser and sharing its two rules
  (`usable_max_age`, `on_stale_as_written`); the parser's behaviour is
  unchanged. A test pins that the two agree: no problem ⇔ the parser kept
  every declared key and the stop the author asked for.
- `validate_workflow`: each problem is a `freshness-contract` warning naming
  the node; and `freshness_contracts` lists every contract the engine will
  enforce (`{node, requires_fresh, on_stale}`). Nothing declared ⇒ no key.
- `get_node_io`: `freshness_contract` for a node that declares one in the
  CURRENT graph, with a note that the report itself is not in the stored
  input. No contract ⇒ no key.
- `add_node_to_workflow`'s `config` description documents both keys;
  `validate_workflow` and `get_node_io` say what they echo.
- One renderer, `utils::render_freshness_contract`, built on the engine's own
  parser — a bound the engine drops is not shown as part of the contract, and
  an unknown `on_stale` is shown as the `annotate` it will be.

**Measured on the reference deployment.** Three live nodes declare a
contract (five keys); all three are well-formed, so this adds no warning
there today. Latent, stated: the class is the next mistyped contract.

**Decided.** Warning, never error: `valid == false` gates publication, and
the engine's own answer to a malformed contract is to run without it.

**Deliberately not done.** Recording at run time which engine keys a node
received (so `get_node_io` could say "`__staleness__` was injected,
any_stale = true" for THAT run). It needs the engine to write a summary into
the node-input snapshot; the static contract answers the authoring question,
and the run's own output shows the consequence.

**Tests.** Core: usable and absent contracts have no problems; every dropped
part is reported; report and parser agree. Validation: the warnings, with
controls. Handlers: the renderer, the listing, the `get_node_io` block, and
the tool descriptions.
