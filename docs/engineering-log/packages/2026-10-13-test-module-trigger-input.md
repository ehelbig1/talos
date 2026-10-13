# `test_module` takes the run's trigger as an argument (2026-10-13)

A module that reads `__trigger_input__` could be rehearsed only by passing
`input: {"__trigger_input__": {…}}`. It worked because `input`'s keys are
spread at the payload root. It was undocumented, and it sat beside the rule
that the engine writes that key itself and removes any copy that arrives
inside caller or upstream data.

## Decided

* **A `trigger_input` argument**, placed where the engine places it: the root
  `__trigger_input__`, set-or-REMOVE, in the one payload shaper every
  rehearsal uses (`talos_worker_runtime::rehearsal::node_payload`). An
  object, at most 1 MB: the same rule as `accumulated`, read by the same
  function (`engine_key_argument`).
* **`__trigger_input__` at the top level of `input` or `config` is REFUSED**,
  before anything runs, with a message that names the argument.
  * Why not accept it: there would be two ways to supply an engine-written
    key, and only one of them is where the engine puts it. A workflow run
    strips a copy that arrives inside upstream data; a rehearsal that keeps
    it rehearses something production never does.
  * Why refused and not silently removed: removal alone would run the module
    with no trigger and leave the caller to find out why. `__accumulated__`
    inside `input` IS removed without a word today; that was left as it is.
* **The engine's other input keys are not removed from `input`**:
  `__staleness__`, `__degraded_inputs__`, `__actor_context__`. A composer
  that surfaces "this data is stale" or "a source failed" can only be
  rehearsed if the caller can hand it that report, and `test_module` has no
  argument for them. Stated in the tool description. In a workflow run only
  the engine can set them; that is unchanged.

## Measured

Who passed the trigger through `input`: the catalog's recorded fixtures
(`module-templates/*/fixtures`), none; the workflow repository's rehearsal
scripts, none (its module tests call the module's own `run` with the key at
the root, which is unaffected). The use that was reported was by hand.

## GraphQL `testModule`

Not mirrored. It does not share the payload shaper: it takes one `input`
string and builds its own payload, with no `config` or `accumulated`
argument either. Giving it the shaper is a separate change.

## Tests

`talos-mcp-handlers` `rehearsal_tool_tests` (+4): the trigger lands at the
root and nowhere else, and is absent without the argument; a same-named key
inside `input` or `config` never becomes the engine key; the refusal names
the place and the argument, and a nested or differently named key is
ordinary data; both engine-key arguments are objects of at most 1 MB. The
existing `accumulated` tests pass unchanged apart from the extra argument.

Not driven end to end: a real module run through the handler.

## Stated limits

* The wording of the `accumulated` type error changed slightly: the purpose
  is now in brackets.
* `run_sandbox` has no `trigger_input` argument.
