# 2026-10-01 — authoring tools: a wrongly typed argument is named, and the secrets step lists only what is missing

Two findings from building a workflow through the MCP tools.

**1. A declared argument passed as the wrong JSON type was read as absent.**
`add_collect_node(connect_to: ["prepare"])` — an array where the schema
declares a string — answered success with `"downstream": null` and wired no
edge; the workflow validated with an extra root node. Handlers read an
argument as its declared type (`.as_str()`, `.as_u64()`), so any other type is
"not supplied". The existing unknown-argument warning covers a misspelled
NAME; nothing covered a wrong TYPE.

Now `utils::mistyped_argument_warning`, applied at the one `tools/call`
dispatch beside the unknown-argument check: for every supplied argument whose
schema declares a `type`, a value of another JSON type appends a warning
naming the argument, the declared type and the type received. The index
(`tool_arg_types`) is built from the same static schemas as the unknown-name
index.

**Decisions.**
* **Warn, do not reject** — the same call the unknown-argument check made.
  Some handlers deliberately accept more than their schema says; rejecting
  would break callers that work today. The warning says the value is
  "usually treated as absent" and to check the result, not that it was ignored.
* **Nothing is claimed about an argument with no declared `type`**
  (`connect_from` takes a string or an array), about `null`, or about the
  dynamic catalog-template tools.
* **Names and types only**, never values, in the warning and in the log line.
* **`connect_to` itself is unchanged** (still one string).

**Not measured.** How often live callers pass a mistyped argument: there is
no per-argument record of past calls. The index holds 400+ typed arguments
across 100+ tools (pinned by a floor so an empty index cannot pass quietly).

**2. `create_workflow` told the caller to provision secrets that were already
stored.** Its "Provision secrets" step listed every grant the workflow's
modules declare, and `ready_to_run` was false whenever any module declared
one. Now the handler reads the caller's secret KEY PATHS (names only) and
`missing_secret_grants` keeps the grants no stored path satisfies, judged by
the one grant matcher `vault_path_permitted` (exact, prefix and glob entries).
The step lists only those; with none missing there is no step and the
workflow can be `ready_to_run`. The reply gains `missing_secrets`.

* **Three-valued.** If the key paths cannot be read, `missing_secrets` is
  `null`, the step is "Check and provision secrets" over every declared grant,
  and `ready_to_run` stays false. A failed read is never "all present" or
  "all missing".
* `required_secrets` keeps its meaning (the grants the modules declare).

Also: the `nodes` description of `create_workflow` now says a node takes
`module_id` OR `node_type`.

**Not changed.** `instantiate_workflow_pattern` has its own copy of the
secrets step and still lists every declared grant.

**Guards.** `mistyped_argument_tests` (the observed call, four controls,
numbers, stable ordering, index floor); `missing_secret_grants` and the three
states of the secrets step in `talos-workflow-creation-helpers`.

**Stated limit.** The handler's read of the key paths and its hand-off to the
response builder are not driven by a test (the handler needs a database and a
module); the pure pieces on either side are.
