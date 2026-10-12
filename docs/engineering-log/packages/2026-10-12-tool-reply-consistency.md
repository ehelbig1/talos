# Three tool replies that cost a second call each (2026-10-12)

## `update_node_config` always answers with a JSON block

It answered in prose, with a JSON block only for `update_config` (its
`dropped_keys`) or when a warning fired. Most write tools answer in JSON.
Every action now carries `{updated, workflow_id, action, node_id?}` beside
the prose, with the action's own fields laid over it, so `dropped_keys`,
`warning` and `secret_access_blocked` are where they were. `remove_node`,
which returned early with prose only, carries `removed_edges` and
`reconnected`. The prose is unchanged.

**Not done:** dropping the prose. Readers of `content[0]` see what they saw.

## `get_node_output` on a run with no stored output says why

It said "Execution has no output data yet" whatever the status. For a
FAILED run that is wrong twice: nothing is still to come, and what the
caller needs is the error. It now says the run failed, that a failed run
records its error instead of node outputs, and names
`get_execution_status(…, detail: true)`. Running, queued, waiting and
cancelled runs each get their own sentence. No error text is repeated in
the reply.

## `add_node_to_workflow`: both fuel figures are explained

`applied_max_fuel` is the MODULE row's default; `configured_max_fuel` is
this node's (its `config.max_fuel` override when set). The 2026-07-26 change
already reported both and explained `configured_max_fuel`. The figure a
caller trips on, `applied_max_fuel`, had no note: it now has
`applied_max_fuel_note`, saying it is the module's default, is what
`get_module_info` shows, and is expected to differ from the node's figure.

## Tests

`update_node_config_block_tests` (the base, an action's own fields kept, an
action with no node) and `no_node_output_message_tests` (a failed run is not
described as unfinished; each status has its sentence).

## Stated limits

The handlers are not driven end to end; the functions that build these
replies are.
