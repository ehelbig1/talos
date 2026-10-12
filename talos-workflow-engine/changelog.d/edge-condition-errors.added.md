An edge whose condition could not be evaluated is recorded. Such an edge is
still not taken, as before; the engine now writes
`__edge_condition_errors__: [{target, condition, error}]` on the SOURCE
node's output (set when an edge errored, removed otherwise, never inherited
from module output), so a branch that silently never fires can be told from a
condition that was false. `reserved_keys::EDGE_CONDITION_ERRORS` and
`apply_edge_condition_errors` in `talos-workflow-engine-core`.
