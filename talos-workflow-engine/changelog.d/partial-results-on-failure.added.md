A run that does not complete leaves the outputs of the nodes that did.
`ParallelWorkflowEngine::take_partial_results` returns, once, what the
scheduler's results map held when a run failed, timed out or was cancelled,
scrubbed by the same two passes a completed run's results pass. Until now
every such exit dropped the map and the caller had only the error text. A run
that completes or pauses leaves nothing to take.
