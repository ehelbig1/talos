A node that forwards its parent's output is not failed by what it forwards.
An `action_links` node downstream of a node that failed under
`continue_on_error` returned that node's `__error` envelope as its own
output, was routed as a failure, and failed the run with the parent's error
text. Its output is now committed and its successors released as for any
committed output (conditional edges are evaluated against the forwarded
envelope). A run that fails downstream of a node that had already failed
names that node: `node 'gate' failed: … (already failed upstream: fetch)`.
A failure message with no failed ancestor is unchanged.
