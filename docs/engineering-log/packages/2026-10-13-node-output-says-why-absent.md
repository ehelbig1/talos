# `get_node_output`: a node that did not run is not a node that does not exist

2026-10-13

## What was wrong

`get_node_output` for a node skipped by a false edge condition answered
"Node 'send2' not found in execution output", the answer it gives for an id
that is in no graph. The operator could not tell a typo from a branch that
was not taken.

The wording observed on the running stack ("Resolved node labels available:
[…]") is from before PR #1254, which changed the list to "Nodes with a
stored output" and added the sentence for a failed run. That change did not
say which of the two cases it was; this one does.

## Decided

When no output is found, the tool now answers two questions it could
already answer and did not (`classify_absent_node`, `absent_node_opening`):

1. **Is the node in the workflow's graph?** By id or by `data.label`. If
   not: "NOT IN THE WORKFLOW'S GRAPH".
2. **If it is, what does this execution show?** One bounded read of the
   node's events, then the stored outputs:
   * a `node_skipped` event: its skip condition was true;
   * a `node_failed` event: it ran and failed, and a failed node stores no
     output;
   * no event: it did not run. For each edge into it (at most six, the rest
     counted): the edge's condition, and whether the node it comes from has
     a stored output. A source that ran with a condition on the edge means
     the condition was false on its output; an entry for this target in the
     source's `__edge_condition_errors__` means the condition could not be
     evaluated, and the evaluator's message is quoted; a source with no
     output did not run either.

**Read, not guessed.** Each sentence states something a stored row shows. A
false condition leaves no record of its own, so "the condition was false" is
said only when the source ran, the edge has a condition and no evaluation
error was recorded for it. When the node's events cannot be read the message
says only what the outputs and the graph show.

**The redaction note was already conditional.** The brief asked that the
paragraph beginning "Values shown as [REDACTED:…]" be emitted only when the
reply contains a marker. It is: `append_redaction_notice` adds it only when
a text block of the reply contains `[REDACTED:`, and
`a_result_showing_a_dlp_marker_gets_the_redaction_notice_once` pins the
control (no marker, no notice). Checked on a running stack: of seven
`get_execution_status` replies, the one that carried the note was the one
holding a marker (`[REDACTED:EMAIL]`), and the six without a marker carried
none. Nothing was changed.

## Deliberately NOT done

* **The graph is the workflow's graph as stored now**, not the version the
  execution ran (`workflow_executions.workflow_version_id` is on the row).
  The tool has always resolved names against the current graph; the message
  now says so. Reading the pinned version is a separate change.
* **`get_sub_workflow_output` keeps its own older wording** ("Available
  nodes: […]").
* **No new record is written by the engine.** The two skips that leave no
  event (no active input after a false condition; an error-pattern mismatch)
  are inferred from what is stored, as above.
* **The redaction note does not say which node holds the marker.**

## Tests

`talos-mcp-handlers` `node_not_in_output_message_tests` (+3): a node that
did not run against a node that is not in the graph; each finding (upstream
did not run, a plain edge whose source ran, a recorded evaluation error, a
skip event, a failure event, a label that resolves to its node); a graph
that cannot be read claims nothing, and incoming edges are bounded.

## Stated limits

* An archived execution's events are gone, so for one the message falls back
  to what the outputs and the graph show.
* A node removed from the graph after the execution ran reads as "not in the
  graph", with the caveat above in the sentence.

## One home

`talos_mcp_handlers::executions::{classify_absent_node, absent_node_opening}`.
