# Four small tool fixes (2026-10-14)

Item 8 of the 2026-10-14 list: four small items, one change.

## 1. `list_workflows` finds a workflow by name

Finding one workflow by name meant paging the whole list, and a `search`
argument was silently ignored.

* **`name`**: exact and case-sensitive (`w.name = $n`; `idx_workflows_name`
  serves it beside the `user_id` predicate).
* **`name_contains`**: case-insensitive substring, matched with
  `strpos(lower(w.name), lower($n)) > 0` rather than `ILIKE`, so `%` and `_`
  are literal characters and nothing needs escaping.
* Both are parameterized, combine with every other filter, and are counted by
  the same `total`. A wrong type, an empty string or more than 256 characters
  is refused, never read as "no filter" (which would answer with everything).
* **No new index.** Measured on the dev stack: the user has 80 workflows, so
  the substring filter scans 80 rows already narrowed by `user_id`.
* `search` stays undeclared, and so stays reported as ignored.

## 2. An ignored argument in the structured result: already done

The brief said `list_workflows` reported an ignored argument only in a text
block. Since 2026-10-13 (`2026-10-13-ignored-arguments-in-the-result-and-two-doc-rules.md`)
every tool's reply passes through ONE decorator
(`talos-mcp-handlers/src/lib.rs`, `carry_ignored_arguments`), which writes
`ignored_arguments` into every JSON-object text block. `list_workflows`
returns a JSON object, so it is covered. Pinned here by a test that `search`
is reported for `list_workflows` while the two new filters are declared.
Nothing else changed.

## 3. `tool_search` and removing a node

Measured on the live stack first: `tool_search("remove node")` DID return
`update_node_config` (third of ten). Two real defects sat beside it:

* **`update_node_config`'s own description sent a reader away**: "prefer …
  the standalone node delete via workflow graph tools for node removal". No
  such tool exists; its `action: "remove_node"` is the only way to remove a
  node. The description now says so.
* **"delete" and "remove" were different words**: "delete edge" put
  `remove_edge` nowhere near the top (and `update_node_config` 19th).
* **The `relevance` label was read off the summed score**: two words each
  found in a name read `exact_name` (live: `add_action_links_node` for "remove
  node").

Fixed in `rank_tools`:
* a closed synonym pair, `delete` ↔ `remove`, a token scoring as its best
  spelling;
* an identifier bonus: when the query as one identifier (`remove node` →
  `remove_node`, in each spelling, at most 8 variants) IS a tool's name or one
  of its `action` enum values, the tool ranks above every tool that merely
  mentions the words;
* `relevance` is now derived from what matched: `exact_name`, `action_match`,
  `name_match`, `description_match`.

The synonym list is deliberately two words and closed: a list that grows is a
second search engine.

## 4. `get_workflow` vs `export_workflow`

`get_workflow` returns `nodes` and `edges` at the top level (enriched:
`module_name`, …); `export_workflow` returns `{version, name, graph_json,
modules, exported_at}` with the stored graph nested under `graph_json`.
Neither shape is changed (callers exist); both descriptions now state the
difference.

## Tests

* `list_workflows_runs_filter_tests::name_filters_find_one_workflow_by_name`
  (migrated clone): exact, exact is case-sensitive, contains ignores case, `%`
  literal, `_` literal, another user's same-named workflow never returned,
  `total` counts the same filter.
* `talos-mcp-handlers`: the name argument rule; `search` reported and the
  filters declared; both shape sentences present; `tool_search` finds
  `update_node_config` for "remove node", "delete node", "remove a node",
  "remove_node", and `remove_edge` for "remove edge" and "delete edge", in the
  first three (the first version of this test failed at "delete edge",
  position 19, before the fix); `relevance` says what matched.
