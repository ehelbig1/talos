# Tool search and argument warnings cover every tool

2026-10-03

## Why

Found while removing the catalog shortcuts from `tools/list`. The crate kept
several separate lists of its tool domains. Two had fallen behind:

* `tool_search` indexed 16 of the 21 domains. The 36 tools of the other
  five — machine learning (20), Ollama (5), ops alerts (5), the knowledge
  graph (4), evaluation (2) — could not be found. Checked on the reference
  deployment: searching `ml_predict` returned `set_speculative_prefetch`,
  `ollama` did not return `ollama_list_models`, `graph_query` was not found.
  The server instructions and the unknown-tool refusal both send a caller to
  `tool_search`.
* The argument-warning indexes (`tool_arg_index`, `tool_arg_types`) covered
  18 domains. A misspelt or mistyped argument to any of 27 tools (machine
  learning, ops alerts, evaluation) drew no warning.

Population: 36 and 27 of 358 static tools.

## What changed

`tool_hints::all_static_tools()` is the one flat list — the registry
`tools/list` already serves, which a test holds equal to the modules on
disk. `tool_search` and both argument indexes read it. The search's ranking
moved into `rank_tools`, unchanged, so it can be tested without a request.

## Behaviour changes, stated

* `tool_search` can return the 36 tools it could not. Ranking is by score,
  then name, as before; the order of the index never affected it.
* A call to one of the 27 tools with an undeclared or mistyped argument now
  carries the warning every other tool's call carries.

## Tests

* Every listed tool is found by searching its own name (358 of 358).
* The five domains, each by a word a caller would use.
* The argument index agrees with the listed schemas for every tool.
* All three fail when a domain is left out of the list.

## Not changed, recorded

* `static_tool_count()` keeps its own independent sum on purpose: a test
  compares it with the registry, and a pin derived from the pinned value
  proves nothing.
* A query with an underscore is searched word by word, so the exact name of
  a multi-word tool scores no higher than other tools sharing its words, and
  ties are broken by name. `ml_predict` is found; it is not guaranteed first.
