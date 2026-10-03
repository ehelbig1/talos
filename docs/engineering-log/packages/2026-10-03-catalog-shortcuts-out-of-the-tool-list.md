# Catalog modules are no longer listed as tools

2026-10-03 (operator decision)

## Why

`tools/list` carried one tool per catalog module, named `<Name>-v1`: an
install shortcut whose input schema was the module's config. Measured on the
reference deployment's live list: 456 tools and 549 KB (about 137,000
tokens); 98 of them were these shortcuts, 166 KB — 30% of the reply, read by
every client at every connect. Two static tools already did the job:
`list_module_catalog` finds a module (and says whether it needs installing at
all), `install_module_from_catalog` installs it, and `get_module_info`
returns its config schema.

Rewording descriptions had been measured first and declined: 23 of 1,890
description strings carried anything removable.

22 of the 98 were not catalog modules: a caller's own modules in a category
other than `sandbox` were listed too, and calling one failed, because the
name mapped to no catalog entry.

## What changed

* `tools/list` is the static tools and nothing else. It no longer reads the
  database or depends on the caller; the reply is built once per process.
* A call to a `<Name>-v1` name is refused (-32601) with the call that
  replaced it: `install_module_from_catalog(name: "<slug>")`. A client
  holding an older tool list learns what to do in one round trip. Nothing is
  installed from that path any more: one route to an install, with its own
  arguments, grants and audit record.
* The process-wide "tool list changed" broadcast is removed, with its five
  senders (module install, delete, bulk delete, rename, hot update). The list
  cannot change while the process runs, and each of those made every
  connected client fetch the whole list again.
* `get_platform_info`: `total_mcp_tools` is the static count;
  `catalog_tool_count` is gone, with the two reads behind it. The report had
  nothing else that could be unmeasured, so its readings ledger went too.
* Server instructions, `get_catalog_status` and the threat model no longer
  describe dynamically registered tools.
* Deleted, having no caller left: `one_row_per_catalog_tool` and
  `NodeTemplateMetadata.shared` (both added earlier the same day to list each
  shortcut once), `utils::sanitize_tool_name`.

## Decisions

* **The by-name route is refused, not kept hidden.** Keeping a route nobody
  can discover would leave a second way to install a module that no list, no
  description and no test names.
* **The metric label `catalog_template` is kept**, now for a refused call to
  a `-v1` name. The name is the caller's own string, so it still must not be
  a label; the series is seeded and read under that value.
* **The three notifications sent after a client connects are kept.** They
  exist so a bridge that caches the tool list fetches it again after a
  deploy, which still changes it.
* **Not done here:** `utils::all_static_tool_schemas` lists 18 of the 21
  tool domains and `tool_search`'s index 16, so argument warnings and tool
  search miss the tools of the domains they leave out. Found while reading
  this code; a separate change, since it is a different defect.

## Limits

* Sizes are from the tool list captured from the reference deployment before
  this change; the static tools were 383 KB of it. Not re-measured on a
  deployed build.
* A client that cached the old list keeps showing the shortcuts until it
  fetches again; calling one gets the refusal.
