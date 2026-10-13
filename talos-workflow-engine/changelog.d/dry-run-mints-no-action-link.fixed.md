A dry run mints no action link. The `action_links` node consulted the link
minter whatever the engine's dry-run flag said, so a rehearsal's output
carried live single-use links. Under a dry run the node now asks the minter
for nothing: every request falls back and is reported under `not_minted`
with the reason `dry_run` (`action_links::DRY_RUN_REASON` in
`talos-workflow-engine-core`). An ordinary run is unchanged.
