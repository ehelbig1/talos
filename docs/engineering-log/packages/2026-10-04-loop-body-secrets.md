# A loop body never received the secrets its config names

2026-10-04

Found by reading the loop's dispatch while designing `for_each_connection`.

## The defect

The loop resolves its body's secrets once, through
`ParallelWorkflowEngine::build_dispatch_secrets(node_id, …)`. That helper
used its one id for two lookups:

* `self.node_configs.get(&node_id)` — keyed by NODE id — to find `vault://`
  references in the node's config;
* `resolver.resolve_module_secrets(node_id)` — keyed by MODULE id.

Its only caller, the loop, passed the body's module id. A module id is not a
key of `node_configs`, so the config lookup returned nothing and no config
reference was ever fetched. The helper also passed an empty grant where the
single-node path passes the module's `allowed_secrets`, so an exact-path
grant delivered nothing either. A loop body that used a credential failed at
the worker with a missing secret.

Population: one helper, one caller. On this fleet 0 of 40 workflows use a
loop node (read-only count, 2026-10-04), so nothing live was failing.

## The fix

The helper takes the node id, the module id and the module's grant, and uses
each where it belongs. The loop passes the body node's id, the body module's
id and the fetched artifact's `allowed_secrets`.

## Test

`tests/loop_body_secrets.rs`: a loop whose body has a `vault://` reference in
its config and an exact-path grant, run with a resolver that records what it
is asked for. The body node also runs once on its own after the loop, and
asks for its secrets then, so a test that only checks "was the path asked
for" passes before the fix. The test counts: two asks per path with the fix
(the loop's and the body's own), one without. Confirmed by restoring the
pre-fix arguments: the test fails, and passes again with the fix.

## Stated limits

The loop's body dispatch is still a hand-built job, separate from the
single-node path. This fixes what it asks the vault for; it does not unify
the two.
