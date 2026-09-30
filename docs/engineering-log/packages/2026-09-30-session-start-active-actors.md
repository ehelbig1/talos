# 2026-09-30 — `session_start` listed terminated actors as active

**Found live.** After the catalog cleanup, `session_start` still listed
`probe-750-readonly`, a terminated probe actor, under `active_actors`.
`AdvancedRepository::list_active_actors_with_memory_count` filtered
`status != 'archived'`, so suspended and terminated actors were reported as
active.

**The larger defect behind the label.** The read's `LIMIT 20` applied after
that filter under `ORDER BY created_at DESC`, so suspended or terminated
actors newer than an active one consumed the limit, and enough of them would
push real active actors out of the list entirely. Latent here: this fleet has
6 active, 1 terminated and 4 archived actors.

**Decided.**
- `active_actors` holds `status = 'active'` only; the limit is now spent on
  active actors.
- A new `inactive_actors` field counts `suspended`, `terminated` and
  `archived` (one aggregate statement, `count_actors_by_status`), rendering
  every status in the `actors.status` CHECK set as 0 when absent, and points
  at `list_actors(status: …)`. Suspended actors are counted rather than hidden
  because suspension is reversible and an operator may need to know.
- A failed read renders `null` (unknown), not `[]`, with a WARN. The rest of
  the brief still collapses failed reads to empty values; this package changes
  only the two fields it touches.
- Rendering is two pure functions (`render_active_actors`,
  `inactive_actor_summary`).

**Proof.** A database test on a real clone: one active actor that is OLDER than
25 terminated and 2 suspended actors is still listed, every listed actor is
active, and the counts are exact. The same test fails against the old
`status != 'archived'` filter (the active actor is crowded out). Unit tests
cover both renderers.

**Not changed.** `probe-750-readonly` itself stays: there is no actor-delete
path, and a hand-written `DELETE` would record nothing and cascade away its
audit trail. A recorded `delete_actor` is the follow-up package.
