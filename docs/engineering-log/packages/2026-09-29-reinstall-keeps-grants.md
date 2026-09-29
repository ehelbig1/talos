# 2026-09-29 — a catalog reinstall silently widened an operator's grants

**Found** while designing the catalog-drift report, whose remedy is
"reinstall". `install_module_from_catalog` lands a reinstall on the existing
`(user_id, name)` row and overwrote all three grant columns with the
template's grant: hosts from the manifest, methods from manifest ∪ caller,
secrets from the manifest. So every narrowing an operator made with
`update_module_hosts`, `update_module_methods` or `update_module_secrets` was
undone by a plain reinstall, and the tool's own description said the opposite
("If a reinstall omits this parameter, the stored list is preserved").

**Live, not latent.** Of the 8 installed catalog copies on the reference
fleet, three Gmail copies carry narrowed secret grants: two pinned to one
account's access token, List Messages scoped to `oauth/gmail` (backing 8
active workflows). The template grants `oauth/gmail/*`. The next reinstall of
any of them would have widened it.

**Decided.**
- **One rule, `grants_for_install`.** A first install is unchanged. On a
  REINSTALL each grant the caller does not pass is the installed copy's
  stored grant, bounded by the new template's grant: never wider than either.
  A grant the caller passes explicitly keeps today's rule. Hosts have no
  caller parameter, so they are always carried.
- **Bounded, not verbatim.** A stored entry the new template no longer grants
  is DROPPED and reported in `grants_not_carried`. Keeping it verbatim would
  let a template that removed a host or path (a security fix) be overridden by
  an old copy; the template author's grant is the only review those entries
  had, the same principle the 2026-09-10 secret-narrowing change used.
- **One matcher per grant.** Hosts use the worker's own
  `host_allowlist_match`, now `pub` and re-exported from
  `talos_worker_runtime::host`, so the controller does not grow a second host
  rule. Secrets use `narrow_secret_grant` / `vault_path_permitted`. Methods
  compare case-insensitively.
- **Unreadable is a refusal.** `ModuleRepository::get_user_module_grants` is
  three-valued; on `Err` the reinstall is refused, because proceeding is the
  widening.
- The response gains `grants_carried_from_installed_copy` and
  `grants_not_carried`. The tool description is corrected, including an older
  error: it described caller secrets as MERGED (union) with `['*']` meaning
  every secret and `[]` not deny-all. Since 2026-09-10 a caller can only
  narrow, `['*']` is the template's own list, and `[]` is deny-all.

**Proof.** Unit tests: a first install is unchanged; a plain reinstall keeps
every narrowing (the live Gmail shape); an explicit parameter wins and dropped
entries are reported; host, method and secret carry rules case by case. A
textual pin (`talos-mcp-handlers/src/install_grants_pin.rs`) holds the call
site: the handler reads the installed copy, refuses on `Err`, passes the copy
(not `None`) to the rule, and writes the rule's result. `talos-mcp-handlers`:
666 passed. **Mutations: 6 applied, 6 caught** (the rule writing the template
grant; the handler passing `None`; `Err` proceeding; host carry admitting
anything; secret narrowing arguments swapped; method carry keeping every verb).

**Stated limits.**
- The pin is TEXTUAL: driving the handler needs the catalog compiler.
- Read-then-write is not atomic: an `update_module_*` call landing between the
  read and the install's write is overwritten by the carried grant.
- A deliberate operator WIDENING beyond the template (e.g. an extra host) is
  dropped on reinstall and reported, not kept. That is the fail-closed
  direction; the operator re-applies it with `update_module_hosts`.
- Other writers of module rows from templates (GraphQL
  `createModuleFromTemplate`, `compile_template`, marketplace install) create
  new rows and do not reinstall over one; not changed.
