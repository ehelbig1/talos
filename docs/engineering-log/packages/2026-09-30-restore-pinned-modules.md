# 2026-09-30 — `restore_pinned_modules` could not restore a pin

**Found** in the 2026-09-29 catalog code survey and confirmed in the code. When
the registry's eviction sweep NULLs a pinned module's bytes, `session_start`
reports `restore_needed` and names `restore_pinned_modules`. That tool:

1. **Looked up the template by the pin's DISPLAY name**, joined straight onto
   the catalog path (`module-templates/LLM Inference`), a directory that
   exists for no template. Every restore of a catalog module whose display
   name is not its directory name failed, with the misleading reason
   "template.rs not found in catalog — module may have been removed".
2. **Joined a caller-supplied string onto a filesystem path.** A pin stores
   the name the install used, and `install_module_from_catalog` accepts a
   caller `display_name`.
3. **Wrote the bytes without their hash.** The writer set `wasm_bytes` and
   `size_bytes` by name but left `content_hash` describing the bytes the row
   used to hold. A module too large to embed is dispatched by reference and
   the worker verifies it against that hash.
4. **Rebuilt from the CURRENT template regardless of the copy.** A copy behind
   the catalog, or edited in place, would have been silently replaced by
   different code under the same module id.

**Latent here:** 0 rows evicted. Two pins exist (LLM Inference and
Gmail: List Messages), backing 22 active workflows.

**Decided.**
- **One resolver**, `resolve_catalog_template_dir`, shared with
  `install_module_from_catalog`. It tries an exact directory only for a safe
  single-component key (ASCII alphanumerics and hyphens), then matches the
  catalog's own directories by `display_name` slug. A key is never used to
  build any other path.
- **The copy is resolved first** (`ModuleRepository::get_pinned_restore_target`,
  user-scoped): its id, catalog slug and stored source. The template is found
  by the slug, falling back to the name.
- **Restore rebuilds only an unchanged copy.** `rebuildable_template` consumes
  the template and returns it only when its source is byte-identical to the
  copy's, so the compile can only use a template that passed the check. A copy
  that differs is refused with the two real remedies: reinstall (grants kept,
  #989) or `hot_update_module`.
- **The write** is `restore_missing_module_wasm`: keyed by id AND owner, sets
  bytes, `content_hash`, size and `compiled_at`, and fills only MISSING bytes,
  so a restore racing a reinstall cannot overwrite fresher ones. The
  `modules_clear_wasm_evicted_at` trigger clears the eviction marker. The
  name-keyed `update_template_precompiled_wasm` is deleted, and its tenancy
  tests are carried to the new writer.
- **One hash function**, `catalog_wasm_content_hash`, for install and restore.

**Proof.**
- Resolver unit tests: a slug and a display name resolve to the same
  template; `../outside`, `..`, `a/b`, `/etc` and names of directories outside
  the catalog never resolve.
- A unit test of the source gate: behind and edited copies are refused.
- DB tests on a disposable Postgres: another tenant's module id and the shared
  catalog row are never written; the owner's evicted row is restored with the
  new hash; present bytes are never overwritten.
- A textual call-site pin covers the order read, resolve, gate, compile, write,
  and forbids joining onto the catalog path.
- `talos-mcp-handlers`: 675 passed.
- **Mutations: 6 applied, 6 caught.** Two survived first and their tests were
  fixed: a hash test seeded with no previous hash, and a textual pin that
  cannot see `if false &&`. The latter is why the gate became a consuming
  function.

**Stated limits.**
- The handler is not driven end to end: that needs the catalog compiler.
- Restore still reads the catalog from the baked disk directory, as install
  does; in OCI mode the disk may differ from the DB catalog.
