//! Catalog-template registration hygiene: slug-idempotent upsert, whole-
//! template WASM refresh (all "twins"), and a read-only duplicate reconciler.
//!
//! Three defects hit live on 2026-07-21 motivated this module:
//!
//! 1. **Duplicate catalog rows.** `modules` enforces uniqueness on the
//!    *mutable* display `name` (`modules_catalog_name_uniq` on `name WHERE
//!    user_id IS NULL`), NOT on the stable `catalog_slug` template identity.
//!    A template whose `display_name` changes between image builds gets a
//!    NEW row under the new name while the old row is orphaned — a "twin".
//!    Workflow nodes reference a module by UUID, so a node pinned to the
//!    stale twin keeps running OLD WASM after a template update. The boot
//!    recompile sweep only refreshed the ONE row it just upserted, so the
//!    twin never got new code.
//!
//! 2. **Metadata-only rows.** The disk seed only recompiled `wasm_bytes`
//!    when the source *changed* against a prior row, so a first-ever seed
//!    left `wasm_bytes = NULL` permanently — advertised as a `*-v1` tool
//!    but failing at execution with "Module not found".
//!
//! The safe fixes (no user-data-destructive migration):
//! - [`upsert_catalog_template_by_slug`] keys on `catalog_slug` so a rename
//!   updates the existing row instead of minting a twin (prevents NEW twins).
//! - [`needs_recompile`] recompiles when the source changed, the declared
//!   `dependencies` changed, **or** the row has no WASM yet (the last fixes
//!   the metadata-only first-seed row).
//! - [`refresh_catalog_wasm_by_slug`] writes the freshly compiled bytes to
//!   EVERY row sharing the slug, so any existing stale twin also gets new
//!   code (the safe alternative to rewriting workflow graph_json).
//! - [`reconcile_duplicate_catalog_modules`] logs a WARN naming each dupe
//!   set and the workflows referencing a stale twin — diagnostic only, it
//!   never rewrites user data.

use anyhow::Result;
use sqlx::{Pool, Postgres, Row};
use uuid::Uuid;

/// Decide whether a catalog row's WASM must be (re)compiled.
///
/// `true` when the on-disk source differs from the stored `source_code`
/// (a genuine template update) OR when the row has no compiled WASM yet
/// (`has_wasm == false`) — the latter is the metadata-only first-seed case
/// that previously slipped through because there was no "prior" row to
/// diff against — OR when the template's declared `dependencies` changed.
///
/// The dependency arm was added 2026-08-11 alongside the fix that made the
/// disk-seeding path forward `talos.json`'s `dependencies` at all. Without
/// it, editing only the manifest (adding a crate a future `template.rs`
/// edit will need, or REMOVING one that is no longer used) leaves the
/// previously compiled WASM in place, so the declared dependency set and
/// the shipped binary silently disagree until some unrelated source edit
/// happens to trigger a rebuild.
///
/// Pure so it is unit-testable without a database.
pub fn needs_recompile(source_changed: bool, has_wasm: bool, deps_changed: bool) -> bool {
    source_changed || deps_changed || !has_wasm
}

/// Outcome of [`upsert_catalog_template_by_slug`].
#[derive(Debug, Clone)]
pub struct RegisteredCatalog {
    /// The canonical row id for this template identity (slug) + catalog scope.
    pub id: Uuid,
    /// Whether the WASM should be (re)compiled after this upsert
    /// (`needs_recompile(source_changed, had_wasm, deps_changed)`).
    pub needs_recompile: bool,
}

/// A compact projection of a catalog module row, for duplicate detection.
#[derive(Debug, Clone)]
pub struct CatalogRowSummary {
    pub id: Uuid,
    pub name: String,
    pub catalog_slug: Option<String>,
    pub user_id: Option<Uuid>,
    pub has_wasm: bool,
    pub compiled_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A set of module rows that share one template identity within one scope —
/// i.e. duplicate "twins". `survivor` is the row a reconciler would keep
/// (newest compiled, WASM-bearing preferred); `stale` are the twins whose
/// references run old code.
#[derive(Debug, Clone)]
pub struct DuplicateSet {
    /// The grouping key: `Some(slug)` when the rows carry a `catalog_slug`,
    /// else the shared display name.
    pub key: String,
    pub survivor: CatalogRowSummary,
    pub stale: Vec<CatalogRowSummary>,
}

/// Group catalog rows into duplicate sets. Rows are grouped by
/// `(catalog_slug OR name, scope)` where scope distinguishes the shared
/// catalog scope (`user_id IS NULL`) from each per-user install — twins are
/// only merged WITHIN a scope, never across tenants. Only sets with more
/// than one row are returned.
///
/// The survivor is chosen as: a WASM-bearing row over a metadata-only one,
/// then the most recently compiled, then (stably) the smallest id. Pure so
/// the grouping + survivor policy is unit-testable without a database.
pub fn find_duplicate_catalog_sets(rows: Vec<CatalogRowSummary>) -> Vec<DuplicateSet> {
    use std::collections::BTreeMap;

    // Group key: (identity, scope). Identity prefers the stable slug and
    // falls back to name for legacy NULL-slug rows. Scope is the user_id
    // (None = shared catalog scope).
    let mut groups: BTreeMap<(String, Option<Uuid>), Vec<CatalogRowSummary>> = BTreeMap::new();
    for row in rows {
        let identity = row
            .catalog_slug
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| row.name.clone());
        groups.entry((identity, row.user_id)).or_default().push(row);
    }

    let mut sets = Vec::new();
    for ((identity, _scope), mut members) in groups {
        if members.len() < 2 {
            continue;
        }
        // Best survivor first: WASM present, then newest compiled_at, then
        // smallest id for stable tie-breaking.
        members.sort_by(|a, b| {
            b.has_wasm
                .cmp(&a.has_wasm)
                .then(b.compiled_at.cmp(&a.compiled_at))
                .then(a.id.cmp(&b.id))
        });
        let survivor = members.remove(0);
        sets.push(DuplicateSet {
            key: identity,
            survivor,
            stale: members,
        });
    }
    sets
}

/// HTTP verbs accepted in a template manifest's `allowed_methods`.
///
/// Kept in lockstep with the MCP `update_module_methods` validator
/// (`talos-mcp-handlers/src/sandbox.rs`) so a verb an operator can set on a user
/// module is also one a template manifest can declare. `HEAD` / `OPTIONS` are
/// accepted for parity even though `wit_http::Method` cannot express them —
/// listing an inexpressible verb is inert, whereas rejecting one an operator
/// legitimately writes would fail the seed.
const HTTP_VERBS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/// Read + normalise a template manifest's `allowed_methods` into the value bound
/// to [`CatalogUpsert::allowed_methods`].
///
/// Returns an EMPTY vec when the field is absent, is not an array, or contains
/// nothing recognisable — which reproduces the pre-2026-08-25 behaviour exactly,
/// because the column is then written as `{}` (the worker's "allow every verb").
///
/// **Unknown verbs are dropped, not fatal.** This is the opposite of the
/// `allowed_hosts` / `allowed_secrets` manifest handling, which skips the whole
/// template on a validation failure, and the asymmetry is deliberate: a
/// malformed host/secret entry WIDENS what a module may reach, so failing the
/// seed closed is right. A junk verb here can only ever fail to match at the
/// enforcement point, so dropping it is the conservative direction — and keeping
/// the template seeded means one typo cannot silently remove a module the fleet
/// depends on.
#[must_use]
pub fn parse_manifest_allowed_methods(manifest: &serde_json::Value) -> Vec<String> {
    manifest
        .get("allowed_methods")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| {
                    let upper = s.trim().to_ascii_uppercase();
                    HTTP_VERBS.contains(&upper.as_str()).then_some(upper)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parameters for [`upsert_catalog_template_by_slug`]. Mirrors the columns
/// the disk seed writes.
pub struct CatalogUpsert<'a> {
    pub name: &'a str,
    pub category: &'a str,
    pub description: &'a str,
    pub config_schema: &'a serde_json::Value,
    pub source_code: &'a str,
    pub allowed_hosts: &'a [String],
    /// HTTP verb allowlist, straight from the template manifest's
    /// `allowed_methods`.
    ///
    /// Before 2026-08-25 this struct had no such field, so the disk/OCI seed
    /// never wrote `modules.allowed_methods` for a shared catalog row — every
    /// catalog row sat permanently at the column default `{}`. At the worker's
    /// three enforcement points (`host/http.rs` `fetch` / `fetch_all`,
    /// `host/graphql.rs`) an EMPTY list means **allow every verb**, so a catalog
    /// row could issue any method regardless of what its template does. Catalog
    /// rows ARE dispatched directly by workflow nodes, not only via user copies:
    /// the shipped HTML-email sender is referenced by six enabled workflows and
    /// has no user copy at all. The sibling user-copy path
    /// (`install_catalog_module_to_modules`) already bound the column, which is
    /// why a user copy of a slug carried a correct list while the shared row for
    /// the SAME slug did not.
    ///
    /// An empty slice keeps the pre-fix behaviour byte-for-byte — the column is
    /// written as `{}`, exactly what it already held.
    pub allowed_methods: &'a [String],
    pub allowed_secrets: &'a [String],
    pub requires_approval_for: &'a [String],
    pub capability_world_long: &'a str,
    pub catalog_slug: &'a str,
    /// The template's declared extra crate dependencies, straight from
    /// `talos_compilation::CatalogTemplate::dependencies`.
    ///
    /// Persisted into `modules.dependencies` so the OTHER compile path that
    /// reads that column — `compile_template`, which instantiates a catalog
    /// template into a user module — gets the same crates the seeder used.
    /// The column was never written for catalog rows before 2026-08-11 (all
    /// 75 shipped rows had `dependencies IS NULL`), which made
    /// `compile_template` a fifth way to lose them.
    pub dependencies: Option<&'a serde_json::Value>,
}

/// Idempotently register a disk/OCI catalog template into the `modules`
/// table, keyed on the **stable `catalog_slug`** rather than the mutable
/// display `name`.
///
/// When a catalog row already exists for this slug (in the shared
/// `user_id IS NULL` scope) it is UPDATEd in place — including a renamed
/// `name` — so a display-name change never mints a twin. When no slug match
/// exists (fresh template, or a legacy row that predates `catalog_slug`) we
/// fall back to the name-keyed upsert, which also backfills the slug.
///
/// Returns the canonical row id and whether a (re)compile is needed
/// (source changed, or the row still has no WASM).
pub async fn upsert_catalog_template_by_slug(
    pool: &Pool<Postgres>,
    params: CatalogUpsert<'_>,
) -> Result<RegisteredCatalog> {
    // Look up the existing canonical row by slug (shared catalog scope).
    let existing = sqlx::query(
        "SELECT id, source_code, dependencies, (wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0) AS has_wasm \
         FROM modules \
         WHERE catalog_slug = $1 AND user_id IS NULL \
         ORDER BY compiled_at DESC NULLS LAST, id ASC \
         LIMIT 1",
    )
    .bind(params.catalog_slug)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = existing {
        let id: Uuid = row.try_get("id")?;
        let prev_source: Option<String> = row.try_get("source_code")?;
        let prev_deps: Option<serde_json::Value> = row.try_get("dependencies")?;
        let has_wasm: bool = row.try_get::<Option<bool>, _>("has_wasm")?.unwrap_or(false);
        let source_changed = prev_source.as_deref() != Some(params.source_code);
        let deps_changed = prev_deps.as_ref() != params.dependencies;

        // Rename-safe in-place update keyed on the canonical id.
        sqlx::query(
            "UPDATE modules SET \
                 name = $2, category = $3, description = $4, config_schema = $5, \
                 source_code = $6, allowed_hosts = $7, allowed_secrets = $8, \
                 requires_approval_for = $9, capability_world = $10, \
                 dependencies = $11, allowed_methods = $12 \
             WHERE id = $1",
        )
        .bind(id)
        .bind(params.name)
        .bind(params.category)
        .bind(params.description)
        .bind(params.config_schema)
        .bind(params.source_code)
        .bind(params.allowed_hosts)
        .bind(params.allowed_secrets)
        .bind(params.requires_approval_for)
        .bind(params.capability_world_long)
        .bind(params.dependencies)
        .bind(params.allowed_methods)
        .execute(pool)
        .await?;

        return Ok(RegisteredCatalog {
            id,
            needs_recompile: needs_recompile(source_changed, has_wasm, deps_changed),
        });
    }

    // No slug match: name-keyed upsert (fresh template, or legacy NULL-slug
    // row whose slug we now backfill). Capture whether the source differed
    // from any prior same-name row so we recompile only when needed; a
    // brand-new insert has no WASM yet so `needs_recompile` is true anyway.
    let row = sqlx::query(
        "WITH prev AS ( \
             SELECT source_code AS prev_source, dependencies AS prev_deps, \
                    (wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0) AS prev_has_wasm \
             FROM modules WHERE name = $1 AND user_id IS NULL \
         ), upsert AS ( \
             INSERT INTO modules ( \
                 user_id, name, kind, category, description, config_schema, \
                 source_code, allowed_hosts, allowed_secrets, requires_approval_for, \
                 capability_world, catalog_slug, dependencies, allowed_methods, \
                 language, created_at, updated_at \
             ) VALUES ( \
                 NULL, $1, 'catalog', $2, $3, $4, \
                 $5, $6, $7, $8, \
                 $9, $10, $11, $12, 'rust', NOW(), NOW() \
             ) \
             ON CONFLICT (name) WHERE user_id IS NULL DO UPDATE SET \
                 category = EXCLUDED.category, \
                 catalog_slug = EXCLUDED.catalog_slug, \
                 description = EXCLUDED.description, \
                 config_schema = EXCLUDED.config_schema, \
                 source_code = EXCLUDED.source_code, \
                 allowed_hosts = EXCLUDED.allowed_hosts, \
                 allowed_secrets = EXCLUDED.allowed_secrets, \
                 requires_approval_for = EXCLUDED.requires_approval_for, \
                 capability_world = EXCLUDED.capability_world, \
                 dependencies = EXCLUDED.dependencies, \
                 allowed_methods = EXCLUDED.allowed_methods \
             /* updated_at deliberately NOT set — see talos-registry/src/lib.rs. */ \
             RETURNING id, \
                 (wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0) AS has_wasm \
         ) \
         SELECT upsert.id, upsert.has_wasm, \
                prev.prev_source, prev.prev_deps, \
                COALESCE(prev.prev_has_wasm, false) AS prev_has_wasm \
         FROM upsert LEFT JOIN prev ON true",
    )
    .bind(params.name)
    .bind(params.category)
    .bind(params.description)
    .bind(params.config_schema)
    .bind(params.source_code)
    .bind(params.allowed_hosts)
    .bind(params.allowed_secrets)
    .bind(params.requires_approval_for)
    .bind(params.capability_world_long)
    .bind(params.catalog_slug)
    .bind(params.dependencies)
    .bind(params.allowed_methods)
    .fetch_one(pool)
    .await?;

    let id: Uuid = row.try_get("id")?;
    let has_wasm: bool = row.try_get::<Option<bool>, _>("has_wasm")?.unwrap_or(false);
    let prev_source: Option<String> = row.try_get("prev_source")?;
    let prev_deps: Option<serde_json::Value> = row.try_get("prev_deps")?;
    let source_changed = prev_source.as_deref() != Some(params.source_code);
    let deps_changed = prev_deps.as_ref() != params.dependencies;

    Ok(RegisteredCatalog {
        id,
        needs_recompile: needs_recompile(source_changed, has_wasm, deps_changed),
    })
}

/// Write freshly compiled WASM to EVERY catalog-derived row sharing this
/// `catalog_slug` — the shared `user_id IS NULL` row AND every per-user
/// install of the same template. This is the safe fix for stale twins:
/// rather than rewriting workflow graph_json to repoint at a survivor
/// (which touches user data), we keep both twins' code current so a node
/// pinned to either UUID runs the new binary.
///
/// Returns the number of rows updated.
pub async fn refresh_catalog_wasm_by_slug(
    pool: &Pool<Postgres>,
    catalog_slug: &str,
    wasm_bytes: &[u8],
    content_hash: &str,
) -> Result<u64> {
    let res = sqlx::query(
        // Compile outputs only; see store_precompiled_template.
        "UPDATE modules SET \
             wasm_bytes = $2, content_hash = $3, size_bytes = $4, \
             compiled_at = NOW() \
         WHERE catalog_slug = $1 AND kind = 'catalog'",
    )
    .bind(catalog_slug)
    .bind(wasm_bytes)
    .bind(content_hash)
    .bind(wasm_bytes.len() as i32)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Read-only reconciler: identify duplicate catalog-module twins and log a
/// WARN naming each dupe set plus the workflows referencing a stale twin.
///
/// This deliberately does NOT rewrite any workflow `graph_json` — repointing
/// node module ids crosses into user data. Its job is to make the drift
/// visible; [`refresh_catalog_wasm_by_slug`] keeps the twins' code fresh so
/// the drift is not silently harmful in the meantime. Safe to run on every
/// boot / periodic sweep.
pub async fn reconcile_duplicate_catalog_modules(pool: &Pool<Postgres>) -> Result<usize> {
    let rows = sqlx::query(
        "SELECT id, name, catalog_slug, user_id, \
                (wasm_bytes IS NOT NULL AND octet_length(wasm_bytes) > 0) AS has_wasm, \
                compiled_at \
         FROM modules WHERE kind = 'catalog'",
    )
    .fetch_all(pool)
    .await?;

    let summaries: Vec<CatalogRowSummary> = rows
        .into_iter()
        .map(|r| -> Result<CatalogRowSummary> {
            Ok(CatalogRowSummary {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
                catalog_slug: r.try_get::<Option<String>, _>("catalog_slug")?,
                user_id: r.try_get::<Option<Uuid>, _>("user_id")?,
                has_wasm: r.try_get::<Option<bool>, _>("has_wasm")?.unwrap_or(false),
                compiled_at: r
                    .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("compiled_at")?,
            })
        })
        .collect::<Result<_>>()?;

    let dupe_sets = find_duplicate_catalog_sets(summaries);
    if dupe_sets.is_empty() {
        return Ok(0);
    }

    for set in &dupe_sets {
        let stale_ids: Vec<String> = set.stale.iter().map(|r| r.id.to_string()).collect();
        tracing::warn!(
            target: "talos_registry",
            event_kind = "duplicate_catalog_modules",
            template = %set.key,
            survivor_id = %set.survivor.id,
            survivor_name = %set.survivor.name,
            stale_ids = %stale_ids.join(","),
            "duplicate catalog module rows detected — keeping newest-compiled as survivor; \
             stale twins are kept WASM-fresh by the recompile sweep (no graph_json rewrite)"
        );

        // Surface which workflows still reference a stale twin (by UUID in
        // graph_json). Read-only — for operator visibility only.
        for stale in &set.stale {
            let needle = format!("%{}%", stale.id);
            match sqlx::query(
                "SELECT id, name FROM workflows WHERE graph_json::text LIKE $1 LIMIT 20",
            )
            .bind(&needle)
            .fetch_all(pool)
            .await
            {
                Ok(refs) if !refs.is_empty() => {
                    let wf_list: Vec<String> = refs
                        .iter()
                        // NOT NULL projection: `.ok()` could only drop rows on
                        // drift, and under-reporting IS this warning's failure
                        // mode. reconcile_* returns Result, so propagate.
                        .map(|r| r.try_get::<Uuid, _>("id").map(|id| id.to_string()))
                        .collect::<std::result::Result<Vec<String>, _>>()?;
                    tracing::warn!(
                        target: "talos_registry",
                        event_kind = "workflows_referencing_stale_module",
                        template = %set.key,
                        stale_module_id = %stale.id,
                        workflow_ids = %wf_list.join(","),
                        "workflows reference a stale catalog-module twin"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        target: "talos_registry",
                        stale_module_id = %stale.id,
                        error = %e,
                        "failed to scan workflows for stale-module references"
                    );
                }
            }
        }
    }

    Ok(dupe_sets.len())
}

#[cfg(test)]
mod allowed_methods_manifest_tests {
    use super::*;

    /// The load-bearing default. An absent field must produce an EMPTY list,
    /// because that is byte-identical to what every catalog row already holds —
    /// adding the column to the seed must not change a single existing row's
    /// effective policy on the first boot after deploy.
    #[test]
    fn absent_field_yields_empty_which_is_the_pre_fix_value() {
        let m = serde_json::json!({ "name": "x", "allowed_hosts": ["example.com"] });
        assert!(parse_manifest_allowed_methods(&m).is_empty());
    }

    #[test]
    fn non_array_value_yields_empty_rather_than_panicking() {
        for v in [
            serde_json::json!({ "allowed_methods": "GET" }),
            serde_json::json!({ "allowed_methods": 7 }),
            serde_json::json!({ "allowed_methods": null }),
            serde_json::json!({ "allowed_methods": { "GET": true } }),
        ] {
            assert!(parse_manifest_allowed_methods(&v).is_empty(), "{v}");
        }
    }

    #[test]
    fn verbs_are_normalised_to_upper_case_and_trimmed() {
        let m = serde_json::json!({ "allowed_methods": ["get", " Post ", "pAtCh"] });
        assert_eq!(parse_manifest_allowed_methods(&m), ["GET", "POST", "PATCH"]);
    }

    /// An unrecognised entry is DROPPED and its siblings survive. The opposite
    /// choice — skipping the template — would let one typo remove a module the
    /// fleet depends on, and a junk verb can only ever fail to match at the
    /// enforcement point, so it cannot widen anything.
    #[test]
    fn unknown_verb_is_dropped_without_discarding_the_valid_siblings() {
        let m = serde_json::json!({ "allowed_methods": ["GET", "TRACE", "", "POST", 42] });
        assert_eq!(parse_manifest_allowed_methods(&m), ["GET", "POST"]);
    }

    /// A list of ONLY junk collapses to empty — i.e. back to "allow all", not to
    /// an accidental deny-all. Stated as a test because the alternative reading
    /// (empty == deny) is the one every sibling field uses, and this field is
    /// the odd one out.
    #[test]
    fn all_entries_unknown_collapses_to_empty_not_to_deny_all() {
        let m = serde_json::json!({ "allowed_methods": ["TRACE", "CONNECT"] });
        assert!(parse_manifest_allowed_methods(&m).is_empty());
    }

    /// Parity with the MCP `update_module_methods` validator's verb set: a verb
    /// an operator may set on a user module must also be declarable in a
    /// template manifest, or the two surfaces disagree about the same column.
    #[test]
    fn accepts_every_verb_the_mcp_validator_accepts() {
        let all = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
        let m = serde_json::json!({ "allowed_methods": all });
        assert_eq!(parse_manifest_allowed_methods(&m), all);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        id: u128,
        name: &str,
        slug: Option<&str>,
        user: Option<u128>,
        has_wasm: bool,
        compiled_secs: Option<i64>,
    ) -> CatalogRowSummary {
        CatalogRowSummary {
            id: Uuid::from_u128(id),
            name: name.to_string(),
            catalog_slug: slug.map(str::to_string),
            user_id: user.map(Uuid::from_u128),
            has_wasm,
            compiled_at: compiled_secs.map(|s| chrono::DateTime::from_timestamp(s, 0).unwrap()),
        }
    }

    // ── needs_recompile ─────────────────────────────────────────────────

    #[test]
    fn recompiles_when_source_changed() {
        assert!(needs_recompile(true, true, false));
    }

    #[test]
    fn recompiles_when_no_wasm_even_if_source_unchanged() {
        // The metadata-only first-seed case: source "unchanged" (there was
        // no prior row) but the row has no WASM → must compile.
        assert!(needs_recompile(false, false, false));
    }

    #[test]
    fn skips_when_source_unchanged_and_wasm_present() {
        assert!(!needs_recompile(false, true, false));
    }

    /// A manifest-only edit — adding or removing a declared crate without
    /// touching `template.rs` — must rebuild. Before the seeder forwarded
    /// `talos.json` `dependencies` at all this could not matter; now that it
    /// does, skipping here would leave the compiled WASM disagreeing with the
    /// declared dependency set until some unrelated source edit happened to
    /// trigger a rebuild.
    #[test]
    fn recompiles_when_only_dependencies_changed() {
        assert!(needs_recompile(false, true, true));
    }

    // ── find_duplicate_catalog_sets ─────────────────────────────────────

    #[test]
    fn no_dupes_when_each_slug_unique() {
        let rows = vec![
            row(
                1,
                "Alert Normalize (Email)",
                Some("alert-email"),
                None,
                true,
                Some(100),
            ),
            row(
                2,
                "Alert Normalize (GCP)",
                Some("alert-gcp"),
                None,
                true,
                Some(100),
            ),
        ];
        assert!(find_duplicate_catalog_sets(rows).is_empty());
    }

    #[test]
    fn groups_twins_by_slug_and_picks_newest_compiled_survivor() {
        // Same slug, same (catalog) scope, different names (a rename) →
        // one dupe set. Newest compiled_at wins.
        let rows = vec![
            row(
                1,
                "Alert Normalize (Email) OLD",
                Some("alert-email"),
                None,
                true,
                Some(100),
            ),
            row(
                2,
                "Alert Normalize (Email)",
                Some("alert-email"),
                None,
                true,
                Some(200),
            ),
        ];
        let sets = find_duplicate_catalog_sets(rows);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].survivor.id, Uuid::from_u128(2));
        assert_eq!(sets[0].stale.len(), 1);
        assert_eq!(sets[0].stale[0].id, Uuid::from_u128(1));
    }

    #[test]
    fn wasm_bearing_row_wins_over_metadata_only_twin() {
        // A metadata-only twin (no WASM) must never be chosen as survivor,
        // even if it were compiled "later" (NULL compiled_at here).
        let rows = vec![
            row(
                1,
                "Hybrid Classify (Alerts)",
                Some("hybrid-alerts"),
                None,
                false,
                None,
            ),
            row(
                2,
                "Hybrid Classify (Alerts)",
                Some("hybrid-alerts"),
                None,
                true,
                Some(50),
            ),
        ];
        let sets = find_duplicate_catalog_sets(rows);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].survivor.id, Uuid::from_u128(2));
        assert!(sets[0].survivor.has_wasm);
    }

    #[test]
    fn different_scopes_are_not_merged() {
        // Same slug but one shared catalog row and one per-user install —
        // different tenants, so NOT a twin set to merge.
        let rows = vec![
            row(
                1,
                "Alert Normalize (Email)",
                Some("alert-email"),
                None,
                true,
                Some(100),
            ),
            row(
                2,
                "Alert Normalize (Email)",
                Some("alert-email"),
                Some(99),
                true,
                Some(100),
            ),
        ];
        assert!(find_duplicate_catalog_sets(rows).is_empty());
    }

    #[test]
    fn falls_back_to_name_grouping_for_legacy_null_slug_rows() {
        let rows = vec![
            row(1, "Legacy Module", None, None, true, Some(100)),
            row(2, "Legacy Module", None, None, true, Some(200)),
        ];
        let sets = find_duplicate_catalog_sets(rows);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].key, "Legacy Module");
        assert_eq!(sets[0].survivor.id, Uuid::from_u128(2));
    }
}
