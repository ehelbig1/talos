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
//!   every PRISTINE row sharing the slug (compare-and-set on the shared
//!   build's hash), so a stale twin gets new code while a hot-updated install
//!   keeps the user's bytes.
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
/// nothing recognisable — which reproduced the pre-2026-08-25 behaviour exactly
/// while `{}` meant "allow every verb" at the worker.
///
/// **That is no longer a no-op and the direction has inverted.** Since
/// 2026-09-24 `{}` DENIES every verb
/// (`talos_workflow_job_protocol::method_permitted`), so a manifest whose
/// verbs are all unrecognised seeds a catalog row that can never egress —
/// where before it seeded one that could egress with anything. Measured on
/// the shipped catalog 2026-09-24: **0 of 75** templates declare an
/// unrecognised verb, so the drop-don't-fail rule below is latent; and 4 of
/// 75 declare `allowed_hosts` with no verbs at all, every one of them
/// verified to make no `http::fetch`-family call (three are webhook
/// listeners, one uses raw `wasi:sockets`, which this gate does not cover).
/// Left alone deliberately: tightening those four manifests is a
/// least-privilege review of the catalog, not a carrier fix.
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

/// Where a shared catalog module's code comes from. The two modes are
/// mutually exclusive per deployment (`TALOS_REGISTRY_URL` set or not), and
/// a row says which one wrote it: dispatch prefers `oci_url` when it is set.
#[derive(Debug, Clone, Copy)]
pub enum CatalogSource<'a> {
    /// The disk seed: the template's source, compiled on this controller.
    /// Clears `oci_url`, so a deployment switched back from registry mode
    /// does not keep dispatching to a registry it no longer syncs.
    Disk { source_code: &'a str },
    /// The registry sync: a signed artifact the worker pulls by this
    /// digest-pinned URL. The row's stored source, if any, is left alone.
    Registry { oci_url: &'a str },
}

/// Why a catalog manifest is not written. One list for both writers, so a
/// manifest the disk seed refuses is refused by the registry sync too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestRefusal {
    /// Neither `display_name` nor `name`.
    NoName,
    /// No `capability_world`. A module's world decides which host
    /// interfaces it is linked against; it is declared, never defaulted.
    NoCapabilityWorld,
    /// A `capability_world` no module can be compiled for.
    UnknownCapabilityWorld(String),
    InvalidAllowedHosts(String),
    InvalidAllowedSecrets(String),
}

impl std::fmt::Display for ManifestRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoName => f.write_str("the manifest has no name or display_name"),
            Self::NoCapabilityWorld => f.write_str("the manifest declares no capability_world"),
            Self::UnknownCapabilityWorld(world) => {
                write!(
                    f,
                    "capability_world '{world}' is not a world a module can be compiled for"
                )
            }
            Self::InvalidAllowedHosts(reason) => write!(f, "invalid allowed_hosts: {reason}"),
            Self::InvalidAllowedSecrets(reason) => write!(f, "invalid requires_secrets: {reason}"),
        }
    }
}

/// What a catalog manifest (`talos.json`) says about its module — everything
/// a shared catalog row stores that comes from the manifest.
///
/// The ONE reading of a manifest for both writers of shared catalog rows: the
/// disk seed (`controller::bootstrap::services::seed_templates`) and the
/// registry sync (`talos_registry::sync`). Until 2026-10-03 each parsed the
/// manifest itself, and they had drifted: the registry sync wrote neither
/// `allowed_methods` nor `capability_world` nor `dependencies` nor
/// `max_fuel`, so a row it created kept those columns' defaults — no verb
/// allowed, `minimal-node`, 2,000,000 — and no HTTP template synced from a
/// registry could make a request.
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogManifest {
    pub name: String,
    pub category: String,
    pub description: String,
    pub config_schema: serde_json::Value,
    pub allowed_hosts: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_secrets: Vec<String>,
    pub requires_approval_for: Vec<String>,
    /// Long form (`http-node`), as the worker's parser and the column want.
    pub capability_world_long: String,
    pub dependencies: Option<serde_json::Value>,
    /// See [`CatalogUpsert::max_fuel`]: the recommendation, the column
    /// default when the manifest recommends nothing, `None` when it
    /// recommends something that cannot be read.
    pub max_fuel: Option<i64>,
    /// Why `recommended_fuel` could not be read, for the caller to log.
    pub fuel_unreadable: Option<String>,
}

fn manifest_strings(manifest: &serde_json::Value, key: &str) -> Vec<String> {
    manifest
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

impl CatalogManifest {
    pub fn parse(manifest: &serde_json::Value) -> std::result::Result<Self, ManifestRefusal> {
        let text = |key: &str| manifest.get(key).and_then(|v| v.as_str());
        let name = text("display_name")
            .or_else(|| text("name"))
            .filter(|n| !n.is_empty())
            .ok_or(ManifestRefusal::NoName)?
            .to_string();

        // `trusted` is the historical short spelling of the automation
        // world; any other short form gains its `-node` suffix.
        let declared = text("capability_world")
            .filter(|w| !w.is_empty())
            .ok_or(ManifestRefusal::NoCapabilityWorld)?;
        let capability_world_long = if declared == "trusted" {
            "automation-node".to_string()
        } else if declared.ends_with("-node") {
            declared.to_string()
        } else {
            format!("{declared}-node")
        };
        if !talos_capability_world::is_compilable_world(&capability_world_long) {
            return Err(ManifestRefusal::UnknownCapabilityWorld(
                declared.to_string(),
            ));
        }

        let allowed_hosts = manifest_strings(manifest, "allowed_hosts");
        crate::validate_allowed_hosts(&allowed_hosts)
            .map_err(ManifestRefusal::InvalidAllowedHosts)?;
        let allowed_secrets = manifest_strings(manifest, "requires_secrets");
        crate::validate_allowed_secrets(&allowed_secrets)
            .map_err(ManifestRefusal::InvalidAllowedSecrets)?;

        let (max_fuel, fuel_unreadable) = match talos_compilation::recommended_max_fuel(manifest) {
            Ok(Some(limit)) => (i64::try_from(limit).ok(), None),
            Ok(None) => (Some(SHARED_CATALOG_DEFAULT_MAX_FUEL), None),
            Err(reason) => (None, Some(reason)),
        };

        Ok(Self {
            name,
            category: text("category").unwrap_or("General").to_string(),
            description: text("description").unwrap_or("").to_string(),
            config_schema: manifest
                .get("config_schema")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            allowed_hosts,
            allowed_methods: parse_manifest_allowed_methods(manifest),
            allowed_secrets,
            requires_approval_for: manifest_strings(manifest, "requires_approval_for"),
            capability_world_long,
            dependencies: talos_compilation::manifest_dependencies(manifest).cloned(),
            max_fuel,
            fuel_unreadable,
        })
    }

    /// The row this manifest writes for the template `catalog_slug`, with
    /// its code coming from `source`.
    pub fn upsert<'a>(
        &'a self,
        catalog_slug: &'a str,
        source: CatalogSource<'a>,
    ) -> CatalogUpsert<'a> {
        CatalogUpsert {
            name: &self.name,
            category: &self.category,
            description: &self.description,
            config_schema: &self.config_schema,
            source,
            allowed_hosts: &self.allowed_hosts,
            allowed_methods: &self.allowed_methods,
            allowed_secrets: &self.allowed_secrets,
            requires_approval_for: &self.requires_approval_for,
            capability_world_long: &self.capability_world_long,
            catalog_slug,
            dependencies: self.dependencies.as_ref(),
            max_fuel: self.max_fuel,
        }
    }
}

/// Parameters for [`upsert_catalog_template_by_slug`]. Mirrors the columns
/// the disk seed writes.
pub struct CatalogUpsert<'a> {
    pub name: &'a str,
    pub category: &'a str,
    pub description: &'a str,
    pub config_schema: &'a serde_json::Value,
    /// Where the module's code comes from; see [`CatalogSource`].
    pub source: CatalogSource<'a>,
    pub allowed_hosts: &'a [String],
    /// HTTP verb allowlist, straight from the template manifest's
    /// `allowed_methods`.
    ///
    /// Before 2026-08-25 this struct had no such field, so the disk/OCI seed
    /// never wrote `modules.allowed_methods` for a shared catalog row — every
    /// catalog row sat permanently at the column default `{}`. At the worker's
    /// three enforcement points (`host/http.rs` `fetch` / `fetch_all`,
    /// `host/graphql.rs`) an EMPTY list meant **allow every verb** until
    /// 2026-09-24, so a catalog row could issue any method regardless of what
    /// its template does. (Since that date empty DENIES every verb, so the
    /// same unbound column is now the opposite failure: a catalog row that
    /// cannot issue any method at all. Binding the column is what fixes both.)
    /// Catalog
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
    /// The shared row's fuel limit: the template's `recommended_fuel`
    /// resolved by `talos_compilation::recommended_max_fuel`, or
    /// [`SHARED_CATALOG_DEFAULT_MAX_FUEL`] for a template that declares
    /// none. `None` leaves the row's limit as it is (a new row takes the
    /// column default): the seed passes it only for a manifest whose
    /// recommendation cannot be read, so a rule nobody could read neither
    /// raises nor lowers a limit.
    ///
    /// Before 2026-10-03 this struct had no such field, so the seed never
    /// wrote `modules.max_fuel` for a shared catalog row: all 79 sat at the
    /// column default (2,000,000) whatever their template recommended, while
    /// an INSTALLED copy of the same template carried the recommendation.
    /// Catalog rows are dispatched directly by workflow nodes (measured on
    /// the reference deployment: 21 live nodes, 819 runs in 30 days), and a
    /// node that sets no `max_fuel` of its own runs under this limit.
    ///
    /// Only the shared row is written. A user's installed copy keeps its own
    /// limit, which the operator may have tuned.
    pub max_fuel: Option<i64>,
}

/// `modules.max_fuel`'s column default, which a shared catalog row carries
/// when its template recommends nothing. Written explicitly rather than left
/// to the column so a template that STOPS recommending a limit goes back to
/// it instead of keeping the old one. A database test holds it equal to the
/// column's default.
pub const SHARED_CATALOG_DEFAULT_MAX_FUEL: i64 = 2_000_000;

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

    // A disk row stores its source and no registry URL; a registry row the
    // reverse, and its stored source (if a disk seed once wrote one) is left
    // as it is.
    let (source_code, oci_url): (Option<&str>, Option<&str>) = match params.source {
        CatalogSource::Disk { source_code } => (Some(source_code), None),
        CatalogSource::Registry { oci_url } => (None, Some(oci_url)),
    };
    // Only a disk row is compiled here; a registry row's bytes are the
    // worker's to pull.
    let recompile = |source_changed: bool, has_wasm: bool, deps_changed: bool| match params.source {
        CatalogSource::Disk { .. } => needs_recompile(source_changed, has_wasm, deps_changed),
        CatalogSource::Registry { .. } => false,
    };

    if let Some(row) = existing {
        let id: Uuid = row.try_get("id")?;
        let prev_source: Option<String> = row.try_get("source_code")?;
        let prev_deps: Option<serde_json::Value> = row.try_get("dependencies")?;
        let has_wasm: bool = row.try_get::<Option<bool>, _>("has_wasm")?.unwrap_or(false);
        let source_changed = source_code.is_some_and(|code| prev_source.as_deref() != Some(code));
        let deps_changed = prev_deps.as_ref() != params.dependencies;

        // Rename-safe in-place update keyed on the canonical id.
        sqlx::query(
            "UPDATE modules SET \
                 name = $2, category = $3, description = $4, config_schema = $5, \
                 source_code = COALESCE($6, source_code), allowed_hosts = $7, \
                 allowed_secrets = $8, \
                 requires_approval_for = $9, capability_world = $10, \
                 dependencies = $11, allowed_methods = $12, \
                 max_fuel = COALESCE($13, max_fuel), oci_url = $14 \
             WHERE id = $1",
        )
        .bind(id)
        .bind(params.name)
        .bind(params.category)
        .bind(params.description)
        .bind(params.config_schema)
        .bind(source_code)
        .bind(params.allowed_hosts)
        .bind(params.allowed_secrets)
        .bind(params.requires_approval_for)
        .bind(params.capability_world_long)
        .bind(params.dependencies)
        .bind(params.allowed_methods)
        .bind(params.max_fuel)
        .bind(oci_url)
        .execute(pool)
        .await?;

        return Ok(RegisteredCatalog {
            id,
            needs_recompile: recompile(source_changed, has_wasm, deps_changed),
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
                 max_fuel, oci_url, language, created_at, updated_at \
             ) VALUES ( \
                 NULL, $1, 'catalog', $2, $3, $4, \
                 COALESCE($5, ''), $6, $7, $8, \
                 $9, $10, $11, $12, \
                 COALESCE($13::bigint, 2000000), $14, 'rust', NOW(), NOW() \
             ) \
             ON CONFLICT (name) WHERE user_id IS NULL DO UPDATE SET \
                 category = EXCLUDED.category, \
                 catalog_slug = EXCLUDED.catalog_slug, \
                 description = EXCLUDED.description, \
                 config_schema = EXCLUDED.config_schema, \
                 source_code = COALESCE($5, modules.source_code), \
                 allowed_hosts = EXCLUDED.allowed_hosts, \
                 allowed_secrets = EXCLUDED.allowed_secrets, \
                 requires_approval_for = EXCLUDED.requires_approval_for, \
                 capability_world = EXCLUDED.capability_world, \
                 dependencies = EXCLUDED.dependencies, \
                 allowed_methods = EXCLUDED.allowed_methods, \
                 max_fuel = COALESCE($13::bigint, modules.max_fuel), \
                 oci_url = EXCLUDED.oci_url \
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
    .bind(source_code)
    .bind(params.allowed_hosts)
    .bind(params.allowed_secrets)
    .bind(params.requires_approval_for)
    .bind(params.capability_world_long)
    .bind(params.catalog_slug)
    .bind(params.dependencies)
    .bind(params.allowed_methods)
    .bind(params.max_fuel)
    .bind(oci_url)
    .fetch_one(pool)
    .await?;

    let id: Uuid = row.try_get("id")?;
    let has_wasm: bool = row.try_get::<Option<bool>, _>("has_wasm")?.unwrap_or(false);
    let prev_source: Option<String> = row.try_get("prev_source")?;
    let prev_deps: Option<serde_json::Value> = row.try_get("prev_deps")?;
    let source_changed = source_code.is_some_and(|code| prev_source.as_deref() != Some(code));
    let deps_changed = prev_deps.as_ref() != params.dependencies;

    Ok(RegisteredCatalog {
        id,
        needs_recompile: recompile(source_changed, has_wasm, deps_changed),
    })
}

/// Write freshly compiled WASM to every catalog-derived row sharing this
/// `catalog_slug` that is still PRISTINE — the shared `user_id IS NULL` row(s)
/// and any per-user install whose bytes are still the shared build's. This is
/// the safe fix for stale twins: rather than rewriting workflow graph_json to
/// repoint at a survivor, we keep the twins' code current.
///
/// **Compare-and-set (2026-09-25).** `hot_update_module` keeps a per-user
/// install's `kind`/`catalog_slug`, so the old `WHERE catalog_slug = $1 AND
/// kind = 'catalog'` also overwrote a user's hot-updated bytes with catalog
/// bytes — the row then RAN catalog code while showing the user's source. A
/// per-user row is now refreshed only when its `content_hash` equals a shared
/// row's hash as it stood BEFORE this refresh (read in the same statement).
/// Stated cost: a pristine install compiled separately whose bytes differ from
/// the shared build is no longer auto-refreshed; it keeps the code it was
/// installed with until reinstalled. Hot update now also clears the row's
/// `catalog_slug` (talos-module-repository), so a detached row is never a
/// candidate again.
///
/// Returns the number of rows updated.
pub async fn refresh_catalog_wasm_by_slug(
    pool: &Pool<Postgres>,
    catalog_slug: &str,
    wasm_bytes: &[u8],
    content_hash: &str,
) -> Result<u64> {
    let res = sqlx::query(REFRESH_CATALOG_WASM_BY_SLUG_SQL)
        .bind(catalog_slug)
        .bind(wasm_bytes)
        .bind(content_hash)
        .bind(wasm_bytes.len() as i32)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// The statement behind [`refresh_catalog_wasm_by_slug`], hoisted so its
/// compare-and-set predicate is pinned without a database. The subquery reads
/// the shared rows' PRE-update hashes (one statement, one snapshot).
pub const REFRESH_CATALOG_WASM_BY_SLUG_SQL: &str =
    // Compile outputs only; see store_precompiled_template.
    "UPDATE modules m SET \
         wasm_bytes = $2, content_hash = $3, size_bytes = $4, \
         compiled_at = NOW() \
     WHERE m.catalog_slug = $1 AND m.kind = 'catalog' \
       AND (m.user_id IS NULL \
            OR EXISTS (SELECT 1 FROM modules c \
                        WHERE c.catalog_slug = $1 AND c.kind = 'catalog' \
                          AND c.user_id IS NULL \
                          AND c.content_hash IS NOT DISTINCT FROM m.content_hash))";

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
mod catalog_manifest_tests {
    use super::{CatalogManifest, ManifestRefusal, SHARED_CATALOG_DEFAULT_MAX_FUEL};
    use serde_json::json;

    fn manifest() -> serde_json::Value {
        json!({
            "name": "example-reader",
            "display_name": "Example Reader",
            "category": "Network",
            "description": "Reads one thing.",
            "capability_world": "http-node",
            "allowed_hosts": ["api.example.test"],
            "allowed_methods": ["get", "POST"],
            "requires_secrets": ["example/api_key"],
            "requires_approval_for": ["send"],
            "config_schema": {"type": "object", "properties": {"URL": {"type": "string"}}},
            "dependencies": {"chrono": "0.4"},
            "recommended_fuel": {"expected_items": 25, "bytes_per_item": 8000, "fuel_per_byte": 3, "safety_multiplier": 3.0}
        })
    }

    /// Every field a shared row stores from the manifest, in one read.
    #[test]
    fn a_manifest_is_read_whole() {
        let m = CatalogManifest::parse(&manifest()).expect("a complete manifest");
        assert_eq!(m.name, "Example Reader");
        assert_eq!(m.category, "Network");
        assert_eq!(m.capability_world_long, "http-node");
        assert_eq!(m.allowed_hosts, ["api.example.test"]);
        assert_eq!(m.allowed_methods, ["GET", "POST"]);
        assert_eq!(m.allowed_secrets, ["example/api_key"]);
        assert_eq!(m.requires_approval_for, ["send"]);
        assert_eq!(m.dependencies, Some(json!({"chrono": "0.4"})));
        assert_eq!(
            m.max_fuel,
            talos_compilation::recommended_max_fuel(&manifest())
                .unwrap()
                .map(|v| v as i64)
        );
        assert_eq!(m.fuel_unreadable, None);
    }

    #[test]
    fn what_a_manifest_leaves_out_is_the_narrowest_reading() {
        let m = CatalogManifest::parse(&json!({"name": "bare", "capability_world": "minimal"}))
            .expect("a name and a world are enough");
        assert_eq!(m.name, "bare");
        assert_eq!(
            m.capability_world_long, "minimal-node",
            "a short world gains its suffix"
        );
        assert!(m.allowed_hosts.is_empty() && m.allowed_methods.is_empty());
        assert!(m.allowed_secrets.is_empty() && m.requires_approval_for.is_empty());
        assert_eq!(m.dependencies, None);
        assert_eq!(m.max_fuel, Some(SHARED_CATALOG_DEFAULT_MAX_FUEL));
        // `trusted` is the historical short spelling of the automation world.
        let trusted = CatalogManifest::parse(&json!({"name": "t", "capability_world": "trusted"}));
        assert_eq!(trusted.unwrap().capability_world_long, "automation-node");
    }

    /// A world is declared, never defaulted, and must be one a module can be
    /// compiled for. The disk seed used to default a missing world to
    /// `automation-node`, the widest there is.
    #[test]
    fn a_manifest_that_cannot_be_trusted_with_a_row_is_refused() {
        let with = |key: &str, value: serde_json::Value| {
            let mut m = manifest();
            m[key] = value;
            CatalogManifest::parse(&m)
        };
        let without = |key: &str| {
            let mut m = manifest();
            m.as_object_mut().unwrap().remove(key);
            m
        };
        assert_eq!(
            CatalogManifest::parse(&without("capability_world")),
            Err(ManifestRefusal::NoCapabilityWorld)
        );
        assert_eq!(
            with("capability_world", json!("")),
            Err(ManifestRefusal::NoCapabilityWorld)
        );
        for unknown in ["llm-node", "root", "http-node-plus"] {
            assert_eq!(
                with("capability_world", json!(unknown)),
                Err(ManifestRefusal::UnknownCapabilityWorld(unknown.to_string())),
            );
        }
        let mut nameless = without("display_name");
        nameless.as_object_mut().unwrap().remove("name");
        assert_eq!(
            CatalogManifest::parse(&nameless),
            Err(ManifestRefusal::NoName)
        );
        assert!(matches!(
            with("allowed_hosts", json!(["https://not-a-host/path"])),
            Err(ManifestRefusal::InvalidAllowedHosts(_))
        ));
        assert!(matches!(
            with("requires_secrets", json!(["../escape"])),
            Err(ManifestRefusal::InvalidAllowedSecrets(_))
        ));
    }

    /// An unreadable recommendation is not a refusal: the row is still
    /// written, with no fuel limit to apply and the reason to log.
    #[test]
    fn an_unreadable_fuel_recommendation_is_reported_not_guessed() {
        let mut m = manifest();
        m["recommended_fuel"] = json!({"byte_per_item": 4000});
        let parsed = CatalogManifest::parse(&m).expect("still a row");
        assert_eq!(parsed.max_fuel, None);
        assert!(parsed
            .fuel_unreadable
            .as_deref()
            .is_some_and(|r| r.contains("recommended_fuel")));
    }

    /// Every manifest this repository ships is accepted, with a world a
    /// module can be compiled for. A parser stricter than the catalog it
    /// reads would drop templates at the next boot.
    #[test]
    fn every_shipped_manifest_is_accepted() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../module-templates");
        let mut read = 0usize;
        for entry in std::fs::read_dir(&root)
            .expect("module-templates")
            .flatten()
        {
            let path = entry.path().join("talos.json");
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let manifest: serde_json::Value =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let parsed = CatalogManifest::parse(&manifest)
                .unwrap_or_else(|refusal| panic!("{}: {refusal}", path.display()));
            assert!(parsed.fuel_unreadable.is_none(), "{}", path.display());
            assert!(parsed.max_fuel.is_some_and(|f| f > 0), "{}", path.display());
            read += 1;
        }
        // 79 on 2026-10-03. A scan that finds none has stopped looking.
        assert!(read >= 70, "only {read} manifests read");
    }
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

    /// The compare-and-set predicate: a per-user row is refreshed only when it
    /// still carries the shared build's hash. Dropping the EXISTS arm restores
    /// the defect (a hot-updated install ran catalog bytes under user source).
    #[test]
    fn refresh_only_touches_pristine_rows() {
        let sql = REFRESH_CATALOG_WASM_BY_SLUG_SQL;
        assert!(sql.contains("m.user_id IS NULL"));
        assert!(sql.contains("c.content_hash IS NOT DISTINCT FROM m.content_hash"));
        assert!(sql.contains("c.user_id IS NULL"));
        // The shared-row hash must be read in the SAME statement (pre-update
        // snapshot), not bound from a caller that already overwrote it.
        assert!(!sql.contains("$5"));
        let where_at = sql.find("WHERE m.catalog_slug").unwrap();
        assert!(sql[where_at..].contains(" AND (m.user_id IS NULL"));
    }

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
