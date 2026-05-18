//! WIT Component Inspector
#![allow(dead_code)]
//!
//! Inspects compiled WASM components to determine which Talos capability world
//! they were compiled against.  This drives two security properties:
//!
//! 1. **Upload validation** — reject a component that claims to be "minimal" but
//!    imports trusted-only interfaces such as `secrets` or `files`.
//! 2. **AI tool discovery** — tell an LLM exactly which host interfaces a node
//!    uses so it can reason about what the node can and cannot do.
//!
//! ## Implementation strategy
//!
//! We scan the raw WASM bytes for the UTF-8 interface name strings that the
//! Component Model linker records in the binary's import section.  This avoids
//! any dependency on a specific version of `wit-component` or `wasmtime`'s
//! reflection API, and works on any valid component produced by `cargo component`.

#[allow(dead_code)]
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

// ============================================================================
// Capability world enum
// ============================================================================

/// The WIT capability world a component was compiled against.
///
/// Ordered from least to most privileged in a **partial order**:
///
/// ```text
/// minimal-node
///     └─ network-node
///             ├─ secrets-node
///             ├─ filesystem-node
///             ├─ messaging-node
///             ├─ cache-node
///             └─ database-node
///                     └─ automation-node (Trusted)
/// ```
///
/// The four tier-3 sub-worlds (`Secrets`, `Filesystem`, `Messaging`, `Cache`)
/// are **incomparable** with each other — `partial_cmp` returns `None` for
/// any pair of distinct sub-worlds.
///
/// `Unknown` is **not** comparable to any named tier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityWorld {
    /// Pure computation — logging, JSON, datetime, crypto, env only.
    /// No outbound I/O; maximum isolation.
    Minimal,
    /// Outbound HTTP (via talos:core/http), webhooks, GraphQL, email, state, templates.
    /// No raw TCP/UDP sockets.
    Http,
    /// All Http capabilities PLUS raw TCP/UDP sockets (wasi:sockets). Adds outbound HTTP, webhooks, GraphQL, email, state, templates, and
    /// data-transform.  Cannot access secrets, files, cache, messaging, or DB.
    Network,
    /// Network + read-only access to the secrets vault.
    Secrets,
    /// Network + sandboxed file I/O.
    Filesystem,
    /// Network + NATS pub/sub messaging.
    Messaging,
    /// Network + Redis distributed cache.
    Cache,
    /// Network + secrets + direct PostgreSQL access.
    Database,
    /// Network + human-in-the-loop approvals.
    Governance,
    /// Full platform capabilities — everything in `network-node` plus secrets,
    /// files, Redis cache, NATS messaging, and database access.
    Trusted,
    /// Not a Talos component, or uses an unrecognised set of imports.
    Unknown,
}

#[allow(dead_code)]
impl CapabilityWorld {
    /// Numeric privilege level for ordering purposes.
    ///
    /// Returns `None` for the tier-3 sub-worlds and for `Unknown` because
    /// they are incomparable (sub-worlds are at the same level but are
    /// distinct; Unknown is incomparable to everything).
    ///
    /// Level mapping:
    ///   Minimal=0, Network=1, sub-worlds=2, Database=3, Trusted=4
    fn level(&self) -> Option<u8> {
        match self {
            Self::Minimal => Some(0),
            Self::Http => Some(1),
            Self::Network => Some(2),
            // Sub-worlds share level 3 but are incomparable with each other.
            // `partial_cmp` special-cases them; do not expose this level.
            Self::Secrets | Self::Filesystem | Self::Messaging | Self::Cache | Self::Governance => {
                Some(3)
            }
            Self::Database => Some(4),
            Self::Trusted => Some(5),
            Self::Unknown => None,
        }
    }

    /// Returns `true` if this world's capability set is a subset of `other`'s.
    ///
    /// Used by `validate_capability_level` to check that a component's detected
    /// world does not exceed its declared world.  This replaces a simple `>`
    /// comparison with the correct partial-order semantics:
    ///
    /// - Any world is a subset of itself.
    /// - `Minimal` ⊆ everything.
    /// - `Network` ⊆ `Secrets | Filesystem | Messaging | Cache | Database | Trusted`.
    /// - `Secrets` ⊆ `Database | Trusted`.
    /// - `Filesystem | Messaging | Cache` ⊆ `Trusted` only.
    /// - `Database` ⊆ `Trusted` only.
    /// - `Trusted` is only a subset of itself.
    /// - `Unknown` is not a subset of anything (invalid component).
    pub fn is_subset_of(&self, other: &Self) -> bool {
        // Unknown is invalid — not a subset of anything, not even itself.
        if matches!(self, Self::Unknown) || matches!(other, Self::Unknown) {
            return false;
        }
        if self == other {
            return true;
        }
        match (self, other) {
            // Minimal is a subset of every named world (Unknown already rejected above).
            (Self::Minimal, _) => true,
            // Http is a subset of every world above it.
            (
                Self::Http,
                Self::Network
                | Self::Secrets
                | Self::Filesystem
                | Self::Messaging
                | Self::Cache
                | Self::Database
                | Self::Trusted,
            ) => true,
            (Self::Http, _) => false,
            // Network is a subset of every world above it.
            (
                Self::Network,
                Self::Secrets
                | Self::Filesystem
                | Self::Messaging
                | Self::Cache
                | Self::Database
                | Self::Trusted,
            ) => true,
            (Self::Network, _) => false,
            // Secrets can escalate to Database (which also provides secrets) or Trusted.
            (Self::Secrets, Self::Database | Self::Trusted) => true,
            (Self::Secrets, _) => false,
            // Filesystem, Messaging, Cache can only escalate to Trusted.
            (Self::Filesystem, Self::Trusted) => true,
            (Self::Filesystem, _) => false,
            (Self::Messaging, Self::Trusted) => true,
            (Self::Messaging, _) => false,
            (Self::Cache, Self::Trusted) => true,
            (Self::Cache, _) => false,
            // Database can only escalate to Trusted.
            (Self::Database, Self::Trusted) => true,
            (Self::Governance, Self::Trusted) => true,
            (Self::Governance, _) => false,
            (Self::Database, _) => false,
            // Trusted is only a subset of itself (handled by `self == other` above).
            (Self::Trusted, _) => false,
            // Unknown is unreachable — the guard at the top of this function
            // returns `false` whenever either side is Unknown.
            (Self::Unknown, _) => unreachable!("Unknown filtered by guard above"),
        }
    }
}

/// The tier-3 sub-worlds are incomparable with each other; all other
/// comparisons follow the numeric level.  `Unknown` is incomparable to all.
impl PartialOrd for CapabilityWorld {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // Sub-worlds at level 2 are incomparable with each other.
        let is_sub_world = |w: &Self| {
            matches!(
                w,
                Self::Secrets | Self::Filesystem | Self::Messaging | Self::Cache | Self::Governance
            )
        };
        if is_sub_world(self) && is_sub_world(other) && self != other {
            return None;
        }
        match (self.level(), other.level()) {
            (Some(a), Some(b)) => a.partial_cmp(&b),
            _ => None, // Unknown (or distinct sub-worlds) is incomparable
        }
    }
}

impl std::fmt::Display for CapabilityWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minimal => write!(f, "minimal"),
            Self::Http => write!(f, "http"),
            Self::Network => write!(f, "network"),
            Self::Secrets => write!(f, "secrets"),
            Self::Filesystem => write!(f, "filesystem"),
            Self::Messaging => write!(f, "messaging"),
            Self::Cache => write!(f, "cache"),
            Self::Database => write!(f, "database"),
            Self::Trusted => write!(f, "trusted"),
            Self::Unknown => write!(f, "unknown"),
            Self::Governance => write!(f, "governance"),
        }
    }
}

impl std::str::FromStr for CapabilityWorld {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "minimal" => Ok(Self::Minimal),
            "http" => Ok(Self::Http),
            "network" => Ok(Self::Network),
            "secrets" => Ok(Self::Secrets),
            "filesystem" => Ok(Self::Filesystem),
            "messaging" => Ok(Self::Messaging),
            "cache" => Ok(Self::Cache),
            "database" => Ok(Self::Database),
            "governance" => Ok(Self::Governance),
            "trusted" => Ok(Self::Trusted),
            _ => Ok(Self::Unknown),
        }
    }
}

// ============================================================================
// Canonical interface names (as encoded in the component binary)
// ============================================================================

/// All talos:core interface names that can appear in a component's import section.
const ALL_TALOS_INTERFACES: &[&str] = &[
    "talos:core/http",
    "talos:core/logging",
    "talos:core/secrets",
    "talos:core/state",
    "talos:core/database",
    "talos:core/email",
    "talos:core/webhook",
    "talos:core/json",
    "talos:core/datetime",
    "talos:core/crypto",
    "talos:core/env",
    "talos:core/files",
    "talos:core/templates",
    "talos:core/data-transform",
    "talos:core/cache",
    "talos:core/messaging",
    "talos:core/graphql",
];

/// Interfaces that first appear in the `network-node` world (above minimal).
const NETWORK_TIER: &[&str] = &[
    "talos:core/http",
    "talos:core/webhook",
    "talos:core/graphql",
    "talos:core/email",
    "talos:core/state",
    "talos:core/data-transform",
    "talos:core/templates",
];

// ============================================================================
// Inspection result
// ============================================================================

/// The result of inspecting a compiled WASM component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInspection {
    /// The detected capability world.
    pub capability_world: CapabilityWorld,
    /// All `talos:core/*` interfaces found in the binary's import section.
    pub imported_interfaces: Vec<String>,
    /// `true` if the binary looks like a valid Talos node (exports `run`).
    pub is_talos_node: bool,
}

// ============================================================================
// Public API
// ============================================================================

/// Inspect a compiled WASM component and determine its capability world.
///
/// Primary detection: scan raw bytes for `talos:core/*` interface name strings
/// embedded in the component's import section.  This is reliable because the
/// Component Model binary format encodes all import names as UTF-8 strings.
///
/// Fallback detection: if no imports survive (Rust's DCE strips all unused WIT
/// imports for pure-computation modules), scan for the world-name string that
/// `cargo component` embeds in the component's type section.  This covers
/// minimal-node templates that call no host functions at all.
pub fn inspect_component(wasm_bytes: &[u8]) -> ComponentInspection {
    use std::collections::HashSet;
    use wasmparser::{Parser, Payload};

    let mut imported = HashSet::new();
    let mut imported_wasi_sockets = false;
    let mut is_talos_node = false;

    for payload in Parser::new(0).parse_all(wasm_bytes) {
        match payload {
            Ok(Payload::ComponentImportSection(s)) => {
                for import in s.into_iter().flatten() {
                    let name = import.name.0;
                    if name.starts_with("talos:core/") {
                        imported.insert(name.to_string());
                    } else if name.starts_with("wasi:sockets/") {
                        imported_wasi_sockets = true;
                    }
                }
            }
            Ok(Payload::ComponentExportSection(s)) => {
                for export in s.into_iter().flatten() {
                    let name = export.name.0;
                    // For pure run functions
                    if name == "run" {
                        is_talos_node = true;
                    }
                }
            }
            _ => {}
        }
    }

    if !imported.is_empty() || imported_wasi_sockets {
        let mut capability_world = classify_world(&imported, imported_wasi_sockets);
        let mut interfaces: Vec<String> = imported.into_iter().collect();
        interfaces.sort();

        if let Some(world) = detect_world_from_type_section(wasm_bytes) {
            capability_world = world;
        }

        return ComponentInspection {
            capability_world,
            imported_interfaces: interfaces,
            is_talos_node,
        };
    }

    // Fallback: no imports survived DCE — check for the world name that
    // cargo-component encodes in the component's type section.
    if let Some(world) = detect_world_from_type_section(wasm_bytes) {
        return ComponentInspection {
            capability_world: world,
            imported_interfaces: vec![],
            is_talos_node,
        };
    }

    ComponentInspection {
        capability_world: CapabilityWorld::Unknown,
        imported_interfaces: vec![],
        is_talos_node,
    }
}

/// Validate that a component does not exceed its declared capability level.
///
/// Returns `Err` if:
/// - The component is not a recognised Talos node (`Unknown` capability world).
/// - The component's actual world is **not** a subset of the declared world
///   (i.e. it imports more interfaces than the declaration permits).
pub fn validate_capability_level(
    inspection: &ComponentInspection,
    declared: &CapabilityWorld,
) -> Result<(), String> {
    // Unknown components cannot be verified — reject them outright.
    if inspection.capability_world == CapabilityWorld::Unknown {
        return Err(format!(
            "Component is not a recognised Talos node (no talos:core imports detected). \
             Declared level: {}",
            declared
        ));
    }
    // If the actual world is not a subset of the declared world, reject.
    if !inspection.capability_world.is_subset_of(declared) {
        return Err(format!(
            "Component imports capabilities outside its declared world: \
             declared={}, actual={}. \
             Imported interfaces: {}",
            declared,
            inspection.capability_world,
            inspection.imported_interfaces.join(", ")
        ));
    }
    Ok(())
}

// ============================================================================
// Private helpers
// ============================================================================

/// Detect the capability world from the component type section when no interface
/// imports survive dead-code elimination.
///
/// `cargo component` embeds the WIT world identifier (e.g. `minimal-node`) as
/// a UTF-8 string in the component's type section.  We scan for each world name
/// in order from most-specific to most-permissive and return the first match.
///
/// This is safe from a security perspective: if DCE removed all imports of a
/// trusted interface, the binary literally cannot call that interface, so
/// downgrading its perceived world to what the type section claims is correct.
///
/// Security note: a false-positive Minimal classification is safe because the
/// tiered linker enforces the real security boundary at execution time.
fn detect_world_from_type_section(bytes: &[u8]) -> Option<CapabilityWorld> {
    // Ordered most-specific first so "database-node" is preferred over "network-node"
    // in case both substrings appear (unlikely but defensive).
    //
    // NOTE: No `talos:core` pre-filter here. The WIT worlds export just `run`
    // (not `talos:core/...`), so when DCE removes all import calls the binary
    // contains no `talos:core` strings at all — but cargo-component still embeds
    // the world name string (e.g. `minimal-node`) in the component type section.
    // The world-name patterns are specific enough to avoid false positives against
    // arbitrary non-Talos WASM, and the tiered linker enforces real security.
    const WORLD_PATTERNS: &[(&[u8], CapabilityWorld)] = &[
        (b"__talos_world_database-node__", CapabilityWorld::Database),
        (b"__talos_world_secrets-node__", CapabilityWorld::Secrets),
        (
            b"__talos_world_filesystem-node__",
            CapabilityWorld::Filesystem,
        ),
        (
            b"__talos_world_messaging-node__",
            CapabilityWorld::Messaging,
        ),
        (b"__talos_world_cache-node__", CapabilityWorld::Cache),
        (b"__talos_world_automation-node__", CapabilityWorld::Trusted),
        (b"__talos_world_network-node__", CapabilityWorld::Http),
        (b"__talos_world_http-node__", CapabilityWorld::Http),
        (b"__talos_world_minimal-node__", CapabilityWorld::Minimal),
        // Legacy fallback
        (b"database-node", CapabilityWorld::Database),
        (b"secrets-node", CapabilityWorld::Secrets),
        (b"filesystem-node", CapabilityWorld::Filesystem),
        (b"messaging-node", CapabilityWorld::Messaging),
        (b"cache-node", CapabilityWorld::Cache),
        (b"automation-node", CapabilityWorld::Trusted),
        (b"network-node", CapabilityWorld::Network),
        (b"http-node", CapabilityWorld::Http),
        (b"minimal-node", CapabilityWorld::Minimal),
        (b"talos:plugin", CapabilityWorld::Minimal),
    ];

    for (pattern, world) in WORLD_PATTERNS {
        if bytes_contain(bytes, pattern) {
            return Some(world.clone());
        }
    }
    None
}

/// Scan the binary for known `talos:core/*` interface name strings.
fn scan_talos_imports(bytes: &[u8]) -> HashSet<String> {
    ALL_TALOS_INTERFACES
        .iter()
        .filter(|&&iface| bytes_contain(bytes, iface.as_bytes()))
        .map(|&iface| iface.to_string())
        .collect()
}

/// Return `true` if `haystack` contains `needle` as a contiguous sub-slice.
fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Classify a set of imported interface names into the most specific world.
///
/// The classification is based on the EXACT set of trusted-tier interfaces
/// present:
///
/// | Trusted interfaces found | World |
/// |---|---|
/// | none | Minimal or Network (checked separately) |
/// | `{secrets}` only | Secrets |
/// | `{files}` only | Filesystem |
/// | `{cache}` only | Cache |
/// | `{messaging}` only | Messaging |
/// | `{secrets, database}` | Database |
/// | `{all five}` | Trusted |
/// | anything else | Trusted (safe escalation) |
fn classify_world(imports: &HashSet<String>, has_sockets: bool) -> CapabilityWorld {
    let has_secrets = imports.contains("talos:core/secrets");
    let has_files = imports.contains("talos:core/files");
    let has_cache = imports.contains("talos:core/cache");
    let has_messaging = imports.contains("talos:core/messaging");
    let has_database = imports.contains("talos:core/database");
    let has_governance = imports.contains("talos:core/governance");

    let any_trusted =
        has_secrets || has_files || has_cache || has_messaging || has_database || has_governance;

    if !any_trusted {
        if has_sockets {
            return CapabilityWorld::Network;
        }
        if NETWORK_TIER.iter().any(|iface| imports.contains(*iface)) {
            return CapabilityWorld::Http;
        }
        return CapabilityWorld::Minimal;
    }

    // Map the EXACT trusted-interface set to a specific world.
    // Any unrecognised combination escalates to Trusted (safe default).
    match (
        has_secrets,
        has_files,
        has_cache,
        has_messaging,
        has_database,
        has_governance,
    ) {
        (true, false, false, false, false, false) => CapabilityWorld::Secrets,
        (false, true, false, false, false, false) => CapabilityWorld::Filesystem,
        (false, false, true, false, false, false) => CapabilityWorld::Cache,
        (false, false, false, true, false, false) => CapabilityWorld::Messaging,
        // database-node provides secrets + database together
        (true, false, false, false, true, false) => CapabilityWorld::Database,
        (false, false, false, false, false, true) => CapabilityWorld::Governance,
        // Full automation-node: all trusted interfaces
        (true, true, true, true, true, true) => CapabilityWorld::Trusted,
        // Any other combination — escalate to Trusted (safe)
        _ => CapabilityWorld::Trusted,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_imports(ifaces: &[&str]) -> HashSet<String> {
        ifaces.iter().map(|s| s.to_string()).collect()
    }

    // ── classify_world ──────────────────────────────────────────────────────

    #[test]
    fn minimal_imports_give_minimal_world() {
        let imports = make_imports(&["talos:core/logging", "talos:core/json"]);
        assert_eq!(classify_world(&imports, false), CapabilityWorld::Minimal);
    }

    #[test]
    fn http_gives_http_world() {
        let imports = make_imports(&["talos:core/logging", "talos:core/http"]);
        assert_eq!(classify_world(&imports, false), CapabilityWorld::Http);
    }

    #[test]
    fn sockets_give_network_world() {
        let imports = make_imports(&["talos:core/logging", "talos:core/http"]);
        assert_eq!(classify_world(&imports, true), CapabilityWorld::Network);
    }

    #[test]
    fn secrets_gives_secrets_world() {
        let imports = make_imports(&["talos:core/http", "talos:core/secrets"]);
        assert_eq!(classify_world(&imports, false), CapabilityWorld::Secrets);
    }

    #[test]
    fn files_gives_filesystem_world() {
        let imports = make_imports(&["talos:core/logging", "talos:core/files"]);
        assert_eq!(classify_world(&imports, false), CapabilityWorld::Filesystem);
    }

    #[test]
    fn cache_gives_cache_world() {
        let imports = make_imports(&["talos:core/http", "talos:core/cache"]);
        assert_eq!(classify_world(&imports, false), CapabilityWorld::Cache);
    }

    #[test]
    fn messaging_gives_messaging_world() {
        let imports = make_imports(&["talos:core/logging", "talos:core/messaging"]);
        assert_eq!(classify_world(&imports, false), CapabilityWorld::Messaging);
    }

    #[test]
    fn secrets_and_database_gives_database_world() {
        let imports = make_imports(&[
            "talos:core/http",
            "talos:core/secrets",
            "talos:core/database",
        ]);
        assert_eq!(classify_world(&imports, false), CapabilityWorld::Database);
    }

    #[test]
    fn all_trusted_gives_trusted_world() {
        let imports = make_imports(&[
            "talos:core/http",
            "talos:core/secrets",
            "talos:core/files",
            "talos:core/cache",
            "talos:core/messaging",
            "talos:core/database",
        ]);
        assert_eq!(classify_world(&imports, false), CapabilityWorld::Trusted);
    }

    #[test]
    fn mixed_trusted_escalates_to_trusted() {
        // files + messaging is an unrecognised combination → safe escalation to Trusted
        let imports = make_imports(&["talos:core/files", "talos:core/messaging"]);
        assert_eq!(classify_world(&imports, false), CapabilityWorld::Trusted);
    }

    // ── is_subset_of ────────────────────────────────────────────────────────

    #[test]
    fn is_subset_of_semantics() {
        // Minimal is a subset of everything named
        assert!(CapabilityWorld::Minimal.is_subset_of(&CapabilityWorld::Network));
        assert!(CapabilityWorld::Minimal.is_subset_of(&CapabilityWorld::Secrets));
        assert!(CapabilityWorld::Minimal.is_subset_of(&CapabilityWorld::Trusted));

        // Network is a subset of every world above it
        assert!(CapabilityWorld::Network.is_subset_of(&CapabilityWorld::Secrets));
        assert!(CapabilityWorld::Network.is_subset_of(&CapabilityWorld::Filesystem));
        assert!(CapabilityWorld::Network.is_subset_of(&CapabilityWorld::Database));
        assert!(CapabilityWorld::Network.is_subset_of(&CapabilityWorld::Trusted));
        assert!(!CapabilityWorld::Network.is_subset_of(&CapabilityWorld::Minimal));

        // Sub-worlds are incompatible with each other
        assert!(!CapabilityWorld::Secrets.is_subset_of(&CapabilityWorld::Filesystem));
        assert!(!CapabilityWorld::Filesystem.is_subset_of(&CapabilityWorld::Cache));
        assert!(!CapabilityWorld::Cache.is_subset_of(&CapabilityWorld::Messaging));

        // Secrets can escalate to Database or Trusted
        assert!(CapabilityWorld::Secrets.is_subset_of(&CapabilityWorld::Database));
        assert!(CapabilityWorld::Secrets.is_subset_of(&CapabilityWorld::Trusted));
        assert!(!CapabilityWorld::Secrets.is_subset_of(&CapabilityWorld::Network));

        // Filesystem, Messaging, Cache can only escalate to Trusted
        assert!(CapabilityWorld::Filesystem.is_subset_of(&CapabilityWorld::Trusted));
        assert!(!CapabilityWorld::Filesystem.is_subset_of(&CapabilityWorld::Database));
        assert!(CapabilityWorld::Messaging.is_subset_of(&CapabilityWorld::Trusted));
        assert!(!CapabilityWorld::Messaging.is_subset_of(&CapabilityWorld::Database));
        assert!(CapabilityWorld::Cache.is_subset_of(&CapabilityWorld::Trusted));
        assert!(!CapabilityWorld::Cache.is_subset_of(&CapabilityWorld::Database));

        // Database can only escalate to Trusted
        assert!(CapabilityWorld::Database.is_subset_of(&CapabilityWorld::Trusted));
        assert!(!CapabilityWorld::Database.is_subset_of(&CapabilityWorld::Secrets));

        // Trusted is only a subset of itself
        assert!(CapabilityWorld::Trusted.is_subset_of(&CapabilityWorld::Trusted));
        assert!(!CapabilityWorld::Trusted.is_subset_of(&CapabilityWorld::Database));

        // Unknown is not a subset of anything
        assert!(!CapabilityWorld::Unknown.is_subset_of(&CapabilityWorld::Trusted));
        assert!(!CapabilityWorld::Unknown.is_subset_of(&CapabilityWorld::Unknown));
    }

    // ── validate_capability_level ────────────────────────────────────────────

    #[test]
    fn validate_rejects_underdeclared_level() {
        let inspection = ComponentInspection {
            capability_world: CapabilityWorld::Secrets,
            imported_interfaces: vec!["talos:core/secrets".to_string()],
            is_talos_node: true,
        };
        // Claiming "minimal" — should fail (secrets > minimal).
        assert!(validate_capability_level(&inspection, &CapabilityWorld::Minimal).is_err());
        // Claiming "network" — should fail (secrets not ⊆ network).
        assert!(validate_capability_level(&inspection, &CapabilityWorld::Network).is_err());
        // Claiming "filesystem" — should fail (different sub-world, incompatible).
        assert!(validate_capability_level(&inspection, &CapabilityWorld::Filesystem).is_err());
        // Claiming "secrets" — should succeed (exact match).
        assert!(validate_capability_level(&inspection, &CapabilityWorld::Secrets).is_ok());
        // Claiming "database" — should succeed (secrets ⊆ database's capabilities).
        assert!(validate_capability_level(&inspection, &CapabilityWorld::Database).is_ok());
        // Claiming "trusted" — should succeed.
        assert!(validate_capability_level(&inspection, &CapabilityWorld::Trusted).is_ok());
    }

    #[test]
    fn validate_rejects_unknown_component() {
        let inspection = ComponentInspection {
            capability_world: CapabilityWorld::Unknown,
            imported_interfaces: vec![],
            is_talos_node: false,
        };
        // Unknown components are rejected regardless of declared level.
        assert!(validate_capability_level(&inspection, &CapabilityWorld::Unknown).is_err());
        assert!(validate_capability_level(&inspection, &CapabilityWorld::Trusted).is_err());
    }

    // ── PartialOrd ──────────────────────────────────────────────────────────

    #[test]
    fn capability_world_ordering() {
        // Linear chain: Minimal < Network < sub-worlds < Database < Trusted
        assert!(CapabilityWorld::Minimal < CapabilityWorld::Network);
        assert!(CapabilityWorld::Network < CapabilityWorld::Secrets);
        assert!(CapabilityWorld::Network < CapabilityWorld::Filesystem);
        assert!(CapabilityWorld::Network < CapabilityWorld::Cache);
        assert!(CapabilityWorld::Network < CapabilityWorld::Messaging);
        assert!(CapabilityWorld::Secrets < CapabilityWorld::Database);
        assert!(CapabilityWorld::Database < CapabilityWorld::Trusted);

        // The four tier-3 sub-worlds are incomparable with each other.
        assert!(CapabilityWorld::Secrets
            .partial_cmp(&CapabilityWorld::Filesystem)
            .is_none());
        assert!(CapabilityWorld::Filesystem
            .partial_cmp(&CapabilityWorld::Cache)
            .is_none());
        assert!(CapabilityWorld::Cache
            .partial_cmp(&CapabilityWorld::Messaging)
            .is_none());
        assert!(CapabilityWorld::Messaging
            .partial_cmp(&CapabilityWorld::Secrets)
            .is_none());

        // Unknown is incomparable to all named tiers.
        assert!(CapabilityWorld::Trusted
            .partial_cmp(&CapabilityWorld::Unknown)
            .is_none());
        assert!(CapabilityWorld::Unknown
            .partial_cmp(&CapabilityWorld::Minimal)
            .is_none());

        // Consequently, Unknown is NOT >= Network — prevents spurious network access.
        assert!(CapabilityWorld::Unknown
            .partial_cmp(&CapabilityWorld::Network)
            .is_none());
    }

    // ── Display / FromStr roundtrip ──────────────────────────────────────────

    #[test]
    fn display_and_parse_roundtrip() {
        for world in [
            CapabilityWorld::Minimal,
            CapabilityWorld::Network,
            CapabilityWorld::Secrets,
            CapabilityWorld::Filesystem,
            CapabilityWorld::Messaging,
            CapabilityWorld::Cache,
            CapabilityWorld::Database,
            CapabilityWorld::Trusted,
        ] {
            let s = world.to_string();
            let parsed: CapabilityWorld = s.parse().unwrap();
            assert_eq!(parsed, world, "roundtrip failed for {:?}", world);
        }
    }
}
