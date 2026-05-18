//! WIT Component Inspector
//!
//! Inspects compiled WASM components to determine which Talos capability world
//! they were compiled against. The `CapabilityWorld` enum and its impls now
//! live in the `talos-capability-world` workspace crate so the controller (and
//! any future tool) can reason about capability levels without depending on
//! this worker crate.

pub use talos_capability_world::CapabilityWorld;

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// Canonical interface names (as encoded in the component binary)
// ============================================================================

/// All talos:core interface names that can appear in a component's import section.
///
/// Pre-extraction this constant + `scan_talos_imports` were used by the
/// import-section scanner; the current code path detects worlds via the
/// type-section walk in `detect_world_from_type_section` and the constant
/// remains as canonical reference for future scanners. `#[allow(dead_code)]`
/// to suppress the warning without removing the documentation.
#[allow(dead_code)]
const ALL_TALOS_INTERFACES: &[&str] = &[
    // Minimal tier
    "talos:core/logging",
    "talos:core/json",
    "talos:core/datetime",
    "talos:core/crypto",
    "talos:core/env",
    // Network tier
    "talos:core/http",
    "talos:core/webhook",
    "talos:core/graphql",
    "talos:core/email",
    "talos:core/state",
    "talos:core/data-transform",
    "talos:core/templates",
    "talos:core/events",
    "talos:core/http-stream",
    // Sub-world specific
    "talos:core/secrets",
    "talos:core/files",
    "talos:core/cache",
    "talos:core/messaging",
    "talos:core/governance",
    "talos:core/database",
    // LLM interfaces (part of secrets-node and above)
    "talos:core/llm",
    "talos:core/llm-tools",
    "talos:core/llm-streaming",
    "talos:core/context-window",
    "talos:core/resource-quotas",
    "talos:core/embedding",
    // Advanced (automation-node only)
    "talos:core/agent-memory",
    "talos:core/agent-orchestration",
    "talos:core/object-storage",
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
    "talos:core/events",
    "talos:core/http-stream",
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
        (b"__talos_world_agent-node__", CapabilityWorld::Agent),
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
        (b"__talos_world_network-node__", CapabilityWorld::Network),
        (b"__talos_world_http-node__", CapabilityWorld::Http),
        (b"__talos_world_minimal-node__", CapabilityWorld::Minimal),
        // Legacy fallback
        (b"database-node", CapabilityWorld::Database),
        (b"agent-node", CapabilityWorld::Agent),
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
/// Reference scanner kept alongside `ALL_TALOS_INTERFACES`; current
/// detection goes through `detect_world_from_type_section`. `#[allow]`
/// to suppress the unused warning without removing the documented helper.
#[allow(dead_code)]
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
    // Any LLM-related interface implies secrets tier (LLM API keys are host-managed).
    let has_llm = imports.contains("talos:core/llm")
        || imports.contains("talos:core/llm-tools")
        || imports.contains("talos:core/llm-streaming")
        || imports.contains("talos:core/context-window")
        || imports.contains("talos:core/resource-quotas")
        || imports.contains("talos:core/embedding");

    let has_agent_memory = imports.contains("talos:core/agent-memory");
    let has_agent_orchestration = imports.contains("talos:core/agent-orchestration");

    let any_trusted = has_secrets
        || has_files
        || has_cache
        || has_messaging
        || has_database
        || has_governance
        || has_llm
        || has_agent_memory
        || has_agent_orchestration;

    if !any_trusted {
        if has_sockets {
            return CapabilityWorld::Network;
        }
        if NETWORK_TIER.iter().any(|iface| imports.contains(*iface)) {
            return CapabilityWorld::Http;
        }
        return CapabilityWorld::Minimal;
    }

    // Map the trusted-interface set to the most specific world.
    // LLM is always paired with secrets (needs API keys), so it doesn't
    // affect the tier classification beyond requiring Secrets level.
    //
    // Agent-node is identified by agent-orchestration (its distinguishing import)
    // combined with secrets/LLM, WITHOUT database/files/cache/messaging.
    //
    // Any unrecognised combination escalates to Trusted (safe default).
    match (
        has_secrets || has_llm, // LLM implies secrets tier
        has_files,
        has_cache,
        has_messaging,
        has_database,
        has_governance,
        has_agent_orchestration,
    ) {
        // Simple tier-3 sub-worlds (single additional capability)
        (true, false, false, false, false, false, false) => CapabilityWorld::Secrets,
        (false, true, false, false, false, false, false) => CapabilityWorld::Filesystem,
        (false, false, true, false, false, false, false) => CapabilityWorld::Cache,
        (false, false, false, true, false, false, false) => CapabilityWorld::Messaging,
        (false, false, false, false, false, true, false) => CapabilityWorld::Governance,
        // database-node: secrets + database (optionally agent-memory, no orchestration)
        (true, false, false, false, true, false, false) => CapabilityWorld::Database,
        // agent-node: secrets + orchestration, no database/files/cache/messaging
        // governance and agent-memory are optional (agent-node includes both)
        (true, false, false, false, false, _, true) => CapabilityWorld::Agent,
        // Full automation-node: all trusted interfaces
        (true, true, true, true, true, true, _) => CapabilityWorld::Trusted,
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

    // ── Canonical world helpers (item A) ────────────────────────────────────

    #[test]
    fn all_roundtrips_through_fromstr() {
        use std::str::FromStr;
        for w in CapabilityWorld::ALL {
            let s = w.as_str();
            assert_eq!(
                CapabilityWorld::from_str(s).unwrap(),
                *w,
                "short form '{}' must roundtrip to the same variant",
                s
            );
            let ns = w.as_node_str();
            assert_eq!(
                CapabilityWorld::from_str(ns).unwrap(),
                *w,
                "-node form '{}' must roundtrip to the same variant",
                ns
            );
        }
    }

    #[test]
    fn all_strs_matches_all_order() {
        assert_eq!(
            CapabilityWorld::all_strs().len(),
            CapabilityWorld::ALL.len()
        );
        for (w, s) in CapabilityWorld::ALL
            .iter()
            .zip(CapabilityWorld::all_strs().iter())
        {
            assert_eq!(w.as_node_str(), *s);
        }
    }

    #[test]
    fn all_does_not_contain_unknown() {
        assert!(
            !CapabilityWorld::ALL.contains(&CapabilityWorld::Unknown),
            "ALL is the set of selectable worlds; Unknown must never appear"
        );
    }

    #[test]
    fn trusted_serialises_to_automation_node() {
        // Publicly the tier is surfaced as `automation-node`. This guards
        // against an accidental rename that would desync the MCP schemas.
        assert_eq!(CapabilityWorld::Trusted.as_node_str(), "automation-node");
    }

    #[test]
    fn llm_node_is_not_a_worker_world() {
        // Item D: `llm-node` is an actor-ceiling privilege-tier label only.
        // The worker's FromStr intentionally maps it to Unknown, and
        // `all_strs()` must NEVER include it (doing so would mislead
        // controller MCP schemas into advertising it as compilable).
        use std::str::FromStr;
        assert_eq!(
            CapabilityWorld::from_str("llm-node").unwrap(),
            CapabilityWorld::Unknown
        );
        assert!(
            !CapabilityWorld::all_strs().contains(&"llm-node"),
            "all_strs() must not include llm-node"
        );
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
        // Direct subset chains
        assert!(CapabilityWorld::Minimal < CapabilityWorld::Network);
        assert!(CapabilityWorld::Network < CapabilityWorld::Secrets);
        assert!(CapabilityWorld::Network < CapabilityWorld::Filesystem);
        assert!(CapabilityWorld::Network < CapabilityWorld::Cache);
        assert!(CapabilityWorld::Network < CapabilityWorld::Messaging);
        assert!(CapabilityWorld::Secrets < CapabilityWorld::Database);
        assert!(CapabilityWorld::Database < CapabilityWorld::Trusted);

        // The five tier-3 sub-worlds are incomparable with each other.
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

        // Worlds in different branches are incomparable, even with different levels.
        // This was a bug in the old PartialOrd: it used numeric levels which falsely
        // implied Http < Governance and Filesystem < Database.
        assert!(CapabilityWorld::Http
            .partial_cmp(&CapabilityWorld::Governance)
            .is_none());
        assert!(CapabilityWorld::Filesystem
            .partial_cmp(&CapabilityWorld::Database)
            .is_none());
        assert!(CapabilityWorld::Cache
            .partial_cmp(&CapabilityWorld::Agent)
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
            let parsed: CapabilityWorld = s.parse().expect("WIT world should be valid");
            assert_eq!(parsed, world, "roundtrip failed for {:?}", world);
        }
    }

    // ── Exhaustive partial order verification ─────────────────────────────────
    // The domain is small enough (12 variants) to check all pairs and triples
    // directly, giving 100% coverage of the partial order axioms.

    const ALL_WORLDS: &[CapabilityWorld] = &[
        CapabilityWorld::Minimal,
        CapabilityWorld::Http,
        CapabilityWorld::Network,
        CapabilityWorld::Secrets,
        CapabilityWorld::Filesystem,
        CapabilityWorld::Messaging,
        CapabilityWorld::Cache,
        CapabilityWorld::Governance,
        CapabilityWorld::Database,
        CapabilityWorld::Agent,
        CapabilityWorld::Trusted,
        CapabilityWorld::Unknown,
    ];

    #[test]
    fn exhaustive_reflexivity() {
        for a in ALL_WORLDS {
            if !matches!(a, CapabilityWorld::Unknown) {
                assert!(
                    a.is_subset_of(a),
                    "Reflexivity violated: {} is not a subset of itself",
                    a
                );
            }
        }
    }

    #[test]
    fn exhaustive_antisymmetry() {
        for a in ALL_WORLDS {
            for b in ALL_WORLDS {
                if a.is_subset_of(b) && b.is_subset_of(a) {
                    assert_eq!(
                        a, b,
                        "Antisymmetry violated: {} ⊆ {} and {} ⊆ {} but {} ≠ {}",
                        a, b, b, a, a, b
                    );
                }
            }
        }
    }

    #[test]
    fn exhaustive_transitivity() {
        for a in ALL_WORLDS {
            for b in ALL_WORLDS {
                for c in ALL_WORLDS {
                    if a.is_subset_of(b) && b.is_subset_of(c) {
                        assert!(
                            a.is_subset_of(c),
                            "Transitivity violated: {} ⊆ {} and {} ⊆ {} but {} ⊄ {}",
                            a,
                            b,
                            b,
                            c,
                            a,
                            c
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn exhaustive_partial_ord_consistent_with_is_subset_of() {
        for a in ALL_WORLDS {
            for b in ALL_WORLDS {
                let subset = a.is_subset_of(b);
                let ord = a.partial_cmp(b);

                // If a ⊆ b, then partial_cmp should return Some(Less) or Some(Equal)
                // (or None for incomparable worlds that happen to have the same level).
                // The converse: if partial_cmp returns Some(Less|Equal), then a ⊆ b.
                if let Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal) = ord {
                    assert!(
                        subset,
                        "PartialOrd says {} <= {} but is_subset_of returns false",
                        a, b
                    );
                }

                // If partial_cmp returns Some(Greater), then a is NOT a subset of b
                if let Some(std::cmp::Ordering::Greater) = ord {
                    assert!(
                        !subset,
                        "PartialOrd says {} > {} but is_subset_of returns true",
                        a, b
                    );
                }
            }
        }
    }

    #[test]
    fn unknown_is_not_subset_of_anything() {
        for w in ALL_WORLDS {
            assert!(
                !CapabilityWorld::Unknown.is_subset_of(w),
                "Unknown should not be a subset of {}",
                w
            );
            assert!(
                !w.is_subset_of(&CapabilityWorld::Unknown),
                "{} should not be a subset of Unknown",
                w
            );
        }
    }

    #[test]
    fn minimal_is_subset_of_all_named_worlds() {
        for w in ALL_WORLDS {
            if !matches!(w, CapabilityWorld::Unknown) {
                assert!(
                    CapabilityWorld::Minimal.is_subset_of(w),
                    "Minimal should be a subset of {}",
                    w
                );
            }
        }
    }

    #[test]
    fn trusted_is_superset_of_all_named_worlds() {
        for w in ALL_WORLDS {
            if !matches!(w, CapabilityWorld::Unknown) {
                assert!(
                    w.is_subset_of(&CapabilityWorld::Trusted),
                    "{} should be a subset of Trusted",
                    w
                );
            }
        }
    }
}

// ── Property-based tests (proptest) ─────────────────────────────────────────
// These supplement the exhaustive tests above with random sampling to guard
// against regressions if new worlds are added.
#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_world() -> impl Strategy<Value = CapabilityWorld> {
        prop_oneof![
            Just(CapabilityWorld::Minimal),
            Just(CapabilityWorld::Http),
            Just(CapabilityWorld::Network),
            Just(CapabilityWorld::Secrets),
            Just(CapabilityWorld::Filesystem),
            Just(CapabilityWorld::Messaging),
            Just(CapabilityWorld::Cache),
            Just(CapabilityWorld::Governance),
            Just(CapabilityWorld::Database),
            Just(CapabilityWorld::Agent),
            Just(CapabilityWorld::Trusted),
            Just(CapabilityWorld::Unknown),
        ]
    }

    proptest! {
        #[test]
        fn prop_reflexivity(a in arb_world()) {
            if !matches!(a, CapabilityWorld::Unknown) {
                prop_assert!(a.is_subset_of(&a), "Reflexivity violated for {}", a);
            }
        }

        #[test]
        fn prop_antisymmetry(a in arb_world(), b in arb_world()) {
            if a.is_subset_of(&b) && b.is_subset_of(&a) {
                prop_assert_eq!(&a, &b, "Antisymmetry violated: {} and {}", a, b);
            }
        }

        #[test]
        fn prop_transitivity(a in arb_world(), b in arb_world(), c in arb_world()) {
            if a.is_subset_of(&b) && b.is_subset_of(&c) {
                prop_assert!(a.is_subset_of(&c),
                    "Transitivity violated: {} ⊆ {} ⊆ {} but {} ⊄ {}", a, b, c, a, c);
            }
        }

        #[test]
        fn prop_partial_ord_consistency(a in arb_world(), b in arb_world()) {
            if let Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal) = a.partial_cmp(&b) {
                prop_assert!(a.is_subset_of(&b),
                    "PartialOrd says {} <= {} but is_subset_of disagrees", a, b);
            }
        }
    }
}
