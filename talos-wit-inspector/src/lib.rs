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
    // Model inference (RFC 0011) — secrets-node and above, same tier as llm
    "talos:core/model",
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
// What each WIT world imports
// ============================================================================
//
// The `talos:core/*` interfaces each world in `wit/talos.wit` imports. These
// tables ARE the rule for "does this binary fit that world": a binary fits a
// world when every interface it imports is in the world's table. The hand-
// written classifier below only names a world for a binary; the fit test
// never goes through it (2026-10-16: a compose module that imported only
// `agent-memory` classified as `trusted`, and a dispatch at its row's world,
// `agent`, was refused — every agent module that read memory without
// orchestrating stopped running). `world_imports_match_the_wit_file` holds
// these tables equal to the WIT file.

const BASE_IMPORTS: &[&str] = &[
    "talos:core/logging",
    "talos:core/json",
    "talos:core/datetime",
    "talos:core/crypto",
    "talos:core/env",
];

const SECRETS_IMPORTS: &[&str] = &[
    "talos:core/secrets",
    "talos:core/llm",
    "talos:core/llm-tools",
    "talos:core/llm-streaming",
    "talos:core/context-window",
    "talos:core/resource-quotas",
    "talos:core/embedding",
    "talos:core/model",
];

const DATABASE_ONLY_IMPORTS: &[&str] = &[
    "talos:core/database",
    "talos:core/agent-memory",
    "talos:core/graph-memory",
];

const AGENT_ONLY_IMPORTS: &[&str] = &[
    "talos:core/agent-memory",
    "talos:core/graph-memory",
    "talos:core/integration-state",
    "talos:core/governance",
    "talos:core/agent-orchestration",
];

const TRUSTED_ONLY_IMPORTS: &[&str] = &[
    "talos:core/files",
    "talos:core/cache",
    "talos:core/messaging",
    "talos:core/database",
    "talos:core/governance",
    "talos:core/agent-memory",
    "talos:core/graph-memory",
    "talos:core/integration-state",
    "talos:core/agent-orchestration",
    "talos:core/object-storage",
];

/// The `talos:core/*` interfaces the WIT world for `world` imports, or `None`
/// for `Unknown`. `network-node` imports what `http-node` does (raw sockets
/// are a `wasi:` grant, decided at runtime by the stored world, not an import).
pub fn world_imports(world: &CapabilityWorld) -> Option<Vec<&'static str>> {
    let tiers: &[&[&str]] = match world {
        CapabilityWorld::Minimal => &[BASE_IMPORTS],
        CapabilityWorld::Http | CapabilityWorld::Network => &[BASE_IMPORTS, NETWORK_TIER],
        CapabilityWorld::Secrets => &[BASE_IMPORTS, NETWORK_TIER, SECRETS_IMPORTS],
        CapabilityWorld::Filesystem => &[BASE_IMPORTS, NETWORK_TIER, &["talos:core/files"]],
        CapabilityWorld::Messaging => &[BASE_IMPORTS, NETWORK_TIER, &["talos:core/messaging"]],
        CapabilityWorld::Cache => &[BASE_IMPORTS, NETWORK_TIER, &["talos:core/cache"]],
        CapabilityWorld::Governance => &[BASE_IMPORTS, NETWORK_TIER, &["talos:core/governance"]],
        CapabilityWorld::Database => &[
            BASE_IMPORTS,
            NETWORK_TIER,
            SECRETS_IMPORTS,
            DATABASE_ONLY_IMPORTS,
        ],
        CapabilityWorld::Agent => &[
            BASE_IMPORTS,
            NETWORK_TIER,
            SECRETS_IMPORTS,
            AGENT_ONLY_IMPORTS,
        ],
        CapabilityWorld::Trusted => &[
            BASE_IMPORTS,
            NETWORK_TIER,
            SECRETS_IMPORTS,
            TRUSTED_ONLY_IMPORTS,
        ],
        CapabilityWorld::Unknown => return None,
    };
    Some(tiers.iter().flat_map(|t| t.iter().copied()).collect())
}

/// The interfaces in `imports` that the WIT world for `world` does not
/// import, sorted. Empty means the binary fits the world. Every interface is
/// outside `Unknown`.
pub fn imports_outside_world(imports: &[String], world: &CapabilityWorld) -> Vec<String> {
    let Some(admitted) = world_imports(world) else {
        let mut all = imports.to_vec();
        all.sort();
        return all;
    };
    let mut outside: Vec<String> = imports
        .iter()
        .filter(|i| !admitted.contains(&i.as_str()))
        .cloned()
        .collect();
    outside.sort();
    outside.dedup();
    outside
}

/// Worlds from narrowest to widest, as the classifier tries them. Among the
/// two incomparable tier-4 worlds `agent-node` comes first: it is the WIT
/// file's preferred world for a module that reads memory, and it grants no
/// raw SQL.
const WORLDS_NARROW_TO_WIDE: &[CapabilityWorld] = &[
    CapabilityWorld::Minimal,
    CapabilityWorld::Http,
    CapabilityWorld::Secrets,
    CapabilityWorld::Governance,
    CapabilityWorld::Filesystem,
    CapabilityWorld::Messaging,
    CapabilityWorld::Cache,
    CapabilityWorld::Agent,
    CapabilityWorld::Database,
    CapabilityWorld::Trusted,
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

        // The import section is ground truth. The world sentinel — a string
        // the SDK macro embeds as a data-segment static, scanned for over the
        // whole binary — may RAISE the world to one that covers what the
        // imports need (a source that declared more than survived DCE), never
        // lower it below them (security review 2026-10-15, E2-7: a binary
        // importing `secrets` with the minimal sentinel embedded inspected as
        // `Minimal`, and the world recorded and the ceilings asked were read
        // off an author-steerable string).
        if let Some(world) = detect_world_from_type_section(wasm_bytes) {
            capability_world = sentinel_never_narrows(capability_world, world, &interfaces);
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
/// The test is on the IMPORT SET, never on the classified world: the binary
/// fits `declared` when every `talos:core/*` interface it imports is one the
/// declared WIT world imports ([`imports_outside_world`]). Two worlds can be
/// incomparable (`agent-node` and `database-node` both import
/// `agent-memory`), so a binary importing only `agent-memory` fits either,
/// and asking "is its classified world a subset of the declared one" refused
/// it for both (2026-10-16).
///
/// Returns `Err` if:
/// - The component is not a recognised Talos node (`Unknown` capability world).
/// - The declared world is `Unknown`.
/// - The component imports an interface outside the declared world.
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
    if *declared == CapabilityWorld::Unknown {
        return Err(format!(
            "Component cannot be checked against an unknown declared world \
             (inspected as {}). Imported interfaces: {}",
            inspection.capability_world,
            inspection.imported_interfaces.join(", ")
        ));
    }
    let outside = imports_outside_world(&inspection.imported_interfaces, declared);
    if !outside.is_empty() {
        return Err(format!(
            "Component imports capabilities outside its declared world: \
             declared={}, outside={}, inspected={}. \
             Imported interfaces: {}",
            declared,
            outside.join(", "),
            inspection.capability_world,
            inspection.imported_interfaces.join(", ")
        ));
    }
    Ok(())
}

/// The world a component is LINKED at, given the dispatcher's world hint and
/// the inspection of the binary that is about to run. The one decision the
/// worker makes before it instantiates a component (security review
/// 2026-10-14, G-1).
///
/// - A hint (the module row's world, which every gate checked) is the link
///   world, and a binary whose inspected world is NOT a subset of it is
///   refused here, before instantiation — [`validate_capability_level`]. The
///   hint's tiered linker would refuse the extra imports anyway; this makes
///   the refusal explicit and names the worlds.
/// - A hint with an `Unknown` inspection links at the hint: inspection can
///   lose the world-name strings (a Wizer snapshot), and the hint's linker
///   resolves only the hint's imports, so nothing wider can link.
/// - No hint (or an `Unknown` hint) links at the inspected world — the legacy
///   shape. Every production dispatch now sends a hint; a construction site
///   that sends none carries `// no-world-hint: <reason>` (lint check 99).
pub fn link_world(
    hint: Option<&CapabilityWorld>,
    inspection: &ComponentInspection,
) -> Result<CapabilityWorld, String> {
    match hint {
        Some(h) if *h != CapabilityWorld::Unknown => {
            if inspection.capability_world != CapabilityWorld::Unknown {
                validate_capability_level(inspection, h)?;
            }
            Ok(h.clone())
        }
        _ => Ok(inspection.capability_world.clone()),
    }
}

// ============================================================================
// Private helpers
// ============================================================================

/// The world of a component that has imports, given the world its imports
/// need (`classified`), the world its sentinel names and the imports
/// themselves: the sentinel when the imports fit it, the imports' world
/// otherwise. Asked of the imports, not of `classified`: `agent-node` and
/// `database-node` are incomparable, so a binary importing only
/// `agent-memory` (classified `agent`) with the database sentinel fits
/// `database-node` and is named so.
fn sentinel_never_narrows(
    classified: CapabilityWorld,
    sentinel: CapabilityWorld,
    imports: &[String],
) -> CapabilityWorld {
    if imports_outside_world(imports, &sentinel).is_empty() {
        sentinel
    } else {
        classified
    }
}

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
    // NOTE: No `talos:core` pre-filter here. The WIT worlds export just `run`
    // (not `talos:core/...`), so when DCE removes all import calls the binary
    // contains no `talos:core` strings at all — but cargo-component still embeds
    // the world name string (e.g. `minimal-node`) in the component type section.
    // The world-name patterns are specific enough to avoid false positives against
    // arbitrary non-Talos WASM, and the tiered linker enforces real security.
    //
    // Sentinel tier: the explicit `__talos_world_<name>__` marker our codegen
    // embeds — one per module by construction, so first match wins.
    const SENTINEL_PATTERNS: &[(&[u8], CapabilityWorld)] = &[
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
    ];
    for (pattern, world) in SENTINEL_PATTERNS {
        if bytes_contain(bytes, pattern) {
            return Some(world.clone());
        }
    }

    // Legacy tier: bare world-name substrings, as embedded by cargo-component
    // (which encodes exactly ONE — its own world). A bare-name match is only
    // trustworthy when it is UNIQUE: componentize-py embeds the ENTIRE
    // consumed WIT text — every world's name — so first-match-wins classified
    // every Python module as `Database` (the first pattern), silently
    // INFLATING its stored world and therefore what the tiered linker grants
    // at runtime. Ambiguity (>1 distinct world name present) returns None so
    // classification falls back to the component's PARSED import section —
    // ground truth, and exhaustive for foreign toolchains, which bind every
    // interface their world declares (no DCE).
    const LEGACY_PATTERNS: &[(&[u8], CapabilityWorld)] = &[
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
    let mut found: Option<CapabilityWorld> = None;
    for (pattern, world) in LEGACY_PATTERNS {
        if bytes_contain(bytes, pattern) {
            if found.is_some() {
                // Two distinct world names in one binary = an embedded WIT
                // document, not a world tag. Refuse to guess.
                return None;
            }
            found = Some(world.clone());
        }
    }
    found
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

/// Name a world for a binary from its import set: the NARROWEST world whose
/// WIT imports cover every interface the binary imports
/// ([`WORLDS_NARROW_TO_WIDE`]). An interface no world imports escalates to
/// `Trusted` (safe default). This is a NAME for the binary — what a row
/// records, what a no-hint link uses — not the fit test; that is
/// [`imports_outside_world`], which a dispatcher asks against the row's own
/// world.
fn classify_world(imports: &HashSet<String>, has_sockets: bool) -> CapabilityWorld {
    // NOTE: `has_sockets` deliberately does NOT escalate the world.
    // Interpreter-based toolchains (componentize-py) structurally import
    // wasi:sockets for their embedded runtime regardless of the talos
    // world — escalating on the import alone classified every Python
    // module as Network, GRANTING it raw sockets (the world drives
    // `allow_wasi_network`). Classification follows the talos:core
    // surface; the socket boundary is enforced at RUNTIME by the
    // context flag derived from the module's stored world (all tier
    // linkers satisfy the wasi:sockets import; non-socket worlds deny
    // the calls — see worker runtime `select_tier`'s layer notes).
    let _ = has_sockets;
    let imports: Vec<String> = imports.iter().cloned().collect();
    WORLDS_NARROW_TO_WIDE
        .iter()
        .find(|w| imports_outside_world(&imports, w).is_empty())
        .cloned()
        .unwrap_or(CapabilityWorld::Trusted)
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
    fn sockets_import_does_not_escalate_world() {
        // A structural wasi:sockets import must NOT bump the classification:
        // interpreter toolchains (componentize-py) import it for their
        // embedded runtime regardless of the talos world, and the world is
        // what GRANTS sockets at runtime (allow_wasi_network derives from the
        // stored world; non-socket worlds deny the calls). Classification
        // follows the talos:core surface only.
        let imports = make_imports(&["talos:core/logging", "talos:core/http"]);
        assert_eq!(classify_world(&imports, true), CapabilityWorld::Http);
        let minimal = make_imports(&["talos:core/logging", "talos:core/json"]);
        assert_eq!(classify_world(&minimal, true), CapabilityWorld::Minimal);
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

    // ── link_world ──────────────────────────────────────────────────────────

    fn inspected(world: CapabilityWorld, interfaces: &[&str]) -> ComponentInspection {
        ComponentInspection {
            capability_world: world,
            imported_interfaces: interfaces.iter().map(|s| s.to_string()).collect(),
            is_talos_node: true,
        }
    }

    #[test]
    fn a_binary_wider_than_its_hint_is_refused() {
        // A row labelled minimal whose binary imports secrets: the label is
        // what every gate checked, the binary is what would run.
        let wide = inspected(CapabilityWorld::Secrets, &["talos:core/secrets"]);
        let err = link_world(Some(&CapabilityWorld::Minimal), &wide).unwrap_err();
        assert!(err.contains("outside its declared world"), "{err}");
        let trusted = inspected(CapabilityWorld::Trusted, &["talos:core/database"]);
        assert!(link_world(Some(&CapabilityWorld::Http), &trusted).is_err());
    }

    #[test]
    fn a_binary_within_its_hint_links_at_the_hint() {
        let narrow = inspected(CapabilityWorld::Minimal, &[]);
        assert_eq!(
            link_world(Some(&CapabilityWorld::Http), &narrow).unwrap(),
            CapabilityWorld::Http
        );
        let exact = inspected(CapabilityWorld::Secrets, &["talos:core/secrets"]);
        assert_eq!(
            link_world(Some(&CapabilityWorld::Secrets), &exact).unwrap(),
            CapabilityWorld::Secrets
        );
    }

    #[test]
    fn an_uninspectable_binary_links_at_its_hint() {
        let unknown = inspected(CapabilityWorld::Unknown, &[]);
        assert_eq!(
            link_world(Some(&CapabilityWorld::Minimal), &unknown).unwrap(),
            CapabilityWorld::Minimal
        );
    }

    #[test]
    fn without_a_hint_the_inspected_world_is_linked() {
        let wide = inspected(CapabilityWorld::Trusted, &["talos:core/database"]);
        assert_eq!(link_world(None, &wide).unwrap(), CapabilityWorld::Trusted);
        assert_eq!(
            link_world(Some(&CapabilityWorld::Unknown), &wide).unwrap(),
            CapabilityWorld::Trusted
        );
    }

    // ── the fit is on the import set, not the classified world ─────────────

    /// 2026-10-16, the live break: a compose module imported only
    /// `agent-memory`, the classifier named it `trusted` (no arm matched),
    /// and the dispatch at its row's world `agent` was refused. The fit is
    /// asked of the imports: `agent-memory` is an import of `agent-node` and
    /// of `database-node`, so the binary links at either; it is not one of
    /// `secrets-node` or `http-node`, so those refuse.
    #[test]
    fn a_memory_reading_module_links_at_agent_and_at_database() {
        // The classified world is set to Trusted on purpose: the fit must not
        // read it.
        let memory_only = inspected(CapabilityWorld::Trusted, &["talos:core/agent-memory"]);
        assert_eq!(
            link_world(Some(&CapabilityWorld::Agent), &memory_only).unwrap(),
            CapabilityWorld::Agent
        );
        assert_eq!(
            link_world(Some(&CapabilityWorld::Database), &memory_only).unwrap(),
            CapabilityWorld::Database
        );
        let err = link_world(Some(&CapabilityWorld::Secrets), &memory_only).unwrap_err();
        assert!(err.contains("outside its declared world"), "{err}");
        assert!(err.contains("outside=talos:core/agent-memory"), "{err}");
        assert!(link_world(Some(&CapabilityWorld::Http), &memory_only).is_err());

        // With secrets and an LLM beside it, the same holds.
        let agent_compose = inspected(
            CapabilityWorld::Trusted,
            &[
                "talos:core/agent-memory",
                "talos:core/llm",
                "talos:core/secrets",
            ],
        );
        assert!(link_world(Some(&CapabilityWorld::Agent), &agent_compose).is_ok());
        assert!(link_world(Some(&CapabilityWorld::Database), &agent_compose).is_ok());
        assert!(link_world(Some(&CapabilityWorld::Secrets), &agent_compose).is_err());
    }

    #[test]
    fn the_fit_names_every_interface_outside_the_world() {
        let wide = inspected(
            CapabilityWorld::Trusted,
            &["talos:core/files", "talos:core/cache", "talos:core/http"],
        );
        let err = validate_capability_level(&wide, &CapabilityWorld::Secrets).unwrap_err();
        assert!(
            err.contains("outside=talos:core/cache, talos:core/files"),
            "{err}"
        );
        // An interface no world imports fits only nowhere.
        let foreign = inspected(CapabilityWorld::Trusted, &["talos:core/not-a-thing"]);
        assert!(validate_capability_level(&foreign, &CapabilityWorld::Trusted).is_err());
        // An unknown declared world is refused, whatever the binary.
        let narrow = inspected(CapabilityWorld::Minimal, &[]);
        assert!(validate_capability_level(&narrow, &CapabilityWorld::Unknown).is_err());
    }

    /// The classifier names the NARROWEST world whose imports cover the
    /// binary's; `agent-node` before `database-node` among the tier-4 pair.
    #[test]
    fn classification_is_the_narrowest_covering_world() {
        use CapabilityWorld as W;
        let c = |ifaces: &[&str]| classify_world(&make_imports(ifaces), false);
        assert_eq!(c(&["talos:core/agent-memory"]), W::Agent);
        assert_eq!(
            c(&["talos:core/agent-memory", "talos:core/secrets"]),
            W::Agent
        );
        assert_eq!(
            c(&["talos:core/governance", "talos:core/secrets"]),
            W::Agent
        );
        assert_eq!(c(&["talos:core/governance"]), W::Governance);
        assert_eq!(c(&["talos:core/database"]), W::Database);
        assert_eq!(
            c(&["talos:core/database", "talos:core/secrets"]),
            W::Database
        );
        assert_eq!(c(&["talos:core/secrets", "talos:core/llm"]), W::Secrets);
        assert_eq!(c(&["talos:core/http", "talos:core/email"]), W::Http);
        assert_eq!(c(&["talos:core/logging"]), W::Minimal);
        assert_eq!(c(&["talos:core/files", "talos:core/cache"]), W::Trusted);
        assert_eq!(c(&["talos:core/object-storage"]), W::Trusted);
        assert_eq!(c(&["talos:core/not-a-thing"]), W::Trusted);
    }

    /// On a real component: imports `agent-memory` only, carries the
    /// `agent-node` sentinel. It inspects as `Agent` and fits `agent-node`.
    #[test]
    fn a_real_memory_only_component_inspects_as_agent_and_fits_it() {
        let bytes = wat::parse_str(
            r#"(component
                 (import "talos:core/agent-memory" (instance))
                 (core module
                   (memory 1)
                   (data (i32.const 0) "__talos_world_agent-node__")))"#,
        )
        .expect("component");
        let inspection = inspect_component(&bytes);
        assert_eq!(
            inspection.imported_interfaces,
            vec!["talos:core/agent-memory".to_string()]
        );
        assert_eq!(inspection.capability_world, CapabilityWorld::Agent);
        assert_eq!(
            link_world(Some(&CapabilityWorld::Agent), &inspection).unwrap(),
            CapabilityWorld::Agent
        );
        // The same binary with the database sentinel is named `database`
        // (it fits), and still links at either tier-4 world.
        let bytes = wat::parse_str(
            r#"(component
                 (import "talos:core/agent-memory" (instance))
                 (core module
                   (memory 1)
                   (data (i32.const 0) "__talos_world_database-node__")))"#,
        )
        .expect("component");
        let inspection = inspect_component(&bytes);
        assert_eq!(inspection.capability_world, CapabilityWorld::Database);
        assert!(link_world(Some(&CapabilityWorld::Agent), &inspection).is_ok());
    }

    /// The import tables are the WIT file's, world by world. Parsed from
    /// `wit/talos.wit` at test time so a world that gains or loses an import
    /// fails here, not at a dispatch.
    #[test]
    fn world_imports_match_the_wit_file() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../wit/talos.wit");
        let wit = std::fs::read_to_string(path).expect("wit/talos.wit is readable");
        let mut worlds: std::collections::HashMap<String, Vec<String>> = Default::default();
        let mut current: Option<String> = None;
        for line in wit.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("world ") {
                let name = rest.trim_end_matches('{').trim().to_string();
                current = Some(name.clone());
                worlds.entry(name).or_default();
            } else if t == "}" {
                current = None;
            } else if let (Some(w), Some(import)) = (&current, t.strip_prefix("import ")) {
                let import = import.trim_end_matches(';').trim();
                // `wasi:` imports and `export`s are not talos:core interfaces.
                if !import.contains(':') {
                    worlds
                        .get_mut(w)
                        .unwrap()
                        .push(format!("talos:core/{import}"));
                }
            }
        }
        for world in CapabilityWorld::ALL {
            let wit_name = world.as_node_str();
            let mut from_wit = worlds
                .get(wit_name)
                .unwrap_or_else(|| panic!("world {wit_name} is in wit/talos.wit"))
                .clone();
            from_wit.sort();
            from_wit.dedup();
            let mut from_table: Vec<String> = world_imports(world)
                .expect("a known world has a table")
                .into_iter()
                .map(str::to_string)
                .collect();
            from_table.sort();
            from_table.dedup();
            assert_eq!(
                from_table, from_wit,
                "imports of {wit_name} differ from wit/talos.wit"
            );
        }
        assert!(world_imports(&CapabilityWorld::Unknown).is_none());
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
    fn type_section_scan_single_world_name_is_trusted() {
        // cargo-component shape: exactly one bare world name embedded.
        let blob = b"...some component bytes...secrets-node...more bytes...";
        assert_eq!(
            detect_world_from_type_section(blob),
            Some(CapabilityWorld::Secrets)
        );
    }

    #[test]
    fn type_section_scan_refuses_ambiguous_world_names() {
        // componentize-py shape: the consumed WIT text (every world name) is
        // embedded verbatim. First-match-wins classified these as Database —
        // world inflation for a minimal module. Ambiguity must return None so
        // the parsed import section decides.
        let blob =
            b"world minimal-node {} world http-node {} world database-node {} world agent-node {}";
        assert_eq!(detect_world_from_type_section(&blob[..]), None);
    }

    #[test]
    fn a_sentinel_never_narrows_the_world_the_imports_need() {
        use CapabilityWorld as W;
        let secrets = vec!["talos:core/secrets".to_string()];
        let http = vec!["talos:core/http".to_string()];
        // Narrower than the imports: the imports win.
        assert_eq!(
            sentinel_never_narrows(W::Secrets, W::Minimal, &secrets),
            W::Secrets
        );
        assert_eq!(sentinel_never_narrows(W::Http, W::Minimal, &http), W::Http);
        // Covering the imports: the declared (wider) world stands.
        assert_eq!(
            sentinel_never_narrows(W::Http, W::Trusted, &http),
            W::Trusted
        );
        assert_eq!(
            sentinel_never_narrows(W::Secrets, W::Secrets, &secrets),
            W::Secrets
        );
        // Incomparable but fitting: a memory-only binary names `agent`, and
        // the database sentinel, which imports agent-memory too, stands.
        let memory = vec!["talos:core/agent-memory".to_string()];
        assert_eq!(
            sentinel_never_narrows(W::Agent, W::Database, &memory),
            W::Database
        );
    }

    /// E2-7 (2026-10-15), on a real component: it imports
    /// `talos:core/secrets` and carries the MINIMAL sentinel in a data
    /// segment. It inspects as `Secrets`, never `Minimal`.
    #[test]
    fn a_secrets_importing_component_with_the_minimal_sentinel_inspects_as_secrets() {
        let bytes = wat::parse_str(
            r#"(component
                 (import "talos:core/secrets" (instance))
                 (core module
                   (memory 1)
                   (data (i32.const 0) "__talos_world_minimal-node__")))"#,
        )
        .expect("component");
        let inspection = inspect_component(&bytes);
        assert!(inspection
            .imported_interfaces
            .contains(&"talos:core/secrets".to_string()));
        assert_eq!(inspection.capability_world, CapabilityWorld::Secrets);
    }

    #[test]
    fn type_section_sentinel_still_wins_outright() {
        // The explicit codegen sentinel is one-per-module by construction and
        // must keep first-match semantics even alongside stray bare names.
        let blob = b"__talos_world_http-node__ ... minimal-node ... database-node";
        assert_eq!(
            detect_world_from_type_section(&blob[..]),
            Some(CapabilityWorld::Http)
        );
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
