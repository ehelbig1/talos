//! WIT Component Inspector
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
    /// Secrets + LLM + agent-memory + governance + agent-orchestration.
    /// No filesystem, cache, messaging, database, or object-storage.
    Agent,
    /// Full platform capabilities — everything in `network-node` plus secrets,
    /// files, Redis cache, NATS messaging, and database access.
    Trusted,
    /// Not a Talos component, or uses an unrecognised set of imports.
    Unknown,
}

#[allow(dead_code)]
impl CapabilityWorld {
    /// Canonical compile-time list of every named, compilable world the
    /// worker recognises. Order is deliberately "ascending privilege" so
    /// callers iterating for UX purposes produce stable, low-to-high output.
    /// Deliberately omits `Unknown` — it is not a selectable world.
    ///
    /// Controller-side schema registration uses this via `all_strs()` to
    /// publish JSON-Schema `"enum"` values for every tool that accepts a
    /// capability world. Maintaining the list here means controller schemas
    /// stay in lockstep with what the worker actually parses — no drift.
    pub const ALL: &'static [Self] = &[
        Self::Minimal,
        Self::Http,
        Self::Network,
        Self::Secrets,
        Self::Governance,
        Self::Messaging,
        Self::Filesystem,
        Self::Cache,
        Self::Database,
        Self::Agent,
        Self::Trusted,
    ];

    /// Canonical short form ("minimal", "http", ...) shared with `FromStr`
    /// and `Display`. Returns `"unknown"` for `Unknown` so the helper is
    /// total — callers that want to reject `Unknown` should filter before
    /// invoking.
    ///
    /// Paired with the suffixed-form consumer-facing aliases used by the
    /// MCP schemas. [`Self::as_node_str`] returns the `-node`-suffixed form.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Http => "http",
            Self::Network => "network",
            Self::Secrets => "secrets",
            Self::Filesystem => "filesystem",
            Self::Messaging => "messaging",
            Self::Cache => "cache",
            Self::Database => "database",
            Self::Governance => "governance",
            Self::Agent => "agent",
            Self::Trusted => "trusted",
            Self::Unknown => "unknown",
        }
    }

    /// Suffixed form used by MCP tool schemas and the CapabilityWorld
    /// references in `talos.wit` (e.g. `"minimal-node"`, `"agent-node"`).
    /// For `Trusted`, returns `"automation-node"` — the public-facing name —
    /// matching the `FromStr` alias.
    pub const fn as_node_str(&self) -> &'static str {
        match self {
            Self::Minimal => "minimal-node",
            Self::Http => "http-node",
            Self::Network => "network-node",
            Self::Secrets => "secrets-node",
            Self::Filesystem => "filesystem-node",
            Self::Messaging => "messaging-node",
            Self::Cache => "cache-node",
            Self::Database => "database-node",
            Self::Governance => "governance-node",
            Self::Agent => "agent-node",
            Self::Trusted => "automation-node",
            Self::Unknown => "unknown",
        }
    }

    /// All compilable capability worlds in `-node` form, in the order of
    /// [`Self::ALL`]. This is the slice controller MCP schemas should use
    /// to publish JSON-Schema `"enum"` values.
    ///
    /// Returns a static slice — no allocation.
    pub fn all_strs() -> &'static [&'static str] {
        // Built once, reused forever. Order mirrors ALL.
        static ALL_STRS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
        ALL_STRS
            .get_or_init(|| {
                CapabilityWorld::ALL
                    .iter()
                    .map(|w| w.as_node_str())
                    .collect()
            })
            .as_slice()
    }

    /// Approximate numeric privilege level for display/logging purposes.
    ///
    /// NOTE: This is NOT used for ordering — `PartialOrd` is derived from
    /// `is_subset_of` which correctly handles the branching lattice.
    ///
    /// Returns `None` for `Unknown` (incomparable to everything).
    ///
    /// Level mapping:
    ///   Minimal=0, Http=1, Network=2, tier-3 sub-worlds=3, tier-4 (Database|Agent)=4, Trusted=5
    fn level(&self) -> Option<u8> {
        match self {
            Self::Minimal => Some(0),
            Self::Http => Some(1),
            Self::Network => Some(2),
            // Tier-3 sub-worlds share level 3 but are incomparable with each other.
            Self::Secrets | Self::Filesystem | Self::Messaging | Self::Cache | Self::Governance => {
                Some(3)
            }
            // Tier-4: Database and Agent are incomparable with each other.
            Self::Database | Self::Agent => Some(4),
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
    /// - `Secrets` ⊆ `Database | Agent | Trusted`.
    /// - `Governance` ⊆ `Agent | Trusted`.
    /// - `Filesystem | Messaging | Cache` ⊆ `Trusted` only.
    /// - `Database` ⊆ `Trusted` only.
    /// - `Agent` ⊆ `Trusted` only.
    /// - `Database` and `Agent` are incomparable (neither is a subset of the other).
    /// - `Trusted` is only a subset of itself.
    /// - `Unknown` is not a subset of anything (invalid component).
    pub fn is_subset_of(&self, other: &Self) -> bool {
        if matches!(self, Self::Unknown) || matches!(other, Self::Unknown) {
            return false;
        }
        if self == other {
            return true;
        }
        match (self, other) {
            (Self::Minimal, _) => true,
            (
                Self::Http,
                Self::Network
                | Self::Secrets
                | Self::Filesystem
                | Self::Messaging
                | Self::Cache
                | Self::Database
                | Self::Agent
                | Self::Trusted,
            ) => true,
            (Self::Http, _) => false,
            (
                Self::Network,
                Self::Secrets
                | Self::Filesystem
                | Self::Messaging
                | Self::Cache
                | Self::Database
                | Self::Agent
                | Self::Trusted,
            ) => true,
            (Self::Network, _) => false,
            // Secrets can escalate to Database, Agent, or Trusted.
            (Self::Secrets, Self::Database | Self::Agent | Self::Trusted) => true,
            (Self::Secrets, _) => false,
            (Self::Filesystem, Self::Trusted) => true,
            (Self::Filesystem, _) => false,
            (Self::Messaging, Self::Trusted) => true,
            (Self::Messaging, _) => false,
            (Self::Cache, Self::Trusted) => true,
            (Self::Cache, _) => false,
            // Governance can escalate to Agent or Trusted.
            (Self::Governance, Self::Agent | Self::Trusted) => true,
            (Self::Governance, _) => false,
            // Database and Agent can only escalate to Trusted (incomparable with each other).
            (Self::Database, Self::Trusted) => true,
            (Self::Database, _) => false,
            (Self::Agent, Self::Trusted) => true,
            (Self::Agent, _) => false,
            (Self::Trusted, _) => false,
            (Self::Unknown, _) => unreachable!("Unknown filtered by guard above"),
        }
    }
}

/// Partial order derived from `is_subset_of` to guarantee consistency.
///
/// `a <= b` iff `a.is_subset_of(b)`. This correctly handles the branching
/// lattice structure where worlds in different branches (e.g., Filesystem vs
/// Database, Http vs Governance) are incomparable even though they have
/// different numeric levels.
impl PartialOrd for CapabilityWorld {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let a_sub_b = self.is_subset_of(other);
        let b_sub_a = other.is_subset_of(self);
        match (a_sub_b, b_sub_a) {
            (true, true) => Some(std::cmp::Ordering::Equal),
            (true, false) => Some(std::cmp::Ordering::Less),
            (false, true) => Some(std::cmp::Ordering::Greater),
            (false, false) => None, // incomparable
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
            Self::Governance => write!(f, "governance"),
            Self::Agent => write!(f, "agent"),
            Self::Trusted => write!(f, "trusted"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::str::FromStr for CapabilityWorld {
    type Err = String;

    /// Parse a capability-world string — accepts both the short form
    /// (`"minimal"`) and the `-node`-suffixed form (`"minimal-node"`).
    ///
    /// Unknown strings return [`Self::Unknown`] (the parser is total) so
    /// callers can still round-trip arbitrary user input. Validation
    /// (rejecting `Unknown`) happens at higher layers that know the set of
    /// acceptable worlds for a given context.
    ///
    /// `llm-node` is **intentionally NOT recognised here.** It is an
    /// actor-ceiling privilege-tier label only — native LLM bindings do
    /// not compile to a distinct WIT world in `talos.wit`. If you receive
    /// `"llm-node"` from the actor layer, do NOT pass it to the
    /// compiler/worker; it is used exclusively by `create_actor` and
    /// `grant_capability_ceiling` for RBAC rank comparison. Any attempt
    /// to parse it here would silently map to `Unknown` — that is the
    /// correct, safe behaviour but callers should filter it upstream
    /// rather than depend on falling through.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "minimal" | "minimal-node" => Ok(Self::Minimal),
            "http" | "http-node" => Ok(Self::Http),
            "network" | "network-node" => Ok(Self::Network),
            "secrets" | "secrets-node" => Ok(Self::Secrets),
            "filesystem" | "filesystem-node" => Ok(Self::Filesystem),
            "messaging" | "messaging-node" => Ok(Self::Messaging),
            "cache" | "cache-node" => Ok(Self::Cache),
            "database" | "database-node" => Ok(Self::Database),
            "governance" | "governance-node" => Ok(Self::Governance),
            "agent" | "agent-node" => Ok(Self::Agent),
            // automation-node is the highest-privilege sandbox world (alias for Trusted)
            "trusted" | "trusted-node" | "automation-node" => Ok(Self::Trusted),
            _ => Ok(Self::Unknown),
        }
    }
}

// ============================================================================
// World rank (privilege level — lower = less privileged)
// ============================================================================

/// Rank a WIT world string by privilege level.
///
/// Ranks mirror the Talos WIT world hierarchy (talos.wit). Tier 3 siblings
/// (secrets/filesystem/messaging/cache/governance) share the same tier but
/// occupy distinct ranks so that higher-ceiling agents can use lower-ranked
/// siblings (a conservative but safe approximation of the DAG-based
/// hierarchy).
///
/// `Unknown` worlds map to the most privileged rank (7) — the safest
/// default, since refusing the call is preferable to silently allowing
/// it. Callers that want a different default should match on the input
/// before delegating.
///
/// `*-node` suffixes (`http-node`, `messaging-node`, etc.) are stripped
/// before lookup so worker-side capability worlds and controller-side
/// dispatch worlds rank identically.
#[must_use]
pub fn world_rank(world: &str) -> u8 {
    match world.trim_end_matches("-node") {
        "minimal" => 0,
        "http" => 1,
        "llm" => 2,                    // Tier 2b: http + native LLM bindings (no vault)
        "network" => 2,                // Tier 2: raw sockets (same rank as llm)
        "secrets" => 3,                // Tier 3a: network + secrets vault
        "governance" => 3,             // Tier 3e: network + human approvals (same tier)
        "messaging" => 4,              // Tier 3c: network + NATS pub/sub
        "filesystem" => 4,             // Tier 3b: network + file I/O (same tier as messaging)
        "cache" => 5,                  // Tier 3d: network + Redis cache
        "database" => 6,               // Tier 4a: network + secrets + SQL
        "agent" => 6,                  // Tier 4b: secrets + memory + governance + orchestration
        "automation" | "trusted" => 7, // Tier 5:  all interfaces
        _ => 7, // Unknown → most privileged (safest default: won't silently allow)
    }
}

// ============================================================================
// Capability-ceiling gate (partial-order lattice — the CORRECT semantics)
// ============================================================================

/// Map a capability-world string to its position in the [`CapabilityWorld`]
/// lattice for ceiling comparison. Accepts both the short (`"secrets"`) and
/// `-node`-suffixed (`"secrets-node"`) forms.
///
/// `llm-node` is an actor-ceiling-only privilege tier with **no distinct WIT
/// world** — its capabilities are `http` + native LLM bindings (vault access
/// is gated separately by `max_llm_tier`, never by the capability world). For
/// lattice comparison it therefore maps to [`CapabilityWorld::Http`]: an
/// `llm-node` ceiling permits exactly the modules an `http-node` ceiling does
/// (it does NOT grant raw sockets / `network`, secrets, files, cache, etc.).
///
/// Returns `None` for any unrecognised string (including `Unknown`) so callers
/// fail closed.
fn lattice_world(world: &str) -> Option<CapabilityWorld> {
    if world_short(world) == "llm" {
        return Some(CapabilityWorld::Http);
    }
    // `FromStr` accepts both the short and `-node` forms for every world
    // EXCEPT the `automation`/`trusted` alias group, where bare `automation`
    // is not recognised (only `automation-node` / `trusted` / `trusted-node`).
    // Try the string as given, then its `-node` form, so every spelling
    // (`secrets`, `secrets-node`, `automation`, `automation-node`) resolves.
    let parse = |s: &str| match s.parse::<CapabilityWorld>() {
        Ok(CapabilityWorld::Unknown) | Err(_) => None,
        Ok(w) => Some(w),
    };
    parse(world).or_else(|| parse(&format!("{}-node", world_short(world))))
}

/// Returns `true` iff a principal or module requiring `requested` capabilities
/// is permitted to run under a `ceiling` capability world, using the
/// **partial-order lattice** ([`CapabilityWorld::is_subset_of`]) rather than a
/// linear rank.
///
/// This is the canonical actor/user capability-ceiling gate. It replaces the
/// legacy `world_rank(requested) <= world_rank(ceiling)` comparison, which was
/// unsound for lattice-INCOMPARABLE siblings: e.g. a `cache-node` ceiling
/// (rank 5) wrongly admitted a `secrets-node` module (rank 3) even though
/// `Secrets ⊄ Cache`, letting a vault-denied actor resolve real secrets at
/// runtime (the worker enforces only the *module's* own world, never the
/// actor's ceiling, so the ceiling gate is the only barrier).
///
/// `is_subset_of` strictly subsumes the old rank gate: every subset edge in
/// the lattice has `world_rank(sub) <= world_rank(super)`, so `req_rank >
/// max_rank` implies `!is_subset_of` — the lattice check rejects a superset of
/// what the rank check rejected, and never loses a legitimate escalation path
/// (`Minimal`/`Http`/`Network` → anything, `Secrets` → `Database`/`Agent`/
/// `Trusted`, `Governance` → `Agent`/`Trusted`).
///
/// Fail-closed: if either side is unrecognised (malformed / legacy actor row,
/// typo'd module world), returns `false`.
#[must_use]
pub fn ceiling_permits(ceiling: &str, requested: &str) -> bool {
    match (lattice_world(ceiling), lattice_world(requested)) {
        (Some(c), Some(r)) => r.is_subset_of(&c),
        _ => false,
    }
}

/// True if `world` names a recognised capability world (short `secrets` or
/// `-node`-suffixed `secrets-node` form). Lets callers distinguish "unknown
/// world" from "known-but-incompatible" for clear error messages, while still
/// routing the actual compatibility decision through [`ceiling_permits`]
/// (the lattice) rather than a local linear rank.
#[must_use]
pub fn is_lattice_world(world: &str) -> bool {
    lattice_world(world).is_some()
}

// ============================================================================
// Capability-world enumeration helpers (extracted from
// controller/src/mcp/capability_worlds.rs)
// ============================================================================

/// Compilable capability worlds — mirror of [`CapabilityWorld::all_strs`].
/// Consumers should prefer [`compilable_worlds_csv`] / this slice over
/// hand-written literals.
pub fn compilable_worlds() -> &'static [&'static str] {
    CapabilityWorld::all_strs()
}

/// Capability worlds valid for an actor's `max_capability_world` ceiling.
///
/// Superset of [`compilable_worlds`] — adds `llm-node`, an actor-level
/// privilege tier with native LLM bindings but no vault access.
/// `llm-node` is NOT a compilable world: do not pass it to
/// compile/run/lint tools.
pub const ACTOR_CEILING_WORLDS: &[&str] = &[
    "minimal-node",
    "http-node",
    "llm-node",
    "network-node",
    "secrets-node",
    "governance-node",
    "messaging-node",
    "filesystem-node",
    "cache-node",
    "database-node",
    "agent-node",
    "automation-node",
];

/// CSV rendering of [`compilable_worlds`].
pub fn compilable_worlds_csv() -> String {
    compilable_worlds().join(", ")
}

/// CSV rendering of [`ACTOR_CEILING_WORLDS`].
pub fn actor_ceiling_worlds_csv() -> String {
    ACTOR_CEILING_WORLDS.join(", ")
}

/// True if `s` is a recognised compilable world.
pub fn is_compilable_world(s: &str) -> bool {
    compilable_worlds().contains(&s)
}

/// True if `s` is a recognised actor-ceiling world.
pub fn is_actor_ceiling_world(s: &str) -> bool {
    ACTOR_CEILING_WORLDS.contains(&s)
}

/// MCP-461: actor-side strict rank lookup.
///
/// `world_rank` returns 7 (most-privileged) for unknown world strings.
/// That's the right fail-closed default for MODULE worlds (an unknown
/// new world is treated as needing the highest ceiling), but it's the
/// WRONG default for ACTOR `max_capability_world` values — a malformed
/// or legacy actor row would silently inherit a tier-7 ceiling and
/// every module would pass the ceiling check.
///
/// Callers that gate "actor can use module X" must use this strict
/// variant for the actor side: it returns `None` when the actor's
/// `max_capability_world` is not in [`ACTOR_CEILING_WORLDS`], so the
/// authorization can reject with a clear "actor ceiling unrecognised"
/// rather than silently grant tier-7. Caller must wire the `None`
/// case to a rejection, not a fall-back rank.
#[must_use]
pub fn actor_world_rank_strict(world: &str) -> Option<u8> {
    if !is_actor_ceiling_world(world) {
        return None;
    }
    Some(world_rank(world))
}

/// Strip the trailing `-node` suffix from a capability-world string,
/// returning the short canonical form. Idempotent — values that don't
/// end in `-node` (already-short) are returned unchanged.
///
/// Many handlers + repos normalize via `world.trim_end_matches("-node")`
/// inline; this helper centralizes the suffix rule so a future rename
/// changes one site.
#[must_use]
pub fn world_short(world: &str) -> &str {
    world.trim_end_matches("-node")
}

/// Worlds that import the `secrets::*` interface (or higher tiers
/// that supersede it). The worker enforces this at runtime — any
/// module whose declared world isn't in this set has its
/// `secrets::*` calls refused with `Forbidden`.
///
/// Mirrored from worker/src/host_impl.rs (around line 1374).
pub fn world_allows_secrets(world: &str) -> bool {
    matches!(
        world_short(world),
        "secrets" | "database" | "agent" | "trusted" | "automation"
    )
}

// ============================================================================
// Write-ceiling mutation profile
// ============================================================================

/// The HTTP suite of write-ceiling-gated ops every world above `Minimal`
/// imports (`http`, `webhook`, `graphql`, `email` in `wit/talos.wit`).
/// `http-fetch`/`http-fetch-all` are gated for MUTATING methods only
/// (POST/PUT/PATCH/DELETE); GET passes — the write ceiling is a mutation
/// control, not an egress control (see `TALOS_WRITE_CEILING_STRICT_EGRESS`
/// for the read-side hardening knob).
const HTTP_SUITE_OPS: &[&str] = &[
    "http-fetch",
    "http-fetch-all",
    "webhook-send",
    "graphql-execute",
    "email-send",
];

const MESSAGING_OPS: &[&str] = &["messaging-publish", "messaging-request"];
const DATABASE_OPS: &[&str] = &["database-query"];
const AGENT_MEMORY_OPS: &[&str] = &[
    "agent-memory-set",
    "agent-memory-delete",
    "agent-memory-store-with-embedding",
];
const INTEGRATION_STATE_OPS: &[&str] = &["integration-state-set", "integration-state-delete"];
const OBJECT_STORAGE_OPS: &[&str] = &["object-storage-put", "object-storage-delete"];

/// Write-ceiling MUTATION PROFILE: the data-mutating host operations a
/// module compiled for this world can reach. Labels are the EXACT `op`
/// strings the worker audits via `TalosContext::write_ceiling_refuses`
/// (`wasi:capability_denied` rows with `policy = "write-ceiling"`), so an
/// operator can correlate each profile entry to audit events one-to-one.
///
/// Derived from the `wit/talos.wit` world imports (verified 2026-07-10):
/// every world above Minimal imports the HTTP suite; Messaging adds NATS
/// publish/request; Database adds SQL + agent-memory; Agent adds
/// agent-memory + integration-state; Trusted (automation-node) has all of
/// the above plus object-storage. NOT in any profile because the worker
/// deliberately does not ceiling-gate them: `http-stream` (read channel),
/// Redis `cache` (ephemeral), sandboxed `files` writes (module-local
/// scratch), and execution `state` (engine-internal durability).
///
/// `Unknown` returns the FULL Trusted profile — fail-closed presentation:
/// a world the inspector can't classify must be assumed capable of
/// everything when an operator reviews it.
pub fn write_gated_ops(world: &CapabilityWorld) -> Vec<&'static str> {
    // Exhaustive match: a NEW world variant is a compile error here,
    // forcing an explicit mutation-profile decision (same pattern as the
    // worker's fs-preopen policy).
    let extra: &[&[&str]] = match world {
        CapabilityWorld::Minimal => return Vec::new(),
        CapabilityWorld::Http
        | CapabilityWorld::Network
        | CapabilityWorld::Secrets
        | CapabilityWorld::Governance
        | CapabilityWorld::Cache
        | CapabilityWorld::Filesystem => &[],
        CapabilityWorld::Messaging => &[MESSAGING_OPS],
        CapabilityWorld::Database => &[DATABASE_OPS, AGENT_MEMORY_OPS],
        CapabilityWorld::Agent => &[AGENT_MEMORY_OPS, INTEGRATION_STATE_OPS],
        CapabilityWorld::Trusted | CapabilityWorld::Unknown => &[
            MESSAGING_OPS,
            DATABASE_OPS,
            AGENT_MEMORY_OPS,
            INTEGRATION_STATE_OPS,
            OBJECT_STORAGE_OPS,
        ],
    };
    let mut ops: Vec<&'static str> = HTTP_SUITE_OPS.to_vec();
    for group in extra {
        ops.extend_from_slice(group);
    }
    ops
}

/// String-form convenience for handler code that holds the world as text
/// (module rows store `capability_world` as a string). Unparseable input
/// maps to `Unknown` → the fail-closed full profile.
pub fn write_gated_ops_str(world: &str) -> Vec<&'static str> {
    let parsed = world
        .parse::<CapabilityWorld>()
        .unwrap_or(CapabilityWorld::Unknown);
    write_gated_ops(&parsed)
}

#[cfg(test)]
mod mutation_profile_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn minimal_mutates_nothing() {
        assert!(write_gated_ops(&CapabilityWorld::Minimal).is_empty());
    }

    #[test]
    fn unknown_is_fail_closed_to_the_full_profile() {
        assert_eq!(
            write_gated_ops(&CapabilityWorld::Unknown),
            write_gated_ops(&CapabilityWorld::Trusted)
        );
        // Unparseable strings take the same fail-closed path.
        assert_eq!(
            write_gated_ops_str("not-a-world"),
            write_gated_ops(&CapabilityWorld::Trusted)
        );
    }

    #[test]
    fn profile_is_monotone_with_the_capability_lattice() {
        // If world A's imports are a subset of world B's, A's mutation
        // profile must be a subset of B's — otherwise the profile claims
        // a capability the lattice says A doesn't have (or hides one).
        for a in CapabilityWorld::ALL {
            for b in CapabilityWorld::ALL {
                if a.is_subset_of(b) {
                    let ops_a: HashSet<_> = write_gated_ops(a).into_iter().collect();
                    let ops_b: HashSet<_> = write_gated_ops(b).into_iter().collect();
                    assert!(
                        ops_a.is_subset(&ops_b),
                        "{} ⊆ {} in the lattice, but its mutation profile is not a subset",
                        a.as_str(),
                        b.as_str()
                    );
                }
            }
        }
    }

    #[test]
    fn str_form_accepts_short_and_node_spellings() {
        assert_eq!(
            write_gated_ops_str("agent-node"),
            write_gated_ops(&CapabilityWorld::Agent)
        );
        assert_eq!(
            write_gated_ops_str("agent"),
            write_gated_ops(&CapabilityWorld::Agent)
        );
        assert_eq!(
            write_gated_ops_str("automation-node"),
            write_gated_ops(&CapabilityWorld::Trusted)
        );
    }

    #[test]
    fn every_profile_op_is_a_known_worker_audit_label() {
        // The full label universe — must stay in lockstep with the worker's
        // write_ceiling_refuses call sites (op strings are the audit key).
        let known: HashSet<&str> = [
            "http-fetch",
            "http-fetch-all",
            "webhook-send",
            "graphql-execute",
            "email-send",
            "messaging-publish",
            "messaging-request",
            "database-query",
            "agent-memory-set",
            "agent-memory-delete",
            "agent-memory-store-with-embedding",
            "integration-state-set",
            "integration-state-delete",
            "object-storage-put",
            "object-storage-delete",
        ]
        .into_iter()
        .collect();
        for w in CapabilityWorld::ALL {
            for op in write_gated_ops(w) {
                assert!(
                    known.contains(op),
                    "unknown op label {op} in {}",
                    w.as_str()
                );
            }
        }
    }
}

#[cfg(test)]
mod ceiling_tests {
    use super::*;

    #[test]
    fn compilable_is_subset_of_actor_ceiling() {
        for w in compilable_worlds() {
            assert!(
                ACTOR_CEILING_WORLDS.contains(w),
                "compilable world {w} missing from actor ceiling list"
            );
        }
    }

    #[test]
    fn actor_ceiling_extras_are_documented() {
        let extras: Vec<&&str> = ACTOR_CEILING_WORLDS
            .iter()
            .filter(|w| !compilable_worlds().contains(w))
            .collect();
        assert_eq!(
            extras,
            vec![&"llm-node"],
            "actor-ceiling-only worlds changed — update the docs in talos-capability-world"
        );
    }

    #[test]
    fn csv_helpers_match_slice_order() {
        assert!(compilable_worlds_csv().starts_with("minimal-node, "));
        assert!(compilable_worlds_csv().ends_with(", automation-node"));
        assert!(actor_ceiling_worlds_csv().contains("llm-node"));
    }

    // -- world_short --

    #[test]
    fn world_short_strips_node_suffix() {
        assert_eq!(world_short("secrets-node"), "secrets");
        assert_eq!(world_short("automation-node"), "automation");
    }

    #[test]
    fn world_short_idempotent_on_short_form() {
        assert_eq!(world_short("secrets"), "secrets");
        assert_eq!(world_short("trusted"), "trusted");
    }

    #[test]
    fn world_short_strips_only_trailing_node() {
        // Substrings of "node" inside the world stay intact.
        assert_eq!(world_short("nodemonkey-node"), "nodemonkey");
    }

    // -- world_allows_secrets --

    #[test]
    fn allows_secrets_for_secrets_tier() {
        assert!(world_allows_secrets("secrets-node"));
        assert!(world_allows_secrets("secrets"));
    }

    #[test]
    fn allows_secrets_for_higher_tiers() {
        assert!(world_allows_secrets("database-node"));
        assert!(world_allows_secrets("agent-node"));
        assert!(world_allows_secrets("trusted"));
        assert!(world_allows_secrets("automation-node"));
    }

    #[test]
    fn denies_secrets_for_lower_tiers() {
        assert!(!world_allows_secrets("minimal-node"));
        assert!(!world_allows_secrets("http-node"));
        assert!(!world_allows_secrets("network-node"));
        assert!(!world_allows_secrets("messaging-node"));
        assert!(!world_allows_secrets("filesystem-node"));
        assert!(!world_allows_secrets("cache-node"));
        assert!(!world_allows_secrets("llm-node"));
        assert!(!world_allows_secrets("governance-node"));
    }

    #[test]
    fn denies_secrets_for_unknown_world() {
        assert!(!world_allows_secrets("custom-node"));
        assert!(!world_allows_secrets(""));
    }

    // -- ceiling_permits (partial-order lattice gate) --

    #[test]
    fn ceiling_permits_rejects_incomparable_tier3_siblings() {
        // The exact bypass class the 2026-05-28 review found: a ceiling
        // intended to DENY vault access must reject a secrets module even
        // though world_rank(secrets)=3 < world_rank(cache)=5.
        for ceiling in [
            "cache-node",
            "messaging-node",
            "filesystem-node",
            "governance-node",
        ] {
            assert!(
                !ceiling_permits(ceiling, "secrets-node"),
                "{ceiling} must NOT permit a secrets-node module (Secrets ⊄ {ceiling})"
            );
        }
        // Symmetric: a secrets ceiling must not permit cache/messaging/filesystem.
        for requested in ["cache-node", "messaging-node", "filesystem-node"] {
            assert!(
                !ceiling_permits("secrets-node", requested),
                "secrets-node must NOT permit a {requested} module"
            );
        }
        // tier-4 incomparable siblings: database ⊉ agent and agent ⊉ database.
        assert!(!ceiling_permits("database-node", "agent-node"));
        assert!(!ceiling_permits("agent-node", "database-node"));
        // agent does NOT include cache/messaging/filesystem/database.
        for requested in [
            "cache-node",
            "messaging-node",
            "filesystem-node",
            "database-node",
        ] {
            assert!(!ceiling_permits("agent-node", requested));
        }
    }

    #[test]
    fn ceiling_permits_allows_legitimate_escalation_paths() {
        // Identity.
        for w in ACTOR_CEILING_WORLDS {
            if *w == "llm-node" {
                continue; // llm has no module-world form; covered separately.
            }
            assert!(ceiling_permits(w, w), "{w} must permit itself");
        }
        // Minimal/Http/Network are subsets of higher worlds.
        assert!(ceiling_permits("secrets-node", "minimal-node"));
        assert!(ceiling_permits("secrets-node", "http-node"));
        assert!(ceiling_permits("secrets-node", "network-node"));
        // Secrets escalates to Database/Agent/Trusted.
        assert!(ceiling_permits("database-node", "secrets-node"));
        assert!(ceiling_permits("agent-node", "secrets-node"));
        assert!(ceiling_permits("automation-node", "secrets-node"));
        // Governance escalates to Agent/Trusted.
        assert!(ceiling_permits("agent-node", "governance-node"));
        assert!(ceiling_permits("automation-node", "governance-node"));
        // Trusted/automation permits everything compilable.
        for w in compilable_worlds() {
            assert!(
                ceiling_permits("automation-node", w),
                "automation-node must permit every compilable world ({w})"
            );
        }
    }

    #[test]
    fn ceiling_permits_handles_llm_node_ceiling() {
        // llm-node ⇒ Http for lattice purposes: permits minimal/http, denies
        // network (sockets), secrets, and everything above http.
        assert!(ceiling_permits("llm-node", "minimal-node"));
        assert!(ceiling_permits("llm-node", "http-node"));
        assert!(ceiling_permits("llm-node", "llm-node"));
        assert!(!ceiling_permits("llm-node", "network-node"));
        assert!(!ceiling_permits("llm-node", "secrets-node"));
        assert!(!ceiling_permits("llm-node", "automation-node"));
    }

    #[test]
    fn is_lattice_world_recognises_known_forms_only() {
        // Both short and -node forms are recognised.
        assert!(is_lattice_world("secrets"));
        assert!(is_lattice_world("secrets-node"));
        assert!(is_lattice_world("governance-node"));
        assert!(is_lattice_world("minimal"));
        // Unknown / malformed / legacy → false (so callers can report it).
        assert!(!is_lattice_world("bogus"));
        assert!(!is_lattice_world(""));
        assert!(!is_lattice_world("tier1"));
    }

    #[test]
    fn ceiling_permits_fails_closed_on_unknown() {
        // Unknown / legacy / malformed ceiling rejects every module.
        assert!(!ceiling_permits("bogus-node", "minimal-node"));
        assert!(!ceiling_permits("", "minimal-node"));
        assert!(!ceiling_permits("tier1", "minimal-node"));
        // Unknown module world rejected even under the highest ceiling.
        assert!(!ceiling_permits("automation-node", "bogus-node"));
        assert!(!ceiling_permits("automation-node", ""));
    }

    #[test]
    fn ceiling_permits_accepts_short_and_node_forms() {
        assert!(ceiling_permits("database", "secrets"));
        assert!(ceiling_permits("database-node", "secrets-node"));
        assert!(ceiling_permits("database", "secrets-node"));
        assert!(ceiling_permits("database-node", "secrets"));
    }

    #[test]
    fn ceiling_permits_subsumes_world_rank_gate() {
        // Property: every subset edge has rank(sub) <= rank(super), so the
        // lattice gate is strictly stricter than the linear rank gate. Verify
        // there is NO (ceiling, requested) pair the rank gate rejected that
        // the lattice gate now ALLOWS (that would be a regression).
        let worlds = compilable_worlds();
        for &c in worlds {
            for &r in worlds {
                let rank_allows = world_rank(r) <= world_rank(c);
                let lattice_allows = ceiling_permits(c, r);
                assert!(
                    !(lattice_allows && !rank_allows),
                    "lattice allows ({c} ⊇ {r}) but rank rejected it — rank/lattice inconsistency"
                );
            }
        }
    }
}
