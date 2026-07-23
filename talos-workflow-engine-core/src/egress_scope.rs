//! Network-egress scope — a per-actor security axis, **independent of**
//! [`LlmTier`](crate::llm_tier::LlmTier), that gates whether a job may make
//! outbound network calls to public (globally-routable) hosts at all.
//!
//! ## Why this is separate from `LlmTier`
//!
//! Historically `max_llm_tier == Tier1` drove BOTH the LLM-provider deny
//! (don't send prompts to Anthropic/OpenAI/Gemini) AND a blanket
//! "no public egress, period" SSRF block (`local_egress_only`). Those serve
//! two DIFFERENT threats:
//!   * **LLM-provider gate** (stays keyed to `LlmTier`): keep prompt/memory
//!     content out of third-party LLMs.
//!   * **Blanket egress gate** (this type): anti-exfiltration — deny ALL
//!     public network egress regardless of host.
//!
//! Conflating them made an actor that only needs "LLM stays local" also lose
//! access to legitimate public APIs (e.g. reading Gmail over HTTPS). Splitting
//! the axis lets an actor be `max_llm_tier = Tier1` (LLM hard-gated local) AND
//! `egress_scope = Public` (can reach declared `allowed_hosts` like Gmail),
//! which no single binary tier could express.
//!
//! ## Override semantics (backward-compatible)
//!
//! The field is carried as `Option<EgressScope>` everywhere:
//!   * `None`  → **fall back to the tier-derived default** (`Tier1` ⇒ local,
//!     `Tier2` ⇒ public). Every existing actor is `None`, so behavior is
//!     byte-identical until an operator sets an explicit scope.
//!   * `Some(Local)`  → deny all public egress (the classic Tier-1 posture),
//!     regardless of `max_llm_tier`.
//!   * `Some(Public)` → permit public egress (subject to per-module
//!     `allowed_hosts` + SSRF filtering), regardless of `max_llm_tier`.
//!
//! `egress_scope` overrides ONLY the blanket public-IP SSRF gate
//! (`worker::context` `local_egress_only`). It deliberately does NOT loosen:
//!   * the LLM-provider name deny (still keyed to `LlmTier`) — so a
//!     `Tier1 + Public` actor reaches Gmail but STILL cannot reach
//!     `api.anthropic.com`;
//!   * the raw `wasi:sockets` grant (still keyed to `LlmTier` — raw sockets
//!     bypass `allowed_hosts` entirely, a bigger hole than filtered egress);
//!   * the public-IP-*literal* deny on the host-fn path (still keyed to
//!     `LlmTier`; hostname egress like `gmail.googleapis.com` is unaffected).
//!
//! Lives in core (below job-protocol) because the engine's `DispatchJob`
//! carries it through the dispatcher pipeline — same placement rationale as
//! [`LlmTier`](crate::llm_tier::LlmTier).

use serde::{Deserialize, Serialize};

/// Per-actor blanket-network-egress scope. Carried as `Option<EgressScope>`;
/// see the module docs for the `None` = tier-derived-default semantics.
///
/// `#[non_exhaustive]` so a future scope (e.g. an explicit host-allowlist
/// variant) can be added in a minor bump without breaking exhaustive matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum EgressScope {
    /// Deny ALL public (globally-routable) network egress — the classic
    /// air-gapped Tier-1 posture, decoupled from the LLM tier.
    Local,
    /// Permit public egress, subject to per-module `allowed_hosts` + SSRF
    /// filtering. The LLM-provider gate (keyed to `LlmTier`) still applies.
    Public,
}

impl EgressScope {
    /// Wire-format string used in the `JobRequest` signing payload and in the
    /// `actors.egress_scope` database column. Stable — never reorder or rename
    /// without coordinating a controller+worker restart.
    pub fn as_signing_str(self) -> &'static str {
        match self {
            EgressScope::Local => "local",
            EgressScope::Public => "public",
        }
    }

    /// Parse from the database-canonical string. Unknown / mistyped values
    /// fall back to `Local` (fail-closed: a drift/typo yields the MORE
    /// restrictive scope — no public egress — never accidental exposure).
    /// Recognised tokens are `"local"` and `"public"`; everything else
    /// (including the empty string) lands in `Local`.
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "public" => EgressScope::Public,
            // "local", unrecognised tokens, and empty strings all fail closed
            // to Local. The explicit "local" arm folds into the wildcard so a
            // future column typo can never accidentally open public egress.
            _ => EgressScope::Local,
        }
    }

    /// Parse the nullable DB column into the override `Option`: `None` (SQL
    /// NULL) preserves the tier-derived default; a present string parses via
    /// [`Self::from_db_str`] (fail-closed to `Local`).
    pub fn from_db_opt(s: Option<&str>) -> Option<Self> {
        s.map(Self::from_db_str)
    }

    /// The more restrictive of two override scopes — used when composing a
    /// parent's scope with a sub-workflow's own actor scope so a sub-workflow
    /// can only ever be *narrowed*, never widened (privilege can't escalate
    /// across the sub-workflow boundary), mirroring
    /// [`LlmTier::most_restrictive`](crate::llm_tier::LlmTier::most_restrictive).
    ///
    /// `Local` (no public egress) is strictly more restrictive than `Public`.
    /// With the `Option` override, a `None` (tier-default) side does NOT
    /// loosen a `Some(Local)` side: `narrow` treats `None` as "no explicit
    /// opinion" and defers to the other side, but any explicit `Local` wins.
    #[must_use]
    pub fn narrow(a: Option<Self>, b: Option<Self>) -> Option<Self> {
        match (a, b) {
            (Some(EgressScope::Local), _) | (_, Some(EgressScope::Local)) => {
                Some(EgressScope::Local)
            }
            (Some(EgressScope::Public), _) | (_, Some(EgressScope::Public)) => {
                Some(EgressScope::Public)
            }
            (None, None) => None,
        }
    }

    /// The concrete scope a NULL/unset override resolves to for a given LLM
    /// tier — the SAME tier-derived default the worker applies in
    /// `resolve_local_egress_only`'s `None` arm (`Tier1` → `Local`, everything
    /// else → `Public`). Keep these in lockstep.
    ///
    /// This exists so sub-workflow narrowing can be made SYMMETRIC with the
    /// concrete tier/write axes: a sub-actor that is air-gapped only by its
    /// tier default (egress column NULL) must NOT lose that air-gap when
    /// invoked under a caller with an explicit `Public` scope. Callers resolve
    /// BOTH sides to their effective scope via [`Self::effective`] before
    /// [`Self::narrow`], so a `None` never "defers to caller" across the
    /// sub-workflow boundary.
    #[must_use]
    pub fn tier_default(tier: crate::LlmTier) -> Self {
        match tier {
            crate::LlmTier::Tier1 => EgressScope::Local,
            _ => EgressScope::Public,
        }
    }

    /// Resolve an override `Option` to the concrete scope actually in force:
    /// an explicit value wins, otherwise the tier-derived default
    /// ([`Self::tier_default`]). Use before [`Self::narrow`] on each side of a
    /// sub-workflow composition.
    #[must_use]
    pub fn effective(scope: Option<Self>, tier: crate::LlmTier) -> Self {
        scope.unwrap_or_else(|| Self::tier_default(tier))
    }
}

#[cfg(test)]
mod tests {
    use super::EgressScope;

    #[test]
    fn canonical_strings_round_trip() {
        assert_eq!(EgressScope::from_db_str("local"), EgressScope::Local);
        assert_eq!(EgressScope::from_db_str("public"), EgressScope::Public);
        assert_eq!(EgressScope::Local.as_signing_str(), "local");
        assert_eq!(EgressScope::Public.as_signing_str(), "public");
    }

    #[test]
    fn unknown_db_value_fails_closed_to_local() {
        // SECURITY: any garbage / drift / migration-bug value in
        // `actors.egress_scope` MUST land on Local (no public egress),
        // never Public. Case-sensitive by design (wire format is lowercase).
        assert_eq!(EgressScope::from_db_str("Public"), EgressScope::Local);
        assert_eq!(EgressScope::from_db_str("PUBLIC"), EgressScope::Local);
        assert_eq!(EgressScope::from_db_str(""), EgressScope::Local);
        assert_eq!(EgressScope::from_db_str("null"), EgressScope::Local);
        assert_eq!(EgressScope::from_db_str("any"), EgressScope::Local);
    }

    #[test]
    fn from_db_opt_preserves_null_as_none() {
        // SQL NULL → None → tier-derived default preserved.
        assert_eq!(EgressScope::from_db_opt(None), None);
        assert_eq!(
            EgressScope::from_db_opt(Some("public")),
            Some(EgressScope::Public)
        );
        // A present-but-garbage value fails closed to Local (NOT to None —
        // an explicit column value is an explicit override, just a safe one).
        assert_eq!(
            EgressScope::from_db_opt(Some("garbage")),
            Some(EgressScope::Local)
        );
    }

    #[test]
    fn effective_folds_tier_default_and_preserves_subworkflow_airgap() {
        use crate::LlmTier;
        // A NULL override resolves to the tier default (mirrors the worker gate).
        assert_eq!(
            EgressScope::effective(None, LlmTier::Tier1),
            EgressScope::Local
        );
        assert_eq!(
            EgressScope::effective(None, LlmTier::Tier2),
            EgressScope::Public
        );
        // An explicit value wins over the tier default.
        assert_eq!(
            EgressScope::effective(Some(EgressScope::Public), LlmTier::Tier1),
            EgressScope::Public
        );
        // THE FIX: a Tier-1 sub-actor with NO explicit override (air-gapped
        // only by its tier default) must NOT lose its air-gap under a Public
        // parent. Resolving both sides to effective BEFORE narrow guarantees it.
        let parent = EgressScope::effective(Some(EgressScope::Public), LlmTier::Tier2);
        let sub = EgressScope::effective(None, LlmTier::Tier1); // NULL column, Tier1
        assert_eq!(
            EgressScope::narrow(Some(parent), Some(sub)),
            Some(EgressScope::Local),
            "Tier-1 sub-actor air-gap must survive a Public parent"
        );
    }

    #[test]
    fn narrow_only_stays_public_when_no_local_side() {
        // SECURITY: narrowing across a sub-workflow boundary can only tighten.
        assert_eq!(
            EgressScope::narrow(Some(EgressScope::Public), Some(EgressScope::Public)),
            Some(EgressScope::Public)
        );
        assert_eq!(
            EgressScope::narrow(Some(EgressScope::Public), Some(EgressScope::Local)),
            Some(EgressScope::Local)
        );
        assert_eq!(
            EgressScope::narrow(Some(EgressScope::Local), Some(EgressScope::Public)),
            Some(EgressScope::Local)
        );
        // None defers to the other side; two Nones stay None (tier default).
        assert_eq!(
            EgressScope::narrow(None, Some(EgressScope::Public)),
            Some(EgressScope::Public)
        );
        assert_eq!(
            EgressScope::narrow(Some(EgressScope::Local), None),
            Some(EgressScope::Local)
        );
        assert_eq!(EgressScope::narrow(None, None), None);
    }
}
