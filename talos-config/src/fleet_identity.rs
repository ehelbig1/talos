//! Whether a production process may still accept the fleet-shared HMAC key
//! where a per-worker Ed25519 identity exists (security review 2026-10-14,
//! B-2).
//!
//! Every worker holds `WORKER_SHARED_KEY`. On a surface that still accepts
//! it, one leaked key — or one compromised worker — signs for ANY actor, user
//! or execution: memory and integration-state RPCs, sandbox SQL, durable
//! state, forged job results, forged dispatches. Per-worker Ed25519 identity
//! already exists (`TALOS_WORKER_SIGNING_KEY`, `TALOS_CONTROLLER_SIGNING_KEY`)
//! and three switches retire the HMAC path, one per surface:
//!
//! | surface | switch | read by |
//! |---|---|---|
//! | dispatch | `TALOS_DISPATCH_REQUIRE_ED25519` | worker |
//! | result | `TALOS_RESULT_REQUIRE_ED25519` | controller |
//! | rpc | `TALOS_RPC_REQUIRE_ED25519` | controller |
//!
//! Until 2026-10-14 nothing required them: a production deployment ran on
//! the shared key by default. Now a production process refuses to boot while
//! a switch it reads is off, unless `TALOS_ALLOW_LEGACY_FLEET_HMAC` names that
//! surface (`dispatch`, `result`, `rpc`, comma-separated, or `all`) — the
//! choice is explicit and logged at ERROR on every boot. The migration path
//! is `docs/worker-identity.md`.

/// One surface that can accept the fleet-shared HMAC key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyFleetSurface {
    Dispatch,
    Result,
    Rpc,
}

impl LegacyFleetSurface {
    /// The word `TALOS_ALLOW_LEGACY_FLEET_HMAC` names this surface by.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dispatch => "dispatch",
            Self::Result => "result",
            Self::Rpc => "rpc",
        }
    }
}

/// One surface as a process read it: the switch's name (read where the
/// process reads it, so each name lives in the process that owns it) and
/// whether it is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceSwitch {
    pub surface: LegacyFleetSurface,
    /// The switch that retires the shared key on this surface.
    pub switch: &'static str,
    pub required: bool,
}

/// The acknowledgement variable.
pub const ALLOW_LEGACY_FLEET_HMAC: &str = "TALOS_ALLOW_LEGACY_FLEET_HMAC";

/// The surfaces `raw` acknowledges: surface names, comma-separated, or `all`.
/// An unknown word is refused, so a typo cannot silently acknowledge nothing
/// (or everything). A boolean (`1`, `true`, `yes`, `on`) is refused too
/// (security review 2026-10-15, B2-8): it is the habit every other
/// `TALOS_ALLOW_*` switch teaches, and here it acknowledged all three surfaces
/// for an operator who meant one. Acknowledging everything is spelled `all`.
pub fn parse_acknowledged(raw: Option<&str>) -> Result<Vec<LegacyFleetSurface>, String> {
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(Vec::new());
    };
    let all = [
        LegacyFleetSurface::Dispatch,
        LegacyFleetSurface::Result,
        LegacyFleetSurface::Rpc,
    ];
    let mut out = Vec::new();
    for word in raw.split(',').map(|w| w.trim().to_ascii_lowercase()) {
        match word.as_str() {
            "all" => return Ok(all.to_vec()),
            "1" | "true" | "yes" | "on" => {
                return Err(format!(
                    "{ALLOW_LEGACY_FLEET_HMAC}={word} is a boolean; this setting names the \
                     surfaces it acknowledges: dispatch, result, rpc (comma-separated) or all"
                ))
            }
            "dispatch" => out.push(LegacyFleetSurface::Dispatch),
            "result" => out.push(LegacyFleetSurface::Result),
            "rpc" => out.push(LegacyFleetSurface::Rpc),
            "" => {}
            other => {
                return Err(format!(
                    "{ALLOW_LEGACY_FLEET_HMAC} names {other:?}, which is not a surface; use \
                     dispatch, result, rpc (comma-separated) or all"
                ))
            }
        }
    }
    Ok(out)
}

/// The decision, pure. `surfaces` is each surface this process reads with
/// whether its require switch is on. Returns the surfaces running on the
/// legacy key by acknowledgement (to log), or the refusal.
pub fn fleet_identity_posture(
    is_production: bool,
    surfaces: &[SurfaceSwitch],
    acknowledged: &[LegacyFleetSurface],
) -> Result<Vec<LegacyFleetSurface>, String> {
    let legacy: Vec<&SurfaceSwitch> = surfaces.iter().filter(|s| !s.required).collect();
    if !is_production {
        return Ok(Vec::new());
    }
    let unacknowledged: Vec<&&SurfaceSwitch> = legacy
        .iter()
        .filter(|s| !acknowledged.contains(&s.surface))
        .collect();
    if unacknowledged.is_empty() {
        return Ok(legacy.iter().map(|s| s.surface).collect());
    }
    let switches: Vec<&str> = unacknowledged.iter().map(|s| s.switch).collect();
    let names: Vec<&str> = unacknowledged.iter().map(|s| s.surface.name()).collect();
    Err(format!(
        "production refuses to accept the fleet-shared WORKER_SHARED_KEY where a per-worker \
         Ed25519 identity exists: {} is off. One leaked key (or one compromised worker) would \
         sign for any actor, user or execution. Set {} once every worker holds an identity \
         key (docs/worker-identity.md), or acknowledge the legacy posture explicitly with \
         {ALLOW_LEGACY_FLEET_HMAC}={}.",
        switches.join(", "),
        switches.join("=1, ") + "=1",
        names.join(","),
    ))
}

/// Apply [`fleet_identity_posture`] to the switches the caller read and the
/// acknowledgement it read (`TALOS_ALLOW_LEGACY_FLEET_HMAC`, raw). Logs an
/// acknowledged legacy posture at ERROR. Call once at boot.
pub fn enforce_production_fleet_identity(
    is_production: bool,
    surfaces: &[SurfaceSwitch],
    acknowledgement: Option<&str>,
) -> Result<(), String> {
    let acknowledged = parse_acknowledged(acknowledgement)?;
    let legacy = fleet_identity_posture(is_production, surfaces, &acknowledged)?;
    if !legacy.is_empty() {
        let names: Vec<&str> = legacy.iter().map(|s| s.name()).collect();
        tracing::error!(
            target: "talos_security",
            event_kind = "legacy_fleet_hmac_in_production",
            surfaces = %names.join(","),
            "production accepts the fleet-shared WORKER_SHARED_KEY on these surfaces, \
             acknowledged via {ALLOW_LEGACY_FLEET_HMAC}; one leaked key signs for any tenant \
             there"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use LegacyFleetSurface::{Dispatch, Result as Res, Rpc};

    fn sw(surface: LegacyFleetSurface, required: bool) -> SurfaceSwitch {
        // Stand-in names: the posture only echoes them, and a real switch
        // name here would read as this crate reading that variable.
        let switch = match surface {
            Dispatch => "SWITCH_DISPATCH",
            Res => "SWITCH_RESULT",
            Rpc => "SWITCH_RPC",
        };
        SurfaceSwitch {
            surface,
            switch,
            required,
        }
    }

    #[test]
    fn production_with_a_switch_off_and_no_acknowledgement_refuses() {
        let err = fleet_identity_posture(true, &[sw(Res, false), sw(Rpc, true)], &[]).unwrap_err();
        assert!(err.contains("SWITCH_RESULT"), "{err}");
        assert!(!err.contains("SWITCH_RPC"), "{err}");
    }

    #[test]
    fn production_with_every_switch_on_boots() {
        assert_eq!(
            fleet_identity_posture(true, &[sw(Res, true), sw(Rpc, true)], &[]),
            Ok(vec![])
        );
    }

    #[test]
    fn an_acknowledgement_covers_only_the_surfaces_it_names() {
        assert_eq!(
            fleet_identity_posture(true, &[sw(Res, true), sw(Rpc, false)], &[Rpc]),
            Ok(vec![Rpc])
        );
        assert!(fleet_identity_posture(true, &[sw(Res, false), sw(Rpc, false)], &[Rpc]).is_err());
    }

    #[test]
    fn outside_production_nothing_is_refused() {
        assert_eq!(
            fleet_identity_posture(false, &[sw(Dispatch, false)], &[]),
            Ok(vec![])
        );
    }

    #[test]
    fn the_acknowledgement_is_parsed_strictly() {
        assert_eq!(parse_acknowledged(None), Ok(vec![]));
        assert_eq!(parse_acknowledged(Some("")), Ok(vec![]));
        assert_eq!(parse_acknowledged(Some("rpc")), Ok(vec![Rpc]));
        assert_eq!(
            parse_acknowledged(Some(" result , rpc ")),
            Ok(vec![Res, Rpc])
        );
        assert_eq!(parse_acknowledged(Some("all")).unwrap().len(), 3);
        assert!(
            parse_acknowledged(Some("rcp")).is_err(),
            "a typo is refused"
        );
        // B2-8: a boolean acknowledges nothing; it is refused, and says why.
        for boolean in ["1", "true", "YES", "on"] {
            let refused = parse_acknowledged(Some(boolean)).expect_err(boolean);
            assert!(refused.contains("boolean"), "{refused}");
        }
        assert!(parse_acknowledged(Some("rpc,1")).is_err());
    }
}
