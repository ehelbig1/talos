//! Capability downgrade detection for module hot-updates.
//!
//! When a module is recompiled with a lower capability world than its previous
//! version, workflows using it might break silently. This module detects such
//! downgrades and returns a warning.

use talos_capability_world::CapabilityWorld;

/// Check if updating from `old_world` to `new_world` is a capability downgrade.
/// Returns a warning message if capabilities were dropped, None if safe.
pub fn check_downgrade(
    module_name: &str,
    old_world: &CapabilityWorld,
    new_world: &CapabilityWorld,
) -> Option<String> {
    // If the new world is a subset of the old, no downgrade
    if old_world.is_subset_of(new_world) {
        return None;
    }

    // If the old world is NOT a subset of the new, capabilities were dropped
    if !new_world.is_subset_of(old_world) && new_world != old_world {
        // Incomparable worlds — warn about potential breakage
        return Some(format!(
            "WARNING: Module '{}' capability world changed from {} to {} — \
             these worlds are incomparable. Workflows using {} interfaces may break.",
            module_name, old_world, new_world, old_world
        ));
    }

    // new is strictly less than old — definite downgrade
    Some(format!(
        "WARNING: Module '{}' downgraded from {} to {}. \
         Workflows relying on {} capabilities will fail at runtime.",
        module_name, old_world, new_world, old_world
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_is_safe() {
        assert!(
            check_downgrade("mod", &CapabilityWorld::Minimal, &CapabilityWorld::Http).is_none()
        );
        assert!(
            check_downgrade("mod", &CapabilityWorld::Http, &CapabilityWorld::Secrets).is_none()
        );
    }

    #[test]
    fn downgrade_is_detected() {
        let warn = check_downgrade(
            "mymod",
            &CapabilityWorld::Secrets,
            &CapabilityWorld::Minimal,
        );
        assert!(warn.is_some());
        assert!(warn.unwrap().contains("downgraded"));
    }

    #[test]
    fn same_world_is_safe() {
        assert!(check_downgrade("mod", &CapabilityWorld::Http, &CapabilityWorld::Http).is_none());
    }

    #[test]
    fn incomparable_worlds_warn() {
        let warn = check_downgrade(
            "mod",
            &CapabilityWorld::Secrets,
            &CapabilityWorld::Filesystem,
        );
        assert!(warn.is_some());
        assert!(warn.unwrap().contains("incomparable"));
    }
}
