/// Role within an organization, ordered by ascending privilege.
///
/// Stored on `org_members.role` as the lowercase string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OrgRole {
    Viewer = 0,
    Member = 1,
    Admin = 2,
    Owner = 3,
}

impl OrgRole {
    /// Parse from the string stored in the database.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(OrgRole::Viewer),
            "member" => Some(OrgRole::Member),
            "admin" => Some(OrgRole::Admin),
            "owner" => Some(OrgRole::Owner),
            _ => None,
        }
    }

    /// Database/API string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            OrgRole::Viewer => "viewer",
            OrgRole::Member => "member",
            OrgRole::Admin => "admin",
            OrgRole::Owner => "owner",
        }
    }

    /// Whether this role can manage (invite/remove/update) members.
    pub fn can_manage_members(&self) -> bool {
        matches!(self, OrgRole::Owner | OrgRole::Admin)
    }

    /// Whether this role can create/edit resources within the org.
    pub fn can_write(&self) -> bool {
        matches!(self, OrgRole::Owner | OrgRole::Admin | OrgRole::Member)
    }

    /// Whether this role can read resources within the org.
    pub fn can_read(&self) -> bool {
        // All roles can read.
        true
    }

    /// Whether this role can delete the organization.
    pub fn can_delete(&self) -> bool {
        matches!(self, OrgRole::Owner)
    }
}

impl std::fmt::Display for OrgRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_matches_privilege() {
        assert!(OrgRole::Owner > OrgRole::Admin);
        assert!(OrgRole::Admin > OrgRole::Member);
        assert!(OrgRole::Member > OrgRole::Viewer);
    }

    #[test]
    fn round_trip_strings() {
        for role in [
            OrgRole::Viewer,
            OrgRole::Member,
            OrgRole::Admin,
            OrgRole::Owner,
        ] {
            assert_eq!(OrgRole::from_str(role.as_str()), Some(role));
        }
    }
}
