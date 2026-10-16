//! Audit every installed module binary against the world rule of the worker
//! about to be deployed (2026-10-16).
//!
//! On 2026-10-16 a deploy changed how the worker names a binary's world and
//! every agent-node module that imports only `agent-memory` was refused at
//! dispatch for the next twenty hours. `make up` could not have known: the
//! rule lived in the worker and the rows in Postgres, and nothing asked the
//! one about the other before the switch. This crate asks, from the candidate
//! controller image, before the candidate worker takes a job.
//!
//! The verdict is not a re-implementation of the dispatch decision; it IS
//! that decision, [`talos_wit_inspector::world_fit_at_dispatch`], on the same
//! bytes with the same hint.

use anyhow::Result;
use talos_module_repository::{ModuleBinaryRow, ModuleRepository};
use talos_wit_inspector::{world_fit_at_dispatch, WorldFit};
use uuid::Uuid;

/// A row a dispatch would refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub owner: Option<Uuid>,
    pub declared_world: String,
    pub reason: String,
}

/// The audit's result. `is_clean` is the gate; `render` is what the operator
/// reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditReport {
    /// Rows with bytes that were inspected.
    pub audited: usize,
    /// Rows that run from a registry reference and could not be inspected.
    pub registry_unaudited: i64,
    pub findings: Vec<Finding>,
}

impl AuditReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// One line per finding, then the totals. Names and ids only: a module
    /// name is the author's and an owner id is a uuid, neither a secret.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for f in &self.findings {
            let owner = f
                .owner
                .map(|u| u.to_string())
                .unwrap_or_else(|| "system".to_string());
            out.push_str(&format!(
                "REFUSED  {} ({}, {}, owner {}) declared {}: {}\n",
                f.name, f.kind, f.id, owner, f.declared_world, f.reason
            ));
        }
        out.push_str(&format!(
            "audited {} module binaries: {} would be refused at dispatch; {} registry references not inspected\n",
            self.audited,
            self.findings.len(),
            self.registry_unaudited
        ));
        out
    }
}

/// Judge one row. `None` is a row the worker links.
pub fn judge(row: &ModuleBinaryRow) -> Option<Finding> {
    let reason = match world_fit_at_dispatch(&row.capability_world, &row.wasm_bytes) {
        WorldFit::Links(_) => return None,
        WorldFit::UnrecognisedWorld(w) => {
            format!("the stored world {w:?} names no world; the worker refuses the hint")
        }
        WorldFit::Refused(reason) => reason,
    };
    Some(Finding {
        id: row.id,
        name: row.name.clone(),
        kind: row.kind.clone(),
        owner: row.owner,
        declared_world: row.capability_world.clone(),
        reason,
    })
}

/// Rows per page. Sandbox binaries run to a few MB each, so a page is a
/// bounded amount of memory and the walk never loads the table.
pub const PAGE: i64 = 64;

/// Walk every row that holds bytes and judge each. Read-only.
pub async fn audit_installed_modules(repo: &ModuleRepository) -> Result<AuditReport> {
    let mut report = AuditReport {
        registry_unaudited: repo.count_registry_reference_modules().await?,
        ..AuditReport::default()
    };
    let mut after: Option<Uuid> = None;
    loop {
        let page = repo.list_module_binaries_after(after, PAGE).await?;
        let Some(last) = page.last() else { break };
        after = Some(last.id);
        for row in &page {
            report.audited += 1;
            if let Some(f) = judge(row) {
                report.findings.push(f);
            }
        }
        if (page.len() as i64) < PAGE {
            break;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(world: &str, wat: &str) -> ModuleBinaryRow {
        ModuleBinaryRow {
            id: Uuid::nil(),
            name: "m".into(),
            kind: "sandbox".into(),
            owner: None,
            capability_world: world.into(),
            wasm_bytes: wat::parse_str(wat).expect("component"),
        }
    }

    const MEMORY_ONLY: &str = r#"(component
        (import "talos:core/agent-memory" (instance))
        (core module (memory 1)))"#;

    /// The row the 2026-10-16 deploy refused is judged clean by the fixed
    /// rule, and the same bytes at a world that does not grant memory are a
    /// finding that names the import.
    #[test]
    fn a_memory_only_agent_row_is_clean_and_a_minimal_one_is_a_finding() {
        assert_eq!(judge(&row("agent-node", MEMORY_ONLY)), None);
        assert_eq!(judge(&row("agent", MEMORY_ONLY)), None);
        let f = judge(&row("minimal-node", MEMORY_ONLY)).expect("finding");
        assert_eq!(f.declared_world, "minimal-node");
        assert!(f.reason.contains("talos:core/agent-memory"), "{}", f.reason);
    }

    /// A world string the worker cannot parse is a finding of its own kind.
    #[test]
    fn an_unrecognised_world_is_a_finding() {
        let f = judge(&row("llm-node", MEMORY_ONLY)).expect("finding");
        assert!(f.reason.contains("names no world"), "{}", f.reason);
    }

    /// The gate is the findings list; the totals are reported either way.
    #[test]
    fn a_report_is_clean_only_with_no_findings_and_says_what_it_skipped() {
        let mut r = AuditReport {
            audited: 3,
            registry_unaudited: 2,
            findings: vec![],
        };
        assert!(r.is_clean());
        assert!(r
            .render()
            .contains("audited 3 module binaries: 0 would be refused"));
        assert!(r.render().contains("2 registry references not inspected"));
        r.findings
            .push(judge(&row("minimal-node", MEMORY_ONLY)).unwrap());
        assert!(!r.is_clean());
        assert!(r.render().starts_with("REFUSED  m (sandbox, "));
    }
}
