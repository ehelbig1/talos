//! The planted-fault gate: every rule of every security check template is
//! shown to tell a fault from its absence.
//!
//! A rule that never fires passes every test that only looks for trouble. So
//! each rule has two fixtures, kept beside its template:
//!
//!   module-templates/<check>/fixtures/planted/<rule>.json   evidence WITH the fault
//!   module-templates/<check>/fixtures/planted/clean.json    evidence without any
//!
//! Each is the envelope the check's `run` is given, `{"config": …, "input": …}`,
//! made-up data only. This runs the real check on them and holds that
//!
//!   * on `<rule>.json` the rule reports a finding, and is neither "passed"
//!     nor "not assessed";
//!   * on `clean.json` the rule reports nothing and IS "passed": it was
//!     assessed and found nothing, which is not the same as not being run;
//!   * `clean.json` is clean by EVERY rule of the check: no finding at all,
//!     and nothing unassessed.
//!
//! A check's rules are read from the check itself (`CATALOGUE_ONLY` hands
//! over its catalogue), so a new rule is held to this from the moment it
//! exists. Rules written before the gate existed (in the authoring lane these
//! templates came from) are listed in `PREDATING`; that list only shrinks.

use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;
use talos_catalog_tests as catalog;

type Run = fn(String) -> Result<String, String>;

/// Every template that carries planted faults. A template with a
/// `fixtures/planted/` directory and no row here fails
/// `every_template_with_planted_faults_is_held_here`.
const CHECKS: &[(&str, Run)] = &[
    (
        "artifact-registry-check",
        catalog::artifact_registry_check::run,
    ),
    ("binauthz-check", catalog::binauthz_check::run),
    (
        "github-dependency-scan-check",
        catalog::github_dependency_scan_check::run,
    ),
    ("github-env-check", catalog::github_env_check::run),
    (
        "security-alerting-check",
        catalog::security_alerting_check::run,
    ),
    ("wif-check", catalog::wif_check::run),
];

const PREDATING: &[(&str, &[&str])] = &[
    (
        "wif-check",
        &[
            "provider-open",
            "binding-whole-pool",
            "binding-unscoped",
            "attribute-by-name",
            "pool-several-providers",
            "provider-custom-audience",
            "data-access-logs-off",
            "outside-account-broad-role",
            "federated-account-basic-role",
            "provider-changes-unalerted",
            "condition-substring",
        ],
    ),
    (
        "github-env-check",
        &[
            "prod-env-no-required-reviewers",
            "env-no-required-reviewers",
            "env-self-review-allowed",
            "prod-env-any-branch",
            "env-any-branch",
            "env-admins-bypass",
            "repo-no-environments",
            "repo-no-production-environment",
        ],
    ),
];

fn templates() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../module-templates")
}

fn planted_dir(check: &str) -> PathBuf {
    templates().join(check).join("fixtures").join("planted")
}

fn predating(check: &str) -> BTreeSet<&'static str> {
    PREDATING
        .iter()
        .filter(|(name, _)| *name == check)
        .flat_map(|(_, rules)| rules.iter().copied())
        .collect()
}

/// The rules a check says it has.
fn rules_of(check: &str, run: Run) -> Vec<String> {
    let out = run(json!({"config": {"CATALOGUE_ONLY": true}}).to_string())
        .unwrap_or_else(|e| panic!("{check}: its catalogue could not be read: {e}"));
    let catalogue: Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("{check}: its catalogue is not JSON: {e}"));
    assert_eq!(
        catalogue["kind"], "security_catalogue",
        "{check}: CATALOGUE_ONLY did not return a catalogue"
    );
    let rules: Vec<String> = catalogue["catalogue"]["rules"]
        .as_array()
        .unwrap_or_else(|| panic!("{check}: the catalogue has no rules"))
        .iter()
        .map(|r| {
            r["rule"]
                .as_str()
                .unwrap_or_else(|| panic!("{check}: a rule has no id"))
                .to_string()
        })
        .collect();
    assert!(!rules.is_empty(), "{check}: the catalogue has no rules");
    rules
}

/// One fixture run through the real check: (findings' rules, passed, not assessed).
fn result_of(check: &str, run: Run, fixture: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let path = planted_dir(check).join(format!("{fixture}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("{check}: {} is missing. Every rule needs evidence with its fault planted, and one clean case for them all.", path.display())
    });
    let envelope: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: not JSON: {e}", path.display()));
    assert!(
        envelope.get("input").is_some_and(Value::is_object)
            && envelope.get("config").is_none_or(Value::is_object),
        "{}: a fixture is {{\"config\": …, \"input\": …}}",
        path.display()
    );
    assert!(
        envelope["config"].get("CATALOGUE_ONLY").is_none()
            && envelope["config"]
                .get("ACCEPTED")
                .is_none_or(|a| a == &json!([])),
        "{}: a fixture judges the evidence, with nothing accepted away",
        path.display()
    );
    let out = run(envelope.to_string())
        .unwrap_or_else(|e| panic!("{}: the check failed on it: {e}", path.display()));
    let result: Value = serde_json::from_str(&out).expect("the check's output is JSON");
    assert_eq!(
        result["kind"],
        "security_check",
        "{}: the check did not judge it",
        path.display()
    );
    let names = |v: &Value| {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let found = result["findings"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|f| f["rule"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    (
        found,
        names(&result["passed"]),
        names(&result["not_assessed"]),
    )
}

#[test]
fn every_rule_catches_its_planted_fault_and_passes_a_clean_case() {
    for (check, run) in CHECKS {
        let old = predating(check);
        let held: Vec<String> = rules_of(check, *run)
            .into_iter()
            .filter(|r| !old.contains(r.as_str()))
            .collect();
        // A fixture for a rule the check no longer has (or never had) proves nothing and is not left lying.
        if let Ok(dir) = std::fs::read_dir(planted_dir(check)) {
            for entry in dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let stem = name
                    .strip_suffix(".json")
                    .unwrap_or_else(|| panic!("{check}: {name} is not a fixture (.json)"));
                assert!(
                    stem == "clean" || held.iter().any(|r| r == stem),
                    "{check}: {name} is for no rule this gate holds"
                );
            }
        }
        if held.is_empty() {
            continue;
        }
        let (clean_found, clean_passed, clean_unassessed) = result_of(check, *run, "clean");
        assert!(
            clean_found.is_empty() && clean_unassessed.is_empty(),
            "{check}: clean.json is not clean: findings {clean_found:?}, not assessed {clean_unassessed:?}"
        );
        for rule in &held {
            let (found, passed, unassessed) = result_of(check, *run, rule);
            assert!(
                found.contains(rule),
                "{check}: {rule} did not catch its planted fault (it found {found:?})"
            );
            assert!(
                !passed.contains(rule) && !unassessed.contains(rule),
                "{check}: {rule} reports a finding and also says it passed or was not assessed"
            );
            assert!(
                clean_passed.contains(rule) && !clean_unassessed.contains(rule),
                "{check}: on the clean case {rule} must be assessed and pass"
            );
        }
    }
}

#[test]
fn every_template_with_planted_faults_is_held_here() {
    let held: BTreeSet<&str> = CHECKS.iter().map(|(name, _)| *name).collect();
    let mut found = BTreeSet::new();
    for entry in std::fs::read_dir(templates())
        .expect("module-templates")
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().to_string();
        if entry.path().join("fixtures").join("planted").is_dir() {
            assert!(
                held.contains(name.as_str()),
                "{name} carries planted faults and is not in CHECKS here, so nothing runs them"
            );
            found.insert(name);
        }
    }
    // A check whose every rule predates the gate has nothing to plant yet; any other carries its fixtures.
    for (name, run) in CHECKS {
        let old = predating(name);
        let all_predate = rules_of(name, *run)
            .iter()
            .all(|r| old.contains(r.as_str()));
        assert!(
            found.contains(*name) || all_predate,
            "{name} is in CHECKS and carries no fixtures/planted/"
        );
    }
}

#[test]
fn the_list_of_rules_that_predate_the_gate_only_shrinks() {
    for (check, listed) in PREDATING {
        let (_, run) = CHECKS
            .iter()
            .find(|(name, _)| name == check)
            .unwrap_or_else(|| panic!("{check} is listed as predating the gate and is not a check here: take it off the list"));
        let rules = rules_of(check, *run);
        for rule in *listed {
            assert!(rules.iter().any(|r| r == rule), "{check}: {rule} is listed as predating the gate and is not a rule any more: take it off the list");
            assert!(
                !planted_dir(check).join(format!("{rule}.json")).exists(),
                "{check}: {rule} has its planted fault now: take it off the list, so the gate holds it"
            );
        }
    }
    let total: usize = PREDATING.iter().map(|(_, rules)| rules.len()).sum();
    assert!(total <= 19, "the list of rules that predate the gate grew to {total}: a new rule gets its fixtures instead");
}
