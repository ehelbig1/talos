// github-env-check: judges how an organisation's repositories protect their
// deployment environments on GitHub, from evidence a reader collected, by
// fixed rules. It reads its input and calls nothing.
//
// Each rule says where it comes from. A rule that cites a published page
// cites the page, the heading and its anchor; a rule that is this module's
// own judgement says so. Nothing here is decided by a model.
//
// Fail-closed, the same way as the workload identity check:
//   * no evidence is an error, not a clean result;
//   * a part of the evidence that was not read makes the rules that need it
//     "not assessed", and what they found on the rest is dropped with them;
//   * "clean" means every rule was assessed and none matched.
//
// A production environment and any other kind are held to the same published
// rules but reported under different names, so that "production is
// protected" can be answered without first protecting every preview. Which
// environments are production is read from their names (`PRODUCTION` in the
// node's config, or the usual words); the table says what each was taken
// for, and a repository with no environment taken for production is itself
// a finding, so a misnamed one cannot pass unseen.
//
// What it does not see, and says so in the table it draws: whether a
// "protected branches only" policy is backed by a branch that is protected
// (that needs a permission the reader is not given), and whether each job
// that deploys names an environment at all.
//
// A finding decided to be acceptable is written into the node's config as
// "rule:severity:subject", exactly as reported, and is then listed as
// accepted instead of found.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const CHECK: &str = "github-environments";
const TITLE: &str = "GitHub environments check";
const PARTS: [&str; 2] = ["repositories", "environments"];
/// The keeper remembers at most two hundred. More than this is refused, never cut.
const MAX_FINDINGS: usize = 180;
const MAX_ROWS: usize = 60;
/// How long the list of environments in one row may be (the report shows this much of a cell).
const ENV_CELL_CHARS: usize = 600;

struct Doc {
    id: &'static str,
    publisher: &'static str,
    title: &'static str,
    url: &'static str,
}
const SECURE_USE: Doc = Doc { id: "github-actions-secure-use", publisher: "GitHub", title: "Secure use reference", url: "https://docs.github.com/en/actions/reference/security/secure-use" };
const ENVIRONMENTS: Doc = Doc { id: "github-deployments-environments", publisher: "GitHub", title: "Deployments and environments", url: "https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments" };
const DOCS: [&Doc; 2] = [&SECURE_USE, &ENVIRONMENTS];

struct Cite {
    doc: &'static Doc,
    anchor: &'static str,
    heading: &'static str,
}
struct Rule {
    id: &'static str,
    needs: &'static [&'static str],
    sources: &'static [Cite],
    task: &'static str,
    remedy: &'static str,
}
const REVIEW: [Cite; 2] = [
    Cite { doc: &SECURE_USE, anchor: "use-secrets-for-sensitive-information", heading: "Use secrets for sensitive information" },
    Cite { doc: &ENVIRONMENTS, anchor: "required-reviewers", heading: "Required reviewers" },
];
const BRANCHES: [Cite; 1] = [Cite { doc: &ENVIRONMENTS, anchor: "deployment-branches-and-tags", heading: "Deployment branches and tags" }];
const RULES: [Rule; 8] = [
    // "Consider requiring review for access to secrets"; "Use required reviewers to require a specific person or team to approve workflow jobs that reference the environment."
    // The same published rule, reported apart for production and for every other environment:
    // what must hold before a production deployment is not what a preview needs.
    Rule { id: "prod-env-no-required-reviewers", needs: &["environments"], task: "Require a reviewer's approval on production deployment environments",
           remedy: "Add required reviewers to the environment, so that a job deploying from it waits for a named person or team to approve.", sources: &REVIEW },
    Rule { id: "env-no-required-reviewers", needs: &["environments"], task: "Require a reviewer's approval on non-production deployment environments",
           remedy: "Add required reviewers to the environment, or record why this kind of environment deploys without an approval.", sources: &REVIEW },
    // "This ensures that deployments to protected environments are always reviewed by more than one person."
    Rule { id: "env-self-review-allowed", needs: &["environments"], task: "Prevent self-review on protected deployment environments",
           remedy: "Turn on \"Prevent self-review\" for the environment, so that the person who starts a deployment cannot be the one who approves it.",
           sources: &[Cite { doc: &ENVIRONMENTS, anchor: "required-reviewers", heading: "Required reviewers" }] },
    // "Use deployment branches and tags to restrict which branches and tags can deploy to the environment."
    Rule { id: "prod-env-any-branch", needs: &["environments"], task: "Restrict which branches and tags can deploy to production environments",
           remedy: "Set the environment's deployment branches and tags to protected branches or to named patterns, so that a job on any other branch cannot use it.", sources: &BRANCHES },
    Rule { id: "env-any-branch", needs: &["environments"], task: "Restrict which branches and tags can deploy to non-production environments",
           remedy: "Set the environment's deployment branches and tags to protected branches or to named patterns, or record why this kind of environment takes any branch.", sources: &BRANCHES },
    Rule { id: "env-admins-bypass", needs: &["environments"], task: "Stop administrators bypassing environment protection rules",
           remedy: "Turn off \"Allow administrators to bypass configured protection rules\" on the environment.", sources: &[] },
    Rule { id: "repo-no-environments", needs: &["repositories", "environments"], task: "Define protected deployment environments in repositories that deploy to the cloud",
           remedy: "Create an environment for each deployment target, give it required reviewers and a branch restriction, and have the jobs that deploy name it.", sources: &[] },
    // Without this, a repository whose production environment has a name this check does not
    // recognise would pass both production rules with nothing looked at.
    Rule { id: "repo-no-production-environment", needs: &["repositories", "environments"], task: "Name the production deployment environment of each repository",
           remedy: "Create the environment production deployments run in, or tell the check which environment names mean production, so that its protection can be verified.", sources: &[] },
];
/// What the environments page describes that this check does not judge, and why.
const NOT_JUDGED: [(Cite, &str); 3] = [
    (Cite { doc: &ENVIRONMENTS, anchor: "wait-timer", heading: "Wait timer" }, "a delay before a deployment is a choice, not a protection this check asks for"),
    (Cite { doc: &ENVIRONMENTS, anchor: "custom-deployment-protection-rules", heading: "Custom deployment protection rules" }, "rules run by other apps; what each one enforces is not in this evidence (their number is shown)"),
    (Cite { doc: &ENVIRONMENTS, anchor: "environment-secrets", heading: "Environment secrets" }, "needs a permission the reader is not given"),
];

fn cite_json(c: &Cite) -> serde_json::Value {
    serde_json::json!({ "document": c.doc.id, "publisher": c.doc.publisher, "title": c.doc.title, "heading": c.heading, "anchor": c.anchor, "url": format!("{}#{}", c.doc.url, c.anchor) })
}
/// What the check hands on besides its findings, in its own words. A reader
/// asking "can this check show X" is answered from here, as it is answered
/// from the rules for "can it judge X".
const PRODUCTS: [(&str, &str); 1] = [("environment-table", "A table of each repository's deployment environments and how each is protected: required reviewers, branch limits and admin bypass")];

fn catalogue() -> serde_json::Value {
    serde_json::json!({
        "documents": DOCS.iter().map(|d| serde_json::json!({ "id": d.id, "publisher": d.publisher, "title": d.title, "url": d.url, "every_heading_accounted_for": false })).collect::<Vec<_>>(),
        "products": PRODUCTS.iter().map(|(id, says)| serde_json::json!({ "id": id, "says": says })).collect::<Vec<_>>(),
        "rules": RULES.iter().map(|r| serde_json::json!({
            "rule": r.id,
            "basis": if r.sources.is_empty() { "local judgement" } else { "published guidance" },
            "task": r.task,
            "remedy": r.remedy,
            "sources": r.sources.iter().map(cite_json).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "not_judged": NOT_JUDGED.iter().map(|(c, why)| { let mut j = cite_json(c); j["why"] = (*why).into(); j }).collect::<Vec<_>>(),
    })
}

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
    #[serde(default)]
    input: Option<EvidenceIn>,
}
#[derive(Deserialize, Default)]
struct Config {
    #[serde(rename = "ACCEPTED")]
    accepted: Option<Vec<String>>,
    #[serde(rename = "CATALOGUE_ONLY")]
    catalogue_only: Option<bool>,
    /// The words that mark an environment's name as production (default: prod, production, prd, live).
    #[serde(rename = "PRODUCTION")]
    production: Option<Vec<String>>,
}
#[derive(Deserialize, Default)]
struct EvidenceIn {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    owner: String,
    repositories: Option<Vec<Repo>>,
    #[serde(default)]
    unread: Vec<String>,
}
#[derive(Deserialize)]
struct Repo {
    #[serde(default)]
    repo: String,
    #[serde(default)]
    environments: Vec<Env>,
}
#[derive(Deserialize)]
struct Env {
    #[serde(default)]
    name: String,
    #[serde(default)]
    reviewers: u64,
    #[serde(default)]
    prevent_self_review: bool,
    #[serde(default)]
    custom_rules: u64,
    #[serde(default)]
    branches: String,
    #[serde(default)]
    patterns: Vec<String>,
    /// GitHub's default is that administrators may bypass: absent counts as allowed.
    #[serde(default = "yes")]
    admins_bypass: bool,
}
fn yes() -> bool {
    true
}

struct Finding {
    rule: &'static str,
    severity: &'static str,
    subject: String,
    says: String,
}

/// A name from evidence, as it may be shown: plain characters, cut to a length.
fn name(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || "-_./@:* ".contains(*c)).take(100).collect::<String>().trim().to_string()
}
fn owner_ok(s: &str) -> bool {
    (1..=40).contains(&s.len()) && s.as_bytes()[0].is_ascii_alphanumeric() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
const PRODUCTION_WORDS: [&str; 4] = ["prod", "production", "prd", "live"];
/// Whether an environment's name says it is where production is deployed
/// from: one of its words (split at anything that is not a letter or digit)
/// is a production word, and the word before it is not "non", "pre" or "not".
/// So "production", "app-prod" and "prod-eu" are; "nonprod", "non-prod",
/// "pre-prod" and "reproduce" are not.
fn production(env: &str, words: &[String]) -> bool {
    let lower = env.to_lowercase();
    let tokens: Vec<&str> = lower.split(|c: char| !c.is_ascii_alphanumeric()).filter(|t| !t.is_empty()).collect();
    tokens.iter().enumerate().any(|(n, t)| words.iter().any(|w| w == t) && !(n > 0 && ["non", "pre", "not"].contains(&tokens[n - 1])))
}
/// Which branches a policy lets deploy. Anything but a known restriction is "any".
fn restricted(e: &Env) -> bool {
    e.branches == "protected" || (e.branches == "selected" && !e.patterns.is_empty())
}

fn check(repos: &[Repo], words: &[String]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    for r in repos {
        let repo = name(&r.repo);
        if r.environments.is_empty() {
            findings.push(Finding { rule: "repo-no-environments", severity: "medium", subject: repo.clone(), says: "defines no deployment environment, so nothing on GitHub's side asks for an approval or limits the branch before a job deploys".to_string() });
        } else if !r.environments.iter().any(|e| production(&e.name, words)) {
            findings.push(Finding { rule: "repo-no-production-environment", severity: "medium", subject: repo.clone(), says: "has environments, and none has a name this check takes for production, so what protects its production deployments was not looked at".to_string() });
        }
        for e in &r.environments {
            let at = format!("{repo}/{}", name(&e.name));
            let prod = production(&e.name, words);
            if e.reviewers == 0 {
                let (rule, severity) = if prod { ("prod-env-no-required-reviewers", "high") } else { ("env-no-required-reviewers", "medium") };
                findings.push(Finding { rule, severity, subject: at.clone(), says: "has no required reviewers: a job that names it deploys without anybody's approval".to_string() });
            } else if !e.prevent_self_review {
                findings.push(Finding { rule: "env-self-review-allowed", severity: "low", subject: at.clone(), says: "lets the person who started a deployment approve it, if they are a reviewer".to_string() });
            }
            if !restricted(e) {
                let (rule, severity) = if prod { ("prod-env-any-branch", "high") } else { ("env-any-branch", "medium") };
                findings.push(Finding { rule, severity, subject: at.clone(), says: "can be deployed to from any branch or tag, a pull request's branch included".to_string() });
            }
            if e.admins_bypass && (e.reviewers > 0 || restricted(e)) {
                findings.push(Finding { rule: "env-admins-bypass", severity: "low", subject: at, says: "lets repository administrators skip its protection rules and force a deployment".to_string() });
            }
        }
    }
    findings
}

/// One row for the environments of a repository that are protected alike:
/// forty environments are rarely forty different setups. Every environment
/// is named in some row; none is left out.
fn table(repos: &[Repo], words: &[String]) -> Option<Vec<Vec<String>>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    for r in repos {
        let repo = name(&r.repo);
        if r.environments.is_empty() {
            rows.push(vec![repo.clone(), "(none)".to_string(), String::new(), String::new(), String::new(), String::new(), String::new()]);
        }
        let start = rows.len();
        for e in &r.environments {
            let from = match e.branches.as_str() {
                "protected" => "protected branches (whether any branch is protected is not checked)".to_string(),
                "selected" if !e.patterns.is_empty() => e.patterns.iter().take(6).map(|p| name(p)).collect::<Vec<_>>().join(", "),
                _ => "any branch or tag".to_string(),
            };
            let mut reviewers = e.reviewers.to_string();
            if e.custom_rules > 0 {
                reviewers.push_str(&format!(" (+{} custom rule(s), not judged)", e.custom_rules));
            }
            let alike = [
                if production(&e.name, words) { "production".to_string() } else { "other".to_string() },
                reviewers,
                if e.reviewers == 0 { "n/a".to_string() } else if e.prevent_self_review { "prevented".to_string() } else { "allowed".to_string() },
                from,
                if e.admins_bypass { "yes".to_string() } else { "no".to_string() },
            ];
            // A row takes names while its list stays short enough to be shown whole; then another row begins.
            let fits = |row: &Vec<String>| row[1].chars().count() + 2 + name(&e.name).chars().count() <= ENV_CELL_CHARS;
            match rows[start..].iter_mut().find(|row| row[2..] == alike && fits(row)) {
                Some(row) => {
                    row[1].push_str(", ");
                    row[1].push_str(&name(&e.name));
                }
                None => {
                    let [kind, a, b, c, d] = alike;
                    rows.push(vec![repo.clone(), name(&e.name), kind, a, b, c, d]);
                }
            }
        }
    }
    // A table that would be cut is not drawn: half a table reads as the whole of it.
    (rows.len() <= MAX_ROWS && rows.iter().all(|r| r[1].chars().count() <= ENV_CELL_CHARS)).then_some(rows)
}

#[talos_module(world = "minimal-node")]
pub fn run(input: String) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    if envelope.config.catalogue_only.unwrap_or(false) {
        return serde_json::to_string(&serde_json::json!({ "kind": "security_catalogue", "check": CHECK, "title": TITLE, "catalogue": catalogue() })).map_err(|e| e.to_string());
    }
    // No evidence is a failure, never a clean result.
    let arrived = envelope.input.filter(|e| e.kind == "github_env_evidence").ok_or("the evidence did not arrive")?;
    if arrived.unread.iter().any(|part| !PARTS.contains(&part.as_str())) {
        return Err("the evidence names a part this check does not know".to_string());
    }
    if !owner_ok(&arrived.owner) {
        return Err("the evidence does not name its owner plainly".to_string());
    }
    let mut unread: Vec<String> = arrived.unread.clone();
    // A list that did not arrive was not read, whatever `unread` says.
    if arrived.repositories.is_none() {
        for part in PARTS {
            if !unread.iter().any(|u| u == part) {
                unread.push(part.to_string());
            }
        }
    }
    let repos = arrived.repositories.unwrap_or_default();
    let accepted_list = match envelope.config.accepted {
        None => Vec::new(),
        Some(list) if list.len() <= 20 && list.iter().all(|a| a.len() <= 300) => list,
        Some(_) => return Err("ACCEPTED holds at most twenty findings".to_string()),
    };
    let not_assessed: Vec<&str> = RULES.iter().filter(|r| r.needs.iter().any(|n| unread.iter().any(|u| u == n))).map(|r| r.id).collect();
    // Which names mean production: the node's words, or the usual ones.
    let words: Vec<String> = match envelope.config.production {
        None => PRODUCTION_WORDS.iter().map(|w| w.to_string()).collect(),
        Some(list) if !list.is_empty() && list.len() <= 10 && list.iter().all(|w| !w.is_empty() && w.len() <= 20 && w.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())) => list,
        Some(_) => return Err("PRODUCTION holds one to ten words of lower-case letters and digits".to_string()),
    };
    let all: Vec<Finding> = check(&repos, &words).into_iter().filter(|f| !not_assessed.contains(&f.rule)).collect();
    if all.len() > MAX_FINDINGS {
        return Err(format!("the check found more than {MAX_FINDINGS} things; reporting some of them would hide the rest"));
    }
    let passed: Vec<&str> = RULES.iter().map(|r| r.id).filter(|id| !not_assessed.contains(id) && !all.iter().any(|f| f.rule == *id)).collect();
    let (accepted, findings): (Vec<Finding>, Vec<Finding>) = all.into_iter().partition(|f| accepted_list.iter().any(|a| *a == format!("{}:{}:{}", f.rule, f.severity, f.subject)));
    let worst = ["critical", "high", "medium", "low"].iter().find(|s| findings.iter().any(|f| f.severity == **s)).copied();
    let with_sources = |list: &[Finding]| -> Vec<serde_json::Value> {
        list.iter()
            .map(|f| {
                let sources: Vec<serde_json::Value> = RULES.iter().find(|r| r.id == f.rule).map(|r| r.sources.iter().map(cite_json).collect()).unwrap_or_default();
                serde_json::json!({ "rule": f.rule, "severity": f.severity, "subject": f.subject, "says": f.says,
                                    "basis": if sources.is_empty() { "local judgement" } else { "published guidance" }, "sources": sources })
            })
            .collect()
    };
    let environments: usize = repos.iter().map(|r| r.environments.len()).sum();
    serde_json::to_string(&serde_json::json!({
        "kind": "security_check", "check": CHECK, "title": TITLE, "project": arrived.owner,
        // Clean only when every rule could be assessed and none matched.
        "clean": findings.is_empty() && not_assessed.is_empty(),
        "worst": worst,
        "findings": with_sources(&findings), "accepted": with_sources(&accepted), "passed": passed, "not_assessed": not_assessed,
        "not_judged": NOT_JUDGED.len(),
        // Drawn only when everything was read; otherwise its rows are absent, never partial.
        "table": {
            "title": "Environments",
            "columns": ["Repository", "Environment", "Kind", "Required reviewers", "Self-review", "Deploys from", "Admins can bypass"],
            "rows": if unread.is_empty() { serde_json::json!(table(&repos, &words)) } else { serde_json::Value::Null },
        },
        "counted": { "repositories": repos.len(), "environments": environments, "production": repos.iter().flat_map(|r| r.environments.iter()).filter(|e| production(&e.name, &words)).count() },
        "production_words": words,
        "unread": unread,
    }))
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
use super::*;
use serde_json::{json, Value};
use talos_module_testkit::host;

fn env(name: &str, reviewers: u64, no_self: bool, branches: &str, patterns: Value, bypass: bool) -> Value {
    json!({"name": name, "reviewers": reviewers, "prevent_self_review": no_self, "wait_minutes": 0, "custom_rules": 0, "branches": branches, "patterns": patterns, "admins_bypass": bypass})
}
fn evidence(repos: Value) -> Value {
    json!({"kind": "github_env_evidence", "owner": "example-org", "repositories": repos, "unread": [], "errors": {}})
}
fn check_of(evidence: Value) -> Value {
    serde_json::from_str(&run(json!({"input": evidence}).to_string()).unwrap()).unwrap()
}
fn rules(out: &Value) -> Vec<(String, String, String)> {
    out["findings"].as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["severity"].as_str().unwrap().to_string(), f["subject"].as_str().unwrap().to_string())).collect()
}
fn f(rule: &str, severity: &str, subject: &str) -> (String, String, String) {
    (rule.to_string(), severity.to_string(), subject.to_string())
}

#[test]
fn every_rule_says_where_it_comes_from_and_names_its_ticket() {
    let out: Value = serde_json::from_str(&run(json!({"config": {"CATALOGUE_ONLY": true}}).to_string()).unwrap()).unwrap();
    assert_eq!((out["kind"].as_str(), out["check"].as_str(), out["title"].as_str()), (Some("security_catalogue"), Some("github-environments"), Some("GitHub environments check")));
    let listed = out["catalogue"]["rules"].as_array().unwrap();
    assert_eq!(listed.len(), RULES.len());
    // Two rules are this module's own judgement and say so; the rest cite GitHub's pages by heading and anchor.
    let local: Vec<&str> = listed.iter().filter(|r| r["basis"] == "local judgement").map(|r| r["rule"].as_str().unwrap()).collect();
    assert_eq!(local, ["env-admins-bypass", "repo-no-environments", "repo-no-production-environment"]);
    for r in listed {
        for s in r["sources"].as_array().unwrap() {
            assert!(s["url"].as_str().unwrap().starts_with("https://docs.github.com/") && s["url"].as_str().unwrap().ends_with(&format!("#{}", s["anchor"].as_str().unwrap())), "{s}");
            assert_eq!(s["publisher"], "GitHub");
        }
        let (task, remedy) = (r["task"].as_str().unwrap(), r["remedy"].as_str().unwrap());
        assert!((20..=90).contains(&task.len()) && task.chars().next().unwrap().is_ascii_uppercase() && !task.ends_with('.'), "{task}");
        assert!((30..=240).contains(&remedy.len()) && remedy.ends_with('.'), "{remedy}");
    }
    let mut titles: Vec<&str> = listed.iter().map(|r| r["task"].as_str().unwrap()).collect();
    titles.sort_unstable();
    titles.dedup();
    assert_eq!(titles.len(), RULES.len());
    // What is not judged is listed with a reason, and nothing is both judged and not judged.
    let not_judged = out["catalogue"]["not_judged"].as_array().unwrap();
    let cited: Vec<&str> = listed.iter().flat_map(|r| r["sources"].as_array().unwrap()).map(|s| s["anchor"].as_str().unwrap()).collect();
    assert!(not_judged.len() == 3 && not_judged.iter().all(|n| !n["why"].as_str().unwrap().is_empty() && !cited.contains(&n["anchor"].as_str().unwrap())));
    // Every document a rule cites is one the catalogue lists.
    let docs: Vec<&str> = out["catalogue"]["documents"].as_array().unwrap().iter().map(|d| d["id"].as_str().unwrap()).collect();
    assert!(listed.iter().flat_map(|r| r["sources"].as_array().unwrap()).chain(not_judged.iter()).all(|s| docs.contains(&s["document"].as_str().unwrap())));
}

#[test]
fn a_protected_environment_is_clean_and_each_gap_is_named_by_its_rule() {
    let hardened = evidence(json!([{"repo": "infra", "environments": [env("production", 2, true, "selected", json!(["main"]), false), env("staging", 1, true, "protected", json!([]), false)]}]));
    let out = check_of(hardened);
    assert_eq!((out["clean"].as_bool(), out["worst"].clone(), out["findings"].clone(), out["project"].as_str()), (Some(true), Value::Null, json!([]), Some("example-org")));
    assert_eq!(out["passed"].as_array().unwrap().len(), RULES.len());
    assert_eq!(out["table"]["rows"], json!([
        ["infra", "production", "production", "2", "prevented", "main", "no"],
        ["infra", "staging", "other", "1", "prevented", "protected branches (whether any branch is protected is not checked)", "no"],
    ]));
    // Environments of one repository that are protected alike share a row, and every one of them is named.
    let alike = check_of(evidence(json!([
        {"repo": "infra", "environments": [env("dev-a", 0, false, "any", json!([]), true), env("production", 2, true, "selected", json!(["main"]), false), env("dev-b", 0, false, "any", json!([]), true)]},
        {"repo": "app", "environments": [env("dev-a", 0, false, "any", json!([]), true)]},
    ])));
    assert_eq!(alike["table"]["rows"], json!([
        ["infra", "dev-a, dev-b", "other", "0", "n/a", "any branch or tag", "yes"],
        ["infra", "production", "production", "2", "prevented", "main", "no"],
        ["app", "dev-a", "other", "0", "n/a", "any branch or tag", "yes"],
    ]));

    let out = check_of(evidence(json!([
        {"repo": "infra", "environments": [
            env("production", 0, false, "any", json!([]), true),          // no approval, any branch
            env("staging", 1, false, "selected", json!(["main"]), true),  // self-review, admins bypass
            env("preview", 1, true, "selected", json!([]), false),        // "selected" with nothing selected restricts nothing
        ]},
        {"repo": "docs", "environments": []},
    ])));
    // The same gap is one rule on a production environment and another on any other.
    assert_eq!(rules(&out), [
        f("prod-env-no-required-reviewers", "high", "infra/production"),
        f("prod-env-any-branch", "high", "infra/production"),
        f("env-self-review-allowed", "low", "infra/staging"),
        f("env-admins-bypass", "low", "infra/staging"),
        f("env-any-branch", "medium", "infra/preview"),
        f("repo-no-environments", "medium", "docs"),
    ]);
    assert_eq!((out["clean"].as_bool(), out["worst"].as_str(), out["passed"].clone()), (Some(false), Some("high"), json!(["env-no-required-reviewers", "repo-no-production-environment"])));
    assert_eq!(out["counted"], json!({"repositories": 2, "environments": 3, "production": 1}));
    // An environment with nothing to bypass is not reported for bypass: that would say nothing.
    assert!(!rules(&out).contains(&f("env-admins-bypass", "low", "infra/production")));
    let first = &out["findings"][0];
    assert_eq!((first["basis"].as_str(), first["sources"].as_array().unwrap().len()), (Some("published guidance"), 2));
    assert_eq!(out["findings"][3]["basis"], "local judgement");
    assert_eq!(out["table"]["rows"][3], json!(["docs", "(none)", "", "", "", "", ""]));
    // A missing bypass flag is GitHub's default: allowed.
    let mut e = env("production", 1, true, "protected", json!([]), false);
    e.as_object_mut().unwrap().remove("admins_bypass");
    assert_eq!(rules(&check_of(evidence(json!([{"repo": "infra", "environments": [e]}])))), [f("env-admins-bypass", "low", "infra/production")]);
}

#[test]
fn what_could_not_be_read_is_not_assessed_and_never_clean() {
    // One repository's environments unread: every rule that needs them is not assessed, and what the rest showed is dropped with it.
    let mut e = evidence(json!([{"repo": "infra", "environments": [env("production", 0, false, "any", json!([]), true)]}]));
    e["unread"] = json!(["environments"]);
    let out = check_of(e);
    assert_eq!((out["clean"].as_bool(), out["findings"].clone(), out["passed"].clone(), out["table"]["rows"].clone()), (Some(false), json!([]), json!([]), Value::Null));
    assert_eq!(out["not_assessed"].as_array().unwrap().len(), RULES.len());
    // The list did not arrive at all, whatever `unread` says.
    let out = check_of(json!({"kind": "github_env_evidence", "owner": "example-org", "unread": []}));
    assert_eq!((out["clean"].as_bool(), out["not_assessed"].as_array().unwrap().len(), out["unread"].clone()), (Some(false), RULES.len(), json!(["repositories", "environments"])));
    // No repositories at all, read in full: nothing to find, and that is clean.
    let out = check_of(evidence(json!([])));
    assert_eq!((out["clean"].as_bool(), out["table"]["rows"].clone()), (Some(true), json!([])));
    // No evidence, evidence of another kind, an unknown part, an owner that is not a name: errors.
    assert_eq!(run(json!({}).to_string()).unwrap_err(), "the evidence did not arrive");
    assert_eq!(run(json!({"input": {"kind": "wif_evidence", "owner": "example-org", "repositories": []}}).to_string()).unwrap_err(), "the evidence did not arrive");
    let mut odd = evidence(json!([]));
    odd["unread"] = json!(["something"]);
    assert_eq!(run(json!({"input": odd}).to_string()).unwrap_err(), "the evidence names a part this check does not know");
    let mut odd = evidence(json!([]));
    odd["owner"] = json!("Example/Org");
    assert_eq!(run(json!({"input": odd}).to_string()).unwrap_err(), "the evidence does not name its owner plainly");
}

#[test]
fn an_exception_is_accepted_only_exactly_as_it_was_reported() {
    let e = evidence(json!([{"repo": "infra", "environments": [env("preview", 0, false, "selected", json!(["main"]), false), env("production", 1, true, "selected", json!(["main"]), false)]}]));
    let accept = |list: Value| -> Value { serde_json::from_str(&run(json!({"config": {"ACCEPTED": list}, "input": e}).to_string()).unwrap()).unwrap() };
    let ok = accept(json!(["env-no-required-reviewers:medium:infra/preview"]));
    assert_eq!((ok["clean"].as_bool(), ok["findings"].clone(), ok["accepted"].as_array().unwrap().len()), (Some(true), json!([]), 1));
    // A rule with only accepted findings did not pass outright.
    assert!(!ok["passed"].as_array().unwrap().iter().any(|r| r == "env-no-required-reviewers"));
    for near in [json!(["env-no-required-reviewers:high:infra/preview"]), json!(["env-no-required-reviewers:medium:infra/*"]), json!(["env-no-required-reviewers:infra/preview"])] {
        assert_eq!(accept(near)["clean"], false);
    }
    assert_eq!(run(json!({"config": {"ACCEPTED": vec!["x"; 21]}, "input": e}).to_string()).unwrap_err(), "ACCEPTED holds at most twenty findings");
}

#[test]
fn more_than_can_be_carried_is_refused_and_never_cut() {
    // 100 unprotected environments: 200 findings. Reporting the first 180 would hide twenty.
    let envs: Vec<Value> = (0..100).map(|n| env(&format!("e{n}"), 0, false, "any", json!([]), false)).collect();
    let big = evidence(json!([{"repo": "infra", "environments": envs}]));
    assert_eq!(run(json!({"input": big}).to_string()).unwrap_err(), "the check found more than 180 things; reporting some of them would hide the rest");
    // 60 environments, 120 findings: all of them are reported, and the table names every environment.
    let envs: Vec<Value> = (0..60).map(|n| env(&format!("e{n}"), 0, false, "any", json!([]), false)).collect();
    let out = check_of(evidence(json!([{"repo": "infra", "environments": envs}])));
    // (Two per environment, and one for the repository: none of these is named for production.)
    assert_eq!(out["findings"].as_array().unwrap().len(), 121);
    let rows = out["table"]["rows"].as_array().unwrap();
    assert_eq!((rows.len(), rows[0][1].as_str().unwrap().split(", ").count()), (1, 60));
    // A list of names too long for one cell carries on in another row: every name is in some row, none is cut.
    let envs: Vec<Value> = (0..60).map(|n| env(&format!("environment-with-a-long-name-{n}"), 0, false, "any", json!([]), false)).collect();
    let out = check_of(evidence(json!([{"repo": "infra", "environments": envs}])));
    let rows = out["table"]["rows"].as_array().unwrap();
    assert!(rows.len() > 1 && rows.iter().all(|r| r[1].as_str().unwrap().chars().count() <= 600 && r.as_array().unwrap()[2..] == rows[0].as_array().unwrap()[2..]));
    assert_eq!(rows.iter().map(|r| r[1].as_str().unwrap().split(", ").count()).sum::<usize>(), 60);
    // More rows than a table should have: it is not drawn, rather than drawn short.
    let repos: Vec<Value> = (0..61).map(|n| json!({"repo": format!("r{n}"), "environments": []})).collect();
    assert_eq!(check_of(evidence(Value::Array(repos)))["table"]["rows"], Value::Null);
}

#[test]
fn production_is_read_from_a_names_words_and_a_repository_without_one_is_a_finding() {
    let usual: Vec<String> = PRODUCTION_WORDS.iter().map(|w| w.to_string()).collect();
    for name in ["production", "Production", "app-prod", "prod-eu", "site_prd", "live", "production-pr"] {
        assert!(production(name, &usual), "{name}");
    }
    // A word that merely contains one, or that is negated, is not production.
    for name in ["nonprod", "non-prod", "pre-prod", "preprod", "not_production", "reproduce", "preview-np", "product", "delivery", ""] {
        assert!(!production(name, &usual), "{name}");
    }
    // An unprotected environment that is not production is the lesser rule, at the lesser severity.
    let nonprod = evidence(json!([{"repo": "infra", "environments": [env("nonprod", 0, false, "any", json!([]), false), env("production", 2, true, "selected", json!(["main"]), false)]}]));
    assert_eq!(rules(&check_of(nonprod)), [f("env-no-required-reviewers", "medium", "infra/nonprod"), f("env-any-branch", "medium", "infra/nonprod")]);
    // A repository whose environments include none taken for production: the production rules found
    // nothing because they looked at nothing, and that is said instead of passed over.
    let unnamed = evidence(json!([{"repo": "infra", "environments": [env("main-site", 2, true, "selected", json!(["main"]), false)]}]));
    let out = check_of(unnamed.clone());
    assert_eq!(rules(&out), [f("repo-no-production-environment", "medium", "infra")]);
    assert_eq!((out["clean"].as_bool(), out["table"]["rows"][0][2].as_str()), (Some(false), Some("other")));
    // The node can say which words mean production here.
    let told: Value = serde_json::from_str(&run(json!({"config": {"PRODUCTION": ["main"]}, "input": unnamed}).to_string()).unwrap()).unwrap();
    assert_eq!((told["clean"].as_bool(), told["table"]["rows"][0][2].as_str(), told["production_words"].clone()), (Some(true), Some("production"), json!(["main"])));
    for bad in [json!([]), json!(["Prod"]), json!(["a b"]), json!(vec!["x"; 11])] {
        assert_eq!(run(json!({"config": {"PRODUCTION": bad}, "input": evidence(json!([]))}).to_string()).unwrap_err(), "PRODUCTION holds one to ten words of lower-case letters and digits");
    }
}
}
