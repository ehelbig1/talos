// github-env-evidence: reads how an organisation's repositories protect
// their deployment environments on GitHub: which environments each
// repository has, whether a deployment needs a reviewer's approval, whether
// the person who started it may approve it, which branches may deploy, and
// whether administrators may bypass all of that. It reads; every request is
// a GET, and the module is granted that verb only.
//
// WHICH repositories is not this module's choice, nor its config's: it reads
// the repositories the GitHub App was installed on, and nothing else can be
// reached with the token it is given. Installing the App on the repositories
// the cloud's identity providers trust is what scopes this.
//
// It judges nothing. What it could not read it says so in `unread` instead
// of handing on an empty list: an empty list of environments means the
// repository has none.
//
// Requests: the installation's repositories, then one listing of
// environments per repository, then one listing of branch patterns for each
// environment that names its own. All bounded.
//
// What it hands on is bounded by its size too: at most 300,000 bytes as
// written, a third of the 1,000,000 the platform takes as a node's input
// (WASM_MAX_INPUT_BYTES). A workflow's first node is given the run's trigger
// three times over (spread as its top-level keys, as `input` and as
// `__trigger_input__`), and a shadow workflow's trigger is this evidence:
// 3 × 300,000 is 900,000, and the rest is room for the node's config and the
// engine's own keys. At the counts alone (30 repositories of 30
// environments, 10 patterns for 40 of them) it could be some 680,000 bytes.
// The repositories are counted as they are read, after room is set aside for
// the rest of the evidence, and one whose environments would take it over the
// bound is left out and the environments named unread, saying how large it
// is: never cut.
//
// Network: api.github.com only. The token is an installation token Talos
// mints for this run; it needs the repository permission "Actions: read".

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const API: &str = "https://api.github.com";
const MAX_REPOS: usize = 30;
const MAX_ENVS: usize = 30;
const MAX_PATTERN_READS: usize = 40;
const MAX_PATTERNS: usize = 10;
/// The most evidence this reader hands on, in bytes as written: a third of the platform's
/// 1,000,000-byte node input, since a workflow's first node is given its trigger three times
/// (3 × 300,000 = 900,000, and 100,000 left for the node's config and the engine's keys).
const MAX_EVIDENCE_BYTES: usize = 300_000;
/// What the evidence holds besides its repositories (kind, owner, unread, errors, counts, and the
/// list's brackets and commas), set aside before any repository is counted. The tests measure the most it can be.
const ENVELOPE_BYTES: usize = 4_000;

/// What the evidence takes so far, in bytes as written, against `MAX_EVIDENCE_BYTES`.
struct Budget {
    used: usize,
}
impl Budget {
    fn new() -> Self {
        Budget { used: ENVELOPE_BYTES }
    }
    /// A part, counted, when it fits in what is left; otherwise nothing is counted and the error says how large it is.
    fn take(&mut self, subject: &str, part: serde_json::Value) -> Result<serde_json::Value, String> {
        let size = part.to_string().len();
        if self.used + size > MAX_EVIDENCE_BYTES {
            return Err(format!("{subject} too large to hand on ({size} bytes as written; the evidence is at most {MAX_EVIDENCE_BYTES} bytes in all)"));
        }
        self.used += size;
        Ok(part)
    }
}

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
}
#[derive(Deserialize, Default)]
struct Config {
    #[serde(rename = "AUTH_HEADER")]
    auth_header: Option<String>,
    /// The organisation (or user) the App is installed on.
    #[serde(rename = "OWNER")]
    owner: Option<String>,
}
#[derive(Deserialize, Default)]
struct Repos {
    #[serde(default)]
    total_count: u64,
    #[serde(default)]
    repositories: Vec<Repo>,
}
#[derive(Deserialize)]
struct Repo {
    #[serde(default)]
    name: String,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    disabled: bool,
    owner: Option<Owner>,
}
#[derive(Deserialize)]
struct Owner {
    #[serde(default)]
    login: String,
}
#[derive(Deserialize, Default)]
struct Environments {
    #[serde(default)]
    total_count: u64,
    #[serde(default)]
    environments: Vec<Environment>,
}
#[derive(Deserialize)]
struct Environment {
    #[serde(default)]
    name: String,
    #[serde(default)]
    protection_rules: Vec<Protection>,
    deployment_branch_policy: Option<BranchPolicy>,
    /// GitHub's default is that administrators may bypass.
    can_admins_bypass: Option<bool>,
}
#[derive(Deserialize)]
struct Protection {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    reviewers: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    prevent_self_review: bool,
    #[serde(default)]
    wait_timer: u64,
}
#[derive(Deserialize)]
struct BranchPolicy {
    #[serde(default)]
    protected_branches: bool,
    #[serde(default)]
    custom_branch_policies: bool,
}
#[derive(Deserialize, Default)]
struct Patterns {
    #[serde(default)]
    branch_policies: Vec<Pattern>,
}
#[derive(Deserialize)]
struct Pattern {
    #[serde(default)]
    name: String,
    #[serde(rename = "type", default)]
    kind: String,
}

/// An account or repository name as GitHub writes one: it goes into request paths.
fn name_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s != "." && s != ".." && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}
fn pct(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}
fn shown(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// One GET. The status and the kind of failure are kept; no body of an error is.
fn get(auth: &str, url: &str) -> Result<Vec<u8>, String> {
    use talos::core::http::{self, Method, Request};
    let req = Request {
        method: Method::Get,
        url: url.to_string(),
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Accept".to_string(), "application/vnd.github+json".to_string()),
            ("X-GitHub-Api-Version".to_string(), "2022-11-28".to_string()),
            ("User-Agent".to_string(), "talos-github-env-evidence".to_string()),
        ],
        body: Vec::new(),
        timeout_ms: Some(20_000),
    };
    let resp = http::fetch(&req).map_err(|e| format!("could not be reached ({e:?})"))?;
    match resp.status {
        200..=299 => Ok(resp.body),
        other => Err(format!("answered HTTP {other}")),
    }
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let cfg = serde_json::from_str::<Envelope>(&input).map_err(|e| format!("Input parse error: {e}"))?.config;
    let auth = cfg.auth_header.filter(|a| !a.trim().is_empty()).ok_or("Missing AUTH_HEADER config")?;
    let owner = cfg.owner.as_deref().map(str::trim).filter(|o| name_ok(o, 39) && !o.contains('.') && !o.contains('_')).ok_or("OWNER must be a GitHub account name")?.to_lowercase();

    let mut unread: Vec<&str> = Vec::new();
    let mut errors = serde_json::Map::new();
    let mut out_repos: Vec<serde_json::Value> = Vec::new();
    let (mut skipped_archived, mut other_owner) = (0usize, 0usize);

    // ---- the repositories the App was installed on
    let listed = (|| -> Result<Vec<Repo>, String> {
        let mut all: Vec<Repo> = Vec::new();
        for page in 1..=2u32 {
            let got: Repos = serde_json::from_slice(&get(&auth, &format!("{API}/installation/repositories?per_page=100&page={page}")).map_err(|e| format!("the repository listing {e}"))?).map_err(|_| "the repository listing answered with something that could not be read".to_string())?;
            let total = got.total_count as usize;
            let n = got.repositories.len();
            all.extend(got.repositories);
            if all.len() >= total || n == 0 {
                return Ok(all);
            }
        }
        // Half a listing is not the listing.
        Err("the App is installed on more than 200 repositories".to_string())
    })();
    let repos: Vec<Repo> = match listed {
        Ok(all) => {
            let mut mine: Vec<Repo> = Vec::new();
            for r in all {
                if !r.owner.as_ref().is_some_and(|o| o.login.eq_ignore_ascii_case(&owner)) {
                    other_owner += 1;
                } else if r.archived || r.disabled {
                    // An archived repository runs no workflow.
                    skipped_archived += 1;
                } else {
                    mine.push(r);
                }
            }
            if mine.len() > MAX_REPOS {
                return Err(format!("the App is installed on more than {MAX_REPOS} active repositories of {owner}; this reader would be cutting them short"));
            }
            mine
        }
        Err(e) => {
            unread.extend(["repositories", "environments"]);
            errors.insert("repositories".to_string(), e.into());
            Vec::new()
        }
    };

    // ---- each repository's environments
    let mut failed_repos = 0usize;
    let mut pattern_reads = 0usize;
    let mut budget = Budget::new();
    for r in &repos {
        if !name_ok(&r.name, 100) {
            failed_repos += 1;
            errors.insert("environments".to_string(), "a repository has a name that could not be used".into());
            continue;
        }
        let read = (|| -> Result<Vec<serde_json::Value>, String> {
            let got: Environments = serde_json::from_slice(&get(&auth, &format!("{API}/repos/{owner}/{}/environments?per_page=100", r.name)).map_err(|e| format!("an environments listing {e}"))?).map_err(|_| "an environments listing answered with something that could not be read".to_string())?;
            if got.total_count as usize > got.environments.len() || got.environments.len() > MAX_ENVS {
                return Err(format!("a repository has more than {} environments", MAX_ENVS.min(100)));
            }
            let mut envs = Vec::new();
            for e in &got.environments {
                let review = e.protection_rules.iter().find(|p| p.kind == "required_reviewers");
                let wait = e.protection_rules.iter().find(|p| p.kind == "wait_timer").map_or(0, |p| p.wait_timer);
                let custom_rules = e.protection_rules.iter().filter(|p| !["required_reviewers", "wait_timer", "branch_policy"].contains(&p.kind.as_str())).count();
                let (branches, patterns) = match &e.deployment_branch_policy {
                    None => ("any", Vec::new()),
                    Some(p) if p.custom_branch_policies => {
                        pattern_reads += 1;
                        if pattern_reads > MAX_PATTERN_READS {
                            return Err(format!("more than {MAX_PATTERN_READS} environments name their own branches"));
                        }
                        let got: Patterns = serde_json::from_slice(&get(&auth, &format!("{API}/repos/{owner}/{}/environments/{}/deployment-branch-policies?per_page=100", r.name, pct(&e.name))).map_err(|e| format!("a branch-pattern listing {e}"))?)
                            .map_err(|_| "a branch-pattern listing answered with something that could not be read".to_string())?;
                        ("selected", got.branch_policies.iter().take(MAX_PATTERNS).map(|p| if p.kind == "tag" { format!("tag:{}", shown(&p.name, 80)) } else { shown(&p.name, 80) }).collect())
                    }
                    Some(p) if p.protected_branches => ("protected", Vec::new()),
                    // A policy object that selects nothing restricts nothing.
                    Some(_) => ("any", Vec::new()),
                };
                envs.push(serde_json::json!({
                    "name": shown(&e.name, 100),
                    "reviewers": review.map_or(0, |p| p.reviewers.len()),
                    "prevent_self_review": review.is_some_and(|p| p.prevent_self_review),
                    "wait_minutes": wait,
                    "custom_rules": custom_rules,
                    "branches": branches,
                    "patterns": patterns,
                    "admins_bypass": e.can_admins_bypass.unwrap_or(true),
                }));
            }
            Ok(envs)
        })();
        // A repository too large to hand on whole is left out, never cut.
        match read.and_then(|envs| budget.take("a repository's environments are", serde_json::json!({ "repo": r.name, "environments": envs }))) {
            Ok(row) => out_repos.push(row),
            Err(e) => {
                failed_repos += 1;
                errors.insert("environments".to_string(), e.into());
            }
        }
    }
    // One repository unread makes the whole part unread: its rules are then not assessed, not passed.
    if failed_repos > 0 && !unread.contains(&"environments") {
        unread.push("environments");
    }

    let mut out = serde_json::json!({
        "kind": "github_env_evidence", "owner": owner,
        "unread": unread, "errors": errors,
        "counted": { "repositories": repos.len(), "repositories_read": out_repos.len(), "archived_skipped": skipped_archived, "other_owner": other_owner },
    });
    // A part that was not read is left out, never written as empty.
    if !unread.contains(&"repositories") {
        out["repositories"] = out_repos.into();
    }
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
use super::*;
use serde_json::{json, Value};
use talos::core::http::Method;
use talos_module_testkit::host;

fn repo(name: &str) -> Value {
    json!({"name": name, "full_name": format!("Example-Org/{name}"), "archived": false, "owner": {"login": "Example-Org"}})
}
fn env(name: &str, rules: Value, policy: Value, bypass: Value) -> Value {
    json!({"name": name, "protection_rules": rules, "deployment_branch_policy": policy, "can_admins_bypass": bypass})
}
/// Answers by path: the installation's repositories, each repository's environments, and branch patterns.
fn github(repos: Value, envs: fn(&str) -> (u16, Value)) {
    host::http::respond_with(move |req| {
        let path = req.url.trim_start_matches("https://api.github.com");
        Ok(if path.starts_with("/installation/repositories") {
            host::http::response(200, json!({"total_count": repos.as_array().unwrap().len(), "repositories": repos}).to_string())
        } else if path.contains("/deployment-branch-policies") {
            host::http::response(200, json!({"total_count": 2, "branch_policies": [{"name": "main", "type": "branch"}, {"name": "v*", "type": "tag"}]}).to_string())
        } else {
            let name = path.trim_start_matches("/repos/example-org/").split('/').next().unwrap().to_string();
            let (status, body) = envs(&name);
            host::http::response(status, body.to_string())
        })
    });
}
/// The envelope every test of this reader runs it with.
fn envelope() -> String {
    json!({"config": {"AUTH_HEADER": "Bearer x", "OWNER": "Example-Org"}}).to_string()
}
fn read() -> Result<Value, String> {
    run(envelope()).map(|o| serde_json::from_str(&o).unwrap())
}
fn two_envs(name: &str) -> (u16, Value) {
    if name == "infra" {
        (200, json!({"total_count": 2, "environments": [
            env("production", json!([{"type": "required_reviewers", "prevent_self_review": true, "reviewers": [{"type": "Team", "reviewer": {"id": 1}}, {"type": "User", "reviewer": {"id": 2}}]}, {"type": "wait_timer", "wait_timer": 5}, {"type": "branch_policy"}]),
                json!({"protected_branches": false, "custom_branch_policies": true}), json!(false)),
            env("preview/pr 1", json!([]), Value::Null, Value::Null),
        ]}))
    } else {
        (200, json!({"total_count": 0, "environments": []}))
    }
}

#[test]
fn it_reads_the_installations_repositories_and_what_protects_each_environment() {
    github(json!([repo("infra"), repo("docs"), {"name": "old", "archived": true, "owner": {"login": "example-org"}}, {"name": "elsewhere", "owner": {"login": "someone-else"}}]), two_envs);
    let out = read().unwrap();
    assert_eq!((out["kind"].as_str(), out["owner"].as_str(), out["unread"].clone()), (Some("github_env_evidence"), Some("example-org"), json!([])));
    assert_eq!(out["repositories"], json!([
        {"repo": "infra", "environments": [
            {"name": "production", "reviewers": 2, "prevent_self_review": true, "wait_minutes": 5, "custom_rules": 0, "branches": "selected", "patterns": ["main", "tag:v*"], "admins_bypass": false},
            // No policy means any branch; GitHub's default lets administrators bypass.
            {"name": "preview/pr 1", "reviewers": 0, "prevent_self_review": false, "wait_minutes": 0, "custom_rules": 0, "branches": "any", "patterns": [], "admins_bypass": true},
        ]},
        // A repository with no environments is a fact, and is written as one.
        {"repo": "docs", "environments": []},
    ]));
    assert_eq!(out["counted"], json!({"repositories": 2, "repositories_read": 2, "archived_skipped": 1, "other_owner": 1}));
    // Every request is a GET to api.github.com, under this owner, with GitHub's headers and no body.
    let seen = host::http::requests();
    assert_eq!(seen.len(), 4);
    assert!(seen.iter().all(|r| matches!(r.method, Method::Get) && r.url.starts_with("https://api.github.com/") && r.body.is_empty()));
    assert_eq!(seen[1].url, "https://api.github.com/repos/example-org/infra/environments?per_page=100");
    // An environment's name goes into a path encoded.
    assert_eq!(seen[2].url, "https://api.github.com/repos/example-org/infra/environments/production/deployment-branch-policies?per_page=100");
    for h in ["Authorization", "X-GitHub-Api-Version", "User-Agent"] {
        assert!(seen[0].headers.iter().any(|(k, _)| k == h), "{h}");
    }
    // This run is the template's recorded run (fixtures/): `make record-template TEMPLATE=github-env-evidence` rewrites it.
    talos_module_testkit::recorded_run::keep("github-env-evidence", &envelope());
}

#[test]
fn the_kinds_of_branch_policy_are_told_apart_and_a_name_is_encoded_in_a_path() {
    github(json!([repo("app")]), |_| (200, json!({"total_count": 3, "environments": [
        env("a/b c", json!([]), json!({"protected_branches": false, "custom_branch_policies": true}), json!(true)),
        env("prot", json!([{"type": "required_reviewers", "reviewers": [{"type": "User"}]}]), json!({"protected_branches": true, "custom_branch_policies": false}), json!(true)),
        env("neither", json!([{"type": "some_app_rule"}]), json!({"protected_branches": false, "custom_branch_policies": false}), json!(true)),
    ]})));
    let out = read().unwrap();
    let envs = out["repositories"][0]["environments"].as_array().unwrap();
    assert_eq!(envs.iter().map(|e| e["branches"].as_str().unwrap()).collect::<Vec<_>>(), ["selected", "protected", "any"]);
    assert_eq!((envs[1]["reviewers"].as_u64(), envs[1]["prevent_self_review"].as_bool(), envs[2]["custom_rules"].as_u64()), (Some(1), Some(false), Some(1)));
    assert!(host::http::requests().iter().any(|r| r.url.contains("/environments/a%2Fb%20c/deployment-branch-policies")));
}

#[test]
fn what_could_not_be_read_is_unread_and_never_an_empty_list() {
    // The repository listing fails: nothing is known, and no `repositories` is written.
    host::http::respond(403, "{}");
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["repositories", "environments"]));
    assert!(out.get("repositories").is_none());
    assert_eq!(out["errors"]["repositories"], "the repository listing answered HTTP 403");
    // One repository's environments fail: the part is unread, and that repository is not written as having none.
    github(json!([repo("infra"), repo("broken")]), |name| if name == "broken" { (404, json!({})) } else { two_envs(name) });
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["environments"]));
    assert_eq!(out["repositories"].as_array().unwrap().iter().map(|r| r["repo"].as_str().unwrap()).collect::<Vec<_>>(), ["infra"]);
    assert_eq!((out["counted"]["repositories"].as_u64(), out["counted"]["repositories_read"].as_u64()), (Some(2), Some(1)));
    // An answer that is not what GitHub sends is unread too.
    github(json!([repo("infra")]), |_| (200, json!({"total_count": 1, "environments": "x"})));
    assert_eq!(read().unwrap()["unread"], json!(["environments"]));
    // A listing that says there is more than it gave is not the listing.
    github(json!([repo("infra")]), |_| (200, json!({"total_count": 140, "environments": [{"name": "one"}]})));
    assert_eq!(read().unwrap()["unread"], json!(["environments"]));
}

#[test]
fn the_configuration_is_checked_before_any_request_and_too_many_repositories_is_refused() {
    for (config, err) in [
        (json!({"OWNER": "example-org"}), "Missing AUTH_HEADER config"),
        (json!({"AUTH_HEADER": "Bearer x"}), "OWNER must be a GitHub account name"),
        (json!({"AUTH_HEADER": "Bearer x", "OWNER": "a/b"}), "OWNER must be a GitHub account name"),
        (json!({"AUTH_HEADER": "Bearer x", "OWNER": ".."}), "OWNER must be a GitHub account name"),
    ] {
        assert_eq!(run(json!({"config": config}).to_string()).unwrap_err(), err);
    }
    assert!(host::http::requests().is_empty());
    let many: Vec<Value> = (0..31).map(|n| repo(&format!("r{n}"))).collect();
    github(Value::Array(many), |_| (200, json!({"total_count": 0, "environments": []})));
    assert!(read().unwrap_err().contains("more than 30 active repositories"));
    // A repository whose name could not go into a path is not skipped quietly.
    github(json!([repo("ok"), repo("bad/name")]), |_| (200, json!({"total_count": 0, "environments": []})));
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["repositories"].as_array().unwrap().len()), (json!(["environments"]), 1));
}

/// A value `n` bytes long as written: a string of `n - 2` characters between its quotes.
fn sized(n: usize) -> Value {
    json!("x".repeat(n - 2))
}

#[test]
fn the_evidence_fits_three_times_in_what_a_node_is_given() {
    // The platform refuses a node input above 1,000,000 bytes (WASM_MAX_INPUT_BYTES), and a workflow's first
    // node is given its trigger three times (top-level keys, `input`, `__trigger_input__`).
    assert_eq!(MAX_EVIDENCE_BYTES, 300_000);
    assert!(3 * MAX_EVIDENCE_BYTES + 100_000 <= 1_000_000);
}

#[test]
fn a_repository_is_counted_in_bytes_as_written_up_to_the_bound_and_one_byte_over_is_refused() {
    let room = MAX_EVIDENCE_BYTES - ENVELOPE_BYTES;
    let mut budget = Budget::new();
    assert_eq!(budget.take("it is", sized(room)), Ok(sized(room)));
    assert_eq!(budget.used, MAX_EVIDENCE_BYTES);
    assert_eq!(Budget::new().take("it is", sized(room + 1)).unwrap_err(), format!("it is too large to hand on ({} bytes as written; the evidence is at most 300000 bytes in all)", room + 1));
    // What does not fit is not counted: what is left stays for the repositories after it.
    let mut budget = Budget::new();
    assert!(budget.take("it is", sized(room - 10)).is_ok() && budget.take("it is", sized(11)).is_err());
    assert!(budget.take("it is", sized(10)).is_ok() && budget.used == MAX_EVIDENCE_BYTES);
    // Bytes, not characters, and escapes as they are written: the collector pins the same size for the same value.
    assert_eq!(json!({"a": "é\"\\😀", "b": [1, true, null]}).to_string().len(), 36);
    let wide = |n: usize| json!(format!("{}{}", "😀".repeat(1000), "x".repeat(n - 2 - 4000)));
    assert!(Budget::new().take("it is", wide(room)).is_ok() && Budget::new().take("it is", wide(room + 1)).is_err());
}

/// Thirty environments, each with the longest name that is handed on.
fn crowded(_: &str) -> (u16, Value) {
    (200, json!({"total_count": 30, "environments": (0..30).map(|i| env(&format!("{i:02}{}", "😀".repeat(98)), json!([]), Value::Null, Value::Null)).collect::<Vec<_>>()}))
}

#[test]
fn a_repository_too_large_to_hand_on_is_left_out_and_the_environments_are_unread() {
    // Each such repository is some 16,000 bytes: eighteen fit in what is handed on, and a nineteenth does not.
    github(json!((0..18).map(|i| repo(&format!("r{i:02}"))).collect::<Vec<_>>()), crowded);
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["repositories"].as_array().unwrap().len()), (json!([]), 18), "{}", out["errors"]);
    assert!(out.to_string().len() <= MAX_EVIDENCE_BYTES);
    github(json!((0..19).map(|i| repo(&format!("r{i:02}"))).collect::<Vec<_>>()), crowded);
    let out = read().unwrap();
    // The collector pins the same size for the same repository.
    assert_eq!((out["unread"].clone(), out["errors"]["environments"].as_str()), (json!(["environments"]), Some("a repository's environments are too large to hand on (16051 bytes as written; the evidence is at most 300000 bytes in all)")));
    assert_eq!((out["repositories"].as_array().unwrap().len(), out["counted"]["repositories_read"].clone()), (18, json!(18)));
    let judged: Value = serde_json::from_str(&crate::github_env_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert!(!judged["not_assessed"].as_array().unwrap().is_empty(), "{judged}");
}

#[test]
fn the_most_it_can_hand_on_fits_in_what_a_node_is_given_three_times() {
    // The largest evidence the counts allow: every environment's name at its longest, and ten of the longest patterns
    // on as many environments as are asked for theirs.
    let e = |n: usize| "😀".repeat(n);
    let mut asked = 0;
    let repos: Vec<Value> = (0..MAX_REPOS)
        .map(|_| {
            let envs: Vec<Value> = (0..MAX_ENVS)
                .map(|_| {
                    asked += 1;
                    let patterns = if asked <= MAX_PATTERN_READS { vec![format!("tag:{}", e(80)); MAX_PATTERNS] } else { vec![] };
                    json!({"name": e(100), "reviewers": u64::MAX, "prevent_self_review": false, "wait_minutes": u64::MAX, "custom_rules": u64::MAX, "branches": "protected", "patterns": patterns, "admins_bypass": false})
                })
                .collect();
            json!({"repo": "x".repeat(100), "environments": envs})
        })
        .collect();
    let unbounded = json!({"repositories": repos}).to_string().len();
    println!("worst-case github env evidence at the counts alone: {unbounded} bytes");
    assert!(unbounded > MAX_EVIDENCE_BYTES);
    // What the evidence holds besides its repositories, at its longest, is within what is set aside for it.
    let mut worst = json!({"kind": "github_env_evidence", "owner": "a".repeat(39), "unread": ["repositories", "environments"],
                           "errors": {"repositories": "x".repeat(200), "environments": "x".repeat(200)},
                           "counted": {"repositories": MAX_REPOS, "repositories_read": MAX_REPOS, "archived_skipped": 200, "other_owner": 200}, "repositories": []});
    let envelope = worst.to_string().len() + MAX_REPOS;
    println!("github env evidence besides its repositories, at most: {envelope} bytes");
    assert!(envelope <= ENVELOPE_BYTES, "{envelope}");
    worst["repositories"] = json!([sized(MAX_EVIDENCE_BYTES - ENVELOPE_BYTES)]);
    let bytes = worst.to_string().len();
    println!("worst-case github env evidence: {bytes} bytes");
    assert!(bytes <= MAX_EVIDENCE_BYTES, "{bytes}");
}
}
