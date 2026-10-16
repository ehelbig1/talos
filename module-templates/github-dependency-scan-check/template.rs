// github-dependency-scan-check: judges whether an organisation's
// repositories scan their dependencies in their GitHub Actions workflows,
// from evidence a reader collected, by fixed rules. It reads its input and
// calls nothing: no network, no model.
//
// A repository passes when one of its ACTIVE workflows has a step this check
// recognises as a dependency scanner: an action it knows (GitHub's dependency
// review action among them), or a command it knows (`cargo audit`,
// `npm audit`, `pip-audit`, `osv-scanner`, `trivy fs`, …). The list is this
// module's (`ACTIONS`, `scanner_command`); a scanner it does not know is not
// seen, and the repository is then reported, for the owner to accept.
//
// And a scan counts only when it runs as a change is made: its workflow runs
// on `pull_request`, `pull_request_target`, `push` or `merge_group`, or is a
// reusable workflow of the same repository that such a workflow calls. A
// repository whose only recognised scanners run otherwise (on a schedule, by
// hand, after another workflow, or by any event this check does not name) is
// a finding of its own (the owner's answer, 2026-10-14: a dependency is to be
// caught before or as it is merged).
//
// `merge_group` counts: GitHub's page says it "Runs your workflow when a pull
// request is added to a merge queue", on the merge group's commit, which
// holds the pull request's changes before they reach the branch, and that a
// repository whose required checks run in Actions must add it "as an
// additional trigger" or the checks are not run in the queue. A scan there
// catches a dependency before it is merged, which is what the owner asked.
//
// When a repository has no step it recognises but its workflows call work
// this reader did not read (a reusable workflow, an action kept in the
// repository itself, or an action from the same organisation's own
// repositories), the scan may be in there: the rule is then not assessed for
// any repository, with the reason in `undecided`, and what it found on the
// others is dropped with it, so half a result can never be accepted away.
// The same for the timing rule, when a workflow's triggers could not be read
// or a workflow that runs on a change calls work that was not read.
//
// The source was read on 2026-10-14. A heading's anchor is given only where
// the page showed it.
//
// Evidence (`kind: "github_workflows_evidence"`), whatever collected it:
//   { owner,
//     repositories: [{ repo, workflows: [{ path, state, triggers | triggers_unread, uses, commands }] }],
//     unread:       ["repositories" | "workflows"] }
//
//   state            active | deleted | disabled_fork | disabled_inactivity | disabled_manually
//   triggers         the event names of the workflow's top-level `on:` key
//   triggers_unread  why they could not be read, in place of `triggers`
//   uses             every `uses:` of the workflow, as written
//   commands         the first words of every command it `run:`s
//   An active workflow that is a file (`.github/workflows/…`) carries the last
//   four; one that does not run, or is GitHub's own (Dependabot's), none.
//
// Fail-closed, the same way as the GitHub environments check:
//   * no evidence is an error, not a clean result;
//   * a part of the evidence that was not read makes the rule "not
//     assessed", and what it found is dropped;
//   * "clean" means every rule was assessed and none matched.
//
// A finding decided to be acceptable is written into the node's config as
// "rule:severity:subject", exactly as reported, and is then listed as
// accepted instead of found.

use serde::Deserialize;
use std::collections::BTreeMap;
use talos_sdk_macros::talos_module;

const CHECK: &str = "github-dependency-scanning";
const TITLE: &str = "GitHub dependency scanning check";
const PARTS: [&str; 2] = ["repositories", "workflows"];
/// The keeper remembers at most two hundred. More than this is refused, never cut.
const MAX_FINDINGS: usize = 180;
const MAX_ROWS: usize = 60;
/// The states GitHub gives a workflow. Only an active one runs.
const STATES: [&str; 5] = ["active", "deleted", "disabled_fork", "disabled_inactivity", "disabled_manually"];
/// The events on which a workflow runs as a change is made: before it is merged, or as it is.
const ON_CHANGE: [&str; 4] = ["pull_request", "pull_request_target", "push", "merge_group"];
/// Where a workflow that is a file in the repository lives.
const WORKFLOW_DIR: &str = ".github/workflows/";
const NO_SCAN: &str = "repo-no-dependency-scan";
const ON_CHANGE_RULE: &str = "repo-scan-not-on-pull-request-or-push";

struct Doc {
    id: &'static str,
    publisher: &'static str,
    title: &'static str,
    url: &'static str,
}
const REVIEW: Doc = Doc { id: "github-dependency-review", publisher: "GitHub", title: "Dependency review", url: "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review" };
const EVENTS: Doc = Doc { id: "github-actions-events", publisher: "GitHub", title: "Events that trigger workflows", url: "https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows" };
const DOCS: [&Doc; 2] = [&REVIEW, &EVENTS];

/// A heading of a document. `anchor` is the fragment the page showed for it, or "".
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
const RULES: [Rule; 2] = [
    // "You can use the dependency review action in your repository to enforce dependency reviews on your pull requests";
    // "The action scans for vulnerable versions of dependencies introduced by package version changes in pull requests".
    Rule { id: "repo-no-dependency-scan", needs: &["repositories", "workflows"], task: "Add a dependency-scanning step to repositories' GitHub Actions build workflows",
           remedy: "Add a step that scans the dependencies of what is built to a workflow that runs on every pull request or push: GitHub's dependency review action, or the scanner of the repository's language (cargo audit, npm audit, pip-audit, osv-scanner, …).",
           sources: &[Cite { doc: &REVIEW, anchor: "about-the-dependency-review-action", heading: "About the dependency review action" }] },
    // The action "scans for vulnerable versions of dependencies introduced by package version changes in pull requests".
    // `pull_request` and `pull_request_target` run "when activity on a pull request in the workflow's repository occurs";
    // `push` "when you push a commit or tag"; `merge_group` "when a pull request is added to a merge queue".
    // "Scheduled workflows will only run on the default branch": a scheduled scan sees a dependency only once it is merged.
    Rule { id: "repo-scan-not-on-pull-request-or-push", needs: &["repositories", "workflows"], task: "Run dependency scans on pull requests or pushes",
           remedy: "Add pull_request (or push, and merge_group where a merge queue is used) to the triggers of the workflow that scans dependencies, or move the scanning step into the workflow that builds every pull request, so that a vulnerable dependency is caught before or as it is merged.",
           sources: &[
               Cite { doc: &REVIEW, anchor: "about-the-dependency-review-action", heading: "About the dependency review action" },
               Cite { doc: &EVENTS, anchor: "pull_request", heading: "pull_request" },
               Cite { doc: &EVENTS, anchor: "pull_request_target", heading: "pull_request_target" },
               Cite { doc: &EVENTS, anchor: "", heading: "push" },
               Cite { doc: &EVENTS, anchor: "", heading: "merge_group" },
               Cite { doc: &EVENTS, anchor: "", heading: "schedule" },
           ] },
];
const LIMITS: [(&str, &[&str]); 2] = [
    (
        "repo-no-dependency-scan",
        &[
            "a scanner run through a script, a make target or a tool this check does not know is not recognised; such a repository is reported, and can be accepted",
            "when the scanning step runs is not this rule's: a repository whose only scanners run on a schedule or by hand is found by repo-scan-not-on-pull-request-or-push",
            "whether a failing scan fails the build (continue-on-error, `|| true`, an action's own inputs) is not judged",
            "only each repository's default branch, of the repositories the GitHub App is installed on; steps written in YAML's flow style are not seen",
            "Dependabot alerts and GitHub's dependency graph, which scan outside the workflows, are not looked at",
        ],
    ),
    (
        "repo-scan-not-on-pull-request-or-push",
        &[
            "activity types and branch or path filters on those events are not judged: a scan that runs only on pull requests to one branch, or only when some files change, counts",
            "a workflow on pull_request_target runs in the context of the default branch, not of the pull request; whether its scan checks out the pull request's code is not judged",
            "a reusable workflow counts when a workflow of the same repository that runs on those events calls it; one called only from another repository is not linked to its callers, and its own repository is found",
            "only the events of a workflow's top-level on: key, as a single event, a list on one line or a mapping; a workflow written in another form leaves the rule undecided",
            "a workflow run after another one completes (workflow_run), or from outside (repository_dispatch), is not linked to what started it, and counts as not run on a pull request or push",
        ],
    ),
];
/// What the same page describes that this check does not judge, and why. The
/// id is this module's (the page did not show the anchor), so the address is the page's.
const NOT_JUDGED: [(&Doc, &str, &str, &str); 2] = [
    (&REVIEW, "enabling-dependency-review", "Enabling dependency review", "a repository setting outside its workflows (the dependency graph); the reader is not given its permission"),
    (&REVIEW, "dependency-submission", "Best practices for using the dependency review API and the dependency submission API together", "how dependency information reaches GitHub for review is not in this evidence"),
];

fn cite_json(c: &Cite) -> serde_json::Value {
    let url = if c.anchor.is_empty() { c.doc.url.to_string() } else { format!("{}#{}", c.doc.url, c.anchor) };
    serde_json::json!({ "document": c.doc.id, "publisher": c.doc.publisher, "title": c.doc.title, "heading": c.heading, "anchor": c.anchor, "url": url })
}
const PRODUCTS: [(&str, &str); 1] = [("scan-table", "A table of each repository's active GitHub Actions workflows, the dependency scanners they run, and which of those run on pull requests or pushes")];

fn catalogue() -> serde_json::Value {
    serde_json::json!({
        "documents": DOCS.iter().map(|d| serde_json::json!({ "id": d.id, "publisher": d.publisher, "title": d.title, "url": d.url, "every_heading_accounted_for": false })).collect::<Vec<_>>(),
        "products": PRODUCTS.iter().map(|(id, says)| serde_json::json!({ "id": id, "says": says })).collect::<Vec<_>>(),
        "rules": RULES.iter().map(|r| serde_json::json!({
            "rule": r.id,
            "basis": if r.sources.is_empty() { "local judgement" } else { "published guidance" },
            "task": r.task,
            "remedy": r.remedy,
            "limits": LIMITS.iter().find(|(rule, _)| *rule == r.id).map(|(_, limits)| limits.to_vec()).unwrap_or_default(),
            "sources": r.sources.iter().map(cite_json).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "not_judged": NOT_JUDGED.iter().map(|(doc, id, heading, why)| serde_json::json!({ "document": doc.id, "publisher": doc.publisher, "title": doc.title, "heading": heading, "anchor": id, "url": doc.url, "why": why })).collect::<Vec<_>>(),
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
    workflows: Vec<WorkflowIn>,
    /// What the check works out about the repository, once, before any rule reads it.
    #[serde(skip)]
    seen: Seen,
}
/// Worked out once per repository: every rule, table cell and count reads these.
#[derive(Default)]
struct Seen {
    scanners: Vec<&'static str>,
    on_change: Vec<bool>,
    scanners_on_change: Vec<&'static str>,
    unread_calls: Vec<String>,
}
#[derive(Deserialize)]
struct WorkflowIn {
    #[serde(default)]
    path: String,
    #[serde(default)]
    state: String,
    /// Absent is not "none": a workflow that does not say what triggers it is undecided.
    triggers: Option<Vec<String>>,
    triggers_unread: Option<String>,
    /// Absent is not "none": an active workflow file whose steps were not handed on is undecided.
    uses: Option<Vec<String>>,
    commands: Option<Vec<String>>,
    /// The scanners this workflow runs, worked out once.
    #[serde(skip)]
    found: Vec<&'static str>,
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
/// A reason from evidence, as it may be shown: no control characters, cut to a length.
fn shown(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}
fn owner_ok(s: &str) -> bool {
    (1..=40).contains(&s.len()) && s.as_bytes()[0].is_ascii_alphanumeric() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Actions that scan dependencies, by repository (the part of `uses` before `@`), and what to call them.
const ACTIONS: [(&str, &str); 11] = [
    ("actions/dependency-review-action", "dependency review"),
    ("aquasecurity/trivy-action", "trivy"),
    ("anchore/scan-action", "grype"),
    ("google/osv-scanner-action", "osv-scanner"),
    ("snyk/actions", "snyk"),
    ("rustsec/audit-check", "cargo audit"),
    ("actions-rs/audit-check", "cargo audit"),
    ("embarkstudios/cargo-deny-action", "cargo deny"),
    ("pypa/gh-action-pip-audit", "pip-audit"),
    ("golang/govulncheck-action", "govulncheck"),
    ("dependency-check/dependency-check_action", "dependency-check"),
];
/// The scanner an action is, if this check knows it: the action itself or anything under it.
fn scanner_action(uses: &str) -> Option<&'static str> {
    let repo = uses.trim().split('@').next().unwrap_or("");
    ACTIONS.iter().find(|(a, _)| starts_with_ignoring_case(repo, a) && matches!(repo.as_bytes().get(a.len()), None | Some(b'/'))).map(|(_, n)| *n)
}
/// Whether `s` starts with `prefix`, ASCII capitals aside (GitHub's owner and repository names are ASCII,
/// matched without regard to case). Nothing is copied: this runs on every step of every workflow.
fn starts_with_ignoring_case(s: &str, prefix: &str) -> bool {
    s.as_bytes().get(..prefix.len()).is_some_and(|p| p.eq_ignore_ascii_case(prefix.as_bytes()))
}
fn contains_ignoring_case(s: &str, part: &str) -> bool {
    s.as_bytes().windows(part.len()).any(|w| w.eq_ignore_ascii_case(part.as_bytes()))
}
/// Every program `scanner_command` recognises, so a command that names none of them is passed over before it is copied.
const PROGRAMS: [&str; 26] = [
    "cargo", "npm", "pnpm", "yarn", "pip-audit", "pip_audit", "safety", "osv-scanner", "trivy", "grype", "snyk", "govulncheck", "bundle",
    "bundler-audit", "composer", "dotnet", "dependency-check", "dependency-check.sh", "mvn", "mvnw", "./mvnw", "gradle", "gradlew", "./gradlew", "gcloud", "mix",
];
/// The scanner a command is, if this check knows it, from its first words.
/// What runs a program and is not the program.
const RUNNERS: [&str; 5] = ["sudo", "npx", "uvx", "bunx", "exec"];
/// Whether a command may run one of the programs, read without copying it: the words before the program
/// are all settings or runners, so it is enough to look up to the first word that is neither. Never false
/// where `scanner_command` would recognise the command, which is what lets it pass over the rest.
fn may_run_a_program(command: &str) -> bool {
    for word in command.split_whitespace() {
        if PROGRAMS.iter().any(|p| word.eq_ignore_ascii_case(p)) {
            return true;
        }
        let runs_another = (word.contains('=') && !word.starts_with('-'))
            || RUNNERS.iter().any(|r| word.eq_ignore_ascii_case(r))
            || ["pipx", "run", "-m"].iter().any(|r| word.eq_ignore_ascii_case(r))
            || starts_with_ignoring_case(word, "python");
        if !runs_another {
            return false;
        }
    }
    false
}
fn scanner_command(command: &str) -> Option<&'static str> {
    if !may_run_a_program(command) {
        return None;
    }
    let lower = command.to_ascii_lowercase();
    let mut w: Vec<&str> = lower.split_whitespace().collect();
    // What runs the program is not the program: environment settings, sudo, a package runner.
    while let Some(first) = w.first() {
        if (first.contains('=') && !first.starts_with('-')) || RUNNERS.contains(first) {
            w.remove(0);
        } else if *first == "pipx" && w.get(1) == Some(&"run") || first.starts_with("python") && w.get(1) == Some(&"-m") {
            w.drain(..2);
        } else {
            break;
        }
    }
    let at = |i: usize| w.get(i).copied().unwrap_or("");
    match at(0) {
        "cargo" if at(1) == "audit" => Some("cargo audit"),
        // `cargo deny check` checks advisories unless it is told to check only others.
        "cargo" if at(1) == "deny" => {
            let after: Vec<&str> = w.iter().skip_while(|x| **x != "check").skip(1).filter(|x| !x.starts_with('-')).copied().collect();
            (w.contains(&"check") && (after.is_empty() || after.iter().any(|x| *x == "advisories" || *x == "all"))).then_some("cargo deny")
        }
        "npm" | "pnpm" if at(1) == "audit" => Some("npm audit"),
        "yarn" if at(1) == "audit" || (at(1) == "npm" && at(2) == "audit") => Some("yarn audit"),
        "pip-audit" | "pip_audit" => Some("pip-audit"),
        "safety" if at(1) == "check" || at(1) == "scan" => Some("safety"),
        "osv-scanner" => Some("osv-scanner"),
        "trivy" if ["fs", "filesystem", "image", "repo", "repository", "rootfs", "sbom"].contains(&at(1)) => Some("trivy"),
        "grype" => Some("grype"),
        "snyk" if at(1) == "test" => Some("snyk"),
        "govulncheck" => Some("govulncheck"),
        "bundle" if at(1) == "audit" => Some("bundler-audit"),
        "bundler-audit" => Some("bundler-audit"),
        "composer" if at(1) == "audit" => Some("composer audit"),
        "dotnet" if w.contains(&"package") && w.contains(&"--vulnerable") => Some("dotnet list package --vulnerable"),
        "dependency-check" | "dependency-check.sh" => Some("dependency-check"),
        "mvn" | "mvnw" | "./mvnw" | "gradle" | "gradlew" | "./gradlew" if w.iter().any(|x| x.contains("dependency-check") || x.contains("dependencycheck")) => Some("dependency-check"),
        "gcloud" if w.get(1..5) == Some(&["artifacts", "docker", "images", "scan"][..]) => Some("on-demand scanning"),
        "mix" if at(1) == "deps.audit" || at(1) == "hex.audit" => Some("mix audit"),
        _ => None,
    }
}
fn once(mut found: Vec<&'static str>) -> Vec<&'static str> {
    let mut seen: Vec<&str> = Vec::new();
    found.retain(|n| if seen.contains(n) { false } else { seen.push(n); true });
    found
}
/// The scanners a workflow runs, if it runs.
fn find_scanners(w: &WorkflowIn) -> Vec<&'static str> {
    if w.state != "active" {
        return Vec::new();
    }
    w.uses.iter().flatten().filter_map(|u| scanner_action(u)).chain(w.commands.iter().flatten().filter_map(|c| scanner_command(c))).collect()
}
fn scanners_of(w: &WorkflowIn) -> &[&'static str] {
    &w.found
}
/// The scanners a repository's active workflows run, each named once.
fn find_repo_scanners(r: &Repo) -> Vec<&'static str> {
    once(r.workflows.iter().flat_map(|w| scanners_of(w).iter().copied()).collect())
}
fn scanners(r: &Repo) -> &[&'static str] {
    &r.seen.scanners
}
/// The workflow file a `uses:` calls in the same repository, if it calls one.
fn local_workflow(uses: &str) -> Option<&str> {
    uses.trim().strip_prefix("./").map(|p| p.split('@').next().unwrap_or(p))
}
/// For each workflow, whether it runs as a change is made: on one of those events,
/// or called by a workflow of the same repository that does (a reusable workflow, at any depth).
/// Each workflow's calls are followed once, so the cost grows with the calls, not their square.
fn find_on_change(r: &Repo) -> Vec<bool> {
    let mut on: Vec<bool> = r.workflows.iter().map(|w| w.triggers.iter().flatten().any(|e| ON_CHANGE.contains(&e.as_str()))).collect();
    let mut by_path: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, w) in r.workflows.iter().enumerate() {
        by_path.entry(w.path.as_str()).or_default().push(i);
    }
    let mut todo: Vec<usize> = (0..on.len()).filter(|&i| on[i]).collect();
    while let Some(caller) = todo.pop() {
        for &called in r.workflows[caller].uses.iter().flatten().filter_map(|u| local_workflow(u)).filter_map(|p| by_path.get(p)).flatten() {
            if !on[called] {
                on[called] = true;
                todo.push(called);
            }
        }
    }
    on
}
fn on_change(r: &Repo) -> &[bool] {
    &r.seen.on_change
}
/// The scanners a repository runs as a change is made, each named once.
fn find_scanners_on_change(r: &Repo, on: &[bool]) -> Vec<&'static str> {
    once(r.workflows.iter().zip(on.iter().copied()).filter(|(_, runs)| *runs).flat_map(|(w, _)| scanners_of(w)).copied().collect())
}
fn scanners_on_change(r: &Repo) -> &[&'static str] {
    &r.seen.scanners_on_change
}
/// What a workflow calls that was not read, and so may hold a scan:
/// a reusable workflow, an action kept in the repository, an action of the same owner.
fn unread_calls_of(w: &WorkflowIn, owner: &str) -> Vec<String> {
    w.uses
        .iter()
        .flatten()
        .map(|u| u.trim())
        .filter(|u| scanner_action(u).is_none())
        .filter(|u| {
            let local = u.starts_with("./") && !starts_with_ignoring_case(u, "./.github/workflows/");
            let reusable = !u.starts_with("./") && contains_ignoring_case(u, "/.github/workflows/");
            let ours = u.split('/').next().is_some_and(|first| first.eq_ignore_ascii_case(owner)) && !u.starts_with("./");
            local || reusable || ours
        })
        .map(name)
        .collect()
}
fn find_unread_calls(r: &Repo, owner: &str) -> Vec<String> {
    r.workflows.iter().filter(|w| w.state == "active").flat_map(|w| unread_calls_of(w, owner)).collect()
}
fn unread_calls(r: &Repo) -> &[String] {
    &r.seen.unread_calls
}
/// Works out, once, what every rule reads about each repository.
fn prepare(repos: &mut [Repo], owner: &str) {
    for r in repos.iter_mut() {
        for w in r.workflows.iter_mut() {
            w.found = find_scanners(w);
        }
        let on = find_on_change(r);
        r.seen = Seen { scanners: find_repo_scanners(r), scanners_on_change: find_scanners_on_change(r, &on), on_change: on, unread_calls: find_unread_calls(r, owner) };
    }
}
fn active(r: &Repo) -> usize {
    r.workflows.iter().filter(|w| w.state == "active").count()
}
/// A workflow the reader should have read and did not hand the steps of, or one in a state this check does not know.
fn unseen(r: &Repo) -> Option<String> {
    if let Some(w) = r.workflows.iter().find(|w| !STATES.contains(&w.state.as_str())) {
        return Some(format!("workflow {} has a state this check does not know ({:?})", name(&w.path), name(&w.state)));
    }
    r.workflows
        .iter()
        .find(|w| w.state == "active" && w.path.starts_with(WORKFLOW_DIR) && (w.uses.is_none() || w.commands.is_none()))
        .map(|w| format!("the steps of workflow {} were not handed on", name(&w.path)))
}

/// The rules, when every repository says what they need; otherwise why each cannot be decided.
fn undecided(repos: &[Repo], owner: &str) -> Vec<(&'static str, String)> {
    let mut open: Vec<(&'static str, String)> = Vec::new();
    // No scanner it recognises: the scan may be in work it did not see.
    let unclear: Vec<(&Repo, String)> = repos
        .iter()
        .filter(|r| scanners(r).is_empty())
        .filter_map(|r| {
            let calls = unread_calls(r);
            if let Some(first) = calls.first() {
                return Some((r, format!("its workflows call {} thing(s) this reader did not read, such as {first}", calls.len())));
            }
            unseen(r).map(|why| (r, why))
        })
        .collect();
    if let Some((r, why)) = unclear.first() {
        open.push(("repo-no-dependency-scan", format!("{} of {} repositories with no scanner it recognises may scan in work it did not see ({}: {why})", unclear.len(), repos.len(), name(&r.repo))));
    }
    // Scanners, none on a change: one may run on a change in a way it could not see.
    let late: Vec<(&Repo, String)> = repos
        .iter()
        .filter(|r| !scanners(r).is_empty() && scanners_on_change(r).is_empty())
        .filter_map(|r| {
            let on = on_change(r);
            if let Some(w) = r.workflows.iter().zip(on).find(|(w, runs)| !**runs && w.state == "active" && w.path.starts_with(WORKFLOW_DIR) && w.triggers.is_none()).map(|(w, _)| w) {
                let why = w.triggers_unread.as_deref().map(|t| shown(t, 120)).unwrap_or_else(|| "the evidence does not say".to_string());
                return Some((r, format!("the triggers of workflow {} could not be read: {why}", name(&w.path))));
            }
            let calls: Vec<String> = r.workflows.iter().zip(on).filter(|(_, runs)| **runs).flat_map(|(w, _)| unread_calls_of(w, owner)).collect();
            if let Some(first) = calls.first() {
                return Some((r, format!("its workflows that run on a change call {} thing(s) this reader did not read, such as {first}", calls.len())));
            }
            unseen(r).map(|seen| (r, seen))
        })
        .collect();
    if let Some((r, why)) = late.first() {
        open.push(("repo-scan-not-on-pull-request-or-push", format!("{} of {} repositories whose recognised scanners run on no pull request or push may run one there in a way it could not see ({}: {why})", late.len(), repos.len(), name(&r.repo))));
    }
    open
}

fn check(repos: &[Repo]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for r in repos.iter().filter(|r| scanners(r).is_empty()) {
        let says = if active(r) == 0 {
            "has no active GitHub Actions workflow, so nothing in its builds scans its dependencies".to_string()
        } else {
            format!("runs no step this check recognises as a dependency scanner in its {} active workflow(s)", active(r))
        };
        findings.push(Finding { rule: "repo-no-dependency-scan", severity: "medium", subject: name(&r.repo), says });
    }
    for r in repos.iter().filter(|r| !scanners(r).is_empty() && scanners_on_change(r).is_empty()) {
        let mut events: Vec<String> = Vec::new();
        for e in r.workflows.iter().filter(|w| !scanners_of(w).is_empty()).flat_map(|w| w.triggers.iter().flatten()).map(|e| name(e)) {
            if !events.contains(&e) {
                events.push(e);
            }
        }
        let when = if events.is_empty() { "no event".to_string() } else { events.join(", ") };
        findings.push(Finding {
            rule: "repo-scan-not-on-pull-request-or-push",
            severity: "medium",
            subject: name(&r.repo),
            says: format!("runs its recognised dependency scanners ({}) only in workflows triggered by {when}: none runs on a pull request, a merge queue or a push", scanners(r).join(", ")),
        });
    }
    findings
}

/// One row per repository. `None` when it would be cut: half a table reads as the whole of it.
fn table(repos: &[Repo]) -> Option<Vec<Vec<String>>> {
    let rows: Vec<Vec<String>> = repos
        .iter()
        .map(|r| {
            let found = scanners(r);
            let on = scanners_on_change(r);
            vec![
                name(&r.repo),
                format!("{} of {}", active(r), r.workflows.len()),
                if found.is_empty() { "none recognised".to_string() } else { found.iter().take(4).copied().collect::<Vec<_>>().join(", ") },
                if on.is_empty() { "none".to_string() } else { on.iter().take(4).copied().collect::<Vec<_>>().join(", ") },
                unread_calls(r).len().to_string(),
            ]
        })
        .collect();
    (rows.len() <= MAX_ROWS).then_some(rows)
}

#[talos_module(world = "minimal-node")]
pub fn run(input: String) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    if envelope.config.catalogue_only.unwrap_or(false) {
        return serde_json::to_string(&serde_json::json!({ "kind": "security_catalogue", "check": CHECK, "title": TITLE, "catalogue": catalogue() })).map_err(|e| e.to_string());
    }
    // No evidence is a failure, never a clean result.
    let arrived = envelope.input.filter(|e| e.kind == "github_workflows_evidence").ok_or("the evidence did not arrive")?;
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
    let mut repos = arrived.repositories.unwrap_or_default();
    prepare(&mut repos, &arrived.owner);
    let accepted_list = match envelope.config.accepted {
        None => Vec::new(),
        Some(list) if list.len() <= 20 && list.iter().all(|a| a.len() <= 300) => list,
        Some(_) => return Err("ACCEPTED holds at most twenty findings".to_string()),
    };
    let read = unread.is_empty();
    let mut undecided = if read { undecided(&repos, &arrived.owner) } else { Vec::new() };
    // With no recognised scanner in any repository, the timing rule has no scan to judge: it is not applicable,
    // or, when whether a scanner runs is itself undecided, undecided with it. Never passed for want of a scan.
    let mut moot: Vec<(&'static str, String)> = Vec::new();
    if read && repos.iter().all(|r| scanners(r).is_empty()) {
        match undecided.iter().find(|(rule, _)| *rule == NO_SCAN).map(|(_, why)| why.clone()) {
            Some(why) => undecided.push((ON_CHANGE_RULE, format!("whether any repository runs a scanner is not decided: {why}"))),
            None => moot.push((ON_CHANGE_RULE, format!("no repository runs a dependency scanner this check recognises, so there is no scan whose timing to judge ({NO_SCAN} is the finding)"))),
        }
    }
    let is_moot = |rule: &str| moot.iter().any(|(r, _)| *r == rule);
    let not_assessed: Vec<&str> = RULES.iter().filter(|r| !is_moot(r.id) && (r.needs.iter().any(|n| unread.iter().any(|u| u == n)) || undecided.iter().any(|(rule, _)| *rule == r.id))).map(|r| r.id).collect();
    let all: Vec<Finding> = check(&repos).into_iter().filter(|f| !not_assessed.contains(&f.rule) && !is_moot(f.rule)).collect();
    if all.len() > MAX_FINDINGS {
        return Err(format!("the check found more than {MAX_FINDINGS} things; reporting some of them would hide the rest"));
    }
    let passed: Vec<&str> = RULES.iter().map(|r| r.id).filter(|id| !not_assessed.contains(id) && !is_moot(id) && !all.iter().any(|f| f.rule == *id)).collect();
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
    serde_json::to_string(&serde_json::json!({
        "kind": "security_check", "check": CHECK, "title": TITLE, "project": arrived.owner,
        // Clean only when every rule could be assessed and none matched.
        "clean": findings.is_empty() && not_assessed.is_empty(),
        "worst": worst,
        "findings": with_sources(&findings), "accepted": with_sources(&accepted), "passed": passed, "not_assessed": not_assessed,
        "undecided": undecided.iter().map(|(rule, why)| serde_json::json!({ "rule": rule, "why": why })).collect::<Vec<_>>(),
        // A rule with nothing to judge, with the reason: neither passed nor "not assessed".
        "not_applicable": moot.iter().map(|(rule, why)| serde_json::json!({ "rule": rule, "why": why })).collect::<Vec<_>>(),
        "not_judged": NOT_JUDGED.len(),
        // Drawn only when everything was read; otherwise its rows are absent, never partial.
        "table": {
            "title": "Dependency scanning in workflows",
            "columns": ["Repository", "Active workflows", "Scanners", "On pull request or push", "Calls not read"],
            "rows": if read { serde_json::json!(table(&repos)) } else { serde_json::Value::Null },
        },
        "counted": { "repositories": repos.len(), "scanning": repos.iter().filter(|r| !scanners(r).is_empty()).count(), "scanning_on_change": repos.iter().filter(|r| !scanners_on_change(r).is_empty()).count() },
        "unread": unread,
    }))
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
use super::*;
use serde_json::{json, Value};

const OWNER: &str = "example-org";

fn check_of(evidence: Value) -> Value {
    serde_json::from_str(&run(json!({"input": evidence}).to_string()).unwrap()).unwrap()
}
fn found(out: &Value) -> Vec<(String, String)> {
    out["findings"].as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["subject"].as_str().unwrap().to_string())).collect()
}
fn names(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect()
}
/// One active workflow that runs on pull requests.
fn wf(path: &str, triggers: Value, uses: Value, commands: Value) -> Value {
    json!({"path": format!(".github/workflows/{path}"), "state": "active", "triggers": triggers, "uses": uses, "commands": commands})
}
fn repo(name: &str, uses: Value, commands: Value) -> Value {
    json!({"repo": name, "workflows": [wf("ci.yml", json!(["pull_request"]), uses, commands)]})
}
fn repo_of(name: &str, workflows: Value) -> Value {
    json!({"repo": name, "workflows": workflows})
}
fn evidence(repos: Value) -> Value {
    json!({"kind": "github_workflows_evidence", "owner": OWNER, "repositories": repos, "unread": []})
}
fn scanning(name: &str) -> Value {
    repo(name, json!(["actions/checkout@v4", "actions/dependency-review-action@v4"]), json!(["cargo build --release"]))
}

#[test]
fn the_catalogue_cites_the_dependency_review_action_and_needs_no_evidence() {
    let out: Value = serde_json::from_str(&run(json!({"config": {"CATALOGUE_ONLY": true}}).to_string()).unwrap()).unwrap();
    assert_eq!((out["kind"].as_str(), out["check"].as_str()), (Some("security_catalogue"), Some("github-dependency-scanning")));
    let cat = &out["catalogue"];
    assert_eq!((cat["rules"].as_array().unwrap().len(), cat["documents"].as_array().unwrap().len()), (RULES.len(), DOCS.len()));
    let rule = &cat["rules"][0];
    assert_eq!((rule["rule"].as_str(), rule["basis"].as_str()), (Some("repo-no-dependency-scan"), Some("published guidance")));
    assert_eq!(rule["sources"][0]["heading"], "About the dependency review action");
    assert_eq!(rule["sources"][0]["url"], "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review#about-the-dependency-review-action");
    assert_eq!(rule["limits"].as_array().unwrap().len(), 5);
    assert!(rule["task"].as_str().is_some_and(|t| !t.is_empty()) && rule["remedy"].as_str().is_some_and(|t| !t.is_empty()));
    assert_eq!(cat["products"][0]["id"], "scan-table");
    let nj = cat["not_judged"].as_array().unwrap();
    assert_eq!(nj.len(), 2);
    assert!(nj.iter().all(|n| !n["anchor"].as_str().unwrap().is_empty() && n["anchor"].as_str().unwrap().len() <= 64 && !n["url"].as_str().unwrap().contains('#')));
    let cited: Vec<&str> = RULES.iter().flat_map(|r| r.sources.iter().map(|c| c.heading)).collect();
    assert!(NOT_JUDGED.iter().all(|(_, _, heading, _)| !cited.contains(heading)));

    // The timing rule rests on the events page, by the headings it read; a fragment only where the page showed one.
    let timing = &cat["rules"][1];
    assert_eq!((timing["rule"].as_str(), timing["basis"].as_str()), (Some("repo-scan-not-on-pull-request-or-push"), Some("published guidance")));
    let headings: Vec<&str> = timing["sources"].as_array().unwrap().iter().map(|c| c["heading"].as_str().unwrap()).collect();
    assert_eq!(headings, ["About the dependency review action", "pull_request", "pull_request_target", "push", "merge_group", "schedule"]);
    assert_eq!(timing["sources"][1]["url"], "https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request");
    assert_eq!(timing["sources"][3]["url"], "https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows");
    assert_eq!(timing["limits"].as_array().unwrap().len(), 5);
}

#[test]
fn a_repository_whose_workflows_scan_dependencies_is_clean() {
    let out = check_of(evidence(json!([scanning("api"), repo("web", json!(["actions/checkout@v4"]), json!(["npm ci", "npm audit --audit-level=high", "pnpm audit"]))])));
    assert_eq!(out["clean"], true, "{out}");
    assert_eq!((names(&out["passed"]), out["not_assessed"].clone(), out["undecided"].clone()), (vec!["repo-no-dependency-scan", "repo-scan-not-on-pull-request-or-push"], json!([]), json!([])));
    assert_eq!(out["table"]["rows"], json!([["api", "1 of 1", "dependency review", "dependency review", "0"], ["web", "1 of 1", "npm audit", "npm audit", "0"]]));
    assert_eq!(out["counted"], json!({"repositories": 2, "scanning": 2, "scanning_on_change": 2}));
}

#[test]
fn a_repository_with_no_scanner_or_no_active_workflow_is_found() {
    let plain = repo("api", json!(["actions/checkout@v4", "actions/setup-node@v4"]), json!(["npm ci", "npm test"]));
    // A workflow that does not run scans nothing, whatever its file says.
    let mut idle = scanning("old");
    idle["workflows"][0]["state"] = json!("disabled_manually");
    let none = json!({"repo": "docs", "workflows": []});
    let out = check_of(evidence(json!([plain, idle, none, scanning("web")])));
    assert_eq!(found(&out), [("repo-no-dependency-scan".to_string(), "api".to_string()), ("repo-no-dependency-scan".to_string(), "old".to_string()), ("repo-no-dependency-scan".to_string(), "docs".to_string())], "{out}");
    let says: Vec<&str> = out["findings"].as_array().unwrap().iter().map(|f| f["says"].as_str().unwrap()).collect();
    assert!(says[0].contains("in its 1 active workflow(s)") && says[1].starts_with("has no active GitHub Actions workflow") && says[2].starts_with("has no active"), "{says:?}");
    assert_eq!((out["worst"].as_str(), out["findings"][0]["severity"].as_str(), out["findings"][0]["basis"].as_str()), (Some("medium"), Some("medium"), Some("published guidance")));
    assert_eq!(out["table"]["rows"][1], json!(["old", "0 of 1", "none recognised", "none", "0"]));
}

#[test]
fn the_scanners_it_knows_are_recognised_by_action_and_by_command() {
    for uses in ["actions/dependency-review-action@v4", "aquasecurity/trivy-action@0.28.0", "anchore/scan-action@v6", "google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@v2",
                 "snyk/actions/node@master", "rustsec/audit-check@v2", "actions-rs/audit-check@v1", "EmbarkStudios/cargo-deny-action@v2", "pypa/gh-action-pip-audit@v1", "golang/govulncheck-action@v1",
                 "dependency-check/Dependency-Check_Action@main"] {
        assert!(scanner_action(uses).is_some(), "{uses}");
    }
    for uses in ["actions/checkout@v4", "snyk/actionsx@v1", "actions/dependency-review-actions@v1", "github/codeql-action/analyze@v3", "./.github/actions/scan"] {
        assert!(scanner_action(uses).is_none(), "{uses}");
    }
    for command in ["cargo audit", "cargo deny check", "cargo deny --all-features check advisories", "cargo deny check all", "npm audit --omit=dev", "pnpm audit", "yarn audit", "yarn npm audit",
                    "pip-audit -r requirements.txt", "python -m pip_audit", "pipx run pip-audit", "safety check", "safety scan", "osv-scanner --lockfile=Cargo.lock", "npx osv-scanner .",
                    "trivy fs .", "trivy image example/app:1", "grype dir:.", "snyk test", "govulncheck ./...", "bundle audit check", "bundler-audit", "composer audit",
                    "dotnet list package --vulnerable", "dependency-check.sh --scan .", "./mvnw org.owasp:dependency-check-maven:check", "./gradlew dependencyCheckAnalyze",
                    "gcloud artifacts docker images scan example/app", "mix deps.audit", "CI=1 sudo cargo audit", "uvx pip-audit"] {
        assert!(scanner_command(command).is_some(), "{command}");
    }
    for command in ["cargo deny check bans licenses", "cargo build", "cargo deny init", "npm ci", "npm auditor", "trivy config .", "snyk monitor", "safety", "make audit", "./scripts/scan.sh",
                    "dotnet list package", "mvn package", "gcloud artifacts docker images list", "echo cargo audit"] {
        assert!(scanner_command(command).is_none(), "{command}");
    }
}

#[test]
fn with_no_scanner_anywhere_the_timing_rule_is_not_applicable_never_passed() {
    let plain = |name: &str| repo(name, json!(["actions/checkout@v4"]), json!(["make test"]));
    let out = check_of(evidence(json!([plain("api"), plain("web")])));
    assert_eq!(found(&out).iter().map(|(rule, _)| rule.as_str()).collect::<Vec<_>>(), ["repo-no-dependency-scan", "repo-no-dependency-scan"], "{out}");
    assert!(!names(&out["passed"]).contains(&"repo-scan-not-on-pull-request-or-push") && names(&out["not_assessed"]).is_empty(), "{out}");
    assert_eq!(out["not_applicable"], json!([{"rule": "repo-scan-not-on-pull-request-or-push", "why": "no repository runs a dependency scanner this check recognises, so there is no scan whose timing to judge (repo-no-dependency-scan is the finding)"}]));
    // One repository that scans is enough for the rule to apply, and pass or find.
    let scanning = repo("lib", json!(["actions/checkout@v4"]), json!(["cargo audit"]));
    let out = check_of(evidence(json!([plain("api"), scanning])));
    assert!(names(&out["passed"]).contains(&"repo-scan-not-on-pull-request-or-push") && out["not_applicable"] == json!([]), "{out}");
    // Evidence that was not all read: nothing is set aside, it is not assessed.
    let mut e = evidence(json!([plain("api")]));
    e["unread"] = json!(["repositories"]);
    let out = check_of(e);
    assert!(out["not_applicable"] == json!([]) && names(&out["not_assessed"]).contains(&"repo-scan-not-on-pull-request-or-push"), "{out}");
}

#[test]
fn work_the_reader_did_not_see_leaves_the_rule_undecided_and_drops_the_rest() {
    let plain = repo("api", json!(["actions/checkout@v4"]), json!(["make test"]));
    for call in ["example-org/shared/.github/workflows/build.yml@main", "./.github/actions/setup", "Example-Org/ci-actions/rust@v1", "other-org/pipelines/.github/workflows/ci.yml@v2"] {
        let hidden = repo("web", json!(["actions/checkout@v4", call]), json!([]));
        let out = check_of(evidence(json!([plain.clone(), hidden])));
        // No repository runs a scanner it recognises, and whether one does is undecided: so is the timing rule, never passed.
        assert_eq!(names(&out["not_assessed"]), ["repo-no-dependency-scan", "repo-scan-not-on-pull-request-or-push"], "{call}: {out}");
        assert!(out["undecided"][1]["why"].as_str().unwrap().starts_with("whether any repository runs a scanner is not decided: 1 of 2"), "{out}");
        assert_eq!(found(&out), [], "half a result is never reported: {out}");
        let why = out["undecided"][0]["why"].as_str().unwrap();
        assert!(why.starts_with("1 of 2 repositories with no scanner it recognises may scan in work it did not see (web:") && why.contains("1 thing(s)"), "{why}");
        assert_eq!(out["clean"], false);
        assert_eq!(out["table"]["rows"][1][4], "1");
    }
    // A local reusable workflow is in the listing already; a docker step and another organisation's action are not work of the repository's own.
    let fine = repo("web", json!(["./.github/workflows/reusable.yml", "docker://alpine:3", "actions/setup-go@v5"]), json!([]));
    assert_eq!(found(&check_of(evidence(json!([fine])))), [("repo-no-dependency-scan".to_string(), "web".to_string())]);
    // A repository that does scan is decided, whatever else it calls.
    let both = repo("web", json!(["example-org/shared/.github/workflows/build.yml@main", "rustsec/audit-check@v2"]), json!([]));
    assert_eq!(check_of(evidence(json!([both])))["clean"], true);
    // A workflow in a state this check does not know may be running.
    let mut odd = repo("web", json!([]), json!([]));
    odd["workflows"] = json!([{"path": ".github/workflows/ci.yml", "state": "sleeping"}]);
    let out = check_of(evidence(json!([odd])));
    assert_eq!(names(&out["not_assessed"]), ["repo-no-dependency-scan", "repo-scan-not-on-pull-request-or-push"]);
    assert!(out["undecided"][0]["why"].as_str().unwrap().contains("state this check does not know"));
    // An active workflow file whose steps did not arrive may hold a scan; GitHub's own workflows have no file to read.
    for missing in ["uses", "commands"] {
        let mut bare = repo("web", json!([]), json!([]));
        bare["workflows"][0].as_object_mut().unwrap().remove(missing);
        let out = check_of(evidence(json!([bare])));
        assert_eq!(names(&out["not_assessed"]), ["repo-no-dependency-scan", "repo-scan-not-on-pull-request-or-push"], "{missing}");
        assert!(out["undecided"][0]["why"].as_str().unwrap().ends_with("(web: the steps of workflow .github/workflows/ci.yml were not handed on)"), "{out}");
    }
    let own = repo_of("web", json!([{"path": "dynamic/dependabot/dependabot-updates", "state": "active"}]));
    assert_eq!(found(&check_of(evidence(json!([own])))), [("repo-no-dependency-scan".to_string(), "web".to_string())]);
    // A workflow that does not run is listed without its steps, and leaves nothing undecided.
    let idle = repo_of("web", json!([{"path": ".github/workflows/old.yml", "state": "disabled_manually"}]));
    assert_eq!(found(&check_of(evidence(json!([idle])))), [("repo-no-dependency-scan".to_string(), "web".to_string())]);
}

#[test]
fn a_part_that_was_not_read_is_not_assessed() {
    let mut e = evidence(json!([repo("api", json!([]), json!([])), repo("web", json!(["./.github/actions/setup"]), json!([]))]));
    e["unread"] = json!(["workflows"]);
    let out = check_of(e);
    assert_eq!((names(&out["not_assessed"]), found(&out), out["table"]["rows"].clone()), (vec!["repo-no-dependency-scan", "repo-scan-not-on-pull-request-or-push"], vec![], Value::Null));
    // A part that was not read is the reason; no row of it is.
    assert_eq!(out["undecided"], json!([]));
    assert_eq!(out["clean"], false);
    let mut e = evidence(json!([]));
    e.as_object_mut().unwrap().remove("repositories");
    let out = check_of(e);
    assert_eq!((names(&out["unread"]), names(&out["not_assessed"])), (vec!["repositories", "workflows"], vec!["repo-no-dependency-scan", "repo-scan-not-on-pull-request-or-push"]));
    // No repositories at all is a fact, and nothing to find.
    assert_eq!(check_of(evidence(json!([])))["clean"], true);
}

#[test]
fn evidence_that_is_missing_or_not_plain_is_refused() {
    let err = |input: Value| run(json!({"input": input}).to_string()).unwrap_err();
    assert_eq!(run(json!({}).to_string()).unwrap_err(), "the evidence did not arrive");
    let mut wrong = evidence(json!([]));
    wrong["kind"] = json!("github_env_evidence");
    assert_eq!(err(wrong), "the evidence did not arrive");
    let mut odd = evidence(json!([]));
    odd["unread"] = json!(["environments"]);
    assert_eq!(err(odd), "the evidence names a part this check does not know");
    for owner in ["", "Example-Org", "example org", "example_org"] {
        let mut e = evidence(json!([]));
        e["owner"] = json!(owner);
        assert_eq!(err(e), "the evidence does not name its owner plainly", "{owner}");
    }
}

#[test]
fn an_accepted_finding_is_matched_exactly_severity_and_all() {
    let e = evidence(json!([repo("docs", json!([]), json!([]))]));
    let with = |accepted: Value| -> Value { serde_json::from_str(&run(json!({"config": {"ACCEPTED": accepted}, "input": e.clone()}).to_string()).unwrap()).unwrap() };
    let out = with(json!(["repo-no-dependency-scan:medium:docs"]));
    assert_eq!((out["findings"].clone(), out["accepted"][0]["subject"].clone(), out["clean"].clone()), (json!([]), json!("docs"), json!(true)));
    assert_eq!(found(&with(json!(["repo-no-dependency-scan:low:docs"]))).len(), 1);
    let many: Vec<String> = (0..21).map(|n| format!("x:low:{n}")).collect();
    assert_eq!(run(json!({"config": {"ACCEPTED": many}, "input": e}).to_string()).unwrap_err(), "ACCEPTED holds at most twenty findings");
}

#[test]
fn more_findings_than_can_be_kept_is_an_error_and_the_table_is_never_cut() {
    let bare = |n: usize| json!((0..n).map(|i| repo(&format!("r{i}"), json!([]), json!([]))).collect::<Vec<_>>());
    assert_eq!(found(&check_of(evidence(bare(MAX_FINDINGS)))).len(), MAX_FINDINGS);
    let err = run(json!({"input": evidence(bare(MAX_FINDINGS + 1))}).to_string()).unwrap_err();
    assert!(err.starts_with("the check found more than 180 things"), "{err}");
    assert_eq!(check_of(evidence(bare(MAX_ROWS)))["table"]["rows"].as_array().unwrap().len(), MAX_ROWS);
    assert_eq!(check_of(evidence(bare(MAX_ROWS + 1)))["table"]["rows"], Value::Null);
}

/// A repository whose scanner runs in a workflow on `triggers`, beside a build on pull requests.
fn scanning_on(triggers: Value) -> Value {
    repo_of("api", json!([wf("build.yml", json!(["pull_request"]), json!(["actions/checkout@v4"]), json!(["cargo build"])), wf("audit.yml", triggers, json!([]), json!(["cargo audit"]))]))
}
fn timing_of(out: &Value) -> Vec<(String, String)> {
    found(out).into_iter().filter(|(rule, _)| rule == "repo-scan-not-on-pull-request-or-push").collect()
}

#[test]
fn a_scan_counts_on_a_pull_request_a_merge_queue_or_a_push() {
    for event in ["pull_request", "pull_request_target", "push", "merge_group"] {
        let out = check_of(evidence(json!([scanning_on(json!(["schedule", event]))])));
        assert_eq!(out["clean"], true, "{event}: {out}");
        assert_eq!(out["table"]["rows"][0][3], "cargo audit", "{event}");
    }
}

#[test]
fn a_repository_whose_only_scanners_run_on_a_schedule_or_by_hand_is_found() {
    for triggers in [json!(["schedule"]), json!(["workflow_dispatch", "schedule"]), json!(["workflow_run"]), json!(["workflow_call"]), json!([])] {
        let out = check_of(evidence(json!([scanning_on(triggers.clone())])));
        assert_eq!(timing_of(&out), [("repo-scan-not-on-pull-request-or-push".to_string(), "api".to_string())], "{triggers}: {out}");
        // It is not also called a repository with no scanner: it has one.
        assert_eq!(found(&out).len(), 1);
        let f = &out["findings"][0];
        assert_eq!((f["severity"].as_str(), f["basis"].as_str(), f["sources"][1]["heading"].as_str()), (Some("medium"), Some("published guidance"), Some("pull_request")));
        assert_eq!((names(&out["passed"]), out["worst"].as_str()), (vec!["repo-no-dependency-scan"], Some("medium")));
        assert_eq!(out["table"]["rows"][0], json!(["api", "2 of 2", "cargo audit", "none", "0"]));
        assert_eq!(out["counted"], json!({"repositories": 1, "scanning": 1, "scanning_on_change": 0}));
    }
    // What it says names the scanners and the events of the workflows that hold them, each once.
    let mut two = scanning_on(json!(["schedule"]));
    two["workflows"].as_array_mut().unwrap().push(wf("nightly.yml", json!(["schedule", "workflow_dispatch"]), json!(["actions/dependency-review-action@v4"]), json!(["cargo audit"])));
    let says = check_of(evidence(json!([two])))["findings"][0]["says"].as_str().unwrap().to_string();
    assert_eq!(says, "runs its recognised dependency scanners (cargo audit, dependency review) only in workflows triggered by schedule, workflow_dispatch: none runs on a pull request, a merge queue or a push");
    let says = check_of(evidence(json!([scanning_on(json!([]))])))["findings"][0]["says"].as_str().unwrap().to_string();
    assert!(says.contains("triggered by no event:"), "{says}");
    // A workflow that does not run is not where its scanner runs from, nor what triggers it.
    let mut idle = scanning_on(json!(["pull_request"]));
    idle["workflows"][1]["state"] = json!("disabled_manually");
    assert_eq!(found(&check_of(evidence(json!([idle])))), [("repo-no-dependency-scan".to_string(), "api".to_string())]);
}

#[test]
fn a_reusable_workflow_runs_when_a_workflow_of_the_repository_that_runs_on_a_change_calls_it() {
    let called = |caller: Value| repo_of("api", json!([caller, wf("audit.yml", json!(["workflow_call"]), json!([]), json!(["cargo audit"]))]));
    // Called from a pull request build, directly or through another reusable workflow.
    let direct = wf("ci.yml", json!(["pull_request"]), json!(["./.github/workflows/audit.yml"]), json!([]));
    assert_eq!(check_of(evidence(json!([called(direct)])))["clean"], true);
    let mut deep = called(wf("ci.yml", json!(["push"]), json!(["./.github/workflows/middle.yml"]), json!([])));
    deep["workflows"].as_array_mut().unwrap().push(wf("middle.yml", json!(["workflow_call"]), json!(["./.github/workflows/audit.yml@main"]), json!([])));
    assert_eq!(check_of(evidence(json!([deep])))["clean"], true);
    // Called only from a scheduled workflow, or from nothing here, it does not.
    for caller in [wf("ci.yml", json!(["schedule"]), json!(["./.github/workflows/audit.yml"]), json!([])), wf("ci.yml", json!(["push"]), json!(["./.github/workflows/other.yml"]), json!([]))] {
        assert_eq!(timing_of(&check_of(evidence(json!([called(caller)])))).len(), 1);
    }
    // A call is of the same repository's file only.
    for uses in ["example-org/api/.github/workflows/audit.yml@main", "./github/workflows/audit.yml", ".github/workflows/audit.yml"] {
        let out = check_of(evidence(json!([called(wf("ci.yml", json!(["push"]), json!([uses]), json!([])))])));
        assert!(out["clean"] == false, "{uses}: {out}");
    }
}

#[test]
fn a_workflow_whose_triggers_were_not_read_leaves_the_timing_rule_undecided() {
    let mut unread = scanning_on(json!(["schedule"]));
    unread["workflows"][0].as_object_mut().unwrap().remove("triggers");
    unread["workflows"][0]["triggers_unread"] = json!("its on: key is not written as one of the forms this reader reads");
    let out = check_of(evidence(json!([unread.clone(), repo("web", json!([]), json!(["npm audit"]))])));
    assert_eq!((names(&out["not_assessed"]), names(&out["passed"])), (vec!["repo-scan-not-on-pull-request-or-push"], vec!["repo-no-dependency-scan"]), "{out}");
    assert_eq!(out["undecided"], json!([{"rule": "repo-scan-not-on-pull-request-or-push", "why": "1 of 2 repositories whose recognised scanners run on no pull request or push may run one there in a way it could not see (api: the triggers of workflow .github/workflows/build.yml could not be read: its on: key is not written as one of the forms this reader reads)"}]));
    assert_eq!((found(&out), out["clean"].clone()), (vec![], json!(false)));
    // Evidence that does not say at all is undecided too.
    unread["workflows"][0].as_object_mut().unwrap().remove("triggers_unread");
    let why = check_of(evidence(json!([unread])))["undecided"][0]["why"].as_str().unwrap().to_string();
    assert!(why.ends_with("could not be read: the evidence does not say)"), "{why}");
    // A workflow that runs on a change through a call needs no triggers of its own; one GitHub runs itself has none to read.
    let mut via_call = repo_of("api", json!([wf("ci.yml", json!(["pull_request"]), json!(["./.github/workflows/audit.yml"]), json!([])), wf("audit.yml", json!([]), json!([]), json!(["cargo audit"]))]));
    via_call["workflows"][1].as_object_mut().unwrap().remove("triggers");
    assert_eq!(check_of(evidence(json!([via_call])))["clean"], true);
    let mut own = scanning_on(json!(["schedule"]));
    own["workflows"].as_array_mut().unwrap().push(json!({"path": "dynamic/dependabot/dependabot-updates", "state": "active"}));
    assert_eq!(timing_of(&check_of(evidence(json!([own])))).len(), 1);
    // Nor does a workflow that does not run, or one that runs on a change through a call and scans nothing.
    let mut idle = scanning_on(json!(["schedule"]));
    idle["workflows"].as_array_mut().unwrap().push(json!({"path": ".github/workflows/old.yml", "state": "disabled_manually"}));
    assert_eq!(timing_of(&check_of(evidence(json!([idle])))).len(), 1);
    let mut helper = scanning_on(json!(["schedule"]));
    helper["workflows"][0]["uses"] = json!(["./.github/workflows/helper.yml"]);
    helper["workflows"].as_array_mut().unwrap().push(json!({"path": ".github/workflows/helper.yml", "state": "active", "uses": [], "commands": ["make lint"]}));
    assert_eq!(timing_of(&check_of(evidence(json!([helper])))).len(), 1);
    // A repository that does scan on a change is decided, whatever else is unread.
    let mut fine = scanning_on(json!(["push"]));
    fine["workflows"][0].as_object_mut().unwrap().remove("triggers");
    assert_eq!(check_of(evidence(json!([fine])))["clean"], true);
}

#[test]
fn work_not_read_that_runs_on_a_change_leaves_the_timing_rule_undecided() {
    let mut hidden = scanning_on(json!(["schedule"]));
    hidden["workflows"][0]["uses"] = json!(["example-org/shared/.github/workflows/build.yml@main"]);
    let out = check_of(evidence(json!([hidden])));
    assert_eq!(names(&out["not_assessed"]), ["repo-scan-not-on-pull-request-or-push"]);
    assert!(out["undecided"][0]["why"].as_str().unwrap().ends_with("(api: its workflows that run on a change call 1 thing(s) this reader did not read, such as example-org/shared/.github/workflows/build.yml@main)"), "{out}");
    // The same call in a workflow that does not run on a change cannot put the scan there.
    let mut late = scanning_on(json!(["schedule"]));
    late["workflows"][1]["uses"] = json!(["./.github/actions/setup"]);
    assert_eq!(timing_of(&check_of(evidence(json!([late])))).len(), 1);
    // A workflow in a state it does not know, or whose steps did not arrive, may be the one that scans on a change.
    let mut odd = scanning_on(json!(["schedule"]));
    odd["workflows"].as_array_mut().unwrap().push(json!({"path": ".github/workflows/x.yml", "state": "sleeping"}));
    assert!(check_of(evidence(json!([odd])))["undecided"][0]["why"].as_str().unwrap().contains("state this check does not know"));
    let mut bare = scanning_on(json!(["schedule"]));
    bare["workflows"][0].as_object_mut().unwrap().remove("commands");
    assert!(check_of(evidence(json!([bare])))["undecided"][0]["why"].as_str().unwrap().contains("were not handed on"));
}
}
