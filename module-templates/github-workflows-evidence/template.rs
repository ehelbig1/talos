// github-workflows-evidence: reads what an organisation's repositories run
// in their GitHub Actions workflows: for each repository the App is installed
// on, its workflows and their state, and, from each active workflow's file on
// the default branch, the events that trigger it, the actions its steps and
// jobs use and the first words of each command they run, each workflow apart.
// It reads; every request is a GET, and the module is granted that verb only.
//
// WHICH repositories is not this module's choice, nor its config's: it reads
// the repositories the GitHub App was installed on, and nothing else can be
// reached with the token it is given.
//
// It judges nothing: which of those steps scan dependencies is the check's to
// say (`github-dependency-scan-check`). What it could not read it says so in
// `unread` instead of handing on an empty list: an empty list of workflows
// means the repository has none.
//
// Requests: the installation's repositories, then one listing of workflows
// per repository, then one file per active workflow. All bounded; more than
// a bound is unread, never cut. At most 30 repositories, 100 workflows in a
// repository (one page of its listing) and 150 workflow files in all: with
// the listings that is at most 182 requests, within the 200 the platform
// lets one run make to one host.
//
// What it hands on is bounded by its size, not by a count of lines: the
// evidence, as written, is at most 300,000 bytes, a third of the 1,000,000
// the platform takes as a node's input (WASM_MAX_INPUT_BYTES). A workflow's
// first node is given the run's trigger three times over (spread as its
// top-level keys, as `input` and as `__trigger_input__`), and a shadow
// workflow's trigger is this evidence: 3 × 300,000 is 900,000, and the rest
// is room for the node's config and the engine's own keys. The repositories
// are counted as they are read, after room is set aside for the rest of the
// evidence, and one whose workflows would take it over the bound is left out
// and the workflows named unread, saying how large it is. A count of `uses:`
// and commands per repository could not be raised to what a large
// repository runs and still fit: thirty repositories at such a count would
// not.
//
// What it takes from a workflow file is read line by line, not by a YAML
// parser: `uses:` values, and the lines of each `run:` (inline, or a `|` or
// `>` block), each command cut at `&&`, `||` and `;` and kept to its first
// six words. A step written in YAML's flow style (`{ uses: … }`) is not seen.
//
// The triggers are the event names of the file's top-level `on:` key, in the
// three forms GitHub's workflow syntax page shows under "Using a single
// event" (`on: push`), "Using multiple events" (`on: [push, fork]`) and
// "Using activity types and filters with multiple events" (a mapping, one
// event per key). Read 2026-10-14 at
// https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax.
// Any other form (a block list, a flow mapping, an anchor, no `on:` key, two
// of them) is not guessed at: the workflow's `triggers_unread` says why, and
// it has no `triggers`.
//
// Network: api.github.com only. The token is an installation token Talos
// mints for this run. It needs the repository permissions "Contents: read"
// (the workflow files) and "Actions: read" (the workflow listing). Without
// Contents the files answer 403, and the workflows are unread.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const API: &str = "https://api.github.com";
const MAX_REPOS: usize = 30;
/// One page of a repository's workflow listing.
const MAX_WORKFLOWS: usize = 100;
const MAX_FILE_READS: usize = 150;
const MAX_FILE_BYTES: usize = 200_000;
/// The most evidence this reader hands on, in bytes as written: a third of the platform's
/// 1,000,000-byte node input, since a workflow's first node is given its trigger three times
/// (3 × 300,000 = 900,000, and 100,000 left for the node's config and the engine's keys).
const MAX_EVIDENCE_BYTES: usize = 300_000;
/// What the evidence holds besides its repositories (kind, owner, unread, errors, counts, and the
/// list's brackets and commas), set aside before any repository is counted. The tests measure the most it can be.
const ENVELOPE_BYTES: usize = 4_000;
const COMMAND_WORDS: usize = 6;
const COMMAND_CHARS: usize = 120;
/// GitHub has some forty events; a workflow that names more is not one this reader understands.
const MAX_TRIGGERS: usize = 40;
const EVENT_CHARS: usize = 40;
/// Where a workflow that is a file in the repository lives. Others (GitHub's own, such as Dependabot's) have no file to read.
const WORKFLOW_DIR: &str = ".github/workflows/";

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
struct Workflows {
    #[serde(default)]
    total_count: u64,
    #[serde(default)]
    workflows: Vec<Workflow>,
}
#[derive(Deserialize)]
struct Workflow {
    #[serde(default)]
    path: String,
    #[serde(default)]
    state: String,
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
/// A workflow file's path as a request path: one file directly in the workflows directory, each part encoded.
fn file_path(path: &str) -> Option<String> {
    let file = path.strip_prefix(WORKFLOW_DIR)?;
    (!file.is_empty() && !file.contains('/') && file != "." && file != ".." && (file.ends_with(".yml") || file.ends_with(".yaml"))).then(|| format!("{WORKFLOW_DIR}{}", pct(file)))
}

/// One GET. The status and the kind of failure are kept; no body of an error is.
fn get(auth: &str, url: &str, accept: &str) -> Result<Vec<u8>, String> {
    use talos::core::http::{self, Method, Request};
    let req = Request {
        method: Method::Get,
        url: url.to_string(),
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Accept".to_string(), accept.to_string()),
            ("X-GitHub-Api-Version".to_string(), "2022-11-28".to_string()),
            ("User-Agent".to_string(), "talos-github-workflows-evidence".to_string()),
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
const JSON: &str = "application/vnd.github+json";
const RAW: &str = "application/vnd.github.raw+json";

/// A value as YAML writes it on one line: a trailing comment and one pair of quotes taken off.
fn scalar(v: &str) -> String {
    let v = v.trim();
    let v = if v.starts_with('"') || v.starts_with('\'') {
        let q = v.chars().next().unwrap_or('"');
        v[1..].split(q).next().unwrap_or("")
    } else {
        v.split(" #").next().unwrap_or("")
    };
    v.trim().to_string()
}
/// The first words of each command on a line of shell.
fn commands_of(line: &str, into: &mut Vec<String>) {
    for piece in line.split("&&").flat_map(|p| p.split("||")).flat_map(|p| p.split(';')) {
        let words: Vec<&str> = piece.split_whitespace().take(COMMAND_WORDS).collect();
        if !words.is_empty() && !words[0].starts_with('#') {
            into.push(shown(&words.join(" "), COMMAND_CHARS));
        }
    }
}
/// The `uses:` values and the commands of `run:` in a workflow file.
fn extract(text: &str) -> (Vec<String>, Vec<String>) {
    let lines: Vec<&str> = text.lines().map(|l| l.trim_end_matches('\r')).collect();
    let (mut uses, mut commands) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        i += 1;
        let mut col = line.len() - line.trim_start().len();
        let mut t = line.trim_start();
        // A list item's key sits after its dash.
        while let Some(rest) = t.strip_prefix("- ") {
            col += 2 + rest.len() - rest.trim_start().len();
            t = rest.trim_start();
        }
        if let Some(v) = t.strip_prefix("uses:") {
            let v = scalar(v);
            if !v.is_empty() {
                uses.push(shown(&v, COMMAND_CHARS));
            }
        } else if let Some(v) = t.strip_prefix("run:") {
            let v = v.trim();
            if v.starts_with('|') || v.starts_with('>') {
                // A block: every following line indented past the key, blank lines among them.
                while i < lines.len() && (lines[i].trim().is_empty() || lines[i].len() - lines[i].trim_start().len() > col) {
                    commands_of(lines[i].trim(), &mut commands);
                    i += 1;
                }
            } else {
                commands_of(&scalar(v), &mut commands);
            }
        }
    }
    (uses, commands)
}
/// A line that is the workflow's own `on:` key, at the top level: what follows the colon.
fn on_key(line: &str) -> Option<&str> {
    ["on:", "\"on\":", "'on':"].iter().find_map(|k| line.strip_prefix(k))
}
/// What follows a key, with a trailing comment taken off.
fn uncommented(v: &str) -> &str {
    let v = v.trim();
    if v.starts_with('#') {
        ""
    } else {
        v.split(" #").next().unwrap_or("").trim()
    }
}
/// One event name, as written: one pair of quotes taken off. `None` when it is not a plain name.
fn event(v: &str) -> Option<String> {
    let v = v.trim();
    let v = if v.len() >= 2 && (v.starts_with('"') && v.ends_with('"') || v.starts_with('\'') && v.ends_with('\'')) { &v[1..v.len() - 1] } else { v };
    (!v.is_empty() && v.len() <= EVENT_CHARS && v.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')).then(|| v.to_string())
}
/// The events that trigger a workflow, from its top-level `on:` key, or why they could not be read.
fn triggers(text: &str) -> Result<Vec<String>, String> {
    let lines: Vec<&str> = text.lines().collect();
    let keys: Vec<usize> = (0..lines.len()).filter(|&i| on_key(lines[i]).is_some()).collect();
    let at = match keys[..] {
        [] => return Err("it has no top-level on: key".to_string()),
        [one] => one,
        _ => return Err("it has more than one top-level on: key".to_string()),
    };
    let value = uncommented(on_key(lines[at]).unwrap_or(""));
    let mut events: Vec<String> = Vec::new();
    if value.is_empty() {
        // A mapping: each key at the first indentation below `on:` is an event; what is further in is its settings.
        let mut indent: Option<usize> = None;
        for line in &lines[at + 1..] {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let col = line.len() - line.trim_start().len();
            if col == 0 {
                break;
            }
            let first = *indent.get_or_insert(col);
            if col > first {
                continue;
            }
            if col < first || t.starts_with('-') {
                return Err("its on: key is not written as one of the forms this reader reads".to_string());
            }
            let name = t.split_once(':').and_then(|(k, _)| event(k)).ok_or("its on: key names an event that is not written plainly")?;
            events.push(name);
        }
    } else if let Some(inner) = value.strip_prefix('[') {
        let inner = inner.strip_suffix(']').ok_or("its on: list does not close on its line")?;
        for item in inner.split(',') {
            events.push(event(item).ok_or("its on: list names an event that is not written plainly")?);
        }
    } else {
        events.push(event(value).ok_or("its on: key is not written as one of the forms this reader reads")?);
    }
    let mut seen: Vec<String> = Vec::new();
    for e in events {
        if !seen.contains(&e) {
            seen.push(e);
        }
    }
    if seen.is_empty() {
        return Err("its on: key names no event".to_string());
    }
    if seen.len() > MAX_TRIGGERS {
        return Err(format!("its on: key names more than {MAX_TRIGGERS} events"));
    }
    Ok(seen)
}
fn add(list: &mut Vec<String>, more: Vec<String>) {
    for m in more {
        if !list.contains(&m) {
            list.push(m);
        }
    }
}

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

/// One repository's workflows, and for each active one what triggers it, what it uses and what it runs.
fn read_repo(auth: &str, owner: &str, repo: &str, file_reads: &mut usize) -> Result<serde_json::Value, String> {
    let got: Workflows = serde_json::from_slice(&get(auth, &format!("{API}/repos/{owner}/{repo}/actions/workflows?per_page=100"), JSON).map_err(|e| format!("a workflow listing {e}"))?).map_err(|_| "a workflow listing answered with something that could not be read".to_string())?;
    if got.total_count as usize > got.workflows.len() || got.workflows.len() > MAX_WORKFLOWS {
        return Err(format!("a repository has more than {MAX_WORKFLOWS} workflows"));
    }
    let mut rows = Vec::new();
    for w in &got.workflows {
        let mut row = serde_json::json!({ "path": shown(&w.path, 200), "state": shown(&w.state, 40) });
        // A workflow that does not run is not read; one that is not a file here has nothing to read.
        if let Some(path) = file_path(&w.path).filter(|_| w.state == "active") {
            *file_reads += 1;
            if *file_reads > MAX_FILE_READS {
                return Err(format!("more than {MAX_FILE_READS} workflow files"));
            }
            let body = get(auth, &format!("{API}/repos/{owner}/{repo}/contents/{path}"), RAW).map_err(|e| format!("a workflow file {e}"))?;
            if body.len() > MAX_FILE_BYTES {
                return Err(format!("a workflow file is larger than {MAX_FILE_BYTES} bytes"));
            }
            let text = String::from_utf8(body).map_err(|_| "a workflow file is not text".to_string())?;
            let (u, c) = extract(&text);
            let (mut uses, mut commands) = (Vec::new(), Vec::new());
            add(&mut uses, u);
            add(&mut commands, c);
            match triggers(&text) {
                Ok(events) => row["triggers"] = events.into(),
                // Said, never guessed: the check leaves its rule undecided on it.
                Err(why) => row["triggers_unread"] = why.into(),
            }
            row["uses"] = uses.into();
            row["commands"] = commands.into();
        }
        rows.push(row);
    }
    Ok(serde_json::json!({ "repo": repo, "workflows": rows }))
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
            let got: Repos = serde_json::from_slice(&get(&auth, &format!("{API}/installation/repositories?per_page=100&page={page}"), JSON).map_err(|e| format!("the repository listing {e}"))?).map_err(|_| "the repository listing answered with something that could not be read".to_string())?;
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
            unread.extend(["repositories", "workflows"]);
            errors.insert("repositories".to_string(), e.into());
            Vec::new()
        }
    };

    // ---- each repository's workflows
    let mut failed_repos = 0usize;
    let mut file_reads = 0usize;
    let mut budget = Budget::new();
    for r in &repos {
        if !name_ok(&r.name, 100) {
            failed_repos += 1;
            errors.insert("workflows".to_string(), "a repository has a name that could not be used".into());
            continue;
        }
        // A repository too large to hand on whole is left out, never cut.
        match read_repo(&auth, &owner, &r.name, &mut file_reads).and_then(|row| budget.take("a repository's workflows are", row)) {
            Ok(row) => out_repos.push(row),
            Err(e) => {
                failed_repos += 1;
                errors.insert("workflows".to_string(), e.into());
            }
        }
    }
    // One repository unread makes the whole part unread: its rule is then not assessed, not passed.
    if failed_repos > 0 && !unread.contains(&"workflows") {
        unread.push("workflows");
    }

    let mut out = serde_json::json!({
        "kind": "github_workflows_evidence", "owner": owner,
        "unread": unread, "errors": errors,
        "counted": { "repositories": repos.len(), "repositories_read": out_repos.len(), "workflow_files_read": file_reads, "archived_skipped": skipped_archived, "other_owner": other_owner },
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

const CI: &str = "name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4 # pinned below
      - name: Install
        run: npm ci && npm run build
      - name: Audit
        run: |
          # a comment, not a command
          npm audit --audit-level=high --omit=dev --json --foo --bar
          echo done; cargo deny check advisories

        env:
          X: 1
      - uses: 'actions/dependency-review-action@v4'
  shared:
    uses: example-org/shared/.github/workflows/build.yml@main
";
const RELEASE: &str = "on: workflow_dispatch\r\njobs:\r\n  r:\r\n    steps:\r\n    - run: >-\r\n        cargo audit\r\n    - uses: \"./.github/actions/setup\"\r\n";

fn repo(name: &str) -> Value {
    json!({"name": name, "archived": false, "owner": {"login": "Example-Org"}})
}
fn read() -> Result<Value, String> {
    run(json!({"config": {"AUTH_HEADER": "Bearer x", "OWNER": "Example-Org"}}).to_string()).map(|o| serde_json::from_str(&o).unwrap())
}
/// Answers by path: the installation's repositories, each repository's workflows, and each file.
fn github(repos: Value, workflows: fn(&str) -> (u16, Value), file: fn(&str) -> (u16, String)) {
    host::http::respond_with(move |req| {
        let path = req.url.trim_start_matches("https://api.github.com");
        Ok(if path.starts_with("/installation/repositories") {
            host::http::response(200, json!({"total_count": repos.as_array().unwrap().len(), "repositories": repos}).to_string())
        } else if path.contains("/actions/workflows") {
            let (status, body) = workflows(path.trim_start_matches("/repos/example-org/").split('/').next().unwrap());
            host::http::response(status, body.to_string())
        } else {
            let (status, body) = file(path);
            host::http::response(status, body)
        })
    });
}
fn two(repo: &str) -> (u16, Value) {
    if repo == "api" {
        (200, json!({"total_count": 4, "workflows": [
            {"id": 1, "name": "ci", "path": ".github/workflows/ci.yml", "state": "active"},
            {"id": 2, "name": "release", "path": ".github/workflows/release.yaml", "state": "active"},
            {"id": 3, "name": "old", "path": ".github/workflows/old.yml", "state": "disabled_manually"},
            {"id": 4, "name": "Dependabot Updates", "path": "dynamic/dependabot/dependabot-updates", "state": "active"},
        ]}))
    } else {
        (200, json!({"total_count": 0, "workflows": []}))
    }
}
fn files(path: &str) -> (u16, String) {
    if path.ends_with("/ci.yml") {
        (200, CI.to_string())
    } else if path.ends_with("/release.yaml") {
        (200, RELEASE.to_string())
    } else {
        (404, "{}".to_string())
    }
}

#[test]
fn it_reads_each_repositorys_active_workflow_files_and_hands_on_their_steps() {
    github(json!([repo("api"), repo("docs"), {"name": "old", "archived": true, "owner": {"login": "example-org"}}, {"name": "elsewhere", "owner": {"login": "someone-else"}}]), two, files);
    let out = read().unwrap();
    assert_eq!((out["kind"].as_str(), out["owner"].as_str(), out["unread"].clone(), out["errors"].clone()), (Some("github_workflows_evidence"), Some("example-org"), json!([]), json!({})));
    assert_eq!(out["repositories"], json!([
        {"repo": "api",
         "workflows": [
            {"path": ".github/workflows/ci.yml", "state": "active", "triggers": ["push", "pull_request"],
             "uses": ["actions/checkout@v4", "actions/dependency-review-action@v4", "example-org/shared/.github/workflows/build.yml@main"],
             "commands": ["npm ci", "npm run build", "npm audit --audit-level=high --omit=dev --json --foo", "echo done", "cargo deny check advisories"]},
            {"path": ".github/workflows/release.yaml", "state": "active", "triggers": ["workflow_dispatch"], "uses": ["./.github/actions/setup"], "commands": ["cargo audit"]},
            // A workflow that does not run, and one that is not a file here, are listed and not read.
            {"path": ".github/workflows/old.yml", "state": "disabled_manually"},
            {"path": "dynamic/dependabot/dependabot-updates", "state": "active"},
         ]},
        // A repository with no workflows is a fact, and is written as one.
        {"repo": "docs", "workflows": []},
    ]));
    assert_eq!(out["counted"], json!({"repositories": 2, "repositories_read": 2, "workflow_files_read": 2, "archived_skipped": 1, "other_owner": 1}));
    // Every request is a GET to api.github.com; the files are asked for raw, from the default branch.
    let seen = host::http::requests();
    assert!(seen.iter().all(|r| matches!(r.method, Method::Get) && r.url.starts_with("https://api.github.com/") && r.body.is_empty()));
    let urls: Vec<&str> = seen.iter().map(|r| r.url.as_str()).collect();
    assert_eq!(urls, [
        "https://api.github.com/installation/repositories?per_page=100&page=1",
        "https://api.github.com/repos/example-org/api/actions/workflows?per_page=100",
        "https://api.github.com/repos/example-org/api/contents/.github/workflows/ci.yml",
        "https://api.github.com/repos/example-org/api/contents/.github/workflows/release.yaml",
        "https://api.github.com/repos/example-org/docs/actions/workflows?per_page=100",
    ]);
    let accept = |r: &talos::core::http::Request| r.headers.iter().find(|(k, _)| k == "Accept").unwrap().1.clone();
    assert_eq!((accept(&seen[1]), accept(&seen[2])), ("application/vnd.github+json".to_string(), "application/vnd.github.raw+json".to_string()));
    // What it hands on is what the check judges: api scans; docs has no workflow.
    let judged: Value = serde_json::from_str(&crate::github_dependency_scan_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    let found: Vec<&str> = judged["findings"].as_array().unwrap().iter().map(|f| f["subject"].as_str().unwrap()).collect();
    assert_eq!((found, judged["not_assessed"].clone()), (vec!["docs"], json!([])), "{judged}");
    assert_eq!(judged["table"]["rows"][0][2], "dependency review, npm audit, cargo deny, cargo audit");
    // cargo audit runs only by hand; the others run on pushes and pull requests.
    assert_eq!(judged["table"]["rows"][0][3], "dependency review, npm audit, cargo deny");
}

#[test]
fn a_workflow_file_that_could_not_be_read_makes_the_workflows_unread() {
    // Without the Contents permission a file answers 403.
    github(json!([repo("api")]), two, |_| (403, "{\"message\": \"secret-looking detail\"}".to_string()));
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["errors"]["workflows"].as_str()), (json!(["workflows"]), Some("a workflow file answered HTTP 403")));
    assert!(!out.to_string().contains("secret-looking"));
    assert_eq!(out["repositories"], json!([]));
    let judged: Value = serde_json::from_str(&crate::github_dependency_scan_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert_eq!((judged["not_assessed"].clone(), judged["clean"].clone()), (json!(["repo-no-dependency-scan", "repo-scan-not-on-pull-request-or-push"]), json!(false)));

    github(json!([repo("api")]), |_| (500, json!({})), files);
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["errors"]["workflows"].as_str()), (json!(["workflows"]), Some("a workflow listing answered HTTP 500")));
    github(json!([repo("api")]), two, |_| (200, "x".repeat(MAX_FILE_BYTES + 1)));
    assert_eq!(read().unwrap()["errors"]["workflows"], format!("a workflow file is larger than {MAX_FILE_BYTES} bytes"));
}

#[test]
fn what_a_file_uses_and_runs_twice_is_handed_on_once_and_each_file_apart() {
    github(json!([repo("api")]), two, |_| (200, format!("{CI}      - uses: actions/checkout@v4\n        run: npm ci\n")));
    let out = read().unwrap();
    let wf = &out["repositories"][0]["workflows"];
    assert_eq!((wf[0]["uses"].as_array().unwrap().len(), wf[0]["commands"].as_array().unwrap().len()), (3, 5), "{out}");
    // Two files that use the same action each say so: what runs when is a workflow's, not the repository's.
    assert_eq!((wf[0]["uses"].clone(), wf[1]["commands"].clone()), (wf[1]["uses"].clone(), wf[0]["commands"].clone()));
}

#[test]
fn the_events_that_trigger_a_workflow_are_read_in_the_three_forms_and_any_other_is_said() {
    assert_eq!(triggers("on: push\n"), Ok(vec!["push".to_string()]));
    assert_eq!(triggers("name: x\n\"on\": 'pull_request' # pr\n"), Ok(vec!["pull_request".to_string()]));
    assert_eq!(triggers("on: [push, \"pull_request\", push]  # both\njobs: {}\n"), Ok(vec!["push".to_string(), "pull_request".to_string()]));
    let mapping = "on: # every change\n  pull_request:\n    branches: [main]\n    types:\n      - opened\n\n  # nightly too\n  schedule:\n    - cron: '0 3 * * *'\n  'merge_group':\njobs:\n  on:\n    push:\n";
    assert_eq!(triggers(mapping), Ok(vec!["pull_request".to_string(), "schedule".to_string(), "merge_group".to_string()]));
    // `on:` further in is a job's key, not the workflow's.
    assert_eq!(triggers("jobs:\n  build:\n    on: push\n").unwrap_err(), "it has no top-level on: key");
    assert_eq!(triggers("on: push\non: pull_request\n").unwrap_err(), "it has more than one top-level on: key");
    assert_eq!(triggers("on:\n  - push\n  - pull_request\n").unwrap_err(), "its on: key is not written as one of the forms this reader reads");
    assert_eq!(triggers("on:\n    push:\n  pull_request:\n").unwrap_err(), "its on: key is not written as one of the forms this reader reads");
    for form in ["on: {push: {branches: [main]}}\n", "on: &triggers\n  push:\n", "on: *triggers\n", "on: |\n  push\n"] {
        assert_eq!(triggers(form).unwrap_err(), "its on: key is not written as one of the forms this reader reads", "{form}");
    }
    assert_eq!(triggers("on: [push,\n  pull_request]\n").unwrap_err(), "its on: list does not close on its line");
    assert_eq!(triggers("on: [push, Pull_Request]\n").unwrap_err(), "its on: list names an event that is not written plainly");
    assert_eq!(triggers("on: []\n").unwrap_err(), "its on: list names an event that is not written plainly");
    assert_eq!(triggers("on:\n  push-it:\n").unwrap_err(), "its on: key names an event that is not written plainly");
    assert_eq!(triggers("on:\njobs:\n  a: {}\n").unwrap_err(), "its on: key names no event");
    assert_eq!(triggers(&format!("on: {}\n", "a".repeat(EVENT_CHARS + 1))).unwrap_err(), "its on: key is not written as one of the forms this reader reads");
    assert_eq!(triggers(&format!("on: {}\n", "a".repeat(EVENT_CHARS))), Ok(vec!["a".repeat(EVENT_CHARS)]));
    let many = (0..=MAX_TRIGGERS).map(|i| format!("{}_{}", (b'a' + (i / 26) as u8) as char, (b'a' + (i % 26) as u8) as char)).collect::<Vec<_>>().join(", ");
    assert_eq!(triggers(&format!("on: [{many}]\n")).unwrap_err(), format!("its on: key names more than {MAX_TRIGGERS} events"));
}

#[test]
fn a_workflow_whose_triggers_cannot_be_read_is_handed_on_with_the_reason_and_no_triggers() {
    github(json!([repo("api")]), two, |path| if path.ends_with("/ci.yml") { (200, CI.replace("on: [push, pull_request]", "on:\n  - push")) } else { files(path) });
    let out = read().unwrap();
    let ci = &out["repositories"][0]["workflows"][0];
    assert_eq!((ci.get("triggers"), ci["triggers_unread"].as_str()), (None, Some("its on: key is not written as one of the forms this reader reads")), "{out}");
    // The file is read all the same, and nothing else of the repository is unread.
    assert_eq!((ci["uses"].as_array().unwrap().len(), out["unread"].clone()), (3, json!([])));
    let judged: Value = serde_json::from_str(&crate::github_dependency_scan_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert_eq!(judged["not_assessed"], json!(["repo-scan-not-on-pull-request-or-push"]), "{judged}");
}

#[test]
fn half_a_repository_listing_or_a_name_that_cannot_be_used_is_unread() {
    host::http::respond_with(|req| {
        Ok(if req.url.contains("/installation/repositories") {
            host::http::response(200, json!({"total_count": 500, "repositories": (0..100).map(|i| repo(&format!("r{i}"))).collect::<Vec<_>>()}).to_string())
        } else {
            host::http::response(200, json!({"total_count": 0, "workflows": []}).to_string())
        })
    });
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["errors"]["repositories"].as_str()), (json!(["repositories", "workflows"]), Some("the App is installed on more than 200 repositories")));
    github(json!([repo("api"), repo("..")]), two, files);
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["errors"]["workflows"].as_str()), (json!(["workflows"]), Some("a repository has a name that could not be used")));
    assert!(host::http::requests().iter().all(|r| !r.url.contains("/repos/example-org/../")));
}

#[test]
fn the_repository_listing_that_could_not_be_read_leaves_everything_unread() {
    host::http::respond_with(|_| Ok(host::http::response(401, "{}")));
    let out = read().unwrap();
    assert!(out.get("repositories").is_none());
    assert_eq!((out["unread"].clone(), out["errors"]["repositories"].as_str()), (json!(["repositories", "workflows"]), Some("the repository listing answered HTTP 401")));
    // No responder: the kind of the failure is kept.
    host::http::respond_with(|_| Err(talos::core::http::Error::Networkerror));
    let why = read().unwrap()["errors"]["repositories"].as_str().unwrap().to_string();
    assert!(why.starts_with("the repository listing could not be reached (") && why.to_lowercase().contains("network"), "{why}");
}

#[test]
fn listings_and_files_beyond_the_bounds_are_unread_never_cut() {
    github(json!([repo("api")]), |_| (200, json!({"total_count": 101, "workflows": []})), files);
    assert_eq!(read().unwrap()["errors"]["workflows"], "a repository has more than 100 workflows");
    // One page of the listing is read whole, and a repository with more than it holds is unread.
    github(json!([repo("api")]), |_| (200, json!({"total_count": 101, "workflows": (0..101).map(|i| json!({"path": format!(".github/workflows/w{i}.yml"), "state": "disabled_manually"})).collect::<Vec<_>>()})), files);
    assert_eq!(read().unwrap()["unread"], json!(["workflows"]));
    github(json!([repo("api")]), |_| (200, json!({"total_count": 100, "workflows": (0..100).map(|i| json!({"path": format!(".github/workflows/w{i}.yml"), "state": "disabled_manually"})).collect::<Vec<_>>()})), files);
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["repositories"][0]["workflows"].as_array().unwrap().len()), (json!([]), MAX_WORKFLOWS));

    // Across repositories, the files read are bounded too.
    let repos = json!((0..2).map(|i| repo(&format!("r{i}"))).collect::<Vec<_>>());
    github(repos.clone(), |_| (200, json!({"total_count": 100, "workflows": (0..100).map(|i| json!({"path": format!(".github/workflows/w{i}.yml"), "state": "active"})).collect::<Vec<_>>()})), |_| (200, "on: push\n".to_string()));
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["errors"]["workflows"].as_str()), (json!(["workflows"]), Some("more than 150 workflow files")));
    assert_eq!(out["counted"]["workflow_files_read"], MAX_FILE_READS + 1);

    let many = json!((0..=MAX_REPOS).map(|i| repo(&format!("r{i}"))).collect::<Vec<_>>());
    github(many, two, files);
    assert!(read().unwrap_err().contains("more than 30 active repositories"));
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
fn what_is_handed_on_is_bounded_by_its_size_and_more_is_unread() {
    // Counted in bytes as written, after room is set aside for the rest of the evidence: up to the bound, and not one byte over.
    let room = MAX_EVIDENCE_BYTES - ENVELOPE_BYTES;
    let mut budget = Budget::new();
    assert_eq!(budget.take("it is", sized(room)), Ok(sized(room)));
    assert_eq!(budget.used, MAX_EVIDENCE_BYTES);
    assert_eq!(Budget::new().take("it is", sized(room + 1)).unwrap_err(), format!("it is too large to hand on ({} bytes as written; the evidence is at most 300000 bytes in all)", room + 1));
    // A row that does not fit is not counted, so what is counted is what was handed on.
    let mut budget = Budget::new();
    assert!(budget.take("it is", sized(room - 10)).is_ok() && budget.take("it is", sized(11)).is_err());
    assert!(budget.take("it is", sized(10)).is_ok() && budget.used == MAX_EVIDENCE_BYTES);
    // Bytes, not characters, and escapes as they are written: the collector pins the same size for the same value.
    assert_eq!(json!({"a": "é\"\\😀", "b": [1, true, null]}).to_string().len(), 36);
    let wide = |n: usize| json!(format!("{}{}", "😀".repeat(1000), "x".repeat(n - 2 - 4000)));
    assert!(Budget::new().take("it is", wide(room)).is_ok() && Budget::new().take("it is", wide(room + 1)).is_err());

    // A repository that runs a thousand distinct commands of a hundred characters is handed on whole;
    // two of them fit in what is handed on, and a third does not.
    fn busy(path: &str) -> (u16, String) {
        let repo = path.trim_start_matches("/repos/example-org/").split('/').next().unwrap().to_string();
        if !path.ends_with("/ci.yml") {
            return (404, "{}".to_string());
        }
        let lines: String = (0..1000).map(|i| format!("          {repo}-{i:04}-{}\n", "y".repeat(100 - repo.len() - 6))).collect();
        (200, format!("on: push\njobs:\n  a:\n    steps:\n      - run: |\n{lines}"))
    }
    fn one(_: &str) -> (u16, Value) {
        (200, json!({"total_count": 1, "workflows": [{"path": ".github/workflows/ci.yml", "state": "active"}]}))
    }
    github(json!((0..2).map(|i| repo(&format!("r{i}"))).collect::<Vec<_>>()), one, busy);
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["repositories"].as_array().unwrap().len()), (json!([]), 2), "{}", out["errors"]);
    assert_eq!(out["repositories"][1]["workflows"][0]["commands"].as_array().unwrap().len(), 1000);
    assert!(out.to_string().len() <= MAX_EVIDENCE_BYTES);
    github(json!((0..3).map(|i| repo(&format!("r{i}"))).collect::<Vec<_>>()), one, busy);
    let out = read().unwrap();
    // The collector pins the same size for the same repository.
    assert_eq!((out["unread"].clone(), out["errors"]["workflows"].as_str()), (json!(["workflows"]), Some("a repository's workflows are too large to hand on (103123 bytes as written; the evidence is at most 300000 bytes in all)")));
    assert_eq!((out["repositories"].as_array().unwrap().len(), out["counted"]["repositories_read"].clone()), (2, json!(2)));
    let judged: Value = serde_json::from_str(&crate::github_dependency_scan_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert_eq!(judged["not_assessed"], json!(["repo-no-dependency-scan", "repo-scan-not-on-pull-request-or-push"]), "{judged}");

    // The most it can hand on: the repositories filling what they are given, and everything else at its longest.
    let mut worst = json!({"kind": "github_workflows_evidence", "owner": "a".repeat(39), "unread": ["repositories", "workflows"],
                           "errors": {"repositories": "x".repeat(200), "workflows": "x".repeat(200)},
                           "counted": {"repositories": MAX_REPOS, "repositories_read": MAX_REPOS, "workflow_files_read": MAX_FILE_READS + 1, "archived_skipped": 200, "other_owner": 200}});
    worst["repositories"] = json!([]);
    let envelope = worst.to_string().len() + MAX_REPOS;
    println!("github workflows evidence besides its repositories, at most: {envelope} bytes");
    assert!(envelope <= ENVELOPE_BYTES, "{envelope}");
    worst["repositories"] = json!([sized(room)]);
    let bytes = worst.to_string().len();
    println!("worst-case github workflows evidence: {bytes} bytes");
    assert!(bytes <= MAX_EVIDENCE_BYTES, "{bytes}");
}

#[test]
fn a_workflow_path_that_is_not_one_file_in_the_workflows_directory_is_not_requested() {
    assert_eq!(file_path(".github/workflows/ci.yml").as_deref(), Some(".github/workflows/ci.yml"));
    assert_eq!(file_path(".github/workflows/my ci.yaml").as_deref(), Some(".github/workflows/my%20ci.yaml"));
    for path in ["ci.yml", "dynamic/dependabot/dependabot-updates", ".github/workflows/../../secrets.yml", ".github/workflows/sub/ci.yml", ".github/workflows/", ".github/workflows/notes.txt", "x/.github/workflows/ci.yml"] {
        assert_eq!(file_path(path), None, "{path}");
    }
}

#[test]
fn steps_are_read_from_a_workflow_line_by_line() {
    let (uses, commands) = extract(CI);
    assert_eq!(uses, ["actions/checkout@v4", "actions/dependency-review-action@v4", "example-org/shared/.github/workflows/build.yml@main"]);
    // A block ends where a line is no further in than its key; blank lines inside it are kept going.
    assert_eq!(commands, ["npm ci", "npm run build", "npm audit --audit-level=high --omit=dev --json --foo", "echo done", "cargo deny check advisories"]);
    let (uses, commands) = extract(RELEASE);
    assert_eq!((uses, commands), (vec!["./.github/actions/setup".to_string()], vec!["cargo audit".to_string()]));
    let (_, commands) = extract("steps:\n  - run: \"pip-audit -r requirements.txt\" # audit\n  - run: osv-scanner --lockfile=x || true\n");
    assert_eq!(commands, ["pip-audit -r requirements.txt", "osv-scanner --lockfile=x", "true"]);
    // A key after a list item's dash is where the block is measured from.
    let (_, commands) = extract("      - run: |\n          cargo audit\n        env:\n          X: 1\n");
    assert_eq!(commands, ["cargo audit"]);
    // A blank line inside a block does not end it.
    let (_, commands) = extract("      - run: |\n          npm ci\n\n          npm audit\n      - run: echo\n");
    assert_eq!(commands, ["npm ci", "npm audit", "echo"]);
    let (uses, _) = extract("    - uses:\n    - uses: ''\n");
    assert!(uses.is_empty());
    assert_eq!(scalar(" 'a b' # c"), "a b");
    assert_eq!((scalar(" a #c"), scalar(" a#c")), ("a".to_string(), "a#c".to_string()));
}

#[test]
fn the_config_must_name_a_token_and_an_owner() {
    let with = |config: Value| run(json!({"config": config}).to_string()).unwrap_err();
    assert_eq!(with(json!({"OWNER": "example-org"})), "Missing AUTH_HEADER config");
    assert_eq!(with(json!({"AUTH_HEADER": " ", "OWNER": "example-org"})), "Missing AUTH_HEADER config");
    for owner in ["", "example.org", "example_org", "a/b", &"a".repeat(40)] {
        assert_eq!(with(json!({"AUTH_HEADER": "Bearer x", "OWNER": owner})), "OWNER must be a GitHub account name", "{owner}");
    }
    assert!(host::http::requests().is_empty());
}
}
