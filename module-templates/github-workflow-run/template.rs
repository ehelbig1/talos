// GitHub: the newest finished run of one workflow on one branch.
//
// Reads GitHub's "list workflow runs" endpoint for REPO / WORKFLOW — the
// workflow's newest PAGE runs on every branch — keeps BRANCH's runs that are
// not pull-request runs, picks the newest FINISHED one itself, and says what
// it found:
//
//   { "state": "failing" | "passing" | "other" | "none", "run": { … } }
//
// `failing` is a run that concluded failure, timed_out or startup_failure;
// `passing` is success; `other` is cancelled, skipped, neutral or anything
// newer GitHub adds; `none` is no finished run on that branch.
//
// `not_run` is a run GitHub marks failed although nothing in it failed: some
// of its jobs never started (GitHub had no runner for them and cancelled
// them), and the only job that failed is GATE_JOB — the job that fails
// because others did not succeed. Measured 2026-10-05 during a GitHub Actions
// incident: two runs on main concluded `failure` with every job that ran
// green, and each paged as a broken main. To tell the two apart the module
// reads the run's jobs, ONLY when the run concluded `failure`. A job that
// never started is `cancelled` with no steps; one cancelled after it started
// still counts as a failure. If the jobs cannot be read the run stays
// `failing` (`jobs_read: false`): a false alarm is better than a hidden one.
//
// With ALERT (the default) the result also rides out as an ops alert under
// `__ops_alert__` — one rolling alert per repo/workflow/branch: a failing run
// raises or bumps it, a passing run resolves it, `other` and `not_run`
// leave it alone.
// Whether a person is TOLD is not this node's business: a compose node after
// it decides that (once per run, not once per poll).
//
// It sends GitHub NO filter. Measured 2026-10-05 on a public repository:
// `branch=main` answered with a list stuck nine days in the past, its
// total_count changing between requests (103, 338, 568, 701), and
// `status=completed&per_page=1` likewise — while the unfiltered listing was
// current and stable (total_count 1866, three requests in a row). So the
// module reads the unfiltered listing and does the choosing: runs on BRANCH,
// not triggered by a pull request (a fork's branch can be named `main` too),
// finished, newest by creation time then run number. If no such run is among
// the newest PAGE, the state is `none` and nothing changes.
//
// Public repositories need no credential (GitHub allows 60 unauthenticated
// requests an hour per address). AUTH_HEADER takes a vault:// reference for a
// private repository or a higher limit; the module never holds the token.
//
// DLP: logs the state and the run number only. A failure names the host and
// the status, never a response body.

use serde::{Deserialize, Serialize};
use talos_sdk_macros::talos_module;

const PROVIDER: &str = "github";
const SOURCE: &str = "github-actions";
const API: &str = "https://api.github.com";
const MAX_TITLE_CHARS: usize = 120;
/// How many of the workflow's newest runs (all branches) are read. The
/// newest FINISHED run on BRANCH is chosen from these by this module.
const PAGE: usize = 30;
/// A run's jobs are read in one page; a listing longer than this is not
/// judged (the run stays `failing`).
const JOBS_PAGE: usize = 100;
/// How many never-started job names the output carries.
const MAX_NOT_RUN_NAMES: usize = 20;

#[derive(Deserialize, Default)]
struct Cfg {
    #[serde(rename = "REPO", default)]
    repo: Option<String>,
    #[serde(rename = "WORKFLOW", default)]
    workflow: Option<String>,
    #[serde(rename = "BRANCH", default)]
    branch: Option<String>,
    #[serde(rename = "AUTH_HEADER", default)]
    auth_header: Option<String>,
    #[serde(rename = "ALERT", default)]
    alert: Option<bool>,
    #[serde(rename = "SEVERITY", default)]
    severity: Option<String>,
    #[serde(rename = "TIMEOUT_MS", default)]
    timeout_ms: Option<u32>,
    #[serde(rename = "GATE_JOB", default)]
    gate_job: Option<String>,
}

#[derive(Deserialize)]
struct Incoming {
    #[serde(default)]
    config: Cfg,
}

#[derive(Deserialize)]
struct RunsPage {
    #[serde(default)]
    workflow_runs: Vec<ApiRun>,
}

#[derive(Deserialize)]
struct ApiRun {
    id: u64,
    #[serde(default)]
    run_number: Option<u64>,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    conclusion: Option<String>,
    #[serde(default)]
    head_sha: Option<String>,
    #[serde(default)]
    head_branch: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    display_title: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
}

#[derive(Deserialize)]
struct JobsPage {
    #[serde(default)]
    total_count: Option<u64>,
    #[serde(default)]
    jobs: Vec<ApiJob>,
}

#[derive(Deserialize)]
struct ApiJob {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    conclusion: Option<String>,
    /// Only whether there are any: a job GitHub never started has none.
    #[serde(default)]
    steps: Option<Vec<serde::de::IgnoredAny>>,
}

/// What a failed run's jobs say about it.
#[derive(Debug, PartialEq)]
enum Jobs {
    /// Something that ran failed (or nothing failed to start): the run failed.
    Failed,
    /// Nothing that ran failed except the gate, and these jobs never started.
    NotRun(Vec<String>),
}

/// Judge a failed run by its jobs. `None` when the listing is incomplete or
/// empty, so the caller keeps the run `failing`.
fn judge_jobs(page: &JobsPage, gate: Option<&str>) -> Option<Jobs> {
    if page.jobs.is_empty() || page.total_count.is_some_and(|t| t > page.jobs.len() as u64) {
        return None;
    }
    let started = |j: &ApiJob| j.steps.as_ref().is_some_and(|s| !s.is_empty());
    let mut never_started = Vec::new();
    for j in &page.jobs {
        let name = j.name.as_deref().unwrap_or("");
        match j.conclusion.as_deref() {
            Some("success" | "skipped" | "neutral") => {}
            Some("cancelled") if !started(j) => never_started.push(clean(name, 100)),
            // The gate fails BECAUSE others did not succeed; it says nothing
            // the other jobs do not.
            _ if gate.is_some_and(|g| g == name) => {}
            _ => return Some(Jobs::Failed),
        }
    }
    if never_started.is_empty() {
        return Some(Jobs::Failed);
    }
    never_started.truncate(MAX_NOT_RUN_NAMES);
    Some(Jobs::NotRun(never_started))
}

#[derive(Serialize)]
struct Run {
    id: u64,
    number: Option<u64>,
    event: String,
    conclusion: String,
    head_sha: String,
    branch: String,
    url: Option<String>,
    title: String,
    created_at: Option<String>,
    finished_at: Option<String>,
}

/// `owner/name`: letters, digits, `-`, `_`, `.`; never `.` or `..` alone.
fn usable_repo(s: &str) -> bool {
    let mut parts = s.split('/');
    let ok = |p: Option<&str>| {
        p.is_some_and(|p| {
            !p.is_empty()
                && p.len() <= 100
                && p != "."
                && p != ".."
                && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
    };
    ok(parts.next()) && ok(parts.next()) && parts.next().is_none()
}

/// A workflow file name (`quality.yml`) or its numeric id.
fn usable_workflow(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// A branch name, percent-encoded for the query string. Refuses what git
/// itself refuses in a ref name and anything outside printable ASCII.
fn encoded_branch(s: &str) -> Option<String> {
    if s.is_empty() || s.len() > 200 || s.contains("..") || s.starts_with('/') || s.ends_with('/') {
        return None;
    }
    let mut out = String::new();
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' => out.push(c),
            '/' => out.push_str("%2F"),
            _ => return None,
        }
    }
    Some(out)
}

fn clean(s: &str, limit: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(limit).collect()
}

fn state_of(conclusion: &str) -> &'static str {
    match conclusion {
        "failure" | "timed_out" | "startup_failure" => "failing",
        "success" => "passing",
        _ => "other",
    }
}

fn severity_hint(s: Option<&str>) -> Result<&'static str, String> {
    match s.unwrap_or("high") {
        "critical" => Ok("critical"),
        "high" => Ok("high"),
        "medium" => Ok("medium"),
        "low" => Ok("low"),
        other => Err(format!(
            "SEVERITY must be critical, high, medium or low, not '{}'",
            clean(other, 20)
        )),
    }
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};

    let incoming: Incoming = serde_json::from_str(&input)
        .map_err(|e| format!("could not read the node input: {e}"))?;
    let cfg = incoming.config;
    let repo = cfg
        .repo
        .as_deref()
        .map(str::trim)
        .filter(|r| usable_repo(r))
        .ok_or("Missing or unusable REPO config (expected owner/name)")?;
    let workflow = cfg
        .workflow
        .as_deref()
        .map(str::trim)
        .filter(|w| usable_workflow(w))
        .ok_or("Missing or unusable WORKFLOW config (expected a file name such as quality.yml, or a workflow id)")?;
    let branch = cfg.branch.as_deref().map(str::trim).unwrap_or("main");
    // BRANCH is no longer sent to GitHub, but it names the alert and a
    // downstream memory key, so it is held to the same rule.
    encoded_branch(branch).ok_or("BRANCH is not a usable branch name")?;
    let alert = cfg.alert.unwrap_or(true);
    let severity = severity_hint(cfg.severity.as_deref())?;
    let gate = match cfg.gate_job.as_deref().map(str::trim).filter(|g| !g.is_empty()) {
        None => None,
        Some(g) if g.chars().count() <= 100 && !g.chars().any(char::is_control) => Some(g),
        Some(_) => return Err("GATE_JOB must be a job name of at most 100 characters".to_string()),
    };
    let timeout_ms = Some(cfg.timeout_ms.unwrap_or(10_000).clamp(1_000, 30_000));

    let mut headers = vec![
        ("Accept".to_string(), "application/vnd.github+json".to_string()),
        ("X-GitHub-Api-Version".to_string(), "2022-11-28".to_string()),
        // GitHub refuses a request without a User-Agent.
        ("User-Agent".to_string(), "talos-github-workflow-run".to_string()),
    ];
    if let Some(auth) = cfg.auth_header.as_deref().filter(|a| !a.trim().is_empty()) {
        headers.push(("Authorization".to_string(), auth.to_string()));
    }
    let req = talos::core::http::Request {
        method: talos::core::http::Method::Get,
        url: format!(
            "{API}/repos/{repo}/actions/workflows/{workflow}/runs?per_page={PAGE}"
        ),
        headers: headers.clone(),
        body: Vec::new(),
        timeout_ms,
    };
    let resp = talos::core::http::fetch(&req).map_err(|_| "api.github.com could not be reached".to_string())?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("api.github.com answered {}", resp.status));
    }
    let page: RunsPage = serde_json::from_slice(&resp.body)
        .map_err(|_| "api.github.com answered with something other than a list of runs".to_string())?;

    let dedup_key = format!("{SOURCE}|{repo}|{workflow}|{branch}");
    // The newest finished run on the branch, chosen here: GitHub is asked to
    // filter nothing and its order is not relied on. RFC 3339 times in one
    // format compare correctly as strings.
    let newest = page
        .workflow_runs
        .into_iter()
        .filter(|r| r.status.as_deref() == Some("completed"))
        .filter(|r| r.head_branch.as_deref() == Some(branch))
        .filter(|r| !r.event.as_deref().unwrap_or("").starts_with("pull_request"))
        .max_by(|a, b| {
            (a.created_at.as_deref().unwrap_or(""), a.run_number.unwrap_or(0))
                .cmp(&(b.created_at.as_deref().unwrap_or(""), b.run_number.unwrap_or(0)))
        });
    let Some(r) = newest else {
        logging::log(Level::Info, "github-workflow-run: no finished run");
        return serde_json::to_string(&serde_json::json!({
            "provider": PROVIDER, "repo": repo, "workflow": workflow, "branch": branch,
            "state": "none",
        }))
        .map_err(|e| e.to_string());
    };
    let conclusion = clean(r.conclusion.as_deref().unwrap_or("unknown"), 30);
    let mut state = state_of(&conclusion);
    // A failed run is checked for jobs that never started (see the header).
    let mut jobs_read = None;
    let mut not_run = Vec::new();
    if conclusion == "failure" {
        let req = talos::core::http::Request {
            method: talos::core::http::Method::Get,
            url: format!(
                "{API}/repos/{repo}/actions/runs/{}/jobs?filter=latest&per_page={JOBS_PAGE}",
                r.id
            ),
            headers,
            body: Vec::new(),
            timeout_ms,
        };
        let verdict = talos::core::http::fetch(&req)
            .ok()
            .filter(|resp| (200..300).contains(&resp.status))
            .and_then(|resp| serde_json::from_slice::<JobsPage>(&resp.body).ok())
            .and_then(|page| judge_jobs(&page, gate));
        jobs_read = Some(verdict.is_some());
        match verdict {
            Some(Jobs::NotRun(names)) => {
                state = "not_run";
                not_run = names;
            }
            Some(Jobs::Failed) => {}
            None => logging::log(
                Level::Warn,
                "github-workflow-run: the failed run's jobs could not be read; it stays failing",
            ),
        }
    }
    let sha = clean(r.head_sha.as_deref().unwrap_or(""), 40);
    let short = sha.chars().take(7).collect::<String>();
    let url = r
        .html_url
        .as_deref()
        .filter(|u| u.starts_with("https://github.com/"))
        .map(|u| clean(u, 300));
    let event = clean(r.event.as_deref().unwrap_or("unknown"), 30);
    let run = Run {
        id: r.id,
        number: r.run_number,
        event: event.clone(),
        conclusion: conclusion.clone(),
        head_sha: sha,
        branch: clean(r.head_branch.as_deref().unwrap_or(branch), 200),
        url: url.clone(),
        title: clean(r.display_title.as_deref().unwrap_or(""), MAX_TITLE_CHARS),
        created_at: r.created_at.as_deref().map(|t| clean(t, 40)),
        finished_at: r.updated_at.as_deref().map(|t| clean(t, 40)),
    };

    let mut out = serde_json::json!({
        "provider": PROVIDER, "repo": repo, "workflow": workflow, "branch": branch,
        "state": state, "run": run,
    });
    if let Some(read) = jobs_read {
        out["jobs_read"] = serde_json::json!(read);
    }
    if !not_run.is_empty() {
        out["jobs_not_run"] = serde_json::json!(not_run);
    }
    if alert {
        let entry = match state {
            "failing" => Some(serde_json::json!({
                "source": SOURCE,
                "dedup_key": dedup_key,
                "external_id": r.id.to_string(),
                "title": format!("{workflow} {conclusion} on {branch} ({repo} {short})"),
                "resource": format!("{repo}@{branch}"),
                "severity_raw": conclusion,
                "severity_hint": severity,
                "raw": { "run_id": r.id, "run_number": r.run_number, "event": event, "url": url },
            })),
            "passing" => Some(serde_json::json!({
                "source": SOURCE,
                "dedup_key": dedup_key,
                "status_event": "resolved",
            })),
            _ => None,
        };
        if let Some(entry) = entry {
            out["__ops_alert__"] = serde_json::json!({ "alerts": [entry] });
        }
    }
    logging::log(
        Level::Info,
        &format!("github-workflow-run: run {} is {state}", r.run_number.unwrap_or(0)),
    );
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use talos_module_testkit::host;

    fn config() -> Value {
        json!({ "REPO": "example-owner/example-repo", "WORKFLOW": "quality.yml" })
    }
    fn read(config: Value) -> Result<Value, String> {
        run(json!({ "config": config }).to_string()).map(|s| serde_json::from_str(&s).unwrap())
    }
    /// One run, finished with `conclusion`, as GitHub lists it.
    fn page(conclusion: &str) -> String {
        json!({ "total_count": 1, "workflow_runs": [{
            "id": 42, "run_number": 7, "event": "push", "status": "completed",
            "conclusion": conclusion, "head_sha": "0123456789abcdef0123456789abcdef01234567",
            "head_branch": "main", "display_title": "made-up title",
            "html_url": "https://github.com/example-owner/example-repo/actions/runs/42",
            "created_at": "2026-01-02T03:04:05Z", "updated_at": "2026-01-02T03:20:05Z",
        }]})
        .to_string()
    }

    /// A job as GitHub lists it: `steps` steps run (0 = never started).
    fn job(name: &str, conclusion: &str, steps: usize) -> Value {
        let steps: Vec<Value> = (0..steps).map(|i| json!({ "name": format!("step {i}"), "conclusion": conclusion })).collect();
        json!({ "name": name, "status": "completed", "conclusion": conclusion, "steps": steps })
    }
    /// Answer the runs listing with `runs` and the jobs listing with `jobs`.
    fn respond_runs_and_jobs(runs: String, jobs: Value) {
        host::http::respond_with(move |req| {
            let body = if req.url.contains("/jobs") { jobs.to_string() } else { runs.clone() };
            Ok(host::http::response(200, body))
        });
    }
    fn jobs(list: Vec<Value>) -> Value {
        json!({ "total_count": list.len(), "jobs": list })
    }
    fn gated(gate: &str) -> Value {
        let mut c = config();
        c["GATE_JOB"] = json!(gate);
        c
    }

    #[test]
    fn a_failed_run_raises_the_rolling_alert() {
        respond_runs_and_jobs(page("failure"), jobs(vec![job("build", "success", 4), job("test", "failure", 6)]));
        let v = read(config()).unwrap();
        assert_eq!(v["state"], "failing");
        assert_eq!(v["jobs_read"], true);
        assert_eq!(v["run"]["id"], 42);
        assert_eq!(v["run"]["url"], "https://github.com/example-owner/example-repo/actions/runs/42");
        let a = &v["__ops_alert__"]["alerts"][0];
        assert_eq!(a["dedup_key"], "github-actions|example-owner/example-repo|quality.yml|main");
        assert_eq!(a["severity_hint"], "high");
        assert_eq!(a["title"], "quality.yml failure on main (example-owner/example-repo 0123456)");
        assert!(a.get("status_event").is_none());
        let sent = host::http::requests();
        assert_eq!(sent.len(), 2);
        assert_eq!(
            sent[0].url,
            "https://api.github.com/repos/example-owner/example-repo/actions/workflows/quality.yml/runs?per_page=30"
        );
        assert_eq!(
            sent[1].url,
            "https://api.github.com/repos/example-owner/example-repo/actions/runs/42/jobs?filter=latest&per_page=100"
        );
        for s in &sent {
            assert!(s.headers.iter().any(|(k, _)| k == "User-Agent"));
            assert!(!s.headers.iter().any(|(k, _)| k == "Authorization"));
        }
    }

    /// The 2026-10-05 shape: two jobs never got a runner, the gate ran and
    /// failed because of them, everything that ran passed.
    #[test]
    fn a_failure_from_jobs_that_never_started_is_not_run() {
        let listing = jobs(vec![
            job("changes", "cancelled", 0),
            job("supply-chain", "cancelled", 0),
            job("lint", "success", 8),
            job("gate", "failure", 3),
            job("tests", "skipped", 0),
        ]);
        respond_runs_and_jobs(page("failure"), listing.clone());
        let v = read(gated("gate")).unwrap();
        assert_eq!(v["state"], "not_run");
        assert_eq!(v["run"]["conclusion"], "failure");
        assert_eq!(v["jobs_not_run"], json!(["changes", "supply-chain"]));
        assert!(v.get("__ops_alert__").is_none(), "not_run leaves the alert alone");
        // Without naming the gate, its failure is a failure.
        respond_runs_and_jobs(page("failure"), listing);
        let v = read(config()).unwrap();
        assert_eq!(v["state"], "failing");
        assert!(v.get("jobs_not_run").is_none());
    }

    /// The other shape: everything ran and passed; only the gate never got a
    /// runner. No gate name is needed — nothing that ran failed.
    #[test]
    fn a_gate_that_never_started_over_green_jobs_is_not_run() {
        respond_runs_and_jobs(
            page("failure"),
            jobs(vec![job("lint", "success", 8), job("tests", "success", 11), job("gate", "cancelled", 0)]),
        );
        let v = read(config()).unwrap();
        assert_eq!(v["state"], "not_run");
        assert_eq!(v["jobs_not_run"], json!(["gate"]));
    }

    #[test]
    fn a_real_failure_beside_jobs_that_never_started_is_failing() {
        for failed in [job("tests", "failure", 11), job("tests", "timed_out", 11), job("tests", "cancelled", 5)] {
            respond_runs_and_jobs(
                page("failure"),
                jobs(vec![job("changes", "cancelled", 0), failed.clone(), job("gate", "failure", 3)]),
            );
            let v = read(gated("gate")).unwrap();
            assert_eq!(v["state"], "failing", "{failed}");
            assert!(v["__ops_alert__"]["alerts"][0]["title"].is_string());
        }
    }

    /// A jobs listing that cannot be trusted keeps the run failing.
    #[test]
    fn unreadable_jobs_keep_the_run_failing() {
        let never_started = jobs(vec![job("changes", "cancelled", 0), job("gate", "failure", 3)]);
        let mut incomplete = never_started.clone();
        incomplete["total_count"] = json!(40);
        for (status, body) in [
            (200, incomplete.to_string()),
            (200, json!({ "total_count": 0, "jobs": [] }).to_string()),
            (200, "not json".to_string()),
            (403, never_started.to_string()),
        ] {
            let runs = page("failure");
            host::http::respond_with(move |req| {
                Ok(if req.url.contains("/jobs") { host::http::response(status, body.clone()) } else { host::http::response(200, runs.clone()) })
            });
            let v = read(gated("gate")).unwrap();
            assert_eq!((v["state"].clone(), v["jobs_read"].clone()), (json!("failing"), json!(false)), "{status}");
            assert!(v["__ops_alert__"]["alerts"][0]["title"].is_string());
        }
        host::http::respond_with(|req| {
            if req.url.contains("/jobs") {
                Err(wit_http_error())
            } else {
                Ok(host::http::response(200, page("failure")))
            }
        });
        assert_eq!(read(gated("gate")).unwrap()["state"], "failing");
    }

    fn wit_http_error() -> talos::core::http::Error {
        talos::core::http::Error::Networkerror
    }

    #[test]
    fn only_a_failed_run_has_its_jobs_read() {
        for c in ["success", "cancelled", "timed_out", "startup_failure"] {
            respond_runs_and_jobs(page(c), jobs(vec![job("gate", "cancelled", 0)]));
            let v = read(gated("gate")).unwrap();
            assert!(v.get("jobs_read").is_none(), "{c}");
            assert!(!host::http::requests().iter().any(|r| r.url.contains("/jobs")), "{c}");
        }
    }

    #[test]
    fn timed_out_and_startup_failure_also_fail() {
        for c in ["timed_out", "startup_failure"] {
            host::http::respond(200, page(c));
            assert_eq!(read(config()).unwrap()["state"], "failing", "{c}");
        }
    }

    #[test]
    fn a_passing_run_resolves_the_same_alert() {
        host::http::respond(200, page("success"));
        let v = read(config()).unwrap();
        assert_eq!(v["state"], "passing");
        let a = &v["__ops_alert__"]["alerts"][0];
        assert_eq!(a["status_event"], "resolved");
        assert_eq!(a["dedup_key"], "github-actions|example-owner/example-repo|quality.yml|main");
    }

    #[test]
    fn a_cancelled_run_leaves_the_alert_alone() {
        host::http::respond(200, page("cancelled"));
        let v = read(config()).unwrap();
        assert_eq!(v["state"], "other");
        assert!(v.get("__ops_alert__").is_none());
    }

    #[test]
    fn no_finished_run_is_none_not_passing() {
        host::http::respond(200, json!({ "total_count": 0, "workflow_runs": [] }).to_string());
        let v = read(config()).unwrap();
        assert_eq!(v["state"], "none");
        assert!(v.get("__ops_alert__").is_none());
    }

    /// GitHub's order is not trusted: an old failure listed first, the newest
    /// run still going, and the newest FINISHED run (a pass) in the middle.
    #[test]
    fn the_newest_finished_run_is_chosen_whatever_the_order() {
        let run = |id: u64, number: u64, created: &str, status: &str, conclusion: Option<&str>| {
            json!({ "id": id, "run_number": number, "event": "push", "status": status,
                    "conclusion": conclusion, "head_branch": "main",
                    "head_sha": "0123456789abcdef0123456789abcdef01234567",
                    "html_url": format!("https://github.com/example-owner/example-repo/actions/runs/{id}"),
                    "created_at": created, "updated_at": created })
        };
        let p = json!({ "total_count": 4, "workflow_runs": [
            run(1, 10, "2026-01-01T00:00:00Z", "completed", Some("failure")),
            run(4, 40, "2026-01-04T00:00:00Z", "in_progress", None),
            run(3, 30, "2026-01-03T00:00:00Z", "completed", Some("success")),
            run(2, 20, "2026-01-02T00:00:00Z", "completed", Some("failure")),
        ]});
        host::http::respond(200, p.to_string());
        let v = read(config()).unwrap();
        assert_eq!((v["state"].clone(), v["run"]["id"].clone()), (json!("passing"), json!(3)));
    }

    /// Only BRANCH's own runs count: a newer failure on another branch, and a
    /// pull-request run whose head branch is also called `main` (a fork's),
    /// are left out.
    #[test]
    fn only_the_branchs_own_runs_count() {
        let run = |id: u64, branch: &str, event: &str, conclusion: &str, created: &str| {
            json!({ "id": id, "run_number": id, "event": event, "status": "completed",
                    "conclusion": conclusion, "head_branch": branch,
                    "head_sha": "0123456789abcdef0123456789abcdef01234567",
                    "created_at": created, "updated_at": created })
        };
        let p = json!({ "workflow_runs": [
            run(5, "feature-x", "pull_request", "failure", "2026-01-05T00:00:00Z"),
            run(4, "main", "pull_request", "failure", "2026-01-04T00:00:00Z"),
            run(3, "main", "push", "success", "2026-01-03T00:00:00Z"),
            run(2, "main", "schedule", "failure", "2026-01-02T00:00:00Z"),
        ]});
        host::http::respond(200, p.to_string());
        let v = read(config()).unwrap();
        assert_eq!((v["state"].clone(), v["run"]["id"].clone()), (json!("passing"), json!(3)));
        let mut c = config();
        c["BRANCH"] = json!("feature-x");
        host::http::respond(200, p.to_string());
        assert_eq!(read(c).unwrap()["state"], "none");
    }

    #[test]
    fn a_run_still_going_is_not_read_as_finished() {
        let mut p: Value = serde_json::from_str(&page("success")).unwrap();
        p["workflow_runs"][0]["status"] = json!("in_progress");
        host::http::respond(200, p.to_string());
        assert_eq!(read(config()).unwrap()["state"], "none");
    }

    #[test]
    fn alert_false_reports_without_an_envelope() {
        host::http::respond(200, page("failure"));
        let mut c = config();
        c["ALERT"] = json!(false);
        let v = read(c).unwrap();
        assert_eq!(v["state"], "failing");
        assert!(v.get("__ops_alert__").is_none());
    }

    #[test]
    fn severity_and_auth_come_from_config() {
        host::http::respond(200, page("failure"));
        let mut c = config();
        c["SEVERITY"] = json!("critical");
        c["AUTH_HEADER"] = json!("Bearer vault://github/token");
        let v = read(c).unwrap();
        assert_eq!(v["__ops_alert__"]["alerts"][0]["severity_hint"], "critical");
        let sent = &host::http::requests()[0];
        assert!(!sent.url.contains("branch="), "{}", sent.url);
        assert!(sent.headers.iter().any(|(k, v)| k == "Authorization" && v == "Bearer vault://github/token"));
    }

    #[test]
    fn unusable_config_is_refused_before_any_request() {
        for (key, value) in [
            ("REPO", json!("example-owner")),
            ("REPO", json!("example-owner/../other")),
            ("REPO", json!("example-owner/repo?x=1")),
            ("WORKFLOW", json!("../../user")),
            ("BRANCH", json!("main&per_page=100")),
            ("BRANCH", json!("a..b")),
            ("SEVERITY", json!("urgent")),
            ("GATE_JOB", json!("x".repeat(101))),
            ("GATE_JOB", json!("gate\nother")),
        ] {
            let mut c = config();
            c[key] = value.clone();
            assert!(read(c).is_err(), "{key}={value}");
        }
        assert!(read(json!({ "WORKFLOW": "quality.yml" })).is_err());
        assert!(host::http::requests().is_empty());
    }

    #[test]
    fn an_error_answer_fails_the_node_and_names_only_the_status() {
        host::http::respond(403, r#"{"message":"API rate limit exceeded for 192.0.2.1."}"#);
        let e = read(config()).unwrap_err();
        assert_eq!(e, "api.github.com answered 403");
    }

    #[test]
    fn a_link_off_github_is_dropped() {
        let mut p: Value = serde_json::from_str(&page("failure")).unwrap();
        p["workflow_runs"][0]["html_url"] = json!("https://elsewhere.example.test/x");
        host::http::respond(200, p.to_string());
        let v = read(config()).unwrap();
        assert!(v["run"]["url"].is_null());
    }
}
