// GitHub: the newest finished run of one workflow on one branch.
//
// Reads GitHub's "list workflow runs" endpoint for REPO / WORKFLOW / BRANCH,
// newest finished run only, and says what it found:
//
//   { "state": "failing" | "passing" | "other" | "none", "run": { … } }
//
// `failing` is a run that concluded failure, timed_out or startup_failure;
// `passing` is success; `other` is cancelled, skipped, neutral or anything
// newer GitHub adds; `none` is no finished run on that branch.
//
// With ALERT (the default) the result also rides out as an ops alert under
// `__ops_alert__` — one rolling alert per repo/workflow/branch: a failing run
// raises or bumps it, a passing run resolves it, `other` leaves it alone.
// Whether a person is TOLD is not this node's business: a compose node after
// it decides that (once per run, not once per poll).
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
    let branch_q = encoded_branch(branch).ok_or("BRANCH is not a usable branch name")?;
    let alert = cfg.alert.unwrap_or(true);
    let severity = severity_hint(cfg.severity.as_deref())?;

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
            "{API}/repos/{repo}/actions/workflows/{workflow}/runs?branch={branch_q}&status=completed&per_page=1"
        ),
        headers,
        body: Vec::new(),
        timeout_ms: Some(cfg.timeout_ms.unwrap_or(10_000).clamp(1_000, 30_000)),
    };
    let resp = talos::core::http::fetch(&req).map_err(|_| "api.github.com could not be reached".to_string())?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("api.github.com answered {}", resp.status));
    }
    let page: RunsPage = serde_json::from_slice(&resp.body)
        .map_err(|_| "api.github.com answered with something other than a list of runs".to_string())?;

    let dedup_key = format!("{SOURCE}|{repo}|{workflow}|{branch}");
    // `status=completed` is asked for; a reply is not trusted to honour it.
    let newest = page
        .workflow_runs
        .into_iter()
        .find(|r| r.status.as_deref() == Some("completed"));
    let Some(r) = newest else {
        logging::log(Level::Info, "github-workflow-run: no finished run");
        return serde_json::to_string(&serde_json::json!({
            "provider": PROVIDER, "repo": repo, "workflow": workflow, "branch": branch,
            "state": "none",
        }))
        .map_err(|e| e.to_string());
    };
    let conclusion = clean(r.conclusion.as_deref().unwrap_or("unknown"), 30);
    let state = state_of(&conclusion);
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

    #[test]
    fn a_failed_run_raises_the_rolling_alert() {
        host::http::respond(200, page("failure"));
        let v = read(config()).unwrap();
        assert_eq!(v["state"], "failing");
        assert_eq!(v["run"]["id"], 42);
        assert_eq!(v["run"]["url"], "https://github.com/example-owner/example-repo/actions/runs/42");
        let a = &v["__ops_alert__"]["alerts"][0];
        assert_eq!(a["dedup_key"], "github-actions|example-owner/example-repo|quality.yml|main");
        assert_eq!(a["severity_hint"], "high");
        assert_eq!(a["title"], "quality.yml failure on main (example-owner/example-repo 0123456)");
        assert!(a.get("status_event").is_none());
        let sent = host::http::requests();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].url,
            "https://api.github.com/repos/example-owner/example-repo/actions/workflows/quality.yml/runs?branch=main&status=completed&per_page=1"
        );
        assert!(sent[0].headers.iter().any(|(k, _)| k == "User-Agent"));
        assert!(!sent[0].headers.iter().any(|(k, _)| k == "Authorization"));
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
        c["BRANCH"] = json!("release/v1");
        let v = read(c).unwrap();
        assert_eq!(v["__ops_alert__"]["alerts"][0]["severity_hint"], "critical");
        let sent = &host::http::requests()[0];
        assert!(sent.url.contains("branch=release%2Fv1&"), "{}", sent.url);
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
