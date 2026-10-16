// gcp-artifact-registry-evidence: reads, from ONE Google Cloud project, the
// facts the Artifact Registry check needs: whether the Container Scanning API
// is on, each Artifact Registry repository's format, mode, scanning setting,
// cleanup policies and tag setting, and, image by image, how old the CRITICAL
// vulnerability findings the registry's scanning recorded are. It reads;
// every request is a GET, and the module is granted no other verb, so it
// cannot change the project whatever it is given.
//
// It judges nothing. It hands on evidence in the neutral shape
// `artifact-registry-check` reads (`kind: "artifact_registry_evidence"`), and
// a part it could not read is left out and named in `unread`, never handed on
// as empty: an empty list of repositories means the project has none.
//
// Requests (all GET):
//   serviceusage.googleapis.com        the Container Scanning API's state on the project
//   artifactregistry.googleapis.com    the project's locations, then the repositories of each
//   containeranalysis.googleapis.com   the project's vulnerability findings, page by page
//
// Of the findings, it hands on, for each image (the finding's resource), the
// age in whole days of each one that is OPEN and CRITICAL, and how many may
// be CRITICAL but do not say what that needs: their severity, when they were
// recorded, or a VEX status it knows. Which findings those are follows the
// rules the check used to apply to each finding itself: the effective
// severity decides, the provider's when it is not said; a VEX status of fixed
// or not affected closes a finding. A finding that says neither severity is
// rated by its CVSS v3 base score when it gives one, on the scale FIRST's
// CVSS v3.1 specification sets (section 5, "Qualitative Severity Rating
// Scale": 9.0 to 10.0 is Critical): at 9.0 or more it is CRITICAL and its age
// is handed on apart, in `scored_ages`, so the check can say so; below, it is
// not CRITICAL. A CVSS v2 score rates nothing (that scale has no Critical),
// and a finding with neither a severity nor a v3 score is counted as before.
// Such an unscored finding, when it is open and its date can be read, also
// has its age handed on, in `unscored_ages`, or in `unscored_fixable_ages`
// when the finding says a fix is available; one whose date or VEX status
// cannot be read is counted in `unscored_unclear`; one closed by its VEX
// status has no age. How old is too old is the check's.
// Which vulnerabilities they are (their ids) is not handed on: what it hands
// on grows with the images, not with the findings, so a project with many
// findings still fits in what a node is given. An age is reckoned from the
// answer's own `Date`, never from a clock of this module's.
//
// What it hands on is bounded, and more than a bound is unread, never cut:
// at most 40 pages of 1,000 findings read, 500 images handed on, and 2,000
// ages for any one image (and each image's name at most 300 characters).
// At those bounds the evidence could be 807,352 bytes, so it is bounded by
// its size too: at most 300,000 bytes as written, a third of the 1,000,000
// the platform takes as a node's input (WASM_MAX_INPUT_BYTES). A workflow's
// first node is given the run's trigger three times over (spread as its
// top-level keys, as `input` and as `__trigger_input__`), and a shadow
// workflow's trigger is this evidence: 3 × 300,000 is 900,000, and the rest
// is room for the node's config and the engine's own keys. (After a reader,
// the check is given it about twice.) A part that would take the evidence
// over that is left out and named in `unread`, saying how large it is, and
// the check reports the rules it needs not assessed. The parts are counted in
// the order they are read; the tests build the worst case and measure it.
//
// The token is a short-lived one for a read-only service account, named in
// the node's config as a vault reference; this module never sees it. The
// module is granted no token path until the owner names the account. It
// needs: serviceusage.services.get, artifactregistry.locations.list,
// artifactregistry.repositories.list and containeranalysis.occurrences.list.

use serde::Deserialize;
use std::collections::BTreeMap;
use talos_sdk_macros::talos_module;

const SERVICE_USAGE: &str = "https://serviceusage.googleapis.com/v1";
const REGISTRY: &str = "https://artifactregistry.googleapis.com/v1";
const ANALYSIS: &str = "https://containeranalysis.googleapis.com/v1";
/// More than these and the part is not read: a reader that cut them short would hand on half.
const MAX_LOCATIONS: usize = 80;
const MAX_REPOS: usize = 200;
const MAX_FINDING_PAGES: usize = 40;
/// Images with a finding that may be CRITICAL, and the ages handed on for one image.
const MAX_IMAGES: usize = 500;
const MAX_AGES_PER_IMAGE: usize = 2_000;
/// The longest image name handed on whole: an Artifact Registry image's address is far shorter.
const MAX_RESOURCE: usize = 300;
const SEVERITIES: [&str; 5] = ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
/// The lowest CVSS v3 base score FIRST's rating scale calls Critical.
const CRITICAL_SCORE: f64 = 9.0;
/// A VEX status that closes a finding, and the ones that leave it open ("" is none given).
const CLOSED: [&str; 2] = ["FIXED", "NOT_AFFECTED"];
const OPEN: [&str; 4] = ["", "STATE_UNSPECIFIED", "AFFECTED", "UNDER_INVESTIGATION"];
/// The most evidence this reader hands on, in bytes as written: a third of the platform's
/// 1,000,000-byte node input, since a workflow's first node is given its trigger three times
/// (3 × 300,000 = 900,000, and 100,000 left for the node's config and the engine's keys).
const MAX_EVIDENCE_BYTES: usize = 300_000;
/// What the evidence holds besides its parts (kind, project, as_of, counts, unread, errors), set
/// aside before any part is counted. The tests measure the most it can be.
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
    /// "Bearer " and a vault reference to the reader account's access token.
    #[serde(rename = "AUTH_HEADER")]
    auth_header: Option<String>,
    /// The project to read, by id.
    #[serde(rename = "PROJECT")]
    project: Option<String>,
}

#[derive(Deserialize)]
struct Service {
    #[serde(default)]
    state: String,
}
#[derive(Deserialize)]
struct Locations {
    #[serde(default)]
    locations: Vec<Location>,
    #[serde(default, rename = "nextPageToken")]
    next: String,
}
#[derive(Deserialize)]
struct Location {
    #[serde(default, rename = "locationId")]
    id: String,
}
#[derive(Deserialize)]
struct Repositories {
    #[serde(default)]
    repositories: Vec<RepoIn>,
    #[serde(default, rename = "nextPageToken")]
    next: String,
}
/// One cleanup policy: only what it does is read, DELETE or KEEP.
#[derive(Deserialize)]
struct PolicyIn {
    #[serde(default)]
    action: String,
}
#[derive(Deserialize)]
struct RepoIn {
    #[serde(default)]
    name: String,
    format: Option<String>,
    mode: Option<String>,
    #[serde(default, rename = "cleanupPolicies")]
    cleanup: BTreeMap<String, PolicyIn>,
    #[serde(default, rename = "cleanupPolicyDryRun")]
    dry_run: bool,
    #[serde(rename = "dockerConfig")]
    docker: Option<DockerConfig>,
    #[serde(rename = "vulnerabilityScanningConfig")]
    scanning: Option<ScanningConfig>,
}
#[derive(Deserialize)]
struct DockerConfig {
    #[serde(default, rename = "immutableTags")]
    immutable: bool,
}
#[derive(Deserialize)]
struct ScanningConfig {
    #[serde(rename = "enablementConfig")]
    config: Option<String>,
}
#[derive(Deserialize)]
struct Occurrences {
    #[serde(default)]
    occurrences: Vec<Occurrence>,
    #[serde(default, rename = "nextPageToken")]
    next: String,
    #[serde(default)]
    unreachable: Vec<String>,
}
#[derive(Deserialize)]
struct Occurrence {
    #[serde(default, rename = "resourceUri")]
    resource: String,
    #[serde(default, rename = "createTime")]
    created: String,
    vulnerability: Option<VulnIn>,
}
#[derive(Deserialize)]
struct VulnIn {
    #[serde(default)]
    severity: String,
    #[serde(default, rename = "effectiveSeverity")]
    effective: String,
    #[serde(rename = "vexAssessment")]
    vex: Option<Vex>,
    #[serde(default, rename = "cvssScore")]
    cvss_score: Option<f64>,
    /// Which CVSS version `cvssScore` is ("CVSS_VERSION_2" or "CVSS_VERSION_3").
    #[serde(default, rename = "cvssVersion")]
    cvss_version: String,
    #[serde(default)]
    cvssv3: Option<Cvss>,
    #[serde(default, rename = "fixAvailable")]
    fix_available: bool,
}
#[derive(Deserialize)]
struct Cvss {
    #[serde(default, rename = "baseScore")]
    base_score: Option<f64>,
}
/// A finding's CVSS v3 base score, when it gives one this reader can rate by: the v3 score itself,
/// else `cvssScore` when it says it is version 3. A score outside 0 to 10 is not one.
fn v3_score(v: &VulnIn) -> Option<f64> {
    let score = v.cvssv3.as_ref().and_then(|c| c.base_score).or(v.cvss_score.filter(|_| v.cvss_version == "CVSS_VERSION_3"))?;
    (0.0..=10.0).contains(&score).then_some(score)
}
#[derive(Deserialize)]
struct Vex {
    #[serde(default)]
    state: String,
}

/// A project id as Google writes one: it goes into request paths.
fn project_ok(s: &str) -> bool {
    (6..=30).contains(&s.len()) && s.as_bytes()[0].is_ascii_lowercase() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
/// A location id as Google writes one: it goes into request paths.
fn location_ok(s: &str) -> bool {
    (2..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn shown(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}
fn pct(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}
/// The last part of a resource name: the repository's.
fn last(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or("")
}

/// One GET: the body and the answer's `Date`. The status and the kind of failure are kept; no body of an error is.
fn get(auth: &str, url: &str) -> Result<(Vec<u8>, Option<String>), String> {
    use talos::core::http::{self, Method, Request};
    let req = Request { method: Method::Get, url: url.to_string(), headers: vec![("Authorization".to_string(), auth.to_string()), ("Accept".to_string(), "application/json".to_string())], body: Vec::new(), timeout_ms: Some(20_000) };
    let resp = http::fetch(&req).map_err(|e| format!("could not be reached ({e:?})"))?;
    match resp.status {
        200..=299 => Ok((resp.body, resp.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("date")).map(|(_, v)| v.clone()))),
        other => Err(format!("answered HTTP {other}")),
    }
}
/// An image's address as a finding names it: a URI's characters only, and short enough to hand on whole.
fn resource_ok(s: &str) -> bool {
    (1..=MAX_RESOURCE).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&b))
}
/// When a finding was recorded, in seconds since 1970, as Google writes a time
/// (`2026-08-01T00:00:00Z`, with a fraction of a second or none). Anything else is not read.
fn recorded(stamp: &str) -> Option<i64> {
    let b = stamp.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[b.len() - 1] != b'Z' {
        return None;
    }
    let fraction = &b[19..b.len() - 1];
    if !fraction.is_empty() && !(fraction[0] == b'.' && (2..=10).contains(&fraction.len()) && fraction[1..].iter().all(u8::is_ascii_digit)) {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<u32> { b[from..to].iter().all(u8::is_ascii_digit).then(|| b[from..to].iter().fold(0, |n, d| n * 10 + u32::from(d - b'0'))) };
    let year = num(0, 4).filter(|y| *y >= 1)?;
    let day = chrono::NaiveDate::from_ymd_opt(year as i32, num(5, 7)?, num(8, 10)?)?;
    Some(day.and_hms_opt(num(11, 13)?, num(14, 16)?, num(17, 19)?)?.and_utc().timestamp())
}

fn parsed<T: serde::de::DeserializeOwned>(body: &[u8], what: &str) -> Result<T, String> {
    serde_json::from_slice(body).map_err(|_| format!("{what} answered with something that could not be read"))
}

/// The Container Scanning API's state, in the shape the check reads.
fn read_scanning_api(auth: &str, project: &str) -> Result<serde_json::Value, String> {
    let what = "the Container Scanning API's state";
    let (body, _) = get(auth, &format!("{SERVICE_USAGE}/projects/{project}/services/containerscanning.googleapis.com")).map_err(|e| format!("{what} {e}"))?;
    let service: Service = parsed(&body, what)?;
    Ok(serde_json::json!({ "state": shown(&service.state, 40) }))
}

/// Every repository of the project, in every location, in the shape the check reads.
fn read_repositories(auth: &str, project: &str) -> Result<Vec<serde_json::Value>, String> {
    let mut locations: Vec<String> = Vec::new();
    let mut token = String::new();
    for page in 0..=2 {
        // Half a listing is not the listing.
        if page == 2 {
            return Err("the location listing did not end within two pages".to_string());
        }
        let what = "the location listing";
        let query = if token.is_empty() { String::new() } else { format!("&pageToken={}", pct(&token)) };
        let (body, _) = get(auth, &format!("{REGISTRY}/projects/{project}/locations?pageSize=100{query}")).map_err(|e| format!("{what} {e}"))?;
        let listed: Locations = parsed(&body, what)?;
        locations.extend(listed.locations.into_iter().map(|l| l.id));
        if listed.next.is_empty() {
            break;
        }
        token = listed.next;
    }
    if locations.len() > MAX_LOCATIONS {
        return Err(format!("the project lists more than {MAX_LOCATIONS} locations; this reader would be cutting them short"));
    }
    let mut repos: Vec<serde_json::Value> = Vec::new();
    for location in &locations {
        if !location_ok(location) {
            return Err("a location has an id that could not be used".to_string());
        }
        let what = "a repository listing";
        let (body, _) = get(auth, &format!("{REGISTRY}/projects/{project}/locations/{location}/repositories?pageSize=1000")).map_err(|e| format!("{what} {e}"))?;
        let listed: Repositories = parsed(&body, what)?;
        if !listed.next.is_empty() || repos.len() + listed.repositories.len() > MAX_REPOS {
            return Err(format!("the project has more than {MAX_REPOS} repositories; this reader would be cutting them short"));
        }
        for r in listed.repositories {
            // What the API leaves out is its default: an unset enum, no policies, no dry run, mutable tags.
            let format = r.format.filter(|f| !f.is_empty()).unwrap_or_else(|| "FORMAT_UNSPECIFIED".to_string());
            let mut row = serde_json::json!({
                "location": shown(location, 40),
                "name": shown(last(&r.name), 100),
                "format": shown(&format, 30),
                "mode": shown(&r.mode.filter(|m| !m.is_empty()).unwrap_or_else(|| "MODE_UNSPECIFIED".to_string()), 40),
                "scanning_config": shown(&r.scanning.and_then(|s| s.config).filter(|c| !c.is_empty()).unwrap_or_else(|| "ENABLEMENT_CONFIG_UNSPECIFIED".to_string()), 40),
                "cleanup_policies": r.cleanup.len(),
                // How many delete, and how many say an action that is neither: a keep policy alone removes nothing.
                "cleanup_deleting": r.cleanup.values().filter(|p| p.action == "DELETE").count(),
                "cleanup_unknown": r.cleanup.values().filter(|p| p.action != "DELETE" && p.action != "KEEP").count(),
                "cleanup_dry_run": r.dry_run,
            });
            // Only a Docker repository has tags to hold still.
            if format == "DOCKER" {
                row["immutable_tags"] = r.docker.is_some_and(|d| d.immutable).into();
            }
            repos.push(row);
        }
    }
    Ok(repos)
}

/// Of one image, what is handed on: the ages of its open CRITICAL findings, and how many may be CRITICAL but do not say.
#[derive(Default)]
struct Image {
    ages: Vec<i64>,
    /// The ages of the open findings that are CRITICAL by their CVSS v3 score alone, saying no severity.
    scored_ages: Vec<i64>,
    severity_unsaid: u64,
    /// The ages of the open, dated findings that say no severity and have no v3 score: no fix said, and a fix said.
    unscored_ages: Vec<i64>,
    unscored_fixable_ages: Vec<i64>,
    /// Findings that say no severity whose date or VEX status cannot be read, so they cannot be aged.
    unscored_unclear: u64,
    undated: u64,
    vex_unknown: u64,
}

/// Image by image, the findings the check judges; how many findings were read in all; and when.
fn read_findings(auth: &str, project: &str) -> Result<(Vec<serde_json::Value>, usize, String), String> {
    let what = "the vulnerability findings";
    let mut images: BTreeMap<String, Image> = BTreeMap::new();
    let mut read = 0usize;
    let (mut as_of, mut now) = (String::new(), 0i64);
    let mut token = String::new();
    for page in 0..=MAX_FINDING_PAGES {
        if page == MAX_FINDING_PAGES {
            return Err(format!("the project has more than {} vulnerability findings; this reader would be cutting them short", MAX_FINDING_PAGES * 1000));
        }
        let query = if token.is_empty() { String::new() } else { format!("&pageToken={}", pct(&token)) };
        let (body, date) = get(auth, &format!("{ANALYSIS}/projects/{project}/occurrences?filter={}&pageSize=1000{query}", pct("kind=\"VULNERABILITY\""))).map_err(|e| format!("{what} {e}"))?;
        if page == 0 {
            // The first answer says when the findings were read: every age is reckoned to it.
            let when = date.and_then(|d| chrono::DateTime::parse_from_rfc2822(d.trim()).ok()).ok_or("the vulnerability findings answered without saying when (no Date)")?;
            as_of = when.with_timezone(&chrono::Utc).format("%Y-%m-%dT%H:%M:%SZ").to_string();
            now = when.timestamp();
        }
        let listed: Occurrences = parsed(&body, what)?;
        if !listed.unreachable.is_empty() {
            return Err(format!("the vulnerability findings could not reach {} region(s), so they are not all of them", listed.unreachable.len()));
        }
        read += listed.occurrences.len();
        for o in listed.occurrences {
            let Some(v) = o.vulnerability else { continue };
            // The effective severity decides; the provider's when it is not said. Neither said is counted, for the check to say so.
            let said = [v.effective.as_str(), v.severity.as_str()].into_iter().find(|s| SEVERITIES.contains(s)).unwrap_or("");
            // Neither said: a CVSS v3 score rates it, CRITICAL from 9.0; without one it stays unsaid.
            let scored = if said.is_empty() { v3_score(&v) } else { None };
            let by_score = scored.is_some_and(|score| score >= CRITICAL_SCORE);
            let severity = match scored {
                Some(_) if by_score => "CRITICAL",
                Some(_) => continue,
                None => said,
            };
            if severity != "CRITICAL" && !severity.is_empty() {
                continue;
            }
            let vex = v.vex.map(|x| x.state).unwrap_or_default();
            let at = recorded(&o.created);
            // A CRITICAL finding closed by its VEX status, with a time that can be read, is not handed on.
            if !severity.is_empty() && at.is_some() && CLOSED.contains(&vex.as_str()) {
                continue;
            }
            if !resource_ok(&o.resource) {
                return Err("a finding that may be CRITICAL names its image in a way this reader cannot hand on whole".to_string());
            }
            let image = images.entry(o.resource).or_default();
            match at {
                _ if severity.is_empty() => {
                    image.severity_unsaid += 1;
                    match at {
                        // Closed by its VEX status: it has no age to hand on.
                        Some(_) if CLOSED.contains(&vex.as_str()) => {}
                        Some(at) if OPEN.contains(&vex.as_str()) => {
                            let age = (now - at).div_euclid(86_400);
                            if v.fix_available { image.unscored_fixable_ages.push(age) } else { image.unscored_ages.push(age) }
                        }
                        _ => image.unscored_unclear += 1,
                    }
                }
                None => image.undated += 1,
                Some(_) if !OPEN.contains(&vex.as_str()) => image.vex_unknown += 1,
                // Whole days, from when it was recorded to when the findings were read.
                Some(at) => {
                    let age = (now - at).div_euclid(86_400);
                    if by_score { image.scored_ages.push(age) } else { image.ages.push(age) }
                }
            }
        }
        if listed.next.is_empty() {
            break;
        }
        token = listed.next;
    }
    if images.len() > MAX_IMAGES {
        return Err(format!("more than {MAX_IMAGES} images have findings that may be CRITICAL; this reader would be cutting them short"));
    }
    if images.values().any(|i| [&i.ages, &i.scored_ages, &i.unscored_ages, &i.unscored_fixable_ages].iter().any(|ages| ages.len() > MAX_AGES_PER_IMAGE)) {
        return Err(format!("an image has more than {MAX_AGES_PER_IMAGE} open CRITICAL findings; this reader would be cutting them short"));
    }
    let handed_on = images
        .into_iter()
        .map(|(resource, mut i)| {
            i.ages.sort_unstable();
            i.scored_ages.sort_unstable();
            i.unscored_ages.sort_unstable();
            i.unscored_fixable_ages.sort_unstable();
            serde_json::json!({ "resource": resource, "open": i.ages.len(), "ages": i.ages, "scored_ages": i.scored_ages, "severity_unsaid": i.severity_unsaid, "unscored_ages": i.unscored_ages, "unscored_fixable_ages": i.unscored_fixable_ages, "unscored_unclear": i.unscored_unclear, "undated": i.undated, "vex_unknown": i.vex_unknown })
        })
        .collect();
    Ok((handed_on, read, as_of))
}

/// The evidence, from what each part's read gave. A part that could not be read, or that would
/// take the evidence over `MAX_EVIDENCE_BYTES`, is left out and named in `unread`.
fn evidence(project: &str, api: Result<serde_json::Value, String>, repos: Result<Vec<serde_json::Value>, String>, findings: Result<(Vec<serde_json::Value>, usize, String), String>) -> serde_json::Value {
    let mut out = serde_json::json!({ "kind": "artifact_registry_evidence", "project": project, "as_of": "" });
    let mut unread: Vec<&str> = Vec::new();
    let mut errors = serde_json::Map::new();
    let mut budget = Budget::new();
    // A part that was not read is left out, never written as empty; one too large to hand on is not cut either.
    match api.and_then(|api| budget.take("the Container Scanning API's state is", api)) {
        Ok(api) => out["scanning_api"] = api,
        Err(e) => {
            unread.push("scanning_api");
            errors.insert("scanning_api".to_string(), e.into());
        }
    }
    match repos.and_then(|repos| budget.take("the repositories are", repos.into())) {
        Ok(repos) => out["repositories"] = repos,
        Err(e) => {
            unread.push("repositories");
            errors.insert("repositories".to_string(), e.into());
        }
    }
    match findings.and_then(|(images, read, as_of)| budget.take("the vulnerability findings are", images.into()).map(|images| (images, read, as_of))) {
        Ok((images, read, as_of)) => {
            out["critical_by_image"] = images;
            out["as_of"] = as_of.into();
            out["counted"] = serde_json::json!({ "findings_read": read });
        }
        Err(e) => {
            unread.push("vulnerabilities");
            errors.insert("vulnerabilities".to_string(), e.into());
        }
    }
    out["unread"] = unread.into();
    out["errors"] = errors.into();
    out
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let cfg = serde_json::from_str::<Envelope>(&input).map_err(|e| format!("Input parse error: {e}"))?.config;
    let auth = cfg.auth_header.filter(|a| !a.trim().is_empty()).ok_or("Missing AUTH_HEADER config")?;
    let project = cfg.project.as_deref().map(str::trim).filter(|p| project_ok(p)).ok_or("PROJECT must be a project id (lower-case letters, digits and dashes)")?.to_string();

    let api = read_scanning_api(&auth, &project);
    let repos = read_repositories(&auth, &project);
    let findings = read_findings(&auth, &project);
    serde_json::to_string(&evidence(&project, api, repos, findings)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
use super::*;
use serde_json::{json, Value};
use talos::core::http::Method;
use talos_module_testkit::host;

const P: &str = "example-np";
const DATE: &str = "Wed, 14 Oct 2026 12:00:00 GMT";

fn read() -> Result<Value, String> {
    run(json!({"config": {"AUTH_HEADER": "Bearer vault://gcp/impersonated/reader@example-np.iam.gserviceaccount.com/access_token", "PROJECT": P}}).to_string()).map(|o| serde_json::from_str(&o).unwrap())
}
fn dated(status: u16, body: String) -> talos::core::http::Response {
    let mut r = host::http::response(status, body);
    r.headers.push(("date".to_string(), DATE.to_string()));
    r
}
fn locations() -> Value {
    json!({"locations": [{"name": format!("projects/{P}/locations/us-central1"), "locationId": "us-central1"}, {"name": format!("projects/{P}/locations/europe-west1"), "locationId": "europe-west1"}]})
}
fn repositories(location: &str) -> Value {
    if location == "europe-west1" {
        return json!({});
    }
    json!({"repositories": [
        {"name": format!("projects/{P}/locations/us-central1/repositories/apps"), "format": "DOCKER", "mode": "STANDARD_REPOSITORY",
         "cleanupPolicies": {"delete-old": {"id": "delete-old", "action": "DELETE", "condition": {"olderThan": "2592000s"}}, "keep-recent": {"id": "keep-recent", "action": "KEEP", "mostRecentVersions": {"keepCount": 5}}},
         "dockerConfig": {"immutableTags": true}, "vulnerabilityScanningConfig": {"enablementConfig": "INHERITED", "enablementState": "SCANNING_ACTIVE"}, "sizeBytes": "12345"},
        {"name": format!("projects/{P}/locations/us-central1/repositories/scratch"), "format": "DOCKER", "mode": "STANDARD_REPOSITORY", "cleanupPolicyDryRun": true},
        {"name": format!("projects/{P}/locations/us-central1/repositories/libs"), "format": "MAVEN", "mode": "STANDARD_REPOSITORY", "vulnerabilityScanningConfig": {"enablementState": "SCANNING_DISABLED"}},
        {"name": format!("projects/{P}/locations/us-central1/repositories/old")}
    ]})
}
const WEB: &str = "https://us-central1-docker.pkg.dev/example-np/apps/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const API: &str = "https://us-central1-docker.pkg.dev/example-np/apps/api@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
fn occurrence(id: &str, effective: Option<&str>, severity: &str, created: &str, vex: Option<&str>) -> Value {
    on(WEB, id, effective, severity, created, vex)
}
/// A vulnerability finding on one image, as Container Analysis writes one.
fn on(image: &str, id: &str, effective: Option<&str>, severity: &str, created: &str, vex: Option<&str>) -> Value {
    let mut v = json!({"severity": severity, "cvssScore": 9.8, "packageIssue": [{"affectedPackage": "openssl"}]});
    if let Some(e) = effective {
        v["effectiveSeverity"] = json!(e);
    }
    if let Some(s) = vex {
        v["vexAssessment"] = json!({"state": s});
    }
    json!({"name": format!("projects/{P}/occurrences/{id}"), "kind": "VULNERABILITY", "resourceUri": image,
           "noteName": format!("projects/goog-vulnz/notes/{id}"), "createTime": created, "vulnerability": v})
}
fn findings() -> Value {
    json!({"occurrences": [
        occurrence("CVE-2026-0001", Some("CRITICAL"), "CRITICAL", "2026-08-01T00:00:00Z", None),
        occurrence("CVE-2026-0002", Some("HIGH"), "CRITICAL", "2026-08-01T00:00:00Z", None),
        occurrence("CVE-2026-0003", Some("CRITICAL"), "MEDIUM", "2026-08-01T00:00:00Z", Some("NOT_AFFECTED")),
        occurrence("CVE-2026-0004", None, "CRITICAL", "2026-08-01T00:00:00Z", None),
        occurrence("CVE-2026-0005", None, "SEVERITY_UNSPECIFIED", "2026-08-01T00:00:00Z", None),
        occurrence("CVE-2026-0006", Some("LOW"), "LOW", "2026-08-01T00:00:00Z", None),
        {"name": format!("projects/{P}/occurrences/pkg"), "kind": "PACKAGE", "resourceUri": "https://example.invalid/x"}
    ]})
}
/// Answers every request by its host, from these; `findings_pages` is answered one page after another.
fn cloud(api: (u16, Value), locs: (u16, Value), findings_pages: Vec<(u16, Value)>) {
    let mut pages = findings_pages.into_iter();
    host::http::respond_with(move |req| {
        let u = &req.url;
        Ok(if u.contains("serviceusage.googleapis.com") {
            dated(api.0, api.1.to_string())
        } else if u.ends_with("/repositories?pageSize=1000") {
            let location = u.split("/locations/").nth(1).unwrap().split('/').next().unwrap();
            dated(200, repositories(location).to_string())
        } else if u.contains("artifactregistry.googleapis.com") {
            dated(locs.0, locs.1.to_string())
        } else {
            let (status, body) = pages.next().unwrap_or((500, json!({})));
            dated(status, body.to_string())
        })
    });
}
fn healthy() {
    cloud((200, json!({"name": "projects/123/services/containerscanning.googleapis.com", "state": "ENABLED"})), (200, locations()), vec![(200, findings())]);
}

#[test]
fn everything_is_read_with_gets_in_the_shape_the_check_reads() {
    healthy();
    let out = read().unwrap();
    assert_eq!((out["kind"].as_str(), out["project"].as_str(), out["unread"].clone(), out["errors"].clone()), (Some("artifact_registry_evidence"), Some(P), json!([]), json!({})));
    assert_eq!((out["scanning_api"].clone(), out["as_of"].as_str()), (json!({"state": "ENABLED"}), Some("2026-10-14T12:00:00Z")));
    // What the API leaves out is written as its default, never left unsaid; a Maven repository has no tag setting.
    assert_eq!(out["repositories"], json!([
        {"location": "us-central1", "name": "apps", "format": "DOCKER", "mode": "STANDARD_REPOSITORY", "scanning_config": "INHERITED", "cleanup_policies": 2, "cleanup_deleting": 1, "cleanup_unknown": 0, "cleanup_dry_run": false, "immutable_tags": true},
        {"location": "us-central1", "name": "scratch", "format": "DOCKER", "mode": "STANDARD_REPOSITORY", "scanning_config": "ENABLEMENT_CONFIG_UNSPECIFIED", "cleanup_policies": 0, "cleanup_deleting": 0, "cleanup_unknown": 0, "cleanup_dry_run": true, "immutable_tags": false},
        {"location": "us-central1", "name": "libs", "format": "MAVEN", "mode": "STANDARD_REPOSITORY", "scanning_config": "ENABLEMENT_CONFIG_UNSPECIFIED", "cleanup_policies": 0, "cleanup_deleting": 0, "cleanup_unknown": 0, "cleanup_dry_run": false},
        {"location": "us-central1", "name": "old", "format": "FORMAT_UNSPECIFIED", "mode": "MODE_UNSPECIFIED", "scanning_config": "ENABLEMENT_CONFIG_UNSPECIFIED", "cleanup_policies": 0, "cleanup_deleting": 0, "cleanup_unknown": 0, "cleanup_dry_run": false},
    ]));
    // Per image: the age of each open CRITICAL finding (by the effective severity, else the provider's), and the one whose severity is not said.
    // 0001 and 0004 are open and CRITICAL; 0002 is HIGH in effect; 0003 is closed by its VEX status; 0006 is LOW. No id is handed on.
    // 0005 says no severity: open and dated, so its age is handed on apart.
    assert_eq!(out["critical_by_image"], json!([{"resource": WEB, "open": 2, "ages": [74, 74], "scored_ages": [], "severity_unsaid": 1, "unscored_ages": [74], "unscored_fixable_ages": [], "unscored_unclear": 0, "undated": 0, "vex_unknown": 0}]));
    assert!(!out.to_string().contains("CVE-"), "{out}");
    assert!(out.get("vulnerabilities").is_none());
    assert_eq!(out["counted"]["findings_read"], 7);
    let seen = host::http::requests();
    assert!(seen.iter().all(|r| matches!(r.method, Method::Get) && r.body.is_empty()));
    let urls: Vec<&str> = seen.iter().map(|r| r.url.as_str()).collect();
    assert_eq!(urls, [
        format!("https://serviceusage.googleapis.com/v1/projects/{P}/services/containerscanning.googleapis.com").as_str(),
        format!("https://artifactregistry.googleapis.com/v1/projects/{P}/locations?pageSize=100").as_str(),
        format!("https://artifactregistry.googleapis.com/v1/projects/{P}/locations/us-central1/repositories?pageSize=1000").as_str(),
        format!("https://artifactregistry.googleapis.com/v1/projects/{P}/locations/europe-west1/repositories?pageSize=1000").as_str(),
        format!("https://containeranalysis.googleapis.com/v1/projects/{P}/occurrences?filter=kind%3D%22VULNERABILITY%22&pageSize=1000").as_str(),
    ]);
    // What it hands on is what the check judges.
    let judged: Value = serde_json::from_str(&crate::artifact_registry_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    // The repository whose mode is not said leaves its rules undecided; the finding whose severity is not said is
    // judged by the unscored rule, so both overdue rules find something.
    assert_eq!(judged["not_assessed"], json!(["repo-scanning-disabled", "repo-no-cleanup-policy", "repo-cleanup-deletes-nothing", "docker-tags-mutable"]), "{judged}");
    let rules: Vec<&str> = judged["findings"].as_array().unwrap().iter().map(|f| f["rule"].as_str().unwrap()).collect();
    assert_eq!(rules, ["critical-vulnerability-overdue", "unscored-vulnerability-overdue"], "{judged}");
    assert_eq!((judged["passed"].clone(), judged["clean"].clone()), (json!(["scanning-api-off"]), json!(false)));
}

#[test]
fn what_the_reader_hands_on_is_judged_when_every_row_says() {
    let mut repos = repositories("us-central1");
    repos["repositories"].as_array_mut().unwrap().truncate(3);
    let body = repos.clone();
    let mut f = findings();
    f["occurrences"].as_array_mut().unwrap().remove(4);
    f["occurrences"].as_array_mut().unwrap().extend([on(API, "CVE-2026-0007", Some("CRITICAL"), "CRITICAL", "2026-09-14T00:00:00Z", Some("UNDER_INVESTIGATION")), on(API, "CVE-2026-0008", Some("CRITICAL"), "CRITICAL", "2026-09-13T11:59:59.5Z", Some("AFFECTED"))]);
    let fbody = f.clone();
    host::http::respond_with(move |req| {
        let u = &req.url;
        Ok(if u.contains("serviceusage") {
            dated(200, json!({"state": "DISABLED"}).to_string())
        } else if u.contains("/repositories?") {
            dated(200, if u.contains("us-central1") { body.to_string() } else { "{}".to_string() })
        } else if u.contains("artifactregistry") {
            dated(200, locations().to_string())
        } else {
            dated(200, fbody.to_string())
        })
    });
    let out = read().unwrap();
    let judged: Value = serde_json::from_str(&crate::artifact_registry_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    let found: Vec<(&str, &str)> = judged["findings"].as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap(), f["subject"].as_str().unwrap())).collect();
    assert_eq!(found, [
        ("scanning-api-off", "Container Scanning API"),
        ("repo-no-cleanup-policy", "repository us-central1/scratch"),
        ("docker-tags-mutable", "repository us-central1/scratch"),
        ("repo-no-cleanup-policy", "repository us-central1/libs"),
        // Images in the order of their names; 30 whole days is not overdue, 31 is.
        ("critical-vulnerability-overdue", format!("image {API}").as_str()),
        ("critical-vulnerability-overdue", format!("image {WEB}").as_str()),
    ], "{judged}");
    assert_eq!(out["critical_by_image"][0]["ages"], json!([30, 31]));
    let says: Vec<&str> = judged["findings"].as_array().unwrap()[4..].iter().map(|f| f["says"].as_str().unwrap()).collect();
    assert_eq!(says, ["has 1 CRITICAL finding open for more than 30 days, the oldest 31 days", "has 2 CRITICAL findings open for more than 30 days, the oldest 74 days"]);
    assert_eq!(judged["not_assessed"], json!([]));
}

#[test]
fn a_part_that_could_not_be_read_is_left_out_and_named_and_no_error_body_is_kept() {
    cloud((403, json!({"error": {"message": "secret-looking detail"}})), (200, locations()), vec![(200, findings())]);
    let out = read().unwrap();
    assert!(out.get("scanning_api").is_none(), "{out}");
    assert_eq!((out["unread"].clone(), out["errors"]["scanning_api"].clone()), (json!(["scanning_api"]), json!("the Container Scanning API's state answered HTTP 403")));
    assert!(!out.to_string().contains("secret-looking"));
    assert_eq!(out["repositories"].as_array().unwrap().len(), 4);

    cloud((200, json!({"state": "ENABLED"})), (500, json!({})), vec![(403, json!({}))]);
    let out = read().unwrap();
    assert!(out.get("repositories").is_none() && out.get("vulnerabilities").is_none(), "{out}");
    assert_eq!(out["unread"], json!(["repositories", "vulnerabilities"]));
    assert_eq!((out["errors"]["repositories"].as_str(), out["errors"]["vulnerabilities"].as_str()), (Some("the location listing answered HTTP 500"), Some("the vulnerability findings answered HTTP 403")));
    assert_eq!(out["as_of"], "");
    let judged: Value = serde_json::from_str(&crate::artifact_registry_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert_eq!(judged["passed"], json!(["scanning-api-off"]));
}

#[test]
fn a_network_failure_keeps_its_kind() {
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["scanning_api", "repositories", "vulnerabilities"]));
    let why = out["errors"]["repositories"].as_str().unwrap();
    assert!(why.starts_with("the location listing could not be reached (") && why.to_lowercase().contains("network"), "{why}");
}

#[test]
fn findings_are_read_page_by_page_and_more_than_can_be_handed_on_are_unread() {
    let mut first = findings();
    first["nextPageToken"] = json!("next/page=2");
    let second = json!({"occurrences": [occurrence("CVE-2026-0100", Some("CRITICAL"), "CRITICAL", "2026-09-01T00:00:00Z", Some("AFFECTED"))]});
    cloud((200, json!({"state": "ENABLED"})), (200, locations()), vec![(200, first), (200, second)]);
    let out = read().unwrap();
    // Every page's findings land on their image, its ages sorted.
    assert_eq!((out["critical_by_image"][0]["ages"].clone(), out["critical_by_image"][0]["open"].clone(), out["counted"]["findings_read"].clone()), (json!([43, 74, 74]), json!(3), json!(8)));
    assert!(host::http::requests().last().unwrap().url.ends_with("&pageSize=1000&pageToken=next%2Fpage%3D2"));

    // A listing that does not end within the pages this reader reads is not the listing.
    let endless: Vec<(u16, Value)> = (0..=MAX_FINDING_PAGES).map(|_| (200, json!({"occurrences": [], "nextPageToken": "more"}))).collect();
    cloud((200, json!({"state": "ENABLED"})), (200, locations()), endless);
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["vulnerabilities"]));
    assert_eq!(out["errors"]["vulnerabilities"], "the project has more than 40000 vulnerability findings; this reader would be cutting them short");
    let just: Vec<(u16, Value)> = (0..MAX_FINDING_PAGES).map(|i| (200, if i + 1 == MAX_FINDING_PAGES { json!({}) } else { json!({"nextPageToken": "more"}) })).collect();
    cloud((200, json!({"state": "ENABLED"})), (200, locations()), just);
    assert_eq!(read().unwrap()["unread"], json!([]));
}

#[test]
fn what_is_handed_on_is_bounded_by_the_images_and_more_than_a_bound_is_unread() {
    let healthy_with = |pages: Vec<(u16, Value)>| cloud((200, json!({"state": "ENABLED"})), (200, locations()), pages);
    // As many images as are handed on, each with a finding; then one more.
    let images = |n: usize| json!({"occurrences": (0..n).map(|i| on(&format!("https://us-central1-docker.pkg.dev/{P}/apps/i{i:04}@sha256:{}", "d".repeat(64)), "CVE-2026-0001", Some("CRITICAL"), "CRITICAL", "2026-09-01T00:00:00Z", None)).collect::<Vec<_>>()});
    healthy_with(vec![(200, images(MAX_IMAGES))]);
    assert_eq!(read().unwrap()["critical_by_image"].as_array().unwrap().len(), MAX_IMAGES);
    healthy_with(vec![(200, images(MAX_IMAGES + 1))]);
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["errors"]["vulnerabilities"].as_str()), (json!(["vulnerabilities"]), Some("more than 500 images have findings that may be CRITICAL; this reader would be cutting them short")));
    assert!(out.get("critical_by_image").is_none());
    // A finding whose severity is not said counts toward the images too: it is never dropped.
    let mut unsaid = images(MAX_IMAGES);
    unsaid["occurrences"].as_array_mut().unwrap().push(on(API, "CVE-2026-0002", None, "SEVERITY_UNSPECIFIED", "2026-09-01T00:00:00Z", None));
    healthy_with(vec![(200, unsaid)]);
    assert_eq!(read().unwrap()["unread"], json!(["vulnerabilities"]));
    // One image with as many open CRITICAL findings as are handed on; then one more, over two pages.
    let many = |n: usize| (0..n).map(|i| occurrence(&format!("CVE-2026-{i:04}"), Some("CRITICAL"), "CRITICAL", "2026-09-01T00:00:00Z", None)).collect::<Vec<_>>();
    healthy_with(vec![(200, json!({"occurrences": many(MAX_AGES_PER_IMAGE / 2), "nextPageToken": "more"})), (200, json!({"occurrences": many(MAX_AGES_PER_IMAGE / 2)}))]);
    assert_eq!(read().unwrap()["critical_by_image"][0]["open"], MAX_AGES_PER_IMAGE);
    healthy_with(vec![(200, json!({"occurrences": many(MAX_AGES_PER_IMAGE / 2), "nextPageToken": "more"})), (200, json!({"occurrences": many(MAX_AGES_PER_IMAGE / 2 + 1)}))]);
    let out = read().unwrap();
    assert_eq!(out["errors"]["vulnerabilities"], "an image has more than 2000 open CRITICAL findings; this reader would be cutting them short");
    // Ages rated by score are bounded apart: as many of each as are handed on, then one more scored.
    let scored = |n: usize| (0..n).map(|i| { let mut o = occurrence(&format!("CVE-2026-{i:04}"), None, "", "2026-09-01T00:00:00Z", None); o["vulnerability"]["cvssv3"] = json!({"baseScore": 9.8}); o }).collect::<Vec<_>>();
    healthy_with(vec![(200, json!({"occurrences": many(MAX_AGES_PER_IMAGE), "nextPageToken": "more"})), (200, json!({"occurrences": scored(MAX_AGES_PER_IMAGE)}))]);
    let out = read().unwrap();
    assert_eq!((out["critical_by_image"][0]["open"].clone(), out["critical_by_image"][0]["scored_ages"].as_array().map(Vec::len)), (json!(MAX_AGES_PER_IMAGE), Some(MAX_AGES_PER_IMAGE)));
    healthy_with(vec![(200, json!({"occurrences": scored(MAX_AGES_PER_IMAGE + 1)}))]);
    assert_eq!(read().unwrap()["errors"]["vulnerabilities"], "an image has more than 2000 open CRITICAL findings; this reader would be cutting them short");
    // Closed findings and findings below CRITICAL are not counted against any bound.
    let mut closed = many(MAX_AGES_PER_IMAGE + 1);
    for o in closed.iter_mut() {
        o["vulnerability"]["vexAssessment"] = json!({"state": "FIXED"});
    }
    closed.extend(images(MAX_IMAGES)["occurrences"].as_array().unwrap().iter().map(|o| {
        let mut low = o.clone();
        low["vulnerability"]["effectiveSeverity"] = json!("LOW");
        low
    }));
    healthy_with(vec![(200, json!({"occurrences": closed}))]);
    assert_eq!(read().unwrap()["critical_by_image"], json!([]));
}

#[test]
fn an_image_named_in_a_way_that_cannot_be_handed_on_whole_is_unread() {
    let named = |image: String| {
        cloud((200, json!({"state": "ENABLED"})), (200, locations()), vec![(200, json!({"occurrences": [on(&image, "CVE-2026-0001", Some("CRITICAL"), "CRITICAL", "2026-09-01T00:00:00Z", None)]}))]);
        read().unwrap()
    };
    let prefix = format!("https://us-central1-docker.pkg.dev/{P}/apps/");
    let longest = format!("{prefix}{}", "x".repeat(MAX_RESOURCE - prefix.len()));
    assert_eq!(longest.len(), MAX_RESOURCE);
    assert_eq!(named(longest.clone())["critical_by_image"][0]["resource"], json!(longest));
    for image in [format!("{longest}x"), String::new(), format!("{WEB} x"), format!("{WEB}\"x"), format!("{WEB}é")] {
        let out = named(image.clone());
        assert_eq!(out["errors"]["vulnerabilities"], "a finding that may be CRITICAL names its image in a way this reader cannot hand on whole", "{image}");
    }
    // A name that would not be handed on is no matter on a finding that is not.
    cloud((200, json!({"state": "ENABLED"})), (200, locations()), vec![(200, json!({"occurrences": [on("", "CVE-2026-0001", Some("HIGH"), "CRITICAL", "2026-09-01T00:00:00Z", None)]}))]);
    assert_eq!(read().unwrap()["unread"], json!([]));
}

#[test]
fn a_finding_that_does_not_say_what_the_check_needs_is_counted_never_dropped() {
    let one = |o: Value| {
        cloud((200, json!({"state": "ENABLED"})), (200, locations()), vec![(200, json!({"occurrences": [o]}))]);
        read().unwrap()["critical_by_image"].clone()
    };
    let counts = |unsaid: u64, undated: u64, vex: u64| json!([{"resource": WEB, "open": 0, "ages": [], "scored_ages": [], "severity_unsaid": unsaid, "unscored_ages": [], "unscored_fixable_ages": [], "unscored_unclear": 0, "undated": undated, "vex_unknown": vex}]);
    // Neither severity said: counted, whatever its VEX status says; aged only when it is open.
    assert_eq!(one(occurrence("CVE-1", None, "", "2026-09-01T00:00:00Z", Some("FIXED"))), counts(1, 0, 0));
    let mut aged = counts(1, 0, 0);
    aged[0]["unscored_ages"] = json!([43]);
    assert_eq!(one(occurrence("CVE-1", Some("SEVERITY_UNSPECIFIED"), "SEVERITY_UNSPECIFIED", "2026-09-01T00:00:00Z", None)), aged);
    // CRITICAL with a time that cannot be read: counted, open or closed.
    for created in ["", "last spring", "2026-09-01", "2026-09-01T00:00:00", "2026-09-01T00:00:00+00:00", "2026-09-01 00:00:00Z", "2026-02-30T00:00:00Z", "2026-09-01T24:00:00Z", "2026-09-01T00:00:60Z", "2026-09-01T00:00:00.Z", "2026-09-01T00:00:00.1234567890Z", "0000-09-01T00:00:00Z", "２０２６-09-01T00:00:00Z", "2026-09-01T00:00:00.0z", "2026-09-01T00:00:00.xZ", "2026/09/01T00:00:00Z", "2026-09-01T00-00:00Z"] {
        assert_eq!(one(occurrence("CVE-1", Some("CRITICAL"), "CRITICAL", created, Some("FIXED"))), counts(0, 1, 0), "{created}");
    }
    // CRITICAL with a VEX status this reader does not know: counted.
    assert_eq!(one(occurrence("CVE-1", Some("CRITICAL"), "CRITICAL", "2026-09-01T00:00:00Z", Some("MAYBE"))), counts(0, 0, 1));
    // Closed by its VEX status, and dated: not handed on at all.
    for vex in ["FIXED", "NOT_AFFECTED"] {
        assert_eq!(one(occurrence("CVE-1", Some("CRITICAL"), "CRITICAL", "2026-09-01T00:00:00Z", Some(vex))), json!([]), "{vex}");
    }
    // Open: no status, an unspecified one, affected, under investigation.
    for vex in [None, Some(""), Some("STATE_UNSPECIFIED"), Some("AFFECTED"), Some("UNDER_INVESTIGATION")] {
        assert_eq!(one(occurrence("CVE-1", Some("CRITICAL"), "CRITICAL", "2026-09-01T00:00:00.123456789Z", vex))[0]["ages"], json!([43]), "{vex:?}");
    }
}

#[test]
fn a_finding_that_says_no_severity_is_rated_by_its_cvss_v3_score() {
    // One finding on WEB, saying no severity, with these CVSS fields in place of the usual ones.
    let with = |cvss: Value, vex: Option<&str>, created: &str| -> Value {
        let mut o = occurrence("CVE-1", None, "", created, vex);
        o["vulnerability"].as_object_mut().unwrap().remove("cvssScore");
        for (k, v) in cvss.as_object().unwrap() {
            o["vulnerability"][k] = v.clone();
        }
        cloud((200, json!({"state": "ENABLED"})), (200, locations()), vec![(200, json!({"occurrences": [o]}))]);
        read().unwrap()
    };
    let one = |cvss: Value| with(cvss, None, "2026-09-01T00:00:00Z")["critical_by_image"].clone();
    let image = |ages: Value, scored: Value, unsaid: u64, undated: u64, vex: u64| json!([{"resource": WEB, "open": ages.as_array().unwrap().len(), "ages": ages, "scored_ages": scored, "severity_unsaid": unsaid, "unscored_ages": [], "unscored_fixable_ages": [], "unscored_unclear": 0, "undated": undated, "vex_unknown": vex}]);
    let scored = image(json!([]), json!([43]), 0, 0, 0);
    let mut unsaid = image(json!([]), json!([]), 1, 0, 0);
    unsaid[0]["unscored_ages"] = json!([43]);
    // 9.0 and above is Critical on FIRST's scale; below it the finding is not CRITICAL, and is not handed on.
    for cvss in [json!({"cvssv3": {"baseScore": 9.8}}), json!({"cvssv3": {"baseScore": 9.0}}), json!({"cvssv3": {"baseScore": 10}}), json!({"cvssScore": 9.8, "cvssVersion": "CVSS_VERSION_3"}), json!({"cvssv3": {}, "cvssScore": 9.1, "cvssVersion": "CVSS_VERSION_3"})] {
        assert_eq!(one(cvss.clone()), scored, "{cvss}");
    }
    for cvss in [json!({"cvssv3": {"baseScore": 8.9}}), json!({"cvssv3": {"baseScore": 0.1}}), json!({"cvssv3": {"baseScore": 8.0}, "cvssScore": 9.8, "cvssVersion": "CVSS_VERSION_3"})] {
        assert_eq!(one(cvss.clone()), json!([]), "{cvss}");
    }
    // A v2 score, a score whose version is not said, one outside 0 to 10, or none: it still does not say.
    for cvss in [json!({"cvssScore": 9.8, "cvssVersion": "CVSS_VERSION_2"}), json!({"cvssScore": 9.8}), json!({"cvssScore": 9.8, "cvssVersion": "CVSS_VERSION_UNSPECIFIED"}), json!({"cvssv3": {"baseScore": 11}}), json!({"cvssv3": {"baseScore": -1}}), json!({"cvssv3": null, "cvssScore": null}), json!({})] {
        assert_eq!(one(cvss.clone()), unsaid, "{cvss}");
    }
    // Rated CRITICAL, it is closed, dated and judged by its VEX status as any CRITICAL finding is.
    let v3 = json!({"cvssv3": {"baseScore": 9.8}});
    assert_eq!(with(v3.clone(), Some("NOT_AFFECTED"), "2026-09-01T00:00:00Z")["critical_by_image"], json!([]));
    assert_eq!(with(v3.clone(), Some("MAYBE"), "2026-09-01T00:00:00Z")["critical_by_image"], image(json!([]), json!([]), 0, 0, 1));
    assert_eq!(with(v3.clone(), None, "")["critical_by_image"], image(json!([]), json!([]), 0, 1, 0));
    // A severity that is said decides, whatever the score.
    let labelled = |effective: &str, base: f64| {
        let mut o = occurrence("CVE-1", Some(effective), "", "2026-09-01T00:00:00Z", None);
        o["vulnerability"]["cvssv3"] = json!({"baseScore": base});
        cloud((200, json!({"state": "ENABLED"})), (200, locations()), vec![(200, json!({"occurrences": [o]}))]);
        read().unwrap()["critical_by_image"].clone()
    };
    assert_eq!(labelled("MEDIUM", 9.8), json!([]));
    assert_eq!(labelled("CRITICAL", 5.0), image(json!([43]), json!([]), 0, 0, 0));
    // A score that is not a number is a findings page this reader cannot read, never one rated as if it said.
    for cvss in [json!({"cvssv3": {"baseScore": "9.8"}}), json!({"cvssScore": true, "cvssVersion": "CVSS_VERSION_3"}), json!({"cvssv3": 9.8})] {
        assert_eq!(with(cvss.clone(), None, "2026-09-01T00:00:00Z")["unread"], json!(["vulnerabilities"]), "{cvss}");
    }
}

#[test]
fn a_finding_no_source_gives_a_severity_is_aged_when_it_can_be() {
    // One finding on WEB saying no severity and no CVSS v3 score.
    let one = |fix: Option<bool>, vex: Option<&str>, created: &str| {
        let mut o = occurrence("CVE-1", None, "", created, vex);
        if let Some(f) = fix {
            o["vulnerability"]["fixAvailable"] = json!(f);
        }
        cloud((200, json!({"state": "ENABLED"})), (200, locations()), vec![(200, json!({"occurrences": [o]}))]);
        read().unwrap()
    };
    let shape = |plain: Value, fixable: Value, unclear: u64| json!([{"resource": WEB, "open": 0, "ages": [], "scored_ages": [], "severity_unsaid": 1, "unscored_ages": plain, "unscored_fixable_ages": fixable, "unscored_unclear": unclear, "undated": 0, "vex_unknown": 0}]);
    // Open and dated: aged, apart by whether a fix is said.
    for (fix, plain, fixable) in [(None, json!([43]), json!([])), (Some(false), json!([43]), json!([])), (Some(true), json!([]), json!([43]))] {
        assert_eq!(one(fix, None, "2026-09-01T00:00:00Z")["critical_by_image"], shape(plain, fixable, 0), "{fix:?}");
    }
    // Aged in whole days as a CRITICAL finding is: one recorded after the findings were read is below zero.
    assert_eq!(one(None, None, "2026-10-14T12:00:01Z")["critical_by_image"], shape(json!([-1]), json!([]), 0));
    assert_eq!(one(Some(true), None, "2026-10-14T12:00:01Z")["critical_by_image"], shape(json!([]), json!([-1]), 0));
    // Closed by its VEX status: counted, not aged. A date or VEX status that cannot be read: counted as unclear.
    assert_eq!(one(Some(true), Some("NOT_AFFECTED"), "2026-09-01T00:00:00Z")["critical_by_image"], shape(json!([]), json!([]), 0));
    assert_eq!(one(None, None, "last spring")["critical_by_image"], shape(json!([]), json!([]), 1));
    assert_eq!(one(None, Some("MAYBE"), "2026-09-01T00:00:00Z")["critical_by_image"], shape(json!([]), json!([]), 1));
    // A fix that is not a yes or no is a page this reader cannot read.
    let mut o = occurrence("CVE-1", None, "", "2026-09-01T00:00:00Z", None);
    o["vulnerability"]["fixAvailable"] = json!("yes");
    cloud((200, json!({"state": "ENABLED"})), (200, locations()), vec![(200, json!({"occurrences": [o]}))]);
    assert_eq!(read().unwrap()["unread"], json!(["vulnerabilities"]));
    // Bounded per image as the other ages are.
    let many = |n: usize, fix: bool| (0..n).map(|i| { let mut o = occurrence(&format!("CVE-2026-{i:04}"), None, "", "2026-09-01T00:00:00Z", None); o["vulnerability"]["fixAvailable"] = json!(fix); o }).collect::<Vec<_>>();
    for fix in [false, true] {
        cloud((200, json!({"state": "ENABLED"})), (200, locations()), vec![(200, json!({"occurrences": many(MAX_AGES_PER_IMAGE + 1, fix)}))]);
        assert_eq!(read().unwrap()["errors"]["vulnerabilities"], "an image has more than 2000 open CRITICAL findings; this reader would be cutting them short", "{fix}");
    }
}

#[test]
fn an_age_is_whole_days_to_when_the_findings_were_read() {
    assert_eq!(recorded("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(recorded("2026-10-14T12:00:00.999Z"), Some(1_791_979_200));
    assert_eq!(recorded("0001-01-01T00:00:00Z"), Some(-62_135_596_800));
    assert_eq!(recorded("2024-02-29T23:59:59Z"), Some(1_709_251_199));
    let aged = |created: &str| {
        cloud((200, json!({"state": "ENABLED"})), (200, locations()), vec![(200, json!({"occurrences": [occurrence("CVE-1", Some("CRITICAL"), "CRITICAL", created, None)]}))]);
        read().unwrap()["critical_by_image"][0]["ages"][0].clone()
    };
    // As of Wed, 14 Oct 2026 12:00:00 GMT: a day is counted once it is whole; after that moment, an age is below zero.
    assert_eq!((aged("2026-10-13T12:00:00Z"), aged("2026-10-13T12:00:01Z"), aged("2026-10-14T12:00:00Z"), aged("2026-10-14T12:00:01Z")), (json!(1), json!(0), json!(0), json!(-1)));
    assert_eq!(aged("2026-09-14T12:00:00Z"), json!(30));
}

/// A value `n` bytes long as written: a string of `n - 2` characters between its quotes.
fn sized(n: usize) -> Value {
    json!("x".repeat(n - 2))
}

#[test]
fn the_evidence_fits_three_times_in_what_a_node_is_given() {
    // The platform refuses a node input above 1,000,000 bytes (WASM_MAX_INPUT_BYTES). A workflow's first node is
    // given its trigger three times (top-level keys, `input`, `__trigger_input__`): a shadow run of this evidence
    // once failed so, 393,270 bytes of evidence making a 1,043,193-byte input. Three copies and 100,000 to spare.
    assert_eq!(MAX_EVIDENCE_BYTES, 300_000);
    assert!(3 * MAX_EVIDENCE_BYTES + 100_000 <= 1_000_000);
}

#[test]
fn a_part_is_counted_in_bytes_as_written_up_to_the_bound_and_one_byte_over_is_refused() {
    let room = MAX_EVIDENCE_BYTES - ENVELOPE_BYTES;
    let mut budget = Budget::new();
    assert_eq!(budget.take("it is", sized(room)), Ok(sized(room)));
    assert_eq!(budget.used, MAX_EVIDENCE_BYTES);
    assert_eq!(Budget::new().take("it is", sized(room + 1)).unwrap_err(), format!("it is too large to hand on ({} bytes as written; the evidence is at most 300000 bytes in all)", room + 1));
    // What does not fit is not counted: what is left stays for the parts after it.
    let mut budget = Budget::new();
    assert!(budget.take("it is", sized(room - 10)).is_ok() && budget.take("it is", sized(11)).is_err());
    assert!(budget.take("it is", sized(10)).is_ok() && budget.used == MAX_EVIDENCE_BYTES);
    // Bytes, not characters, and escapes as they are written: the collector pins the same size for the same value.
    assert_eq!(json!({"a": "é\"\\😀", "b": [1, true, null]}).to_string().len(), 36);
    let wide = |n: usize| json!(format!("{}{}", "😀".repeat(1000), "x".repeat(n - 2 - 4000)));
    assert_eq!(wide(room).to_string().len(), room);
    assert!(Budget::new().take("it is", wide(room)).is_ok() && Budget::new().take("it is", wide(room + 1)).is_err());
}

#[test]
fn a_part_that_would_take_the_evidence_over_the_bound_is_left_out_and_named_never_cut() {
    let api = json!({"state": "ENABLED"});
    let dated = || -> Result<(Vec<Value>, usize, String), String> { Ok((vec![], 0, "2026-10-14T12:00:00Z".to_string())) };
    // Repositories that leave exactly room for the findings (none: `[]`, two bytes) are handed on with them, and the
    // evidence is no larger than the bound; one byte more and the findings are what make it too large.
    let rest = MAX_EVIDENCE_BYTES - ENVELOPE_BYTES - api.to_string().len() - 2;
    let filling = |n: usize| -> Result<Vec<Value>, String> { Ok(vec![sized(n - 2)]) };
    let out = evidence(P, Ok(api.clone()), filling(rest), dated());
    assert_eq!((out["unread"].clone(), out["critical_by_image"].clone()), (json!([]), json!([])));
    assert!(out.to_string().len() <= MAX_EVIDENCE_BYTES);
    let out = evidence(P, Ok(api.clone()), filling(rest + 1), dated());
    assert_eq!((out["unread"].clone(), out["errors"]["vulnerabilities"].as_str()), (json!(["vulnerabilities"]), Some("the vulnerability findings are too large to hand on (2 bytes as written; the evidence is at most 300000 bytes in all)")));
    assert!(out.get("critical_by_image").is_none() && out.get("counted").is_none() && out["as_of"] == "", "{}", out["errors"]);
    assert_eq!(out["repositories"].to_string().len(), rest + 1);
    // Each part is left out alone, and the parts after it are still handed on.
    let room = MAX_EVIDENCE_BYTES - ENVELOPE_BYTES;
    let out = evidence(P, Ok(sized(room + 1)), Ok(vec![]), dated());
    assert_eq!((out["unread"].clone(), out["repositories"].clone(), out["critical_by_image"].clone()), (json!(["scanning_api"]), json!([]), json!([])));
    assert!(out.get("scanning_api").is_none() && out["errors"]["scanning_api"].as_str().unwrap().starts_with("the Container Scanning API's state is too large to hand on ("));
    let out = evidence(P, Ok(api.clone()), filling(room), dated());
    assert_eq!((out["unread"].clone(), out["scanning_api"].clone()), (json!(["repositories"]), api.clone()));
    assert!(out.get("repositories").is_none() && out["errors"]["repositories"].as_str().unwrap().starts_with("the repositories are too large to hand on ("));
    // A part that could not be read is not counted against the bound: it is not there.
    let out = evidence(P, Err("the Container Scanning API's state answered HTTP 403".to_string()), filling(room - 2), dated());
    assert_eq!(out["unread"], json!(["scanning_api"]));
}

#[test]
fn findings_too_large_to_hand_on_are_unread_and_the_check_does_not_assess_them() {
    // 500 images with the longest names, each with 40 open CRITICAL findings recorded in the year 1: 20,000 ages of
    // six digits, over twenty pages. Each bound on its own is met; together they are more than can be handed on.
    let image = |i: usize| format!("https://us-central1-docker.pkg.dev/{P}/apps/i{i:04}@{}", "x".repeat(MAX_RESOURCE - 57));
    assert_eq!(image(0).len(), MAX_RESOURCE);
    let pages: Vec<(u16, Value)> = (0..20)
        .map(|p| {
            let occurrences: Vec<Value> = (0..1000).map(|k| on(&image((p * 1000 + k) % MAX_IMAGES), "CVE-2026-0001", Some("CRITICAL"), "CRITICAL", "0001-01-01T00:00:00Z", None)).collect();
            (200, if p + 1 == 20 { json!({"occurrences": occurrences}) } else { json!({"occurrences": occurrences, "nextPageToken": "more"}) })
        })
        .collect();
    cloud((200, json!({"state": "ENABLED"})), (200, locations()), pages);
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["vulnerabilities"]), "{}", out["errors"]);
    let why = out["errors"]["vulnerabilities"].as_str().unwrap();
    assert!(why.starts_with("the vulnerability findings are too large to hand on (") && why.ends_with(" bytes as written; the evidence is at most 300000 bytes in all)"), "{why}");
    let size: usize = why.trim_start_matches("the vulnerability findings are too large to hand on (").split(' ').next().unwrap().parse().unwrap();
    // The collector, given the same answers, says the same size: the two count alike.
    assert_eq!(size, 373_501);
    assert!(size > MAX_EVIDENCE_BYTES - ENVELOPE_BYTES);
    // What was read beside them is handed on, and the whole is within the bound.
    assert_eq!((out["repositories"].as_array().unwrap().len(), out["scanning_api"].clone()), (4, json!({"state": "ENABLED"})));
    assert!(out.get("critical_by_image").is_none() && out.to_string().len() <= MAX_EVIDENCE_BYTES);
    let judged: Value = serde_json::from_str(&crate::artifact_registry_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert!(judged["not_assessed"].as_array().unwrap().contains(&json!("critical-vulnerability-overdue")), "{judged}");
}

#[test]
fn the_most_it_can_hand_on_fits_in_what_a_node_is_given_three_times() {
    // The largest evidence the other bounds allow: every repository with its longest values, and every finding
    // read open and CRITICAL with the widest age, spread over as many images with the longest names as are handed on.
    let longest = |i: usize| format!("{i:04}{}", "x".repeat(MAX_RESOURCE - 4));
    let ages_in_all = MAX_FINDING_PAGES * 1000;
    // The widest age two four-digit years can make: eight characters.
    let widest = (recorded("0001-01-01T00:00:00Z").unwrap() - recorded("9999-12-31T23:59:59Z").unwrap()).div_euclid(86_400);
    assert_eq!(widest.to_string().len(), 8);
    let images: Vec<Value> = (0..MAX_IMAGES)
        .map(|i| {
            let n = ages_in_all / MAX_IMAGES;
            assert!(n <= MAX_AGES_PER_IMAGE);
            json!({"resource": longest(i), "open": n, "ages": vec![widest; n], "scored_ages": [], "severity_unsaid": ages_in_all, "unscored_ages": [], "unscored_fixable_ages": [], "unscored_unclear": ages_in_all, "undated": ages_in_all, "vex_unknown": ages_in_all})
        })
        .collect();
    let repos: Vec<Value> = (0..MAX_REPOS)
        .map(|_| json!({"location": "😀".repeat(40), "name": "😀".repeat(100), "format": "😀".repeat(30), "mode": "😀".repeat(40), "scanning_config": "😀".repeat(40), "cleanup_policies": u64::MAX, "cleanup_deleting": u64::MAX, "cleanup_unknown": u64::MAX, "cleanup_dry_run": false, "immutable_tags": false}))
        .collect();
    let api = json!({"state": "😀".repeat(40)});
    let unbounded = json!({"kind": "artifact_registry_evidence", "project": "a".repeat(30), "as_of": "2026-10-14T12:00:00Z", "scanning_api": api, "repositories": repos,
                           "critical_by_image": images, "counted": {"findings_read": ages_in_all}, "unread": [], "errors": {}});
    println!("worst-case artifact registry evidence at the other bounds alone: {} bytes", unbounded.to_string().len());
    // With the size bound, the findings are what is left out; the rest is handed on, within the bound.
    let out = evidence(&"a".repeat(30), Ok(api), Ok(repos), Ok((images, ages_in_all, "2026-10-14T12:00:00Z".to_string())));
    let bytes = out.to_string().len();
    println!("worst-case artifact registry evidence handed on: {bytes} bytes");
    assert_eq!(out["unread"], json!(["vulnerabilities"]));
    assert!(bytes <= MAX_EVIDENCE_BYTES, "{bytes}");
    // What the evidence holds besides its parts, at its longest (every part unread, each error longer than any this
    // reader writes), is within what is set aside for it.
    let longest_error = "😀".repeat(200);
    let envelope = evidence(&"a".repeat(30), Err(longest_error.clone()), Err(longest_error.clone()), Err(longest_error));
    let bytes = envelope.to_string().len() + json!({"counted": {"findings_read": u64::MAX}, "as_of": "2026-10-14T12:00:00Z"}).to_string().len();
    println!("artifact registry evidence besides its parts, at most: {bytes} bytes");
    assert!(bytes <= ENVELOPE_BYTES, "{bytes}");
}

#[test]
fn findings_from_a_region_that_could_not_be_reached_or_with_no_date_are_unread() {
    let mut partial = findings();
    partial["unreachable"] = json!(["asia-east1"]);
    cloud((200, json!({"state": "ENABLED"})), (200, locations()), vec![(200, partial)]);
    let out = read().unwrap();
    assert!(out.get("vulnerabilities").is_none());
    assert_eq!(out["errors"]["vulnerabilities"], "the vulnerability findings could not reach 1 region(s), so they are not all of them");

    host::http::respond_with(|req| Ok(if req.url.contains("containeranalysis") { host::http::response(200, findings().to_string()) } else { dated(200, "{}".to_string()) }));
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["vulnerabilities"]));
    assert_eq!((out["errors"]["vulnerabilities"].as_str(), out["as_of"].as_str()), (Some("the vulnerability findings answered without saying when (no Date)"), Some("")));
}

#[test]
fn listings_that_would_be_cut_are_unread() {
    let paged = json!({"locations": [{"locationId": "us-central1"}], "nextPageToken": "more"});
    cloud((200, json!({"state": "ENABLED"})), (200, paged), vec![(200, findings())]);
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["errors"]["repositories"].as_str()), (json!(["repositories"]), Some("the location listing did not end within two pages")));
    let many = json!({"locations": (0..=MAX_LOCATIONS).map(|i| json!({"locationId": format!("region-{i}")})).collect::<Vec<_>>()});
    cloud((200, json!({"state": "ENABLED"})), (200, many), vec![(200, findings())]);
    assert!(read().unwrap()["errors"]["repositories"].as_str().unwrap().contains("more than 80 locations"));
    let odd = json!({"locations": [{"locationId": "us-central1/../x"}]});
    cloud((200, json!({"state": "ENABLED"})), (200, odd), vec![(200, findings())]);
    assert_eq!(read().unwrap()["errors"]["repositories"], "a location has an id that could not be used");

    let crowd = move |n: usize, next: &'static str| {
        host::http::respond_with(move |req| {
            Ok(if req.url.contains("/repositories?") {
                dated(200, json!({"repositories": (0..n).map(|i| json!({"name": format!("r{i}"), "format": "NPM", "mode": "STANDARD_REPOSITORY"})).collect::<Vec<_>>(), "nextPageToken": next}).to_string())
            } else if req.url.contains("artifactregistry") {
                dated(200, json!({"locations": [{"locationId": "us-central1"}]}).to_string())
            } else {
                dated(200, "{}".to_string())
            })
        })
    };
    crowd(MAX_REPOS + 1, "");
    assert!(read().unwrap()["errors"]["repositories"].as_str().unwrap().contains("more than 200 repositories"));
    crowd(3, "more");
    assert_eq!(read().unwrap()["unread"], json!(["repositories"]));
    crowd(MAX_REPOS, "");
    assert_eq!(read().unwrap()["repositories"].as_array().unwrap().len(), MAX_REPOS);
}

#[test]
fn an_answer_that_cannot_be_read_is_unread() {
    host::http::respond_with(|_| Ok(dated(200, "not json".to_string())));
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["scanning_api", "repositories", "vulnerabilities"]));
    assert_eq!(out["errors"]["scanning_api"], "the Container Scanning API's state answered with something that could not be read");
}

#[test]
fn the_config_must_name_a_token_and_a_plain_project() {
    let with = |config: Value| run(json!({"config": config}).to_string()).unwrap_err();
    assert_eq!(with(json!({"PROJECT": P})), "Missing AUTH_HEADER config");
    assert_eq!(with(json!({"AUTH_HEADER": " ", "PROJECT": P})), "Missing AUTH_HEADER config");
    for project in ["", "Example-NP", "example-np/../other", "ex"] {
        assert_eq!(with(json!({"AUTH_HEADER": "Bearer x", "PROJECT": project})), "PROJECT must be a project id (lower-case letters, digits and dashes)", "{project}");
    }
    assert!(host::http::requests().is_empty());
}

#[test]
fn what_each_cleanup_policy_does_is_counted_and_an_action_it_does_not_know_is_said() {
    let repos = json!({"repositories": [{"name": format!("projects/{P}/locations/us-central1/repositories/r"), "format": "DOCKER", "mode": "STANDARD_REPOSITORY",
        "cleanupPolicies": {"a": {"action": "DELETE"}, "b": {"action": "KEEP"}, "c": {"action": "ACTION_UNSPECIFIED"}, "d": {}, "e": {"action": "delete"}}}]});
    host::http::respond_with(move |req| {
        let u = req.url.clone();
        let body = if u.contains("serviceusage") { json!({"state": "ENABLED"}) } else if u.ends_with("/repositories?pageSize=1000") { repos.clone() } else if u.contains("artifactregistry") { locations() } else { findings() };
        Ok(talos::core::http::Response { status: 200, headers: vec![("date".to_string(), "Wed, 14 Oct 2026 12:00:00 GMT".to_string())], body: body.to_string().into_bytes() })
    });
    let out = read().unwrap();
    let r = out["repositories"].as_array().unwrap().iter().find(|r| r["name"] == "r").unwrap().clone();
    // Only the API's own spelling is a delete; anything else that is not KEEP is an action this reader does not know.
    assert_eq!((r["cleanup_policies"].as_u64(), r["cleanup_deleting"].as_u64(), r["cleanup_unknown"].as_u64()), (Some(5), Some(1), Some(3)));
}
}
