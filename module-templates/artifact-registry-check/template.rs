// artifact-registry-check: judges ONE Google Cloud project's Artifact
// Registry from evidence a reader collected, by fixed rules: whether the
// registry's own vulnerability scanning is on (the project's Container
// Scanning API, and each Docker repository's own setting), whether a CRITICAL
// finding of that scanning has been left open for more than thirty days,
// whether each repository has cleanup policies, and whether each Docker
// repository's tags are immutable. It reads its input and calls nothing: no
// cloud, no network, no model, no clock.
//
// Each rule says where it comes from: the published page and the heading it
// rests on, or that it is this module's own judgement. The pages were read
// on 2026-10-14. A heading's anchor is given only where the page itself
// showed it; otherwise the source names the page alone, never a guessed
// fragment. A practice this check does not judge is named by the heading and
// an id of this module's own (`anchor`), with the page's address.
//
// The module also carries its CATALOGUE (`CATALOGUE_ONLY: true`): every rule
// with its task, remedy, limits and sources, what it hands on besides its
// findings, and what of the same guidance it does not judge.
//
// Evidence (`kind: "artifact_registry_evidence"`), whatever collected it:
//   { project, as_of,
//     scanning_api:    { state },                      the Container Scanning API on the project
//     repositories:    [{ location, name, format, mode, scanning_config,
//                         cleanup_policies, cleanup_dry_run, immutable_tags }],
//     critical_by_image: [{ resource, open, ages, scored_ages, severity_unsaid, unscored_ages,
//                           unscored_fixable_ages, unscored_unclear, undated, vex_unknown }],
//     unread:          ["scanning_api" | "repositories" | "vulnerabilities"] }
//
//   as_of            when the evidence was read (RFC 3339): every age was
//                    reckoned to it by the reader, never from a clock here
//   state            ENABLED | DISABLED (Service Usage's words)
//   format, mode     as Artifact Registry writes them (DOCKER, …;
//                    STANDARD_REPOSITORY | REMOTE_REPOSITORY | VIRTUAL_REPOSITORY | ASSURED_OSS_REPOSITORY)
//   scanning_config  ENABLEMENT_CONFIG_UNSPECIFIED | INHERITED | DISABLED
//   cleanup_policies how many the repository has (a number, not a list)
//   immutable_tags   a Docker repository's setting
//   critical_by_image  the scanning's findings, one entry per image (its
//                    resource) that has any the check judges: `ages` is the
//                    age in whole days of each of its OPEN findings whose
//                    effective severity is CRITICAL (the provider's when the
//                    effective one is not said; a VEX status of FIXED or
//                    NOT_AFFECTED closes one), and `open` how many there
//                    are; `scored_ages` the ages of the open findings that
//                    say no severity but are CRITICAL by their CVSS v3 base
//                    score (9.0 or more, FIRST's scale), apart from `ages`;
//                    `unscored_ages` / `unscored_fixable_ages` the ages of
//                    the open findings that say no severity and have no v3
//                    score (apart by whether a fix is available), and
//                    `unscored_unclear` how many such cannot be aged;
//                    the last three count the findings that may be
//                    CRITICAL but do not say their severity, when they were
//                    recorded, or a VEX status the reader knows. This part
//                    is named "vulnerabilities" in `unread`. Which
//                    vulnerabilities they are is not handed on.
//
// Fail-closed, the same way as the workload identity check:
//   * no evidence is an error, not a clean result;
//   * a part that is missing, or named in `unread`, makes the rules that
//     need it "not assessed", and what they found on the rest is dropped;
//   * a part that was read but whose rows do not say what a rule needs (a
//     mode or a format this check does not know, a count that is absent, a
//     finding whose severity, date or VEX status was not said) makes that rule not assessed too,
//     with the reason in `undecided`;
//   * except that what cannot take a finding away does not drop it: findings
//     that do not say their severity, date or VEX status can only add to an
//     image's overdue CRITICAL findings, so the ones that are certain are still
//     reported while the rule stays not assessed, with the unsaid ones counted
//     apart in `undecided` and in `counted`;
//   * "clean" means every rule was assessed and none matched.
//
// A finding the owner has decided to live with is named in the node's config
// (`ACCEPTED: ["rule:severity:subject"]`), exactly, and is then reported as
// accepted instead of found.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const CHECK: &str = "artifact-registry";
const TITLE: &str = "Artifact Registry check";
const PARTS: [&str; 3] = ["scanning_api", "repositories", "vulnerabilities"];
/// The keeper remembers at most two hundred. More than this is refused, never cut.
const MAX_FINDINGS: usize = 180;
const MAX_ROWS: usize = 60;
/// The owner's threshold: a CRITICAL finding open longer than this is overdue.
const OVERDUE_DAYS: i64 = 30;
const OVERDUE: &str = "critical-vulnerability-overdue";
const UNSCORED: &str = "unscored-vulnerability-overdue";

const DOCKER: &str = "DOCKER";
const STANDARD: &str = "STANDARD_REPOSITORY";
const REMOTE: &str = "REMOTE_REPOSITORY";
/// The modes Artifact Registry writes. Only a standard repository holds what
/// is pushed to it; a remote one caches another source; a virtual one holds nothing.
const MODES: [&str; 4] = [STANDARD, REMOTE, "VIRTUAL_REPOSITORY", "ASSURED_OSS_REPOSITORY"];
/// A repository's own scanning setting. Unspecified is inherited for a Docker repository.
const SCANNING_CONFIGS: [&str; 3] = ["ENABLEMENT_CONFIG_UNSPECIFIED", "INHERITED", "DISABLED"];

// ------------------------------------------------------------ the sources

struct Doc {
    id: &'static str,
    publisher: &'static str,
    title: &'static str,
    url: &'static str,
}
const SCANNING: Doc = Doc { id: "google-artifact-analysis-automatic-scanning", publisher: "Google Cloud", title: "Enable or disable automatic scanning", url: "https://docs.cloud.google.com/artifact-analysis/docs/enable-automatic-scanning" };
const OVERVIEW: Doc = Doc { id: "google-artifact-analysis-container-scanning", publisher: "Google Cloud", title: "Container scanning overview", url: "https://docs.cloud.google.com/artifact-analysis/docs/container-scanning-overview" };
const CLEANUP: Doc = Doc { id: "google-artifact-registry-cleanup-policies", publisher: "Google Cloud", title: "Configure cleanup policies", url: "https://docs.cloud.google.com/artifact-registry/docs/repositories/cleanup-policy" };
const NAMES: Doc = Doc { id: "google-artifact-registry-names", publisher: "Google Cloud", title: "Repository and image names", url: "https://docs.cloud.google.com/artifact-registry/docs/docker/names" };
const DOCS: [&Doc; 4] = [&SCANNING, &OVERVIEW, &CLEANUP, &NAMES];

/// A heading of a document. `anchor` is the fragment the page showed for it,
/// or "" when it showed none: a source then names the page alone.
struct Cite {
    doc: &'static Doc,
    anchor: &'static str,
    heading: &'static str,
}
struct Rule {
    id: &'static str,
    needs: &'static [&'static str],
    sources: &'static [Cite],
    /// The title of a ticket that would put a finding of this rule right:
    /// what to do, verb first, naming no project.
    task: &'static str,
    remedy: &'static str,
}
const RULES: [Rule; 7] = [
    // "Enable the Container Scanning API"; enabling it "activates scanning for all images you push to standard and remote Docker repositories".
    Rule { id: "scanning-api-off", needs: &["scanning_api"], task: "Turn on Artifact Registry vulnerability scanning for the project",
           remedy: "Enable the Container Scanning API (containerscanning.googleapis.com) on the project, so that the images pushed to its Docker repositories are scanned. Billing for it begins when it is enabled.",
           sources: &[Cite { doc: &SCANNING, anchor: "", heading: "Enable the Container Scanning API" }] },
    // "Control scanning settings for an individual repository": a repository may prevent scanning while the API is on.
    Rule { id: "repo-scanning-disabled", needs: &["repositories"], task: "Allow vulnerability scanning in Docker repositories that prevent it",
           remedy: "Edit the repository and allow vulnerability scanning in it (gcloud: --allow-vulnerability-scanning), or record why its images must go unscanned.",
           sources: &[Cite { doc: &SCANNING, anchor: "disable-repo", heading: "Control scanning settings for an individual repository" }] },
    // The threshold is the owner's: no CRITICAL finding open for more than thirty days. No published page sets it.
    Rule { id: "critical-vulnerability-overdue", needs: &["vulnerabilities"], task: "Triage CRITICAL image vulnerabilities open more than thirty days",
           remedy: "Rebuild the image on fixed packages and push it (then retire the old digest), or record the finding's VEX status as not affected or fixed, with its justification.",
           sources: &[] },
    // The owner's decision (2026-10-15): a finding no source gives a severity is not taken as CRITICAL; it is
    // reported here once open longer than the same threshold. No published page sets it.
    Rule { id: "unscored-vulnerability-overdue", needs: &["vulnerabilities"], task: "Triage image vulnerabilities with no severity open more than thirty days",
           remedy: "Find the vulnerability's severity at its source (the distribution's security tracker, or its CVE record); rebuild the image on fixed packages where a fix is available, or record its VEX status as not affected or fixed, with its justification.",
           sources: &[] },
    // "Artifact Registry cleanup policies let you automate artifact retention and removal across your repositories."
    Rule { id: "repo-no-cleanup-policy", needs: &["repositories"], task: "Set cleanup policies on Artifact Registry repositories that have none",
           remedy: "Give the repository cleanup policies: a delete policy for the age after which versions go, and keep policies for what must stay. Test them with a dry run first, then turn the dry run off.",
           sources: &[Cite { doc: &CLEANUP, anchor: "", heading: "Configure cleanup policies" }] },
    // "Test your policies with a dry run": a dry run only records what would be deleted. And "If an artifact matches
    // the criteria in both the delete policy and the keep policy, the artifact is kept": keep policies alone delete nothing.
    Rule { id: "repo-cleanup-deletes-nothing", needs: &["repositories"], task: "Make Artifact Registry cleanup policies delete what they are meant to",
           remedy: "Give the repository at least one delete policy for the versions that should go, and turn its dry run off once the policies have been tested.",
           sources: &[Cite { doc: &CLEANUP, anchor: "", heading: "Create a delete policy" }, Cite { doc: &CLEANUP, anchor: "", heading: "Test your policies with a dry run" }] },
    // "Container image versions": with mutable tags a tag's digest can change, and "they can also be manipulated by a bad actor to associate a tag with a malicious version of an image."
    Rule { id: "docker-tags-mutable", needs: &["repositories"], task: "Turn on immutable tags in Docker repositories",
           remedy: "Turn on the repository's immutable image tags setting, so that a tag always points to the same image digest; a tagged image can then no longer be deleted, nor a tag moved.",
           sources: &[Cite { doc: &NAMES, anchor: "versions", heading: "Container image versions" }] },
];

/// What a rule does not judge of what it is about, in its catalogue entry,
/// so that "there is a rule for it" is never read as "all of it is checked".
const LIMITS: [(&str, &[&str]); 7] = [
    ("scanning-api-off", &["only the project's own Container Scanning API; on-demand scanning in a build is not looked at"]),
    (
        "repo-scanning-disabled",
        &[
            "only Docker repositories, standard and remote: Maven, npm and Python repositories, whose scanning is off unless turned on, are not judged",
            "the scanning state Artifact Analysis reports for a repository is shown in the table and not judged",
        ],
    ),
    (
        "critical-vulnerability-overdue",
        &[
            "findings below CRITICAL are not judged",
            "which vulnerabilities an image's overdue findings are (their CVE ids) is not handed on, only how many there are and the oldest's age: the image's Vulnerabilities tab in the Google Cloud console (Artifact Registry, the image's digest) names them",
            "a finding's age is reckoned from when the scanning recorded it on that image digest, in whole days, so one is overdue from its thirty-first whole day; the same vulnerability on an older digest of the image is not linked to it",
            "findings Artifact Analysis has archived, and images not pulled for thirty days whose findings are no longer updated, are judged on what was last recorded",
            "a finding is closed only by a VEX status of fixed or not affected; whether that status is true is not judged",
            "a finding that says no severity is rated by its CVSS v3 base score, on the scale of FIRST's CVSS v3.1 specification (section 5, Qualitative Severity Rating Scale: 9.0 to 10.0 is Critical); one with only a CVSS v2 score, or none, is counted as not saying",
            "a finding that says no severity and has no CVSS v3 score is not taken as CRITICAL: unscored-vulnerability-overdue reports it once it has been open more than thirty days",
        ],
    ),
    (
        "unscored-vulnerability-overdue",
        &[
            "how serious such a vulnerability is is not judged: no severity is given to judge it by, so one may be CRITICAL",
            "which vulnerabilities they are is not handed on, only how many there are, how many say a fix is available, and the oldest's age: the image's Vulnerabilities tab in the Google Cloud console names them",
            "a finding's age is reckoned as for critical-vulnerability-overdue, from when the scanning recorded it on that image digest, in whole days",
        ],
    ),
    (
        "repo-no-cleanup-policy",
        &[
            "only standard repositories; remote and virtual ones are not judged",
            "only whether a repository has a cleanup policy: whether one deletes anything is the next rule's, and what they keep or delete, and after how long, is not judged",
        ],
    ),
    (
        "repo-cleanup-deletes-nothing",
        &[
            "only standard repositories; remote and virtual ones are not judged",
            "only whether a repository's policies can delete anything: what a delete policy's conditions select, and whether a keep policy shields all of it, is not judged",
        ],
    ),
    ("docker-tags-mutable", &["only standard Docker repositories; remote and virtual ones are not judged"]),
];

/// Practices of the same guidance this check does not judge, and why. The
/// id is this module's (the page did not show its anchor), so the address is the page's.
const NOT_JUDGED: [(&Doc, &str, &str, &str); 3] = [
    (&OVERVIEW, "on-demand-scanning", "On-demand scanning", "scanning an image in a build, before it reaches the registry; this check reads the registry's own scanning"),
    (&OVERVIEW, "control-deployment-of-vulnerable-images", "Control deployment of vulnerable images", "keeping vulnerable images from running is Binary Authorization's, judged by the Binary Authorization check"),
    (&SCANNING, "extend-your-monitoring-time-window", "Extend your monitoring time window", "how long images are kept under continuous analysis is not in this evidence"),
];

fn cite_json(c: &Cite) -> serde_json::Value {
    let url = if c.anchor.is_empty() { c.doc.url.to_string() } else { format!("{}#{}", c.doc.url, c.anchor) };
    serde_json::json!({ "document": c.doc.id, "publisher": c.doc.publisher, "title": c.doc.title, "heading": c.heading, "anchor": c.anchor, "url": url })
}
fn sources_of(rule: &str) -> Vec<serde_json::Value> {
    RULES.iter().find(|r| r.id == rule).map(|r| r.sources.iter().map(cite_json).collect()).unwrap_or_default()
}
fn basis(sources: &[serde_json::Value]) -> &'static str {
    if sources.is_empty() {
        "local judgement"
    } else {
        "published guidance"
    }
}

/// What the check hands on besides its findings, in its own words.
const PRODUCTS: [(&str, &str); 1] = [("repository-table", "A table of each Artifact Registry repository of the project: its format and mode, whether it allows vulnerability scanning, its cleanup policies and whether its tags are immutable")];

fn catalogue() -> serde_json::Value {
    serde_json::json!({
        "documents": DOCS.iter().map(|d| serde_json::json!({ "id": d.id, "publisher": d.publisher, "title": d.title, "url": d.url, "every_heading_accounted_for": false })).collect::<Vec<_>>(),
        "products": PRODUCTS.iter().map(|(id, says)| serde_json::json!({ "id": id, "says": says })).collect::<Vec<_>>(),
        "rules": RULES.iter().map(|r| {
            let sources: Vec<serde_json::Value> = r.sources.iter().map(cite_json).collect();
            serde_json::json!({
                "rule": r.id,
                "basis": basis(&sources),
                "task": r.task,
                "remedy": r.remedy,
                "limits": LIMITS.iter().find(|(rule, _)| *rule == r.id).map(|(_, limits)| limits.to_vec()).unwrap_or_default(),
                "sources": sources,
            })
        }).collect::<Vec<_>>(),
        "not_judged": NOT_JUDGED.iter().map(|(doc, id, heading, why)| serde_json::json!({ "document": doc.id, "publisher": doc.publisher, "title": doc.title, "heading": heading, "anchor": id, "url": doc.url, "why": why })).collect::<Vec<_>>(),
    })
}

// ----------------------------------------------------------- the evidence

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
    #[serde(default)]
    input: Option<EvidenceIn>,
}
#[derive(Deserialize, Default)]
struct Config {
    /// Findings decided to be acceptable, each as "rule:severity:subject", exactly as reported.
    #[serde(rename = "ACCEPTED")]
    accepted: Option<Vec<String>>,
    /// Return the catalogue of rules and judge nothing.
    #[serde(rename = "CATALOGUE_ONLY")]
    catalogue_only: Option<bool>,
}
#[derive(Deserialize, Default)]
struct EvidenceIn {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    project: String,
    #[serde(default)]
    as_of: String,
    scanning_api: Option<ScanningApi>,
    repositories: Option<Vec<Repo>>,
    /// The "vulnerabilities" part. Evidence of the older shape (a list of findings) does not carry it, and is not assessed.
    critical_by_image: Option<Vec<Image>>,
    #[serde(default)]
    unread: Vec<String>,
}
#[derive(Deserialize, Default)]
struct ScanningApi {
    #[serde(default)]
    state: String,
}
#[derive(Deserialize)]
struct Repo {
    #[serde(default)]
    location: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    format: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    scanning_config: String,
    /// How many cleanup policies; absent is not "none": evidence that does not say is undecided.
    cleanup_policies: Option<u64>,
    /// How many of its cleanup policies delete, and how many say an action the reader did not know.
    cleanup_deleting: Option<u64>,
    cleanup_unknown: Option<u64>,
    #[serde(default)]
    cleanup_dry_run: bool,
    /// Absent is not "mutable": evidence that does not say is undecided.
    immutable_tags: Option<bool>,
}
/// One image's findings. Absent is not "none": an image that does not say is undecided.
#[derive(Deserialize)]
struct Image {
    #[serde(default)]
    resource: String,
    /// How many open CRITICAL findings it has, and the age of each in whole days.
    open: Option<u64>,
    ages: Option<Vec<i64>>,
    /// The ages of the open findings CRITICAL by their CVSS v3 score alone. Absent is none: a reader that
    /// rates nothing by score counts those findings in `severity_unsaid`, so nothing it read is lost.
    #[serde(default)]
    scored_ages: Vec<i64>,
    /// The ages of the open findings that say no severity and have no CVSS v3 score (no fix said; a fix said),
    /// and how many such findings cannot be aged. Absent is not "none" when the image has such findings.
    unscored_ages: Option<Vec<i64>>,
    unscored_fixable_ages: Option<Vec<i64>>,
    unscored_unclear: Option<u64>,
    /// How many may be CRITICAL but do not say their severity, when they were recorded, or a VEX status the reader knows.
    severity_unsaid: Option<u64>,
    undated: Option<u64>,
    vex_unknown: Option<u64>,
}

struct Finding {
    rule: &'static str,
    severity: &'static str,
    subject: String,
    says: String,
}

/// A name from evidence, as it may be shown: plain characters, cut to a length.
fn name(s: &str, max: usize) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || "-_./@:*".contains(*c)).take(max).collect()
}
/// A project id as Google writes one.
fn project_ok(s: &str) -> bool {
    (6..=30).contains(&s.len()) && s.as_bytes()[0].is_ascii_lowercase() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn repo_name(r: &Repo) -> String {
    format!("{}/{}", name(&r.location, 60), name(&r.name, 100))
}
fn docker(r: &Repo) -> bool {
    r.format == DOCKER
}
/// Whether a repository's format is said: "" and the unspecified value are not.
fn format_known(r: &Repo) -> bool {
    !r.format.is_empty() && r.format != "FORMAT_UNSPECIFIED"
}
/// Whether a repository scans images: a Docker one, standard or remote.
fn scannable(r: &Repo) -> bool {
    docker(r) && (r.mode == STANDARD || r.mode == REMOTE)
}
/// How many of an image's CRITICAL findings cannot be aged or judged by their VEX status; `None` when the image does not say.
fn unclear(i: &Image) -> Option<u64> {
    Some(i.undated? + i.vex_unknown?)
}
/// Of an image's findings that say no severity, how many were aged and how many could not be; `None` when it does not say.
fn unscored(i: &Image) -> Option<(u64, u64)> {
    Some(((i.unscored_ages.as_ref()?.len() + i.unscored_fixable_ages.as_ref()?.len()) as u64, i.unscored_unclear?))
}
fn seconds(stamp: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(stamp.trim()).ok().map(|t| t.timestamp())
}

/// Why a rule whose part was read cannot be fully assessed.
struct Undecided {
    rule: &'static str,
    why: String,
    /// What is not said can only add to what the rule found, never take a finding away:
    /// the caller still reports what was found, and the rule stays not assessed.
    adds_only: bool,
}
/// How many of an image's findings do not say their severity, when they were recorded, and a VEX status the reader knows.
fn unsaid_counts(images: &[Image]) -> (u64, u64, u64) {
    images.iter().fold((0, 0, 0), |(s, d, v), i| (s + i.severity_unsaid.unwrap_or(0), d + i.undated.unwrap_or(0), v + i.vex_unknown.unwrap_or(0)))
}

/// Rules whose part was read but whose rows do not say what the rule needs,
/// each with the reason, the first per rule. The caller reports such a rule as
/// not assessed and drops what it found on the rows that did say, unless the
/// reason is one that can only add to what it found.
fn undecided(api: Option<&ScanningApi>, repos: Option<&[Repo]>, images: Option<&[Image]>, as_of: &str) -> Vec<Undecided> {
    let mut open: Vec<(&'static str, String)> = Vec::new();
    let mut adds_only: Vec<(&'static str, String)> = Vec::new();
    if let Some(a) = api {
        if a.state != "ENABLED" && a.state != "DISABLED" {
            open.push(("scanning-api-off", format!("the evidence does not say whether the Container Scanning API is on (its state reads {:?})", name(&a.state, 40))));
        }
    }
    if let Some(rs) = repos {
        for r in rs {
            let at = repo_name(r);
            if !MODES.contains(&r.mode.as_str()) {
                let why = format!("repository {at} has a mode this check does not know ({:?})", name(&r.mode, 40));
                open.push(("repo-no-cleanup-policy", why.clone()));
                open.push(("repo-cleanup-deletes-nothing", why.clone()));
                if docker(r) || !format_known(r) {
                    open.push(("repo-scanning-disabled", why.clone()));
                    open.push(("docker-tags-mutable", why));
                }
                continue;
            }
            if !format_known(r) && (r.mode == STANDARD || r.mode == REMOTE) {
                let why = format!("repository {at} does not say its format, so whether it holds images is not known");
                open.push(("repo-scanning-disabled", why.clone()));
                if r.mode == STANDARD {
                    open.push(("docker-tags-mutable", why));
                }
            }
            if scannable(r) && !SCANNING_CONFIGS.contains(&r.scanning_config.as_str()) {
                open.push(("repo-scanning-disabled", format!("Docker repository {at} has a scanning setting this check does not know ({:?})", name(&r.scanning_config, 40))));
            }
            if r.mode == STANDARD && r.cleanup_policies.is_none() {
                open.push(("repo-no-cleanup-policy", format!("repository {at} does not say how many cleanup policies it has")));
                open.push(("repo-cleanup-deletes-nothing", format!("repository {at} does not say how many cleanup policies it has")));
            }
            if r.mode == STANDARD && r.cleanup_policies.is_some_and(|n| n > 0) {
                if r.cleanup_deleting.is_none() || r.cleanup_unknown.is_none() {
                    open.push(("repo-cleanup-deletes-nothing", format!("repository {at} does not say what its cleanup policies do")));
                } else if r.cleanup_unknown.is_some_and(|n| n > 0) {
                    open.push(("repo-cleanup-deletes-nothing", format!("repository {at} has a cleanup policy whose action this check does not know")));
                }
            }
            if r.mode == STANDARD && docker(r) && r.immutable_tags.is_none() {
                open.push(("docker-tags-mutable", format!("Docker repository {at} does not say whether its tags are immutable")));
            }
        }
    }
    if let Some(is) = images {
        if seconds(as_of).is_none() {
            open.push(("critical-vulnerability-overdue", "the evidence does not say when it was read, so no finding's age can be reckoned".to_string()));
        }
        if let Some(i) = is.iter().find(|i| i.ages.is_none() || i.open.is_none() || unclear(i).is_none()) {
            open.push(("critical-vulnerability-overdue", format!("image {} does not say how many of its findings are open and CRITICAL, how old they are, or how many do not say", name(&i.resource, 240))));
        }
        if let Some(i) = is.iter().find(|i| i.ages.as_ref().zip(i.open).is_some_and(|(ages, n)| ages.len() as u64 != n)) {
            open.push(("critical-vulnerability-overdue", format!("image {} says it has {} open CRITICAL findings and hands on the age of {}", name(&i.resource, 240), i.open.unwrap_or(0), i.ages.as_ref().map_or(0, Vec::len))));
        }
        let unsaid: Vec<&Image> = is.iter().filter(|i| unclear(i).is_some_and(|n| n > 0)).collect();
        if let Some(first) = unsaid.first() {
            let (_, date, vex) = unsaid_counts(is);
            let parts: Vec<String> = [(date, "no date recorded"), (vex, "a VEX status the reader does not know")].iter().filter(|(n, _)| *n > 0).map(|(n, what)| format!("{n} with {what}")).collect();
            adds_only.push((
                OVERDUE,
                format!(
                    "{} CRITICAL findings on {} of {} images do not say what this rule needs ({}), so more may be overdue than is reported (image {} among them)",
                    unsaid.iter().filter_map(|i| unclear(i)).sum::<u64>(),
                    unsaid.len(),
                    is.len(),
                    parts.join(", "),
                    name(&first.resource, 240)
                ),
            ));
        }
        // The findings no source gives a severity: aged by the reader, or counted when they cannot be.
        if seconds(as_of).is_none() {
            open.push((UNSCORED, "the evidence does not say when it was read, so no finding's age can be reckoned".to_string()));
        }
        if let Some(i) = is.iter().find(|i| i.severity_unsaid.is_none()) {
            open.push((UNSCORED, format!("image {} does not say how many of its findings say no severity", name(&i.resource, 240))));
        }
        if let Some(i) = is.iter().find(|i| i.severity_unsaid.is_some_and(|n| n > 0) && unscored(i).is_none()) {
            open.push((UNSCORED, format!("image {} has {} findings that say no severity and does not hand on their ages", name(&i.resource, 240), i.severity_unsaid.unwrap_or(0))));
        }
        if let Some(i) = is.iter().find(|i| unscored(i).zip(i.severity_unsaid).is_some_and(|((aged, unclear), n)| aged + unclear > n)) {
            open.push((UNSCORED, format!("image {} hands on more aged or unaged findings with no severity than it says it has ({})", name(&i.resource, 240), i.severity_unsaid.unwrap_or(0))));
        }
        let unaged: Vec<&Image> = is.iter().filter(|i| i.unscored_unclear.is_some_and(|n| n > 0)).collect();
        if let Some(first) = unaged.first() {
            adds_only.push((
                UNSCORED,
                format!(
                    "{} findings with no severity on {} of {} images cannot be aged (no date recorded, or a VEX status the reader does not know), so more may be overdue than is reported (image {} among them)",
                    unaged.iter().filter_map(|i| i.unscored_unclear).sum::<u64>(),
                    unaged.len(),
                    is.len(),
                    name(&first.resource, 240)
                ),
            ));
        }
    }
    // One reason per rule: the first. One that can only add comes after every other, so it is
    // the rule's reason only when nothing else leaves the rule undecided.
    let mut seen: Vec<&str> = Vec::new();
    let mut out: Vec<Undecided> = Vec::new();
    for (rule, why) in open {
        if !seen.contains(&rule) {
            seen.push(rule);
            out.push(Undecided { rule, why, adds_only: false });
        }
    }
    for (rule, why) in adds_only {
        if !seen.contains(&rule) {
            out.push(Undecided { rule, why, adds_only: true });
        }
    }
    out
}

/// Every rule that matched. Which rules could not be assessed is decided by
/// the caller, from what was unread and from `undecided`.
fn check(api: &ScanningApi, repos: &[Repo], images: &[Image]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    if api.state == "DISABLED" {
        findings.push(Finding { rule: "scanning-api-off", severity: "high", subject: "Container Scanning API".to_string(), says: "is not enabled on the project, so no image pushed to its Artifact Registry repositories is scanned for vulnerabilities".to_string() });
    }
    for r in repos {
        let at = repo_name(r);
        if scannable(r) && r.scanning_config == "DISABLED" {
            findings.push(Finding { rule: "repo-scanning-disabled", severity: "high", subject: format!("repository {at}"), says: "prevents vulnerability scanning, so its images are not scanned even with the project's scanning on".to_string() });
        }
        if r.mode == STANDARD && r.cleanup_policies == Some(0) {
            let dry = if r.cleanup_dry_run { " (it is set to dry run, which deletes nothing)" } else { "" };
            findings.push(Finding { rule: "repo-no-cleanup-policy", severity: "medium", subject: format!("repository {at}"), says: format!("has no cleanup policy, so no retention period is set on what it holds{dry}") });
        }
        // Policies that cannot remove anything set no retention period: all of them keep, or the repository only dry-runs them.
        // (A policy whose action is not known leaves the rule undecided, which drops what it finds.)
        if r.mode == STANDARD && r.cleanup_policies.is_some_and(|n| n > 0) {
            if let Some(deleting) = r.cleanup_deleting {
                if deleting == 0 || r.cleanup_dry_run {
                    let why = if deleting == 0 { "has only keep policies, which delete nothing" } else { "is set to dry run, so its delete policies only record what they would delete" };
                    findings.push(Finding { rule: "repo-cleanup-deletes-nothing", severity: "medium", subject: format!("repository {at}"), says: format!("{why}: no retention period takes effect") });
                }
            }
        }
        if r.mode == STANDARD && docker(r) && r.immutable_tags == Some(false) {
            findings.push(Finding { rule: "docker-tags-mutable", severity: "medium", subject: format!("repository {at}"), says: "has mutable tags: a tag can be moved to another image, so what a tag names can change after it was checked".to_string() });
        }
    }
    // One finding per image: how many of its open CRITICAL findings are older than allowed, and the oldest's age.
    for i in images {
        let overdue: Vec<i64> = i.ages.iter().flatten().chain(&i.scored_ages).copied().filter(|days| *days > OVERDUE_DAYS).collect();
        let by_score = i.scored_ages.iter().filter(|days| **days > OVERDUE_DAYS).count();
        if let Some(oldest) = overdue.iter().max() {
            let n = overdue.len();
            // Findings on it that do not say what the rule needs may add to the count, never lower it.
            let more = match unclear(i) {
                Some(u) if u > 0 => format!(", and {u} more of its CRITICAL findings do not say their date or VEX status"),
                _ => String::new(),
            };
            findings.push(Finding {
                rule: "critical-vulnerability-overdue",
                severity: "high",
                subject: format!("image {}", name(&i.resource, 240)),
                says: format!(
                    "has {n} CRITICAL finding{} open for more than {OVERDUE_DAYS} days, the oldest {oldest} days{}{more}",
                    if n == 1 { "" } else { "s" },
                    if by_score == 0 { String::new() } else { format!(" ({by_score} of them CRITICAL by their CVSS v3 score, saying no severity)") }
                ),
            });
        }
    }
    // One finding per image whose findings no source gives a severity have been open longer than allowed.
    for i in images {
        let over = |ages: &Option<Vec<i64>>| ages.iter().flatten().copied().filter(|days| *days > OVERDUE_DAYS).collect::<Vec<i64>>();
        let (plain, fixable) = (over(&i.unscored_ages), over(&i.unscored_fixable_ages));
        if let Some(oldest) = plain.iter().chain(&fixable).max() {
            let n = plain.len() + fixable.len();
            let more = match i.unscored_unclear {
                Some(u) if u > 0 => format!(", and {u} more of its findings with no severity cannot be aged"),
                _ => String::new(),
            };
            findings.push(Finding {
                rule: UNSCORED,
                severity: "medium",
                subject: format!("image {}", name(&i.resource, 240)),
                says: format!(
                    "has {n} vulnerability finding{} that no source gives a severity open for more than {OVERDUE_DAYS} days, the oldest {oldest} days; {} of them {} a fix available{more}",
                    if n == 1 { "" } else { "s" },
                    fixable.len(),
                    if fixable.len() == 1 { "has" } else { "have" }
                ),
            });
        }
    }
    findings
}

/// One row per repository. `None` when it would be cut: half a table reads as the whole of it.
fn table(repos: &[Repo]) -> Option<Vec<Vec<String>>> {
    let rows: Vec<Vec<String>> = repos
        .iter()
        .map(|r| {
            vec![
                repo_name(r),
                name(&r.format, 30),
                name(&r.mode, 40),
                if !scannable(r) { "n/a".to_string() } else if r.scanning_config == "DISABLED" { "prevented".to_string() } else { "allowed".to_string() },
                if r.mode != STANDARD {
                    "n/a".to_string()
                } else {
                    match r.cleanup_policies {
                        None => "not said".to_string(),
                        Some(n) => format!("{n}{}{}", r.cleanup_deleting.filter(|_| n > 0).map(|d| format!(", {d} deleting")).unwrap_or_default(), if r.cleanup_dry_run { " (dry run)" } else { "" }),
                    }
                },
                if r.mode != STANDARD || !docker(r) {
                    "n/a".to_string()
                } else {
                    match r.immutable_tags {
                        None => "not said",
                        Some(true) => "yes",
                        Some(false) => "no",
                    }
                    .to_string()
                },
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
    let arrived = envelope.input.filter(|e| e.kind == "artifact_registry_evidence").ok_or("the evidence did not arrive")?;
    if arrived.unread.iter().any(|part| !PARTS.contains(&part.as_str())) {
        return Err("the evidence names a part this check does not know".to_string());
    }
    // A result is kept and reported by its project: one that cannot be named plainly is not judged.
    if !project_ok(&arrived.project) {
        return Err("the evidence does not name its project plainly".to_string());
    }
    let accepted_list = match envelope.config.accepted {
        None => Vec::new(),
        Some(list) if list.len() <= 20 && list.iter().all(|a| a.len() <= 300) => list,
        Some(_) => return Err("ACCEPTED holds at most twenty findings".to_string()),
    };
    // A part that did not arrive was not read, whatever `unread` says.
    let mut unread: Vec<String> = arrived.unread.clone();
    for (part, given) in [("scanning_api", arrived.scanning_api.is_some()), ("repositories", arrived.repositories.is_some()), ("vulnerabilities", arrived.critical_by_image.is_some())] {
        if !given && !unread.iter().any(|u| u == part) {
            unread.push(part.to_string());
        }
    }
    let read = |part: &str| !unread.iter().any(|u| u == part);
    let api = arrived.scanning_api.unwrap_or_default();
    let repos = arrived.repositories.unwrap_or_default();
    let images = arrived.critical_by_image.unwrap_or_default();
    let undecided = undecided(read("scanning_api").then_some(&api), read("repositories").then_some(repos.as_slice()), read("vulnerabilities").then_some(images.as_slice()), &arrived.as_of);
    let not_assessed: Vec<&str> = RULES.iter().filter(|r| r.needs.iter().any(|n| !read(n)) || undecided.iter().any(|u| u.rule == r.id)).map(|r| r.id).collect();
    // What a rule found is kept while what is not said can only add to it; the rule stays not assessed.
    let adds_only: Vec<&str> = undecided.iter().filter(|u| u.adds_only).map(|u| u.rule).collect();
    let all: Vec<Finding> = check(&api, &repos, &images).into_iter().filter(|f| !not_assessed.contains(&f.rule) || adds_only.contains(&f.rule)).collect();
    if all.len() > MAX_FINDINGS {
        return Err(format!("the check found more than {MAX_FINDINGS} things; reporting some of them would hide the rest"));
    }
    let passed: Vec<&str> = RULES.iter().map(|r| r.id).filter(|id| !not_assessed.contains(id) && !all.iter().any(|f| f.rule == *id)).collect();
    // Accepted only by an exact match on what was reported.
    let (accepted, findings): (Vec<Finding>, Vec<Finding>) = all.into_iter().partition(|f| accepted_list.iter().any(|a| *a == format!("{}:{}:{}", f.rule, f.severity, f.subject)));
    let worst = ["critical", "high", "medium", "low"].iter().find(|s| findings.iter().any(|f| f.severity == **s)).copied();
    let listed = |list: &[Finding]| -> Vec<serde_json::Value> {
        list.iter()
            .map(|f| {
                let sources = sources_of(f.rule);
                serde_json::json!({ "rule": f.rule, "severity": f.severity, "subject": f.subject, "says": f.says, "basis": basis(&sources), "sources": sources })
            })
            .collect()
    };
    // Counted apart from the findings: what may be CRITICAL but does not say what the overdue rule needs.
    let unsaid = unsaid_counts(&images);
    serde_json::to_string(&serde_json::json!({
        "kind": "security_check", "check": CHECK, "title": TITLE, "project": arrived.project,
        // Clean only when every rule could be assessed and none matched.
        "clean": findings.is_empty() && not_assessed.is_empty(),
        "worst": worst,
        "findings": listed(&findings), "accepted": listed(&accepted), "passed": passed, "not_assessed": not_assessed,
        // Why a rule is not assessed although its part was read.
        "undecided": undecided.iter().map(|u| serde_json::json!({ "rule": u.rule, "why": u.why })).collect::<Vec<_>>(),
        "not_judged": NOT_JUDGED.len(),
        // Drawn only when the repositories were read; otherwise its rows are absent, never partial.
        "table": {
            "title": "Artifact Registry repositories",
            "columns": ["Repository", "Format", "Mode", "Vulnerability scanning", "Cleanup policies", "Immutable tags"],
            "rows": if read("repositories") { serde_json::json!(table(&repos)) } else { serde_json::Value::Null },
        },
        "counted": { "repositories": repos.len(), "images_handed_on": images.len(), "open_critical": images.iter().map(|i| i.ages.as_ref().map_or(0, Vec::len)).sum::<usize>(),
                     "critical_by_score": images.iter().map(|i| i.scored_ages.len()).sum::<usize>(),
                     "unscored_open": images.iter().map(|i| i.unscored_ages.as_ref().map_or(0, Vec::len) + i.unscored_fixable_ages.as_ref().map_or(0, Vec::len)).sum::<usize>(),
                     "unscored_fixable": images.iter().map(|i| i.unscored_fixable_ages.as_ref().map_or(0, Vec::len)).sum::<usize>(),
                     "severity_unsaid": unsaid.0, "undated": unsaid.1, "vex_unknown": unsaid.2, "as_of": name(&arrived.as_of, 40) },
        "unread": unread,
    }))
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
use super::*;
use serde_json::{json, Value};

const P: &str = "example-np";
const AS_OF: &str = "2026-10-14T12:00:00Z";

fn check_of(evidence: Value) -> Value {
    serde_json::from_str(&run(json!({"input": evidence}).to_string()).unwrap()).unwrap()
}
fn found(out: &Value) -> Vec<(String, String, String)> {
    out["findings"].as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["severity"].as_str().unwrap().to_string(), f["subject"].as_str().unwrap().to_string())).collect()
}
fn of_rule(out: &Value, rule: &str) -> Vec<String> {
    found(out).into_iter().filter(|(r, _, _)| r == rule).map(|(_, _, subject)| subject).collect()
}
fn names(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect()
}
fn repo(name: &str, format: &str, mode: &str) -> Value {
    json!({"location": "us-central1", "name": name, "format": format, "mode": mode, "scanning_config": "INHERITED", "cleanup_policies": 2, "cleanup_deleting": 1, "cleanup_unknown": 0, "cleanup_dry_run": false, "immutable_tags": true})
}
fn digest(name: &str) -> String {
    format!("https://us-central1-docker.pkg.dev/{P}/apps/{name}@sha256:{}", "a".repeat(64))
}
/// One image's open CRITICAL findings, by their ages in days, as a reader hands them on.
fn image(name: &str, ages: &[i64]) -> Value {
    json!({"resource": digest(name), "open": ages.len(), "ages": ages, "severity_unsaid": 0, "undated": 0, "vex_unknown": 0})
}
fn evidence(state: &str, repos: Value, images: Value) -> Value {
    json!({"kind": "artifact_registry_evidence", "project": P, "as_of": AS_OF, "scanning_api": {"state": state}, "repositories": repos, "critical_by_image": images, "unread": []})
}
/// Scanning on, one Docker repository with cleanup policies and immutable tags, and no CRITICAL finding overdue.
fn sound() -> Value {
    evidence("ENABLED", json!([repo("apps", "DOCKER", "STANDARD_REPOSITORY")]), json!([image("web", &[13])]))
}
fn with_repo(r: Value) -> Value {
    evidence("ENABLED", json!([r]), json!([]))
}

#[test]
fn the_catalogue_cites_what_was_read_and_needs_no_evidence() {
    let out: Value = serde_json::from_str(&run(json!({"config": {"CATALOGUE_ONLY": true}}).to_string()).unwrap()).unwrap();
    assert_eq!((out["kind"].as_str(), out["check"].as_str()), (Some("security_catalogue"), Some("artifact-registry")));
    let cat = &out["catalogue"];
    let rules = cat["rules"].as_array().unwrap();
    assert_eq!(rules.len(), RULES.len());
    let rule = |id: &str| rules.iter().find(|r| r["rule"] == id).unwrap().clone();
    // The threshold is the owner's, so that rule is this module's judgement; the rest cite a heading.
    assert_eq!((rule("critical-vulnerability-overdue")["basis"].as_str(), rule("critical-vulnerability-overdue")["sources"].clone()), (Some("local judgement"), json!([])));
    for id in ["scanning-api-off", "repo-scanning-disabled", "repo-no-cleanup-policy", "repo-cleanup-deletes-nothing", "docker-tags-mutable"] {
        assert_eq!(rule(id)["basis"], "published guidance", "{id}");
    }
    // A fragment is given only where the page showed one.
    assert_eq!(rule("repo-scanning-disabled")["sources"][0]["url"], "https://docs.cloud.google.com/artifact-analysis/docs/enable-automatic-scanning#disable-repo");
    assert_eq!(rule("docker-tags-mutable")["sources"][0]["url"], "https://docs.cloud.google.com/artifact-registry/docs/docker/names#versions");
    assert_eq!(rule("scanning-api-off")["sources"][0]["url"], "https://docs.cloud.google.com/artifact-analysis/docs/enable-automatic-scanning");
    assert_eq!(rule("scanning-api-off")["sources"][0]["heading"], "Enable the Container Scanning API");
    assert!(rules.iter().all(|r| r["task"].as_str().is_some_and(|t| !t.is_empty()) && r["remedy"].as_str().is_some_and(|t| !t.is_empty())));
    assert_eq!(cat["documents"].as_array().unwrap().len(), DOCS.len());
    assert_eq!(cat["products"][0]["id"], "repository-table");
    // What is not judged has an id to be named by, a heading, a reason, and the page's address without a guessed fragment.
    let nj = cat["not_judged"].as_array().unwrap();
    assert_eq!(nj.len(), NOT_JUDGED.len());
    assert!(nj.iter().all(|n| !n["anchor"].as_str().unwrap().is_empty() && !n["why"].as_str().unwrap().is_empty() && !n["url"].as_str().unwrap().contains('#')));
    // A heading is cited by a rule or listed as not judged, never both.
    let cited: Vec<&str> = RULES.iter().flat_map(|r| r.sources.iter().map(|c| c.heading)).collect();
    assert!(NOT_JUDGED.iter().all(|(_, _, heading, _)| !cited.contains(heading)));
    let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), RULES.len());
}

#[test]
fn what_a_rule_does_not_judge_is_in_its_catalogue_entry() {
    let out: Value = serde_json::from_str(&run(json!({"config": {"CATALOGUE_ONLY": true}}).to_string()).unwrap()).unwrap();
    let limits = |id: &str| -> Vec<String> { out["catalogue"]["rules"].as_array().unwrap().iter().find(|r| r["rule"] == id).unwrap()["limits"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect() };
    assert_eq!((limits("critical-vulnerability-overdue").len(), limits("unscored-vulnerability-overdue").len()), (7, 3));
    assert_eq!(limits("critical-vulnerability-overdue")[0], "findings below CRITICAL are not judged");
    // The ids are no longer handed on: the limit says so, and where they are shown.
    assert!(limits("critical-vulnerability-overdue")[1].contains("CVE ids") && limits("critical-vulnerability-overdue")[1].contains("console"));
    assert_eq!((limits("repo-scanning-disabled").len(), limits("repo-no-cleanup-policy").len(), limits("scanning-api-off").len(), limits("docker-tags-mutable").len()), (2, 2, 1, 1));
    assert!(LIMITS.iter().all(|(id, _)| RULES.iter().any(|r| r.id == *id)));
}

#[test]
fn scanning_on_and_repositories_set_and_no_overdue_finding_is_clean() {
    let out = check_of(sound());
    assert_eq!(out["clean"], true, "{out}");
    assert_eq!(names(&out["passed"]).len(), RULES.len());
    assert_eq!((out["not_assessed"].clone(), out["undecided"].clone(), out["worst"].clone()), (json!([]), json!([]), Value::Null));
    assert_eq!(out["table"]["rows"], json!([["us-central1/apps", "DOCKER", "STANDARD_REPOSITORY", "allowed", "2, 1 deleting", "yes"]]));
}

#[test]
fn the_container_scanning_api_off_is_found() {
    let mut e = sound();
    e["scanning_api"]["state"] = json!("DISABLED");
    let out = check_of(e);
    assert_eq!(found(&out), [("scanning-api-off".to_string(), "high".to_string(), "Container Scanning API".to_string())], "{out}");
    assert_eq!(out["findings"][0]["sources"][0]["heading"], "Enable the Container Scanning API");
    for state in ["", "STATE_UNSPECIFIED", "SOMETIMES"] {
        let mut e = sound();
        e["scanning_api"]["state"] = json!(state);
        let out = check_of(e);
        assert_eq!(names(&out["not_assessed"]), ["scanning-api-off"], "{state}: {out}");
        assert!(out["undecided"][0]["why"].as_str().unwrap().contains("Container Scanning API"));
    }
}

#[test]
fn a_docker_repository_that_prevents_scanning_is_found_and_others_are_not() {
    let mut off = repo("apps", "DOCKER", "STANDARD_REPOSITORY");
    off["scanning_config"] = json!("DISABLED");
    let mut cache = repo("cache", "DOCKER", "REMOTE_REPOSITORY");
    cache["scanning_config"] = json!("DISABLED");
    let mut maven = repo("libs", "MAVEN", "STANDARD_REPOSITORY");
    maven["scanning_config"] = json!("DISABLED");
    let mut virt = repo("all", "DOCKER", "VIRTUAL_REPOSITORY");
    virt["scanning_config"] = json!("DISABLED");
    let mut unset = repo("quiet", "DOCKER", "STANDARD_REPOSITORY");
    unset["scanning_config"] = json!("ENABLEMENT_CONFIG_UNSPECIFIED");
    let out = check_of(evidence("ENABLED", json!([off, cache, maven, virt, unset]), json!([])));
    assert_eq!(of_rule(&out, "repo-scanning-disabled"), ["repository us-central1/apps", "repository us-central1/cache"], "{out}");
    assert_eq!(out["table"]["rows"][2][3], "n/a");
    assert_eq!(out["table"]["rows"][4][3], "allowed");
    for config in ["", "SOMETHING_NEW"] {
        let mut r = repo("apps", "DOCKER", "REMOTE_REPOSITORY");
        r["scanning_config"] = json!(config);
        let out = check_of(with_repo(r));
        assert_eq!(names(&out["not_assessed"]), ["repo-scanning-disabled"], "{config}: {out}");
    }
}

#[test]
fn an_image_with_critical_findings_open_more_than_thirty_days_is_found_once() {
    let out = check_of(evidence("ENABLED", json!([]), json!([image("web", &[2, 30, 31, 74, 74]), image("api", &[30, 0]), image("db", &[400]), image("cache", &[])])));
    // Thirty whole days is not more than thirty; one finding per image, however many of its findings are overdue.
    assert_eq!(of_rule(&out, "critical-vulnerability-overdue"), [format!("image {}", digest("web")), format!("image {}", digest("db"))], "{out}");
    let says: Vec<&str> = out["findings"].as_array().unwrap().iter().map(|f| f["says"].as_str().unwrap()).collect();
    assert_eq!(says, ["has 3 CRITICAL findings open for more than 30 days, the oldest 74 days", "has 1 CRITICAL finding open for more than 30 days, the oldest 400 days"]);
    assert_eq!((out["findings"][0]["severity"].as_str(), out["findings"][0]["basis"].as_str()), (Some("high"), Some("local judgement")));
    assert_eq!(out["counted"], json!({"repositories": 0, "images_handed_on": 4, "open_critical": 8, "critical_by_score": 0, "unscored_open": 0, "unscored_fixable": 0, "severity_unsaid": 0, "undated": 0, "vex_unknown": 0, "as_of": AS_OF}));
    // The order the ages come in does not matter, nor does an age before the evidence was read.
    let out = check_of(evidence("ENABLED", json!([]), json!([image("web", &[31, -1, 90, 5])])));
    assert_eq!(out["findings"][0]["says"], "has 2 CRITICAL findings open for more than 30 days, the oldest 90 days");
    // No image with an open CRITICAL finding is a fact, and passes.
    let out = check_of(evidence("ENABLED", json!([]), json!([])));
    assert!(names(&out["passed"]).contains(&"critical-vulnerability-overdue"), "{out}");
}

#[test]
fn findings_with_no_severity_open_more_than_thirty_days_are_found_apart() {
    let web = vec![("unscored-vulnerability-overdue".to_string(), "medium".to_string(), format!("image {}", digest("web")))];
    let unscored = |name: &str, unsaid: u64, plain: Value, fixable: Value, unclear: u64| {
        let mut i = image(name, &[]);
        i["severity_unsaid"] = json!(unsaid);
        i["unscored_ages"] = plain;
        i["unscored_fixable_ages"] = fixable;
        i["unscored_unclear"] = json!(unclear);
        i
    };
    // Over thirty whole days, with or without a fix; thirty is not over. The CRITICAL rule has nothing to judge, and passes.
    let out = check_of(evidence("ENABLED", json!([]), json!([unscored("web", 10, json!([31, 5, 400, 30]), json!([45, 2]), 0)])));
    assert_eq!(found(&out), web, "{out}");
    assert_eq!(out["findings"][0]["says"], "has 3 vulnerability findings that no source gives a severity open for more than 30 days, the oldest 400 days; 1 of them has a fix available");
    assert!(names(&out["passed"]).contains(&"critical-vulnerability-overdue") && out["clean"] == false, "{out}");
    assert_eq!((out["counted"]["unscored_open"].clone(), out["counted"]["unscored_fixable"].clone()), (json!(6), json!(2)));
    // None over thirty days: the rule passes.
    let out = check_of(evidence("ENABLED", json!([]), json!([unscored("web", 3, json!([30, 2]), json!([1]), 0)])));
    assert!(names(&out["passed"]).contains(&"unscored-vulnerability-overdue") && found(&out).is_empty(), "{out}");
    // Some cannot be aged: what is certain is reported, the rule stays not assessed, and the reason counts them.
    let out = check_of(evidence("ENABLED", json!([]), json!([unscored("web", 10, json!([31]), json!([]), 4)])));
    assert_eq!((names(&out["not_assessed"]), found(&out)), (vec!["unscored-vulnerability-overdue"], web.clone()), "{out}");
    assert!(out["findings"][0]["says"].as_str().unwrap().ends_with("; 0 of them have a fix available, and 4 more of its findings with no severity cannot be aged"), "{out}");
    assert!(out["undecided"][0]["why"].as_str().unwrap().starts_with("4 findings with no severity on 1 of 1 images cannot be aged"), "{out}");
    // A reader that hands on no ages for them, an image that does not say how many say no severity, or one that hands on
    // more than it says: not assessed, with nothing found, and the CRITICAL rule still decided.
    let mut older = image("web", &[90]);
    older["severity_unsaid"] = json!(3);
    let mut silent = image("web", &[90]);
    silent.as_object_mut().unwrap().remove("severity_unsaid");
    for (i, why) in [(older, "has 3 findings that say no severity and does not hand on their ages"), (silent, "does not say how many of its findings say no severity"), (unscored("web", 1, json!([40, 41]), json!([]), 0), "hands on more aged or unaged findings with no severity than it says it has (1)")] {
        let out = check_of(evidence("ENABLED", json!([]), json!([i])));
        assert_eq!(names(&out["not_assessed"]), ["unscored-vulnerability-overdue"], "{why}: {out}");
        assert!(found(&out).iter().all(|(rule, _, _)| rule != "unscored-vulnerability-overdue"), "{out}");
        assert!(out["undecided"][0]["why"].as_str().unwrap().ends_with(why), "{out}");
    }
    // No finding without a severity, from a reader that hands on no unscored ages: nothing to judge, and it passes.
    let out = check_of(evidence("ENABLED", json!([]), json!([image("web", &[3])])));
    assert!(names(&out["passed"]).contains(&"unscored-vulnerability-overdue"), "{out}");
}

#[test]
fn findings_critical_by_their_cvss_score_are_judged_and_said_to_be() {
    // Two labelled ages and three rated CRITICAL by score alone, two of them overdue.
    let mut web = image("web", &[90, 5]);
    web["scored_ages"] = json!([31, 400, 30]);
    let out = check_of(evidence("ENABLED", json!([]), json!([web])));
    assert_eq!(out["findings"][0]["says"], "has 3 CRITICAL findings open for more than 30 days, the oldest 400 days (2 of them CRITICAL by their CVSS v3 score, saying no severity)");
    assert_eq!((out["counted"]["open_critical"].clone(), out["counted"]["critical_by_score"].clone()), (json!(2), json!(3)));
    // Only scored findings overdue: found all the same; none overdue: the rule passes.
    let mut scored_only = image("api", &[]);
    scored_only["scored_ages"] = json!([45]);
    let out = check_of(evidence("ENABLED", json!([]), json!([scored_only])));
    assert_eq!(out["findings"][0]["says"], "has 1 CRITICAL finding open for more than 30 days, the oldest 45 days (1 of them CRITICAL by their CVSS v3 score, saying no severity)");
    let mut recent = image("api", &[3]);
    recent["scored_ages"] = json!([30, 2]);
    let out = check_of(evidence("ENABLED", json!([]), json!([recent])));
    assert!(names(&out["passed"]).contains(&"critical-vulnerability-overdue"), "{out}");
    // Evidence from a reader that rates nothing by score reads as it always did.
    let mut older = image("web", &[90]);
    older.as_object_mut().unwrap().remove("scored_ages");
    let out = check_of(evidence("ENABLED", json!([]), json!([older])));
    assert_eq!((out["findings"][0]["says"].clone(), out["counted"]["critical_by_score"].clone()), (json!("has 1 CRITICAL finding open for more than 30 days, the oldest 90 days"), json!(0)));
}

#[test]
fn findings_that_do_not_say_leave_the_rule_undecided_and_keep_what_is_certain() {
    let overdue = image("web", &[90]);
    let web = vec![("critical-vulnerability-overdue".to_string(), "high".to_string(), format!("image {}", digest("web")))];
    // A CRITICAL finding whose date or VEX status is not said can only add: what is certain is reported, and the rule
    // is still not assessed.
    for (field, n, what) in [("undated", 2, "no date recorded"), ("vex_unknown", 3, "a VEX status the reader does not know")] {
        let mut unclear = image("api", &[]);
        unclear[field] = json!(n);
        let out = check_of(evidence("ENABLED", json!([]), json!([overdue.clone(), unclear])));
        assert_eq!(names(&out["not_assessed"]), ["critical-vulnerability-overdue"], "{field}: {out}");
        assert_eq!(found(&out), web, "{field}: {out}");
        assert!(!names(&out["passed"]).contains(&"critical-vulnerability-overdue") && out["clean"] == false, "{out}");
        let why = out["undecided"][0]["why"].as_str().unwrap();
        assert!(why.starts_with(&format!("{n} CRITICAL findings on 1 of 2 images do not say what this rule needs ({n} with {what}), so more may be overdue")) && why.contains(&digest("api")), "{why}");
        assert_eq!(out["counted"][field], n, "{out}");
    }
    // A finding that says no severity is not taken as CRITICAL (the owner's decision, 2026-10-15): the rule is decided
    // without it, and it is judged by the unscored rule instead.
    let mut unscored = image("api", &[]);
    unscored["severity_unsaid"] = json!(1330);
    unscored["unscored_ages"] = json!([5]);
    unscored["unscored_fixable_ages"] = json!([]);
    unscored["unscored_unclear"] = json!(0);
    let out = check_of(evidence("ENABLED", json!([]), json!([overdue.clone(), unscored])));
    assert_eq!((names(&out["not_assessed"]), found(&out)), (Vec::<&str>::new(), web.clone()), "{out}");
    assert!(names(&out["passed"]).contains(&"unscored-vulnerability-overdue"), "{out}");
    // Each kind is counted apart, and an image's own CRITICAL findings that do not say are named on its finding.
    let mut both = image("web", &[90, 3]);
    both["severity_unsaid"] = json!(1330);
    both["vex_unknown"] = json!(2);
    both["unscored_ages"] = json!([]);
    both["unscored_fixable_ages"] = json!([]);
    both["unscored_unclear"] = json!(0);
    let out = check_of(evidence("ENABLED", json!([]), json!([both])));
    assert_eq!(found(&out), web, "{out}");
    assert_eq!(out["findings"][0]["says"], "has 1 CRITICAL finding open for more than 30 days, the oldest 90 days, and 2 more of its CRITICAL findings do not say their date or VEX status");
    let reason = |out: &Value, rule: &str| out["undecided"].as_array().unwrap().iter().find(|u| u["rule"] == rule).map(|u| u["why"].as_str().unwrap().to_string()).unwrap_or_default();
    assert!(reason(&out, "critical-vulnerability-overdue").starts_with("2 CRITICAL findings on 1 of 1 images do not say what this rule needs (2 with a VEX status the reader does not know)"), "{out}");
    assert_eq!((out["counted"]["severity_unsaid"].clone(), out["counted"]["undated"].clone(), out["counted"]["vex_unknown"].clone()), (json!(1330), json!(0), json!(2)));
    // Nothing certain is overdue: undecided, with nothing found and nothing passed.
    let mut unclear = image("api", &[5]);
    unclear["undated"] = json!(4);
    let out = check_of(evidence("ENABLED", json!([]), json!([unclear.clone()])));
    assert_eq!((names(&out["not_assessed"]), found(&out)), (vec!["critical-vulnerability-overdue"], vec![]), "{out}");
    assert!(!names(&out["passed"]).contains(&"critical-vulnerability-overdue"), "{out}");
    // Anything else that leaves the rule undecided still drops what it found: half a result is never reported.
    let mut short = image("api", &[5]);
    short["open"] = json!(2);
    let out = check_of(evidence("ENABLED", json!([]), json!([overdue.clone(), unclear, short])));
    assert_eq!((names(&out["not_assessed"]), found(&out)), (vec!["critical-vulnerability-overdue"], vec![]), "{out}");
    assert_eq!(out["undecided"].as_array().unwrap().len(), 1, "one reason per rule: {out}");
    assert!(out["undecided"][0]["why"].as_str().unwrap().ends_with("says it has 2 open CRITICAL findings and hands on the age of 1"), "{out}");
    // An image that leaves out what it holds, or whose count is not its list of ages, is not judged as if it said.
    for field in ["open", "ages", "undated", "vex_unknown"] {
        let mut quiet = image("api", &[5]);
        quiet.as_object_mut().unwrap().remove(field);
        let out = check_of(evidence("ENABLED", json!([]), json!([overdue.clone(), quiet])));
        assert_eq!((names(&out["not_assessed"]), found(&out)), (vec!["critical-vulnerability-overdue"], vec![]), "{field}: {out}");
        assert!(out["undecided"][0]["why"].as_str().unwrap().contains("does not say how many"), "{out}");
    }
    let mut short = image("api", &[5]);
    short["open"] = json!(2);
    let out = check_of(evidence("ENABLED", json!([]), json!([overdue.clone(), short])));
    assert_eq!((names(&out["not_assessed"]), found(&out)), (vec!["critical-vulnerability-overdue"], vec![]), "{out}");
    assert!(out["undecided"][0]["why"].as_str().unwrap().ends_with("says it has 2 open CRITICAL findings and hands on the age of 1"), "{out}");
    // Evidence that does not say when it was read cannot be aged.
    for as_of in ["", "yesterday"] {
        let mut e = evidence("ENABLED", json!([]), json!([overdue.clone()]));
        e["as_of"] = json!(as_of);
        let out = check_of(e);
        assert_eq!((names(&out["not_assessed"]), found(&out)), (vec!["critical-vulnerability-overdue", "unscored-vulnerability-overdue"], vec![]), "{as_of}");
        assert!(out["undecided"].as_array().unwrap().iter().all(|u| u["why"].as_str().unwrap().contains("when it was read")), "{out}");
    }
}

#[test]
fn evidence_of_the_older_shape_is_not_assessed_never_passed() {
    // A reader that hands on each finding (as one did before) gives the rule nothing it reads.
    let mut e = sound();
    e.as_object_mut().unwrap().remove("critical_by_image");
    e["vulnerabilities"] = json!([{"resource": digest("web"), "vulnerability": "CVE-2026-0001", "effective_severity": "CRITICAL", "severity": "CRITICAL", "created": "2026-01-01T00:00:00Z", "vex_state": ""}]);
    let out = check_of(e);
    assert_eq!((names(&out["not_assessed"]), names(&out["unread"]), out["clean"].clone()), (vec!["critical-vulnerability-overdue", "unscored-vulnerability-overdue"], vec!["vulnerabilities"], json!(false)), "{out}");
}

#[test]
fn a_standard_repository_with_no_cleanup_policy_is_found() {
    let mut none = repo("apps", "DOCKER", "STANDARD_REPOSITORY");
    none["cleanup_policies"] = json!(0);
    let mut dry = repo("libs", "MAVEN", "STANDARD_REPOSITORY");
    dry["cleanup_policies"] = json!(0);
    dry["cleanup_dry_run"] = json!(true);
    let mut remote = repo("cache", "DOCKER", "REMOTE_REPOSITORY");
    remote["cleanup_policies"] = json!(0);
    let mut virt = repo("all", "DOCKER", "VIRTUAL_REPOSITORY");
    virt["cleanup_policies"] = json!(0);
    let mut dry_with_policies = repo("tools", "NPM", "STANDARD_REPOSITORY");
    dry_with_policies["cleanup_dry_run"] = json!(true);
    let out = check_of(evidence("ENABLED", json!([none, dry, remote, virt, dry_with_policies]), json!([])));
    assert_eq!(of_rule(&out, "repo-no-cleanup-policy"), ["repository us-central1/apps", "repository us-central1/libs"], "{out}");
    let says: Vec<&str> = out["findings"].as_array().unwrap().iter().filter(|f| f["rule"] == "repo-no-cleanup-policy").map(|f| f["says"].as_str().unwrap()).collect();
    assert!(!says[0].contains("dry run") && says[1].contains("dry run"), "{says:?}");
    let rows = out["table"]["rows"].as_array().unwrap();
    assert_eq!((rows[2][4].as_str(), rows[4][4].as_str()), (Some("n/a"), Some("2, 1 deleting (dry run)")));
    let mut quiet = repo("apps", "PYTHON", "STANDARD_REPOSITORY");
    quiet.as_object_mut().unwrap().remove("cleanup_policies");
    let out = check_of(with_repo(quiet));
    assert_eq!(names(&out["not_assessed"]), ["repo-no-cleanup-policy", "repo-cleanup-deletes-nothing"], "{out}");
    assert_eq!(out["table"]["rows"][0][4], "not said");
}

#[test]
fn a_standard_docker_repository_with_mutable_tags_is_found() {
    let mut mutable = repo("apps", "DOCKER", "STANDARD_REPOSITORY");
    mutable["immutable_tags"] = json!(false);
    let mut remote = repo("cache", "DOCKER", "REMOTE_REPOSITORY");
    remote["immutable_tags"] = json!(false);
    let mut maven = repo("libs", "MAVEN", "STANDARD_REPOSITORY");
    maven["immutable_tags"] = json!(false);
    let out = check_of(evidence("ENABLED", json!([mutable, remote, maven]), json!([])));
    assert_eq!(of_rule(&out, "docker-tags-mutable"), ["repository us-central1/apps"], "{out}");
    assert_eq!(out["table"]["rows"][0][5], "no");
    let mut quiet = repo("apps", "DOCKER", "STANDARD_REPOSITORY");
    quiet.as_object_mut().unwrap().remove("immutable_tags");
    let out = check_of(with_repo(quiet));
    assert_eq!(names(&out["not_assessed"]), ["docker-tags-mutable"], "{out}");
    // A Maven repository has no tags to judge: not saying is nothing missing.
    let mut maven = repo("libs", "MAVEN", "STANDARD_REPOSITORY");
    maven.as_object_mut().unwrap().remove("immutable_tags");
    assert_eq!(check_of(with_repo(maven))["clean"], true);
}

#[test]
fn a_repository_whose_mode_or_format_is_not_known_leaves_the_rules_that_need_it_undecided() {
    let mut odd = repo("apps", "DOCKER", "MODE_UNSPECIFIED");
    odd["cleanup_policies"] = json!(0);
    odd["immutable_tags"] = json!(false);
    let out = check_of(evidence("ENABLED", json!([odd, {"location": "us-east1", "name": "x", "format": "DOCKER", "mode": "STANDARD_REPOSITORY", "scanning_config": "DISABLED", "cleanup_policies": 0, "immutable_tags": false}]), json!([])));
    assert_eq!(names(&out["not_assessed"]), ["repo-scanning-disabled", "repo-no-cleanup-policy", "repo-cleanup-deletes-nothing", "docker-tags-mutable"], "{out}");
    assert_eq!(found(&out), []);
    assert!(out["undecided"][0]["why"].as_str().unwrap().contains("MODE_UNSPECIFIED"));
    // An unknown mode on a repository that is not Docker matters only to the cleanup rule.
    let out = check_of(with_repo(repo("libs", "MAVEN", "")));
    assert_eq!(names(&out["not_assessed"]), ["repo-no-cleanup-policy", "repo-cleanup-deletes-nothing"], "{out}");
    // A standard repository that does not say its format may hold images.
    for format in ["", "FORMAT_UNSPECIFIED"] {
        let out = check_of(with_repo(repo("apps", format, "STANDARD_REPOSITORY")));
        assert_eq!(names(&out["not_assessed"]), ["repo-scanning-disabled", "docker-tags-mutable"], "{format}: {out}");
        assert!(out["undecided"][0]["why"].as_str().unwrap().contains("does not say its format"));
        let out = check_of(with_repo(repo("cache", format, "REMOTE_REPOSITORY")));
        assert_eq!(names(&out["not_assessed"]), ["repo-scanning-disabled"], "{format}: {out}");
    }
}

#[test]
fn a_part_that_was_not_read_is_not_assessed_and_its_findings_are_dropped() {
    let mut e = sound();
    e["scanning_api"]["state"] = json!("DISABLED");
    e["unread"] = json!(["scanning_api"]);
    let out = check_of(e);
    assert_eq!((names(&out["not_assessed"]), found(&out)), (vec!["scanning-api-off"], vec![]));
    assert_eq!(out["clean"], false);
    let mut e = sound();
    e.as_object_mut().unwrap().remove("repositories");
    let out = check_of(e);
    assert_eq!(names(&out["not_assessed"]), ["repo-scanning-disabled", "repo-no-cleanup-policy", "repo-cleanup-deletes-nothing", "docker-tags-mutable"]);
    assert_eq!((names(&out["unread"]), out["table"]["rows"].clone()), (vec!["repositories"], Value::Null));
    let mut e = sound();
    e.as_object_mut().unwrap().remove("critical_by_image");
    assert_eq!(names(&check_of(e)["not_assessed"]), ["critical-vulnerability-overdue", "unscored-vulnerability-overdue"]);
    let mut e = sound();
    e["critical_by_image"] = json!([image("web", &[90])]);
    e["unread"] = json!(["vulnerabilities"]);
    let out = check_of(e);
    assert_eq!((names(&out["not_assessed"]), found(&out)), (vec!["critical-vulnerability-overdue", "unscored-vulnerability-overdue"], vec![]));
    let mut e = sound();
    e.as_object_mut().unwrap().remove("scanning_api");
    assert_eq!(names(&check_of(e)["not_assessed"]), ["scanning-api-off"]);
}

#[test]
fn evidence_that_is_missing_or_not_plain_is_refused() {
    let err = |input: Value| run(json!({"input": input}).to_string()).unwrap_err();
    assert_eq!(run(json!({}).to_string()).unwrap_err(), "the evidence did not arrive");
    let mut wrong = sound();
    wrong["kind"] = json!("binauthz_evidence");
    assert_eq!(err(wrong), "the evidence did not arrive");
    let mut odd = sound();
    odd["unread"] = json!(["repositories", "buckets"]);
    assert_eq!(err(odd), "the evidence names a part this check does not know");
    for project in ["", "Example-NP", "ex", "example-np/../x"] {
        let mut e = sound();
        e["project"] = json!(project);
        assert_eq!(err(e), "the evidence does not name its project plainly", "{project}");
    }
}

#[test]
fn an_accepted_finding_is_matched_exactly_severity_and_all() {
    let mut e = sound();
    e["scanning_api"]["state"] = json!("DISABLED");
    let with = |accepted: Value| -> Value { serde_json::from_str(&run(json!({"config": {"ACCEPTED": accepted}, "input": e.clone()}).to_string()).unwrap()).unwrap() };
    let out = with(json!(["scanning-api-off:high:Container Scanning API"]));
    assert_eq!((out["findings"].clone(), out["accepted"][0]["rule"].clone(), out["clean"].clone()), (json!([]), json!("scanning-api-off"), json!(true)));
    assert_eq!(found(&with(json!(["scanning-api-off:medium:Container Scanning API"]))).len(), 1);
    let many: Vec<String> = (0..21).map(|n| format!("x:low:{n}")).collect();
    assert_eq!(run(json!({"config": {"ACCEPTED": many}, "input": e}).to_string()).unwrap_err(), "ACCEPTED holds at most twenty findings");
}

#[test]
fn more_findings_than_can_be_kept_is_an_error_not_a_cut() {
    let overdue = |n: usize| -> Value { json!((0..n).map(|i| image(&format!("web{i}"), &[90])).collect::<Vec<_>>()) };
    assert_eq!(found(&check_of(evidence("ENABLED", json!([]), overdue(MAX_FINDINGS)))).len(), MAX_FINDINGS);
    let err = run(json!({"input": evidence("ENABLED", json!([]), overdue(MAX_FINDINGS + 1))}).to_string()).unwrap_err();
    assert!(err.starts_with("the check found more than 180 things"), "{err}");
}

#[test]
fn the_table_is_never_cut() {
    let at_most: Vec<Value> = (0..MAX_ROWS).map(|i| repo(&format!("r{i}"), "DOCKER", "STANDARD_REPOSITORY")).collect();
    assert_eq!(check_of(evidence("ENABLED", json!(at_most), json!([])))["table"]["rows"].as_array().unwrap().len(), MAX_ROWS);
    let more: Vec<Value> = (0..=MAX_ROWS).map(|i| repo(&format!("r{i}"), "DOCKER", "STANDARD_REPOSITORY")).collect();
    let out = check_of(evidence("ENABLED", json!(more), json!([])));
    assert_eq!((out["clean"].clone(), out["table"]["rows"].clone()), (json!(true), Value::Null));
}

#[test]
fn cleanup_policies_that_cannot_delete_anything_are_found_and_ones_it_cannot_read_are_undecided() {
    let with = |deleting: Value, unknown: Value, dry: bool| {
        let mut r = repo("apps", "DOCKER", "STANDARD_REPOSITORY");
        r["cleanup_deleting"] = deleting;
        r["cleanup_unknown"] = unknown;
        r["cleanup_dry_run"] = json!(dry);
        check_of(with_repo(r))
    };
    // Keep policies only: nothing is ever deleted.
    let out = with(json!(0), json!(0), false);
    assert_eq!(of_rule(&out, "repo-cleanup-deletes-nothing"), ["repository us-central1/apps"], "{out}");
    assert!(out["findings"].as_array().unwrap().iter().any(|f| f["rule"] == "repo-cleanup-deletes-nothing" && f["severity"] == "medium" && f["says"].as_str().unwrap().contains("only keep policies")));
    // A delete policy that only dry-runs.
    let out = with(json!(1), json!(0), true);
    assert!(out["findings"].as_array().unwrap().iter().any(|f| f["rule"] == "repo-cleanup-deletes-nothing" && f["says"].as_str().unwrap().contains("dry run")), "{out}");
    // A live delete policy: passes, and the rule rests on the page it cites.
    let out = with(json!(1), json!(0), false);
    assert!(of_rule(&out, "repo-cleanup-deletes-nothing").is_empty() && names(&out["passed"]).contains(&"repo-cleanup-deletes-nothing"), "{out}");
    // Policies whose actions it does not know, or evidence that does not say: undecided, never passed.
    for (deleting, unknown) in [(json!(1), json!(1)), (json!(null), json!(0)), (json!(1), json!(null))] {
        let out = with(deleting.clone(), unknown.clone(), false);
        assert_eq!(names(&out["not_assessed"]), ["repo-cleanup-deletes-nothing"], "{deleting} {unknown}: {out}");
    }
    // No policy at all is the other rule's finding, not this one's.
    let mut none = repo("apps", "DOCKER", "STANDARD_REPOSITORY");
    none["cleanup_policies"] = json!(0);
    none["cleanup_deleting"] = json!(0);
    let out = check_of(with_repo(none));
    assert!(of_rule(&out, "repo-cleanup-deletes-nothing").is_empty() && !of_rule(&out, "repo-no-cleanup-policy").is_empty());
}
}
