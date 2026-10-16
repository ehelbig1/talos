// binauthz-check: judges ONE Google Cloud project's Binary Authorization
// setup from evidence a reader collected, by fixed rules: whether a policy is
// defined (the Binary Authorization API is on, and its rules hold images to
// something), and whether it is enforced (its rules block, and the project's
// GKE clusters and Cloud Run services apply it). It reads its input and calls
// nothing: no cloud, no network, no model.
//
// Each rule says where it comes from: the published page and the heading it
// rests on. The pages were read on 2026-10-14, by a later session than the
// one that wrote the rules (which could not read them). A heading's anchor is
// given only where the page itself showed it; otherwise the source names the
// page alone, never a guessed fragment. A practice of the same guidance this
// check does not judge is named by its heading and an id of this module's own
// (`anchor`), with the page's address.
//
// One rule changed when the pages were read: `exempts-every-image` called a
// lone `*` a pattern that exempts every image. The policy reference says
// "The `*` wildcard only matches images in the specified directory" (and
// "`**` matches images in subdirectories"), so `*` alone exempts only images
// at the top of no directory, not every image. A pattern is now found only
// when it is nothing but wildcards and slashes with a `**` among them.
//
// Three rules were added after the first real run (2026-10-14), from the
// owner's answers: the containers run on Cloud Run, and a project may have no
// GKE cluster at all.
//   * `binauthz-api-off`: the Binary Authorization API turned off on the
//     project is a finding (high). With it off no policy is in effect, so the
//     four rules about the policy are NOT APPLICABLE then (moot), whatever the
//     policy read answered: they are reported in `not_applicable` with the
//     reason, never as passed and never as "not assessed", and what they
//     found is dropped. They are judged again once the API is on.
//   * `cloud-run-not-enforcing`: a Cloud Run service whose own Binary
//     Authorization setting is off is a finding (high, as a cluster that does
//     not enforce: it is where the images run, and nothing checks them there).
//   * a project with no GKE cluster (the listing was read and is empty) gives
//     `cluster-not-enforcing` nothing to judge: it is NOT APPLICABLE, with the
//     reason, so it never reads as good news. The same for a project with no
//     Cloud Run service. A rule that is not applicable does not stop a result
//     being clean: a project with no cluster can be clean.
//
// The module also carries its CATALOGUE (`CATALOGUE_ONLY: true`): every rule
// with its task, remedy and limits, and what it hands on besides findings.
//
// Evidence (`kind: "binauthz_evidence"`), whatever collected it:
//   { project,
//     api:      { state },
//     policy:   { rules: [{ scope, applies_to, evaluation, enforcement }],
//                 exempt_patterns: [string] },
//     clusters: [{ location, name, evaluation, legacy_enabled }],
//     services: [{ location, name, binauthz }],
//     unread:   ["api" | "policy" | "clusters" | "services"] }
//
//   state        ENABLED | DISABLED | STATE_UNSPECIFIED (Service Usage's words)
//                for binaryauthorization.googleapis.com on the project
//   binauthz     a Cloud Run service's own setting: "" (off), "default" (the
//                project's policy), or a Cloud Run platform policy
//                (projects/<project>/platforms/cloudRun/<name>)
//
//   scope        "default" for the policy's default rule; "cluster",
//                "namespace", "service_account" or "istio_identity" for a
//                rule that applies to one of those, named in `applies_to`
//                (a cluster as "<location>.<name>", as the policy keys it)
//   evaluation   ALWAYS_ALLOW | REQUIRE_ATTESTATION | ALWAYS_DENY
//   enforcement  ENFORCED_BLOCK_AND_AUDIT_LOG | DRYRUN_AUDIT_LOG_ONLY
//   a cluster's  evaluation: DISABLED | PROJECT_SINGLETON_POLICY_ENFORCE |
//                POLICY_BINDINGS | POLICY_BINDINGS_AND_PROJECT_SINGLETON_POLICY_ENFORCE,
//                or unset, when `legacy_enabled` (the older on/off switch) decides
//
// Fail-closed, the same way as the workload identity check:
//   * no evidence is an error, not a clean result;
//   * a part that is missing, or named in `unread`, makes the rules that
//     need it "not assessed", and what they found on the rest is dropped
//     (evidence from a reader older than the API and service rules lacks
//     those parts, so the rules are not assessed: never passed);
//   * a part that was read but whose rows do not say what a rule needs (a
//     mode this check does not know, a policy without exactly one default
//     rule, a cluster that says neither its mode nor its switch, an API state
//     that is neither on nor off, a service whose setting is none of the
//     three) makes that rule not assessed too, with the reason in `undecided`;
//   * "clean" means no rule matched and every rule was assessed, or had
//     nothing to judge (`not_applicable`, with the reason).
//
// A finding the owner has decided to live with is named in the node's config
// (`ACCEPTED: ["rule:severity:subject"]`), exactly, and is then reported as
// accepted instead of found.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const CHECK: &str = "binary-authorization";
const TITLE: &str = "Binary Authorization check";
const PARTS: [&str; 4] = ["api", "policy", "clusters", "services"];
/// The keeper remembers at most two hundred. More than this is refused, never cut.
const MAX_FINDINGS: usize = 180;
const MAX_ROWS: usize = 60;

/// What a rule of the policy does with an image.
const EVALUATIONS: [&str; 3] = ["ALWAYS_ALLOW", "REQUIRE_ATTESTATION", "ALWAYS_DENY"];
/// What a rule does with an image it does not admit: block it, or only log it.
const ENFORCEMENTS: [&str; 2] = ["ENFORCED_BLOCK_AND_AUDIT_LOG", "DRYRUN_AUDIT_LOG_ONLY"];
const DRY_RUN: &str = "DRYRUN_AUDIT_LOG_ONLY";
/// The kinds of rule a policy holds besides its default.
const SPECIFIC: [&str; 4] = ["cluster", "namespace", "service_account", "istio_identity"];

// ------------------------------------------------------------ the sources

struct Doc {
    id: &'static str,
    publisher: &'static str,
    title: &'static str,
    url: &'static str,
}
const REFERENCE: Doc = Doc { id: "google-binauthz-policy-yaml", publisher: "Google Cloud", title: "Policy YAML reference", url: "https://docs.cloud.google.com/binary-authorization/docs/policy-yaml-reference" };
const CONCEPTS: Doc = Doc { id: "google-binauthz-concepts", publisher: "Google Cloud", title: "Binary Authorization concepts", url: "https://docs.cloud.google.com/binary-authorization/docs/key-concepts" };
const CONSOLE: Doc = Doc { id: "google-binauthz-configure-policy-console", publisher: "Google Cloud", title: "Configure a policy using the Google Cloud console", url: "https://docs.cloud.google.com/binary-authorization/docs/configuring-policy-console" };
const DRY_RUN_PAGE: Doc = Doc { id: "google-binauthz-dry-run", publisher: "Google Cloud", title: "Enable dry-run mode", url: "https://docs.cloud.google.com/binary-authorization/docs/enabling-dry-run" };
const ENABLE: Doc = Doc { id: "google-binauthz-enable-cluster", publisher: "Google Cloud", title: "Enable enforcement on an existing cluster", url: "https://docs.cloud.google.com/binary-authorization/docs/enable-cluster" };
const RUN_ENABLE: Doc = Doc { id: "google-binauthz-enable-cloud-run", publisher: "Google Cloud", title: "Enable Binary Authorization for Cloud Run", url: "https://docs.cloud.google.com/binary-authorization/docs/run/enabling-binauthz-cloud-run" };
const RUN_OVERVIEW: Doc = Doc { id: "google-binauthz-cloud-run-overview", publisher: "Google Cloud", title: "Set up overview for Cloud Run", url: "https://docs.cloud.google.com/binary-authorization/docs/run/overview" };
const RUN_REQUIRE: Doc = Doc { id: "google-binauthz-require-cloud-run", publisher: "Google Cloud", title: "Require Binary Authorization for Cloud Run", url: "https://docs.cloud.google.com/binary-authorization/docs/run/requiring-binauthz-cloud-run" };
const SERVICE_USAGE: Doc = Doc { id: "google-service-usage-services", publisher: "Google Cloud", title: "REST Resource: services (Service Usage API)", url: "https://docs.cloud.google.com/service-usage/docs/reference/rest/v1/services" };
const DOCS: [&Doc; 9] = [&REFERENCE, &CONCEPTS, &CONSOLE, &DRY_RUN_PAGE, &ENABLE, &RUN_ENABLE, &RUN_OVERVIEW, &RUN_REQUIRE, &SERVICE_USAGE];

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
    // Both setup pages begin with the API: "Enable the Binary Authorization API" (for a cluster), "Enable the Cloud Run,
    // Artifact Registry, Binary Authorization APIs, if any are not already enabled" (for Cloud Run). Service Usage's
    // DISABLED: "The service cannot be used by this consumer. It has either been explicitly disabled, or has never been enabled."
    Rule { id: "binauthz-api-off", needs: &["api"], task: "Turn on Binary Authorization for the project",
           remedy: "Enable the Binary Authorization API (binaryauthorization.googleapis.com) on the project, then define its policy and have its clusters and Cloud Run services enforce it; the check judges the policy on its next run.",
           sources: &[
               Cite { doc: &ENABLE, anchor: "", heading: "Before you begin" },
               Cite { doc: &RUN_ENABLE, anchor: "", heading: "Before you begin" },
               Cite { doc: &SERVICE_USAGE, anchor: "State", heading: "State" },
           ] },
    // "We don't recommend using the Allow all evaluation mode in the default rule." The default rule
    // "defines the constraints that apply to all non-exempt container images" without a rule of their own.
    Rule { id: "default-rule-allows-all", needs: &["policy"], task: "Define a Binary Authorization policy that holds images to attestations by default",
           remedy: "Set the policy's default rule to require attestations from the attestors your builds sign with (or to deny), and exempt by name only the images that must run without one.",
           sources: &[Cite { doc: &CONSOLE, anchor: "", heading: "Set the default rule" }, Cite { doc: &REFERENCE, anchor: "defaultadmissionrule", heading: "defaultAdmissionRule" }] },
    // "If Binary Authorization applies a cluster-specific rule to a deployment, the default rule is not considered";
    // a specific rule applies "to images that are to be deployed to specific clusters, service account, or identity";
    // Allow all "allows all images to be deployed". The pages advise against Allow all for the DEFAULT rule only:
    // that a specific rule which admits everything is a fault is this check's reading of the same advice.
    Rule { id: "specific-rule-allows-all", needs: &["policy"], task: "Remove Binary Authorization rules that admit every image",
           remedy: "Make the rule require attestations, or delete it so that the default rule applies; if its target must run unchecked images, record why.",
           sources: &[
               Cite { doc: &REFERENCE, anchor: "clusteradmissionrules", heading: "clusterAdmissionRules" },
               Cite { doc: &CONCEPTS, anchor: "specific-rules", heading: "Specific rules" },
               Cite { doc: &CONCEPTS, anchor: "evaluation-modes", heading: "Evaluation modes" },
           ] },
    // Dry run "is primarily used for testing a policy in your environment before it goes into effect", and
    // "allows all container images to be deployed, even if those images violate the Binary Authorization policy";
    // "You can set dry-run mode in the default rule or a specific rule".
    Rule { id: "rule-dry-run", needs: &["policy"], task: "Enforce Binary Authorization rules that only log",
           remedy: "Change the rule's enforcement mode to block and log (ENFORCED_BLOCK_AND_AUDIT_LOG), once its audit log shows no image it would wrongly block.",
           sources: &[Cite { doc: &CONCEPTS, anchor: "enforcement-modes", heading: "Enforcement modes" }, Cite { doc: &DRY_RUN_PAGE, anchor: "", heading: "Disable dry-run mode" }] },
    // "Binary Authorization always allows exempt images to be deployed." "The `**` wildcard matches images in
    // subdirectories"; "The `*` wildcard only matches images in the specified directory". The reference's
    // fragment for its heading was shown two ways (by the page and by a page linking to it), so none is given.
    Rule { id: "exempts-every-image", needs: &["policy"], task: "Narrow Binary Authorization exempt image patterns that match every image",
           remedy: "Replace the pattern with the registry paths that must be exempt, so that every other image is held to the policy.",
           sources: &[Cite { doc: &REFERENCE, anchor: "", heading: "admissionWhitelistPatterns" }, Cite { doc: &CONCEPTS, anchor: "exempt_images", heading: "Exempt images" }] },
    // PROJECT_SINGLETON_POLICY_ENFORCE "enables only enforcement"; POLICY_BINDINGS "enables only CV monitoring and
    // disables an existing enforcement policy if there is one"; the third mode "enables both enforcement and CV monitoring".
    Rule { id: "cluster-not-enforcing", needs: &["clusters"], task: "Enforce the Binary Authorization policy on every GKE cluster",
           remedy: "Set the cluster's Binary Authorization evaluation mode to enforce the project policy (PROJECT_SINGLETON_POLICY_ENFORCE), once the policy admits the images the cluster runs.",
           sources: &[Cite { doc: &ENABLE, anchor: "", heading: "Enable enforcement" }] },
    // "When you set a Binary Authorization policy on a service, Cloud Run checks the policy each time you deploy a new
    // revision"; the setting is the service's own ("gcloud run services update SERVICE_NAME --binary-authorization=default"),
    // and "Binary Authorization can be disabled by Cloud Run developers if the policy is not configured". High, as a
    // cluster that does not enforce: the service is where the images run, and with the setting off none is checked.
    Rule { id: "cloud-run-not-enforcing", needs: &["services"], task: "Enforce Binary Authorization on every Cloud Run service",
           remedy: "Turn on the service's Binary Authorization setting with the project's policy (gcloud run services update SERVICE --binary-authorization=default), then deploy a revision or update its traffic so that enforcement takes effect.",
           sources: &[
               Cite { doc: &RUN_ENABLE, anchor: "", heading: "Enable Binary Authorization on an existing Cloud Run service" },
               Cite { doc: &RUN_OVERVIEW, anchor: "", heading: "Policies applied to Cloud Run services" },
           ] },
];

/// What a rule does not judge of what it is about, in its catalogue entry,
/// so that "there is a rule for it" is never read as "all of it is checked".
const LIMITS: [(&str, &[&str]); 6] = [
    ("binauthz-api-off", &[
        "with the API off no policy is in effect, so the policy's rules are reported as not applicable, never as passed; the policy's own faults are found once the API is on",
        "whether a cluster or a Cloud Run service set to enforce can do so while the API is off is not judged: their rules judge the setting itself",
    ]),
    ("default-rule-allows-all", &["which attestors a rule requires, and what a build must pass before an attestor signs, are not judged"]),
    ("rule-dry-run", &["deployments made with the break-glass annotation, which skip the policy, are not looked at"]),
    ("exempts-every-image", &["only a pattern that matches every image (nothing but wildcards and slashes, with a ** among them) is found; one that exempts a whole registry, a public repository, or only the top directory (a lone *) is not judged"]),
    (
        "cluster-not-enforcing",
        &[
            "only the GKE clusters of the one project the evidence is of; clusters outside Google Cloud are not seen",
            "an admission controller other than Binary Authorization that verifies images is not recognised",
            "a platform policy bound to a cluster for continuous validation reports and does not block, and is not judged",
            "a project with no GKE cluster gives this rule nothing to judge: it is reported as not applicable, never as passed",
        ],
    ),
    (
        "cloud-run-not-enforcing",
        &[
            "which policy a service applies (the project's, or a named Cloud Run platform policy) and what that policy requires are not judged: only that it applies one",
            "deployments made with break-glass, which bypass the policy, are not looked at",
            "whether the organisation policy Allowed Binary Authorization Policies (Cloud Run) requires the setting is not read",
            "a revision deployed before the setting was turned on may still serve traffic; which revisions serve it is not looked at",
            "only the Cloud Run services of the one project the evidence is of; a project with none gives this rule nothing to judge, and it is reported as not applicable",
        ],
    ),
];

/// What the check hands on besides its findings, in its own words.
const PRODUCTS: [(&str, &str); 2] = [
    ("deployment-table", "A table of each GKE cluster and each Cloud Run service of the project: whether it enforces Binary Authorization, and which rule of the policy (or which Cloud Run platform policy) applies to it"),
    ("not-applicable", "The rules that had nothing to judge, each with why: no GKE cluster, no Cloud Run service, or the policy's rules with the Binary Authorization API off"),
];

/// Practices of the same guidance this check does not judge, and why. The
/// id is this module's (a fragment is not guessed), so the address is the page's.
const NOT_JUDGED: [(&Doc, &str, &str, &str); 5] = [
    (&RUN_REQUIRE, "require-binauthz-org-policy", "Set the organization policy", "whether the organisation policy run.allowedBinaryAuthorizationPolicies requires Binary Authorization on Cloud Run is a setting of the organisation, and not in this evidence"),
    (&RUN_OVERVIEW, "cloud-run-jobs", "Policies applied to Cloud Run jobs", "Cloud Run jobs are not read, only services; a job's policy is checked when it is executed"),
    (&CONCEPTS, "attestations", "Attestations", "which attestors a rule requires, their keys, and what a build must pass before one signs are not in this evidence"),
    (&CONCEPTS, "continuous-validation", "Continuous Validation", "checking running Pods against platform policies reports and blocks nothing; the evidence says only whether a cluster's mode includes it"),
    (&CONCEPTS, "google-maintained-system-images", "Google-maintained system images", "whether the policy trusts Google's system images (globalPolicyEvaluationMode) is not in this evidence"),
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
    api: Option<Api>,
    policy: Option<Policy>,
    clusters: Option<Vec<Cluster>>,
    services: Option<Vec<RunService>>,
    #[serde(default)]
    unread: Vec<String>,
}
#[derive(Deserialize, Default)]
struct Api {
    #[serde(default)]
    state: String,
}
#[derive(Deserialize, Default)]
struct Policy {
    #[serde(default)]
    rules: Vec<AdmissionRule>,
    #[serde(default)]
    exempt_patterns: Vec<String>,
}
#[derive(Deserialize)]
struct AdmissionRule {
    #[serde(default)]
    scope: String,
    #[serde(default)]
    applies_to: String,
    #[serde(default)]
    evaluation: String,
    #[serde(default)]
    enforcement: String,
}
#[derive(Deserialize)]
struct Cluster {
    #[serde(default)]
    location: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    evaluation: String,
    /// The older on/off switch, read only when no evaluation mode is set.
    /// Absent is not "off": evidence that does not say is undecided.
    legacy_enabled: Option<bool>,
}

#[derive(Deserialize)]
struct RunService {
    #[serde(default)]
    location: String,
    #[serde(default)]
    name: String,
    /// The service's own setting. Absent is not "off": evidence that does not say is undecided.
    binauthz: Option<String>,
}

struct Finding {
    rule: &'static str,
    severity: &'static str,
    subject: String,
    says: String,
}

/// A name from evidence, as it may be shown: plain characters, cut to a length.
fn name(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || "-_./@:*".contains(*c)).take(120).collect()
}
/// A project id as Google writes one.
fn project_ok(s: &str) -> bool {
    (6..=30).contains(&s.len()) && s.as_bytes()[0].is_ascii_lowercase() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn is_default(r: &AdmissionRule) -> bool {
    r.scope == "default"
}
/// How a rule is named in a finding: the default one, or the target of a specific one.
fn rule_name(r: &AdmissionRule) -> String {
    if is_default(r) {
        "default rule".to_string()
    } else {
        format!("{} rule {}", name(&r.scope), name(&r.applies_to))
    }
}
/// Whether a cluster enforces the project's policy when an image is admitted.
/// `None` when the evidence does not say.
fn enforces(c: &Cluster) -> Option<bool> {
    match c.evaluation.trim() {
        "PROJECT_SINGLETON_POLICY_ENFORCE" | "POLICY_BINDINGS_AND_PROJECT_SINGLETON_POLICY_ENFORCE" => Some(true),
        // Continuous validation alone reports on running images and blocks nothing.
        "DISABLED" | "POLICY_BINDINGS" => Some(false),
        "" | "EVALUATION_MODE_UNSPECIFIED" => c.legacy_enabled,
        _ => None,
    }
}
/// What a Cloud Run service's own setting does.
#[derive(PartialEq, Debug)]
enum RunSetting {
    Off,
    /// The project's policy (`default`).
    ProjectPolicy,
    /// A Cloud Run platform policy, by its name.
    Platform(String),
}
/// A Cloud Run service's setting, or `None` when the evidence does not say
/// which service it is or what its setting is.
fn run_setting(s: &RunService) -> Option<RunSetting> {
    if s.name.trim().is_empty() || s.location.trim().is_empty() {
        return None;
    }
    match s.binauthz.as_deref()? {
        "" => Some(RunSetting::Off),
        "default" => Some(RunSetting::ProjectPolicy),
        other => match other.split('/').collect::<Vec<_>>().as_slice() {
            ["projects", project, "platforms", "cloudRun", policy] if !project.is_empty() && !policy.is_empty() && name(policy) == *policy => Some(RunSetting::Platform(policy.to_string())),
            _ => None,
        },
    }
}
fn api_off(api: Option<&Api>) -> bool {
    api.is_some_and(|a| a.state == "DISABLED")
}
/// Rules that had nothing to judge, each with the reason. Such a rule is
/// neither passed nor "not assessed", and what it found is dropped.
fn not_applicable(api: Option<&Api>, clusters: Option<&[Cluster]>, services: Option<&[RunService]>) -> Vec<(&'static str, String)> {
    let mut moot: Vec<(&'static str, String)> = Vec::new();
    if api_off(api) {
        for r in RULES.iter().filter(|r| r.needs.contains(&"policy")) {
            moot.push((r.id, "the Binary Authorization API is off on the project, so no policy is in effect there for this rule to judge (binauthz-api-off is the finding)".to_string()));
        }
    }
    if clusters.is_some_and(|c| c.is_empty()) {
        moot.push(("cluster-not-enforcing", "the project has no GKE cluster, so there was nothing for this rule to judge".to_string()));
    }
    if services.is_some_and(|s| s.is_empty()) {
        moot.push(("cloud-run-not-enforcing", "the project has no Cloud Run service, so there was nothing for this rule to judge".to_string()));
    }
    moot
}

/// A pattern that exempts every image: nothing in it but wildcards and slashes,
/// and a `**` among them. A `*` matches only in one directory, so `*` alone does not.
fn matches_everything(pattern: &str) -> bool {
    let p = pattern.trim();
    p.contains("**") && p.chars().all(|c| c == '*' || c == '/')
}

/// Rules whose part was read but whose rows do not say what the rule needs,
/// each with the reason. The caller reports such a rule as not assessed and
/// drops what it found on the rows that did say.
fn undecided(api: Option<&Api>, policy: Option<&Policy>, clusters: Option<&[Cluster]>, services: Option<&[RunService]>) -> Vec<(&'static str, String)> {
    let mut open: Vec<(&'static str, String)> = Vec::new();
    if let Some(a) = api {
        if a.state != "ENABLED" && a.state != "DISABLED" {
            open.push(("binauthz-api-off", format!("the evidence does not say whether the Binary Authorization API is on (its state reads {:?})", name(&a.state))));
        }
    }
    if let Some(p) = policy {
        let defaults = p.rules.iter().filter(|r| is_default(r)).count();
        if defaults != 1 {
            let why = format!("the policy holds {defaults} default rules; a Binary Authorization policy has exactly one, so this evidence is not the whole policy");
            open.push(("default-rule-allows-all", why.clone()));
            open.push(("rule-dry-run", why));
        }
        for r in &p.rules {
            if !is_default(r) && !SPECIFIC.contains(&r.scope.as_str()) {
                let why = format!("a rule applies to a kind of target this check does not know ({})", name(&r.scope));
                open.push(("specific-rule-allows-all", why.clone()));
                open.push(("rule-dry-run", why));
            } else if !EVALUATIONS.contains(&r.evaluation.as_str()) {
                let why = format!("the {} has an evaluation mode this check does not know ({:?})", rule_name(r), name(&r.evaluation));
                open.push((if is_default(r) { "default-rule-allows-all" } else { "specific-rule-allows-all" }, why.clone()));
                open.push(("rule-dry-run", why));
            } else if r.evaluation != "ALWAYS_ALLOW" && !ENFORCEMENTS.contains(&r.enforcement.as_str()) {
                open.push(("rule-dry-run", format!("the {} has an enforcement mode this check does not know ({:?})", rule_name(r), name(&r.enforcement))));
            }
        }
    }
    if let Some(cs) = clusters {
        let unknown: Vec<String> = cs.iter().filter(|c| enforces(c).is_none()).map(|c| format!("{}/{}", name(&c.location), name(&c.name))).collect();
        if let Some(first) = unknown.first() {
            open.push(("cluster-not-enforcing", format!("{} of {} clusters do not say whether they enforce Binary Authorization: an unknown evaluation mode, or no mode and no on/off switch ({first} among them)", unknown.len(), cs.len())));
        }
    }
    if let Some(ss) = services {
        let unknown: Vec<String> = ss.iter().filter(|s| run_setting(s).is_none()).map(|s| format!("{}/{}", name(&s.location), name(&s.name))).collect();
        if let Some(first) = unknown.first() {
            open.push(("cloud-run-not-enforcing", format!("{} of {} Cloud Run services have a Binary Authorization setting this check cannot read: none in the evidence, one that names neither the project's policy (default) nor a Cloud Run platform policy, or a service with no name or region ({first} among them)", unknown.len(), ss.len())));
        }
    }
    // One reason per rule: the first.
    let mut seen: Vec<&str> = Vec::new();
    open.retain(|(rule, _)| if seen.contains(rule) { false } else { seen.push(rule); true });
    open
}

/// Every rule that matched. Which rules could not be assessed is decided by
/// the caller, from what was unread and from `undecided`.
fn check(api: &Api, policy: &Policy, clusters: &[Cluster], services: &[RunService]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    if api.state == "DISABLED" {
        findings.push(Finding { rule: "binauthz-api-off", severity: "high", subject: "Binary Authorization API".to_string(), says: "is not enabled on the project: no Binary Authorization policy is in effect there, so no image deployed to its clusters or Cloud Run services is held to one".to_string() });
    }
    for r in policy.rules.iter().filter(|r| r.evaluation == "ALWAYS_ALLOW") {
        if is_default(r) {
            findings.push(Finding { rule: "default-rule-allows-all", severity: "high", subject: rule_name(r), says: "admits every image: wherever no more specific rule applies, any image deploys without an attestation".to_string() });
        } else if SPECIFIC.contains(&r.scope.as_str()) {
            findings.push(Finding { rule: "specific-rule-allows-all", severity: "medium", subject: rule_name(r), says: "admits every image to its target, whatever the default rule requires".to_string() });
        }
    }
    for r in policy.rules.iter().filter(|r| r.evaluation != "ALWAYS_ALLOW" && EVALUATIONS.contains(&r.evaluation.as_str()) && r.enforcement == DRY_RUN) {
        let severity = if is_default(r) { "high" } else { "medium" };
        findings.push(Finding { rule: "rule-dry-run", severity, subject: rule_name(r), says: "is in dry-run mode: an image it does not admit is logged and deploys all the same".to_string() });
    }
    for p in policy.exempt_patterns.iter().filter(|p| matches_everything(p)) {
        findings.push(Finding { rule: "exempts-every-image", severity: "high", subject: format!("exempt pattern {}", name(p.trim())), says: "matches every image, so no image is held to the policy's rules".to_string() });
    }
    for c in clusters {
        if enforces(c) == Some(false) {
            let how = if c.evaluation.trim() == "POLICY_BINDINGS" { "only watches running images (continuous validation), which reports and blocks nothing" } else { "has Binary Authorization turned off" };
            findings.push(Finding { rule: "cluster-not-enforcing", severity: "high", subject: format!("cluster {}/{}", name(&c.location), name(&c.name)), says: format!("{how}: the project's policy is not applied when an image is deployed to it") });
        }
    }
    for s in services.iter().filter(|s| run_setting(s) == Some(RunSetting::Off)) {
        findings.push(Finding { rule: "cloud-run-not-enforcing", severity: "high", subject: format!("Cloud Run service {}/{}", name(&s.location), name(&s.name)), says: "has its Binary Authorization setting off: a revision deployed to it is not checked against any policy".to_string() });
    }
    findings
}

/// One row per cluster and per Cloud Run service: whether it enforces, and
/// which rule of the policy applies to it (a rule for the cluster, or the
/// default), or which platform policy a service names. With the API off no
/// rule applies. `None` when it would be cut: half a table reads as the whole of it.
fn table(api_off: bool, policy: &Policy, clusters: &[Cluster], services: &[RunService]) -> Option<Vec<Vec<String>>> {
    let default = policy.rules.iter().find(|r| is_default(r));
    let said = |e: Option<bool>| match e {
        Some(true) => "yes",
        Some(false) => "no",
        None => "not said",
    }
    .to_string();
    let modes = |r: Option<&AdmissionRule>| -> [String; 2] { [r.map(|r| name(&r.evaluation)).unwrap_or_default(), r.map(|r| if r.evaluation == "ALWAYS_ALLOW" { "n/a".to_string() } else { name(&r.enforcement) }).unwrap_or_default()] };
    let off = "none: the API is off".to_string();
    let mut rows: Vec<Vec<String>> = Vec::new();
    for c in clusters {
        let own = policy.rules.iter().find(|r| r.scope == "cluster" && r.applies_to == format!("{}.{}", c.location, c.name));
        let applies = own.or(default);
        let [evaluation, enforcement] = if api_off { [String::new(), String::new()] } else { modes(applies) };
        let rule = if api_off { off.clone() } else if own.is_some() { "its own rule".to_string() } else { "the default rule".to_string() };
        rows.push(vec!["GKE cluster".to_string(), format!("{}/{}", name(&c.location), name(&c.name)), said(enforces(c)), rule, evaluation, enforcement]);
    }
    for s in services {
        let setting = run_setting(s);
        let (rule, [evaluation, enforcement]) = match &setting {
            Some(RunSetting::ProjectPolicy) if api_off => (off.clone(), [String::new(), String::new()]),
            // Cloud Run applies a policy's default rule: it has no rule of its own in the project's policy.
            Some(RunSetting::ProjectPolicy) => ("the default rule".to_string(), modes(default)),
            Some(RunSetting::Platform(p)) => (format!("platform policy {p}"), [String::new(), String::new()]),
            Some(RunSetting::Off) => ("none".to_string(), [String::new(), String::new()]),
            None => ("not said".to_string(), [String::new(), String::new()]),
        };
        rows.push(vec!["Cloud Run service".to_string(), format!("{}/{}", name(&s.location), name(&s.name)), said(setting.map(|x| x != RunSetting::Off)), rule, evaluation, enforcement]);
    }
    (rows.len() <= MAX_ROWS).then_some(rows)
}

#[talos_module(world = "minimal-node")]
pub fn run(input: String) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    if envelope.config.catalogue_only.unwrap_or(false) {
        return serde_json::to_string(&serde_json::json!({ "kind": "security_catalogue", "check": CHECK, "title": TITLE, "catalogue": catalogue() })).map_err(|e| e.to_string());
    }
    // No evidence is a failure, never a clean result.
    let arrived = envelope.input.filter(|e| e.kind == "binauthz_evidence").ok_or("the evidence did not arrive")?;
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
    for (part, given) in [("api", arrived.api.is_some()), ("policy", arrived.policy.is_some()), ("clusters", arrived.clusters.is_some()), ("services", arrived.services.is_some())] {
        if !given && !unread.iter().any(|u| u == part) {
            unread.push(part.to_string());
        }
    }
    let read = |part: &str| !unread.iter().any(|u| u == part);
    let api = arrived.api.unwrap_or_default();
    let policy = arrived.policy.unwrap_or_default();
    let clusters = arrived.clusters.unwrap_or_default();
    let services = arrived.services.unwrap_or_default();
    // A rule with nothing to judge is set aside first: it is neither passed nor "not assessed".
    let moot = not_applicable(read("api").then_some(&api), read("clusters").then_some(clusters.as_slice()), read("services").then_some(services.as_slice()));
    let is_moot = |rule: &str| moot.iter().any(|(r, _)| *r == rule);
    let undecided: Vec<(&str, String)> = undecided(read("api").then_some(&api), read("policy").then_some(&policy), read("clusters").then_some(clusters.as_slice()), read("services").then_some(services.as_slice())).into_iter().filter(|(rule, _)| !is_moot(rule)).collect();
    let not_assessed: Vec<&str> = RULES.iter().filter(|r| !is_moot(r.id) && (r.needs.iter().any(|n| !read(n)) || undecided.iter().any(|(rule, _)| *rule == r.id))).map(|r| r.id).collect();
    let all: Vec<Finding> = check(&api, &policy, &clusters, &services).into_iter().filter(|f| !not_assessed.contains(&f.rule) && !is_moot(f.rule)).collect();
    if all.len() > MAX_FINDINGS {
        return Err(format!("the check found more than {MAX_FINDINGS} things; reporting some of them would hide the rest"));
    }
    let passed: Vec<&str> = RULES.iter().map(|r| r.id).filter(|id| !not_assessed.contains(id) && !is_moot(id) && !all.iter().any(|f| f.rule == *id)).collect();
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
    serde_json::to_string(&serde_json::json!({
        "kind": "security_check", "check": CHECK, "title": TITLE, "project": arrived.project,
        // Clean only when no rule matched and every rule was assessed or had nothing to judge.
        "clean": findings.is_empty() && not_assessed.is_empty(),
        "worst": worst,
        "findings": listed(&findings), "accepted": listed(&accepted), "passed": passed, "not_assessed": not_assessed,
        // Why a rule is not assessed although its part was read.
        "undecided": undecided.iter().map(|(rule, why)| serde_json::json!({ "rule": rule, "why": why })).collect::<Vec<_>>(),
        // The rules that had nothing to judge, and why: never counted as passed.
        "not_applicable": moot.iter().map(|(rule, why)| serde_json::json!({ "rule": rule, "why": why })).collect::<Vec<_>>(),
        "not_judged": NOT_JUDGED.len(),
        // Drawn only when the clusters, the services and the policy were read (the policy is not needed
        // with the API off: no rule applies then); otherwise its rows are absent, never partial.
        "table": {
            "title": "Where images are deployed",
            "columns": ["Runs on", "Name", "Enforces Binary Authorization", "Rule that applies", "Evaluation", "Enforcement"],
            "rows": if read("clusters") && read("services") && (read("policy") || api_off(read("api").then_some(&api))) { serde_json::json!(table(api_off(read("api").then_some(&api)), &policy, &clusters, &services)) } else { serde_json::Value::Null },
        },
        "counted": { "rules": policy.rules.len(), "exempt_patterns": policy.exempt_patterns.len(), "clusters": clusters.len(), "services": services.len() },
        "unread": unread,
    }))
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
use super::*;
use serde_json::{json, Value};

const P: &str = "example-np";

fn check_of(evidence: Value) -> Value {
    serde_json::from_str(&run(json!({"input": evidence}).to_string()).unwrap()).unwrap()
}
fn found(out: &Value) -> Vec<(String, String, String)> {
    out["findings"].as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["severity"].as_str().unwrap().to_string(), f["subject"].as_str().unwrap().to_string())).collect()
}
fn of_rule(out: &Value, rule: &str) -> Vec<(String, String)> {
    found(out).into_iter().filter(|(r, _, _)| r == rule).map(|(_, s, subject)| (s, subject)).collect()
}
fn names(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect()
}
fn rule(scope: &str, applies_to: &str, evaluation: &str, enforcement: &str) -> Value {
    json!({"scope": scope, "applies_to": applies_to, "evaluation": evaluation, "enforcement": enforcement})
}
fn enforced_default() -> Value {
    rule("default", "", "REQUIRE_ATTESTATION", "ENFORCED_BLOCK_AND_AUDIT_LOG")
}
fn cluster(location: &str, name: &str, evaluation: &str) -> Value {
    json!({"location": location, "name": name, "evaluation": evaluation, "legacy_enabled": false})
}
fn service(location: &str, name: &str, binauthz: &str) -> Value {
    json!({"location": location, "name": name, "binauthz": binauthz})
}
/// Evidence whose policy holds `rules` and `patterns`, for `clusters`, with the API on and one
/// Cloud Run service on the project's policy.
fn evidence(rules: Value, patterns: Value, clusters: Value) -> Value {
    with_services(evidence_api("ENABLED", rules, patterns, clusters), json!([service("us-central1", "api", "default")]))
}
fn evidence_api(state: &str, rules: Value, patterns: Value, clusters: Value) -> Value {
    json!({"kind": "binauthz_evidence", "project": P, "api": {"state": state}, "policy": {"rules": rules, "exempt_patterns": patterns}, "clusters": clusters, "services": [], "unread": []})
}
fn with_services(mut e: Value, services: Value) -> Value {
    e["services"] = services;
    e
}
fn moot(out: &Value) -> Vec<&str> {
    out["not_applicable"].as_array().unwrap().iter().map(|n| n["rule"].as_str().unwrap()).collect()
}
/// A policy that holds every image to an attestation, and one cluster that enforces it.
fn sound() -> Value {
    evidence(json!([enforced_default()]), json!(["registry.example/base/*"]), json!([cluster("us-central1", "apps", "PROJECT_SINGLETON_POLICY_ENFORCE")]))
}

#[test]
fn every_rule_cites_the_headings_it_rests_on_and_the_catalogue_needs_no_evidence() {
    let out: Value = serde_json::from_str(&run(json!({"config": {"CATALOGUE_ONLY": true}}).to_string()).unwrap()).unwrap();
    assert_eq!((out["kind"].as_str(), out["check"].as_str()), (Some("security_catalogue"), Some("binary-authorization")));
    let cat = &out["catalogue"];
    let listed = cat["rules"].as_array().unwrap();
    assert_eq!(listed.len(), RULES.len());
    let rule = |id: &str| listed.iter().find(|r| r["rule"] == id).unwrap().clone();
    let headings = |id: &str| -> Vec<String> { rule(id)["sources"].as_array().unwrap().iter().map(|c| c["heading"].as_str().unwrap().to_string()).collect() };
    // Every rule rests on a heading that was read.
    assert!(listed.iter().all(|r| r["basis"] == "published guidance" && !r["sources"].as_array().unwrap().is_empty()));
    // A rule that came to cite nothing would say it is this module's own judgement.
    assert_eq!((basis(&[]), basis(&[json!({})])), ("local judgement", "published guidance"));
    assert_eq!(headings("default-rule-allows-all"), ["Set the default rule", "defaultAdmissionRule"]);
    assert_eq!(headings("specific-rule-allows-all"), ["clusterAdmissionRules", "Specific rules", "Evaluation modes"]);
    assert_eq!(headings("rule-dry-run"), ["Enforcement modes", "Disable dry-run mode"]);
    assert_eq!(headings("exempts-every-image"), ["admissionWhitelistPatterns", "Exempt images"]);
    assert_eq!(headings("cluster-not-enforcing"), ["Enable enforcement"]);
    assert_eq!(headings("binauthz-api-off"), ["Before you begin", "Before you begin", "State"]);
    assert_eq!(headings("cloud-run-not-enforcing"), ["Enable Binary Authorization on an existing Cloud Run service", "Policies applied to Cloud Run services"]);
    assert_eq!(rule("binauthz-api-off")["sources"][1]["url"], "https://docs.cloud.google.com/binary-authorization/docs/run/enabling-binauthz-cloud-run");
    assert_eq!(rule("binauthz-api-off")["sources"][2]["url"], "https://docs.cloud.google.com/service-usage/docs/reference/rest/v1/services#State");
    assert_eq!(rule("cloud-run-not-enforcing")["sources"][1]["url"], "https://docs.cloud.google.com/binary-authorization/docs/run/overview");
    // A fragment is given only where the page showed one.
    assert_eq!(rule("default-rule-allows-all")["sources"][1]["url"], "https://docs.cloud.google.com/binary-authorization/docs/policy-yaml-reference#defaultadmissionrule");
    assert_eq!(rule("default-rule-allows-all")["sources"][0]["url"], "https://docs.cloud.google.com/binary-authorization/docs/configuring-policy-console");
    assert_eq!(rule("exempts-every-image")["sources"][0]["url"], "https://docs.cloud.google.com/binary-authorization/docs/policy-yaml-reference");
    assert_eq!(rule("cluster-not-enforcing")["sources"][0]["url"], "https://docs.cloud.google.com/binary-authorization/docs/enable-cluster");
    assert!(listed.iter().all(|r| r["task"].as_str().is_some_and(|t| !t.is_empty()) && r["remedy"].as_str().is_some_and(|t| !t.is_empty())));
    assert_eq!(cat["documents"].as_array().unwrap().len(), DOCS.len());
    assert_eq!((cat["products"][0]["id"].as_str(), cat["products"][1]["id"].as_str()), (Some("deployment-table"), Some("not-applicable")));
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
    let limits = |id: &str| out["catalogue"]["rules"].as_array().unwrap().iter().find(|r| r["rule"] == id).unwrap()["limits"].as_array().unwrap().len();
    assert_eq!((limits("cluster-not-enforcing"), limits("cloud-run-not-enforcing"), limits("binauthz-api-off")), (4, 5, 2));
    assert_eq!((limits("default-rule-allows-all"), limits("rule-dry-run"), limits("exempts-every-image")), (1, 1, 1));
    assert_eq!(limits("specific-rule-allows-all"), 0);
    // Every limit names a rule that exists.
    assert!(LIMITS.iter().all(|(id, _)| RULES.iter().any(|r| r.id == *id)));
}

#[test]
fn a_policy_that_holds_images_to_attestations_and_a_cluster_that_enforces_it_is_clean() {
    let out = check_of(sound());
    assert_eq!(out["clean"], true, "{out}");
    assert_eq!(out["findings"], json!([]));
    assert_eq!(names(&out["passed"]).len(), RULES.len());
    assert_eq!((out["not_assessed"].clone(), out["undecided"].clone()), (json!([]), json!([])));
    assert_eq!((out["project"].as_str(), out["worst"].clone()), (Some(P), Value::Null));
    assert_eq!(out["not_applicable"], json!([]));
    assert_eq!(out["table"]["rows"], json!([
        ["GKE cluster", "us-central1/apps", "yes", "the default rule", "REQUIRE_ATTESTATION", "ENFORCED_BLOCK_AND_AUDIT_LOG"],
        ["Cloud Run service", "us-central1/api", "yes", "the default rule", "REQUIRE_ATTESTATION", "ENFORCED_BLOCK_AND_AUDIT_LOG"],
    ]));
}

#[test]
fn a_default_rule_that_admits_every_image_is_found_whatever_it_enforces() {
    for enforcement in ["ENFORCED_BLOCK_AND_AUDIT_LOG", "DRYRUN_AUDIT_LOG_ONLY", ""] {
        let out = check_of(evidence(json!([rule("default", "", "ALWAYS_ALLOW", enforcement)]), json!([]), json!([])));
        assert_eq!(found(&out), [("default-rule-allows-all".to_string(), "high".to_string(), "default rule".to_string())], "{enforcement}: {out}");
        // A rule that admits everything has nothing to log either: it is not also reported as dry-run.
        assert!(names(&out["passed"]).contains(&"rule-dry-run"), "{out}");
        assert_eq!(out["worst"], "high");
    }
    // Requiring attestations, or denying, is a policy defined.
    for evaluation in ["REQUIRE_ATTESTATION", "ALWAYS_DENY"] {
        let out = check_of(evidence(json!([rule("default", "", evaluation, "ENFORCED_BLOCK_AND_AUDIT_LOG")]), json!([]), json!([])));
        assert!(of_rule(&out, "default-rule-allows-all").is_empty() && names(&out["passed"]).contains(&"default-rule-allows-all"), "{out}");
    }
}

#[test]
fn a_rule_for_one_target_that_admits_every_image_is_found_for_each_kind_of_target() {
    for scope in SPECIFIC {
        let out = check_of(evidence(json!([enforced_default(), rule(scope, "us-central1.apps", "ALWAYS_ALLOW", "ENFORCED_BLOCK_AND_AUDIT_LOG")]), json!([]), json!([])));
        assert_eq!(found(&out), [("specific-rule-allows-all".to_string(), "medium".to_string(), format!("{scope} rule us-central1.apps"))], "{out}");
        assert!(names(&out["passed"]).contains(&"default-rule-allows-all"));
    }
    let out = check_of(evidence(json!([enforced_default(), rule("cluster", "us-central1.apps", "REQUIRE_ATTESTATION", "ENFORCED_BLOCK_AND_AUDIT_LOG")]), json!([]), json!([])));
    assert_eq!(out["clean"], true, "{out}");
}

#[test]
fn a_rule_in_dry_run_is_found_and_the_default_one_is_the_more_serious() {
    let out = check_of(evidence(
        json!([rule("default", "", "REQUIRE_ATTESTATION", "DRYRUN_AUDIT_LOG_ONLY"), rule("cluster", "us-east1.batch", "ALWAYS_DENY", "DRYRUN_AUDIT_LOG_ONLY"), rule("namespace", "jobs", "REQUIRE_ATTESTATION", "ENFORCED_BLOCK_AND_AUDIT_LOG")]),
        json!([]),
        json!([]),
    ));
    assert_eq!(of_rule(&out, "rule-dry-run"), [("high".to_string(), "default rule".to_string()), ("medium".to_string(), "cluster rule us-east1.batch".to_string())]);
    assert_eq!(found(&out).len(), 2, "{out}");
}

#[test]
fn an_exempt_pattern_made_only_of_wildcards_is_found_and_a_registry_path_is_not() {
    let out = check_of(evidence(json!([enforced_default()]), json!(["*", "**", " */** ", "registry.example/team/**", "", "docker.example/*", "*/*"]), json!([])));
    assert_eq!(of_rule(&out, "exempts-every-image"), [("high".to_string(), "exempt pattern **".to_string()), ("high".to_string(), "exempt pattern */**".to_string())]);
    // A finding says where its rule comes from.
    let f = out["findings"].as_array().unwrap().iter().find(|f| f["rule"] == "exempts-every-image").unwrap().clone();
    assert_eq!((f["basis"].as_str(), f["sources"][1]["heading"].as_str()), (Some("published guidance"), Some("Exempt images")));
    assert_eq!(out["not_judged"], NOT_JUDGED.len());
}

#[test]
fn a_cluster_that_does_not_apply_the_policy_is_found_and_one_that_does_is_not() {
    let legacy = |on: bool, evaluation: &str| json!({"location": "europe-west1-b", "name": format!("legacy-{on}-{}", evaluation.len()), "evaluation": evaluation, "legacy_enabled": on});
    let out = check_of(evidence(
        json!([enforced_default()]),
        json!([]),
        json!([
            cluster("us-central1", "off", "DISABLED"),
            cluster("us-central1", "watching", "POLICY_BINDINGS"),
            cluster("us-central1", "single", "PROJECT_SINGLETON_POLICY_ENFORCE"),
            cluster("us-central1", "both", "POLICY_BINDINGS_AND_PROJECT_SINGLETON_POLICY_ENFORCE"),
            legacy(true, ""),
            legacy(false, ""),
            legacy(true, "EVALUATION_MODE_UNSPECIFIED"),
            legacy(false, "EVALUATION_MODE_UNSPECIFIED"),
        ]),
    ));
    let subjects: Vec<String> = of_rule(&out, "cluster-not-enforcing")
        .into_iter()
        .map(|(severity, subject)| {
            assert_eq!(severity, "high");
            subject
        })
        .collect();
    assert_eq!(subjects, ["cluster us-central1/off", "cluster us-central1/watching", "cluster europe-west1-b/legacy-false-0", "cluster europe-west1-b/legacy-false-27"]);
    let says: Vec<&str> = out["findings"].as_array().unwrap().iter().map(|f| f["says"].as_str().unwrap()).collect();
    assert!(says[0].starts_with("has Binary Authorization turned off") && says[1].contains("continuous validation"), "{says:?}");
}

#[test]
fn a_project_with_no_gke_cluster_says_so_and_can_still_be_clean() {
    let out = check_of(evidence(json!([enforced_default()]), json!([]), json!([])));
    // Nothing to judge is not good news: the cluster rule is neither passed nor "not assessed", and says why.
    assert!(!names(&out["passed"]).contains(&"cluster-not-enforcing"), "{out}");
    assert_eq!((moot(&out), out["not_assessed"].clone()), (vec!["cluster-not-enforcing"], json!([])));
    assert_eq!(out["not_applicable"][0]["why"], "the project has no GKE cluster, so there was nothing for this rule to judge");
    // Every other rule was assessed and passed, so the result is clean.
    assert_eq!((out["clean"].clone(), names(&out["passed"]).len()), (json!(true), RULES.len() - 1), "{out}");
    // A cluster listing that was not read is not "no cluster".
    let mut e = evidence(json!([enforced_default()]), json!([]), json!([]));
    e["unread"] = json!(["clusters"]);
    let out = check_of(e);
    assert_eq!((names(&out["not_assessed"]), moot(&out)), (vec!["cluster-not-enforcing"], vec![]));
    // No Cloud Run service either: the same, for the service rule.
    let out = check_of(with_services(evidence(json!([enforced_default()]), json!([]), json!([])), json!([])));
    assert_eq!((moot(&out), out["clean"].clone()), (vec!["cluster-not-enforcing", "cloud-run-not-enforcing"], json!(true)));
    assert_eq!(out["not_applicable"][1]["why"], "the project has no Cloud Run service, so there was nothing for this rule to judge");
    assert_eq!(out["table"]["rows"], json!([]));
}

#[test]
fn a_cluster_that_does_not_say_leaves_the_rule_undecided_and_drops_what_it_found_on_the_others() {
    for unclear in [json!({"location": "us-central1", "name": "quiet", "evaluation": ""}), json!({"location": "us-central1", "name": "quiet", "evaluation": "SOMETHING_NEW", "legacy_enabled": true})] {
        let out = check_of(evidence(json!([enforced_default()]), json!([]), json!([cluster("us-central1", "off", "DISABLED"), unclear.clone()])));
        assert_eq!(names(&out["not_assessed"]), ["cluster-not-enforcing"], "{unclear}: {out}");
        assert!(of_rule(&out, "cluster-not-enforcing").is_empty(), "half a result is never reported: {out}");
        assert_eq!(out["undecided"][0]["rule"], "cluster-not-enforcing");
        let why = out["undecided"][0]["why"].as_str().unwrap();
        assert!(why.starts_with("1 of 2 clusters do not say") && why.contains("us-central1/quiet"), "{why}");
        assert_eq!(out["clean"], false);
        assert_eq!(out["table"]["rows"][1][2], "not said");
    }
}

#[test]
fn a_policy_without_exactly_one_default_rule_is_not_the_whole_policy() {
    for rules in [json!([rule("cluster", "us-central1.apps", "REQUIRE_ATTESTATION", "DRYRUN_AUDIT_LOG_ONLY")]), json!([enforced_default(), rule("default", "", "ALWAYS_ALLOW", "ENFORCED_BLOCK_AND_AUDIT_LOG")])] {
        let out = check_of(evidence(rules.clone(), json!([]), json!([])));
        assert_eq!(names(&out["not_assessed"]), ["default-rule-allows-all", "rule-dry-run"], "{rules}: {out}");
        assert_eq!(found(&out), [], "{out}");
        assert!(out["undecided"][0]["why"].as_str().unwrap().contains("default rules"));
        // The rules that do not need the default are still judged.
        assert!(names(&out["passed"]).contains(&"specific-rule-allows-all"));
    }
}

#[test]
fn a_mode_the_check_does_not_know_leaves_the_rules_that_need_it_undecided() {
    // An unknown evaluation on a rule for one target: whether it admits everything, and whether it only logs, are both unknown.
    let out = check_of(evidence(json!([rule("default", "", "ALWAYS_ALLOW", ""), rule("cluster", "us-central1.apps", "ALLOW_SOMETIMES", "DRYRUN_AUDIT_LOG_ONLY")]), json!([]), json!([])));
    assert_eq!(names(&out["not_assessed"]), ["specific-rule-allows-all", "rule-dry-run"], "{out}");
    assert_eq!(found(&out), [("default-rule-allows-all".to_string(), "high".to_string(), "default rule".to_string())]);
    // An unknown evaluation on the default rule.
    let out = check_of(evidence(json!([rule("default", "", "", "ENFORCED_BLOCK_AND_AUDIT_LOG")]), json!([]), json!([])));
    assert_eq!(names(&out["not_assessed"]), ["default-rule-allows-all", "rule-dry-run"], "{out}");
    // An unknown enforcement matters only to a rule that holds images to something.
    let out = check_of(evidence(json!([rule("default", "", "REQUIRE_ATTESTATION", "LOG_A_LITTLE")]), json!([]), json!([])));
    assert_eq!(names(&out["not_assessed"]), ["rule-dry-run"], "{out}");
    assert!(out["undecided"][0]["why"].as_str().unwrap().contains("enforcement mode"));
    let out = check_of(evidence(json!([enforced_default(), rule("namespace", "jobs", "ALWAYS_ALLOW", "LOG_A_LITTLE")]), json!([]), json!([])));
    assert_eq!((out["not_assessed"].clone(), of_rule(&out, "specific-rule-allows-all").len()), (json!([]), 1), "{out}");
}

#[test]
fn a_rule_for_a_kind_of_target_the_check_does_not_know_is_undecided() {
    let out = check_of(evidence(json!([enforced_default(), rule("node_pool", "pool-a", "ALWAYS_ALLOW", "DRYRUN_AUDIT_LOG_ONLY")]), json!([]), json!([])));
    assert_eq!(names(&out["not_assessed"]), ["specific-rule-allows-all", "rule-dry-run"], "{out}");
    assert!(out["undecided"][0]["why"].as_str().unwrap().contains("node_pool"));
    assert_eq!(found(&out), []);
}

#[test]
fn a_part_that_was_not_read_is_not_assessed_and_its_findings_are_dropped() {
    // Named unread although it arrived.
    let mut e = evidence(json!([rule("default", "", "ALWAYS_ALLOW", "")]), json!([]), json!([cluster("us-central1", "off", "DISABLED")]));
    e["unread"] = json!(["clusters"]);
    let out = check_of(e);
    assert_eq!(names(&out["not_assessed"]), ["cluster-not-enforcing"]);
    assert_eq!(found(&out), [("default-rule-allows-all".to_string(), "high".to_string(), "default rule".to_string())]);
    assert_eq!((out["clean"].clone(), out["table"]["rows"].clone()), (json!(false), Value::Null));
    // Missing from the evidence: the same as unread.
    let mut e = sound();
    e.as_object_mut().unwrap().remove("policy");
    let out = check_of(e);
    assert_eq!(names(&out["not_assessed"]), ["default-rule-allows-all", "specific-rule-allows-all", "rule-dry-run", "exempts-every-image"]);
    assert_eq!(names(&out["unread"]), ["policy"]);
    assert_eq!((out["clean"].clone(), names(&out["passed"])), (json!(false), vec!["binauthz-api-off", "cluster-not-enforcing", "cloud-run-not-enforcing"]));
    // With the API on, the table needs the policy.
    assert_eq!(out["table"]["rows"], Value::Null);
    let mut e = sound();
    e.as_object_mut().unwrap().remove("clusters");
    assert_eq!(names(&check_of(e)["not_assessed"]), ["cluster-not-enforcing"]);
    // Evidence from a reader older than the API and service rules: those rules are not assessed, never passed.
    let mut e = sound();
    e.as_object_mut().unwrap().remove("api");
    e.as_object_mut().unwrap().remove("services");
    let out = check_of(e);
    assert_eq!((names(&out["not_assessed"]), names(&out["unread"])), (vec!["binauthz-api-off", "cloud-run-not-enforcing"], vec!["api", "services"]));
    assert_eq!((out["clean"].clone(), out["table"]["rows"].clone()), (json!(false), Value::Null));
    // Named unread although it arrived.
    let mut e = with_services(sound(), json!([service("us-central1", "open", "")]));
    e["api"] = json!({"state": "DISABLED"});
    e["unread"] = json!(["api", "services"]);
    let out = check_of(e);
    assert_eq!((names(&out["not_assessed"]), found(&out), moot(&out)), (vec!["binauthz-api-off", "cloud-run-not-enforcing"], vec![], vec![]), "{out}");
}

#[test]
fn the_binary_authorization_api_turned_off_is_found_and_the_policy_rules_are_moot() {
    // What the first real run met: the API off, the policy refused with it, and no GKE cluster.
    let mut e = evidence_api("DISABLED", json!([]), json!([]), json!([]));
    e.as_object_mut().unwrap().remove("policy");
    e["unread"] = json!(["policy"]);
    let out = check_of(with_services(e, json!([service("us-central1", "api", "default")])));
    assert_eq!(found(&out), [("binauthz-api-off".to_string(), "high".to_string(), "Binary Authorization API".to_string())], "{out}");
    // Not "not assessed" (the policy could not be read because there is none in effect), and never passed.
    assert_eq!(moot(&out), ["default-rule-allows-all", "specific-rule-allows-all", "rule-dry-run", "exempts-every-image", "cluster-not-enforcing"]);
    assert!(out["not_applicable"][0]["why"].as_str().unwrap().starts_with("the Binary Authorization API is off on the project"));
    assert_eq!((out["not_assessed"].clone(), names(&out["passed"]), out["clean"].clone(), out["worst"].clone()), (json!([]), vec!["cloud-run-not-enforcing"], json!(false), json!("high")));
    // The table is still drawn: no rule applies with the API off.
    assert_eq!(out["table"]["rows"], json!([["Cloud Run service", "us-central1/api", "yes", "none: the API is off", "", ""]]));
    // A policy read all the same is moot too: what its rules would have found is dropped, and so is what they could not decide.
    let out = check_of(evidence_api("DISABLED", json!([rule("default", "", "ALWAYS_ALLOW", ""), rule("node_pool", "a", "ALWAYS_ALLOW", "")]), json!(["**"]), json!([cluster("us-central1", "apps", "PROJECT_SINGLETON_POLICY_ENFORCE")])));
    assert_eq!(names(&out["passed"]), ["cluster-not-enforcing"], "{out}");
    assert_eq!((found(&out).len(), out["undecided"].clone(), moot(&out).len()), (1, json!([]), 5), "{out}");
    assert_eq!(out["table"]["rows"][0], json!(["GKE cluster", "us-central1/apps", "yes", "none: the API is off", "", ""]));
    // The API on is the API on.
    let out = check_of(sound());
    assert!(names(&out["passed"]).contains(&"binauthz-api-off") && moot(&out).is_empty());
}

#[test]
fn an_api_state_that_is_neither_on_nor_off_is_undecided_and_moots_nothing() {
    for state in ["", "STATE_UNSPECIFIED", "disabled", "SOMETHING_NEW"] {
        let mut e = sound();
        e["api"] = json!({"state": state});
        let out = check_of(e);
        assert_eq!((names(&out["not_assessed"]), moot(&out)), (vec!["binauthz-api-off"], vec![]), "{state}: {out}");
        assert_eq!(out["undecided"][0]["rule"], "binauthz-api-off");
        assert!(out["undecided"][0]["why"].as_str().unwrap().starts_with("the evidence does not say whether the Binary Authorization API is on"));
        // The policy is judged as it reads.
        assert_eq!(names(&out["passed"]).len(), RULES.len() - 1);
    }
}

#[test]
fn a_cloud_run_service_whose_setting_is_off_is_found_and_one_that_applies_a_policy_is_not() {
    let out = check_of(with_services(sound(), json!([
        service("us-central1", "api", "default"),
        service("europe-west1", "worker", "projects/example-np/platforms/cloudRun/strict"),
        service("us-central1", "preview", ""),
        service("asia-east1", "batch", ""),
    ])));
    assert_eq!(of_rule(&out, "cloud-run-not-enforcing"), [("high".to_string(), "Cloud Run service us-central1/preview".to_string()), ("high".to_string(), "Cloud Run service asia-east1/batch".to_string())], "{out}");
    let f = out["findings"].as_array().unwrap().iter().find(|f| f["rule"] == "cloud-run-not-enforcing").unwrap().clone();
    assert!(f["says"].as_str().unwrap().starts_with("has its Binary Authorization setting off"));
    assert_eq!(f["sources"][0]["heading"], "Enable Binary Authorization on an existing Cloud Run service");
    let rows: Vec<Value> = out["table"]["rows"].as_array().unwrap().iter().filter(|r| r[0] == "Cloud Run service").cloned().collect();
    assert_eq!(rows, [
        json!(["Cloud Run service", "us-central1/api", "yes", "the default rule", "REQUIRE_ATTESTATION", "ENFORCED_BLOCK_AND_AUDIT_LOG"]),
        json!(["Cloud Run service", "europe-west1/worker", "yes", "platform policy strict", "", ""]),
        json!(["Cloud Run service", "us-central1/preview", "no", "none", "", ""]),
        json!(["Cloud Run service", "asia-east1/batch", "no", "none", "", ""]),
    ]);
    let out = check_of(with_services(sound(), json!([service("us-central1", "api", "default"), service("europe-west1", "worker", "projects/123456789012/platforms/cloudRun/strict")])));
    assert_eq!(out["clean"], true, "{out}");
}

#[test]
fn a_cloud_run_service_whose_setting_cannot_be_read_leaves_the_rule_undecided_and_drops_what_it_found() {
    let unclear = [
        json!({"location": "us-central1", "name": "quiet"}),
        service("us-central1", "quiet", "Default"),
        service("us-central1", "quiet", "projects/example-np/platforms/gke/strict"),
        service("us-central1", "quiet", "projects//platforms/cloudRun/strict"),
        service("us-central1", "quiet", "projects/example-np/platforms/cloudRun/"),
        service("us-central1", "quiet", "projects/example-np/platforms/cloudRun/a b"),
        service("us-central1", "quiet", "projects/example-np/platforms/cloudRun/strict/extra"),
        service("", "quiet", "default"),
        service("us-central1", " ", "default"),
    ];
    for u in unclear {
        let out = check_of(with_services(sound(), json!([service("us-central1", "open", ""), u.clone()])));
        assert_eq!(names(&out["not_assessed"]), ["cloud-run-not-enforcing"], "{u}: {out}");
        assert!(of_rule(&out, "cloud-run-not-enforcing").is_empty(), "half a result is never reported: {out}");
        let why = out["undecided"][0]["why"].as_str().unwrap();
        assert!(why.starts_with("1 of 2 Cloud Run services have a Binary Authorization setting this check cannot read"), "{why}");
        assert_eq!((out["clean"].clone(), out["table"]["rows"][2][2].clone()), (json!(false), json!("not said")));
    }
}

#[test]
fn evidence_that_is_missing_or_not_plain_is_refused() {
    let err = |input: Value| run(json!({"input": input}).to_string()).unwrap_err();
    assert_eq!(run(json!({}).to_string()).unwrap_err(), "the evidence did not arrive");
    let mut wrong = sound();
    wrong["kind"] = json!("wif_evidence");
    assert_eq!(err(wrong), "the evidence did not arrive");
    let mut odd = sound();
    odd["unread"] = json!(["policy", "nodes"]);
    assert_eq!(err(odd), "the evidence names a part this check does not know");
    for project in ["", "Example-NP", "ex", "example project", "example-np/../x"] {
        let mut e = sound();
        e["project"] = json!(project);
        assert_eq!(err(e), "the evidence does not name its project plainly", "{project}");
    }
}

#[test]
fn an_accepted_finding_is_matched_exactly_severity_and_all() {
    let e = evidence(json!([rule("default", "", "ALWAYS_ALLOW", "")]), json!([]), json!([]));
    let with = |accepted: Value| -> Value { serde_json::from_str(&run(json!({"config": {"ACCEPTED": accepted}, "input": e.clone()}).to_string()).unwrap()).unwrap() };
    let out = with(json!(["default-rule-allows-all:high:default rule"]));
    assert_eq!((out["findings"].clone(), out["accepted"][0]["rule"].clone(), out["clean"].clone()), (json!([]), json!("default-rule-allows-all"), json!(true)));
    let out = with(json!(["default-rule-allows-all:medium:default rule"]));
    assert_eq!(found(&out).len(), 1);
    let many: Vec<String> = (0..21).map(|n| format!("x:low:{n}")).collect();
    assert_eq!(run(json!({"config": {"ACCEPTED": many}, "input": e}).to_string()).unwrap_err(), "ACCEPTED holds at most twenty findings");
}

#[test]
fn more_findings_than_can_be_kept_is_an_error_not_a_cut() {
    let off = |n: usize| -> Value { json!((0..n).map(|i| cluster("us-central1", &format!("c{i}"), "DISABLED")).collect::<Vec<_>>()) };
    let out = check_of(evidence(json!([enforced_default()]), json!([]), off(MAX_FINDINGS)));
    assert_eq!(found(&out).len(), MAX_FINDINGS);
    let err = run(json!({"input": evidence(json!([enforced_default()]), json!([]), off(MAX_FINDINGS + 1))}).to_string()).unwrap_err();
    assert!(err.starts_with("the check found more than 180 things"), "{err}");
}

#[test]
fn the_table_says_which_rule_applies_to_each_cluster_and_service_and_is_never_cut() {
    let out = check_of(evidence(
        json!([enforced_default(), rule("cluster", "us-east1.batch", "ALWAYS_ALLOW", "ENFORCED_BLOCK_AND_AUDIT_LOG"), rule("cluster", "us-west1.other", "ALWAYS_DENY", "DRYRUN_AUDIT_LOG_ONLY")]),
        json!([]),
        json!([cluster("us-east1", "batch", "PROJECT_SINGLETON_POLICY_ENFORCE"), cluster("us-west1", "apps", "DISABLED")]),
    ));
    assert_eq!(out["table"]["rows"], json!([
        ["GKE cluster", "us-east1/batch", "yes", "its own rule", "ALWAYS_ALLOW", "n/a"],
        ["GKE cluster", "us-west1/apps", "no", "the default rule", "REQUIRE_ATTESTATION", "ENFORCED_BLOCK_AND_AUDIT_LOG"],
        ["Cloud Run service", "us-central1/api", "yes", "the default rule", "REQUIRE_ATTESTATION", "ENFORCED_BLOCK_AND_AUDIT_LOG"],
    ]));
    // The services count towards the rows too: here one service, and clusters to fill the rest.
    let clusters_of = |n: usize| -> Value { json!((0..n).map(|i| cluster("us-central1", &format!("c{i}"), "PROJECT_SINGLETON_POLICY_ENFORCE")).collect::<Vec<_>>()) };
    assert_eq!(check_of(evidence(json!([enforced_default()]), json!([]), clusters_of(MAX_ROWS - 1)))["table"]["rows"].as_array().unwrap().len(), MAX_ROWS);
    let out = check_of(evidence(json!([enforced_default()]), json!([]), clusters_of(MAX_ROWS)));
    assert_eq!((out["clean"].clone(), out["table"]["rows"].clone()), (json!(true), Value::Null));
    let services: Vec<Value> = (0..=MAX_ROWS).map(|i| service("us-central1", &format!("s{i}"), "default")).collect();
    assert_eq!(check_of(with_services(sound(), json!(services)))["table"]["rows"], Value::Null);
}
}
