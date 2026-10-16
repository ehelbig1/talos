// gcp-binauthz-evidence: reads, from ONE Google Cloud project, the facts the
// Binary Authorization check needs: whether the Binary Authorization API is
// on, the project's policy (its default rule, its rules for particular
// clusters, namespaces, service accounts and service identities, and the
// image patterns it exempts), for each GKE cluster of the project whether it
// applies that policy, and for each Cloud Run service of the project its own
// Binary Authorization setting. It reads; every request is a GET, and the
// module is granted no other verb, so it cannot change the project whatever
// it is given.
//
// It judges nothing. It hands on evidence in the neutral shape
// `binauthz-check` reads (`kind: "binauthz_evidence"`), and a part it could
// not read is left out and named in `unread`, never handed on as empty: an
// empty list of clusters means the project has none, and an empty list of
// services that it has no Cloud Run service.
//
// Requests (all GET):
//   serviceusage.googleapis.com          the Binary Authorization API's state on the project
//   binaryauthorization.googleapis.com   the project's policy
//   container.googleapis.com             the project's clusters, in every location
//   run.googleapis.com                   the project's Cloud Run services, in every location, page by page
//
// Every part is asked for whatever another part answered: with the API off,
// the policy usually answers an error, and that is handed on as unread.
//
// A listing that says some locations could not be reached (`missingZones`
// for the clusters, `unreachable` for the services) is not the listing: that
// part is then unread.
//
// The Cloud Run services are read through the Cloud Run Admin API's v1
// (Knative) listing on the global endpoint,
// `GET https://run.googleapis.com/apis/serving.knative.dev/v1/namespaces/<project>/services`
// (https://docs.cloud.google.com/run/docs/reference/rest/v1/namespaces.services/list,
// read 2026-10-14). That page says its `unreachable` field is "for calls
// against the global endpoint" and lists "Cloud locations that could not be
// reached", which is read here as: such a call lists every region. The page
// does not say so in other words, so the first real run is to confirm it. The
// v2 listing is no shortcut: its location "cannot be the "-" wildcard", so
// it takes one request per region.
// A service's setting is its `run.googleapis.com/binary-authorization`
// annotation (accepted in "Service.metadata.annotations"), which "Enable
// Binary Authorization for Cloud Run" sets to `default`; the v2 resource's
// BinaryAuthorization says of the same setting "If False, binary
// authorization will be disabled", and names a policy as
// `projects/{project}/platforms/cloudRun/{policy-name}`. No annotation is
// handed on as "" (the setting is off); a value is handed on as it reads, for
// the check to judge. The region is the service's `cloud.googleapis.com/location`
// label (Cloud Run YAML Reference). A further page is asked for with the
// listing's `metadata.continue`, as the method's `continue` query parameter
// (the ListMeta page says `pageToken` instead; the method lists no such
// parameter, so the method's own name is used).
//
// What it hands on is bounded by its size as well as by the counts above: at
// most 300,000 bytes as written, a third of the 1,000,000 the platform takes
// as a node's input (WASM_MAX_INPUT_BYTES). A workflow's first node is given
// the run's trigger three times over (spread as its top-level keys, as
// `input` and as `__trigger_input__`), and a shadow workflow's trigger is
// this evidence: 3 × 300,000 is 900,000, and the rest is room for the node's
// config and the engine's own keys. At the counts alone the evidence could
// be some 860,000 bytes (the tests build it). The parts are counted in the
// order they are read, and one that would take the evidence over the bound
// is left out and named in `unread`, saying how large it is: never cut.
//
// The token is a short-lived one for a read-only service account, named in
// the node's config as a vault reference; this module never sees it. The
// module is granted no token path until the owner names the account. It
// needs: serviceusage.services.get, binaryauthorization.policy.get,
// container.clusters.list and run.services.list.

use serde::Deserialize;
use std::collections::BTreeMap;
use talos_sdk_macros::talos_module;

const SERVICE_USAGE: &str = "https://serviceusage.googleapis.com/v1";
const BINAUTHZ: &str = "https://binaryauthorization.googleapis.com/v1";
const CONTAINER: &str = "https://container.googleapis.com/v1";
const RUN: &str = "https://run.googleapis.com/apis/serving.knative.dev/v1";
/// More than these and the part is not read: a reader that cut them short would hand on half.
const MAX_RULES: usize = 200;
const MAX_PATTERNS: usize = 100;
const MAX_CLUSTERS: usize = 100;
const MAX_SERVICES: usize = 200;
const MAX_SERVICE_PAGES: usize = 5;
/// Where a Cloud Run service keeps its region, and its Binary Authorization setting.
const LOCATION_LABEL: &str = "cloud.googleapis.com/location";
const BINAUTHZ_ANNOTATION: &str = "run.googleapis.com/binary-authorization";
/// The most evidence this reader hands on, in bytes as written: a third of the platform's
/// 1,000,000-byte node input, since a workflow's first node is given its trigger three times
/// (3 × 300,000 = 900,000, and 100,000 left for the node's config and the engine's keys).
const MAX_EVIDENCE_BYTES: usize = 300_000;
/// What the evidence holds besides its parts (kind, project, unread, errors), set aside before
/// any part is counted. The tests measure the most it can be.
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
struct Policy {
    #[serde(default, rename = "admissionWhitelistPatterns")]
    patterns: Vec<Pattern>,
    #[serde(rename = "defaultAdmissionRule")]
    default: Option<AdmissionRule>,
    #[serde(default, rename = "clusterAdmissionRules")]
    cluster: BTreeMap<String, AdmissionRule>,
    #[serde(default, rename = "kubernetesNamespaceAdmissionRules")]
    namespace: BTreeMap<String, AdmissionRule>,
    #[serde(default, rename = "kubernetesServiceAccountAdmissionRules")]
    service_account: BTreeMap<String, AdmissionRule>,
    #[serde(default, rename = "istioServiceIdentityAdmissionRules")]
    istio_identity: BTreeMap<String, AdmissionRule>,
}
#[derive(Deserialize)]
struct Pattern {
    #[serde(default, rename = "namePattern")]
    name: String,
}
#[derive(Deserialize)]
struct AdmissionRule {
    #[serde(default, rename = "evaluationMode")]
    evaluation: String,
    #[serde(default, rename = "enforcementMode")]
    enforcement: String,
}
#[derive(Deserialize)]
struct Clusters {
    #[serde(default)]
    clusters: Vec<ClusterIn>,
    #[serde(default, rename = "missingZones")]
    missing: Vec<String>,
}
#[derive(Deserialize)]
struct ClusterIn {
    #[serde(default)]
    name: String,
    #[serde(default)]
    location: String,
    #[serde(rename = "binaryAuthorization")]
    binauthz: Option<BinAuthz>,
}
/// A cluster that has never been given this block has Binary Authorization off: that is the API's own reading.
#[derive(Deserialize)]
struct BinAuthz {
    #[serde(default)]
    enabled: bool,
    #[serde(default, rename = "evaluationMode")]
    evaluation: String,
}

#[derive(Deserialize)]
struct RunServices {
    #[serde(default)]
    items: Vec<RunService>,
    #[serde(default)]
    unreachable: Vec<String>,
    #[serde(default)]
    metadata: ListMeta,
}
#[derive(Deserialize, Default)]
struct ListMeta {
    #[serde(default, rename = "continue")]
    next: String,
}
#[derive(Deserialize)]
struct RunService {
    #[serde(default)]
    metadata: ObjectMeta,
}
#[derive(Deserialize, Default)]
struct ObjectMeta {
    #[serde(default)]
    name: String,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

/// A project id as Google writes one: it goes into request paths.
fn project_ok(s: &str) -> bool {
    (6..=30).contains(&s.len()) && s.as_bytes()[0].is_ascii_lowercase() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn shown(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}
fn pct(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// One GET. The status and the kind of failure are kept; no body of an error is.
fn get(auth: &str, url: &str) -> Result<Vec<u8>, String> {
    use talos::core::http::{self, Method, Request};
    let req = Request { method: Method::Get, url: url.to_string(), headers: vec![("Authorization".to_string(), auth.to_string()), ("Accept".to_string(), "application/json".to_string())], body: Vec::new(), timeout_ms: Some(20_000) };
    let resp = http::fetch(&req).map_err(|e| format!("could not be reached ({e:?})"))?;
    match resp.status {
        200..=299 => Ok(resp.body),
        other => Err(format!("answered HTTP {other}")),
    }
}

/// The Binary Authorization API's state, in the shape the check reads.
fn read_api(auth: &str, project: &str) -> Result<serde_json::Value, String> {
    let what = "the Binary Authorization API's state";
    let service: Service = serde_json::from_slice(&get(auth, &format!("{SERVICE_USAGE}/projects/{project}/services/binaryauthorization.googleapis.com")).map_err(|e| format!("{what} {e}"))?).map_err(|_| format!("{what} answered with something that could not be read"))?;
    Ok(serde_json::json!({ "state": shown(&service.state, 40) }))
}

/// The policy in the shape the check reads.
fn read_policy(auth: &str, project: &str) -> Result<serde_json::Value, String> {
    let policy: Policy = serde_json::from_slice(&get(auth, &format!("{BINAUTHZ}/projects/{project}/policy")).map_err(|e| format!("the policy {e}"))?).map_err(|_| "the policy answered with something that could not be read".to_string())?;
    let row = |scope: &str, applies_to: &str, r: &AdmissionRule| serde_json::json!({ "scope": scope, "applies_to": shown(applies_to, 200), "evaluation": shown(&r.evaluation, 60), "enforcement": shown(&r.enforcement, 60) });
    // A policy with no default rule is handed on without one: the check says it cannot decide on it.
    let mut rules: Vec<serde_json::Value> = policy.default.iter().map(|r| row("default", "", r)).collect();
    for (scope, listed) in [("cluster", &policy.cluster), ("namespace", &policy.namespace), ("service_account", &policy.service_account), ("istio_identity", &policy.istio_identity)] {
        rules.extend(listed.iter().map(|(target, r)| row(scope, target, r)));
    }
    if rules.len() > MAX_RULES {
        return Err(format!("the policy has more than {MAX_RULES} rules; this reader would be cutting them short"));
    }
    if policy.patterns.len() > MAX_PATTERNS {
        return Err(format!("the policy exempts more than {MAX_PATTERNS} image patterns; this reader would be cutting them short"));
    }
    Ok(serde_json::json!({ "rules": rules, "exempt_patterns": policy.patterns.iter().map(|p| shown(&p.name, 300)).collect::<Vec<_>>() }))
}

/// Every cluster of the project, in the shape the check reads.
fn read_clusters(auth: &str, project: &str) -> Result<Vec<serde_json::Value>, String> {
    let listed: Clusters = serde_json::from_slice(&get(auth, &format!("{CONTAINER}/projects/{project}/locations/-/clusters")).map_err(|e| format!("the cluster listing {e}"))?).map_err(|_| "the cluster listing answered with something that could not be read".to_string())?;
    // Half a listing is not the listing.
    if !listed.missing.is_empty() {
        return Err(format!("the cluster listing could not reach {} location(s), so it is not the whole listing", listed.missing.len()));
    }
    if listed.clusters.len() > MAX_CLUSTERS {
        return Err(format!("the project has more than {MAX_CLUSTERS} clusters; this reader would be cutting them short"));
    }
    Ok(listed
        .clusters
        .iter()
        .map(|c| {
            serde_json::json!({
                "location": shown(&c.location, 60), "name": shown(&c.name, 100),
                "evaluation": c.binauthz.as_ref().map(|b| shown(&b.evaluation, 60)).unwrap_or_default(),
                "legacy_enabled": c.binauthz.as_ref().is_some_and(|b| b.enabled),
            })
        })
        .collect())
}

/// Every Cloud Run service of the project, in every location, in the shape the check reads.
fn read_services(auth: &str, project: &str) -> Result<Vec<serde_json::Value>, String> {
    let what = "the Cloud Run service listing";
    let mut services: Vec<serde_json::Value> = Vec::new();
    let mut token = String::new();
    for page in 0.. {
        if page == MAX_SERVICE_PAGES {
            return Err(format!("{what} runs to more than {MAX_SERVICE_PAGES} pages; this reader would be cutting it short"));
        }
        let query = if token.is_empty() { String::new() } else { format!("?continue={}", pct(&token)) };
        let listed: RunServices = serde_json::from_slice(&get(auth, &format!("{RUN}/namespaces/{project}/services{query}")).map_err(|e| format!("{what} {e}"))?).map_err(|_| format!("{what} answered with something that could not be read"))?;
        // Half a listing is not the listing.
        if !listed.unreachable.is_empty() {
            return Err(format!("{what} could not reach {} location(s), so it is not the whole listing", listed.unreachable.len()));
        }
        for s in &listed.items {
            let m = &s.metadata;
            // No annotation is the setting off: handed on as "", for the check to read as such.
            services.push(serde_json::json!({
                "location": shown(m.labels.get(LOCATION_LABEL).map(String::as_str).unwrap_or(""), 60),
                "name": shown(&m.name, 100),
                "binauthz": shown(m.annotations.get(BINAUTHZ_ANNOTATION).map(String::as_str).unwrap_or(""), 300),
            }));
        }
        if services.len() > MAX_SERVICES {
            return Err(format!("the project has more than {MAX_SERVICES} Cloud Run services; this reader would be cutting them short"));
        }
        if listed.metadata.next.is_empty() {
            break;
        }
        token = listed.metadata.next;
    }
    Ok(services)
}

/// The evidence, from what each part's read gave. A part that could not be read, or that would
/// take the evidence over `MAX_EVIDENCE_BYTES`, is left out and named in `unread`.
fn evidence(project: &str, api: Result<serde_json::Value, String>, policy: Result<serde_json::Value, String>, clusters: Result<Vec<serde_json::Value>, String>, services: Result<Vec<serde_json::Value>, String>) -> serde_json::Value {
    let mut out = serde_json::json!({ "kind": "binauthz_evidence", "project": project });
    let mut unread: Vec<&str> = Vec::new();
    let mut errors = serde_json::Map::new();
    let mut budget = Budget::new();
    // A part that was not read is left out, never written as empty; one too large to hand on is not cut either.
    match api.and_then(|api| budget.take("the Binary Authorization API's state is", api)) {
        Ok(api) => out["api"] = api,
        Err(e) => {
            unread.push("api");
            errors.insert("api".to_string(), e.into());
        }
    }
    match policy.and_then(|policy| budget.take("the policy is", policy)) {
        Ok(policy) => out["policy"] = policy,
        Err(e) => {
            unread.push("policy");
            errors.insert("policy".to_string(), e.into());
        }
    }
    match clusters.and_then(|clusters| budget.take("the clusters are", clusters.into())) {
        Ok(clusters) => out["clusters"] = clusters,
        Err(e) => {
            unread.push("clusters");
            errors.insert("clusters".to_string(), e.into());
        }
    }
    match services.and_then(|services| budget.take("the Cloud Run services are", services.into())) {
        Ok(services) => out["services"] = services,
        Err(e) => {
            unread.push("services");
            errors.insert("services".to_string(), e.into());
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

    // Every part is asked for whatever another part answered.
    let api = read_api(&auth, &project);
    let policy = read_policy(&auth, &project);
    let clusters = read_clusters(&auth, &project);
    let services = read_services(&auth, &project);
    serde_json::to_string(&evidence(&project, api, policy, clusters, services)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
use super::*;
use serde_json::{json, Value};
use talos::core::http::Method;
use talos_module_testkit::host;

const P: &str = "example-np";
/// The envelope every test of this reader runs it with.
fn envelope() -> String {
    json!({"config": {"AUTH_HEADER": "Bearer vault://gcp/impersonated/reader@example-np.iam.gserviceaccount.com/access_token", "PROJECT": P}}).to_string()
}
fn read() -> Result<Value, String> {
    run(envelope()).map(|o| serde_json::from_str(&o).unwrap())
}
fn policy() -> Value {
    json!({
        "name": "projects/example-np/policy",
        "globalPolicyEvaluationMode": "ENABLE",
        "admissionWhitelistPatterns": [{"namePattern": "registry.example/base/*"}, {"namePattern": "**"}],
        "defaultAdmissionRule": {"evaluationMode": "REQUIRE_ATTESTATION", "enforcementMode": "ENFORCED_BLOCK_AND_AUDIT_LOG", "requireAttestationsBy": ["projects/example-np/attestors/built"]},
        "clusterAdmissionRules": {
            "us-east1.batch": {"evaluationMode": "ALWAYS_ALLOW", "enforcementMode": "ENFORCED_BLOCK_AND_AUDIT_LOG"},
            "us-central1.apps": {"evaluationMode": "REQUIRE_ATTESTATION", "enforcementMode": "DRYRUN_AUDIT_LOG_ONLY", "requireAttestationsBy": ["projects/example-np/attestors/built"]}
        },
        "kubernetesNamespaceAdmissionRules": {"jobs": {"evaluationMode": "ALWAYS_DENY", "enforcementMode": "ENFORCED_BLOCK_AND_AUDIT_LOG"}},
        "updateTime": "2026-01-02T03:04:05Z"
    })
}
fn clusters() -> Value {
    json!({"clusters": [
        {"name": "apps", "location": "us-central1", "status": "RUNNING", "binaryAuthorization": {"evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"}},
        {"name": "batch", "location": "us-east1", "status": "RUNNING", "binaryAuthorization": {"enabled": true}},
        {"name": "scratch", "location": "us-west1-a", "status": "RUNNING"}
    ]})
}
/// Three Cloud Run services, in two regions: one on the project's policy, one on a named
/// platform policy, one with the setting off (no annotation at all).
fn services() -> Value {
    json!({"apiVersion": "serving.knative.dev/v1", "kind": "ServiceList", "metadata": {}, "items": [
        {"apiVersion": "serving.knative.dev/v1", "kind": "Service", "metadata": {"name": "api", "namespace": "123456789012", "labels": {"cloud.googleapis.com/location": "us-central1"}, "annotations": {"run.googleapis.com/binary-authorization": "default", "run.googleapis.com/ingress": "all"}}, "spec": {"template": {"spec": {"containers": [{"image": "registry.example/api:1"}]}}}},
        {"metadata": {"name": "worker", "labels": {"cloud.googleapis.com/location": "europe-west1"}, "annotations": {"run.googleapis.com/binary-authorization": "projects/example-np/platforms/cloudRun/strict"}}},
        {"metadata": {"name": "preview", "labels": {"cloud.googleapis.com/location": "us-central1"}, "annotations": {"run.googleapis.com/ingress": "internal"}}}
    ]})
}
/// Every answer, by the host it is asked of: (status, body).
struct Answers {
    api: (u16, Value),
    policy: (u16, Value),
    clusters: (u16, Value),
    services: (u16, Value),
}
fn answers() -> Answers {
    Answers { api: (200, json!({"name": "projects/123456789012/services/binaryauthorization.googleapis.com", "state": "ENABLED"})), policy: (200, policy()), clusters: (200, clusters()), services: (200, services()) }
}
fn cloud(a: Answers) {
    host::http::respond_with(move |req| {
        let (status, body) = if req.url.contains("serviceusage.googleapis.com") {
            &a.api
        } else if req.url.contains("binaryauthorization.googleapis.com") {
            &a.policy
        } else if req.url.contains("container.googleapis.com") {
            &a.clusters
        } else {
            &a.services
        };
        Ok(host::http::response(*status, body.to_string()))
    });
}

#[test]
fn the_api_the_policy_the_clusters_and_the_services_are_read_with_gets_in_the_shape_the_check_reads() {
    cloud(answers());
    let out = read().unwrap();
    assert_eq!((out["kind"].as_str(), out["project"].as_str(), out["unread"].clone(), out["errors"].clone()), (Some("binauthz_evidence"), Some(P), json!([]), json!({})));
    assert_eq!(out["policy"], json!({
        "rules": [
            {"scope": "default", "applies_to": "", "evaluation": "REQUIRE_ATTESTATION", "enforcement": "ENFORCED_BLOCK_AND_AUDIT_LOG"},
            {"scope": "cluster", "applies_to": "us-central1.apps", "evaluation": "REQUIRE_ATTESTATION", "enforcement": "DRYRUN_AUDIT_LOG_ONLY"},
            {"scope": "cluster", "applies_to": "us-east1.batch", "evaluation": "ALWAYS_ALLOW", "enforcement": "ENFORCED_BLOCK_AND_AUDIT_LOG"},
            {"scope": "namespace", "applies_to": "jobs", "evaluation": "ALWAYS_DENY", "enforcement": "ENFORCED_BLOCK_AND_AUDIT_LOG"},
        ],
        "exempt_patterns": ["registry.example/base/*", "**"],
    }));
    // A cluster that was never given the block has it off: written as such, not left unsaid.
    assert_eq!(out["clusters"], json!([
        {"location": "us-central1", "name": "apps", "evaluation": "PROJECT_SINGLETON_POLICY_ENFORCE", "legacy_enabled": false},
        {"location": "us-east1", "name": "batch", "evaluation": "", "legacy_enabled": true},
        {"location": "us-west1-a", "name": "scratch", "evaluation": "", "legacy_enabled": false},
    ]));
    assert_eq!(out["api"], json!({"state": "ENABLED"}));
    // A service with no annotation has the setting off: handed on as "", not left unsaid.
    assert_eq!(out["services"], json!([
        {"location": "us-central1", "name": "api", "binauthz": "default"},
        {"location": "europe-west1", "name": "worker", "binauthz": "projects/example-np/platforms/cloudRun/strict"},
        {"location": "us-central1", "name": "preview", "binauthz": ""},
    ]));
    let seen = host::http::requests();
    assert_eq!(seen.len(), 4);
    assert!(seen.iter().all(|r| matches!(r.method, Method::Get) && r.body.is_empty()));
    assert_eq!(seen[0].url, format!("https://serviceusage.googleapis.com/v1/projects/{P}/services/binaryauthorization.googleapis.com"));
    assert_eq!(seen[1].url, format!("https://binaryauthorization.googleapis.com/v1/projects/{P}/policy"));
    assert_eq!(seen[2].url, format!("https://container.googleapis.com/v1/projects/{P}/locations/-/clusters"));
    assert_eq!(seen[3].url, format!("https://run.googleapis.com/apis/serving.knative.dev/v1/namespaces/{P}/services"));
    // What it hands on is what the check judges.
    let judged: Value = serde_json::from_str(&crate::binauthz_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    let found: Vec<(&str, &str)> = judged["findings"].as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap(), f["subject"].as_str().unwrap())).collect();
    assert_eq!(found, [
        ("specific-rule-allows-all", "cluster rule us-east1.batch"),
        ("rule-dry-run", "cluster rule us-central1.apps"),
        ("exempts-every-image", "exempt pattern **"),
        ("cluster-not-enforcing", "cluster us-west1-a/scratch"),
        ("cloud-run-not-enforcing", "Cloud Run service us-central1/preview"),
    ]);
    assert_eq!((judged["not_assessed"].clone(), judged["clean"].clone()), (json!([]), json!(false)));
    // This run is the template's recorded run (fixtures/): `make record-template TEMPLATE=gcp-binauthz-evidence` rewrites it.
    talos_module_testkit::recorded_run::keep("gcp-binauthz-evidence", &envelope());
}

#[test]
fn a_part_that_could_not_be_read_is_left_out_and_named_and_no_error_body_is_kept() {
    cloud(Answers { policy: (403, json!({"error": {"message": "secret-looking detail"}})), ..answers() });
    let out = read().unwrap();
    assert!(out.get("policy").is_none(), "{out}");
    assert_eq!((out["unread"].clone(), out["errors"]["policy"].clone()), (json!(["policy"]), json!("the policy answered HTTP 403")));
    assert_eq!(out["clusters"].as_array().unwrap().len(), 3);
    assert!(!out.to_string().contains("secret-looking"));
    // The check then judges the clusters and says it could not judge the policy.
    let judged: Value = serde_json::from_str(&crate::binauthz_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert_eq!(judged["not_assessed"], json!(["default-rule-allows-all", "specific-rule-allows-all", "rule-dry-run", "exempts-every-image"]));

    cloud(Answers { clusters: (500, json!({})), ..answers() });
    let out = read().unwrap();
    assert!(out.get("clusters").is_none());
    assert_eq!((out["unread"].clone(), out["errors"]["clusters"].clone()), (json!(["clusters"]), json!("the cluster listing answered HTTP 500")));

    cloud(Answers { api: (403, json!({"error": {"message": "secret-looking detail"}})), services: (403, json!({})), ..answers() });
    let out = read().unwrap();
    assert!(out.get("api").is_none() && out.get("services").is_none(), "{out}");
    assert_eq!(out["unread"], json!(["api", "services"]));
    assert_eq!((out["errors"]["api"].as_str(), out["errors"]["services"].as_str()), (Some("the Binary Authorization API's state answered HTTP 403"), Some("the Cloud Run service listing answered HTTP 403")));
    assert!(!out.to_string().contains("secret-looking"));
}

#[test]
fn with_the_api_off_every_part_is_still_asked_for_and_the_check_finds_the_api_off() {
    // What the first real run met: the API off, and the policy refused because of it.
    cloud(Answers { api: (200, json!({"state": "DISABLED"})), policy: (403, json!({"error": {"status": "PERMISSION_DENIED"}})), clusters: (200, json!({})), ..answers() });
    let out = read().unwrap();
    assert_eq!(host::http::requests().len(), 4);
    assert_eq!((out["api"].clone(), out["unread"].clone()), (json!({"state": "DISABLED"}), json!(["policy"])));
    let judged: Value = serde_json::from_str(&crate::binauthz_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    let found: Vec<&str> = judged["findings"].as_array().unwrap().iter().map(|f| f["rule"].as_str().unwrap()).collect();
    assert_eq!(found, ["binauthz-api-off", "cloud-run-not-enforcing"], "{judged}");
    // The policy's rules are moot and the cluster rule had nothing to judge: neither is passed, neither is "not assessed".
    let moot: Vec<&str> = judged["not_applicable"].as_array().unwrap().iter().map(|n| n["rule"].as_str().unwrap()).collect();
    assert_eq!(moot, ["default-rule-allows-all", "specific-rule-allows-all", "rule-dry-run", "exempts-every-image", "cluster-not-enforcing"]);
    assert_eq!((judged["not_assessed"].clone(), judged["passed"].clone(), judged["clean"].clone()), (json!([]), json!([]), json!(false)));
}

#[test]
fn a_network_failure_keeps_its_kind() {
    // No responder: every request fails as a network error would.
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["api", "policy", "clusters", "services"]));
    for (part, what) in [("api", "the Binary Authorization API's state"), ("policy", "the policy"), ("services", "the Cloud Run service listing")] {
        let why = out["errors"][part].as_str().unwrap();
        assert!(why.starts_with(&format!("{what} could not be reached (")) && why.to_lowercase().contains("network"), "{why}");
    }
}

#[test]
fn a_cluster_listing_that_missed_a_location_is_not_the_listing() {
    cloud(Answers { clusters: (200, json!({"clusters": clusters()["clusters"], "missingZones": ["asia-east1-a"]})), ..answers() });
    let out = read().unwrap();
    assert!(out.get("clusters").is_none());
    assert_eq!(out["errors"]["clusters"], "the cluster listing could not reach 1 location(s), so it is not the whole listing");
    // An empty listing is a fact: the project has no clusters.
    cloud(Answers { clusters: (200, json!({})), ..answers() });
    assert_eq!((read().unwrap()["clusters"].clone(), read().unwrap()["unread"].clone()), (json!([]), json!([])));
}

#[test]
fn a_service_listing_that_missed_a_location_is_not_the_listing_and_an_empty_one_is_a_fact() {
    cloud(Answers { services: (200, json!({"items": services()["items"], "unreachable": ["asia-east1", "me-west1"]})), ..answers() });
    let out = read().unwrap();
    assert!(out.get("services").is_none(), "{out}");
    assert_eq!((out["unread"].clone(), out["errors"]["services"].as_str()), (json!(["services"]), Some("the Cloud Run service listing could not reach 2 location(s), so it is not the whole listing")));
    // No Cloud Run service at all: a listing with no items.
    for empty in [json!({}), json!({"apiVersion": "serving.knative.dev/v1", "kind": "ServiceList", "metadata": {}})] {
        cloud(Answers { services: (200, empty), ..answers() });
        let out = read().unwrap();
        assert_eq!((out["services"].clone(), out["unread"].clone()), (json!([]), json!([])));
    }
}

#[test]
fn the_services_are_read_page_by_page_and_a_listing_too_long_to_hand_on_whole_is_unread() {
    let page = |from: usize, n: usize, next: &str| json!({"metadata": {"continue": next}, "items": (from..from + n).map(|i| json!({"metadata": {"name": format!("s{i}"), "labels": {"cloud.googleapis.com/location": "us-central1"}, "annotations": {"run.googleapis.com/binary-authorization": "default"}}})).collect::<Vec<_>>()});
    let (first, second) = (page(0, 2, "tok/en=1"), page(2, 1, ""));
    host::http::respond_with(move |req| {
        let body = if req.url.contains("serviceusage") { json!({"state": "ENABLED"}) } else if req.url.contains("binaryauthorization") { policy() } else if req.url.contains("container") { clusters() } else if req.url.ends_with("?continue=tok%2Fen%3D1") { second.clone() } else { first.clone() };
        Ok(host::http::response(200, body.to_string()))
    });
    let out = read().unwrap();
    let names: Vec<&str> = out["services"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["s0", "s1", "s2"]);
    assert_eq!(host::http::requests().last().unwrap().url, format!("https://run.googleapis.com/apis/serving.knative.dev/v1/namespaces/{P}/services?continue=tok%2Fen%3D1"));

    // A listing that never ends is cut off at its last page and handed on as unread.
    let run_calls = || host::http::requests().iter().filter(|r| r.url.contains("run.googleapis.com")).count();
    let before = run_calls();
    host::http::respond_with(move |req| Ok(host::http::response(200, if req.url.contains("run.googleapis.com") { json!({"metadata": {"continue": "more"}, "items": []}) } else { json!({}) }.to_string())));
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["services"]), "{out}");
    assert!(out["errors"]["services"].as_str().unwrap().contains("more than 5 pages"));
    assert_eq!(run_calls() - before, MAX_SERVICE_PAGES);
    // Exactly as many pages as are read is the whole listing.
    let mut asked = 0;
    host::http::respond_with(move |req| {
        let body = if req.url.contains("run.googleapis.com") {
            asked += 1;
            json!({"metadata": {"continue": if asked < MAX_SERVICE_PAGES { "more" } else { "" }}, "items": []})
        } else {
            json!({})
        };
        Ok(host::http::response(200, body.to_string()))
    });
    assert_eq!(read().unwrap()["services"], json!([]));

    // More services than can be handed on.
    let many = page(0, MAX_SERVICES + 1, "");
    cloud(Answers { services: (200, many), ..answers() });
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["services"]));
    assert!(out["errors"]["services"].as_str().unwrap().contains("more than 200 Cloud Run services"));
    cloud(Answers { services: (200, page(0, MAX_SERVICES, "")), ..answers() });
    assert_eq!(read().unwrap()["services"].as_array().unwrap().len(), MAX_SERVICES);
}

#[test]
fn an_answer_that_cannot_be_read_or_is_too_long_to_hand_on_whole_is_unread() {
    host::http::respond_with(|_| Ok(host::http::response(200, "not json")));
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["api", "policy", "clusters", "services"]));
    assert_eq!(out["errors"]["policy"], "the policy answered with something that could not be read");
    assert_eq!(out["errors"]["api"], "the Binary Authorization API's state answered with something that could not be read");
    assert_eq!(out["errors"]["services"], "the Cloud Run service listing answered with something that could not be read");
    // A field of the wrong type is an answer that could not be read: a label that is not a string, a state that is not one.
    cloud(Answers { api: (200, json!({"state": 2})), services: (200, json!({"items": [{"metadata": {"name": "api", "labels": {"cloud.googleapis.com/location": 7}}}]})), ..answers() });
    assert_eq!(read().unwrap()["unread"], json!(["api", "services"]));
    for bad in [json!({"items": [], "metadata": null}), json!({"items": [{"metadata": null}]}), json!({"items": [{"metadata": {"annotations": null}}]}), json!({"items": ["api"]}), json!({"items": [], "unreachable": [3]}), json!({"items": [], "metadata": {"continue": 1}}), json!({"items": [{"metadata": {"name": "api", "annotations": {"run.googleapis.com/ingress": 7}}}]})] {
        cloud(Answers { services: (200, bad.clone()), ..answers() });
        let out = read().unwrap();
        assert_eq!((out["unread"].clone(), out["errors"]["services"].as_str()), (json!(["services"]), Some("the Cloud Run service listing answered with something that could not be read")), "{bad}");
    }

    let many: Vec<Value> = (0..=MAX_CLUSTERS).map(|i| json!({"name": format!("c{i}"), "location": "us-central1"})).collect();
    cloud(Answers { clusters: (200, json!({"clusters": many})), ..answers() });
    assert_eq!(read().unwrap()["unread"], json!(["clusters"]));
    let just: Vec<Value> = (0..MAX_CLUSTERS).map(|i| json!({"name": format!("c{i}"), "location": "us-central1"})).collect();
    cloud(Answers { clusters: (200, json!({"clusters": just})), ..answers() });
    assert_eq!(read().unwrap()["clusters"].as_array().unwrap().len(), MAX_CLUSTERS);

    let rules: serde_json::Map<String, Value> = (0..MAX_RULES).map(|i| (format!("ns{i}"), json!({"evaluationMode": "ALWAYS_DENY", "enforcementMode": "ENFORCED_BLOCK_AND_AUDIT_LOG"}))).collect();
    let mut p = policy();
    p["kubernetesNamespaceAdmissionRules"] = Value::Object(rules);
    cloud(Answers { policy: (200, p), ..answers() });
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["policy"]));
    assert!(out["errors"]["policy"].as_str().unwrap().contains("more than 200 rules"));

    let mut p = policy();
    p["admissionWhitelistPatterns"] = json!((0..=MAX_PATTERNS).map(|i| json!({"namePattern": format!("registry.example/{i}/*")})).collect::<Vec<_>>());
    cloud(Answers { policy: (200, p), ..answers() });
    assert_eq!(read().unwrap()["unread"], json!(["policy"]));
}

#[test]
fn a_policy_without_a_default_rule_is_handed_on_without_one_and_the_check_does_not_pass_it() {
    let mut p = policy();
    p.as_object_mut().unwrap().remove("defaultAdmissionRule");
    cloud(Answers { policy: (200, p), ..answers() });
    let out = read().unwrap();
    assert!(out["policy"]["rules"].as_array().unwrap().iter().all(|r| r["scope"] != "default"));
    let judged: Value = serde_json::from_str(&crate::binauthz_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert_eq!(judged["not_assessed"], json!(["default-rule-allows-all", "rule-dry-run"]));
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
    assert!(Budget::new().take("it is", wide(room)).is_ok() && Budget::new().take("it is", wide(room + 1)).is_err());
}

#[test]
fn a_part_that_would_take_the_evidence_over_the_bound_is_left_out_and_named_never_cut() {
    let api = json!({"state": "ENABLED"});
    let policy = json!({"rules": [], "exempt_patterns": []});
    let room = MAX_EVIDENCE_BYTES - ENVELOPE_BYTES;
    // Clusters that leave exactly room for the services (none: `[]`, two bytes); one byte more and the services are what make it too large.
    let rest = room - api.to_string().len() - policy.to_string().len() - 2;
    let filling = |n: usize| -> Result<Vec<Value>, String> { Ok(vec![sized(n - 2)]) };
    let out = evidence(P, Ok(api.clone()), Ok(policy.clone()), filling(rest), Ok(vec![]));
    assert_eq!((out["unread"].clone(), out["services"].clone()), (json!([]), json!([])));
    assert!(out.to_string().len() <= MAX_EVIDENCE_BYTES);
    let out = evidence(P, Ok(api.clone()), Ok(policy.clone()), filling(rest + 1), Ok(vec![]));
    assert_eq!((out["unread"].clone(), out["errors"]["services"].as_str()), (json!(["services"]), Some("the Cloud Run services are too large to hand on (2 bytes as written; the evidence is at most 300000 bytes in all)")));
    assert!(out.get("services").is_none());
    // Each part is left out alone, and the parts after it are still handed on.
    let out = evidence(P, Ok(sized(room + 1)), Ok(policy.clone()), Ok(vec![]), Ok(vec![]));
    assert_eq!((out["unread"].clone(), out["policy"].clone()), (json!(["api"]), policy.clone()));
    assert!(out.get("api").is_none() && out["errors"]["api"].as_str().unwrap().starts_with("the Binary Authorization API's state is too large to hand on ("));
    let out = evidence(P, Ok(api.clone()), Ok(sized(room)), Ok(vec![]), Ok(vec![]));
    assert_eq!((out["unread"].clone(), out["clusters"].clone(), out["services"].clone()), (json!(["policy"]), json!([]), json!([])));
    assert!(out.get("policy").is_none() && out["errors"]["policy"].as_str().unwrap().starts_with("the policy is too large to hand on ("));
    let out = evidence(P, Ok(api.clone()), Ok(policy.clone()), filling(room), Ok(vec![]));
    assert_eq!((out["unread"].clone(), out["services"].clone()), (json!(["clusters"]), json!([])));
    assert!(out.get("clusters").is_none() && out["errors"]["clusters"].as_str().unwrap().starts_with("the clusters are too large to hand on ("));
    // A part that could not be read is not counted against the bound: it is not there.
    let out = evidence(P, Err("the Binary Authorization API's state answered HTTP 403".to_string()), Ok(policy.clone()), filling(room - policy.to_string().len() - 2), Ok(vec![]));
    assert_eq!(out["unread"], json!(["api"]));
}

#[test]
fn services_too_large_to_hand_on_are_unread_and_the_check_does_not_assess_them() {
    // As many services as are handed on, each with its longest name, region and setting: more than can be handed on.
    let mut a = answers();
    let wide = |n: usize| "😀".repeat(n);
    a.services = (200, json!({"items": (0..MAX_SERVICES).map(|i| json!({"metadata": {"name": format!("{i:03}{}", wide(97)), "labels": {LOCATION_LABEL: wide(60)}, "annotations": {BINAUTHZ_ANNOTATION: wide(300)}}})).collect::<Vec<_>>()}));
    cloud(a);
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["services"]), "{}", out["errors"]);
    // The collector, given the same answers, says the same size: the two count alike.
    assert_eq!(out["errors"]["services"], "the Cloud Run services are too large to hand on (374201 bytes as written; the evidence is at most 300000 bytes in all)");
    assert!(out.get("services").is_none() && out["clusters"].as_array().unwrap().len() == 3);
    let judged: Value = serde_json::from_str(&crate::binauthz_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert!(!judged["not_assessed"].as_array().unwrap().is_empty(), "{judged}");
}

#[test]
fn the_most_it_can_hand_on_fits_in_what_a_node_is_given_three_times() {
    // The largest evidence the counts allow: every rule, pattern, cluster and service at its longest (four bytes a character).
    let e = |n: usize| "😀".repeat(n);
    let rules: Vec<Value> = (0..MAX_RULES).map(|_| json!({"scope": "service_account", "applies_to": e(200), "evaluation": e(60), "enforcement": e(60)})).collect();
    let policy = json!({"rules": rules, "exempt_patterns": vec![e(300); MAX_PATTERNS]});
    let clusters: Vec<Value> = (0..MAX_CLUSTERS).map(|_| json!({"location": e(60), "name": e(100), "evaluation": e(60), "legacy_enabled": false})).collect();
    let services: Vec<Value> = (0..MAX_SERVICES).map(|_| json!({"location": e(60), "name": e(100), "binauthz": e(300)})).collect();
    let api = json!({"state": e(40)});
    let unbounded = json!({"kind": "binauthz_evidence", "project": "a".repeat(30), "api": api, "policy": policy, "clusters": clusters, "services": services, "unread": [], "errors": {}});
    println!("worst-case binauthz evidence at the counts alone: {} bytes", unbounded.to_string().len());
    assert!(unbounded.to_string().len() > MAX_EVIDENCE_BYTES);
    let out = evidence(&"a".repeat(30), Ok(api), Ok(policy), Ok(clusters), Ok(services));
    let bytes = out.to_string().len();
    println!("worst-case binauthz evidence handed on: {bytes} bytes");
    assert!(bytes <= MAX_EVIDENCE_BYTES && out["unread"] == json!(["policy", "services"]), "{bytes} {}", out["unread"]);
    // What the evidence holds besides its parts, at its longest, is within what is set aside for it.
    let longest = "😀".repeat(200);
    let envelope = evidence(&"a".repeat(30), Err(longest.clone()), Err(longest.clone()), Err(longest.clone()), Err(longest));
    let bytes = envelope.to_string().len();
    println!("binauthz evidence besides its parts, at most: {bytes} bytes");
    assert!(bytes <= ENVELOPE_BYTES, "{bytes}");
}
}
