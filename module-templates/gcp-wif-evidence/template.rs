// gcp-wif-evidence: collects, from ONE Google Cloud project, the facts a
// Workload Identity Federation check needs: the pools and their providers,
// who may impersonate which service account, what roles are held on the
// project, which audit logs are on, and which alerts watch which log filters. It reads; every request is a GET,
// and the module is granted no other verb, so it cannot change the project
// whatever it is given.
//
// It judges nothing. It hands on evidence in the neutral shape `wif-check`
// reads (`kind: "wif_evidence"`), and for each part it could not read it
// says so in `unread` instead of handing on an empty list: an empty list
// would read as "nothing there", and the check would pass on it.
//
// Requests (all GET):
//   iam.googleapis.com         the project's workload identity pools, then each pool's providers
//   cloudasset.googleapis.com  the IAM policies of the project and of its service accounts
//   monitoring.googleapis.com  the alert policies
//   logging.googleapis.com     the log-based metrics those policies may name
//
// What it hands on is bounded by its size: at most 300,000 bytes as written,
// a third of the 1,000,000 the platform takes as a node's input
// (WASM_MAX_INPUT_BYTES). A workflow's first node is given the run's trigger
// three times over (spread as its top-level keys, as `input` and as
// `__trigger_input__`), and a shadow workflow's trigger is this evidence:
// 3 × 300,000 is 900,000, and the rest is room for the node's config and the
// engine's own keys. Nothing else bounds it: a condition, a member or a role
// is handed on whole, and the alerts alone could be 300 × 10 filters of 600
// characters. The parts are counted in the order they are handed on
// (providers, bindings, roles, audit logs, alerts), and one that would take
// the evidence over the bound is named in `unread`, saying how large it is,
// and handed on empty as an unread part is: never cut.
//
// The token is a short-lived one for a read-only service account, named in
// the node's config as a vault reference; this module never sees it.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const IAM: &str = "https://iam.googleapis.com/v1";
const ASSETS: &str = "https://cloudasset.googleapis.com/v1";
const MONITORING: &str = "https://monitoring.googleapis.com/v3";
const LOGGING: &str = "https://logging.googleapis.com/v2";
const MAX_ALERTS: usize = 300;
const FILTER_CHARS: usize = 600;
const MAX_POOLS: usize = 25;
const MAX_PAGES: usize = 6;
const MAX_ROWS: usize = 2000;
/// The most evidence this reader hands on, in bytes as written: a third of the platform's
/// 1,000,000-byte node input, since a workflow's first node is given its trigger three times
/// (3 × 300,000 = 900,000, and 100,000 left for the node's config and the engine's keys).
const MAX_EVIDENCE_BYTES: usize = 300_000;
/// What the evidence holds besides its parts (kind, project, unread, errors, the parts' keys),
/// set aside before any part is counted. The tests measure the most it can be.
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

/// The evidence, from the parts in the order they are handed on. A part that would take the
/// evidence over `MAX_EVIDENCE_BYTES` is named in `unread` and handed on empty, as an unread part
/// is; a part already unread is empty, and is not counted.
fn evidence(project: &str, parts: Vec<(&'static str, &str, Vec<serde_json::Value>)>, mut unread: Vec<&'static str>, mut errors: serde_json::Map<String, serde_json::Value>) -> serde_json::Value {
    let mut out = serde_json::json!({ "kind": "wif_evidence", "project": project });
    let mut budget = Budget::new();
    for (name, subject, rows) in parts {
        if unread.contains(&name) {
            out[name] = rows.into();
            continue;
        }
        match budget.take(subject, rows.into()) {
            Ok(rows) => out[name] = rows,
            Err(e) => {
                unread.push(name);
                errors.insert(name.to_string(), e.into());
                out[name] = serde_json::json!([]);
            }
        }
    }
    out["unread"] = unread.into();
    out["errors"] = errors.into();
    out
}

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
}
#[derive(Deserialize, Default)]
struct Config {
    /// "Bearer " and a vault reference to `gcp/impersonated/<reader service
    /// account>/access_token`. The module is granted that one path when the
    /// account exists; until then it holds no secret and can read nothing.
    #[serde(rename = "AUTH_HEADER")]
    auth_header: Option<String>,
    /// The project to read, by id.
    #[serde(rename = "PROJECT")]
    project: Option<String>,
}

#[derive(Deserialize, Default)]
struct Pools {
    #[serde(default, rename = "workloadIdentityPools")]
    pools: Vec<Pool>,
    #[serde(rename = "nextPageToken")]
    next: Option<String>,
}
#[derive(Deserialize)]
struct Pool {
    #[serde(default)]
    name: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    disabled: bool,
}
#[derive(Deserialize, Default)]
struct Providers {
    #[serde(default, rename = "workloadIdentityPoolProviders")]
    providers: Vec<Provider>,
    #[serde(rename = "nextPageToken")]
    next: Option<String>,
}
#[derive(Deserialize)]
struct Provider {
    #[serde(default)]
    name: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    disabled: bool,
    #[serde(default, rename = "attributeCondition")]
    condition: String,
    oidc: Option<Oidc>,
    aws: Option<Aws>,
    saml: Option<Saml>,
    x509: Option<X509>,
}
/// A SAML provider trusts the identity provider its metadata describes.
#[derive(Deserialize)]
struct Saml {
    #[serde(default, rename = "idpMetadataXml")]
    metadata: String,
}
/// An X.509 provider trusts whoever holds a certificate its trust anchors issued.
#[derive(Deserialize)]
struct X509 {
    #[serde(rename = "trustStore")]
    store: Option<TrustStore>,
}
#[derive(Deserialize)]
struct TrustStore {
    #[serde(default, rename = "trustAnchors")]
    anchors: Vec<Anchor>,
}
#[derive(Deserialize)]
struct Anchor {
    #[serde(default, rename = "pemCertificate")]
    pem: String,
}

// ── shared: draft_hash (copied from modules/_shared/draft_hash.rs; edit it there, then run scripts/assemble.py) ──
/// A fingerprint of a draft's lines: SHA-256 over each line's two parts,
/// each prefixed with its length, the first 128 bits in hex. It ties an
/// approval to the exact draft that was shown: a draft that was replaced has
/// another fingerprint, and no two drafts worth making share one. It is not
/// a signature. Nothing here holds a key, so it shows that content is what
/// it was, never who kept it: the draft lives in the owner's own memory and
/// the link that carries the fingerprint is the secret.
fn draft_hash(lines: &[(&str, &str)]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for (a, b) in lines {
        // A length before each part: no choice of words can make two different lists read the same.
        hasher.update((a.len() as u64).to_le_bytes());
        hasher.update(a.as_bytes());
        hasher.update((b.len() as u64).to_le_bytes());
        hasher.update(b.as_bytes());
    }
    hasher.finalize()[..16].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A fingerprint as `draft_hash` writes one.
fn draft_hash_ok(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
// ── end shared: draft_hash ──

/// The identity provider a SAML provider trusts: the `entityID` its metadata
/// declares, and nothing else of the document. `None` when the metadata does
/// not say one plainly; the check then reports that it was not told, which
/// is not the same as being told of a different one.
fn saml_entity(metadata: &str) -> Option<String> {
    let rest = metadata[metadata.find("entityID")? + "entityID".len()..].trim_start().strip_prefix('=')?.trim_start();
    let quote = rest.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let value = &rest[1..];
    let entity = value[..value.find(quote)?].trim();
    (!entity.is_empty() && entity.len() <= 300 && !entity.chars().any(char::is_control)).then(|| entity.to_string())
}

/// Whom an X.509 provider trusts, as one value two providers can be compared
/// by: a fingerprint of its trust anchors, whatever order or line breaks
/// they were written with. The certificates themselves are not handed on.
fn x509_anchors(store: &TrustStore) -> Option<String> {
    let mut anchors: Vec<String> = store.anchors.iter().map(|a| a.pem.chars().filter(|c| !c.is_whitespace()).collect::<String>()).filter(|p| !p.is_empty()).collect();
    anchors.sort();
    anchors.dedup();
    let parts: Vec<(&str, &str)> = anchors.iter().map(|p| ("anchor", p.as_str())).collect();
    (!parts.is_empty()).then(|| draft_hash(&parts))
}
/// An AWS provider trusts one AWS account: that account is its identity provider.
#[derive(Deserialize)]
struct Aws {
    #[serde(default, rename = "accountId")]
    account: String,
}
#[derive(Deserialize)]
struct Oidc {
    #[serde(default, rename = "issuerUri")]
    issuer: String,
    #[serde(default, rename = "allowedAudiences")]
    audiences: Vec<String>,
}
#[derive(Deserialize, Default)]
struct Assets {
    #[serde(default)]
    assets: Vec<Asset>,
    #[serde(rename = "nextPageToken")]
    next: Option<String>,
}
#[derive(Deserialize)]
struct Asset {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "assetType")]
    kind: String,
    #[serde(rename = "iamPolicy")]
    policy: Option<Policy>,
}
#[derive(Deserialize, Default)]
struct Policy {
    #[serde(default)]
    bindings: Vec<PolicyBinding>,
    #[serde(default, rename = "auditConfigs")]
    audit: Vec<AuditConfig>,
}
#[derive(Deserialize)]
struct PolicyBinding {
    #[serde(default)]
    role: String,
    #[serde(default)]
    members: Vec<String>,
}
#[derive(Deserialize)]
struct AuditConfig {
    #[serde(default)]
    service: String,
    #[serde(default, rename = "auditLogConfigs")]
    logs: Vec<AuditLog>,
}
#[derive(Deserialize)]
struct AuditLog {
    #[serde(default, rename = "logType")]
    kind: String,
}

#[derive(Deserialize, Default)]
struct AlertPolicies {
    #[serde(default, rename = "alertPolicies")]
    policies: Vec<AlertPolicy>,
    #[serde(rename = "nextPageToken")]
    next: Option<String>,
}
#[derive(Deserialize)]
struct AlertPolicy {
    #[serde(default, rename = "displayName")]
    name: String,
    /// Unset means on: that is the service's own reading of a policy that does not say.
    enabled: Option<bool>,
    #[serde(default)]
    conditions: Vec<AlertCondition>,
}
#[derive(Deserialize)]
struct AlertCondition {
    #[serde(rename = "conditionMatchedLog")]
    matched_log: Option<Filtered>,
    #[serde(rename = "conditionThreshold")]
    threshold: Option<Filtered>,
    #[serde(rename = "conditionAbsent")]
    absent: Option<Filtered>,
}
#[derive(Deserialize)]
struct Filtered {
    #[serde(default)]
    filter: String,
}
#[derive(Deserialize, Default)]
struct LogMetrics {
    #[serde(default)]
    metrics: Vec<LogMetric>,
    #[serde(rename = "nextPageToken")]
    next: Option<String>,
}
#[derive(Deserialize)]
struct LogMetric {
    #[serde(default)]
    name: String,
    #[serde(default)]
    filter: String,
    #[serde(default)]
    disabled: bool,
}

/// A project id as Google writes one: it goes into request paths.
fn project_ok(s: &str) -> bool {
    (6..=30).contains(&s.len()) && s.as_bytes()[0].is_ascii_lowercase() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
/// The last part of a resource name, when it is a plain id.
fn last(name: &str) -> Option<&str> {
    name.rsplit('/').next().filter(|s| !s.is_empty() && s.len() <= 100 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)))
}
/// A page token goes back into a query: only what Google issues.
fn token_ok(t: &str) -> bool {
    !t.is_empty() && t.len() <= 2000 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_=+/.".contains(&b))
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

/// Every page of a listing, as far as `MAX_PAGES`. A listing cut short by the
/// page limit is an error: half a listing is not the listing.
fn pages<T: for<'de> Deserialize<'de>>(auth: &str, base: &str, next: fn(&T) -> Option<&String>) -> Result<Vec<T>, String> {
    let mut out: Vec<T> = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let url = match &token {
            None => base.to_string(),
            Some(t) => format!("{base}&pageToken={}", pct(t)),
        };
        let page: T = serde_json::from_slice(&get(auth, &url)?).map_err(|_| "answered with something that could not be read".to_string())?;
        token = next(&page).filter(|t| token_ok(t)).cloned();
        let more = next(&page).is_some();
        out.push(page);
        if !more {
            return Ok(out);
        }
        if token.is_none() {
            return Err("gave a page token that could not be used".to_string());
        }
    }
    Err(format!("has more than {MAX_PAGES} pages"))
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let cfg = serde_json::from_str::<Envelope>(&input).map_err(|e| format!("Input parse error: {e}"))?.config;
    let auth = cfg.auth_header.filter(|a| !a.trim().is_empty()).ok_or("Missing AUTH_HEADER config")?;
    let project = cfg.project.as_deref().map(str::trim).filter(|p| project_ok(p)).ok_or("PROJECT must be a project id (lower-case letters, digits and dashes)")?.to_string();

    let mut unread: Vec<&str> = Vec::new();
    let mut errors = serde_json::Map::new();

    // ---- pools and their providers
    let mut providers: Vec<serde_json::Value> = Vec::new();
    let read_providers = (|| -> Result<Vec<serde_json::Value>, String> {
        let mut found = Vec::new();
        let listed = pages::<Pools>(&auth, &format!("{IAM}/projects/{project}/locations/global/workloadIdentityPools?pageSize=100"), |p| p.next.as_ref()).map_err(|e| format!("the pools listing {e}"))?;
        let pools: Vec<&Pool> = listed.iter().flat_map(|p| p.pools.iter()).filter(|p| p.state != "DELETED").collect();
        if pools.len() > MAX_POOLS {
            return Err(format!("the project has more than {MAX_POOLS} pools"));
        }
        for pool in pools {
            let pool_id = last(&pool.name).ok_or("a pool has a name that could not be read")?;
            let listed = pages::<Providers>(&auth, &format!("{IAM}/projects/{project}/locations/global/workloadIdentityPools/{pool_id}/providers?pageSize=100"), |p| p.next.as_ref()).map_err(|e| format!("the providers listing of a pool {e}"))?;
            for p in listed.iter().flat_map(|l| l.providers.iter()).filter(|p| p.state != "DELETED") {
                let mut row = serde_json::json!({
                    "pool": pool_id, "provider": last(&p.name).ok_or("a provider has a name that could not be read")?,
                    "issuer": p.oidc.as_ref().map(|o| o.issuer.as_str()).unwrap_or(""),
                    "condition": p.condition,
                    "audiences": p.oidc.as_ref().map(|o| o.audiences.clone()).unwrap_or_default(),
                    // A provider of a disabled pool issues nothing.
                    "disabled": p.disabled || pool.disabled,
                });
                // Whom a provider of another kind trusts, as the issuer says it for an OpenID Connect one. Each
                // key is carried only by its own kind of provider, and only when the provider says it plainly:
                // a provider that hands on none of them leaves the check untold, and the check says so.
                if let Some(aws) = &p.aws {
                    row["aws_account"] = aws.account.as_str().into();
                }
                if let Some(entity) = p.saml.as_ref().and_then(|s| saml_entity(&s.metadata)) {
                    row["saml_entity"] = entity.into();
                }
                if let Some(anchors) = p.x509.as_ref().and_then(|x| x.store.as_ref()).and_then(x509_anchors) {
                    row["x509_anchors"] = anchors.into();
                }
                found.push(row);
            }
        }
        Ok(found)
    })();
    match read_providers {
        Ok(found) => providers = found,
        Err(e) => {
            unread.push("providers");
            errors.insert("providers".to_string(), e.into());
        }
    }

    // ---- IAM policies of the project and of its service accounts
    let (mut bindings, mut roles, mut audit): (Vec<serde_json::Value>, Vec<serde_json::Value>, Vec<serde_json::Value>) = (Vec::new(), Vec::new(), Vec::new());
    let url = format!("{ASSETS}/projects/{project}/assets?contentType=IAM_POLICY&assetTypes=iam.googleapis.com%2FServiceAccount&assetTypes=cloudresourcemanager.googleapis.com%2FProject&pageSize=500");
    match pages::<Assets>(&auth, &url, |p| p.next.as_ref()) {
        Ok(listed) => {
            let mut project_seen = false;
            for asset in listed.iter().flat_map(|l| l.assets.iter()) {
                let Some(policy) = &asset.policy else { continue };
                if asset.kind == "iam.googleapis.com/ServiceAccount" {
                    let Some(sa) = last(&asset.name) else { continue };
                    for b in &policy.bindings {
                        for m in &b.members {
                            bindings.push(serde_json::json!({ "service_account": sa, "role": b.role, "member": m }));
                        }
                    }
                } else if asset.kind == "cloudresourcemanager.googleapis.com/Project" {
                    project_seen = true;
                    for b in &policy.bindings {
                        for m in &b.members {
                            roles.push(serde_json::json!({ "member": m, "role": b.role }));
                        }
                    }
                    for a in &policy.audit {
                        audit.push(serde_json::json!({ "service": a.service, "log_types": a.logs.iter().map(|l| l.kind.as_str()).collect::<Vec<_>>() }));
                    }
                }
            }
            // A service account with no policy has no bindings: that is a fact. The project
            // always has a policy: not seeing it means its roles and audit logs were not read.
            if !project_seen {
                unread.extend(["roles", "audit_logs"]);
                errors.insert("roles".to_string(), "the project's own policy was not in the listing".into());
            }
            if bindings.len() + roles.len() > MAX_ROWS {
                return Err(format!("the project has more than {MAX_ROWS} role grants; this reader would be cutting them short"));
            }
        }
        Err(e) => {
            unread.extend(["bindings", "roles", "audit_logs"]);
            errors.insert("policies".to_string(), format!("the policies listing {e}").into());
        }
    }

    // ---- alert policies, with the log filter behind each: its own, or that of
    // the log-based metric a condition counts.
    let read_alerts = (|| -> Result<Vec<serde_json::Value>, String> {
        let metrics = pages::<LogMetrics>(&auth, &format!("{LOGGING}/projects/{project}/metrics?pageSize=200"), |p| p.next.as_ref()).map_err(|e| format!("the log metrics listing {e}"))?;
        let metrics: Vec<&LogMetric> = metrics.iter().flat_map(|p| p.metrics.iter()).filter(|m| !m.disabled && !m.name.is_empty()).collect();
        let policies = pages::<AlertPolicies>(&auth, &format!("{MONITORING}/projects/{project}/alertPolicies?pageSize=200"), |p| p.next.as_ref()).map_err(|e| format!("the alert policies listing {e}"))?;
        let cut = |f: &str| f.chars().filter(|c| !c.is_control()).take(FILTER_CHARS).collect::<String>();
        let mut found = Vec::new();
        for policy in policies.iter().flat_map(|p| p.policies.iter()) {
            let mut filters: Vec<String> = Vec::new();
            for c in &policy.conditions {
                if let Some(f) = &c.matched_log {
                    filters.push(cut(&f.filter));
                }
                for counted in [&c.threshold, &c.absent].into_iter().flatten() {
                    // A condition on a log-based metric watches whatever that metric's filter matches.
                    for m in metrics.iter().filter(|m| counted.filter.contains(&format!("logging.googleapis.com/user/{}\"", m.name)) || counted.filter.ends_with(&format!("logging.googleapis.com/user/{}", m.name))) {
                        filters.push(cut(&m.filter));
                    }
                }
            }
            filters.truncate(10);
            found.push(serde_json::json!({ "name": cut(&policy.name).chars().take(100).collect::<String>(), "enabled": policy.enabled.unwrap_or(true), "filters": filters }));
        }
        if found.len() > MAX_ALERTS {
            return Err(format!("the project has more than {MAX_ALERTS} alert policies"));
        }
        Ok(found)
    })();
    let alerts = match read_alerts {
        Ok(found) => found,
        Err(e) => {
            unread.push("alerts");
            errors.insert("alerts".to_string(), e.into());
            Vec::new()
        }
    };

    let parts = vec![
        ("providers", "the providers are", providers),
        ("bindings", "the service accounts' role grants are", bindings),
        ("roles", "the project's role grants are", roles),
        ("audit_logs", "the audit log settings are", audit),
        ("alerts", "the alert policies are", alerts),
    ];
    serde_json::to_string(&evidence(&project, parts, unread, errors)).map_err(|e| e.to_string())
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
fn pools() -> Value {
    json!({"workloadIdentityPools": [
        {"name": "projects/123/locations/global/workloadIdentityPools/tf-pool", "state": "ACTIVE"},
        {"name": "projects/123/locations/global/workloadIdentityPools/off-pool", "state": "ACTIVE", "disabled": true},
        {"name": "projects/123/locations/global/workloadIdentityPools/gone", "state": "DELETED"}]})
}
fn providers(pool: &str) -> Value {
    json!({"workloadIdentityPoolProviders": [
        {"name": format!("projects/123/locations/global/workloadIdentityPools/{pool}/providers/github"), "state": "ACTIVE", "attributeCondition": "assertion.repository == 'org/infra'",
         "attributeMapping": {"google.subject": "assertion.sub"}, "oidc": {"issuerUri": "https://token.actions.githubusercontent.com", "allowedAudiences": ["https://example.com/aud"]}},
        {"name": format!("projects/123/locations/global/workloadIdentityPools/{pool}/providers/old"), "state": "DELETED"}]})
}
fn assets() -> Value {
    json!({"assets": [
        {"name": "//iam.googleapis.com/projects/example-np/serviceAccounts/tf-admin@example-np.iam.gserviceaccount.com", "assetType": "iam.googleapis.com/ServiceAccount",
         "iamPolicy": {"bindings": [{"role": "roles/iam.workloadIdentityUser", "members": ["principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/tf-pool/attribute.repository/org/infra", "user:someone@example.com"]}]}},
        {"name": "//cloudresourcemanager.googleapis.com/projects/123", "assetType": "cloudresourcemanager.googleapis.com/Project",
         "iamPolicy": {"bindings": [{"role": "roles/resourcemanager.projectIamAdmin", "members": ["serviceAccount:tf-admin@example-np.iam.gserviceaccount.com"]}],
                       "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}, {"logType": "DATA_READ", "exemptedMembers": ["user:x@example.com"]}]}]}}]})
}
fn alert_policies() -> Value {
    json!({"alertPolicies": [
        {"displayName": "IAM policy changes", "enabled": true, "conditions": [{"conditionMatchedLog": {"filter": "protoPayload.methodName=\"SetIamPolicy\""}}]},
        {"displayName": "WIF changes", "conditions": [{"conditionThreshold": {"filter": "metric.type=\"logging.googleapis.com/user/wif-provider-changes\" AND resource.type=\"global\""}}]},
        {"displayName": "Off", "enabled": false, "conditions": [{"conditionThreshold": {"filter": "metric.type=\"logging.googleapis.com/user/disabled-metric\""}}]}]})
}
fn log_metrics() -> Value {
    json!({"metrics": [{"name": "wif-provider-changes", "filter": "protoPayload.methodName:\"WorkloadIdentityPoolProviders\""},
                       {"name": "wif-provider-changes-old", "filter": "SHOULD NOT MATCH A LONGER NAME"},
                       {"name": "disabled-metric", "filter": "x", "disabled": true}]})
}
fn cloud(pool_status: u16, asset_body: Value, asset_status: u16) {
    cloud_with_alerts(pool_status, asset_body, asset_status, 200);
}
fn cloud_with_alerts(pool_status: u16, asset_body: Value, asset_status: u16, alert_status: u16) {
    host::http::respond_with(move |req| {
        let u = &req.url;
        Ok(if u.contains("/alertPolicies?") { host::http::response(alert_status, alert_policies().to_string()) }
           else if u.contains("logging.googleapis.com") { host::http::response(200, log_metrics().to_string()) }
           else if u.contains("/assets?") { host::http::response(asset_status, asset_body.to_string()) }
           else if u.contains("/providers?") { host::http::response(200, providers(if u.contains("/tf-pool/") { "tf-pool" } else { "off-pool" }).to_string()) }
           else { host::http::response(pool_status, pools().to_string()) })
    });
}

#[test]
fn the_projects_facts_are_collected_with_gets_only_in_the_shape_the_check_reads() {
    cloud(200, assets(), 200);
    let out = read().unwrap();
    assert_eq!((out["kind"].as_str(), out["project"].as_str(), out["unread"].clone()), (Some("wif_evidence"), Some(P), json!([])));
    assert_eq!(out["providers"], json!([
        {"pool": "tf-pool", "provider": "github", "issuer": "https://token.actions.githubusercontent.com", "condition": "assertion.repository == 'org/infra'", "audiences": ["https://example.com/aud"], "disabled": false},
        {"pool": "off-pool", "provider": "github", "issuer": "https://token.actions.githubusercontent.com", "condition": "assertion.repository == 'org/infra'", "audiences": ["https://example.com/aud"], "disabled": true},
    ]));
    assert_eq!(out["bindings"].as_array().unwrap().len(), 2);
    assert_eq!(out["bindings"][0], json!({"service_account": "tf-admin@example-np.iam.gserviceaccount.com", "role": "roles/iam.workloadIdentityUser", "member": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/tf-pool/attribute.repository/org/infra"}));
    assert_eq!(out["roles"], json!([{"member": "serviceAccount:tf-admin@example-np.iam.gserviceaccount.com", "role": "roles/resourcemanager.projectIamAdmin"}]));
    assert_eq!(out["audit_logs"], json!([{"service": "allServices", "log_types": ["ADMIN_READ", "DATA_READ"]}]));
    let seen = host::http::requests();
    // The pools, each live pool's providers, the policies, the log metrics, the alerts: six requests, every one a GET with no body.
    assert_eq!(seen.len(), 6);
    assert_eq!(out["alerts"], json!([
        {"name": "IAM policy changes", "enabled": true, "filters": ["protoPayload.methodName=\"SetIamPolicy\""]},
        {"name": "WIF changes", "enabled": true, "filters": ["protoPayload.methodName:\"WorkloadIdentityPoolProviders\""]},
        {"name": "Off", "enabled": false, "filters": []},
    ]));
    assert!(seen.iter().all(|r| matches!(r.method, Method::Get) && r.body.is_empty()));
    assert_eq!(seen[0].url, format!("https://iam.googleapis.com/v1/projects/{P}/locations/global/workloadIdentityPools?pageSize=100"));
    assert_eq!(seen[3].url, format!("https://cloudasset.googleapis.com/v1/projects/{P}/assets?contentType=IAM_POLICY&assetTypes=iam.googleapis.com%2FServiceAccount&assetTypes=cloudresourcemanager.googleapis.com%2FProject&pageSize=500"));
    // What it hands on is what the check judges: the known-bad binding is found from it.
    let judged: Value = serde_json::from_str(&crate::wif_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    let found: Vec<&str> = judged["findings"].as_array().unwrap().iter().map(|f| f["rule"].as_str().unwrap()).collect();
    assert!(found.contains(&"binding-unscoped") && found.contains(&"attribute-by-name") && found.contains(&"provider-custom-audience"), "{found:?}");
    assert_eq!(judged["not_assessed"], json!([]));
    // This run is the template's recorded run (fixtures/): `make record-template TEMPLATE=gcp-wif-evidence` rewrites it.
    talos_module_testkit::recorded_run::keep("gcp-wif-evidence", &envelope());
}

#[test]
fn a_part_that_could_not_be_read_is_named_unread_and_never_handed_on_as_empty() {
    cloud(403, assets(), 200);
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["providers"].clone()), (json!(["providers"]), json!([])));
    assert_eq!(out["errors"]["providers"], "the pools listing answered HTTP 403");
    cloud(200, assets(), 500);
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["bindings", "roles", "audit_logs"]));
    // The alert policies could not be listed: that part is unread, and its rule is not assessed.
    cloud_with_alerts(200, assets(), 200, 403);
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["errors"]["alerts"].as_str()), (json!(["alerts"]), Some("the alert policies listing answered HTTP 403")));
    let judged: Value = serde_json::from_str(&crate::wif_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert_eq!(judged["not_assessed"], json!(["provider-changes-unalerted"]));
    // The project's own policy missing from the listing: its roles and audit logs were not read.
    let mut only_sa = assets();
    only_sa["assets"].as_array_mut().unwrap().pop();
    cloud(200, only_sa, 200);
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["bindings"].as_array().unwrap().len()), (json!(["roles", "audit_logs"]), 2));
    // The check then refuses to call any of it clean.
    let judged: Value = serde_json::from_str(&crate::wif_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert_eq!(judged["clean"], false);
    assert!(judged["not_assessed"].as_array().unwrap().iter().any(|r| r == "data-access-logs-off"));
    // A listing with more pages than are followed is an error, not a short list.
    host::http::respond_with(|req| Ok(if req.url.contains("/assets?") { host::http::response(200, json!({"assets": [], "nextPageToken": "abc"}).to_string()) } else { host::http::response(200, json!({}).to_string()) }));
    let out = read().unwrap();
    assert_eq!(out["errors"]["policies"], "the policies listing has more than 6 pages");
    host::http::respond_with(|_| Err(talos::core::http::Error::Timeout));
    let out = read().unwrap();
    assert!(out["errors"]["providers"].as_str().unwrap().to_lowercase().contains("timeout"));
}

#[test]
fn config_is_checked_before_any_request() {
    cloud(200, assets(), 200);
    assert_eq!(run(json!({"config": {"PROJECT": P}}).to_string()).unwrap_err(), "Missing AUTH_HEADER config");
    for bad in ["", "Example", "a/../b", "ex", "example np", "1example"] {
        assert_eq!(run(json!({"config": {"AUTH_HEADER": "Bearer x", "PROJECT": bad}}).to_string()).unwrap_err(), "PROJECT must be a project id (lower-case letters, digits and dashes)", "{bad}");
    }
    assert!(host::http::requests().is_empty());
}

#[test]
fn an_aws_provider_hands_on_the_account_it_trusts_and_the_check_reads_it() {
    // Two pools, each with an AWS provider for one account; a third pool's provider is SAML and says neither.
    let pools = json!({"workloadIdentityPools": [
        {"name": "projects/123/locations/global/workloadIdentityPools/batch-a", "state": "ACTIVE"},
        {"name": "projects/123/locations/global/workloadIdentityPools/batch-b", "state": "ACTIVE"},
        {"name": "projects/123/locations/global/workloadIdentityPools/people", "state": "ACTIVE", "disabled": true}]});
    host::http::respond_with(move |req| {
        let u = &req.url;
        Ok(if u.contains("/alertPolicies?") { host::http::response(200, alert_policies().to_string()) }
           else if u.contains("logging.googleapis.com") { host::http::response(200, log_metrics().to_string()) }
           else if u.contains("/assets?") { host::http::response(200, assets().to_string()) }
           else if u.contains("/people/providers?") { host::http::response(200, json!({"workloadIdentityPoolProviders": [{"name": "projects/123/locations/global/workloadIdentityPools/people/providers/sso", "state": "ACTIVE", "saml": {"idpMetadataXml": "<x/>"}}]}).to_string()) }
           else if u.contains("/providers?") { host::http::response(200, json!({"workloadIdentityPoolProviders": [{"name": format!("projects/123/locations/global/workloadIdentityPools/{}/providers/aws", if u.contains("/batch-a/") { "batch-a" } else { "batch-b" }), "state": "ACTIVE", "attributeCondition": "assertion.arn.startsWith('arn:aws:sts::123456789012:assumed-role/batch/')", "aws": {"accountId": "123456789012"}}]}).to_string()) }
           else { host::http::response(200, pools.to_string()) })
    });
    let out = read().unwrap();
    assert_eq!(out["providers"], json!([
        {"pool": "batch-a", "provider": "aws", "issuer": "", "aws_account": "123456789012", "condition": "assertion.arn.startsWith('arn:aws:sts::123456789012:assumed-role/batch/')", "audiences": [], "disabled": false},
        {"pool": "batch-b", "provider": "aws", "issuer": "", "aws_account": "123456789012", "condition": "assertion.arn.startsWith('arn:aws:sts::123456789012:assumed-role/batch/')", "audiences": [], "disabled": false},
        // Neither an issuer nor an account: the check is not told whom this one trusts.
        {"pool": "people", "provider": "sso", "issuer": "", "condition": "", "audiences": [], "disabled": true},
    ]));
    assert!(host::http::requests().iter().all(|r| matches!(r.method, Method::Get) && r.body.is_empty()));
    // The real check, on what the real reader handed on: one account federated twice.
    let judged: Value = serde_json::from_str(&crate::wif_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    let found: Vec<&str> = judged["findings"].as_array().unwrap().iter().filter(|f| f["rule"] == "identity-provider-federated-twice").map(|f| f["subject"].as_str().unwrap()).collect();
    assert_eq!(found, ["identity provider aws-account/123456789012"]);
}

#[test]
fn a_saml_and_an_x509_provider_hand_on_whom_they_trust_and_nothing_else_of_it() {
    // What is read out of a SAML provider's metadata: its entity id, however the attribute is quoted and spaced.
    assert_eq!(saml_entity("<md:EntityDescriptor xmlns:md=\"urn:x\" entityID=\"https://idp.example/saml\"><md:X/></md:EntityDescriptor>").as_deref(), Some("https://idp.example/saml"));
    assert_eq!(saml_entity("<EntityDescriptor entityID = ' https://idp.example/saml '>").as_deref(), Some("https://idp.example/saml"));
    // Metadata that does not say one plainly says nothing: no entity id, an empty one, an unclosed one, one with a line break, one too long.
    let long = format!("<E entityID=\"{}\">", "a".repeat(301));
    for silent in ["", "<x/>", "<E entityID=\"\">", "<E entityID=\"https://idp.example", "<E entityID=\"a\nb\">", "<E entityID>", "<E entityID=https://idp.example>", long.as_str()] {
        assert_eq!(saml_entity(silent), None, "{silent}");
    }
    // An X.509 provider's trust anchors as one value: the same anchors in another order, with other line breaks, are the same value.
    let store = |pems: &[&str]| TrustStore { anchors: pems.iter().map(|p| Anchor { pem: (*p).to_string() }).collect() };
    let one = "-----BEGIN CERTIFICATE-----\nAAA\nBBB\n-----END CERTIFICATE-----";
    let two = "-----BEGIN CERTIFICATE-----\nCCC\n-----END CERTIFICATE-----";
    // scripts/collect_wif_evidence.py takes the same fingerprint of the same anchor; its test pins the same answer.
    assert_eq!(x509_anchors(&store(&[one])).as_deref(), Some("9f21dec47026a896f6b17f3ac9c2e8d7"));
    assert_eq!(x509_anchors(&store(&[one, two])), x509_anchors(&store(&[two, "-----BEGIN CERTIFICATE-----AAA BBB-----END CERTIFICATE-----\n", one])));
    assert_ne!(x509_anchors(&store(&[one])), x509_anchors(&store(&[one, two])));
    assert_eq!((x509_anchors(&store(&[])), x509_anchors(&store(&["", "  \n"]))), (None, None));

    let pools = json!({"workloadIdentityPools": [{"name": "projects/123/locations/global/workloadIdentityPools/people", "state": "ACTIVE"}]});
    let metadata = "<md:EntityDescriptor entityID=\"https://idp.example/saml\"><md:KeyDescriptor>SECRETISH</md:KeyDescriptor></md:EntityDescriptor>";
    let providers = json!({"workloadIdentityPoolProviders": [
        {"name": "projects/123/locations/global/workloadIdentityPools/people/providers/sso", "state": "ACTIVE", "saml": {"idpMetadataXml": metadata}},
        {"name": "projects/123/locations/global/workloadIdentityPools/people/providers/sso-again", "state": "ACTIVE", "saml": {"idpMetadataXml": metadata}},
        {"name": "projects/123/locations/global/workloadIdentityPools/people/providers/devices", "state": "ACTIVE", "x509": {"trustStore": {"trustAnchors": [{"pemCertificate": one}], "intermediateCas": [{"pemCertificate": two}]}}},
        {"name": "projects/123/locations/global/workloadIdentityPools/people/providers/empty", "state": "ACTIVE", "disabled": true, "x509": {"trustStore": {}}},
    ]});
    host::http::respond_with(move |req| {
        let u = &req.url;
        Ok(if u.contains("/alertPolicies?") { host::http::response(200, alert_policies().to_string()) }
           else if u.contains("logging.googleapis.com") { host::http::response(200, log_metrics().to_string()) }
           else if u.contains("/assets?") { host::http::response(200, assets().to_string()) }
           else if u.contains("/providers?") { host::http::response(200, providers.to_string()) }
           else { host::http::response(200, pools.to_string()) })
    });
    let out = read().unwrap();
    assert_eq!(out["providers"], json!([
        {"pool": "people", "provider": "sso", "issuer": "", "saml_entity": "https://idp.example/saml", "condition": "", "audiences": [], "disabled": false},
        {"pool": "people", "provider": "sso-again", "issuer": "", "saml_entity": "https://idp.example/saml", "condition": "", "audiences": [], "disabled": false},
        {"pool": "people", "provider": "devices", "issuer": "", "x509_anchors": "9f21dec47026a896f6b17f3ac9c2e8d7", "condition": "", "audiences": [], "disabled": false},
        // A trust store with no anchor says nothing, so nothing is handed on for it.
        {"pool": "people", "provider": "empty", "issuer": "", "condition": "", "audiences": [], "disabled": true},
    ]));
    // The metadata and the certificates themselves stay where they were read.
    assert!(!out.to_string().contains("SECRETISH") && !out.to_string().contains("BEGIN CERTIFICATE"));
    // The real check, on what the real reader handed on: every live provider says whom it trusts, so the rule
    // is assessed, and the one identity provider behind two of them is found.
    let judged: Value = serde_json::from_str(&crate::wif_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert!(!judged["not_assessed"].as_array().unwrap().iter().any(|r| r == "identity-provider-federated-twice") && judged["undecided"] == json!([]));
    let found: Vec<&str> = judged["findings"].as_array().unwrap().iter().filter(|f| f["rule"] == "identity-provider-federated-twice").map(|f| f["subject"].as_str().unwrap()).collect();
    assert_eq!(found, ["identity provider saml-entity/https://idp.example/saml"]);
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

/// The five parts, in the order they are handed on, each as given.
fn five(providers: Vec<Value>, bindings: Vec<Value>, roles: Vec<Value>, audit: Vec<Value>, alerts: Vec<Value>) -> Vec<(&'static str, &'static str, Vec<Value>)> {
    vec![("providers", "the providers are", providers), ("bindings", "the service accounts' role grants are", bindings), ("roles", "the project's role grants are", roles), ("audit_logs", "the audit log settings are", audit), ("alerts", "the alert policies are", alerts)]
}

#[test]
fn a_part_that_would_take_the_evidence_over_the_bound_is_named_unread_and_handed_on_empty_never_cut() {
    let room = MAX_EVIDENCE_BYTES - ENVELOPE_BYTES;
    // A list of one value `n` bytes long as written.
    let filling = |n: usize| vec![sized(n - 2)];
    // Providers that leave exactly room for the other four parts (each `[]`, two bytes); one byte more and the alerts are what make it too large.
    let out = evidence(P, five(filling(room - 8), vec![], vec![], vec![], vec![]), vec![], serde_json::Map::new());
    assert_eq!((out["unread"].clone(), out["errors"].clone()), (json!([]), json!({})));
    assert!(out.to_string().len() <= MAX_EVIDENCE_BYTES);
    let out = evidence(P, five(filling(room - 7), vec![], vec![], vec![], vec![]), vec![], serde_json::Map::new());
    assert_eq!((out["unread"].clone(), out["errors"]["alerts"].as_str(), out["alerts"].clone()), (json!(["alerts"]), Some("the alert policies are too large to hand on (2 bytes as written; the evidence is at most 300000 bytes in all)"), json!([])));
    // Each part is named alone, and the parts after it are still handed on.
    let out = evidence(P, five(filling(room + 1), vec![json!(1)], vec![json!(2)], vec![json!(3)], vec![json!(4)]), vec![], serde_json::Map::new());
    assert_eq!((out["unread"].clone(), out["providers"].clone(), out["alerts"].clone()), (json!(["providers"]), json!([]), json!([4])));
    assert!(out["errors"]["providers"].as_str().unwrap().starts_with("the providers are too large to hand on ("));
    for (i, (name, subject)) in [("bindings", "the service accounts' role grants are"), ("roles", "the project's role grants are"), ("audit_logs", "the audit log settings are"), ("alerts", "the alert policies are")].into_iter().enumerate() {
        let mut parts = five(vec![], vec![], vec![], vec![], vec![]);
        parts[i + 1].2 = filling(room);
        let out = evidence(P, parts, vec![], serde_json::Map::new());
        assert_eq!((out["unread"].clone(), out[name].clone()), (json!([name]), json!([])), "{name}");
        assert!(out["errors"][name].as_str().unwrap().starts_with(&format!("{subject} too large to hand on (")), "{name}");
    }
    // A part already unread is handed on empty, is not counted, and is not named twice; its error is kept.
    let errors: serde_json::Map<String, Value> = [("policies".to_string(), json!("the policies listing answered HTTP 500"))].into_iter().collect();
    let out = evidence(P, five(filling(room), vec![], vec![], vec![], vec![]), vec!["bindings", "roles", "audit_logs"], errors.clone());
    assert_eq!((out["unread"].clone(), out["errors"].clone()), (json!(["bindings", "roles", "audit_logs", "alerts"]), json!({"policies": "the policies listing answered HTTP 500", "alerts": "the alert policies are too large to hand on (2 bytes as written; the evidence is at most 300000 bytes in all)"})));
    let out = evidence(P, five(filling(room - 2), vec![], vec![], vec![], vec![]), vec!["bindings", "roles", "audit_logs"], errors);
    assert_eq!(out["unread"], json!(["bindings", "roles", "audit_logs"]));
}

#[test]
fn alerts_too_large_to_hand_on_are_unread_and_the_check_does_not_assess_them() {
    // Sixty alert policies, each watching ten log filters of the most that is handed on of one: more than can be handed on.
    let policies = json!({"alertPolicies": (0..60).map(|i| json!({"displayName": format!("alert {i}"), "conditions": (0..10).map(|_| json!({"conditionMatchedLog": {"filter": "x".repeat(FILTER_CHARS)}})).collect::<Vec<_>>()})).collect::<Vec<_>>()});
    host::http::respond_with(move |req| {
        let u = &req.url;
        Ok(if u.contains("/alertPolicies?") { host::http::response(200, policies.to_string()) }
           else if u.contains("logging.googleapis.com") { host::http::response(200, log_metrics().to_string()) }
           else if u.contains("/assets?") { host::http::response(200, assets().to_string()) }
           else if u.contains("/providers?") { host::http::response(200, providers(if u.contains("/tf-pool/") { "tf-pool" } else { "off-pool" }).to_string()) }
           else { host::http::response(200, pools().to_string()) })
    });
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["alerts"].clone()), (json!(["alerts"]), json!([])), "{}", out["errors"]);
    // The collector pins the same size for the same alerts.
    assert_eq!(out["errors"]["alerts"], "the alert policies are too large to hand on (364611 bytes as written; the evidence is at most 300000 bytes in all)");
    assert_eq!(out["providers"].as_array().unwrap().len(), 2);
    assert!(out.to_string().len() <= MAX_EVIDENCE_BYTES);
    let judged: Value = serde_json::from_str(&crate::wif_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert_eq!(judged["not_assessed"], json!(["provider-changes-unalerted"]), "{judged}");
}

#[test]
fn the_most_it_can_hand_on_fits_in_what_a_node_is_given_three_times() {
    // Nothing else bounds what it is handed: the alerts alone, at their counts, are some seven million bytes.
    let filters = vec!["😀".repeat(FILTER_CHARS); 10];
    let alerts: Vec<Value> = (0..MAX_ALERTS).map(|_| json!({"name": "😀".repeat(100), "enabled": true, "filters": filters})).collect();
    let rows = |n: usize| -> Vec<Value> { (0..n).map(|_| json!({"member": "x".repeat(1000), "role": "x".repeat(1000)})).collect() };
    let parts = five(rows(100), rows(MAX_ROWS / 2), rows(MAX_ROWS / 2), rows(10), alerts);
    let unbounded: usize = parts.iter().map(|(_, _, rows)| Value::from(rows.clone()).to_string().len()).sum();
    println!("worst-case wif evidence at its counts alone: more than {unbounded} bytes");
    assert!(unbounded > MAX_EVIDENCE_BYTES);
    let out = evidence(&"a".repeat(30), parts, vec![], serde_json::Map::new());
    let bytes = out.to_string().len();
    println!("worst-case wif evidence handed on: {bytes} bytes");
    assert!(bytes <= MAX_EVIDENCE_BYTES, "{bytes}");
    assert_eq!(out["unread"], json!(["bindings", "roles", "alerts"]));
    // What the evidence holds besides its parts, at its longest (every part unread, an error under each name this
    // reader writes one under, each longer than any it writes), is within what is set aside for it.
    let errors: serde_json::Map<String, Value> = ["providers", "policies", "bindings", "roles", "audit_logs", "alerts"].iter().map(|k| (k.to_string(), json!("x".repeat(200)))).collect();
    let envelope = evidence(&"a".repeat(30), five(vec![], vec![], vec![], vec![], vec![]), vec!["providers", "bindings", "roles", "audit_logs", "alerts"], errors);
    let bytes = envelope.to_string().len();
    println!("wif evidence besides its parts, at most: {bytes} bytes");
    assert!(bytes <= ENVELOPE_BYTES, "{bytes}");
}
}
