// wif-check: judges ONE Google Cloud project's Workload Identity Federation
// setup from evidence a reader collected, by fixed rules. It reads its input
// and calls nothing: no cloud, no network, no model.
//
// Every finding is a rule that matched named evidence, and every rule says
// where it comes from: the published document and the heading in it. A rule
// that is this module's own judgement says so instead of borrowing a source.
// Nothing is worded by a model, so the same evidence always gives the same
// answer.
//
// The module also carries its CATALOGUE: every rule with its sources, and
// every practice of the main source that it does NOT judge, with the reason.
// `CATALOGUE_ONLY: true` returns just that, so another workflow can compare
// the headings cited here with the headings the documents have today.
//
// Evidence (`kind: "wif_evidence"`), whatever collected it:
//   { project,
//     providers: [{ pool, provider, issuer, aws_account, saml_entity, x509_anchors, condition, audiences, disabled }],
//     bindings:  [{ service_account, role, member }],     on service accounts
//     roles:     [{ member, role }],                       on the project
//     audit_logs:[{ service, log_types }],                 the project's audit config
//     alerts:    [{ name, enabled, filters }],             alert policies and the log filters behind them
//     unread:    ["providers" | "bindings" | "roles" | "audit_logs" | "alerts"] }
//
// Every part must be PRESENT to count as read. A part that is missing from
// the evidence is treated exactly like one named in `unread`: an empty list
// is a fact ("no providers"), an absent one is not.
//
// Besides the findings it draws the TRUST MAP the same evidence implies: for
// each pool, its providers' conditions, each service account bound to it,
// what that account can change, and who can therefore get a token. The map
// states what is there; the findings say what is wrong with it. It is given
// only when the providers, bindings and roles were all read: a map with a
// part missing would look complete.
//
// A part that could not be read is NOT a pass. The rules that needed it are
// reported as not assessed, and the check as a whole is then not clean.
// The same holds for a rule whose part was read but whose rows do not say
// what it needs (`undecided`, with the reason): it is not assessed either.
//
// A finding the owner has decided to live with is named in the node's config
// (`ACCEPTED: ["rule:severity:subject"]`), exactly, and is then reported as
// accepted instead of found. The severity is part of what was accepted: the
// same finding grown more serious is a finding again.

use serde::{Deserialize, Serialize};
use talos_sdk_macros::talos_module;

/// The keeper remembers at most two hundred. More than this is refused, never cut.
const MAX_FINDINGS: usize = 180;
/// Of those, the roles that hand over the whole project.
const OWNING_ROLES: [&str; 4] = ["roles/owner", "roles/editor", "roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin"];

/// The project a user-managed service account lives in, from its address
/// (`name@example-project.iam.gserviceaccount.com`). `None` for anything else, and
/// for the accounts Google runs on a project's behalf (`service-<number>@…`),
/// which are not somebody's deploy identity.
fn home_project(member: &str) -> Option<(&str, &str)> {
    let email = member.strip_prefix("serviceAccount:")?;
    let (local, domain) = email.split_once('@')?;
    let project = domain.strip_suffix(".iam.gserviceaccount.com")?;
    let agent = ["service-org-", "service-folder-", "service-"].iter().any(|p| local.strip_prefix(p).is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())));
    (!agent && !project.is_empty() && !project.contains('.') && !project.starts_with("gcp-sa-")).then_some((email, project))
}

/// Roles that let their holder change who can do what.
const BROAD_ROLES: [&str; 9] = [
    "roles/owner", "roles/editor", "roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin", "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountKeyAdmin", "roles/iam.workloadIdentityPoolAdmin", "roles/iam.serviceAccountUser",
];
/// The basic roles: each carries thousands of permissions across every service.
const BASIC_ROLES: [&str; 3] = ["roles/owner", "roles/editor", "roles/viewer"];
/// What a condition must mention to limit WHICH run of a repository gets a token.
const NARROWING: [&str; 5] = ["ref", "environment", "job_workflow_ref", "workflow_ref", "ref_protected"];
const PARTS: [&str; 5] = ["providers", "bindings", "roles", "audit_logs", "alerts"];
/// How many providers a finding names in its sentence; the count is always the whole number.
const MAX_NAMED: usize = 6;

// ------------------------------------------------------------ the sources

/// A published document a rule can cite.
struct Doc {
    id: &'static str,
    publisher: &'static str,
    title: &'static str,
    url: &'static str,
    /// Every practice heading of this document is either cited by a rule or
    /// listed as not judged. A watcher can then tell when the document gains
    /// a practice this module has not accounted for.
    accounted: bool,
}
const GOOGLE_WIF: Doc = Doc {
    id: "google-wif-best-practices",
    publisher: "Google Cloud",
    title: "Best practices for using Workload Identity Federation",
    url: "https://docs.cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation",
    accounted: true,
};
const GITHUB_OIDC: Doc = Doc {
    id: "github-oidc-reference",
    publisher: "GitHub",
    title: "OpenID Connect reference",
    url: "https://docs.github.com/en/actions/reference/security/oidc",
    accounted: false,
};
const GOOGLE_ROLES: Doc = Doc {
    id: "google-iam-roles",
    publisher: "Google Cloud",
    title: "Roles and permissions",
    url: "https://docs.cloud.google.com/iam/docs/roles-overview",
    accounted: false,
};
const DOCS: [&Doc; 3] = [&GOOGLE_WIF, &GITHUB_OIDC, &GOOGLE_ROLES];

/// One heading of a document: its anchor on the page and its words.
struct Cite {
    doc: &'static Doc,
    anchor: &'static str,
    heading: &'static str,
}
const fn google(anchor: &'static str, heading: &'static str) -> Cite {
    Cite { doc: &GOOGLE_WIF, anchor, heading }
}
const fn github(anchor: &'static str, heading: &'static str) -> Cite {
    Cite { doc: &GITHUB_OIDC, anchor, heading }
}

/// A rule: what it is called, which evidence it needs, and where it comes
/// from. No sources means it is this module's own judgement.
struct Rule {
    id: &'static str,
    needs: &'static [&'static str],
    sources: &'static [Cite],
    /// The title of a ticket that would put a finding of this rule right:
    /// what to do, verb first, naming no project.
    task: &'static str,
    /// What to change, in a sentence or two.
    remedy: &'static str,
}
const RULES: [Rule; 12] = [
    Rule { id: "provider-open", needs: &["providers"], task: "Add attribute conditions to Workload Identity providers that have none", remedy: "Give each provider an attribute condition that admits only the organisation and the repositories meant to use it.", sources: &[
        google("multi-tenant-attribute-conditions", "Use attribute conditions when federating with GitHub or other multi-tenant identity providers"),
        github("oidc-claims-used-to-define-trust-conditions-on-cloud-roles", "OIDC claims used to define trust conditions on cloud roles"),
    ] },
    Rule { id: "binding-whole-pool", needs: &["bindings", "roles"], task: "Stop granting service account access to whole Workload Identity pools", remedy: "Replace each member that ends in /* with the single repository, or the single subject, that needs the account.", sources: &[google("avoid-all-members", "Avoid granting access to all members of a pool")] },
    Rule { id: "binding-unscoped", needs: &["providers", "bindings", "roles"], task: "Limit which workflow runs can act as privileged service accounts", remedy: "Make the provider's condition, or the binding's member, name the branch, environment or workflow that may use the account, so that a pull request or another branch of the repository cannot.", sources: &[
        google("protecting_against_privilege_escalation_threats", "Protecting against privilege escalation threats"),
        github("example-subject-claims", "Example subject claims"),
    ] },
    Rule { id: "attribute-by-name", needs: &["providers", "bindings"], task: "Identify repositories by numeric ID in Workload Identity conditions and bindings", remedy: "Use repository_id and repository_owner_id in provider conditions, map them to attributes, and bind on those attributes instead of on names.", sources: &[
        google("use-immutable-attributes", "Use immutable attributes in attribute mappings"),
        google("use-non-reusable-attributes", "Use non-reusable attributes in attribute mappings"),
    ] },
    Rule { id: "pool-several-providers", needs: &["providers"], task: "Give each Workload Identity pool a single provider", remedy: "Move each extra provider to a pool of its own.", sources: &[google("avoid-subject-collisions", "Use a single provider per workload identity pool to avoid subject collisions")] },
    // Judged within the one project the evidence is of (see LIMITS: the catalogue says so).
    Rule { id: "identity-provider-federated-twice", needs: &["providers"], task: "Federate with each identity provider through a single Workload Identity provider", remedy: "Keep one pool and one provider for each identity provider, with a mapping and a condition that admit every identity that needs access; move the bindings to it and remove the others.", sources: &[google("avoid-federating-twice", "Avoid federating with the same identity provider twice")] },
    Rule { id: "provider-custom-audience", needs: &["providers"], task: "Use each Workload Identity provider's own address as its token audience", remedy: "Remove the custom allowed audiences, so that only tokens issued for this provider are accepted.", sources: &[google("provider-audience", "Use the URL of the workload identity pool provider as the audience")] },
    Rule { id: "data-access-logs-off", needs: &["audit_logs"], task: "Enable data access logs for the IAM and Security Token Service APIs", remedy: "Turn on Data Access audit logs for iam.googleapis.com and sts.googleapis.com.", sources: &[google("enable-data-access-logs", "Enable data access logs for IAM APIs")] },
    Rule { id: "outside-account-broad-role", needs: &["roles"], task: "Review access-changing roles held by service accounts from other projects", remedy: "Replace the role with the narrowest one the account needs, or move the work to a service account of this project.", sources: &[google("use-service-accounts-in-same-project", "Use service accounts that reside in the same project as the resources you need to access")] },
    // "In production environments, do not grant basic roles unless there is no alternative."
    Rule { id: "federated-account-basic-role", needs: &["bindings", "roles"], task: "Replace basic roles on federated service accounts with specific roles", remedy: "Grant the predefined or custom roles the account's work needs, then remove Owner, Editor or Viewer.", sources: &[Cite { doc: &GOOGLE_ROLES, anchor: "basic", heading: "Basic roles" }] },
    Rule { id: "provider-changes-unalerted", needs: &["alerts"], task: "Alert on changes to Workload Identity pools and providers", remedy: "Add a log-based alert on Admin Activity entries for the WorkloadIdentityPools methods, sent to a channel the team reads.", sources: &[] },
    Rule { id: "condition-substring", needs: &["providers"], task: "Compare whole values in Workload Identity provider conditions", remedy: "Replace each .contains(...) with an equality, or with a list of whole values.", sources: &[] },
];

/// What a rule does not judge of the practice it is about, in the rule's own
/// catalogue entry. A practice the check does not judge at all is in
/// `NOT_JUDGED`; this is for the rest of a practice a rule judges in part,
/// so that "there is a rule for it" is never read as "all of it is checked".
/// The gap report shows these beside a match, and a build brief beside the
/// nearest rule.
const LIMITS: [(&str, &[&str]); 1] = [(
    "identity-provider-federated-twice",
    &[
        "only within the one project the evidence is of: the same identity provider federated again in another project is not seen",
        "one identity provider reached under two different addresses is not recognised as one",
    ],
)];

/// Practices of the main source this check does not judge, and why. Listed
/// so that "no finding" is never read as "every practice was checked".
const NOT_JUDGED: [(Cite, &str); 12] = [
    (google("additional-token-exchange", "Use an additional token exchange to use ambient credentials that aren't supported by Workload Identity Federation"), "advice on when to use federation, not a setting"),
    (google("dedicated-project", "Use a dedicated project to manage workload identity pools and providers"), "needs to know what else the project holds; not in this evidence"),
    (google("disable-pool-creation", "Use organizational policy constraints to disable the creation of workload identity pool providers in other projects"), "an organization policy; needs organization-level evidence"),
    (google("protect-oidc-metadata", "Protect the OIDC metadata endpoint of your identity provider"), "about an identity provider you host; GitHub hosts its own"),
    (google("modify-attribute-mappings", "Don't allow attribute mappings to be modified"), "about who may edit a provider; needs the pools' own access policy"),
    (google("non-authoritative-attributes", "Don't rely on attributes that aren't stable or authoritative"), "a judgement about what each attribute means; only names-versus-ids is checked (attribute-by-name)"),
    (google("validate-external-creds", "Validate credential configurations from an external source before using them to authenticate to Google APIs"), "about client code, not the project's setup"),
    (google("use-unique-subject-mapping", "Use a unique subject mapping"), "no rule written yet"),
    (google("use-dedicated-service-accounts", "Use a dedicated service account for each application"), "what counts as one application is not in the evidence"),
    (google("ambient-credentials", "Use Workload Identity Federation for applications that have access to ambient credentials"), "advice on when to use federation, not a setting"),
    (google("reduce-number-of-credentials", "Use Workload Identity Federation to reduce the number of credentials that require rotation"), "advice on when to use federation, not a setting"),
    (google("sts-regional-endpoints", "Use Workload Identity Federation with regional endpoints to address data residency requirements"), "a data-residency choice, not judged here"),
];

fn cite_json(c: &Cite) -> serde_json::Value {
    serde_json::json!({ "document": c.doc.id, "publisher": c.doc.publisher, "title": c.doc.title, "heading": c.heading, "anchor": c.anchor, "url": format!("{}#{}", c.doc.url, c.anchor) })
}
/// What the check hands on besides its findings, in its own words. A reader
/// asking "can this check show X" is answered from here, as it is answered
/// from the rules for "can it judge X".
const PRODUCTS: [(&str, &str); 1] = [("trust-map", "A map of which outside identities (pools and their providers) can act as which service accounts, and the access-changing roles those accounts hold")];

fn catalogue() -> serde_json::Value {
    serde_json::json!({
        "documents": DOCS.iter().map(|d| serde_json::json!({ "id": d.id, "publisher": d.publisher, "title": d.title, "url": d.url, "every_heading_accounted_for": d.accounted })).collect::<Vec<_>>(),
        "products": PRODUCTS.iter().map(|(id, says)| serde_json::json!({ "id": id, "says": says })).collect::<Vec<_>>(),
        "rules": RULES.iter().map(|r| serde_json::json!({
            "rule": r.id,
            "basis": if r.sources.is_empty() { "local judgement" } else { "published guidance" },
            "task": r.task,
            "remedy": r.remedy,
            "limits": LIMITS.iter().find(|(rule, _)| *rule == r.id).map(|(_, limits)| limits.to_vec()).unwrap_or_default(),
            "sources": r.sources.iter().map(cite_json).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "not_judged": NOT_JUDGED.iter().map(|(c, why)| { let mut j = cite_json(c); j["why"] = (*why).into(); j }).collect::<Vec<_>>(),
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
    /// Return the catalogue of rules and sources and judge nothing.
    #[serde(rename = "CATALOGUE_ONLY")]
    catalogue_only: Option<bool>,
}
/// Evidence as it arrives: each part there or not.
#[derive(Deserialize, Default)]
struct EvidenceIn {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    project: String,
    providers: Option<Vec<Provider>>,
    bindings: Option<Vec<Binding>>,
    roles: Option<Vec<Role>>,
    audit_logs: Option<Vec<AuditLog>>,
    alerts: Option<Vec<Alert>>,
    #[serde(default)]
    unread: Vec<String>,
}
/// Evidence after a missing part has been counted as unread.
struct Evidence {
    project: String,
    providers: Vec<Provider>,
    bindings: Vec<Binding>,
    roles: Vec<Role>,
    audit_logs: Vec<AuditLog>,
    alerts: Vec<Alert>,
    unread: Vec<String>,
}
fn part<T>(name: &str, given: Option<Vec<T>>, unread: &mut Vec<String>) -> Vec<T> {
    if given.is_none() && !unread.iter().any(|u| u == name) {
        unread.push(name.to_string());
    }
    given.unwrap_or_default()
}
impl EvidenceIn {
    fn settle(self) -> Evidence {
        let mut unread = self.unread;
        Evidence {
            providers: part("providers", self.providers, &mut unread),
            bindings: part("bindings", self.bindings, &mut unread),
            roles: part("roles", self.roles, &mut unread),
            audit_logs: part("audit_logs", self.audit_logs, &mut unread),
            alerts: part("alerts", self.alerts, &mut unread),
            project: self.project,
            unread,
        }
    }
}
/// An alert policy: whether it is on, and the log filters it watches (its
/// own, and those of the log-based metrics its conditions name).
#[derive(Deserialize)]
struct Alert {
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    filters: Vec<String>,
}
fn yes() -> bool {
    true
}
#[derive(Deserialize)]
struct Provider {
    #[serde(default)]
    pool: String,
    #[serde(default)]
    provider: String,
    /// The OpenID Connect issuer the provider trusts. Empty for a provider of another kind.
    #[serde(default)]
    issuer: String,
    /// The AWS account the provider trusts, for an AWS provider.
    #[serde(default)]
    aws_account: String,
    /// The entity id of the identity provider a SAML provider trusts.
    #[serde(default)]
    saml_entity: String,
    /// A fingerprint of the trust anchors of an X.509 provider.
    #[serde(default)]
    x509_anchors: String,
    #[serde(default)]
    condition: String,
    /// Audiences the provider accepts beyond its own address. Empty is the default.
    #[serde(default)]
    audiences: Vec<String>,
    #[serde(default)]
    disabled: bool,
}
#[derive(Deserialize)]
struct Binding {
    #[serde(default)]
    service_account: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    member: String,
}
#[derive(Deserialize)]
struct Role {
    #[serde(default)]
    member: String,
    #[serde(default)]
    role: String,
}
#[derive(Deserialize)]
struct AuditLog {
    #[serde(default)]
    service: String,
    #[serde(default)]
    log_types: Vec<String>,
}

#[derive(Serialize, Debug, PartialEq)]
struct Finding {
    rule: &'static str,
    severity: &'static str,
    /// The provider, binding or setting the rule matched, by name.
    subject: String,
    says: String,
}

/// A name from evidence, as it may be shown: plain characters, cut to a length.
fn name(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || "-_./@:*".contains(*c)).take(120).collect()
}

/// Whether a provider condition limits which RUN gets a token, not only
/// which repository: it names a branch, an environment or a workflow.
fn narrows(condition: &str) -> bool {
    let c = condition.to_lowercase();
    NARROWING.iter().any(|word| c.contains(&format!(".{word}")) || c.contains(&format!("{word} ")) || c.contains(&format!("{word}=")))
        || c.contains(":environment:")
        || c.contains(":ref:")
}

/// Whether text names a repository or its owner by NAME: `repository` or
/// `repository_owner` not followed by `_id`. A name can be given to another
/// repository after a rename or a deletion; an id cannot.
fn by_name(text: &str) -> bool {
    let t = text.to_lowercase();
    let mut at = 0;
    while let Some(found) = t[at..].find("repository") {
        let rest = &t[at + found + "repository".len()..];
        let rest = rest.strip_prefix("_owner").unwrap_or(rest);
        if !rest.starts_with("_id") && !rest.starts_with("_visibility") {
            return true;
        }
        at += found + "repository".len();
    }
    false
}

/// How wide a binding's member is: the whole pool, a whole repository, or narrower.
#[derive(PartialEq, Debug)]
enum Width {
    Pool,
    Repository,
    Narrow,
    NotFederated,
}
/// The pool a federated member belongs to, and how wide the member is.
fn member_of(member: &str) -> (Option<String>, Width) {
    let Some(rest) = member.split("/workloadIdentityPools/").nth(1) else { return (None, Width::NotFederated) };
    let (pool, what) = rest.split_once('/').unwrap_or((rest, ""));
    let width = if !member.starts_with("principalSet://") {
        Width::Narrow
    } else if what == "*" || what.is_empty() {
        Width::Pool
    } else if what.starts_with("attribute.repository") {
        Width::Repository
    } else {
        Width::Narrow
    };
    (Some(name(pool)), width)
}

/// Which outside identity provider a provider federates with, as far as the
/// evidence says: an OpenID Connect issuer's address (letter case and a
/// closing slash aside), an AWS account, a SAML identity provider's entity
/// id, or the fingerprint of an X.509 provider's trust anchors. `None` when
/// the evidence names none of them (metadata with no entity id, a trust
/// store with no anchor, or evidence that left it out): such a provider
/// cannot be told apart from another, which is not the same as being a
/// different one.
fn federates_with(p: &Provider) -> Option<String> {
    let issuer = p.issuer.trim().trim_end_matches('/').to_ascii_lowercase();
    // One provider is of one kind. Each kind's identity is kept apart by its prefix, so an entity id
    // can never be taken for an issuer of the same spelling.
    let of_kind = |prefix: &str, value: &str| Some(value.trim()).filter(|v| !v.is_empty()).map(|v| format!("{prefix}/{v}"));
    if !issuer.is_empty() {
        Some(issuer)
    } else {
        of_kind("aws-account", &p.aws_account).or_else(|| of_kind("saml-entity", &p.saml_entity)).or_else(|| of_kind("x509-anchors", &p.x509_anchors))
    }
}

/// Rules whose part was read but whose rows do not say what the rule needs,
/// each with the reason. The caller reports such a rule as not assessed, and
/// drops what it found on the rows that did say, exactly as for an unread
/// part: half a result that could be accepted away would leave the check
/// clean with the other half never judged.
fn undecided(e: &Evidence) -> Vec<(&'static str, String)> {
    let mut open: Vec<(&'static str, String)> = Vec::new();
    let live: Vec<&Provider> = e.providers.iter().filter(|p| !p.disabled).collect();
    // One live provider federates with nothing twice, whoever it trusts. Two or more, one of
    // them not saying whom it trusts, may be the same identity provider twice.
    let unnamed = live.iter().filter(|p| federates_with(p).is_none()).count();
    if live.len() > 1 && unnamed > 0 {
        open.push(("identity-provider-federated-twice", format!("{unnamed} of {} live providers do not say which identity provider they trust (no issuer, AWS account, SAML entity id or X.509 trust anchor in the evidence)", live.len())));
    }
    open
}

/// Every rule that matched. Which rules could not be assessed is decided by
/// the caller from what was unread and from `undecided`.
fn check(e: &Evidence) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let live: Vec<&Provider> = e.providers.iter().filter(|p| !p.disabled).collect();
    let at = |p: &Provider| format!("{}/{}", name(&p.pool), name(&p.provider));

    for p in live.iter().filter(|p| p.condition.trim().is_empty()) {
        findings.push(Finding { rule: "provider-open", severity: "critical", subject: at(p), says: "has no condition: any repository of the identity provider can ask it for a token".to_string() });
    }

    for b in e.bindings.iter().filter(|b| b.role == "roles/iam.workloadIdentityUser" || b.role == "roles/iam.serviceAccountTokenCreator") {
        let (Some(pool), width) = member_of(&b.member) else { continue };
        let sa = name(&b.service_account);
        // What the account can do decides how much a wide binding matters.
        let held: Vec<String> = e.roles.iter().filter(|r| r.member.strip_prefix("serviceAccount:").map(name).as_deref() == Some(sa.as_str()) && BROAD_ROLES.contains(&r.role.as_str())).map(|r| name(&r.role)).collect();
        let (severity, power) = if held.is_empty() { ("low", "it holds no role that can change access".to_string()) } else { ("high", format!("it holds {}", held.join(", "))) };
        let subject = format!("{sa} <- pool {pool}");
        if width == Width::Pool {
            findings.push(Finding { rule: "binding-whole-pool", severity, subject: subject.clone(), says: format!("can be impersonated by every identity the pool admits; {power}") });
        }
        if width == Width::Narrow {
            continue;
        }
        // A wide member is acceptable only when EVERY live provider of its pool limits the run.
        let of_pool: Vec<&&Provider> = live.iter().filter(|p| name(&p.pool) == pool).collect();
        if of_pool.is_empty() || !of_pool.iter().all(|p| narrows(&p.condition)) {
            let who = if width == Width::Pool { "anything the pool admits" } else { "any workflow run in the repository, pull requests included" };
            findings.push(Finding { rule: "binding-unscoped", severity, subject, says: format!("can be impersonated by {who}: neither the binding nor the pool's provider limits the branch, environment or workflow; {power}") });
        }
    }

    // An account that identities outside Google Cloud can act as, holding a basic role.
    let mut federated: Vec<String> = e
        .bindings
        .iter()
        .filter(|b| b.role == "roles/iam.workloadIdentityUser" || b.role == "roles/iam.serviceAccountTokenCreator")
        .filter(|b| member_of(&b.member).0.is_some())
        .map(|b| name(&b.service_account))
        .collect();
    federated.sort();
    federated.dedup();
    for sa in &federated {
        for r in e.roles.iter().filter(|r| r.member.strip_prefix("serviceAccount:").map(name).as_deref() == Some(sa.as_str()) && BASIC_ROLES.contains(&r.role.as_str())) {
            // Viewer reads everything and changes nothing; Owner and Editor change nearly anything.
            let severity = if r.role == "roles/viewer" { "low" } else { "high" };
            findings.push(Finding { rule: "federated-account-basic-role", severity, subject: format!("{sa} holds {}", name(&r.role)), says: "can be acted as from outside Google Cloud and holds a basic role, which carries thousands of permissions across every service; grant the predefined or custom roles its work needs instead".to_string() });
        }
    }

    for p in live.iter().filter(|p| by_name(&p.condition)) {
        findings.push(Finding { rule: "attribute-by-name", severity: "medium", subject: at(p), says: "its condition names a repository or owner by name; a name can pass to another repository after a rename or deletion, a numeric id cannot".to_string() });
    }
    for b in e.bindings.iter().filter(|b| b.member.contains("/attribute.repository/") || b.member.contains("/attribute.repository_owner/")) {
        if let (Some(pool), _) = member_of(&b.member) {
            findings.push(Finding { rule: "attribute-by-name", severity: "medium", subject: format!("{} <- pool {pool}", name(&b.service_account)), says: "its binding names a repository or owner by name; bind on the numeric id attribute instead".to_string() });
        }
    }

    let mut pools: Vec<String> = live.iter().map(|p| name(&p.pool)).collect();
    pools.sort();
    pools.dedup();
    for pool in pools {
        let count = live.iter().filter(|p| name(&p.pool) == pool).count();
        if count > 1 {
            findings.push(Finding { rule: "pool-several-providers", severity: "low", subject: format!("pool {pool}"), says: format!("has {count} providers; two providers of one pool can issue the same subject for different identities") });
        }
    }

    // One outside identity provider behind more than one live provider, in one pool or in several.
    let trusted: Vec<(String, String)> = live.iter().filter_map(|p| federates_with(p).map(|idp| (idp, at(p)))).collect();
    let mut idps: Vec<&String> = trusted.iter().map(|(idp, _)| idp).collect();
    idps.sort();
    idps.dedup();
    for idp in idps {
        let through: Vec<&str> = trusted.iter().filter(|(of, _)| of == idp).map(|(_, at)| at.as_str()).collect();
        if through.len() > 1 {
            let named = through.iter().take(MAX_NAMED).copied().collect::<Vec<_>>().join(", ");
            let more = if through.len() > MAX_NAMED { format!(" and {} more", through.len() - MAX_NAMED) } else { String::new() };
            findings.push(Finding { rule: "identity-provider-federated-twice", severity: "low", subject: format!("identity provider {}", name(idp)), says: format!("is federated through {} providers ({named}{more}); one outside identity then becomes several principals, which is harder to audit and to revoke", through.len()) });
        }
    }

    for p in live.iter().filter(|p| p.audiences.iter().any(|a| !a.trim().is_empty())) {
        findings.push(Finding { rule: "provider-custom-audience", severity: "low", subject: at(p), says: "accepts an audience other than its own address, so a token minted for another purpose may be accepted".to_string() });
    }

    // A service account that lives in another project and can change access here. Its own
    // federation and bindings are in its home project, so who can act as it is not in this evidence.
    for r in e.roles.iter().filter(|r| BROAD_ROLES.contains(&r.role.as_str())) {
        let Some((email, home)) = home_project(&r.member) else { continue };
        if home == e.project {
            continue;
        }
        let severity = if OWNING_ROLES.contains(&r.role.as_str()) { "high" } else { "medium" };
        findings.push(Finding { rule: "outside-account-broad-role", severity, subject: format!("{} holds {}", name(email), name(&r.role)), says: format!("is a service account of another project ({}) with a role that can change access here; who may act as it is decided in that project and cannot be seen from this one", name(home)) });
    }

    // Data access logs for the two services federation goes through.
    let logged = |service: &str| e.audit_logs.iter().any(|a| (a.service == service || a.service == "allServices") && a.log_types.iter().any(|t| t == "DATA_READ" || t == "ADMIN_READ" || t == "DATA_WRITE"));
    for service in ["iam.googleapis.com", "sts.googleapis.com"] {
        if !logged(service) {
            findings.push(Finding { rule: "data-access-logs-off", severity: "medium", subject: service.to_string(), says: "has no data access logs enabled, so who exchanged or impersonated what cannot be reconstructed later".to_string() });
        }
    }

    // Somebody must be told when a pool or provider is changed: loosening a condition is one edit.
    let watched = e.alerts.iter().any(|a| a.enabled && a.filters.iter().any(|f| f.to_lowercase().contains("workloadidentitypool")));
    if !watched {
        findings.push(Finding { rule: "provider-changes-unalerted", severity: "low", subject: name(&e.project), says: "has no enabled alert that watches changes to workload identity pools or providers, so a loosened condition would go unnoticed".to_string() });
    }

    for p in live.iter().filter(|p| p.condition.contains(".contains(")) {
        findings.push(Finding { rule: "condition-substring", severity: "low", subject: at(p), says: "its condition matches by substring, which a crafted name can satisfy; compare whole values".to_string() });
    }
    findings
}

const MAX_MAP_ROWS: usize = 40;

/// The trust map: one row per (pool, bound service account), and one for a
/// pool nothing is bound to. `who` is derived by the same tests the rules use.
fn trust_map(e: &Evidence) -> Vec<serde_json::Value> {
    let live: Vec<&Provider> = e.providers.iter().filter(|p| !p.disabled).collect();
    let mut pools: Vec<String> = e.providers.iter().map(|p| name(&p.pool)).collect();
    let bound: Vec<(String, Width, &Binding)> = e
        .bindings
        .iter()
        .filter(|b| b.role == "roles/iam.workloadIdentityUser" || b.role == "roles/iam.serviceAccountTokenCreator")
        .filter_map(|b| match member_of(&b.member) {
            (Some(pool), width) => Some((pool, width, b)),
            _ => None,
        })
        .collect();
    pools.extend(bound.iter().map(|(pool, _, _)| pool.clone()));
    pools.sort();
    pools.dedup();
    let mut rows: Vec<serde_json::Value> = Vec::new();
    for pool in pools {
        let of_pool: Vec<&&Provider> = live.iter().filter(|p| name(&p.pool) == pool).collect();
        let conditions: Vec<serde_json::Value> = e
            .providers
            .iter()
            .filter(|p| name(&p.pool) == pool)
            .map(|p| serde_json::json!({ "provider": name(&p.provider), "condition": p.condition.chars().filter(|c| !c.is_control()).take(300).collect::<String>(), "disabled": p.disabled }))
            .collect();
        let limited = !of_pool.is_empty() && of_pool.iter().all(|p| narrows(&p.condition));
        let mut any = false;
        for (_, width, b) in bound.iter().filter(|(p, _, _)| *p == pool) {
            any = true;
            let sa = name(&b.service_account);
            let holds: Vec<String> = e.roles.iter().filter(|r| r.member.strip_prefix("serviceAccount:").map(name).as_deref() == Some(sa.as_str()) && BROAD_ROLES.contains(&r.role.as_str())).map(|r| name(&r.role)).collect();
            let who = if of_pool.is_empty() {
                "nobody: the pool has no live provider"
            } else if *width == Width::Narrow {
                "only the identity the binding names"
            } else if limited {
                "only runs the provider admits: it limits the branch, environment or workflow"
            } else if *width == Width::Pool {
                "anything the pool admits"
            } else {
                "any workflow run in the repository, pull requests included"
            };
            rows.push(serde_json::json!({ "pool": pool, "providers": conditions, "service_account": sa, "role": name(&b.role), "can_change_access_with": holds, "who": who }));
        }
        if !any {
            rows.push(serde_json::json!({ "pool": pool, "providers": conditions, "service_account": null, "who": "nobody: no service account is bound to it" }));
        }
    }
    rows.truncate(MAX_MAP_ROWS);
    rows
}

#[talos_module(world = "minimal-node")]
pub fn run(input: String) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    if envelope.config.catalogue_only.unwrap_or(false) {
        return serde_json::to_string(&serde_json::json!({ "kind": "security_catalogue", "check": "workload-identity", "title": "Workload Identity check", "catalogue": catalogue() })).map_err(|e| e.to_string());
    }
    // No evidence is a failure, never a clean result.
    let arrived = envelope.input.filter(|e| e.kind == "wif_evidence").ok_or("the evidence did not arrive")?;
    if arrived.unread.iter().any(|part| !PARTS.contains(&part.as_str())) {
        return Err("the evidence names a part this check does not know".to_string());
    }
    let evidence = arrived.settle();
    let accepted_list = match envelope.config.accepted {
        None => Vec::new(),
        Some(list) if list.len() <= 20 && list.iter().all(|a| a.len() <= 300) => list,
        Some(_) => return Err("ACCEPTED holds at most twenty findings".to_string()),
    };
    // A rule whose evidence was not all read is not assessed: what it found
    // on partial evidence is dropped with it, so it is never half a result.
    // Nor is a rule whose rows did not say what it needs.
    let undecided = undecided(&evidence);
    let not_assessed: Vec<&str> = RULES.iter().filter(|r| r.needs.iter().any(|n| evidence.unread.iter().any(|u| u == n)) || undecided.iter().any(|(rule, _)| *rule == r.id)).map(|r| r.id).collect();
    let all: Vec<Finding> = check(&evidence).into_iter().filter(|f| !not_assessed.contains(&f.rule)).collect();
    if all.len() > MAX_FINDINGS {
        return Err(format!("the check found more than {MAX_FINDINGS} things; reporting some of them would hide the rest"));
    }
    let passed: Vec<&str> = RULES.iter().map(|r| r.id).filter(|id| !not_assessed.contains(id) && !all.iter().any(|f| f.rule == *id)).collect();
    // Accepted only by an exact match on what was reported.
    let (accepted, findings): (Vec<Finding>, Vec<Finding>) = all.into_iter().partition(|f| accepted_list.iter().any(|a| *a == format!("{}:{}:{}", f.rule, f.severity, f.subject)));
    let worst = ["critical", "high", "medium", "low"].iter().find(|s| findings.iter().any(|f| f.severity == **s)).copied();
    let with_sources = |list: &[Finding]| -> Vec<serde_json::Value> {
        list.iter()
            .map(|f| {
                let rule = RULES.iter().find(|r| r.id == f.rule);
                let sources: Vec<serde_json::Value> = rule.map(|r| r.sources.iter().map(cite_json).collect()).unwrap_or_default();
                serde_json::json!({ "rule": f.rule, "severity": f.severity, "subject": f.subject, "says": f.says,
                                    "basis": if sources.is_empty() { "local judgement" } else { "published guidance" }, "sources": sources })
            })
            .collect()
    };
    serde_json::to_string(&serde_json::json!({
        "kind": "security_check", "check": "workload-identity", "title": "Workload Identity check", "project": name(&evidence.project),
        // Clean only when every rule could be assessed and none matched.
        "clean": findings.is_empty() && not_assessed.is_empty(),
        "worst": worst,
        "findings": with_sources(&findings), "accepted": with_sources(&accepted), "passed": passed, "not_assessed": not_assessed,
        // Why a rule is not assessed although its part was read. A rule not assessed for an unread part is not here.
        "undecided": undecided.iter().map(|(rule, why)| serde_json::json!({ "rule": rule, "why": why })).collect::<Vec<_>>(),
        "not_judged": NOT_JUDGED.len(),
        // Drawn only from parts that were all read; otherwise absent, never partial.
        "trust_map": if ["providers", "bindings", "roles"].iter().any(|p| evidence.unread.iter().any(|u| u == p)) { serde_json::Value::Null } else { trust_map(&evidence).into() },
        "counted": { "providers": evidence.providers.len(), "bindings": evidence.bindings.len(), "roles": evidence.roles.len(), "audit_logs": evidence.audit_logs.len(), "alerts": evidence.alerts.len() },
        "unread": evidence.unread,
    }))
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
use super::*;
use serde_json::{json, Value};

const POOL: &str = "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools";
const ADMIN: &str = "tf-admin@example-np.iam.gserviceaccount.com";

fn check_of(evidence: Value) -> Value {
    serde_json::from_str(&run(json!({"input": evidence}).to_string()).unwrap()).unwrap()
}
fn rules(out: &Value) -> Vec<(String, String, String)> {
    out["findings"].as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["severity"].as_str().unwrap().to_string(), f["subject"].as_str().unwrap().to_string())).collect()
}
fn logs() -> Value {
    json!([{"service": "allServices", "log_types": ["ADMIN_READ", "DATA_READ"]}])
}
/// Evidence with the two parts a case is about; logging is on unless the case says otherwise.
fn evidence(providers: Value, bindings: Value, roles: Value) -> Value {
    json!({"kind": "wif_evidence", "project": "example-np", "providers": providers, "bindings": bindings, "roles": roles, "audit_logs": logs(),
           "alerts": [{"name": "wif changes", "enabled": true, "filters": ["protoPayload.methodName:\"WorkloadIdentityPools\""]}]})
}
fn user(sa: &str, member: &str) -> Value {
    json!({"service_account": sa, "role": "roles/iam.workloadIdentityUser", "member": member})
}
const BY_ID: &str = "assertion.repository_id == '123456' && assertion.repository_owner_id == '99'";

#[test]
fn every_rule_says_where_it_comes_from_and_the_catalogue_needs_no_evidence() {
    let out: Value = serde_json::from_str(&run(json!({"config": {"CATALOGUE_ONLY": true}}).to_string()).unwrap()).unwrap();
    assert_eq!((out["kind"].as_str(), out["check"].as_str()), (Some("security_catalogue"), Some("workload-identity")));
    let cat = &out["catalogue"];
    let listed = cat["rules"].as_array().unwrap();
    assert_eq!(listed.len(), RULES.len());
    // One rule is this module's own judgement and says so; every other cites a document, a heading and its anchor.
    let local: Vec<&str> = listed.iter().filter(|r| r["basis"] == "local judgement").map(|r| r["rule"].as_str().unwrap()).collect();
    assert_eq!(local, ["provider-changes-unalerted", "condition-substring"]);
    for r in listed.iter().filter(|r| r["basis"] == "published guidance") {
        let sources = r["sources"].as_array().unwrap();
        assert!(!sources.is_empty(), "{r}");
        for s in sources {
            assert!(s["url"].as_str().unwrap().starts_with("https://docs.") && s["url"].as_str().unwrap().ends_with(&format!("#{}", s["anchor"].as_str().unwrap())), "{s}");
            assert!(!s["heading"].as_str().unwrap().is_empty() && !s["publisher"].as_str().unwrap().is_empty());
        }
    }
    assert_eq!(cat["rules"][0]["sources"][0], json!({
        "document": "google-wif-best-practices", "publisher": "Google Cloud", "title": "Best practices for using Workload Identity Federation",
        "heading": "Use attribute conditions when federating with GitHub or other multi-tenant identity providers", "anchor": "multi-tenant-attribute-conditions",
        "url": "https://docs.cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation#multi-tenant-attribute-conditions",
    }));
    // What is not judged is listed with a reason, and nothing is both judged and not judged.
    let not_judged = cat["not_judged"].as_array().unwrap();
    assert_eq!(not_judged.len(), 12);
    assert!(not_judged.iter().all(|n| n["why"].as_str().is_some_and(|w| !w.is_empty())));
    let cited: Vec<&str> = listed.iter().flat_map(|r| r["sources"].as_array().unwrap()).map(|s| s["anchor"].as_str().unwrap()).collect();
    assert!(not_judged.iter().all(|n| !cited.contains(&n["anchor"].as_str().unwrap())));
    let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), RULES.len());
}

#[test]
fn the_known_bad_setup_is_found_named_and_sourced() {
    // The admin service account is bound to the whole repository, and the pool's provider only checks the repository's name.
    let out = check_of(evidence(
        json!([{"pool": "tf-pool", "provider": "github", "condition": "assertion.repository == 'org/infra'"}]),
        json!([user(ADMIN, &format!("{POOL}/tf-pool/attribute.repository/org/infra"))]),
        json!([{"member": format!("serviceAccount:{ADMIN}"), "role": "roles/resourcemanager.projectIamAdmin"}, {"member": format!("serviceAccount:{ADMIN}"), "role": "roles/storage.admin"},
               {"member": "serviceAccount:other@example-np.iam.gserviceaccount.com", "role": "roles/owner"}]),
    ));
    assert_eq!((out["clean"].as_bool(), out["worst"].as_str(), out["project"].as_str()), (Some(false), Some("high"), Some("example-np")));
    assert_eq!(rules(&out), [
        ("binding-unscoped".to_string(), "high".to_string(), format!("{ADMIN} <- pool tf-pool")),
        ("attribute-by-name".to_string(), "medium".to_string(), "tf-pool/github".to_string()),
        ("attribute-by-name".to_string(), "medium".to_string(), format!("{ADMIN} <- pool tf-pool")),
    ]);
    let first = &out["findings"][0];
    let says = first["says"].as_str().unwrap();
    // An owner that workflows cannot reach is not named, and a storage role is not an access role.
    assert!(says.contains("pull requests included") && says.ends_with("it holds roles/resourcemanager.projectIamAdmin"), "{says}");
    assert_eq!(first["basis"], "published guidance");
    let publishers: Vec<&str> = first["sources"].as_array().unwrap().iter().map(|s| s["publisher"].as_str().unwrap()).collect();
    assert_eq!(publishers, ["Google Cloud", "GitHub"]);
    // The other account holding owner is this project's own: not an outside account.
    assert_eq!(out["passed"], json!(["provider-open", "binding-whole-pool", "pool-several-providers", "identity-provider-federated-twice", "provider-custom-audience", "data-access-logs-off", "outside-account-broad-role", "federated-account-basic-role", "provider-changes-unalerted", "condition-substring"]));
    assert_eq!((out["not_assessed"].clone(), out["not_judged"].as_u64()), (json!([]), Some(12)));
}

#[test]
fn the_hardened_setup_is_clean_and_an_exception_must_be_written_down_with_its_severity() {
    let apply = format!("{BY_ID} && assertion.environment == 'nonprod' && assertion.ref == 'refs/heads/main' && assertion.job_workflow_ref == 'org/infra/.github/workflows/apply.yml@refs/heads/main'");
    let hardened = evidence(
        json!([{"pool": "tf-apply-pool", "provider": "github", "condition": apply}, {"pool": "old-pool", "provider": "unused", "condition": "", "disabled": true}]),
        json!([user(ADMIN, &format!("{POOL}/tf-apply-pool/attribute.repository_id/123456"))]),
        json!([{"member": format!("serviceAccount:{ADMIN}"), "role": "roles/resourcemanager.projectIamAdmin"}]),
    );
    let out = check_of(hardened);
    assert_eq!((out["clean"].as_bool(), out["worst"].clone(), out["findings"].clone()), (Some(true), Value::Null, json!([])));
    assert_eq!(out["passed"].as_array().unwrap().len(), RULES.len());

    // A read-only plan identity open to the whole repository is still said (it is true), and is low.
    let plan = "tf-plan@example-np.iam.gserviceaccount.com";
    let mut with_plan = evidence(
        json!([{"pool": "tf-pool", "provider": "github", "condition": BY_ID}]),
        json!([user(plan, &format!("{POOL}/tf-pool/attribute.repository_id/123456"))]),
        json!([{"member": format!("serviceAccount:{plan}"), "role": "roles/viewer"}]),
    );
    let subject = format!("{plan} <- pool tf-pool");
    let viewer = format!("{plan} holds roles/viewer");
    assert_eq!(rules(&check_of(with_plan.clone())), [("binding-unscoped".to_string(), "low".to_string(), subject.clone()), ("federated-account-basic-role".to_string(), "low".to_string(), viewer.clone())]);
    let accept = |evidence: &Value, list: Value| -> Value { serde_json::from_str(&run(json!({"config": {"ACCEPTED": list}, "input": evidence}).to_string()).unwrap()).unwrap() };
    // Each finding is accepted by itself: one of the two leaves the other standing.
    assert_eq!(accept(&with_plan, json!([format!("binding-unscoped:low:{subject}")]))["clean"], false);
    let ok = accept(&with_plan, json!([format!("binding-unscoped:low:{subject}"), format!("federated-account-basic-role:low:{viewer}")]));
    assert_eq!((ok["clean"].as_bool(), ok["findings"].clone(), ok["accepted"][0]["sources"].as_array().unwrap().len()), (Some(true), json!([]), 2));
    // A near miss accepts nothing.
    assert_eq!(accept(&with_plan, json!([format!("binding-unscoped:{subject}"), "binding-unscoped:low:*", format!("binding-unscoped:low:{plan}")]))["clean"], false);
    // The same account later given a role that can change access is a finding again.
    with_plan["roles"] = json!([{"member": format!("serviceAccount:{plan}"), "role": "roles/owner"}]);
    let grown = accept(&with_plan, json!([format!("binding-unscoped:low:{subject}"), format!("federated-account-basic-role:low:{viewer}")]));
    assert_eq!((grown["clean"].as_bool(), grown["findings"][0]["severity"].as_str(), grown["accepted"].clone()), (Some(false), Some("high"), json!([])));
    assert_eq!(rules(&grown)[1], ("federated-account-basic-role".to_string(), "high".to_string(), format!("{plan} holds roles/owner")));
    assert_eq!(run(json!({"config": {"ACCEPTED": vec!["x"; 21]}, "input": with_plan}).to_string()).unwrap_err(), "ACCEPTED holds at most twenty findings");
}

#[test]
fn each_rule_matches_what_it_says_and_nothing_wider() {
    let sa = "sa@example-p.iam.gserviceaccount.com";
    let only = |out: &Value, rule: &str| -> Vec<String> { rules(out).into_iter().filter(|(r, _, _)| r == rule).map(|(_, _, s)| s).collect() };
    let with = |providers: Value, member: Option<&str>| check_of(evidence(providers, member.map(|m| json!([user(sa, m)])).unwrap_or(json!([])), json!([])));

    // provider-open: no condition, or a blank one. Critical.
    let open = with(json!([{"pool": "a", "provider": "b", "condition": "  "}]), None);
    assert_eq!((only(&open, "provider-open"), open["worst"].as_str()), (vec!["a/b".to_string()], Some("critical")));
    // binding-whole-pool: every identity of the pool, whatever the provider says.
    let whole = with(json!([{"pool": "a", "provider": "b", "condition": format!("{BY_ID} && assertion.ref == 'refs/heads/main'")}]), Some(&format!("{POOL}/a/*")));
    assert_eq!((only(&whole, "binding-whole-pool").len(), only(&whole, "binding-unscoped").len()), (1, 0));
    // binding-unscoped: one provider of the pool limits the run and another does not.
    let mixed = with(json!([{"pool": "a", "provider": "b", "condition": "assertion.ref=='refs/heads/main'"}, {"pool": "a", "provider": "c", "condition": BY_ID}]), Some(&format!("{POOL}/a/attribute.repository_id/1")));
    assert_eq!((only(&mixed, "binding-unscoped").len(), only(&mixed, "pool-several-providers")), (1, vec!["pool a".to_string()]));
    // A pool with no live provider proves nothing about limits.
    assert_eq!(only(&with(json!([]), Some(&format!("{POOL}/a/attribute.repository_id/1"))), "binding-unscoped").len(), 1);
    // Narrow members and members that are not federated are not a wide binding.
    for narrow in [format!("{POOL}/a/attribute.environment/prod"), "principal://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/a/subject/x".to_string(), "serviceAccount:x@example-p.iam.gserviceaccount.com".to_string()] {
        let out = with(json!([{"pool": "a", "provider": "b", "condition": BY_ID}]), Some(&narrow));
        assert!(only(&out, "binding-unscoped").is_empty() && only(&out, "binding-whole-pool").is_empty(), "{narrow}");
    }
    // attribute-by-name: a name, not an id, in a condition or a binding.
    for (condition, named) in [("assertion.repository == 'o/r'", true), ("assertion.repository_owner=='o'", true), ("attribute.repository in ['o/r']", true),
                               ("assertion.repository_id == '1'", false), ("assertion.repository_owner_id == '9' && assertion.repository_visibility == 'private'", false), ("assertion.ref == 'refs/heads/main'", false)] {
        assert_eq!(by_name(condition), named, "{condition}");
    }
    assert_eq!(only(&with(json!([{"pool": "a", "provider": "b", "condition": BY_ID}]), Some(&format!("{POOL}/a/attribute.repository_owner/o"))), "attribute-by-name"), [format!("{sa} <- pool a")]);
    // provider-custom-audience, and a substring condition (which still counts as limiting the run).
    let odd = with(json!([{"pool": "a", "provider": "b", "condition": "assertion.sub.contains(':environment:Production')", "audiences": ["https://other.example"]}]), Some(&format!("{POOL}/a/attribute.repository_id/1")));
    assert_eq!((only(&odd, "provider-custom-audience"), only(&odd, "condition-substring"), only(&odd, "binding-unscoped").len()), (vec!["a/b".to_string()], vec!["a/b".to_string()], 0));
    assert_eq!(odd["findings"].as_array().unwrap().iter().find(|f| f["rule"] == "condition-substring").unwrap()["basis"], "local judgement");
    // A name with markup in it is shown as plain characters.
    assert_eq!(only(&with(json!([{"pool": "a<script>", "provider": "b\nc", "condition": ""}]), None), "provider-open"), ["ascript/bc"]);

    // data-access-logs-off: each of the two services needs a data access log, its own or the project-wide one.
    let logged = |audit: Value| {
        let mut e = evidence(json!([]), json!([]), json!([]));
        e["audit_logs"] = audit;
        only(&check_of(e), "data-access-logs-off")
    };
    assert_eq!(logged(json!([])), ["iam.googleapis.com", "sts.googleapis.com"]);
    assert_eq!(logged(json!([{"service": "iam.googleapis.com", "log_types": ["DATA_READ"]}, {"service": "sts.googleapis.com", "log_types": []}, {"service": "storage.googleapis.com", "log_types": ["DATA_READ"]}])), ["sts.googleapis.com"]);
    assert!(logged(json!([{"service": "allServices", "log_types": ["ADMIN_READ"]}])).is_empty());
}

#[test]
fn what_could_not_be_read_is_not_assessed_and_never_clean() {
    // Bindings unread: a finding the readable parts would give on their own is still reported; the rules that
    // needed bindings are not assessed, and what they half-found is dropped with them.
    let mut e = evidence(json!([{"pool": "a", "provider": "b", "condition": "assertion.repository == 'o/r'"}]), json!([]), json!([]));
    e["unread"] = json!(["bindings"]);
    let out = check_of(e.clone());
    assert_eq!(out["clean"], false);
    assert_eq!(out["not_assessed"], json!(["binding-whole-pool", "binding-unscoped", "attribute-by-name", "federated-account-basic-role"]));
    assert!(rules(&out).is_empty(), "the by-name finding belongs to a rule that also needed bindings: {out}");
    assert_eq!(out["passed"], json!(["provider-open", "pool-several-providers", "identity-provider-federated-twice", "provider-custom-audience", "data-access-logs-off", "outside-account-broad-role", "provider-changes-unalerted", "condition-substring"]));
    // Audit logs unread: the logging rule is not assessed instead of reporting both services as unlogged.
    e["unread"] = json!(["audit_logs"]);
    e["audit_logs"] = json!([]);
    let out = check_of(e.clone());
    assert_eq!((out["not_assessed"].clone(), out["clean"].as_bool()), (json!(["data-access-logs-off"]), Some(false)));
    assert!(rules(&out).iter().all(|(r, _, _)| r != "data-access-logs-off"));
    e["unread"] = json!(["everything"]);
    assert_eq!(run(json!({"input": e}).to_string()).unwrap_err(), "the evidence names a part this check does not know");
    // No evidence, or something else in its place, is a failure and not a pass.
    for input in [json!(null), json!({"kind": "ticket"}), json!({"error": "could not reach the cloud", "is_error": true})] {
        assert_eq!(run(json!({"input": input}).to_string()).unwrap_err(), "the evidence did not arrive");
    }
}

#[test]
fn a_service_account_of_another_project_that_can_change_access_here_is_named() {
    let roles = json!([
        {"member": "serviceAccount:deployer@example-landing-zone.iam.gserviceaccount.com", "role": "roles/owner"},
        {"member": "serviceAccount:deployer@example-landing-zone.iam.gserviceaccount.com", "role": "roles/storage.admin"},
        {"member": "serviceAccount:ci@example-other-team.iam.gserviceaccount.com", "role": "roles/iam.serviceAccountUser"},
        // This project's own account, a person, a group, and the accounts Google runs for a project: not outside deploy identities.
        {"member": "serviceAccount:tf-admin@example-np.iam.gserviceaccount.com", "role": "roles/owner"},
        {"member": "user:someone@example.com", "role": "roles/owner"},
        {"member": "group:admins@example.com", "role": "roles/owner"},
        {"member": "serviceAccount:123456@cloudservices.gserviceaccount.com", "role": "roles/editor"},
        {"member": "serviceAccount:123456-compute@developer.gserviceaccount.com", "role": "roles/editor"},
        {"member": "serviceAccount:service-123456@gcp-sa-cloudasset.iam.gserviceaccount.com", "role": "roles/editor"},
        {"member": "serviceAccount:service-123456@container-engine-robot.iam.gserviceaccount.com", "role": "roles/editor"},
        {"member": "serviceAccount:service-org-99@example-system.iam.gserviceaccount.com", "role": "roles/owner"},
        // An outside account with a role that changes nothing about access.
        {"member": "serviceAccount:reader@example-landing-zone.iam.gserviceaccount.com", "role": "roles/viewer"},
    ]);
    let out = check_of(evidence(json!([]), json!([]), roles));
    assert_eq!(rules(&out), [
        ("outside-account-broad-role".to_string(), "high".to_string(), "deployer@example-landing-zone.iam.gserviceaccount.com holds roles/owner".to_string()),
        ("outside-account-broad-role".to_string(), "medium".to_string(), "ci@example-other-team.iam.gserviceaccount.com holds roles/iam.serviceAccountUser".to_string()),
    ]);
    let f = &out["findings"][0];
    assert!(f["says"].as_str().unwrap().contains("another project (example-landing-zone)") && f["says"].as_str().unwrap().contains("cannot be seen from this one"));
    assert_eq!((f["basis"].as_str(), f["sources"][0]["anchor"].as_str()), (Some("published guidance"), Some("use-service-accounts-in-same-project")));
    // An account named like Google's own but with letters after "service-" is somebody's account.
    assert_eq!(home_project("serviceAccount:service-desk@example-other.iam.gserviceaccount.com"), Some(("service-desk@example-other.iam.gserviceaccount.com", "example-other")));
    // Roles unread: not assessed, never passed.
    let mut blind = evidence(json!([]), json!([]), json!([]));
    blind["unread"] = json!(["roles"]);
    assert!(check_of(blind)["not_assessed"].as_array().unwrap().iter().any(|r| r == "outside-account-broad-role"));
}

#[test]
fn the_trust_map_says_who_can_get_a_token_for_each_bound_account_and_is_absent_when_a_part_was_unread() {
    let apply = format!("{BY_ID} && assertion.environment == 'nonprod' && assertion.ref == 'refs/heads/main'");
    let mut e = evidence(
        json!([{"pool": "tf-pool", "provider": "github", "condition": "assertion.repository == 'org/infra'"},
               {"pool": "apply-pool", "provider": "github", "condition": apply},
               {"pool": "empty-pool", "provider": "github", "condition": BY_ID},
               {"pool": "off-pool", "provider": "old", "condition": "", "disabled": true}]),
        json!([user(ADMIN, &format!("{POOL}/tf-pool/attribute.repository/org/infra")),
               user("deploy@example-np.iam.gserviceaccount.com", &format!("{POOL}/apply-pool/attribute.repository_id/1")),
               user("one@example-np.iam.gserviceaccount.com", &format!("{POOL}/tf-pool/attribute.environment/prod")),
               user("whole@example-np.iam.gserviceaccount.com", &format!("{POOL}/tf-pool/*")),
               user("orphan@example-np.iam.gserviceaccount.com", &format!("{POOL}/off-pool/attribute.repository_id/1")),
               {"service_account": ADMIN, "role": "roles/iam.serviceAccountUser", "member": "user:someone@example.com"}]),
        json!([{"member": format!("serviceAccount:{ADMIN}"), "role": "roles/resourcemanager.projectIamAdmin"}, {"member": format!("serviceAccount:{ADMIN}"), "role": "roles/storage.admin"}]),
    );
    let out = check_of(e.clone());
    let rows: Vec<(String, String, String)> = out["trust_map"].as_array().unwrap().iter().map(|r| (r["pool"].as_str().unwrap().to_string(), r["service_account"].as_str().unwrap_or("-").to_string(), r["who"].as_str().unwrap().to_string())).collect();
    assert_eq!(rows, [
        ("apply-pool".to_string(), "deploy@example-np.iam.gserviceaccount.com".to_string(), "only runs the provider admits: it limits the branch, environment or workflow".to_string()),
        ("empty-pool".to_string(), "-".to_string(), "nobody: no service account is bound to it".to_string()),
        ("off-pool".to_string(), "orphan@example-np.iam.gserviceaccount.com".to_string(), "nobody: the pool has no live provider".to_string()),
        ("tf-pool".to_string(), ADMIN.to_string(), "any workflow run in the repository, pull requests included".to_string()),
        ("tf-pool".to_string(), "one@example-np.iam.gserviceaccount.com".to_string(), "only the identity the binding names".to_string()),
        ("tf-pool".to_string(), "whole@example-np.iam.gserviceaccount.com".to_string(), "anything the pool admits".to_string()),
    ]);
    // What the admin account can change access with is listed; a storage role is not.
    let admin = &out["trust_map"][3];
    assert_eq!((admin["can_change_access_with"].clone(), admin["providers"][0]["condition"].as_str()), (json!(["roles/resourcemanager.projectIamAdmin"]), Some("assertion.repository == 'org/infra'")));
    // A person who can act as the account is not a federation row.
    assert_eq!(out["trust_map"].as_array().unwrap().len(), 6);
    // With any of the three parts unread there is no map at all: never a partial one.
    for part in ["providers", "bindings", "roles"] {
        e["unread"] = json!([part]);
        assert_eq!(check_of(e.clone())["trust_map"], Value::Null, "{part}");
    }
    e["unread"] = json!(["audit_logs"]);
    assert!(check_of(e)["trust_map"].is_array());
}

#[test]
fn a_part_missing_from_the_evidence_is_unread_and_an_empty_one_is_a_fact() {
    // Only the kind and the project: nothing was read, so nothing passes and nothing is clean.
    let bare = check_of(json!({"kind": "wif_evidence", "project": "example-np"}));
    assert_eq!((bare["clean"].as_bool(), bare["passed"].clone(), bare["findings"].clone(), bare["trust_map"].clone()), (Some(false), json!([]), json!([]), Value::Null));
    assert_eq!(bare["not_assessed"].as_array().unwrap().len(), RULES.len());
    assert_eq!(bare["unread"], json!(["providers", "bindings", "roles", "audit_logs", "alerts"]));
    // Every part present and empty: read, and judged. No providers and no bindings is a finding-free fact;
    // no audit logs and no alerts are findings.
    let empty = check_of(json!({"kind": "wif_evidence", "project": "example-np", "providers": [], "bindings": [], "roles": [], "audit_logs": [], "alerts": []}));
    assert_eq!(empty["not_assessed"], json!([]));
    let found: Vec<&str> = empty["findings"].as_array().unwrap().iter().map(|f| f["rule"].as_str().unwrap()).collect();
    assert_eq!(found, ["data-access-logs-off", "data-access-logs-off", "provider-changes-unalerted"]);
    // One part missing takes only its own rules with it.
    let mut e = evidence(json!([]), json!([]), json!([]));
    e.as_object_mut().unwrap().remove("alerts");
    let out = check_of(e);
    assert_eq!((out["not_assessed"].clone(), out["clean"].as_bool()), (json!(["provider-changes-unalerted"]), Some(false)));
}

#[test]
fn an_alert_counts_only_if_it_is_on_and_watches_pools_or_providers() {
    let with = |alerts: Value| {
        let mut e = evidence(json!([]), json!([]), json!([]));
        e["alerts"] = alerts;
        let out = check_of(e);
        out["findings"].as_array().unwrap().iter().any(|f| f["rule"] == "provider-changes-unalerted")
    };
    assert!(with(json!([])));
    assert!(with(json!([{"name": "iam", "enabled": true, "filters": ["protoPayload.methodName=\"SetIamPolicy\""]}])));
    assert!(with(json!([{"name": "off", "enabled": false, "filters": ["methodName:WorkloadIdentityPoolProviders"]}])));
    assert!(!with(json!([{"name": "on", "enabled": true, "filters": ["x", "protoPayload.methodName:\"google.iam.v1.WorkloadIdentityPools.UpdateWorkloadIdentityPoolProvider\""]}])));
    // A policy that does not say whether it is on is on: that is the service's own default.
    assert!(!with(json!([{"name": "unset", "filters": ["workloadidentitypool"]}])));
    let e = evidence(json!([]), json!([]), json!([]));
    let mut none = e.clone();
    none["alerts"] = json!([]);
    let f = check_of(none)["findings"].as_array().unwrap().iter().find(|f| f["rule"] == "provider-changes-unalerted").cloned().unwrap();
    assert_eq!((f["severity"].as_str(), f["subject"].as_str(), f["basis"].as_str()), (Some("low"), Some("example-np"), Some("local judgement")));
}

#[test]
fn a_basic_role_is_reported_only_on_an_account_that_can_be_acted_as_from_outside() {
    let deploy = "deploy@example-np.iam.gserviceaccount.com";
    let basic = |out: &Value| -> Vec<(String, String)> { rules(out).into_iter().filter(|(r, _, _)| r == "federated-account-basic-role").map(|(_, sev, s)| (sev, s)).collect() };
    let roles = json!([
        {"member": format!("serviceAccount:{deploy}"), "role": "roles/editor"},
        {"member": format!("serviceAccount:{deploy}"), "role": "roles/storage.admin"},
        {"member": "serviceAccount:batch@example-np.iam.gserviceaccount.com", "role": "roles/editor"},
        {"member": "user:someone@example.com", "role": "roles/owner"},
    ]);
    let hardened = json!([{"pool": "ci", "provider": "github", "condition": format!("{BY_ID} && assertion.ref == 'refs/heads/main'")}]);
    // Bound twice (two repositories): said once. The account nobody outside can act as, and the person, are not this rule's.
    let out = check_of(evidence(hardened.clone(), json!([user(deploy, &format!("{POOL}/ci/attribute.repository_id/1")), user(deploy, &format!("{POOL}/ci/attribute.repository_id/2"))]), roles.clone()));
    assert_eq!(basic(&out), [("high".to_string(), format!("{deploy} holds roles/editor"))]);
    let f = out["findings"].as_array().unwrap().iter().find(|f| f["rule"] == "federated-account-basic-role").unwrap();
    assert_eq!((f["basis"].as_str(), f["sources"][0]["publisher"].as_str(), f["sources"][0]["url"].as_str()), (Some("published guidance"), Some("Google Cloud"), Some("https://docs.cloud.google.com/iam/docs/roles-overview#basic")));
    // An account a person (not a pool) may act as is not federated.
    let out = check_of(evidence(hardened.clone(), json!([{"service_account": deploy, "role": "roles/iam.serviceAccountTokenCreator", "member": "user:someone@example.com"}]), roles.clone()));
    assert!(basic(&out).is_empty() && out["passed"].as_array().unwrap().iter().any(|r| r == "federated-account-basic-role"));
    // With the roles unread the rule is not assessed, never passed.
    let mut e = evidence(hardened, json!([user(deploy, &format!("{POOL}/ci/attribute.repository_id/1"))]), json!([]));
    e["unread"] = json!(["roles"]);
    let out = check_of(e);
    assert!(basic(&out).is_empty());
    assert!(out["not_assessed"].as_array().unwrap().iter().any(|r| r == "federated-account-basic-role") && !out["passed"].as_array().unwrap().iter().any(|r| r == "federated-account-basic-role"));
}

#[test]
fn every_rule_names_the_ticket_that_would_fix_it() {
    let out: Value = serde_json::from_str(&run(json!({"config": {"CATALOGUE_ONLY": true}}).to_string()).unwrap()).unwrap();
    let listed = out["catalogue"]["rules"].as_array().unwrap();
    let mut titles: Vec<&str> = listed.iter().map(|r| r["task"].as_str().unwrap()).collect();
    for r in listed {
        let (task, remedy) = (r["task"].as_str().unwrap(), r["remedy"].as_str().unwrap());
        // A title a board can carry: what to do, verb first, one line, no project named.
        assert!((20..=90).contains(&task.len()) && task.chars().next().unwrap().is_ascii_uppercase() && !task.ends_with('.') && !task.contains('\n'), "{task}");
        assert!((30..=240).contains(&remedy.len()) && remedy.ends_with('.'), "{remedy}");
        assert!(!task.contains("example") && !task.to_lowercase().contains("nonprod"), "{task}");
    }
    // Two rules never file under one title: a filed title is how a rule is known to be covered.
    titles.sort_unstable();
    titles.dedup();
    assert_eq!(titles.len(), RULES.len());
}

#[test]
fn more_findings_than_can_be_carried_is_refused_and_never_cut() {
    let open: Vec<Value> = (0..181).map(|n| json!({"pool": format!("p{n}"), "provider": "github", "condition": ""})).collect();
    assert_eq!(run(json!({"input": evidence(Value::Array(open), json!([]), json!([]))}).to_string()).unwrap_err(), "the check found more than 180 things; reporting some of them would hide the rest");
    let open: Vec<Value> = (0..150).map(|n| json!({"pool": format!("p{n}"), "provider": "github", "condition": ""})).collect();
    assert_eq!(check_of(evidence(Value::Array(open), json!([]), json!([])))["findings"].as_array().unwrap().len(), 150);
}

const TWICE: &str = "identity-provider-federated-twice";
/// Live providers, each in a pool of its own unless the case names the pool: (pool, provider, issuer, AWS account).
fn trusting(rows: &[(&str, &str, &str, &str)]) -> Value {
    Value::Array(rows.iter().map(|(pool, provider, issuer, account)| json!({"pool": pool, "provider": provider, "issuer": issuer, "aws_account": account, "condition": BY_ID})).collect())
}
fn twice(out: &Value) -> Vec<(String, String, String)> {
    out["findings"].as_array().unwrap().iter().filter(|f| f["rule"] == TWICE).map(|f| (f["severity"].as_str().unwrap().to_string(), f["subject"].as_str().unwrap().to_string(), f["says"].as_str().unwrap().to_string())).collect()
}
fn of_providers(providers: Value) -> Value {
    check_of(evidence(providers, json!([]), json!([])))
}

#[test]
fn an_identity_provider_trusted_by_two_live_providers_is_named_once_with_each_of_them() {
    // Two pools, one issuer: one finding for the identity provider, naming both. The third trusts somebody else.
    let out = of_providers(trusting(&[("a", "ci", "https://tokens.one.example", ""), ("b", "ci", "https://tokens.one.example", ""), ("c", "ci", "https://tokens.two.example", "")]));
    assert_eq!(twice(&out), [("low".to_string(), "identity provider https://tokens.one.example".to_string(), "is federated through 2 providers (a/ci, b/ci); one outside identity then becomes several principals, which is harder to audit and to revoke".to_string())]);
    let f = out["findings"].as_array().unwrap().iter().find(|f| f["rule"] == TWICE).unwrap();
    assert_eq!((f["basis"].as_str(), f["sources"][0]["anchor"].as_str(), f["sources"][0]["heading"].as_str()), (Some("published guidance"), Some("avoid-federating-twice"), Some("Avoid federating with the same identity provider twice")));
    assert!(!out["passed"].as_array().unwrap().iter().any(|r| r == TWICE) && out["not_assessed"] == json!([]) && out["clean"] == false);
    // In ONE pool it is this fault and the single-provider one as well: two rules, two things wrong.
    let one_pool = of_providers(trusting(&[("a", "x", "https://tokens.one.example", ""), ("a", "y", "https://tokens.one.example", "")]));
    assert_eq!((twice(&one_pool).len(), one_pool["findings"].as_array().unwrap().iter().filter(|f| f["rule"] == "pool-several-providers").count()), (1, 1));
    // Different identity providers, however many, are not this fault: the rule is assessed and passes.
    let apart = of_providers(trusting(&[("a", "ci", "https://tokens.one.example", ""), ("b", "ci", "https://tokens.two.example", ""), ("c", "ci", "https://tokens.one.example/tenant-7", ""), ("d", "aws", "", "123456789012")]));
    assert!(twice(&apart).is_empty() && apart["passed"].as_array().unwrap().iter().any(|r| r == TWICE), "{apart}");
    // An issuer is one address however it was typed: letter case and a closing slash do not make a second identity provider.
    for other in ["https://Tokens.One.Example", "https://tokens.one.example/", " https://tokens.one.example "] {
        assert_eq!(twice(&of_providers(trusting(&[("a", "ci", "https://tokens.one.example", ""), ("b", "ci", other, "")]))).len(), 1, "{other:?}");
    }
    // An AWS account trusted twice is the same fault; two accounts are two identity providers.
    let aws = of_providers(trusting(&[("a", "aws", "", "123456789012"), ("b", "aws", "", "123456789012"), ("c", "aws", "", "210987654321")]));
    assert_eq!(twice(&aws).iter().map(|(_, subject, _)| subject.as_str()).collect::<Vec<_>>(), ["identity provider aws-account/123456789012"]);
    // A disabled provider issues nothing: it is not a second federation.
    let mut off = trusting(&[("a", "ci", "https://tokens.one.example", ""), ("b", "ci", "https://tokens.one.example", "")]);
    off[1]["disabled"] = json!(true);
    let off = of_providers(off);
    assert!(twice(&off).is_empty() && off["passed"].as_array().unwrap().iter().any(|r| r == TWICE));
}

#[test]
fn a_finding_names_six_providers_and_counts_the_rest() {
    let pools: Vec<String> = (1..=8).map(|n| format!("p{n}")).collect();
    let rows: Vec<(&str, &str, &str, &str)> = pools.iter().map(|p| (p.as_str(), "ci", "https://tokens.one.example", "")).collect();
    let found = twice(&of_providers(trusting(&rows)));
    assert_eq!(found.len(), 1);
    let says = &found[0].2;
    assert!(says.starts_with("is federated through 8 providers (p1/ci, p2/ci, p3/ci, p4/ci, p5/ci, p6/ci and 2 more);"), "{says}");
    assert!(!says.contains("p7/ci") && !says.contains("p8/ci"), "{says}");
    // Six are all named, with nothing said to be left out.
    let says = &twice(&of_providers(trusting(&rows[..6])))[0].2;
    assert!(says.contains("p6/ci)") && !says.contains("more"), "{says}");
}

#[test]
fn a_provider_that_does_not_say_whom_it_trusts_leaves_the_rule_not_assessed_and_never_passed() {
    let state = |out: &Value| (out["passed"].as_array().unwrap().iter().any(|r| r == TWICE), out["not_assessed"].as_array().unwrap().iter().any(|r| r == TWICE), twice(out).len());
    // Two live providers, one with neither an issuer nor an AWS account (a SAML provider, or evidence that left it
    // out): they may be the same identity provider. Not assessed, not clean, and the reason is given.
    let silent = of_providers(trusting(&[("a", "ci", "https://tokens.one.example", ""), ("b", "saml", "", "")]));
    assert_eq!((state(&silent), silent["clean"].as_bool()), ((false, true, 0), Some(false)));
    assert_eq!(silent["undecided"], json!([{"rule": TWICE, "why": "1 of 2 live providers do not say which identity provider they trust (no issuer, AWS account, SAML entity id or X.509 trust anchor in the evidence)"}]));
    // Only this rule is taken: the others that read the providers are judged as before.
    assert_eq!(silent["not_assessed"], json!([TWICE]));
    // A blank issuer is no issuer.
    assert_eq!(state(&of_providers(trusting(&[("a", "ci", "https://tokens.one.example", ""), ("b", "x", "  ", " ")]))), (false, true, 0));
    // One live provider is the same as nothing, whoever it trusts: assessed, and passed.
    let alone = of_providers(trusting(&[("a", "saml", "", "")]));
    assert_eq!((state(&alone), alone["undecided"].clone()), ((true, false, 0), json!([])));
    // A silent provider that is disabled leaves nothing open.
    let mut off = trusting(&[("a", "ci", "https://tokens.one.example", ""), ("b", "saml", "", "")]);
    off[1]["disabled"] = json!(true);
    assert_eq!(state(&of_providers(off)), (true, false, 0));
    // A fault among the providers that do say is dropped with the rest, as it is for an unread part: half a
    // result, once accepted, would leave the check clean with the silent provider never judged.
    let both = trusting(&[("a", "ci", "https://tokens.one.example", ""), ("b", "ci", "https://tokens.one.example", ""), ("c", "saml", "", "")]);
    let out = of_providers(both.clone());
    assert_eq!((state(&out), out["undecided"][0]["why"].as_str().map(|w| w.starts_with("1 of 3 live providers"))), ((false, true, 0), Some(true)));
    let accepted: Value = serde_json::from_str(&run(json!({"config": {"ACCEPTED": ["identity-provider-federated-twice:low:identity provider https://tokens.one.example"]}, "input": evidence(both, json!([]), json!([]))}).to_string()).unwrap()).unwrap();
    assert_eq!((accepted["clean"].as_bool(), accepted["accepted"].clone(), state(&accepted)), (Some(false), json!([]), (false, true, 0)));
    // The providers unread: not assessed for that reason, which `unread` already gives.
    let mut blind = evidence(json!([]), json!([]), json!([]));
    blind["unread"] = json!(["providers"]);
    let blind = check_of(blind);
    assert_eq!((state(&blind), blind["undecided"].clone()), ((false, true, 0), json!([])));
}

#[test]
fn each_kind_of_provider_is_told_apart_by_what_it_trusts_and_one_kind_is_never_taken_for_another() {
    let provider = |name: &str, extra: Value| { let mut p = json!({"pool": name, "provider": "p", "issuer": "", "condition": "x == 'y'", "audiences": [], "disabled": false}); p.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone()); p };
    let twice = |providers: Vec<Value>| -> (Vec<String>, bool) {
        let out: Value = check_of(evidence(Value::Array(providers), json!([]), json!([])));
        (out["findings"].as_array().unwrap().iter().filter(|f| f["rule"] == "identity-provider-federated-twice").map(|f| f["subject"].as_str().unwrap().to_string()).collect(),
         out["not_assessed"].as_array().unwrap().iter().any(|r| r == "identity-provider-federated-twice"))
    };
    // Two SAML providers of one identity provider; two X.509 providers with the same trust anchors.
    assert_eq!(twice(vec![provider("a", json!({"saml_entity": "https://idp.example/saml"})), provider("b", json!({"saml_entity": " https://idp.example/saml "}))]), (vec!["identity provider saml-entity/https://idp.example/saml".to_string()], false));
    assert_eq!(twice(vec![provider("a", json!({"x509_anchors": "9f21dec47026a896f6b17f3ac9c2e8d7"})), provider("b", json!({"x509_anchors": "9f21dec47026a896f6b17f3ac9c2e8d7"}))]).0, ["identity provider x509-anchors/9f21dec47026a896f6b17f3ac9c2e8d7"]);
    // Different identity providers of one kind, and the same spelling under two kinds: nothing is federated twice.
    assert_eq!(twice(vec![provider("a", json!({"saml_entity": "https://idp.example/one"})), provider("b", json!({"saml_entity": "https://idp.example/two"}))]), (vec![], false));
    assert_eq!(twice(vec![provider("a", json!({"issuer": "https://idp.example/saml"})), provider("b", json!({"saml_entity": "https://idp.example/saml"})), provider("c", json!({"aws_account": "https://idp.example/saml"}))]), (vec![], false));
    // An entity id is compared as it is written: letter case tells two apart, as it does not for an issuer's address.
    assert_eq!(twice(vec![provider("a", json!({"saml_entity": "https://idp.example/SAML"})), provider("b", json!({"saml_entity": "https://idp.example/saml"}))]), (vec![], false));
    // One that says whom it trusts beside one that does not: not assessed, and nothing is reported on half the rows.
    assert_eq!(twice(vec![provider("a", json!({"saml_entity": "https://idp.example/saml"})), provider("b", json!({"saml_entity": "https://idp.example/saml"})), provider("c", json!({"saml_entity": "  "}))]), (vec![], true));
}

#[test]
fn a_rules_limits_are_in_its_catalogue_entry_and_only_a_real_rule_has_any() {
    let catalogue: Value = serde_json::from_str(&run(json!({"config": {"CATALOGUE_ONLY": true}}).to_string()).unwrap()).unwrap();
    let rules = catalogue["catalogue"]["rules"].as_array().unwrap();
    // Every rule says its limits, as a list that may be empty.
    assert!(rules.iter().all(|r| r["limits"].is_array()));
    let twice = rules.iter().find(|r| r["rule"] == "identity-provider-federated-twice").unwrap();
    assert_eq!(twice["limits"].as_array().unwrap().len(), 2);
    assert!(twice["limits"][0].as_str().unwrap().starts_with("only within the one project"));
    // A limit is one plain line a phone can show, and is written for a rule that exists.
    for (rule, limits) in LIMITS {
        assert!(RULES.iter().any(|r| r.id == rule), "{rule} has limits and is not a rule");
        assert!(!limits.is_empty() && limits.iter().all(|l| !l.is_empty() && l.len() <= 160 && !l.contains('\n')), "{rule}");
    }
    assert_eq!(rules.iter().filter(|r| !r["limits"].as_array().unwrap().is_empty()).count(), LIMITS.len());
}
}
