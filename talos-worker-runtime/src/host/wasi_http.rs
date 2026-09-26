//! `wasi:http/outgoing-handler` for the trusted/automation world, GATED
//! (2026-09-25).
//!
//! # What was wrong
//!
//! `build_trusted_linker` linked the upstream `outgoing-handler`, and
//! `TalosContext`'s `WasiHttpView` supplied `default_hooks()`, whose
//! `send_request` connects with raw hyper/tokio: no host allowlist, no SSRF
//! check on the authority or on what it resolves to, no tier-1 LLM-host deny,
//! no local-only egress, no rate limit, no method allowlist, no write ceiling,
//! nothing in the audit ledger. `talos-compilation` keeps a JS module's
//! `fetch` wired to it for exactly this world (`world_grants_raw_wasi_http`),
//! so an automation-node module had a complete second egress channel beside
//! `talos:core/http` with none of that channel's controls. The comment
//! justifying it — "trusted modules are operator-authored" — was not true of
//! the platform: any user holding an `automation-node` capability grant
//! compiles one.
//!
//! # The shape of the fix
//!
//! Two layers, because either alone leaves a hole:
//!
//! 1. [`gated_handle`] replaces the upstream `handle`. It sees the request
//!    AND the whole [`TalosContext`], so it applies the SAME gate set, in the
//!    same order, as `talos:core/http::fetch`: scheme, empty allowlist, SSRF on
//!    an IP-literal authority, `allowed_hosts`, the egress posture (tier-1 LLM
//!    hosts, public literals under tier 1 or local-only egress), the write
//!    ceiling on its verb axis / strict read egress, the method allowlist, the
//!    per-execution and per-host rate limits, cancellation and dry-run. Each
//!    refusal is recorded the way every other surface records one (guest
//!    diagnostic + WORM ledger). Then it delegates to the upstream `handle`.
//! 2. [`HardenedWasiHttpHooks`] replaces `default_hooks()`: `send_request`
//!    goes through the execution's hardened `reqwest` client — the
//!    `SsrfFilteringResolver` (private-IP and local-only egress checked on the
//!    RESOLVED address, at connect, which is the only place a hostname's DNS
//!    answer can be checked without a rebinding window), no proxy, no
//!    redirects. The default path resolved the name itself.
//!
//! # Stated limits
//!
//! * The gate runs synchronously (the p2 host trait is sync), so a refusal is
//!   appended to the ledger with a non-blocking lock; see
//!   [`TalosContext::record_capability_denied_now`].
//! * A hostname that resolves to a refused address is refused at connect by
//!   the resolver and reaches the guest as a connection error, with no ledger
//!   entry — the same limit as `talos:core/http`'s resolver layer, minus the
//!   pre-flight lookup `fetch` does for the audit signal (a lookup here would
//!   block the sync gate).
//! * `vault://` markers are not substituted on this channel. A guest that puts
//!   one in a header or body sends the literal marker.
//! * `allowed_methods` is the closed five-verb set; `HEAD`, `OPTIONS`,
//!   `CONNECT`, `TRACE` and custom verbs can never be declared, so they are
//!   always refused here.

use std::time::Duration;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use wasmtime::component::Resource;
use wasmtime_wasi_http::p2::bindings::http::{outgoing_handler, types as wt};
use wasmtime_wasi_http::p2::body::{HyperIncomingBody, HyperOutgoingBody};
use wasmtime_wasi_http::p2::types::{
    HostFutureIncomingResponse, HostOutgoingRequest, IncomingResponse, OutgoingRequestConfig,
};
use wasmtime_wasi_http::p2::{HttpResult, WasiHttpHooks, WasiHttpView};

use super::egress::insecure_http_opt_in;
use super::limits::{MAX_HTTP_CALLS_PER_EXECUTION, MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION};
use crate::context::TalosContext;

/// The capability token on this surface's audit rows. A raw `wasi:http`
/// request IS an `http-fetch` through another ABI, so it carries that op
/// label: the write ceiling's op partition (`write_gated_ops`, the
/// verb-inferred set pinned by `ceiling_axis_pins`) and the audit vocabulary
/// an operator correlates against stay closed. The SURFACE is told apart in
/// the target, which reads `wasi:http <host>`.
pub(crate) const WASI_HTTP_OP: &str = "http-fetch";

/// Prefix on every audit target from this surface.
pub(crate) const WASI_HTTP_TARGET_PREFIX: &str = "wasi:http";

/// Upper bound on a response body read through this channel, the same knob
/// and default as `talos:core/http::fetch`.
fn max_response_bytes() -> usize {
    talos_config::positive_env_or_default::<usize>("WASM_HTTP_MAX_RESPONSE_BYTES", 10 * 1024 * 1024)
}

// ─────────────────────────────────────────────────────────────────────────────
// The admission decision — pure, so every refusal is unit-testable.
// ─────────────────────────────────────────────────────────────────────────────

/// The request fields the gate reads, lifted out of the resource table.
#[derive(Debug, Clone)]
pub(crate) struct WasiHttpTarget {
    /// Upper-case verb token (`GET`, `POST`, …, or a custom verb).
    pub(crate) method: String,
    /// `None` = the guest set no scheme (upstream defaults to HTTPS).
    pub(crate) scheme: Option<wt::Scheme>,
    pub(crate) authority: Option<String>,
}

/// The policy the gate applies, read from the context at call time.
pub(crate) struct WasiHttpPolicy<'a> {
    pub(crate) allowed_hosts: &'a [String],
    pub(crate) allowed_methods: &'a [String],
    pub(crate) max_llm_tier: talos_workflow_job_protocol::LlmTier,
    pub(crate) local_egress_only: bool,
    pub(crate) max_write_ceiling: talos_workflow_job_protocol::WriteCeiling,
    pub(crate) http_verb_ceiling: Option<talos_workflow_job_protocol::WriteCeiling>,
    pub(crate) write_ceiling_enforced: bool,
    pub(crate) strict_egress: bool,
    pub(crate) insecure_http_opt_in: bool,
}

/// A refusal: what to record, and what the guest gets back.
#[derive(Debug, Clone)]
pub(crate) struct WasiHttpRefusal {
    /// Audit `policy` token (same vocabulary as `talos:core/http`).
    pub(crate) policy: &'static str,
    /// Audit `target` (host, IP, or `"<METHOD> <host>"`; never a secret).
    pub(crate) target: String,
    pub(crate) code: wt::ErrorCode,
    pub(crate) detail: Option<&'static str>,
}

/// An admitted request: the normalized host and the per-host rate-limit key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WasiHttpAdmitted {
    pub(crate) host: String,
    pub(crate) host_for_limit: String,
    pub(crate) mutates: bool,
}

fn refuse(policy: &'static str, target: impl Into<String>) -> WasiHttpRefusal {
    WasiHttpRefusal {
        policy,
        target: target.into(),
        code: wt::ErrorCode::HttpRequestDenied,
        detail: None,
    }
}

/// `GET` and `HEAD` are reads; every other verb, including a custom one, is
/// treated as a mutation (fail closed on the write-ceiling axis).
fn method_mutates(method: &str) -> bool {
    !matches!(method, "GET" | "HEAD")
}

/// The stateless half of the gate, in `talos:core/http::fetch`'s order.
pub(crate) fn wasi_http_admission(
    target: &WasiHttpTarget,
    policy: &WasiHttpPolicy<'_>,
) -> Result<WasiHttpAdmitted, WasiHttpRefusal> {
    let scheme = match &target.scheme {
        None | Some(wt::Scheme::Https) => "https",
        Some(wt::Scheme::Http) => "http",
        Some(wt::Scheme::Other(_)) => {
            return Err(WasiHttpRefusal {
                code: wt::ErrorCode::HttpProtocolError,
                ..refuse("insecure-scheme", "other-scheme")
            })
        }
    };
    let authority_str = target.authority.as_deref().unwrap_or("");
    // Parsed with the SAME parser the upstream request builder uses, so a
    // string this gate reads one way cannot be sent as another.
    let authority: http::uri::Authority = authority_str.parse().map_err(|_| WasiHttpRefusal {
        code: wt::ErrorCode::HttpRequestUriInvalid,
        ..refuse("invalid-authority", "")
    })?;
    // The host:port the gate judges must be exactly the one presented. The
    // authority parser accepts a port that is not a u16 (`:99999`) or is empty
    // or zero-padded, and `port_u16()` silently drops those — so the gate
    // would judge `host:443` while `host:99999` was presented. Refuse any
    // authority that does not round-trip rather than read it two ways
    // (userinfo, if any, is not part of the comparison).
    let presented = authority
        .as_str()
        .rsplit_once('@')
        .map_or(authority.as_str(), |(_, host_port)| host_port);
    let canonical = match authority.port_u16() {
        Some(p) => format!("{}:{p}", authority.host()),
        None => authority.host().to_string(),
    };
    if !presented.eq_ignore_ascii_case(&canonical) {
        return Err(WasiHttpRefusal {
            code: wt::ErrorCode::HttpRequestUriInvalid,
            ..refuse("invalid-authority", "")
        });
    }
    // WHATWG normalisation (decimal / hex IP spellings become dotted quads) —
    // the same normaliser `reqwest` applies when it sends.
    let port = authority
        .port_u16()
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    let url =
        url::Url::parse(&format!("{scheme}://{}{port}/", authority.host())).map_err(|_| {
            WasiHttpRefusal {
                code: wt::ErrorCode::HttpRequestUriInvalid,
                ..refuse("invalid-authority", "")
            }
        })?;
    // Scheme, allowlist, IP literal, `allowed_hosts`, egress posture: the
    // same function `talos:core/http::fetch` / `fetch_all` call.
    let url_policy = super::egress_admission::UrlPolicy {
        allowed_hosts: policy.allowed_hosts,
        max_llm_tier: policy.max_llm_tier,
        local_egress_only: policy.local_egress_only,
        insecure_http_opt_in: policy.insecure_http_opt_in,
    };
    let super::egress_admission::UrlAdmitted {
        host,
        host_match: matched,
        host_for_limit,
        ..
    } = super::egress_admission::admit_parsed_url(url, &url_policy)
        .map_err(|r| refuse(r.policy, r.target))?;
    let mutates = method_mutates(&target.method);
    // The write ceiling on its VERB-INFERRED axis, under the `http-fetch` op
    // label (see `WASI_HTTP_OP`). The pair is written on one line so
    // `ceiling_axis_pins` counts this site with the other gates.
    let (axis, _op) = (
        talos_workflow_job_protocol::CeilingAxis::VerbInferred,
        "http-fetch",
    );
    if mutates
        && talos_workflow_job_protocol::write_ceiling_denies_axis(
            policy.write_ceiling_enforced,
            axis,
            policy.max_write_ceiling,
            policy.http_verb_ceiling,
        )
    {
        return Err(WasiHttpRefusal {
            detail: Some(super::http::WRITE_CEILING_VERB_DETAIL),
            ..refuse("write-ceiling", host)
        });
    }
    if !mutates
        && crate::context::strict_egress_denies(
            policy.write_ceiling_enforced,
            policy.strict_egress,
            policy.max_write_ceiling,
            matched,
        )
    {
        return Err(refuse("write-ceiling-strict-egress", host));
    }
    if !talos_workflow_job_protocol::method_permitted(policy.allowed_methods, &target.method) {
        return Err(WasiHttpRefusal {
            detail: Some(talos_workflow_job_protocol::METHOD_ALLOWLIST_REMEDY),
            ..refuse("method-allowlist", format!("{} {host}", target.method))
        });
    }
    Ok(WasiHttpAdmitted {
        host,
        host_for_limit,
        mutates,
    })
}

fn method_token(m: &wt::Method) -> String {
    match m {
        wt::Method::Get => "GET".into(),
        wt::Method::Head => "HEAD".into(),
        wt::Method::Post => "POST".into(),
        wt::Method::Put => "PUT".into(),
        wt::Method::Delete => "DELETE".into(),
        wt::Method::Connect => "CONNECT".into(),
        wt::Method::Options => "OPTIONS".into(),
        wt::Method::Trace => "TRACE".into(),
        wt::Method::Patch => "PATCH".into(),
        wt::Method::Other(s) => s.to_ascii_uppercase(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The gated handler.
// ─────────────────────────────────────────────────────────────────────────────

/// The `wasi:http` package version upstream binds (`wit/deps/http.wit`).
/// The linker matches semver-compatible `0.2.x` imports against it, exactly
/// as it does for upstream's own registration.
pub(crate) const OUTGOING_HANDLER_INTERFACE: &str = "wasi:http/outgoing-handler@0.2.12";

/// Link the gated `handle` in place of upstream's `add_only_http_to_linker_async`
/// (which the trusted linker used), beside `wasi:http/types`.
///
/// Registered directly with `func_wrap` rather than through the generated
/// `outgoing_handler::add_to_linker`: that trait has `wasi:http/types::Host` as
/// a supertrait, so a wrapper type would have to re-implement the whole types
/// surface. The signature is the WIT one —
/// `handle(outgoing-request, option<request-options>) -> result<future-incoming-response, error-code>`
/// — and the typed resources are upstream's own (`with` mappings), so the
/// upstream `handle` this delegates to sees exactly what it would have.
pub(crate) fn add_gated_outgoing_handler(
    l: &mut wasmtime::component::Linker<TalosContext>,
) -> anyhow::Result<()> {
    let mut inst = l.instance(OUTGOING_HANDLER_INTERFACE)?;
    inst.func_wrap(
        "handle",
        |mut store: wasmtime::StoreContextMut<'_, TalosContext>,
         (request, options): (
            Resource<HostOutgoingRequest>,
            Option<Resource<wt::RequestOptions>>,
        )| {
            let outcome = match gated_handle(store.data_mut(), request, options) {
                Ok(future) => Ok(future),
                // An `ErrorCode` goes to the guest; anything else traps —
                // upstream's `convert_error_code`, verbatim.
                Err(e) => Err(e.downcast()?),
            };
            Ok((outcome,))
        },
    )?;
    Ok(())
}

/// The gated `wasi:http/outgoing-handler.handle`: the WHOLE context in view,
/// not the `WasiHttpCtxView` projection the upstream handler gets.
pub(crate) fn gated_handle(
    ctx: &mut TalosContext,
    request: Resource<HostOutgoingRequest>,
    options: Option<Resource<wt::RequestOptions>>,
) -> HttpResult<Resource<HostFutureIncomingResponse>> {
    let target = {
        let req = ctx.table.get(&request)?;
        WasiHttpTarget {
            method: method_token(&req.method),
            scheme: req.scheme.clone(),
            authority: req.authority.clone(),
        }
    };
    let decision = {
        let policy = WasiHttpPolicy {
            allowed_hosts: &ctx.allowed_hosts,
            allowed_methods: &ctx.allowed_methods,
            max_llm_tier: ctx.max_llm_tier,
            local_egress_only: ctx.local_egress_only,
            max_write_ceiling: ctx.max_write_ceiling,
            http_verb_ceiling: ctx.http_verb_ceiling,
            write_ceiling_enforced: crate::context::write_ceiling_enforced(),
            strict_egress: crate::context::write_ceiling_strict_egress(),
            insecure_http_opt_in: insecure_http_opt_in(),
        };
        wasi_http_admission(&target, &policy)
    };
    let admitted = match decision {
        Ok(a) => a,
        Err(r) => return Err(ctx.refuse_wasi_http(request, r)),
    };

    // Budget + cancellation: charged AFTER the stateless checks admitted,
    // exactly as `fetch` does (a refused request spends no budget).
    if !ctx.check_rate_limit(&ctx.http_call_count, MAX_HTTP_CALLS_PER_EXECUTION) {
        let host = admitted.host.clone();
        return Err(ctx.refuse_wasi_http(request, refuse("execution-rate-limit", host)));
    }
    if !ctx.check_per_host_rate_limit(
        &admitted.host_for_limit,
        MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION,
    ) {
        let host = admitted.host.clone();
        return Err(ctx.refuse_wasi_http(request, refuse("per-host-rate-limit", host)));
    }
    if ctx.is_cancelled() {
        drop(ctx.table.delete(request));
        return Err(wt::ErrorCode::HttpRequestDenied.into());
    }

    // Dry-run: a mutating request is mocked, never sent — the contract
    // `talos:core/http::fetch` already honours.
    if ctx.dry_run && admitted.mutates {
        drop(ctx.table.delete(request));
        tracing::info!(
            method = %target.method,
            host = %admitted.host,
            "Dry-run: intercepted mutating wasi:http request (pre-network)"
        );
        return Ok(ctx
            .table
            .push(dry_run_response(&target.method, &admitted.host))?);
    }

    let mut view = <TalosContext as WasiHttpView>::http(ctx);
    outgoing_handler::Host::handle(&mut view, request, options)
}

impl TalosContext {
    /// Record a `wasi:http` refusal the way every other egress surface records
    /// one, drop the request resource, and return what the guest receives.
    fn refuse_wasi_http(
        &mut self,
        request: Resource<HostOutgoingRequest>,
        refusal: WasiHttpRefusal,
    ) -> wasmtime_wasi_http::p2::HttpError {
        // Consume the request (and its body) so the resource is not leaked.
        drop(self.table.delete(request));
        let target = format!("{WASI_HTTP_TARGET_PREFIX} {}", refusal.target);
        self.record_capability_denied_now(WASI_HTTP_OP, refusal.policy, &target, refusal.detail);
        tracing::warn!(
            op = WASI_HTTP_OP,
            policy = refusal.policy,
            target = %refusal.target,
            module_id = ?self.module_id,
            actor_id = ?self.actor_id,
            "wasi:http outgoing request refused by the egress gate"
        );
        refusal.code.into()
    }
}

fn dry_run_response(method: &str, host: &str) -> HostFutureIncomingResponse {
    let body = serde_json::to_vec(&serde_json::json!({
        "__dry_run__": true,
        "intercepted_method": method,
        "intercepted_host": host,
    }))
    .unwrap_or_default();
    let body: HyperIncomingBody = http_body_util::Full::new(Bytes::from(body))
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed_unsync();
    let resp = http::Response::builder()
        .status(200)
        .header("x-talos-dry-run", "true")
        .header("content-type", "application/json")
        .body(body);
    HostFutureIncomingResponse::ready(Ok(match resp {
        Ok(resp) => Ok(IncomingResponse {
            resp,
            worker: None,
            between_bytes_timeout: Duration::from_secs(600),
        }),
        Err(_) => Err(wt::ErrorCode::InternalError(None)),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// The send path: the execution's hardened client, never a raw connect.
// ─────────────────────────────────────────────────────────────────────────────

/// `WasiHttpHooks` whose `send_request` uses the execution's hardened
/// `reqwest` client (SSRF-filtering resolver incl. local-only egress, no
/// proxy, no redirects, 5 s connect timeout) instead of upstream's raw
/// `TcpStream::connect` on a name it resolves itself.
pub(crate) struct HardenedWasiHttpHooks {
    client: reqwest::Client,
}

impl HardenedWasiHttpHooks {
    pub(crate) fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl WasiHttpHooks for HardenedWasiHttpHooks {
    fn send_request(
        &mut self,
        request: http::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        let client = self.client.clone();
        let handle = wasmtime_wasi::runtime::spawn(async move {
            Ok(send_via_hardened_client(client, request, config).await)
        });
        Ok(HostFutureIncomingResponse::pending(handle))
    }
}

async fn send_via_hardened_client(
    client: reqwest::Client,
    request: http::Request<HyperOutgoingBody>,
    config: OutgoingRequestConfig,
) -> Result<IncomingResponse, wt::ErrorCode> {
    let (parts, body) = request.into_parts();
    let stream = TryStreamExt::map_err(http_body_util::BodyStream::new(body), |e| {
        std::io::Error::other(format!("{e:?}"))
    })
    .try_filter_map(|frame| async move { Ok(frame.into_data().ok()) });
    let request = http::Request::from_parts(parts, reqwest::Body::wrap_stream(stream));
    let request =
        reqwest::Request::try_from(request).map_err(|_| wt::ErrorCode::HttpRequestUriInvalid)?;

    let response = tokio::time::timeout(config.first_byte_timeout, client.execute(request))
        .await
        .map_err(|_| wt::ErrorCode::ConnectionReadTimeout)?
        .map_err(|e| {
            if e.is_timeout() {
                wt::ErrorCode::ConnectionTimeout
            } else if e.is_connect() {
                // Includes the SSRF resolver refusing a private / public-under-
                // local-only address — the connect is the gate.
                wt::ErrorCode::ConnectionRefused
            } else {
                wt::ErrorCode::HttpProtocolError
            }
        })?;

    let max = max_response_bytes();
    let (parts, body) = http::Response::<reqwest::Body>::from(response).into_parts();
    let body: HyperIncomingBody = http_body_util::Limited::new(body, max)
        .map_err(move |e| {
            if e.is::<http_body_util::LengthLimitError>() {
                wt::ErrorCode::HttpResponseBodySize(u64::try_from(max).ok())
            } else {
                wt::ErrorCode::HttpProtocolError
            }
        })
        .boxed_unsync();
    Ok(IncomingResponse {
        resp: http::Response::from_parts(parts, body),
        worker: None,
        between_bytes_timeout: config.between_bytes_timeout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_workflow_job_protocol::{LlmTier, WriteCeiling};

    fn target(method: &str, authority: &str) -> WasiHttpTarget {
        WasiHttpTarget {
            method: method.to_string(),
            scheme: Some(wt::Scheme::Https),
            authority: Some(authority.to_string()),
        }
    }

    struct P {
        hosts: Vec<String>,
        methods: Vec<String>,
        tier: LlmTier,
        local: bool,
        write: WriteCeiling,
        verb: Option<WriteCeiling>,
        enforced: bool,
    }

    impl Default for P {
        fn default() -> Self {
            Self {
                hosts: vec!["api.example.com".into()],
                methods: vec!["GET".into(), "POST".into()],
                tier: LlmTier::Tier2,
                local: false,
                write: WriteCeiling::Write,
                verb: None,
                enforced: false,
            }
        }
    }

    fn admit(t: &WasiHttpTarget, p: &P) -> Result<WasiHttpAdmitted, WasiHttpRefusal> {
        wasi_http_admission(
            t,
            &WasiHttpPolicy {
                allowed_hosts: &p.hosts,
                allowed_methods: &p.methods,
                max_llm_tier: p.tier,
                local_egress_only: p.local,
                max_write_ceiling: p.write,
                http_verb_ceiling: p.verb,
                write_ceiling_enforced: p.enforced,
                strict_egress: false,
                insecure_http_opt_in: false,
            },
        )
    }

    fn policy_of(r: Result<WasiHttpAdmitted, WasiHttpRefusal>) -> &'static str {
        r.expect_err("expected a refusal").policy
    }

    /// Control: a request every gate admits.
    #[test]
    fn an_allowed_host_and_verb_is_admitted() {
        let a = admit(&target("GET", "api.example.com"), &P::default()).unwrap();
        assert_eq!(a.host, "api.example.com");
        assert_eq!(a.host_for_limit, "api.example.com:443");
        assert!(!a.mutates);
    }

    /// The upstream handler had NONE of these.
    #[test]
    fn the_talos_http_gate_set_applies() {
        let p = P::default();
        assert_eq!(
            policy_of(admit(&target("GET", "evil.example.org"), &p)),
            "allowed-hosts"
        );
        let star = P {
            hosts: vec!["*".into()],
            ..P::default()
        };
        // SSRF on an IP-literal authority, including a decimal spelling of
        // loopback and the cloud metadata endpoint — even under `*`.
        for a in [
            "127.0.0.1",
            "2130706433",
            "169.254.169.254",
            "[::1]",
            "10.0.0.5:8080",
        ] {
            let pol = policy_of(admit(&target("GET", a), &star));
            assert!(
                pol.starts_with("private-ip")
                    || pol.contains("metadata")
                    || pol.starts_with("link-local"),
                "{a}: {pol}"
            );
        }
        assert_eq!(
            policy_of(admit(
                &target("GET", "api.example.com"),
                &P {
                    hosts: vec![],
                    ..P::default()
                }
            )),
            "no-allowlist-configured"
        );
        // Method allowlist: an undeclared verb, and verbs outside the closed set.
        for m in ["DELETE", "HEAD", "CONNECT", "TRACE", "PROPFIND"] {
            assert_eq!(
                policy_of(admit(&target(m, "api.example.com"), &p)),
                "method-allowlist",
                "{m}"
            );
        }
    }

    #[test]
    fn egress_posture_applies_on_this_channel_too() {
        let star = P {
            hosts: vec!["*".into()],
            ..P::default()
        };
        // Tier 1: provider hostname and public literals refused.
        let t1 = P {
            tier: LlmTier::Tier1,
            ..star
        };
        assert_eq!(
            policy_of(admit(&target("POST", "api.anthropic.com"), &t1)),
            "tier1-llm-egress"
        );
        assert_eq!(
            policy_of(admit(&target("GET", "8.8.8.8"), &t1)),
            "tier1-public-ip-egress"
        );
        // Tier 2 + local-only egress: a public literal is refused.
        let local = P {
            hosts: vec!["*".into()],
            local: true,
            ..P::default()
        };
        assert_eq!(
            policy_of(admit(&target("GET", "8.8.8.8"), &local)),
            "local-egress-public-ip"
        );
    }

    /// The write ceiling applies on its VERB axis, override included.
    #[test]
    fn the_write_ceiling_governs_mutating_verbs() {
        let ro = P {
            write: WriteCeiling::ReadOnly,
            enforced: true,
            ..P::default()
        };
        let r = admit(&target("POST", "api.example.com"), &ro).unwrap_err();
        assert_eq!(r.policy, "write-ceiling");
        assert!(
            r.detail.is_some(),
            "the verb-rule detail travels with the refusal"
        );
        // A read is still admitted.
        assert!(admit(&target("GET", "api.example.com"), &ro).is_ok());
        // The verb override lifts it, exactly as on talos:core/http.
        let granted = P {
            verb: Some(WriteCeiling::Write),
            ..ro
        };
        assert!(admit(&target("POST", "api.example.com"), &granted).is_ok());
        // Unenforced deployments refuse nothing on this axis.
        let off = P {
            write: WriteCeiling::ReadOnly,
            ..P::default()
        };
        assert!(admit(&target("POST", "api.example.com"), &off).is_ok());
    }

    #[test]
    fn plaintext_and_other_schemes_are_refused() {
        let mut t = target("GET", "api.example.com");
        t.scheme = Some(wt::Scheme::Http);
        assert_eq!(policy_of(admit(&t, &P::default())), "insecure-scheme");
        t.scheme = Some(wt::Scheme::Other("ftp".into()));
        assert!(admit(&t, &P::default()).is_err());
    }

    /// Control for the round-trip rule: well-formed ports and userinfo pass.
    #[test]
    fn a_well_formed_authority_round_trips() {
        let p = P::default();
        let a = admit(&target("GET", "api.example.com:8443"), &p).unwrap();
        assert_eq!(a.host_for_limit, "api.example.com:8443");
        assert!(admit(&target("GET", "user:pw@api.example.com"), &p).is_ok());
        let star = P {
            hosts: vec!["*".into()],
            ..P::default()
        };
        assert_eq!(
            policy_of(admit(&target("GET", "[::1]:8080"), &star)),
            policy_of(admit(&target("GET", "[::1]"), &star)),
            "an IPv6 literal with a port is still judged as that literal"
        );
    }

    #[test]
    fn a_malformed_authority_is_refused() {
        for a in [
            "",
            "evil.com/@api.example.com",
            "api.example.com:99999",
            "api.example.com:",
            "api.example.com:0443",
        ] {
            let r = admit(&target("GET", a), &P::default());
            assert!(r.is_err(), "{a:?}: {r:?}");
        }
    }

    // ── The handler itself, on a real context ─────────────────────────────

    use std::collections::HashMap;
    use std::sync::Arc;

    fn trusted_ctx(hosts: &[&str], methods: &[&str]) -> TalosContext {
        TalosContext::new(
            crate::wit_inspector::CapabilityWorld::Trusted,
            hosts.iter().map(|h| (*h).to_string()).collect(),
            methods.iter().map(|m| (*m).to_string()).collect(),
            128,
            HashMap::new(),
            None,
            None,
            false,
            None,
            Arc::new(crate::expose_fallback::ExposeFallback::new()),
            LlmTier::Tier2,
            None,
        )
        .expect("context builds")
    }

    fn push_request(
        ctx: &mut TalosContext,
        method: wt::Method,
        authority: &str,
    ) -> Resource<HostOutgoingRequest> {
        ctx.table
            .push(HostOutgoingRequest {
                method,
                scheme: Some(wt::Scheme::Https),
                authority: Some(authority.to_string()),
                path_with_query: Some("/x".to_string()),
                headers: Default::default(),
                body: None,
            })
            .expect("push request")
    }

    fn error_code(e: wasmtime_wasi_http::p2::HttpError) -> wt::ErrorCode {
        e.downcast().expect("a guest-visible ErrorCode, not a trap")
    }

    /// A refused request is refused BY THE HANDLER, recorded to the guest
    /// diagnostic sink AND the WORM ledger, and its resource is consumed.
    #[tokio::test]
    async fn a_refused_request_is_recorded_and_never_sent() {
        let mut ctx = trusted_ctx(&["api.example.com"], &["GET"]);
        let sink: crate::context::HostDiagSink = Arc::new(std::sync::Mutex::new(Vec::new()));
        ctx.host_diag_sink = Some(sink.clone());
        let ledger = Arc::new(tokio::sync::Mutex::new(crate::audit::ExecutionLedger::new(
            "wf", "exec",
        )));
        ctx.set_audit_ledger(ledger.clone());

        let req = push_request(&mut ctx, wt::Method::Get, "169.254.169.254");
        let rep = req.rep();
        let err = gated_handle(&mut ctx, req, None).expect_err("SSRF target refused");
        assert!(matches!(error_code(err), wt::ErrorCode::HttpRequestDenied));

        let lines = sink.lock().unwrap().clone();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("http-fetch denied by policy")
                    && l.contains("wasi:http 169.254.169.254")),
            "{lines:?}"
        );
        assert_eq!(ledger.lock().await.current_sequence, 1, "one ledger event");
        assert!(
            ctx.table
                .get(&Resource::<HostOutgoingRequest>::new_own(rep))
                .is_err(),
            "the refused request's resource was consumed"
        );
    }

    /// Dry-run: a mutating verb is answered with a mock, never sent.
    #[tokio::test]
    async fn dry_run_mocks_a_mutating_request() {
        let mut ctx = trusted_ctx(&["api.example.com"], &["POST"]);
        ctx.set_dry_run(true);
        let req = push_request(&mut ctx, wt::Method::Post, "api.example.com");
        let fut = gated_handle(&mut ctx, req, None).expect("mocked");
        let fut = ctx.table.delete(fut).unwrap();
        assert!(fut.is_ready(), "answered in place, no task spawned");
        let resp = fut.unwrap_ready().unwrap().expect("a mock response");
        assert_eq!(resp.resp.status(), 200);
        assert_eq!(resp.resp.headers()["x-talos-dry-run"], "true");
    }

    /// An admitted request reaches the SEND path (a pending future from the
    /// hardened hooks), and spends one unit of the shared HTTP budget.
    #[tokio::test]
    async fn an_admitted_request_is_sent_and_charged() {
        let mut ctx = trusted_ctx(&["api.example.com"], &["GET"]);
        let before = ctx
            .http_call_count
            .load(std::sync::atomic::Ordering::Relaxed);
        let req = push_request(&mut ctx, wt::Method::Get, "api.example.com");
        let fut = gated_handle(&mut ctx, req, None).expect("admitted");
        let fut = ctx.table.delete(fut).unwrap();
        assert!(
            !fut.is_ready(),
            "handed to the send path, which runs in a task"
        );
        assert_eq!(
            ctx.http_call_count
                .load(std::sync::atomic::Ordering::Relaxed),
            before + 1
        );
        // A refusal spends nothing.
        let req = push_request(&mut ctx, wt::Method::Get, "evil.example.org");
        assert!(gated_handle(&mut ctx, req, None).is_err());
        assert_eq!(
            ctx.http_call_count
                .load(std::sync::atomic::Ordering::Relaxed),
            before + 1
        );
    }

    // ── The send path: connect-time SSRF ──────────────────────────────────

    fn get_localhost(port: u16) -> http::Request<HyperOutgoingBody> {
        let body: HyperOutgoingBody = http_body_util::Empty::<Bytes>::new()
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed_unsync();
        http::Request::builder()
            .method("GET")
            .uri(format!("http://localhost:{port}/"))
            .body(body)
            .unwrap()
    }

    fn config() -> OutgoingRequestConfig {
        OutgoingRequestConfig {
            use_tls: false,
            connect_timeout: Duration::from_secs(5),
            first_byte_timeout: Duration::from_secs(5),
            between_bytes_timeout: Duration::from_secs(5),
        }
    }

    async fn resolve(fut: HostFutureIncomingResponse) -> Result<IncomingResponse, wt::ErrorCode> {
        match fut {
            HostFutureIncomingResponse::Pending(h) => h.await.expect("no trap"),
            HostFutureIncomingResponse::Ready(r) => r.expect("no trap"),
            HostFutureIncomingResponse::Consumed => panic!("consumed"),
        }
    }

    /// A HOSTNAME that resolves to loopback is refused at connect by the
    /// hardened send path — the case the gate cannot see (it runs before DNS).
    /// CONTROL: upstream's default send path, which this replaced, reaches the
    /// same listener. Both directions run against one live socket.
    #[tokio::test]
    async fn the_send_path_refuses_a_name_that_resolves_private_where_upstream_connected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _read = sock.read(&mut buf).await;
                let _written = sock
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await;
            }
        });

        // Control: the path this replaced connects to loopback.
        let upstream = wasmtime_wasi_http::p2::default_send_request(get_localhost(port), config());
        let reached = resolve(upstream).await;
        assert!(
            matches!(&reached, Ok(r) if r.resp.status() == 200),
            "control: upstream's raw connect reaches the loopback listener"
        );

        let ctx = trusted_ctx(&["localhost"], &["GET"]);
        let mut hooks = HardenedWasiHttpHooks::new(ctx.http_client.clone());
        let fut = hooks.send_request(get_localhost(port), config()).unwrap();
        let refused = resolve(fut).await;
        assert!(
            matches!(refused, Err(wt::ErrorCode::ConnectionRefused)),
            "the hardened path refuses the resolved loopback address: {:?}",
            refused.map(|r| r.resp.status())
        );
    }

    // ── Wiring pins ───────────────────────────────────────────────────────

    /// Strip whole-line `//` comments, which quote the banned calls.
    fn code_only(src: &str) -> String {
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
        let start = src
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} not found"));
        let rest = &src[start..];
        &rest[..rest.find("\n}\n").unwrap_or(rest.len())]
    }

    /// The trusted linker links THIS handler, not upstream's. TEXTUAL, and it
    /// says so: no test here instantiates a component that imports
    /// `wasi:http`, so what proves the gate BEHAVES is `gated_handle`'s own
    /// tests; this proves the linker reaches it. Lives outside `runtime.rs`
    /// so reverting that file cannot delete its own pin.
    #[test]
    fn the_trusted_handler_is_the_gated_one() {
        let runtime = code_only(include_str!("../runtime.rs"));
        let body = fn_body(&runtime, "fn build_trusted_linker(");
        let gated = format!("add_gated_{}(", "outgoing_handler");
        let upstream = format!("add_only_http_to_{}(", "linker_async");
        assert!(body.contains(&gated), "{body}");
        assert!(
            !body.contains(&upstream),
            "upstream's ungated handler is back: {body}"
        );
    }

    /// The send path is the hardened one, never `default_hooks()`.
    #[test]
    fn the_wasi_http_view_never_uses_default_hooks() {
        let ctx_src = code_only(include_str!("../context.rs"));
        let body = fn_body(
            &ctx_src,
            "impl wasmtime_wasi_http::p2::WasiHttpView for TalosContext {",
        );
        assert!(body.contains("hooks: &mut self.wasi_http_hooks"), "{body}");
        assert!(!body.contains(&format!("default_{}()", "hooks")), "{body}");
    }
}
