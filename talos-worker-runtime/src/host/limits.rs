//! Shared per-execution resource caps, rate-limit constants, and the
//! platform-reserved NATS publish-prefix policy, with their
//! constants-contract test modules.

/// Maximum HTTP fetch calls per execution (prevents external API flooding).
pub(crate) const MAX_HTTP_CALLS_PER_EXECUTION: u64 = 1000;
/// M-6: maximum HTTP fetch calls to a SINGLE upstream host per execution.
///
/// Without this cap, a guest module can spend its global budget
/// (`MAX_HTTP_CALLS_PER_EXECUTION = 1000`) entirely against one host
/// and turn the worker into a third-party DoS amplification primitive
/// (1000 requests/sec from a typical fleet, with allowed_hosts
/// granted by a legitimate operator).
///
/// 200 is a fifth of the global cap — comfortable headroom for
/// legitimate paginated fetch loops while making the abuse pattern
/// unattractive. The circuit breaker (`circuit_breaker.rs`) handles
/// failure-driven cutoffs separately; this gate is about healthy-
/// upstream load shaping.
pub(crate) const MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION: u64 = 200;
/// Maximum database queries per execution.
pub(crate) const MAX_DB_QUERIES_PER_EXECUTION: u64 = 500;
/// RFC 0011 P2c: maximum `model::predict*` INPUTS per execution (a
/// batch of N counts N). Each input costs the controller a local embed
/// + an ANN query under the shared in-flight semaphore (cap 8), so an
/// unbounded guest loop would starve every other tenant's predict
/// traffic. 2000 ≈ 60+ full batches — far above any legitimate
/// classify node (inbox batches run ~25) while bounding the abuse case.
pub(crate) const MAX_MODEL_PREDICT_INPUTS_PER_EXECUTION: u64 = 2000;
/// Per-execution cap on `model::few-shot` CALLS. One fetch per LLM
/// fallback leg is the intended shape; the cap stops a guest loop from
/// turning the server-side decrypt path into a scan.
pub(crate) const MAX_MODEL_FEWSHOT_CALLS_PER_EXECUTION: u64 = 8;
/// Maximum NATS publish calls per execution.
pub(crate) const MAX_MESSAGING_PUBLISHES_PER_EXECUTION: u64 = 1000;
/// MCP-524: subject prefixes reserved for the platform that WASM modules
/// must NOT publish to via `wit_messaging`. The signed-RPC layer rejects
/// forged payloads on these subjects, but each rejected message costs
/// the controller a signature-verification + error-log line; a guest
/// looping to its rate-limit cap (1000/exec) burns ~50ms of controller
/// CPU + 1000 error logs per execution.
///
/// Each entry is a prefix matched with `starts_with`; trailing `.`s
/// keep them from accidentally matching legitimate user subjects (e.g.
/// `talos_app.*` doesn't match `talos.`).
///
/// The NATS-reserved namespaces are blocked too: NATS reserves the `$`
/// prefix wholesale for system subjects (`$SYS.*` server control,
/// `$JS.API.*` JetStream stream/consumer management, `$KV`/`$OBJ` stores,
/// …) and uses `_INBOX.` for request/reply inboxes. A guest has no
/// legitimate reason to publish to either. Crucially, absent fine-grained
/// NATS account permissions — NOT guaranteed; the single-user deploy path
/// ships without per-subject ACLs — this app-level check is the ONLY gate,
/// so e.g. `$JS.API.STREAM.DELETE.<name>` from guest code could otherwise
/// delete a JetStream stream. `$` has no trailing dot on purpose: the whole
/// prefix is reserved, so the bare marker blocks every current AND future
/// system namespace in one rule.
// INVARIANT (2026-06-04 messaging audit). This deny-list is a *publish-side*
// barrier only, and for the host-only `talos.*` subjects with no HMAC-verifying
// consumer (`talos.audit.ledger`, `talos.events.*`) it is the SOLE thing keeping
// guest code from forging messages on them. Two rules the audit confirmed hold
// and that any future change MUST preserve:
//   1. Every NEW host-only NATS subject the controller listens on or trusts must
//      be covered by a prefix here (today all are `talos.`-prefixed → covered).
//   2. Any NEW controller subscriber on a subject NOT covered by this deny-list
//      (i.e. one a guest could publish to) MUST HMAC-verify the message before
//      acting — never trust a guest-publishable subject. (The four data RPCs +
//      job dispatch already do; see `req.verify()`.)
// Deny-lists historically drift (PR #114/#115/#117); these two rules are why the
// surface is currently airtight despite no per-subject NATS ACLs.
pub(crate) const RESERVED_PUBLISH_PREFIXES: &[&str] = &[
    talos_workflow_job_protocol::subjects::NAMESPACE_PREFIX,
    "wasm.",   // wasm.log.* — controller WASM-log subscriber
    "$",       // NATS system subjects: $SYS.*, $JS.API.*, $KV, $OBJ, …
    "_INBOX.", // NATS request/reply inboxes
];

/// Returns `true` when `topic` is on the platform-reserved prefix
/// deny-list and must not be published from guest code. ASCII-prefix
/// match; subject characters in NATS are 7-bit anyway.
pub(crate) fn reject_reserved_topic_prefix(topic: &str) -> bool {
    RESERVED_PUBLISH_PREFIXES
        .iter()
        .any(|prefix| topic.starts_with(prefix))
}

/// MCP-756 (2026-05-13): NATS subjects rarely exceed 256 bytes (the
/// protocol limit is configurable but defaults are tiny). 1024 is a
/// generous cap that fits any reasonable subject hierarchy while
/// bounding the amplification path through `record_capability_denied`
/// (which writes the topic verbatim to the WORM audit ledger and
/// NATS-publishes it) AND through `tracing::warn!(topic = %topic)`
/// log lines. Sibling cap to wit_cache::MAX_CACHE_KEY_BYTES (also
/// 1024) — same threat model: short identifier-style strings that
/// flow into shared infrastructure surfaces.
pub(crate) const MAX_MESSAGING_TOPIC_BYTES: usize = 1024;

/// MCP-523: Maximum email sends per execution. Pre-fix `wit_email::send`
/// had no per-execution rate limit (every sibling outbound surface
/// did — `wit_http`, `wit_database`, `wit_messaging`, …). A buggy or
/// malicious WASM module could loop email sends until WASM execution
/// timeout. At a 100ms-per-call legitimate-API response time and a
/// 30s execution budget that's ~300 emails per execution, each
/// counted against the operator's third-party email-sending quota
/// (SendGrid / Postmark / etc.) and routed to recipients the
/// operator never reviewed. Cap at 50 per execution — matches
/// `MAX_RECIPIENTS` (the per-message recipient cap), so the
/// worst-case fanout per execution is 50×50 = 2500 deliveries
/// before the WASM is killed.
pub(crate) const MAX_EMAIL_SENDS_PER_EXECUTION: u64 = 50;
/// Per-message recipient cap (to + cc + bcc combined). Paired with
/// MAX_EMAIL_SENDS_PER_EXECUTION so the worst-case fanout per execution
/// is 50×50 = 2500 deliveries. MCP-541: pre-fix the cap only applied to
/// `msg.to.len()`; cc/bcc were unbounded, so the documented worst-case
/// fanout was a lie. Now enforces the total.
pub(crate) const MAX_EMAIL_RECIPIENTS_PER_MESSAGE: usize = 50;
/// MCP-537: per-execution cap on `wit_webhook::send` calls. Pre-fix
/// the webhook surface had NO rate limit (despite a misleading
/// comment on `wit_email::send` claiming the four sibling surfaces
/// all enforced one — wit_http, wit_database, wit_messaging do; only
/// wit_webhook didn't). Each call can fire up to `1 + max_retries`
/// (default 4) outbound POSTs of up to 1 MB body each, so a hot loop
/// from a compromised WASM module could blast hundreds of outbound
/// requests to operator-allowlisted hosts. Cap at 100 — matches the
/// "rare, intentional, not a hot-loop" semantics of webhook dispatch
/// in workflow design.
pub(crate) const MAX_WEBHOOK_SENDS_PER_EXECUTION: u64 = 100;
/// MCP-537: per-execution cap on `wit_graphql::execute` +
/// `execute_with_retry`. Same gap as wit_webhook above. GraphQL
/// queries can be expensive on the upstream server (deep selection
/// sets) and the worker's outbound bandwidth, so an upper cap of 200
/// matches the existing http_call ceiling spirit — generous for
/// normal pagination, tight enough to prevent abuse.
pub(crate) const MAX_GRAPHQL_QUERIES_PER_EXECUTION: u64 = 200;
/// MCP-583: per-call cap on `wit_webhook::send` retry count. Pre-fix
/// `max_retries` was caller-supplied `option<u32>` with no upper
/// bound — a module could pass `u32::MAX` and (combined with a
/// non-timeout transport error like connection-refused) loop the
/// retry path until the WASM execution timeout, holding a worker
/// slot. The companion `MAX_WEBHOOK_SENDS_PER_EXECUTION` bounds the
/// number of distinct send() calls; this bounds the retry fanout
/// PER call so the design-doc "1+max_retries (default 4) actual
/// POSTs" promise actually holds. 10 is a generous cap — sibling
/// `wit_graphql` does exponential backoff with the same upper-bound
/// semantics (caps backoff at 30s) but doesn't expose retry-count
/// to the caller at all.
pub(crate) const MAX_WEBHOOK_RETRIES_PER_SEND: u32 = 10;
/// MCP-583: per-call cap on `wit_webhook::send` retry sleep. Pre-fix
/// `retry_delay_ms` was caller-supplied `option<u32>` with no upper
/// bound — `u32::MAX` ms is ~50 days. Combined with the (formerly)
/// unbounded retry count, a single send() could block a worker
/// indefinitely. Matches `wit_graphql`'s 30s backoff cap.
pub(crate) const MAX_WEBHOOK_RETRY_DELAY_MS: u32 = 30_000;
/// MCP-584: per-call cap on `wit_http::fetch` / `wit_http::fetch_all`
/// / `wit_graphql::execute` `timeout_ms`. Pre-fix the WIT contract
/// exposes these as `option<u32>` so a module could pass `u32::MAX`
/// (~50 days) and tie up the reqwest client + worker thread awaiting
/// the response. Today's async-fuel accounting is observation-only
/// (`consume_async_fuel` computes a cost but does not deduct it from
/// the wasmtime store), so the WASM execution budget does not bound
/// this naturally. The 120s cap matches the convention already
/// established by `wit_agent_orchestration::invoke` at line 6095
/// (`timeout_ms.min(120_000)`).
pub(crate) const MAX_HTTP_TIMEOUT_MS: u32 = 120_000;
/// MCP-657: per-call cap on guest-supplied `wit_messaging::request`
/// timeout_ms. Sibling of MAX_HTTP_TIMEOUT_MS — without the cap a
/// guest could pass `u32::MAX` (~49 days) and the awaiting
/// `tokio::time::timeout` future would hold a worker task until the
/// NATS reply arrives or the deadline elapses. async fuel is
/// observation-only (MCP-583/584 class). 60s matches the NATS
/// req/reply convention — these are short interactive RPCs, not
/// long-poll patterns. Sibling cap to MAX_HTTP_TIMEOUT_MS but tighter
/// because NATS req/reply has a clearer interactivity expectation.
pub(crate) const MAX_MESSAGING_REQUEST_TIMEOUT_MS: u32 = 60_000;
/// MCP-720 (2026-05-13): timeout for `wit_object_storage::{put, get,
/// delete, list_objects}` send() calls. The shared `self.http_client`
/// (worker/src/context.rs:633) intentionally omits a client-level
/// `.timeout(...)` because LLM-stream paths need long-running
/// connections; per-operation timeouts at the call site are the
/// canonical shape (see `wit_llm::complete` line ~5991 which wraps
/// its `send` in a 60/120 s `tokio::time::timeout` accordingly).
/// Pre-fix the four S3 paths called `.send().await` bare — a slow or
/// unresponsive S3 backend (misconfigured `S3_ENDPOINT`, MinIO down,
/// upstream outage) would park the worker task indefinitely (TCP
/// keepalive only fires after hours by default). 120 s matches the
/// convention established by `MAX_HTTP_TIMEOUT_MS`; large-object
/// uploads on slow networks may need operator tuning later.
pub(crate) const OBJECT_STORAGE_TIMEOUT_MS: u64 = 120_000;
/// MCP-588: per-execution cap on guest-initiated `wit_secrets::get_secret`
/// calls. Pre-fix the surface had no rate limit — a module could loop
/// `get_secret` thousands of times within its fuel budget, each call
/// appending to the local audit ledger AND publishing to
/// `talos.audit.ledger` over NATS. The audit-pipeline DoS is the
/// concern (one execution flooding many MB of audit traffic); the
/// secret values themselves stay host-side. Host-initiated resolutions
/// (`resolve_vault_header` from http / graphql / webhook headers) are
/// bounded by their parent surface's per-execution cap. 100 is
/// generous — real modules typically consume 1-5 distinct secrets.
pub(crate) const MAX_SECRET_ACCESSES_PER_EXECUTION: u64 = 100;
/// MCP-585: per-call cap on `wit_embedding::generate` text input.
/// Pre-fix the text input was unbounded — a module could pass a
/// 100 MB string before the upstream OpenAI API returned 400. The
/// outbound network buffer + JSON-encode pass still consumed worker
/// memory and bandwidth for the whole string. 64 KiB is generous —
/// even text-embedding-3-large caps at 8192 tokens (~32 KiB at
/// typical 4 chars/token), so 64 KiB covers worst-case multi-byte
/// UTF-8 input that still falls within the model's token window.
pub(crate) const MAX_EMBEDDING_TEXT_BYTES: usize = 65_536;
/// Maximum bytes writable to the sandbox per execution (1 GiB).
pub(crate) const MAX_FS_BYTES_PER_EXECUTION: u64 = 1_073_741_824;
/// Maximum log messages per execution (prevents NATS flooding).
pub(crate) const MAX_LOG_MESSAGES_PER_EXECUTION: u64 = 10_000;
/// Maximum Tier-2 secret exposures per user per day (global limit across all executions).
pub(crate) const MAX_TIER2_EXPOSES_PER_USER_PER_DAY: u64 = 100;
/// Maximum concurrent LLM streams per execution (prevents resource leaks).
pub(crate) const MAX_LLM_STREAMS_PER_EXECUTION: usize = 10;
/// MCP-1113 (2026-05-16): defense-in-depth caps on `spawn_sse_stream`'s
/// per-stream buffers. The SSE reader receives bytes from an external
/// LLM provider on a tokio::spawn'd background task. A misbehaving /
/// compromised / MITM'd provider could grow three buffers unbounded:
///
///  * `buffer` — accumulates raw chunks until `\n`. Provider that
///    streams a long line with no newline → buffer grows monotonically
///    until worker OOM.
///  * `tool_input_bufs` map — one entry per `content_block_start`
///    event whose content_block.type is `tool_use`. Provider that
///    emits many starts without matching stops → HashMap grows.
///  * Each entry's accumulated `input_json_delta` string — provider
///    that streams long tool input chunks without `content_block_stop`
///    → individual entry grows.
///
/// Caps mirror the sibling SSE consumer at line ~10168
/// (TALOS_SSE_MAX_EVENT_BYTES, 10 MiB default). The other SSE path
/// already enforces this — `spawn_sse_stream` is the holdout.
///
/// Same defense-in-depth class as MCP-1013 (wit_data_transform XML/
/// JSON cap), MCP-1014 (WIT outbound body cap), MCP-1024/1026/1033
/// (signed-RPC structural caps at verify time).
pub(crate) const MAX_LLM_STREAM_BUFFER_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const MAX_TOOL_INPUT_BUFS_PER_STREAM: usize = 64;
pub(crate) const MAX_TOOL_INPUT_BUF_BYTES: usize = 1024 * 1024;
/// MCP-1213 (2026-05-18): cap the non-streaming LLM completion body
/// at 10 MiB. Pre-fix `response.json()` and `response.text()` buffered
/// the full body with no size limit — a misbehaving / compromised
/// provider returning a 1 GB body would OOM the worker pod. 10 MiB
/// is comfortable for any legitimate completion (typical responses
/// are 1-100 KiB).
pub(crate) const MAX_LLM_BODY_BYTES: usize = 10 * 1024 * 1024;
/// Hard cap on the caller-supplied `options` JSON for
/// `llm::complete-with-options` (provider-feature passthrough). Provider
/// tuning objects are tiny (a handful of scalar fields); 8 KiB is generous
/// while bounding the merge work + outbound body growth from a runaway or
/// hostile config value.
pub(crate) const MAX_PROVIDER_OPTIONS_BYTES: usize = 8 * 1024;
/// MCP-1213 (2026-05-18): hard cap on per-call LLM exchange wall time
/// (send + receive). Pre-fix the 120s `tokio::time::timeout` wrapped
/// ONLY `.send()` (header receipt) — body-read via `.json()` / `.text()`
/// had no timeout, so a slow/stuck body stream from the provider would
/// hang the WASM call indefinitely (real prod symptom: daily-brief
/// synthesize node ran for 5+ minutes with no progress after MCP-1212
/// re-sign fix unmasked the underlying hang). 120s covers reasonable
/// Claude/GPT-4 latency for long outputs; legitimate calls finish in
/// seconds. Ollama (local) uses LOCAL_LLM_EXCHANGE_TIMEOUT_SECS.
pub(crate) const EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS: u64 = 120;
pub(crate) const LOCAL_LLM_EXCHANGE_TIMEOUT_SECS: u64 = 60;
/// MCP-1215 (2026-05-18): connect-phase timeout for the SSE-based
/// streaming LLM path (`wit_llm_streaming::spawn_sse_stream`). Pre-fix
/// the spawned task's `req_builder.json(&body).send().await` was bare
/// — the global `http_client` deliberately has no client-level timeout
/// (LLM-stream paths legitimately hold long-lived connections), and
/// the sibling `wit_http_stream::connect` had this exact gap closed
/// by MCP-721 with a 30 s connect cap. `wit_llm_streaming` was the
/// holdout: a provider that opens TCP but never sends response headers
/// (network split, upstream-LB stall, MITM) would park the spawned
/// task until the engine's node-level timeout fired, with no useful
/// error surfaced to the guest. The corresponding non-streaming path
/// `wit_llm::complete` is covered by the MCP-1213
/// `EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS` wrapper. 30 s matches MCP-721;
/// legitimate LLM connect typically completes in 100–500 ms.
pub(crate) const LLM_STREAM_CONNECT_TIMEOUT_SECS: u64 = 30;
/// MCP-1215 (2026-05-18): idle-between-chunks timeout for the LLM
/// streaming bytes_stream loop. Defense-in-depth on top of the
/// connect timeout: a provider that completes the HTTP handshake and
/// then goes silent (no bytes, no ping) would otherwise let the
/// spawned task hold a stream slot for the entire execution timeout,
/// blocking the guest's `next_event` indefinitely. Both major
/// providers emit something within seconds: Anthropic sends `ping`
/// events ~every 15 s as keep-alive, OpenAI streams chunks
/// continuously during generation. 60 s is generous headroom that
/// still catches a genuinely-stuck stream within one node timeout
/// window. The general-purpose SSE path (`wit_http_stream`) does NOT
/// get this cap — it serves push-notification use cases that
/// legitimately stay quiet for hours.
pub(crate) const LLM_STREAM_IDLE_TIMEOUT_SECS: u64 = 60;
/// Maximum events per execution for the events interface.
pub(crate) const MAX_EVENTS_PER_EXECUTION: u64 = 100;

/// Maximum event payload size (1 MiB).
pub(crate) const MAX_EVENT_PAYLOAD_BYTES: usize = 1_048_576;
/// MCP-600 (2026-05-12): Maximum metadata size for `events::emit_with_metadata`
/// (64 KiB). Pre-fix, `metadata` was unbounded while `payload` was 1 MiB
/// capped — a guest could pass up to ~30 MiB metadata (limited only by
/// the linear-memory cap), forcing the host to re-allocate, serialize
/// it into the event JSON, and only THEN fail downstream when NATS
/// rejected the over-1MiB publish. Same DoS amplification class as
/// MCP-585 (unbounded embedding text). Metadata is meant for small
/// auxiliary structured fields (correlation IDs, source tags) — 64 KiB
/// is generous and well below NATS's 1 MiB default ceiling.
pub(crate) const MAX_EVENT_METADATA_BYTES: usize = 65_536;
/// Maximum concurrent SSE connections per execution.
pub(crate) const MAX_SSE_STREAMS_PER_EXECUTION: usize = 5;
/// L-finding-7 (2026-05-23): per-host cumulative SSE connect cap.
///
/// `MAX_SSE_STREAMS_PER_EXECUTION` (5) is the global ceiling on
/// concurrent streams, but pre-fix all 5 could be opened against ONE
/// upstream — the worker holds a long-lived connection slot per
/// stream and amplifies inbound bandwidth from that target back into
/// the cluster for the full execution timeout. With 5 concurrent
/// streams, capping per-host CUMULATIVE connects at 3 forces a
/// well-behaved workflow that wants multi-stream subscribed-many
/// pattern to distribute across hosts, while still permitting
/// reconnect-on-disconnect within the same host (3 attempts is
/// generous for transient SSE drops). Tracking cumulative connects
/// (not "currently open") matches `MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION`'s
/// semantics and short-circuits a churn-loop abuse pattern
/// (connect → drop → reconnect → repeat to bypass the concurrent cap).
pub(crate) const MAX_SSE_CONNECTS_PER_HOST_PER_EXECUTION: u64 = 3;
/// Maximum bytes returned by files::read (64 MiB — prevents OOM on large files).
pub(crate) const MAX_FILE_READ_BYTES: usize = 64 * 1024 * 1024;
/// Maximum bytes returned by object-storage::get (64 MiB — prevents OOM on large objects).
pub(crate) const MAX_OBJECT_READ_BYTES: usize = 64 * 1024 * 1024;
/// MCP-1115 (2026-05-16): cap on the XML LIST response from
/// `wit_object_storage::list_objects`. The S3-compatible LIST API
/// returns `<ListBucketResult>` XML; for max_keys=1000 (the API cap)
/// with maximum-realistic 1 KiB-per-entry XML serialisation that's
/// ~1 MiB. 4 MiB is generous headroom + bounds a malicious /
/// compromised / MITM'd S3-compatible endpoint that ignores
/// max-keys=1000 and returns mega-XML to OOM the worker via
/// `response.text().await` buffering.
pub(crate) const MAX_LIST_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// MCP-1076 (2026-05-16): Maximum outbound request body for WIT HTTP /
/// webhook host functions. Pre-fix three inline `const _: usize = 10_000_000`
/// copies existed: `wit_http::fetch::MAX_HTTP_BODY_BYTES`,
/// `wit_http::fetch_all::MAX_HTTP_BODY_BYTES_BATCH`, and
/// `wit_webhook::send::MAX_WEBHOOK_BODY_BYTES`. Same N-inline-copies
/// drift class as MCP-1075 (CSRF cookie builder), MCP-1040/1041
/// (session cookies), and MCP-1014 (the original outbound-body
/// uncapped fix that introduced all three constants). Future tuning
/// of the cap (e.g., to 20 MB for larger payloads, or different caps
/// per method) now lands in ONE place. Closes the MCP-1014 trio's
/// drift hazard.
pub(crate) const MAX_OUTBOUND_HTTP_BODY_BYTES: usize = 10_000_000;

/// MCP-1105 (2026-05-16): cap caller-supplied header count on every
/// outbound WIT host path that iterates `req.headers`.
///
/// Five sites — `wit_http::fetch`, `wit_http::fetch_all` (per-batch
/// entry), `wit_graphql::execute_graphql_inner`, `wit_webhook::send`,
/// `wit_http_stream::connect` — accept caller-supplied
/// `Vec<(String, String)>` and iterate, calling
/// `resolve_vault_header` per entry. `resolve_vault_header` consults
/// `SecretsManager` on every `vault://` value, which hits the DB. A
/// guest with HTTP capability could pass 10000 headers (each
/// `vault://path/...`) and force the host to do 10000 sequential
/// vault lookups BEFORE any outbound request fires — for `fetch_all`,
/// multiply by the batch size and the retry budget.
///
/// HTTP servers reject requests with too many headers (nginx default
/// 100, IIS default 16) so the outbound request fails anyway — but
/// the host has already paid the DB-traffic cost.
///
/// Real-world APIs accept 10–20 headers (Content-Type, Authorization,
/// Accept, User-Agent, vendor-specific). 64 is comfortable headroom.
pub(crate) const MAX_OUTBOUND_HEADERS: usize = 64;

/// MCP-1148 (2026-05-16): cap caller-supplied URL length at the WIT
/// host boundary.
///
/// Sibling defense-in-depth gap to MCP-1013/1014 (caller-controlled
/// `String` / `Vec<u8>` in WIT host functions needs explicit caps —
/// wasmtime memory limits the GUEST, not the host's clones of the
/// crossed-boundary data).
///
/// Every outbound HTTP / GraphQL / webhook path runs `url::Url::parse`
/// on `req.url` BEFORE any other validation. `url::Url::parse` is
/// O(N) in URL length; a guest with HTTP capability passing a 10 MB
/// URL string forces the host to materialise the String at the WIT
/// boundary, then walk the parser over every byte, for every call.
/// `MAX_HTTP_CALLS_PER_EXECUTION = 1000` means one execution can pay
/// 10 GB of URL-parse work via a hostile guest.
///
/// 8 KiB matches the de-facto industry maximum (Apache `LimitRequestLine`
/// default 8190, Nginx `large_client_header_buffers` default 8K,
/// IIS `MaxFieldLength` default 16K). RFC 3986 doesn't formally cap
/// URL length but >8K URLs fail at most real-world ingress anyway, so
/// rejecting at the WIT boundary just turns a downstream failure mode
/// (502 from the target) into a loud failure mode (Invalidurl) with
/// no wasted host parse work. Real APIs use far shorter URLs (typical
/// REST URL is <500 bytes).
pub(crate) const MAX_OUTBOUND_URL_BYTES: usize = 8192;

/// MCP-1114 (2026-05-16): cap response-header count + per-value size
/// on inbound responses from external servers.
///
/// Sibling defense-in-depth gap to MCP-1105 (which capped OUTBOUND
/// headers). Both `wit_http::fetch` and `wit_http::fetch_all` collect
/// `response.headers()` into a `Vec<(String, String)>` via
/// `.iter().map(...).collect()` with NO upstream-count cap and NO
/// per-value-size cap. reqwest + hyper enforce h1's
/// `max_buf_size` (8 KiB default) on the headers BLOCK, but the
/// per-header parsing splits that buffer into many `HeaderValue`s
/// inside the response. For HTTP/2 there's `http2_max_header_list_size`
/// which reqwest leaves at hyper's default (uncapped on receive). A
/// malicious / compromised / MITM'd server could:
///
///  * Return 10k+ short headers via HTTP/2 — host materialises 10k
///    `(String, String)` tuples + collects into Vec; ~64 bytes per
///    tuple × 10k = ~640 KiB of host RAM per response, multiplied
///    by concurrent WASM calls.
///  * Return a few headers with multi-MB values via either protocol
///    if the response is chunked (each `HeaderValue` clone allocates
///    its own owned String).
///
/// 128 inbound headers is 2× the outbound cap because legitimate
/// servers carry more (CORS, security headers, Vary, multiple
/// Set-Cookie). 16 KiB per value is generous (long Set-Cookie /
/// content-security-policy strings live in that range).
///
/// Overflow → `wit_http::Error::Networkerror`. The connection has
/// already been opened so a hard reject is the right shape — a
/// well-behaved server cannot legitimately exceed these bounds, and
/// degrading silently (truncation) would change header semantics
/// (truncated cookie → broken session). Sibling shape to MCP-1014
/// (outbound body cap) and MCP-1113 (LLM SSE buffer cap).
pub(crate) const MAX_INBOUND_HEADERS: usize = 128;
pub(crate) const MAX_INBOUND_HEADER_VALUE_BYTES: usize = 16 * 1024;

/// Operator opt-in: allow modules to reach hostnames that resolve to RFC1918 /
/// loopback / link-local IPs, when those hostnames are explicitly named in the
/// module's `allowed_hosts` (not via `"*"`). IP literals to private ranges
/// stay rejected unconditionally; wildcard allowlists keep full SSRF protection.
///
/// The intended use case is local-development bridging — e.g. a worker
/// container reaching a sibling service on `host.docker.internal:3030`.
/// Default off; flip to "1" / "true" only on deployments where the worker's
/// network exposure is operator-controlled (no untrusted module authors).
///
/// # Security implications
///
/// Enabling this flag weakens SSRF protection: a module with an explicit
/// `allowed_hosts` entry for a hostname the operator controls can reach
/// internal services behind that hostname. Before enabling, verify:
///
/// 1. **No untrusted module authors** — only operator-authored modules
///    should be deployed on workers with this flag set.
/// 2. **Explicit hosts only** — the bypass is scoped to exact-match
///    hostnames in `allowed_hosts`; `"*"` does NOT trigger the bypass.
/// 3. **IP literals still blocked** — `http://127.0.0.1` and
///    `http://169.254.169.254` (cloud metadata) remain denied regardless.
/// 4. **DNS rebinding** — an attacker who controls a hostname's DNS can
///    point it at internal IPs. This flag trusts that explicitly-listed
///    hostnames have stable, operator-controlled DNS.
///
/// Read once at startup. Restart the worker after changing the env var.
// MCP-1060 (2026-05-15): routed through the canonical
// `bool_env_or_default` helper rather than an inline `matches!` copy.
// This site originally accepted `1 | true | yes | on` — the canonical
// helper accepts the same plus `false | 0 | no | off` for explicit
// negation, which is a strict-superset behaviour change (operators
// who set `=off` previously got `false` via the no-match arm; same
// result now via the recognised-falsy arm).
pub(crate) static ALLOW_PRIVATE_HOST_TARGETS: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| {
        let raw_enabled =
            talos_config::bool_env_or_default("WORKER_ALLOW_PRIVATE_HOST_TARGETS", false);
        // wasm-security-review (2026-05-22): refuse to honour the flag
        // in production. The flag is a dev-only convenience (reaching
        // `host.docker.internal` etc.) and shouldn't widen the SSRF
        // blast radius on a production deployment. Matches the
        // `ssrf_resolver` production gate so the two layers agree on
        // when the bypass is actually live.
        let is_prod = talos_config::is_production();
        let enabled = raw_enabled && !is_prod;
        if raw_enabled && is_prod {
            tracing::warn!(
                "WORKER_ALLOW_PRIVATE_HOST_TARGETS=true is ignored in production. \
                 The env toggle is dev-only — unset it on this deployment, or \
                 unset RUST_ENV=production if this is a single-pod dev cluster."
            );
        } else if enabled {
            // L-2: structured WARN at first lookup so operators see in
            // dev logs that the SSRF defense is relaxed. The flag is a
            // "trust me, I know what I'm doing" escape hatch — it
            // should be visible at runtime, not silent.
            tracing::warn!(
                "WORKER_ALLOW_PRIVATE_HOST_TARGETS=true — \
                 SSRF defense relaxed for hostnames in allowed_hosts. \
                 IP literals to private ranges remain blocked. \
                 Dev-only — production deployments ignore this flag."
            );
        }
        enabled
    });

#[cfg(test)]
mod reserved_topic_prefix_tests {
    //! MCP-524: pin the platform-reserved subject prefixes so a
    //! future refactor that loosens the list surfaces here.
    use super::reject_reserved_topic_prefix;

    #[test]
    fn rejects_talos_internal_subjects() {
        // Signed-RPC subjects — every one of these is platform-owned.
        // Each rejected guest publish would still cost the controller
        // a signature-verification + error-log line, hence the deny.
        for subj in &[
            "talos.memory.op",
            "talos.graph.search",
            "talos.database.query",
            "talos.state.write",
            "talos.integration_state.op",
            "talos.results.abc123",
            "talos.workers.heartbeat.worker-1",
            "talos.workers.cmd.shutdown",
            "talos.alerts.execution_failed",
            "talos.", // bare prefix
        ] {
            assert!(
                reject_reserved_topic_prefix(subj),
                "must reject reserved subject {subj}"
            );
        }
    }

    #[test]
    fn rejects_wasm_internal_subjects() {
        // wasm.log.* feeds the controller's WASM-log subscriber.
        for subj in &["wasm.log.execution-123", "wasm.log.", "wasm."] {
            assert!(
                reject_reserved_topic_prefix(subj),
                "must reject reserved subject {subj}"
            );
        }
    }

    #[test]
    fn allows_user_namespaced_subjects() {
        // Modules should use their own subject namespace. A subject
        // that LOOKS like talos but isn't `talos.` prefixed (e.g.
        // `talos_app.*`) must pass — only the exact `talos.` and
        // `wasm.` prefixes are reserved.
        for subj in &[
            "app.orders.created",
            "team_a.events.user_signed_up",
            "talos_app.notifications", // no trailing dot match
            "wasmer.something",        // no trailing dot match
            "my-org.module-a.event",
            "events.payment.captured",
        ] {
            assert!(
                !reject_reserved_topic_prefix(subj),
                "must allow user-namespaced subject {subj}"
            );
        }
    }

    #[test]
    fn empty_subject_is_not_reserved() {
        // Empty subject is a NATS-level error elsewhere; this helper
        // only handles the prefix concern. Don't accidentally match
        // empty against `""` prefix (would always be true).
        assert!(!reject_reserved_topic_prefix(""));
    }

    #[test]
    fn rejects_nats_reserved_system_and_inbox_subjects() {
        // NATS reserves `$` wholesale for system subjects, and `_INBOX.`
        // for request/reply. A guest must not publish to either — most
        // dangerously `$JS.API.*` (JetStream management) when the worker's
        // NATS account lacks per-subject ACLs.
        for subj in &[
            "$SYS.REQ.SERVER.PING",
            "$JS.API.STREAM.DELETE.MY_STREAM",
            "$JS.API.CONSUMER.DELETE.S.C",
            "$KV.store.key",
            "$OBJ.bucket.chunk",
            "$", // bare marker
            "_INBOX.aBcD1234efGh5678",
            "_INBOX.",
        ] {
            assert!(
                reject_reserved_topic_prefix(subj),
                "must reject NATS-reserved subject {subj}"
            );
        }
    }

    #[test]
    fn dollar_and_inbox_do_not_over_match_user_subjects() {
        // The `$` / `_INBOX.` additions must not catch legitimate subjects
        // that merely CONTAIN those tokens mid-string or share a stem.
        for subj in &[
            "orders.$pecial",     // `$` not at the start
            "_INBOXING.notice",   // shares stem but not the `_INBOX.` prefix
            "team._inbox.shadow", // `_inbox` lowercase, not at start
            "prices.usd$.update", // `$` mid-subject
        ] {
            assert!(
                !reject_reserved_topic_prefix(subj),
                "must allow user subject {subj}"
            );
        }
    }
}

#[cfg(test)]
mod webhook_and_graphql_rate_limit_constants {
    //! MCP-537: tripwires for the two new per-execution caps. Bumping
    //! either past these values needs an explicit operator decision
    //! (outbound bandwidth + third-party-quota implications) and should
    //! land here in a separate, reviewed commit.
    use super::{MAX_GRAPHQL_QUERIES_PER_EXECUTION, MAX_WEBHOOK_SENDS_PER_EXECUTION};

    #[test]
    fn webhook_cap_holds_at_one_hundred() {
        // Matches the "rare, intentional, not a hot loop" semantics of
        // workflow webhook dispatch. A single send can fan out to
        // 1+max_retries (default 4) actual POSTs, so the worst-case
        // outbound-request count from one execution is 400.
        assert_eq!(MAX_WEBHOOK_SENDS_PER_EXECUTION, 100);
    }

    #[test]
    fn graphql_cap_holds_at_two_hundred() {
        // Generous for paginated queries (5-page workflows are common),
        // tight enough to prevent abuse. Each query is also independently
        // gated by MAX_GRAPHQL_QUERY_BYTES (1 MB) at the request side.
        assert_eq!(MAX_GRAPHQL_QUERIES_PER_EXECUTION, 200);
    }

    #[test]
    // Constants-contract test: the const-evaluable assert IS the point.
    // (Latent clippy::assertions_on_constants, surfaced by --all-targets.)
    #[allow(clippy::assertions_on_constants)]
    fn webhook_cap_below_http_cap_by_design() {
        // Webhook is a strict-subset of HTTP semantically (POST only).
        // If a future PR bumps webhook past http, that's a structural
        // signal that the surfaces should converge instead.
        assert!(MAX_WEBHOOK_SENDS_PER_EXECUTION < super::MAX_HTTP_CALLS_PER_EXECUTION);
    }

    #[test]
    fn http_timeout_cap_matches_agent_orchestration_convention() {
        // MCP-584: this cap intentionally matches the
        // `wit_agent_orchestration::invoke` timeout cap (120_000 ms,
        // i.e. 2 min) so all caller-controlled timeouts in the WIT
        // surface use the same ceiling. If a future PR diverges them
        // it should land here in a separate, reviewed commit with
        // explicit operator-decision context.
        assert_eq!(super::MAX_HTTP_TIMEOUT_MS, 120_000);
    }

    #[test]
    fn webhook_retry_caps_bound_worst_case_dwell_time() {
        // MCP-583: bound the worst-case time a single send() can hold a
        // worker slot. Pre-fix the caller could pass max_retries =
        // retry_delay_ms = u32::MAX, blocking the slot for ~50 days *
        // 4 billion attempts. With these caps:
        //
        //   max_dwell = MAX_WEBHOOK_RETRIES_PER_SEND * MAX_WEBHOOK_RETRY_DELAY_MS
        //             = 10 * 30_000 = 300_000 ms = 5 minutes
        //
        // Still long enough that legitimate slow upstreams retry, short
        // enough that a malicious module can't camp a worker slot.
        // The 30s request timeout is on top of this (so worst-case
        // wall time is closer to (10 * 30_000) + (11 * 30_000) = 11
        // min) but the timeout is a separate axis from this test.
        let max_dwell_ms = (super::MAX_WEBHOOK_RETRIES_PER_SEND as u64)
            * (super::MAX_WEBHOOK_RETRY_DELAY_MS as u64);
        assert!(
            max_dwell_ms <= 5 * 60 * 1000,
            "max retry-sleep dwell time must stay ≤ 5 minutes; got {}ms",
            max_dwell_ms
        );
    }
}

#[cfg(test)]
mod llm_stream_timeout_constants {
    //! MCP-1215 (2026-05-18): tripwire pinning the connect and idle
    //! timeouts for `wit_llm_streaming::spawn_sse_stream`. Bumping
    //! either past the documented operator-decision ceiling (30 s
    //! connect to match MCP-721, 60 s idle to keep within one node
    //! timeout window) should land here in a reviewed commit.
    use super::{LLM_STREAM_CONNECT_TIMEOUT_SECS, LLM_STREAM_IDLE_TIMEOUT_SECS};

    #[test]
    fn connect_timeout_matches_sse_sibling() {
        // wit_http_stream::connect uses 30 s for its initial-send cap
        // (MCP-721). The streaming LLM path should match — both are
        // "open the TCP connection and receive response headers"
        // phases over the same global http_client.
        assert_eq!(LLM_STREAM_CONNECT_TIMEOUT_SECS, 30);
    }

    #[test]
    fn idle_timeout_bounds_one_node_window() {
        // 60 s idle is the documented ceiling: long enough to absorb
        // Anthropic's ~15 s `ping` cadence with comfortable headroom,
        // short enough that a stuck stream fails within the engine's
        // typical 60 s node timeout instead of dangling the slot for
        // the rest of the execution.
        assert_eq!(LLM_STREAM_IDLE_TIMEOUT_SECS, 60);
    }

    #[test]
    // Constants-contract test — see webhook_cap_below_http_cap_by_design.
    #[allow(clippy::assertions_on_constants)]
    fn connect_strictly_less_than_idle() {
        // The connect phase should always fail faster than the
        // per-chunk idle phase — a stuck handshake is a harder dead
        // signal than a slow stream of bytes.
        assert!(LLM_STREAM_CONNECT_TIMEOUT_SECS < LLM_STREAM_IDLE_TIMEOUT_SECS);
    }
}

#[cfg(test)]
mod email_recipient_cap_constants {
    //! MCP-541: tripwire pinning the per-message recipient cap and the
    //! sends-per-execution cap that combines with it. The MCP-523 design
    //! comment on `MAX_EMAIL_SENDS_PER_EXECUTION` promises "worst-case
    //! fanout per execution is 50×50 = 2500 deliveries" — both factors
    //! must hold for that promise. Any future change to either constant
    //! needs to land here in a reviewed commit.
    use super::{MAX_EMAIL_RECIPIENTS_PER_MESSAGE, MAX_EMAIL_SENDS_PER_EXECUTION};

    #[test]
    fn recipient_cap_holds_at_fifty() {
        assert_eq!(MAX_EMAIL_RECIPIENTS_PER_MESSAGE, 50);
    }

    #[test]
    fn sends_per_execution_cap_holds_at_fifty() {
        assert_eq!(MAX_EMAIL_SENDS_PER_EXECUTION, 50);
    }

    #[test]
    fn worst_case_fanout_invariant() {
        // Product of the two caps. Bumping either past this product
        // (currently 2500) needs an explicit operator decision about
        // third-party send-quota implications.
        let worst_case =
            (MAX_EMAIL_SENDS_PER_EXECUTION as usize) * MAX_EMAIL_RECIPIENTS_PER_MESSAGE;
        assert_eq!(worst_case, 2500);
    }
}
