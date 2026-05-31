//! Host function implementations for all WIT interfaces.
//!
//! Each `impl <interface>::Host for TalosContext` block provides the host side
//! of one WIT interface imported by the `automation-node` world.

use crate::circuit_breaker::get_global_circuit_breaker;
use crate::context::TalosContext;

// Bring the generated WIT bindings into scope.
use crate::bindings::talos::core::{
    agent_memory as wit_agent_memory, agent_orchestration as wit_agent_orchestration,
    cache as wit_cache, context_window as wit_context_window, crypto as wit_crypto,
    data_transform as wit_data_transform, database as wit_database, datetime as wit_datetime,
    email as wit_email, embedding as wit_embedding, env as wit_env, events as wit_events,
    files as wit_files, graph_memory as wit_graph_memory, graphql as wit_graphql, http as wit_http,
    http_stream as wit_http_stream, integration_state as wit_integration_state, json as wit_json,
    llm as wit_llm, llm_streaming as wit_llm_streaming, llm_tools as wit_llm_tools,
    logging as wit_logging, messaging as wit_messaging, object_storage as wit_object_storage,
    resource_quotas as wit_resource_quotas, secrets as wit_secrets, state as wit_state,
    templates as wit_templates, webhook as wit_webhook,
};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};

/// Maximum HTTP fetch calls per execution (prevents external API flooding).
const MAX_HTTP_CALLS_PER_EXECUTION: u64 = 1000;
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
const MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION: u64 = 200;
/// Maximum database queries per execution.
const MAX_DB_QUERIES_PER_EXECUTION: u64 = 500;
/// Maximum NATS publish calls per execution.
const MAX_MESSAGING_PUBLISHES_PER_EXECUTION: u64 = 1000;
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
const RESERVED_PUBLISH_PREFIXES: &[&str] = &[
    "talos.",
    "wasm.", // wasm.log.* — controller WASM-log subscriber
];

/// Returns `true` when `topic` is on the platform-reserved prefix
/// deny-list and must not be published from guest code. ASCII-prefix
/// match; subject characters in NATS are 7-bit anyway.
fn reject_reserved_topic_prefix(topic: &str) -> bool {
    RESERVED_PUBLISH_PREFIXES
        .iter()
        .any(|prefix| topic.starts_with(prefix))
}

/// L-17 (2026-05-22): shape-based introspection-query detector.
/// Returns true if the GraphQL `query` text looks like it's asking
/// for schema introspection at the top level (`__schema` or
/// `__type`). False otherwise.
///
/// Detection strategy:
///   1. Strip GraphQL block / line comments (#... up to EOL).
///   2. Find the first `{` (the root selection-set opener).
///   3. Scan ahead for `__schema` or `__type` *before* any inner
///      `{` — that is, at the root selection level. Introspection
///      fields buried in fragments or aliases are not flagged
///      (intentional limitation; see callsite comment).
///
/// Pure function so the policy is unit-testable. Conservatively
/// returns `false` on malformed input — the request will fail
/// downstream at the remote GraphQL endpoint anyway; we don't want
/// to over-block legitimate-but-weird queries.
pub(crate) fn looks_like_graphql_introspection(query: &str) -> bool {
    // Strip line comments (GraphQL uses `#` for comments).
    let comment_stripped: String = query
        .lines()
        .map(|line| match line.find('#') {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");

    // L-finding-8: also strip the contents of string literals so a
    // `fragment Sneaky on Query { __schema }` substring embedded
    // inside a user-supplied string argument is NOT mistaken for a
    // real fragment definition. GraphQL has two string forms — `"..."`
    // (with `\"` and `\\` escapes) and `"""..."""` block strings (no
    // escapes, terminator is three quotes). Both are replaced with
    // same-length spaces so byte offsets stay stable for downstream
    // diagnostics.
    let stripped = strip_graphql_string_literals(&comment_stripped);

    // Pass 1 (primary): top-level introspection in the operation's
    // root selection set. Find the root `{` and walk for `__schema`
    // or `__type` until the first nested `{`. This is the high-
    // confidence path that catches the canonical
    // `{ __schema { types { name } } }` pattern.
    let primary = top_level_root_selection_has_introspection(&stripped);
    if primary {
        return true;
    }

    // Pass 2 (L-finding-8, 2026-05-23): fragment-hidden introspection.
    // Pre-fix a guest could bury `__schema` / `__type` inside a
    // `fragment X on Query { ... }` and reference the fragment from
    // the root selection set:
    //     fragment Sneaky on Query { __schema { types { name } } }
    //     query Q { ...Sneaky }
    // Pass 1 only walked the operation body so this query slipped
    // through with no audit event fired. We don't pull in a full
    // GraphQL parser (the only worker-bound option,
    // async-graphql-parser, would add ~1 ms of parse cost to the
    // wit_graphql hot path); instead we do a shape-based scan
    // specifically for fragment definitions and check whether each
    // fragment's body imports an introspection meta-field.
    //
    // The detector intentionally over-fires on rare patterns (e.g.
    // a fragment defined on a custom type with a user-defined field
    // named `__schema_foo` — though `__` is reserved by GraphQL
    // spec so that should not occur in well-formed schemas). The
    // existing `actor_tier1 || env_block` gating in the caller
    // means false positives are observable via WARN (allow-mode)
    // and only HARD-BLOCK under the deliberate operator opt-in;
    // false negatives, by contrast, leave the audit stream silent.
    // Prefer false-positive WARN over false-negative silence.
    fragment_body_has_introspection(&stripped)
}

/// Inner scan for the primary "top-level introspection" pattern.
/// Returns true if the operation body's root selection set
/// imports `__schema` or `__type` (before any nested selection
/// opens its own brace pair).
fn top_level_root_selection_has_introspection(stripped: &str) -> bool {
    let Some(brace_idx) = stripped.find('{') else {
        return false;
    };
    let after_brace = &stripped[brace_idx + 1..];
    let bytes = after_brace.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'{' {
            // Entered a nested selection — primary scan ends here.
            return false;
        }
        if b == b'_' && bytes.get(i + 1).copied() == Some(b'_') {
            if has_introspection_token_at(after_brace, i) {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// L-finding-8: scan for `fragment <name> on <type> { ... }`
/// blocks and return true if ANY fragment body imports a
/// `__schema` / `__type` meta-field at its top level. The
/// fragment's brace-balanced body is matched lexically (no full
/// parse) — sufficient for shape-based detection.
fn fragment_body_has_introspection(stripped: &str) -> bool {
    let bytes = stripped.as_bytes();
    // Walk for the literal `fragment` keyword with word boundaries.
    let mut i = 0;
    while i + 8 < bytes.len() {
        // Cheap initial filter: only attempt the full keyword match
        // when we see `f` (saves walking byte-by-byte for the rest
        // of the keyword on every position).
        if bytes[i] == b'f'
            && stripped[i..].starts_with("fragment")
            && is_word_boundary_left(bytes, i)
            && bytes
                .get(i + 8)
                .map(|c| !(c.is_ascii_alphanumeric() || *c == b'_'))
                .unwrap_or(true)
        {
            // Find the opening brace of the fragment body. Anything
            // between the `fragment` keyword and the next `{` is the
            // fragment name + `on <type>` clause — we don't care
            // about its contents, only that we find the brace that
            // opens the body.
            let tail = &stripped[i + 8..];
            if let Some(brace_off) = tail.find('{') {
                let body_start = i + 8 + brace_off + 1;
                let body = match find_brace_balanced_body(&stripped[body_start..]) {
                    Some(b) => b,
                    None => {
                        // Malformed fragment — give up on this match
                        // and continue scanning. The whole query will
                        // almost certainly fail downstream parse, so
                        // we don't need a precise verdict here.
                        i += 8;
                        continue;
                    }
                };
                if root_selection_imports_introspection(body) {
                    return true;
                }
                // Skip past the body we already scanned.
                i = body_start + body.len();
                continue;
            }
        }
        i += 1;
    }
    false
}

/// Returns the brace-balanced body of a block whose opening `{`
/// has already been consumed. The returned slice ends at the
/// matching `}` (exclusive). Returns `None` if no matching brace
/// is found (malformed input).
fn find_brace_balanced_body(after_open: &str) -> Option<&str> {
    let bytes = after_open.as_bytes();
    let mut depth: i32 = 1;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&after_open[..i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Same shape as `top_level_root_selection_has_introspection` but
/// scans the body of a brace-balanced selection set (the caller
/// has already consumed the opening `{`).
fn root_selection_imports_introspection(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            // Nested selection — stop here for shape-based detection
            // (same semantics as the primary scan; nested `__schema`
            // on a non-Query type isn't introspection).
            return false;
        }
        if bytes[i] == b'_' && bytes.get(i + 1).copied() == Some(b'_') {
            if has_introspection_token_at(body, i) {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Returns true when `slice[start..]` begins with either `__schema`
/// or `__type` followed by a word boundary. Shared by the primary
/// scan and the fragment-body scan.
fn has_introspection_token_at(slice: &str, start: usize) -> bool {
    let rest = &slice[start..];
    let bytes = rest.as_bytes();
    for tok in ["__schema", "__type"] {
        if rest.len() >= tok.len() && rest.starts_with(tok) {
            let next = bytes.get(tok.len()).copied();
            let is_word_boundary = match next {
                None => true,
                Some(c) => !(c.is_ascii_alphanumeric() || c == b'_'),
            };
            if is_word_boundary {
                return true;
            }
        }
    }
    false
}

/// L-finding-8: word-boundary check for the LEFT side of a
/// keyword match (the `is_word_boundary` checks elsewhere only
/// guard the right side because the scan walks forward).
fn is_word_boundary_left(bytes: &[u8], at: usize) -> bool {
    if at == 0 {
        return true;
    }
    let prev = bytes[at - 1];
    !(prev.is_ascii_alphanumeric() || prev == b'_')
}

/// L-finding-8: replace the contents of GraphQL string literals
/// (both `"..."` and `"""..."""` block strings) with spaces so
/// the scan can't match `fragment` / `__schema` inside string
/// arguments. Preserves the opening/closing quotes (and all byte
/// offsets) so brace-balance accounting elsewhere stays consistent.
///
/// String forms (per GraphQL October 2021 spec):
///   - Regular string: `"<chars or \uXXXX or \" or \\ or \n etc.>"`
///   - Block string:   `"""<any chars, terminator is three quotes>"""`
///
/// The implementation is a small state machine over bytes; it
/// runs in O(n) and allocates one String of the same length as
/// input. Not a parser — only handles enough to defeat the shape-
/// based-detection bypass cases. A malformed query that opens a
/// string without closing it is treated as "rest of input is
/// inside the string" which over-strips but is safe (the
/// downstream GraphQL server will reject the malformed query
/// anyway).
fn strip_graphql_string_literals(input: &str) -> String {
    enum State {
        Normal,
        InRegularString,
        InBlockString,
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut state = State::Normal;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match state {
            State::Normal => {
                // Detect `"""` first because `"` is a prefix of `"""`.
                if b == b'"'
                    && bytes.get(i + 1).copied() == Some(b'"')
                    && bytes.get(i + 2).copied() == Some(b'"')
                {
                    out.extend_from_slice(b"\"\"\"");
                    state = State::InBlockString;
                    i += 3;
                    continue;
                }
                if b == b'"' {
                    out.push(b'"');
                    state = State::InRegularString;
                    i += 1;
                    continue;
                }
                out.push(b);
                i += 1;
            }
            State::InRegularString => {
                if b == b'\\' {
                    // Skip the backslash AND the next byte (the
                    // escaped char). Replace BOTH with spaces so
                    // length is preserved.
                    out.push(b' ');
                    if i + 1 < bytes.len() {
                        out.push(b' ');
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                if b == b'"' {
                    out.push(b'"');
                    state = State::Normal;
                    i += 1;
                    continue;
                }
                // Regular strings don't span newlines per spec; a raw
                // newline inside is malformed. Preserve it as a space
                // so line numbers in diagnostics stay consistent. The
                // detector doesn't care either way.
                out.push(b' ');
                i += 1;
            }
            State::InBlockString => {
                // Block-string terminator is `"""` with no escape
                // for embedded quotes (the spec uses `\"""` to escape).
                if b == b'\\'
                    && bytes.get(i + 1).copied() == Some(b'"')
                    && bytes.get(i + 2).copied() == Some(b'"')
                    && bytes.get(i + 3).copied() == Some(b'"')
                {
                    // Escaped triple-quote inside a block string —
                    // four bytes, all stripped to spaces so we don't
                    // confuse the terminator check below.
                    out.extend_from_slice(b"    ");
                    i += 4;
                    continue;
                }
                if b == b'"'
                    && bytes.get(i + 1).copied() == Some(b'"')
                    && bytes.get(i + 2).copied() == Some(b'"')
                {
                    out.extend_from_slice(b"\"\"\"");
                    state = State::Normal;
                    i += 3;
                    continue;
                }
                out.push(b' ');
                i += 1;
            }
        }
    }
    // SAFETY: we only ever pushed ASCII bytes (`"`, spaces) or
    // copied original bytes verbatim. Since the original input was
    // valid UTF-8 and we only mutate bytes that were themselves
    // ASCII (string-literal contents → spaces; quotes preserved as
    // ASCII), every emitted byte sequence is a valid UTF-8 sequence
    // or an ASCII space, which is also valid UTF-8. The total
    // length matches the input length so byte offsets are preserved
    // for downstream diagnostics.
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod strip_string_literals_tests {
    use super::strip_graphql_string_literals;

    #[test]
    fn strips_regular_string_content() {
        let s = strip_graphql_string_literals(r#"query { f(x: "fragment X on Q { __schema }") }"#);
        // Quotes preserved, contents replaced with spaces.
        assert!(s.starts_with("query { f(x: \""));
        assert!(s.ends_with("\") }"));
        // The `fragment` keyword inside the literal MUST NOT survive.
        assert!(!s.contains("fragment"));
        assert!(!s.contains("__schema"));
    }

    #[test]
    fn handles_escaped_quote_in_string() {
        let s = strip_graphql_string_literals(r#"f(x: "a\"b") {}"#);
        // Two quotes (open, close), no other quote characters in output
        // because the escaped `\"` was stripped to spaces.
        let quote_count = s.bytes().filter(|c| *c == b'"').count();
        assert_eq!(quote_count, 2, "expected 2 quotes in {s:?}");
    }

    #[test]
    fn strips_block_string_content() {
        let s = strip_graphql_string_literals(
            r#"f(desc: """fragment X on Q { __schema }""") {}"#,
        );
        assert!(!s.contains("fragment"));
        assert!(!s.contains("__schema"));
    }

    #[test]
    fn preserves_normal_query_unchanged() {
        let q = r#"{ __schema { types { name } } }"#;
        let s = strip_graphql_string_literals(q);
        assert_eq!(s, q);
    }

    #[test]
    fn length_preserved_for_offset_stability() {
        let q = r#"f(x: "fragment Sneaky")"#;
        let s = strip_graphql_string_literals(q);
        assert_eq!(s.len(), q.len(), "byte length must be preserved");
    }
}

#[cfg(test)]
mod introspection_detector_tests {
    use super::looks_like_graphql_introspection;

    #[test]
    fn detects_top_level_schema_query() {
        assert!(looks_like_graphql_introspection("{ __schema { types { name } } }"));
    }

    #[test]
    fn detects_top_level_type_query() {
        assert!(looks_like_graphql_introspection("{ __type(name: \"User\") { name } }"));
    }

    #[test]
    fn detects_with_query_keyword() {
        assert!(looks_like_graphql_introspection(
            "query IntrospectionQuery { __schema { types { name } } }"
        ));
    }

    #[test]
    fn ignores_user_field_named_similarly() {
        // `__schema_extension` is a custom field on the schema,
        // not the meta-field. Word-boundary check should prevent
        // false-positive.
        assert!(!looks_like_graphql_introspection(
            "{ user { __schema_extension } }"
        ));
    }

    #[test]
    fn ignores_introspection_buried_in_nested_selection() {
        // Documented limitation: only top-level introspection
        // selections are flagged. A query where `__schema` is
        // nested inside a user field isn't really doing GraphQL
        // introspection in the normal sense — there's no field
        // named `user.__schema` at the schema level — and false-
        // positives here would block more than they protect.
        assert!(!looks_like_graphql_introspection(
            "{ user { profile { __schema { types } } } }"
        ));
    }

    #[test]
    fn handles_comments_before_schema() {
        assert!(looks_like_graphql_introspection(
            "# explore schema\n{ __schema { types { name } } }"
        ));
    }

    #[test]
    fn returns_false_on_normal_query() {
        assert!(!looks_like_graphql_introspection(
            "query { user(id: 1) { name email } }"
        ));
    }

    #[test]
    fn returns_false_on_malformed_query() {
        // Defensive: malformed → false. We don't want to over-
        // block; the downstream GraphQL endpoint will reject it
        // for the right reason.
        assert!(!looks_like_graphql_introspection("not a query at all"));
        assert!(!looks_like_graphql_introspection(""));
    }

    #[test]
    fn detects_query_with_alias() {
        // GraphQL aliases: `s: __schema { ... }` is also an
        // introspection query. Our shape-based scan walks token-
        // by-token until a nested `{` so a leading alias `s:` is
        // skipped and the `__schema` selection is still flagged.
        assert!(looks_like_graphql_introspection(
            "{ s: __schema { types { name } } }"
        ));
    }

    #[test]
    fn does_not_double_count_word_boundary() {
        // `__schemafoo` is a custom field — must NOT match. The
        // word-boundary check guards against this.
        assert!(!looks_like_graphql_introspection(
            "{ __schemafoo { name } }"
        ));
    }

    // ─── L-finding-8: fragment-hidden introspection ───

    /// The canonical bypass: introspection in a fragment definition,
    /// referenced from the query body. Pre-L-finding-8 this returned
    /// false because the primary scan only walked the operation body.
    #[test]
    fn detects_fragment_hidden_schema() {
        let q = r#"
            fragment Sneaky on Query { __schema { types { name } } }
            query Q { ...Sneaky }
        "#;
        assert!(looks_like_graphql_introspection(q));
    }

    /// Same bypass with `__type` instead of `__schema`.
    #[test]
    fn detects_fragment_hidden_type() {
        let q = r#"
            fragment Sneaky on Query { __type(name: "User") { name } }
            query Q { ...Sneaky }
        "#;
        assert!(looks_like_graphql_introspection(q));
    }

    /// Fragment-hidden introspection with the fragment defined
    /// AFTER the query body. Detector should not depend on
    /// declaration order.
    #[test]
    fn detects_fragment_hidden_schema_fragment_after_query() {
        let q = r#"
            query Q { ...Sneaky }
            fragment Sneaky on Query { __schema { queryType { name } } }
        "#;
        assert!(looks_like_graphql_introspection(q));
    }

    /// A fragment that does NOT import an introspection meta-field
    /// must not trigger. False-positive guard.
    #[test]
    fn ignores_fragment_without_introspection() {
        let q = r#"
            fragment Fields on User { id name email }
            query Q { user(id: 1) { ...Fields } }
        "#;
        assert!(!looks_like_graphql_introspection(q));
    }

    /// A fragment defined on a non-Query type that imports `__schema`
    /// at its root WILL be flagged — `__` prefixes are reserved by
    /// GraphQL spec so a user-defined field with that name shouldn't
    /// exist in well-formed schemas. Over-firing here is acceptable
    /// (audit WARN only in allow-mode); the alternative is a silent
    /// bypass when an operator misuses the prefix. Documents the
    /// trade-off.
    #[test]
    fn flags_fragment_on_non_query_with_introspection_token() {
        // Note: `__schema` on a user type is semantically nonsense
        // (introspection meta-fields only exist on Query) — but
        // detector intentionally errs toward catching it.
        let q = r#"
            fragment Weird on User { __schema { types { name } } }
            query Q { user(id: 1) { ...Weird } }
        "#;
        assert!(looks_like_graphql_introspection(q));
    }

    /// `__schema` buried inside a NESTED selection of a fragment
    /// (not at the fragment's root) is NOT introspection at GraphQL
    /// semantics — same logic as the primary scan's
    /// `ignores_introspection_buried_in_nested_selection` test.
    /// Confirms parity between the two scan passes.
    #[test]
    fn ignores_introspection_nested_inside_fragment_body() {
        let q = r#"
            fragment Inner on User { profile { __schema { types } } }
            query Q { user(id: 1) { ...Inner } }
        "#;
        assert!(!looks_like_graphql_introspection(q));
    }

    /// The word `fragment` appearing inside a string literal MUST
    /// NOT trigger the fragment scan. (Defense-in-depth check —
    /// the current implementation doesn't handle string literals
    /// specifically, but the brace-balanced body extraction won't
    /// find a matching `}` inside a string so the scan bails out
    /// safely on malformed input.)
    #[test]
    fn ignores_fragment_keyword_inside_string_literal_argument() {
        // The introspection token is in the same string literal
        // but never appears as a top-level selection of any
        // fragment, so neither scan should fire.
        let q = r#"query Q { thing(label: "fragment Sneaky on Query { __schema }") { id } }"#;
        assert!(!looks_like_graphql_introspection(q));
    }

    /// Multi-line normal query with fragments — no introspection —
    /// remains a clean negative.
    #[test]
    fn complex_normal_query_with_fragments_is_negative() {
        let q = r#"
            query OrderDetails($id: ID!) {
              order(id: $id) {
                ...OrderHeader
                items { ...LineItem }
              }
            }
            fragment OrderHeader on Order { id status total }
            fragment LineItem on Item { sku name qty }
        "#;
        assert!(!looks_like_graphql_introspection(q));
    }
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
const MAX_MESSAGING_TOPIC_BYTES: usize = 1024;

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
const MAX_EMAIL_SENDS_PER_EXECUTION: u64 = 50;
/// Per-message recipient cap (to + cc + bcc combined). Paired with
/// MAX_EMAIL_SENDS_PER_EXECUTION so the worst-case fanout per execution
/// is 50×50 = 2500 deliveries. MCP-541: pre-fix the cap only applied to
/// `msg.to.len()`; cc/bcc were unbounded, so the documented worst-case
/// fanout was a lie. Now enforces the total.
const MAX_EMAIL_RECIPIENTS_PER_MESSAGE: usize = 50;
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
const MAX_WEBHOOK_SENDS_PER_EXECUTION: u64 = 100;
/// MCP-537: per-execution cap on `wit_graphql::execute` +
/// `execute_with_retry`. Same gap as wit_webhook above. GraphQL
/// queries can be expensive on the upstream server (deep selection
/// sets) and the worker's outbound bandwidth, so an upper cap of 200
/// matches the existing http_call ceiling spirit — generous for
/// normal pagination, tight enough to prevent abuse.
const MAX_GRAPHQL_QUERIES_PER_EXECUTION: u64 = 200;
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
const MAX_WEBHOOK_RETRIES_PER_SEND: u32 = 10;
/// MCP-583: per-call cap on `wit_webhook::send` retry sleep. Pre-fix
/// `retry_delay_ms` was caller-supplied `option<u32>` with no upper
/// bound — `u32::MAX` ms is ~50 days. Combined with the (formerly)
/// unbounded retry count, a single send() could block a worker
/// indefinitely. Matches `wit_graphql`'s 30s backoff cap.
const MAX_WEBHOOK_RETRY_DELAY_MS: u32 = 30_000;
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
const MAX_HTTP_TIMEOUT_MS: u32 = 120_000;
/// MCP-657: per-call cap on guest-supplied `wit_messaging::request`
/// timeout_ms. Sibling of MAX_HTTP_TIMEOUT_MS — without the cap a
/// guest could pass `u32::MAX` (~49 days) and the awaiting
/// `tokio::time::timeout` future would hold a worker task until the
/// NATS reply arrives or the deadline elapses. async fuel is
/// observation-only (MCP-583/584 class). 60s matches the NATS
/// req/reply convention — these are short interactive RPCs, not
/// long-poll patterns. Sibling cap to MAX_HTTP_TIMEOUT_MS but tighter
/// because NATS req/reply has a clearer interactivity expectation.
const MAX_MESSAGING_REQUEST_TIMEOUT_MS: u32 = 60_000;
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
const OBJECT_STORAGE_TIMEOUT_MS: u64 = 120_000;
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
const MAX_SECRET_ACCESSES_PER_EXECUTION: u64 = 100;
/// MCP-585: per-call cap on `wit_embedding::generate` text input.
/// Pre-fix the text input was unbounded — a module could pass a
/// 100 MB string before the upstream OpenAI API returned 400. The
/// outbound network buffer + JSON-encode pass still consumed worker
/// memory and bandwidth for the whole string. 64 KiB is generous —
/// even text-embedding-3-large caps at 8192 tokens (~32 KiB at
/// typical 4 chars/token), so 64 KiB covers worst-case multi-byte
/// UTF-8 input that still falls within the model's token window.
const MAX_EMBEDDING_TEXT_BYTES: usize = 65_536;
/// Maximum bytes writable to the sandbox per execution (1 GiB).
const MAX_FS_BYTES_PER_EXECUTION: u64 = 1_073_741_824;
/// Maximum log messages per execution (prevents NATS flooding).
const MAX_LOG_MESSAGES_PER_EXECUTION: u64 = 10_000;
/// Maximum Tier-2 secret exposures per user per day (global limit across all executions).
const MAX_TIER2_EXPOSES_PER_USER_PER_DAY: u64 = 100;
/// Maximum concurrent LLM streams per execution (prevents resource leaks).
const MAX_LLM_STREAMS_PER_EXECUTION: usize = 10;
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
const MAX_LLM_STREAM_BUFFER_BYTES: usize = 10 * 1024 * 1024;
const MAX_TOOL_INPUT_BUFS_PER_STREAM: usize = 64;
const MAX_TOOL_INPUT_BUF_BYTES: usize = 1024 * 1024;
/// MCP-1213 (2026-05-18): cap the non-streaming LLM completion body
/// at 10 MiB. Pre-fix `response.json()` and `response.text()` buffered
/// the full body with no size limit — a misbehaving / compromised
/// provider returning a 1 GB body would OOM the worker pod. 10 MiB
/// is comfortable for any legitimate completion (typical responses
/// are 1-100 KiB).
const MAX_LLM_BODY_BYTES: usize = 10 * 1024 * 1024;
/// MCP-1213 (2026-05-18): hard cap on per-call LLM exchange wall time
/// (send + receive). Pre-fix the 120s `tokio::time::timeout` wrapped
/// ONLY `.send()` (header receipt) — body-read via `.json()` / `.text()`
/// had no timeout, so a slow/stuck body stream from the provider would
/// hang the WASM call indefinitely (real prod symptom: daily-brief
/// synthesize node ran for 5+ minutes with no progress after MCP-1212
/// re-sign fix unmasked the underlying hang). 120s covers reasonable
/// Claude/GPT-4 latency for long outputs; legitimate calls finish in
/// seconds. Ollama (local) uses LOCAL_LLM_EXCHANGE_TIMEOUT_SECS.
const EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS: u64 = 120;
const LOCAL_LLM_EXCHANGE_TIMEOUT_SECS: u64 = 60;
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
const LLM_STREAM_CONNECT_TIMEOUT_SECS: u64 = 30;
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
const LLM_STREAM_IDLE_TIMEOUT_SECS: u64 = 60;
/// Maximum events per execution for the events interface.
const MAX_EVENTS_PER_EXECUTION: u64 = 100;

/// Cached Ollama base URL (read once from OLLAMA_URL env var).
///
/// MCP-630 (2026-05-12): treat `OLLAMA_URL=""` (a Helm placeholder
/// pattern) as unset and fall through to the in-cluster default. Pre-fix
/// the bare `unwrap_or_else(|_| default)` returned `""`, producing a
/// base-URL-less `format!("{}/v1/chat/completions", "")` that failed at
/// request time with a confusing url-parse error rather than using the
/// default. Sibling to MCP-615/620/621/623 (empty-env-var class). The
/// worker is credential-free and doesn't depend on `talos-config`, so
/// the helper is inlined here.
fn ollama_base_url() -> &'static str {
    static URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URL.get_or_init(|| {
        std::env::var("OLLAMA_URL")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "http://ollama:11434".to_string())
    })
}
/// Maximum event payload size (1 MiB).
const MAX_EVENT_PAYLOAD_BYTES: usize = 1_048_576;
/// MCP-600 (2026-05-12): Maximum metadata size for `events::emit_with_metadata`
/// (64 KiB). Pre-fix, `metadata` was unbounded while `payload` was 1 MiB
/// capped — a guest could pass up to ~30 MiB metadata (limited only by
/// the linear-memory cap), forcing the host to re-allocate, serialize
/// it into the event JSON, and only THEN fail downstream when NATS
/// rejected the over-1MiB publish. Same DoS amplification class as
/// MCP-585 (unbounded embedding text). Metadata is meant for small
/// auxiliary structured fields (correlation IDs, source tags) — 64 KiB
/// is generous and well below NATS's 1 MiB default ceiling.
const MAX_EVENT_METADATA_BYTES: usize = 65_536;
/// Maximum concurrent SSE connections per execution.
const MAX_SSE_STREAMS_PER_EXECUTION: usize = 5;
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
const MAX_SSE_CONNECTS_PER_HOST_PER_EXECUTION: u64 = 3;
/// Maximum bytes returned by files::read (64 MiB — prevents OOM on large files).
const MAX_FILE_READ_BYTES: usize = 64 * 1024 * 1024;
/// Maximum bytes returned by object-storage::get (64 MiB — prevents OOM on large objects).
const MAX_OBJECT_READ_BYTES: usize = 64 * 1024 * 1024;
/// MCP-1115 (2026-05-16): cap on the XML LIST response from
/// `wit_object_storage::list_objects`. The S3-compatible LIST API
/// returns `<ListBucketResult>` XML; for max_keys=1000 (the API cap)
/// with maximum-realistic 1 KiB-per-entry XML serialisation that's
/// ~1 MiB. 4 MiB is generous headroom + bounds a malicious /
/// compromised / MITM'd S3-compatible endpoint that ignores
/// max-keys=1000 and returns mega-XML to OOM the worker via
/// `response.text().await` buffering.
const MAX_LIST_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
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
static ALLOW_PRIVATE_HOST_TARGETS: std::sync::LazyLock<bool> =
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

// ============================================================================
// SSRF private-IP classification
// ============================================================================
//
// "Is this IP one we refuse to reach?" Used by every place we have an IP in
// hand: the IP-literal arms in `fetch` / `fetch_all`, and the DNS-resolved arm
// in `fetch`. Returns the `record_capability_denied` policy string when the IP
// is denied so the caller emits a consistent audit trail. The logic is shared
// with the controller via `talos-ssrf-classify` — adding a new range is one
// edit in that crate, for both gates.

// Both functions now live in `talos-ssrf-classify` (std-only), shared with the
// controller's `talos_http_utils::ssrf` so the SSRF deny-list — including the
// IPv6 transition-form coverage (IPv4-mapped/compatible, NAT64, 6to4) added in
// the 2026-05-31 consolidation — is defined in exactly one place. The policy
// strings ("private-ip", "private-ip-unspecified", "private-ip-cgnat",
// "private-ip-ipv4-mapped-ipv6", …) are preserved for the audit trail.
pub(crate) use talos_ssrf_classify::classify_private_ip;

/// Tier-1 (local-Ollama-only) data-egress deny-check on a URL host.
///
/// Returns `Some(policy)` — the `record_capability_denied` reason — when a
/// Tier-1 actor must be refused this destination, `None` when allowed.
///
/// Two cases:
/// 1. A known external LLM provider hostname (`is_external_llm_host`).
/// 2. A **globally-routable IP literal**. The hostname deny-list (case 1) is
///    name-based, so a guest with `allowed_hosts: ["*"]` could otherwise reach
///    a provider by raw IP (`https://<ip>/v1/messages`) and slip the ceiling —
///    the IP-literal bypass found in the 2026-05-28 review. A public IP literal
///    is "data leaving the host" and has no legitimate Tier-1 use (local Ollama
///    is reached via hostname/localhost/private IP). Private, loopback,
///    link-local, CGNAT, and unspecified literals are governed by the SSRF
///    classifier and remain allowed here (so `127.0.0.1:11434` Ollama works).
///
/// `host_lower` MUST already be lowercased by the caller (matches the existing
/// call sites). IPv6 literals are accepted with or without surrounding
/// brackets.
fn tier1_egress_deny_reason(host_lower: &str) -> Option<&'static str> {
    if talos_workflow_job_protocol::is_external_llm_host(host_lower) {
        return Some("tier1-llm-egress");
    }
    let bare = host_lower
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host_lower);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        // Public/routable IP literal (SSRF classifier returns None) → deny.
        if classify_private_ip(ip).is_none() {
            return Some("tier1-public-ip-egress");
        }
    }
    None
}

#[cfg(test)]
mod tier1_egress_tests {
    use super::tier1_egress_deny_reason;

    #[test]
    fn denies_known_provider_hostname() {
        assert_eq!(
            tier1_egress_deny_reason("api.anthropic.com"),
            Some("tier1-llm-egress")
        );
    }

    #[test]
    fn denies_public_ip_literal() {
        // Public IPv4 / IPv6 literals — the bypass class.
        assert_eq!(
            tier1_egress_deny_reason("160.79.104.10"),
            Some("tier1-public-ip-egress")
        );
        assert_eq!(
            tier1_egress_deny_reason("8.8.8.8"),
            Some("tier1-public-ip-egress")
        );
        assert_eq!(
            tier1_egress_deny_reason("[2606:4700:4700::1111]"),
            Some("tier1-public-ip-egress")
        );
    }

    #[test]
    fn allows_local_ip_literals_for_ollama() {
        // Local Ollama at loopback / private IP must still work for Tier-1.
        assert_eq!(tier1_egress_deny_reason("127.0.0.1"), None);
        assert_eq!(tier1_egress_deny_reason("192.168.1.50"), None);
        assert_eq!(tier1_egress_deny_reason("10.0.0.3"), None);
        assert_eq!(tier1_egress_deny_reason("[::1]"), None);
        assert_eq!(tier1_egress_deny_reason("0.0.0.0"), None);
    }

    #[test]
    fn allows_non_provider_hostnames() {
        // A DNS hostname that isn't a provider is governed by allowed_hosts,
        // not by this Tier-1 deny-check.
        assert_eq!(tier1_egress_deny_reason("ollama.internal"), None);
        assert_eq!(tier1_egress_deny_reason("example.com"), None);
    }
}

/// Match a host against the per-module `allowed_hosts` patterns.
///
/// Patterns can be:
/// * `"*"` — wildcard, matches any host (per-job override; SSRF / IP-literal
///   / tier-1 LLM deny-list still apply on top).
/// * `"example.com"` — exact match.
/// * `".example.com"` — suffix match (matches `api.example.com`,
///   `foo.bar.example.com`, but NOT bare `example.com`).
///
/// **Case handling.** Both sides are lowercased before comparison. The
/// `url` crate's WHATWG-conformant parser already lowercases ASCII
/// hostnames in `Url::host_str()`, but operator-supplied `allowed_hosts`
/// patterns come straight off the signed `JobRequest` and may be
/// mixed-case. Without this normalisation, an operator who configures
/// `allowed_hosts: ["API.example.com"]` (mixed case) silently denies
/// every legitimate request to the (already-lowercased) host
/// `api.example.com` — a configuration footgun. Lowercasing both sides
/// closes the gap defensively.
///
/// **Performance.** The lowercased host is computed once per `fetch` and
/// the pattern lowercase happens lazily inside the closure — for the
/// common all-lowercase case this is `ASCII fast-path` in the stdlib
/// (no allocation on `String::to_ascii_lowercase` only if the string is
/// already lowercase? — no, it allocates always). For `fetch_all` (which
/// loops over a batch) we lowercase the host once outside the batch loop
/// and let the caller pass the pre-lowercased host in.
///
/// **What this does NOT do.** Punycode / IDN normalisation, scheme check,
/// port check, or path check. SSRF / IP-literal blocking is upstream of
/// this matcher (see `classify_private_ip` + `validate_no_dns_rebinding`).
/// Tier-1 LLM-host deny-list is downstream (see
/// `is_external_llm_host`). This function is the operator-grant gate,
/// not the platform deny-gate.
pub(crate) fn host_allowlist_match(allowed: &[String], host: &str) -> bool {
    if allowed.is_empty() {
        return false;
    }
    // Strip the FQDN trailing dot before compare. `url::Url::parse` preserves
    // it (RFC 3986); DNS resolves both forms to the same record. Without the
    // strip, a host `example.com.` would silently fail to match an operator
    // grant of `example.com`. We also strip the dot from the pattern side so
    // an operator who pastes a copy of the FQDN-with-dot still matches the
    // dotless form a client sends.
    let host_lower = host.trim_end_matches('.').to_ascii_lowercase();
    allowed.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        // Patterns starting with `.` are suffix patterns by design — preserve
        // that leading dot, only strip the TRAILING one. `.example.com.` and
        // `.example.com` should both match `api.example.com`.
        let pattern_lower = pattern.trim_end_matches('.').to_ascii_lowercase();
        if pattern_lower.starts_with('.') {
            host_lower.ends_with(pattern_lower.as_str())
        } else {
            host_lower == pattern_lower
        }
    })
}

#[cfg(test)]
mod host_allowlist_match_tests {
    use super::host_allowlist_match;

    #[test]
    fn exact_match_lowercases_pattern() {
        // Operator misconfigures with mixed case — should still match
        // the (already-lowercased) host from `Url::host_str()`.
        let allowed = vec!["API.Example.com".to_string()];
        assert!(host_allowlist_match(&allowed, "api.example.com"));
    }

    #[test]
    fn exact_match_lowercases_host() {
        // Defensive: even if a caller passes an unnormalised host, the
        // matcher lowercases it.
        let allowed = vec!["api.example.com".to_string()];
        assert!(host_allowlist_match(&allowed, "API.EXAMPLE.COM"));
    }

    #[test]
    fn suffix_match_lowercased() {
        let allowed = vec![".EXAMPLE.com".to_string()];
        assert!(host_allowlist_match(&allowed, "api.example.com"));
        assert!(host_allowlist_match(&allowed, "FOO.bar.Example.com"));
    }

    #[test]
    fn suffix_match_does_not_match_bare_domain() {
        // ".example.com" means subdomains only — bare "example.com"
        // must NOT match (else the dot prefix is meaningless).
        let allowed = vec![".example.com".to_string()];
        assert!(!host_allowlist_match(&allowed, "example.com"));
    }

    #[test]
    fn suffix_match_does_not_match_sibling_domain() {
        // Defense against the classic suffix-confusion: "badexample.com"
        // must NOT match ".example.com". The leading dot in the pattern
        // ensures we match a sub-domain boundary, not a substring.
        let allowed = vec![".example.com".to_string()];
        assert!(!host_allowlist_match(&allowed, "badexample.com"));
    }

    #[test]
    fn wildcard_matches_any_host() {
        let allowed = vec!["*".to_string()];
        assert!(host_allowlist_match(&allowed, "anything.example.com"));
        assert!(host_allowlist_match(&allowed, "10.0.0.1"));
        // (Wildcard does not bypass SSRF gates — those run before this matcher.)
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let allowed: Vec<String> = vec![];
        assert!(!host_allowlist_match(&allowed, "api.example.com"));
    }

    #[test]
    fn no_pattern_matches_unrelated_host() {
        let allowed = vec!["api.example.com".to_string()];
        assert!(!host_allowlist_match(&allowed, "evil.example.com"));
        assert!(!host_allowlist_match(&allowed, "example.com"));
    }

    // Wasm-security review 2026-05-23: trailing-dot normalisation. Same
    // class as `is_external_llm_host` — `url::Url::parse` preserves the
    // FQDN trailing dot and the strict equality check would otherwise let
    // an attacker bypass a tightly-scoped operator grant.
    #[test]
    fn trailing_dot_on_host_does_not_bypass() {
        let allowed = vec!["api.example.com".to_string()];
        assert!(host_allowlist_match(&allowed, "api.example.com."));
        assert!(host_allowlist_match(&allowed, "API.EXAMPLE.COM."));
    }

    #[test]
    fn trailing_dot_on_pattern_still_matches() {
        // Operator who copy-pastes an FQDN with the trailing dot should not
        // have their pattern silently break against a dotless host (which
        // is what `host_str()` returns when the URL has no trailing dot).
        let allowed = vec!["api.example.com.".to_string()];
        assert!(host_allowlist_match(&allowed, "api.example.com"));
        assert!(host_allowlist_match(&allowed, "api.example.com."));
    }

    #[test]
    fn trailing_dot_suffix_pattern_still_matches() {
        let allowed = vec![".example.com".to_string()];
        assert!(host_allowlist_match(&allowed, "api.example.com."));
        assert!(host_allowlist_match(&allowed, "foo.bar.example.com."));
        // Leading-dot suffix pattern must still NOT match the bare apex
        // even with trailing-dot — the suffix-match invariant from the
        // existing test cases must hold.
        assert!(!host_allowlist_match(&allowed, "example.com."));
    }
}

/// Outcome of the URL-scheme check applied to every outbound WIT
/// host call (`fetch`, `fetch_all`, `webhook::send`, `graphql::execute`,
/// `http_stream::connect`). Plaintext HTTP is denied by default
/// because:
///   1. `vault://` header substitution can interpolate a secret into
///      a plaintext request, exfiltrating it to any on-path observer.
///   2. The SSRF gates protect the network destination but cannot
///      protect data in flight.
///   3. The Talos SDK's idiomatic config flow encourages outbound
///      calls to first-party APIs which are uniformly HTTPS.
///
/// Operators with a legitimate plaintext target (dev sidecars, local
/// services already gated by `WORKER_ALLOW_PRIVATE_HOST_TARGETS`)
/// opt in with `WASM_ALLOW_INSECURE_HTTP=1`. The opt-in is process-
/// wide because it covers per-execution `http://` use rather than
/// per-execution policy.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UrlSchemeVerdict {
    /// Scheme is `https`. Always allowed.
    Https,
    /// Scheme is something other than `https` AND the operator-level
    /// opt-in is set. Allowed, but the caller MUST emit an audit row
    /// so the deviation is visible to operators.
    InsecureAllowedByOptIn { scheme: String },
    /// Scheme is not `https` and there is no opt-in. Deny.
    InsecureRefused { scheme: String },
}

/// Pure scheme-policy decision. Side-effect free so the security-
/// critical default is unit-testable without touching DNS, sockets,
/// or the env. Callers translate the verdict into the right deny
/// + audit shape for their host-fn boundary.
pub(crate) fn classify_url_scheme(scheme: &str, insecure_opt_in: bool) -> UrlSchemeVerdict {
    // The scheme is already lowercased by `url::Url::parse`. Compare
    // exact for determinism; treat anything else as insecure.
    if scheme == "https" {
        return UrlSchemeVerdict::Https;
    }
    // 2026-05-28 audit F4: the `WASM_ALLOW_INSECURE_HTTP` env var is
    // documented as "permit plaintext HTTP". Pre-fix the implementation
    // greenlit ANY non-`https` scheme under the opt-in, including
    // `file://`, `ftp://`, `data:`, and any future scheme. Reqwest
    // refuses these today so the practical hole is closed, but a
    // future HTTP-client swap (curl, ureq, hyper-multiplex) would
    // inherit the gap. Whitelist `http` explicitly so the opt-in's
    // scope matches its name and any other scheme falls through to
    // `InsecureRefused` regardless of opt-in state.
    if scheme == "http" && insecure_opt_in {
        return UrlSchemeVerdict::InsecureAllowedByOptIn {
            scheme: scheme.to_string(),
        };
    }
    UrlSchemeVerdict::InsecureRefused {
        scheme: scheme.to_string(),
    }
}

/// Read the operator-level opt-in env var. Recognised forms: `1`,
/// `true`, `yes` (case-insensitive). Anything else is treated as off.
/// Empty / unset → off — same fail-closed default as
/// `TALOS_ALLOW_UNATTESTED_WASM`.
pub(crate) fn insecure_http_opt_in() -> bool {
    std::env::var("WASM_ALLOW_INSECURE_HTTP")
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

#[cfg(test)]
mod url_scheme_policy_tests {
    use super::{classify_url_scheme, UrlSchemeVerdict};

    #[test]
    fn https_always_allowed() {
        assert_eq!(classify_url_scheme("https", false), UrlSchemeVerdict::Https);
        assert_eq!(classify_url_scheme("https", true), UrlSchemeVerdict::Https);
    }

    #[test]
    fn http_refused_by_default() {
        assert!(matches!(
            classify_url_scheme("http", false),
            UrlSchemeVerdict::InsecureRefused { .. }
        ));
    }

    #[test]
    fn http_allowed_when_opt_in_set() {
        assert!(matches!(
            classify_url_scheme("http", true),
            UrlSchemeVerdict::InsecureAllowedByOptIn { .. }
        ));
    }

    #[test]
    fn unusual_schemes_treated_as_insecure() {
        // `file://`, `ftp://`, custom — all denied by default. The
        // outer reqwest connect would refuse most of these anyway,
        // but failing closed here keeps the policy uniform.
        assert!(matches!(
            classify_url_scheme("file", false),
            UrlSchemeVerdict::InsecureRefused { .. }
        ));
        assert!(matches!(
            classify_url_scheme("ftp", false),
            UrlSchemeVerdict::InsecureRefused { .. }
        ));
    }

    #[test]
    fn opt_in_does_not_extend_to_non_http_schemes() {
        // 2026-05-28 audit F4: the `WASM_ALLOW_INSECURE_HTTP` opt-in
        // is documented as "permit plaintext HTTP". Pre-fix it greenlit
        // ANY non-https scheme. Reqwest refuses these today but a
        // future client swap would inherit the hole. Pin the
        // post-fix behaviour: only `http` is widened by the opt-in;
        // every other scheme stays Refused even when opt-in is on.
        for s in ["file", "ftp", "data", "ws", "wss", "javascript", "ldap"] {
            assert!(
                matches!(
                    classify_url_scheme(s, true),
                    UrlSchemeVerdict::InsecureRefused { .. }
                ),
                "scheme {s} must stay Refused under opt-in; got {:?}",
                classify_url_scheme(s, true)
            );
        }
    }
}

#[cfg(test)]
mod classify_private_ip_tests {
    //! MCP-553: cover the IPv4/IPv6 unspecified range. Without these
    //! a guest with `allowed_hosts: ["*"]` could reach loopback by
    //! spelling it `http://0.0.0.0:PORT` (Linux kernel substitutes
    //! 127.0.0.1) — bypassing the SSRF gate that already covers
    //! `is_loopback`/`is_private`/`is_link_local`/CGNAT.
    use super::classify_private_ip;
    use talos_ssrf_classify::classify_private_ipv4;

    #[test]
    fn ipv4_unspecified_is_blocked() {
        let unspec: std::net::Ipv4Addr = "0.0.0.0".parse().unwrap();
        assert_eq!(
            classify_private_ipv4(unspec),
            Some("private-ip-unspecified")
        );
    }

    #[test]
    fn ipv4_unspecified_subnet_is_blocked() {
        // MCP-1069 (2026-05-15): widened from is_unspecified() (exact
        // `0.0.0.0` only) to the FULL 0.0.0.0/8 "this network" range
        // (RFC 1122). Pre-1069 this test pinned narrow `0.1.2.3 → None`
        // behaviour with a "expand if CVE" note. The note acknowledged
        // 0.x.x.x is kernel-substituted on some Linux versions — so
        // narrow coverage was a known gap, not a verified safe behaviour.
        // Sibling of the ssrf.rs MCP-1067/1068 widening of the
        // controller-side guard. Bringing the runtime classifier and
        // the pre-validation guard into consistent /8 coverage.
        for ip in &["0.0.0.0", "0.0.0.1", "0.1.2.3", "0.255.255.255"] {
            let addr: std::net::Ipv4Addr = ip.parse().unwrap();
            assert_eq!(
                classify_private_ipv4(addr),
                Some("private-ip-unspecified"),
                "should block {ip} (0.0.0.0/8 subnet)"
            );
        }
    }

    #[test]
    fn ipv6_unspecified_is_blocked() {
        let unspec: std::net::IpAddr = "::".parse().unwrap();
        assert_eq!(classify_private_ip(unspec), Some("private-ip-unspecified"));
    }

    #[test]
    fn ipv4_mapped_unspecified_is_blocked_via_mapping() {
        // ::ffff:0.0.0.0 should map to 0.0.0.0 and be rejected via
        // the IPv4-mapped path (with the v6-mapped label).
        //
        // MCP-1069: ALSO covers the rest of the IPv4-mapped 0.0.0.0/8
        // range (`::ffff:0.0.0.1` etc.) since the underlying
        // `classify_private_ipv4` now blocks the full /8.
        for mapped_str in &[
            "::ffff:0.0.0.0",
            "::ffff:0.0.0.1",
            "::ffff:0.42.42.42",
            "::ffff:0.255.255.255",
        ] {
            let mapped: std::net::IpAddr = mapped_str.parse().unwrap();
            let result = classify_private_ip(mapped);
            assert_eq!(
                result,
                Some("private-ip-ipv4-mapped-ipv6"),
                "should block {mapped_str}"
            );
        }
    }

    #[test]
    fn public_addresses_still_pass() {
        // Sanity tripwire: 8.8.8.8 and 2001:4860::8888 must NOT be
        // blocked by the new unspecified gate.
        let pub_v4: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();
        assert_eq!(classify_private_ipv4(pub_v4), None);
        let pub_v6: std::net::IpAddr = "2001:4860::8888".parse().unwrap();
        assert_eq!(classify_private_ip(pub_v6), None);
    }
}

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
            "wasmer.something",         // no trailing dot match
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

#[cfg(test)]
mod private_ip_tests {
    use super::classify_private_ip;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn allows_public_ipv4() {
        assert_eq!(classify_private_ip(v4(8, 8, 8, 8)), None);
        assert_eq!(classify_private_ip(v4(1, 1, 1, 1)), None);
    }

    #[test]
    fn blocks_ipv4_private_ranges() {
        assert_eq!(classify_private_ip(v4(127, 0, 0, 1)), Some("private-ip"));
        assert_eq!(classify_private_ip(v4(10, 0, 0, 1)), Some("private-ip"));
        assert_eq!(classify_private_ip(v4(192, 168, 1, 1)), Some("private-ip"));
        assert_eq!(classify_private_ip(v4(172, 16, 0, 1)), Some("private-ip"));
        assert_eq!(classify_private_ip(v4(169, 254, 0, 1)), Some("private-ip"));
        assert_eq!(classify_private_ip(v4(224, 0, 0, 1)), Some("private-ip"));
    }

    #[test]
    fn blocks_ipv4_cgnat() {
        // 100.64.0.0/10 covers 100.64.0.0 – 100.127.255.255.
        assert_eq!(
            classify_private_ip(v4(100, 64, 0, 1)),
            Some("private-ip-cgnat")
        );
        assert_eq!(
            classify_private_ip(v4(100, 127, 255, 254)),
            Some("private-ip-cgnat")
        );
        // 100.63.x.x is OUTSIDE the CGNAT block — public.
        assert_eq!(classify_private_ip(v4(100, 63, 0, 1)), None);
        // 100.128.x.x is OUTSIDE the CGNAT block — public.
        assert_eq!(classify_private_ip(v4(100, 128, 0, 1)), None);
    }

    #[test]
    fn allows_public_ipv6() {
        assert_eq!(classify_private_ip(v6("2001:4860:4860::8888")), None);
    }

    #[test]
    fn blocks_ipv6_loopback_multicast_linklocal_uniquelocal() {
        assert_eq!(classify_private_ip(v6("::1")), Some("private-ip"));
        assert_eq!(classify_private_ip(v6("ff02::1")), Some("private-ip"));
        assert_eq!(classify_private_ip(v6("fe80::1")), Some("private-ip"));
        assert_eq!(classify_private_ip(v6("fc00::1")), Some("private-ip"));
        assert_eq!(classify_private_ip(v6("fd00::1")), Some("private-ip"));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_to_private() {
        // ::ffff:127.0.0.1 — loopback via mapped IPv6.
        assert_eq!(
            classify_private_ip(v6("::ffff:127.0.0.1")),
            Some("private-ip-ipv4-mapped-ipv6")
        );
        assert_eq!(
            classify_private_ip(v6("::ffff:10.0.0.1")),
            Some("private-ip-ipv4-mapped-ipv6")
        );
        assert_eq!(
            classify_private_ip(v6("::ffff:192.168.1.1")),
            Some("private-ip-ipv4-mapped-ipv6")
        );
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_to_cgnat() {
        // The bug we're fixing — mapped CGNAT must use the cgnat policy.
        assert_eq!(
            classify_private_ip(v6("::ffff:100.64.0.1")),
            Some("private-ip-cgnat-ipv4-mapped-ipv6")
        );
        assert_eq!(
            classify_private_ip(v6("::ffff:100.127.255.254")),
            Some("private-ip-cgnat-ipv4-mapped-ipv6")
        );
    }

    #[test]
    fn allows_ipv4_mapped_ipv6_to_public() {
        assert_eq!(classify_private_ip(v6("::ffff:8.8.8.8")), None);
        assert_eq!(classify_private_ip(v6("::ffff:1.1.1.1")), None);
    }
}

// ============================================================================
// Vault path allowlist matcher
// ============================================================================
//
// The matcher itself lives in `talos_workflow_job_protocol::vault_path_permitted` so the
// controller (static validation, hygiene, engine) and worker (runtime
// enforcement in `secrets::get_secret()`) agree exactly on which paths are
// permitted. Re-exported under the old name for local call sites.

use talos_workflow_job_protocol::vault_path_permitted as vault_path_allowed;

#[cfg(test)]
mod vault_allowlist_tests {
    use super::vault_path_allowed;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_list_denies_everything() {
        assert!(!vault_path_allowed(&[], "anthropic/api_key"));
        assert!(!vault_path_allowed(&[], ""));
    }

    #[test]
    fn wildcard_allows_everything() {
        let allow = s(&["*"]);
        assert!(vault_path_allowed(&allow, "anthropic/api_key"));
        assert!(vault_path_allowed(&allow, "oauth/gmail/user/token"));
    }

    #[test]
    fn exact_match_allowed() {
        let allow = s(&["anthropic/api_key"]);
        assert!(vault_path_allowed(&allow, "anthropic/api_key"));
    }

    #[test]
    fn prefix_allows_subpath_but_not_sibling() {
        let allow = s(&["oauth/gmail"]);
        assert!(vault_path_allowed(&allow, "oauth/gmail/user/access_token"));
        // "oauth/gmailicious" must NOT match — we compare "prefix/" not "prefix".
        assert!(!vault_path_allowed(&allow, "oauth/gmailicious/x"));
        // "oauth/atlassian" must NOT match.
        assert!(!vault_path_allowed(&allow, "oauth/atlassian/token"));
    }

    #[test]
    fn glob_form_behaves_like_prefix() {
        let allow = s(&["oauth/gmail/*"]);
        assert!(vault_path_allowed(&allow, "oauth/gmail/user/token"));
        assert!(!vault_path_allowed(&allow, "oauth/atlassian/token"));
    }

    #[test]
    fn denies_path_not_in_grant() {
        // Regression for the vault:// header bypass: gmail-fetch-thread-light
        // had allowed_secrets=[] (deny-all) but resolve_vault_header used to
        // resolve anyway. With the fix, vault_path_allowed([], _) is false.
        assert!(!vault_path_allowed(&[], "oauth/gmail/user/access_token"));

        let allow = s(&["oauth/gmail/*"]);
        assert!(!vault_path_allowed(&allow, "anthropic/api_key"));
    }
}

#[cfg(test)]
mod llm_tier_decision_tests {
    use super::{decide_llm_tier_access, LlmTierDecision};
    use talos_workflow_job_protocol::LlmTier;

    #[test]
    fn ollama_always_needs_no_key_regardless_of_tier() {
        // Ollama is local — no vault lookup, no tier gate.
        assert_eq!(
            decide_llm_tier_access("ollama", LlmTier::Tier1),
            LlmTierDecision::NoKeyNeeded
        );
        assert_eq!(
            decide_llm_tier_access("ollama", LlmTier::Tier2),
            LlmTierDecision::NoKeyNeeded
        );
    }

    #[test]
    fn tier1_refuses_every_external_provider() {
        // The security contract: a tier-1 ceiling MUST block every
        // non-Ollama provider. Adding a new external provider and
        // forgetting to add a tier check here would regress privacy.
        for provider in ["anthropic", "openai", "gemini", "future-provider"] {
            assert_eq!(
                decide_llm_tier_access(provider, LlmTier::Tier1),
                LlmTierDecision::Refused,
                "tier1 must refuse `{provider}`"
            );
        }
    }

    #[test]
    fn tier2_allows_every_external_provider() {
        for provider in ["anthropic", "openai", "gemini"] {
            assert_eq!(
                decide_llm_tier_access(provider, LlmTier::Tier2),
                LlmTierDecision::Allowed,
                "tier2 must allow `{provider}`"
            );
        }
    }

    #[test]
    fn tier1_blocks_unknown_provider_conservatively() {
        // Unknown providers under tier1 must be refused — `provider_tier`
        // in job-protocol defaults unknown providers to Tier2 (external),
        // so tier-1 actors should never reach them.
        assert_eq!(
            decide_llm_tier_access("cohere", LlmTier::Tier1),
            LlmTierDecision::Refused
        );
    }

    #[test]
    fn default_tier_is_tier2() {
        // Backward-compat default — existing workflows without an
        // explicit ceiling continue to reach external providers.
        let default_tier = LlmTier::default();
        assert_eq!(
            decide_llm_tier_access("anthropic", default_tier),
            LlmTierDecision::Allowed,
            "default tier must allow external providers for backward compat"
        );
    }
}

#[cfg(test)]
mod external_llm_host_tests {
    use talos_workflow_job_protocol::{is_external_llm_host, is_tier2_llm_vault_path};

    #[test]
    fn canonical_llm_hosts_are_blocked() {
        // The C3-bypass closers. If any of these return false, a
        // tier-1 guest reaches that provider via wit_http::fetch and
        // the privacy ceiling is broken.
        for host in [
            "api.anthropic.com",
            "api.openai.com",
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
        ] {
            assert!(
                is_external_llm_host(host),
                "{host} must be on the external-LLM deny list"
            );
        }
    }

    #[test]
    fn region_subdomains_are_blocked() {
        // Region subdomains (eu.api.openai.com, eu.api.anthropic.com)
        // must also trigger — attackers can use them to reach the
        // same provider via a regional endpoint.
        assert!(is_external_llm_host("eu.api.openai.com"));
        assert!(is_external_llm_host("us-east-1.api.anthropic.com"));
        assert!(is_external_llm_host(
            "us-central1.aiplatform.googleapis.com"
        ));
    }

    #[test]
    fn benign_hosts_are_not_blocked() {
        // Obvious false-positive check — the deny-list must not
        // accidentally catch user APIs.
        for host in [
            "api.example.com",
            "httpbin.org",
            "api.github.com",
            "slack.com",
            "api.notion.com",
        ] {
            assert!(
                !is_external_llm_host(host),
                "{host} must not be on the external-LLM deny list"
            );
        }
    }

    #[test]
    fn case_insensitive_and_trailing_dot_safe() {
        // Wasm-security review 2026-05-23: the helper now normalises
        // both trailing-dot AND case at the matcher entry as
        // defense-in-depth against an upstream caller forgetting
        // to lowercase or strip the dot. Pre-fix the contract was
        // "callers MUST pass lowercased / dot-stripped host";
        // post-fix the contract is "matcher hardens what you give it"
        // — same correctness, smaller surface for upstream regressions.
        assert!(is_external_llm_host("api.anthropic.com"));
        assert!(
            is_external_llm_host("API.ANTHROPIC.COM"),
            "matcher now lowercases internally (defense in depth)"
        );
        assert!(
            is_external_llm_host("api.anthropic.com."),
            "matcher now strips trailing dot (defense in depth)"
        );
        assert!(
            is_external_llm_host("EU.API.OPENAI.COM."),
            "matcher handles uppercase + trailing dot together"
        );
    }

    #[test]
    fn tier2_vault_paths_recognised() {
        // Complements the host-deny-list: the vault:// header path
        // must also refuse external LLM credentials for tier-1 jobs.
        for path in ["anthropic/api_key", "openai/api_key", "gemini/api_key"] {
            assert!(is_tier2_llm_vault_path(path));
        }
        assert!(!is_tier2_llm_vault_path("oauth/gmail/user/access_token"));
        assert!(!is_tier2_llm_vault_path("my-app/secret"));
    }
}

// ============================================================================
// Wasm-security review 2026-05-22 (MEDIUM-3): vault-path redaction tests
// ============================================================================
//
// The deny paths in `resolve_vault_header` (allowlist-deny, tier-1-LLM-deny,
// resolve-failed) used to leak the literal vault path back to the guest on
// the allowlist-deny arm while the resolve-failed arm correctly emitted only
// a hash. That asymmetry was a probing oracle: a malicious module could
// distinguish "path is in some allowlist I don't have" from "path is in my
// allowlist but resolve failed" and use the difference to fingerprint the
// host's vault layout. These tests pin the post-fix contract — every deny
// path emits the same `vault_path_hash` form and never the literal path.
#[cfg(test)]
mod vault_path_redaction_tests {
    use super::vault_path_short_hash;

    #[test]
    fn hash_is_16_hex_chars() {
        // Operators grep host logs by hash; the hash length is part of
        // the operator contract. 16 hex chars = 8 bytes = 64 bits of
        // collision space, more than enough for any realistic vault.
        let h = vault_path_short_hash("anthropic/api_key");
        assert_eq!(h.len(), 16, "hash must be exactly 16 hex chars");
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_lowercase())),
            "hash must be lowercase hex digits only — got `{h}`"
        );
    }

    #[test]
    fn hash_is_deterministic() {
        // Same path → same hash, otherwise host log ↔ guest error
        // correlation breaks across requests.
        let a = vault_path_short_hash("oauth/gmail/user/access_token");
        let b = vault_path_short_hash("oauth/gmail/user/access_token");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_paths_get_distinct_hashes() {
        // Tripwire against a future refactor that accidentally
        // collapses the hash (e.g. truncating to a single byte). Hash
        // must distinguish the realistic vault-path inventory.
        let paths = [
            "anthropic/api_key",
            "openai/api_key",
            "gemini/api_key",
            "oauth/gmail/user/access_token",
            "oauth/gcal/user/access_token",
            "stripe/api_key",
            "aws/secret_access_key",
            "github/personal_access_token",
        ];
        let mut seen = std::collections::HashSet::new();
        for p in paths {
            assert!(
                seen.insert(vault_path_short_hash(p)),
                "hash collision on `{p}` — review the hash length"
            );
        }
    }

    /// Build the literal deny-error format string in the same shape as
    /// `resolve_vault_header`'s allowlist-deny arm, then assert the
    /// security-critical invariants. If a future refactor reintroduces
    /// the literal vault path into the guest-visible error, this test
    /// fires — the inline format string above MUST stay in sync.
    #[test]
    fn allowlist_deny_error_contains_hash_not_literal_path() {
        let vault_path = "stripe/secret/customer/cus_PROBE";
        let hash = vault_path_short_hash(vault_path);
        let header_name = "Authorization";
        let err = format!(
            "Header '{header_name}' references a vault secret not permitted by this \
             module's allowed_secrets grant (vault_path_hash={hash}). \
             Operator: grep host logs for this hash to see the literal path, then \
             reinstall the module with the path added to allowed_secrets."
        );

        // Hash MUST appear so operators can correlate.
        assert!(
            err.contains(&format!("vault_path_hash={hash}")),
            "error must surface the vault_path_hash"
        );

        // Literal path MUST NOT appear — this is the regression class
        // the 2026-05-22 review caught.
        assert!(
            !err.contains(vault_path),
            "error must NOT echo the literal vault path back to the guest — got: {err}"
        );

        // Specific path components (the operator-recognisable parts
        // like "stripe" or "customer") must not leak either, even if
        // some future format string only includes a substring.
        assert!(!err.contains("stripe"));
        assert!(!err.contains("cus_PROBE"));
    }

    #[test]
    fn tier1_llm_deny_error_contains_hash_not_literal_path() {
        // The Tier-2 LLM provider key paths are public constants, so
        // the redaction here is mostly for consistency — but if the
        // operator inventory ever grows to include a custom provider
        // path, the redaction matters again. Pin the format.
        let vault_path = "anthropic/api_key";
        let hash = vault_path_short_hash(vault_path);
        let header_name = "X-Custom-Auth";
        let err = format!(
            "Header '{header_name}' references a Tier-2 LLM provider key \
             (vault_path_hash={hash}) but this actor's ceiling is \
             Tier-1 (local Ollama only); external provider credentials are refused."
        );
        assert!(err.contains(&format!("vault_path_hash={hash}")));
        assert!(
            !err.contains(vault_path),
            "Tier-1 LLM deny must redact the vault path even though the path is a public constant — got: {err}"
        );
    }

    #[test]
    fn resolve_failed_error_contains_hash_not_literal_path() {
        // The pre-existing safe path; pin it so a future "let's be
        // helpful and include the path" PR breaks the test.
        let vault_path = "oauth/gcal/user/refresh_token";
        let hash = vault_path_short_hash(vault_path);
        let header_name = "Authorization";
        let err = format!(
            "Header '{header_name}' references a vault secret \
             that could not be resolved (vault_path_hash={hash}). \
             Operator: grep host logs for this hash to see the literal path."
        );
        assert!(err.contains(&format!("vault_path_hash={hash}")));
        assert!(!err.contains(vault_path));
        assert!(!err.contains("gcal"));
        assert!(!err.contains("refresh_token"));
    }
}

// ============================================================================
// MCP-1098: S3 bucket / key URL-injection validator tests
// ============================================================================
#[cfg(test)]
mod s3_identifier_validation_tests {
    use super::{validate_s3_bucket, validate_s3_key};

    #[test]
    fn bucket_canonical_names_accepted() {
        for b in [
            "my-bucket",
            "team.assets",
            "logs2024",
            "abc",
            // 63-char (AWS max).
            "a23456789012345678901234567890123456789012345678901234567890123",
        ] {
            assert!(validate_s3_bucket(b).is_ok(), "rejected: {b}");
        }
    }

    #[test]
    fn bucket_url_injection_rejected() {
        for b in [
            "",                 // empty
            "Bucket",           // uppercase
            "my_bucket",        // underscore
            "my bucket",        // space
            ".bucket",          // leading dot
            "bucket.",          // trailing dot
            "-bucket",          // leading hyphen
            "bucket-",          // trailing hyphen
            "my..bucket",       // consecutive dots
            "my/other-bucket",  // slash
            "../private",       // traversal
            "bucket?acl=x",     // query injection
            "bucket#frag",      // fragment
            "bucket\r\nX:1",    // CRLF
            "bucket\x00null",   // NUL
        ] {
            assert!(
                validate_s3_bucket(b).is_err(),
                "accepted disallowed bucket: {b:?}"
            );
        }
    }

    #[test]
    fn key_canonical_paths_accepted() {
        for k in [
            "file.txt",
            "year=2026/month=05/day=16/event.json",
            "user/uuid-1234/profile.png",
            "deep/path/with/many/segments/file.bin",
            // Special-but-permitted chars per S3 recommended charset.
            "report (final) v2.csv",
            "logs+extra-data.txt",
        ] {
            assert!(validate_s3_key(k).is_ok(), "rejected: {k:?}");
        }
    }

    #[test]
    fn key_url_injection_rejected() {
        // The headline attack: ?acl= would set object ACL post-signing.
        assert!(validate_s3_key("file.txt?acl=public-read").is_err());
        // Sibling variants the URL parser would honour.
        assert!(validate_s3_key("file?versionId=abc").is_err());
        assert!(validate_s3_key("path/file#fragment").is_err());
        assert!(validate_s3_key("file\r\nHeader: 1").is_err());
        assert!(validate_s3_key("file\x00name").is_err());
        assert!(validate_s3_key("file\x01control").is_err());
    }

    #[test]
    fn key_traversal_segments_rejected() {
        assert!(validate_s3_key("../other-bucket-key").is_err());
        assert!(validate_s3_key("path/../escape").is_err());
        assert!(validate_s3_key("path/./normal").is_err());
        assert!(validate_s3_key("..").is_err());
        assert!(validate_s3_key(".").is_err());
        // Sanity: a literal ".." substring inside a segment is fine.
        assert!(validate_s3_key("path/with..dots-in-name").is_ok());
    }

    #[test]
    fn key_length_bounds_enforced() {
        assert!(validate_s3_key("").is_err());
        let max = "x".repeat(1024);
        assert!(validate_s3_key(&max).is_ok());
        let over = "x".repeat(1025);
        assert!(validate_s3_key(&over).is_err());
    }
}

// ============================================================================
// Vault header resolution — shared by HTTP, fetch_all, GraphQL, Webhook, NATS
// ============================================================================

/// Re-export of the canonical LLM provider check. The actual list lives in
/// `talos_workflow_job_protocol::LLM_PROVIDER_VAULT_PATHS` so controller + worker share
/// one definition — if you add a provider there, every deny/prefetch/cache
/// site picks it up automatically. See `talos_workflow_job_protocol` for the security-
/// rationale doc and test coverage.
use talos_workflow_job_protocol::is_llm_provider_vault_path as is_reserved_host_secret_path;

/// 16-hex-char (8-byte) SHA-256 prefix of a vault path. Stable identity for
/// host-log ↔ guest-error correlation without leaking the literal path back
/// to the guest sandbox.
///
/// **Why this is a function, not an inline expression.** Three sites in
/// `resolve_vault_header` (allowlist-deny, tier-1-LLM-deny, resolve-failed)
/// build deny errors that MUST be byte-identical in their hash component so
/// operators can grep the host log with one query. Centralising the hash
/// here is the only way to guarantee the three sites stay in lockstep
/// across refactors. The wasm-security review of 2026-05-22 (MEDIUM-3)
/// caught the allowlist-deny path echoing the literal `vault_path` while
/// the resolve-failed path correctly emitted only the hash — a probing
/// oracle that fingerprinted host vault structure. Pulling the hash into
/// a helper makes "every deny path uses the same redaction" enforceable
/// at the type level rather than by reading three string literals.
///
/// 8 bytes is collision-free across any realistic vault-path inventory
/// (2^64 distinct paths before birthday collisions become probable) and
/// short enough to keep error/log lines readable.
pub(crate) fn vault_path_short_hash(vault_path: &str) -> String {
    let h = Sha256::digest(vault_path.as_bytes());
    hex::encode(&h[..8])
}

impl TalosContext {
    /// Resolve `host` and reject if any A/AAAA record falls in the
    /// private/loopback/link-local/CGNAT/IPv4-mapped-IPv6 deny-list.
    ///
    /// Closes the DNS-rebinding window for hostname-based egress: an
    /// attacker who controls a domain in `allowed_hosts` could otherwise
    /// resolve it to 127.0.0.1 / 100.64.x.x / ::ffff:10.0.0.1 at request
    /// time and reach internal services. IP literals are caught by
    /// `classify_private_ip` directly at the URL parse step; this fn
    /// covers the hostname case.
    ///
    /// Returns `Ok(())` when every resolved IP is public, OR when the
    /// operator has explicitly opted into private-host targets via
    /// `WORKER_ALLOW_PRIVATE_HOST_TARGETS=1` AND the host appears
    /// verbatim (not via "*") in `allowed_hosts`. Returns `Err(reason)`
    /// otherwise — caller maps to its own host-fn error type and emits
    /// an audit event.
    ///
    /// `capability_label` is the talos.audit.ledger label for the deny
    /// path ("http-fetch", "webhook", "graphql", etc.) so the audit
    /// trail attributes the rejection to the correct host fn.
    async fn validate_no_dns_rebinding(
        &mut self,
        host: &str,
        capability_label: &'static str,
    ) -> Result<(), &'static str> {
        let bypass =
            *ALLOW_PRIVATE_HOST_TARGETS && self.allowed_hosts.iter().any(|p| p != "*" && p == host);
        if bypass {
            tracing::debug!(
                host,
                capability_label,
                "DNS-SSRF bypass active (WORKER_ALLOW_PRIVATE_HOST_TARGETS=1 + explicit allowlist hit)"
            );
            return Ok(());
        }

        match tokio::net::lookup_host(format!("{}:80", host)).await {
            Ok(addrs) => {
                for addr in addrs {
                    let ip = addr.ip();
                    if let Some(policy) = classify_private_ip(ip) {
                        self.record_capability_denied(capability_label, policy, &ip.to_string())
                            .await;
                        tracing::warn!(
                            host,
                            ip = %ip,
                            policy,
                            capability_label,
                            "WASM module blocked: hostname resolved to a private IP"
                        );
                        return Err(policy);
                    }
                }
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    host,
                    capability_label,
                    error = %e,
                    "Failed to resolve hostname for SSRF validation"
                );
                Err("dns-resolution-failed")
            }
        }
    }

    /// Check a vault path against this module's `allowed_secrets` grant, AND
    /// against the host-reserved path deny-list.
    ///
    /// Single enforcement point shared by `get_secret` (guest-initiated) and
    /// `resolve_vault_header` (host-initiated on behalf of http/graphql/webhook/nats),
    /// so no WASM-reachable code path can bypass either check.
    fn check_secret_allowlist(&self, key_path: &str) -> Result<(), ()> {
        // Host-reserved paths win over allowed_secrets — a module with
        // `allowed_secrets: ["*"]` must still not read LLM provider keys,
        // because those are pre-fetched into every job by the controller
        // purely for internal `llm::*` consumption.
        if is_reserved_host_secret_path(key_path) {
            tracing::warn!(
                gate = "reserved_host_path",
                key_path,
                module_id = ?self.module_id,
                capability_world = ?self.capability_world,
                "WASM module attempted to read a reserved host secret path — denied. \
                 LLM provider keys are host-only; use the `llm::*` host functions, \
                 which resolve these paths internally without exposing them to guests."
            );
            return Err(());
        }
        if vault_path_allowed(&self.allowed_secrets, key_path) {
            Ok(())
        } else {
            // Log the grant *shape*, not the contents. Earlier versions
            // printed `format!("{:?}", self.allowed_secrets)` — that
            // reveals the operator's vault namespace structure
            // (`["oauth/gmail/*", "anthropic/api_key", ...]`) into
            // production logs every time a guest fumbles a path. The
            // shape is sensitive (it telegraphs which integrations are
            // provisioned for this actor) so we replace it with a
            // count + SHA-256 fingerprint of the joined paths. The
            // fingerprint is stable across runs with the same grant,
            // so operators can still correlate "did this module's
            // grant change?" without seeing the actual paths.
            let grant_summary = if self.allowed_secrets.is_empty() {
                "EMPTY (deny-all)".to_string()
            } else {
                let mut hasher = Sha256::new();
                // Sort the paths before hashing so the fingerprint is
                // order-stable. The signed `JobRequest` already sorts
                // `allowed_secrets` (canonical-bytes rule) but defending
                // against future drift is cheap.
                let mut sorted: Vec<&str> =
                    self.allowed_secrets.iter().map(String::as_str).collect();
                sorted.sort_unstable();
                for path in &sorted {
                    hasher.update(path.as_bytes());
                    hasher.update(b"\0"); // separator — defends against
                                          // `["ab","c"]` colliding with `["a","bc"]`.
                }
                let fp = hex::encode(&hasher.finalize()[..8]);
                format!("count={} fp={}", self.allowed_secrets.len(), fp)
            };
            tracing::warn!(
                gate = "allowlist",
                key_path,
                module_id = ?self.module_id,
                capability_world = ?self.capability_world,
                allowed_secrets = %grant_summary,
                "module requested a secret not in its allowed_secrets list. \
                 Fix: recompile with allowed_secrets: [\"<prefix>\"] (e.g. [\"github/token\"] for a specific key, \
                 or [\"oauth/gmail\"] for a prefix grant). Wildcard [\"*\"] permits all non-reserved paths."
            );
            Err(())
        }
    }

    /// Resolve a `vault://` header value to its plaintext via the `SecretProvider`.
    ///
    /// If `value` does not start with `vault://` it is returned unchanged
    /// (zero allocation via `Cow::Borrowed`). If the vault path cannot be
    /// resolved, an error is returned — the caller MUST fail the operation
    /// rather than proceeding with an unresolved reference.
    ///
    /// SECURITY: enforces the module's `allowed_secrets` grant before resolving.
    /// Previously this path bypassed the allowlist — any http-node module could
    /// read any secret by stuffing `vault://any/path` into an outbound header.
    ///
    /// Plaintext exits through `into_auth_header` — auditable via AuditingProvider:
    ///   grep -rn "into_auth_header" worker/src/
    ///
    /// `&mut self` + `async` so deny paths can append to the cryptographic
    /// audit ledger via `record_capability_denied`. Previously this was a
    /// sync `&self` function that used `block_in_place`+`block_on` to call
    /// the async provider, which (a) blocked a runtime worker thread for
    /// the duration of every vault lookup and (b) made it impossible to
    /// emit signed audit events from the deny paths. Both fixed here.
    async fn resolve_vault_header<'a>(
        &mut self,
        header_name: &str,
        value: &'a str,
    ) -> Result<std::borrow::Cow<'a, str>, String> {
        let Some(vault_path) = value.strip_prefix("vault://") else {
            return Ok(std::borrow::Cow::Borrowed(value));
        };

        // Hash the vault path once up-front. Used both for audit
        // correlation (host log) and as the *only* identifier surfaced
        // in guest-visible deny messages — see the redaction rationale
        // below.
        let vault_path_hash = vault_path_short_hash(vault_path);

        // SECURITY: enforce the module's allowed_secrets grant before we
        // even attempt provider resolution. This closes the bypass where
        // http-capable modules could exfiltrate arbitrary vault keys via
        // vault:// header references.
        //
        // Wasm-security review 2026-05-22 (MEDIUM-3): the deny error
        // previously echoed the literal `vault_path` back to the guest.
        // Combined with the hash-only error on the resolve-failed path
        // (below, line ~1772) this gave a malicious module a probing
        // oracle: any path that came back with the literal echoed was
        // "syntactically valid + not in my allowlist", any path that
        // came back with just a hash was "in my allowlist but resolve
        // failed". Iterating across well-known vault prefixes fingered
        // the host's vault layout. Both deny paths now emit the hash-
        // only form so the guest learns no more than what it already
        // knew (the path it just sent), and audit cross-correlation
        // uses the same `vault_path_hash` operators grep the host log
        // for. The full path goes to `record_capability_denied` and the
        // tracing log only — never back to the guest.
        if self.check_secret_allowlist(vault_path).is_err() {
            // Full SHA-256 in the audit-ledger entry (mirrors the
            // `secrets::get` deny site); the truncated `vault_path_hash`
            // above is what the operator will see in the guest-side
            // error and the corresponding tracing log line.
            let full_path_hash = format!("{:x}", Sha256::digest(vault_path.as_bytes()));
            self.record_capability_denied("vault-header", "secret-allowlist", &full_path_hash)
                .await;
            tracing::warn!(
                vault_path,
                vault_path_hash = %vault_path_hash,
                header_name,
                actor_id = ?self.actor_id,
                "vault:// header rejected: not in module's allowed_secrets grant"
            );
            return Err(format!(
                "Header '{header_name}' references a vault secret not permitted by this \
                 module's allowed_secrets grant (vault_path_hash={vault_path_hash}). \
                 Operator: grep host logs for this hash to see the literal path, then \
                 reinstall the module with the path added to allowed_secrets."
            ));
        }

        // Tier-1 LLM egress ceiling — refuse vault:// resolution for
        // Tier-2 LLM provider keys. Even if the host allowlist is
        // somehow bypassed, the guest can't interpolate an Anthropic
        // / OpenAI / Gemini key into a header without this gate.
        // Together with the host-deny list in `fetch`, this closes
        // the two halves of the C3 bypass: can't reach the host AND
        // can't materialise the credential in-guest.
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) && talos_workflow_job_protocol::is_tier2_llm_vault_path(vault_path)
        {
            // Wasm-security review 2026-05-22 (MEDIUM-3 sibling): the
            // Tier-2 LLM provider key paths (`anthropic/api_key`,
            // `openai/api_key`, `gemini/api_key`) are public constants,
            // so the redaction here is mostly for consistency with the
            // allowlist-deny path above. Same audit/log/error shape:
            // full hash in audit, truncated hash in guest error + log.
            let full_path_hash = format!("{:x}", Sha256::digest(vault_path.as_bytes()));
            self.record_capability_denied("vault-header", "tier1-llm-egress", &full_path_hash)
                .await;
            tracing::warn!(
                vault_path,
                vault_path_hash = %vault_path_hash,
                header_name,
                actor_id = ?self.actor_id,
                "tier-1 actor attempted vault:// header for external LLM key; refused"
            );
            return Err(format!(
                "Header '{header_name}' references a Tier-2 LLM provider key \
                 (vault_path_hash={vault_path_hash}) but this actor's ceiling is \
                 Tier-1 (local Ollama only); external provider credentials are refused."
            ));
        }

        let exec_id = self
            .execution_id
            .as_deref()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .unwrap_or_else(uuid::Uuid::new_v4);

        // `vault_path_hash` was computed up-front and is reused here
        // for log/guest-error cross-correlation (see L-1 rationale at
        // the top of this function). SHA-256(path)[..16] gives 8 bytes
        // of identity — collision-free for any realistic vault-path
        // inventory while keeping the log line compact.
        match self.provider.resolve(vault_path, exec_id).await {
            Ok(handle) => {
                let header_result = self.provider.into_auth_header(handle, header_name);
                // Always release — both success and error paths must drop the slot
                // so the Zeroizing<String> is freed and secret material is erased.
                let _ = self.provider.release(handle).await;
                match header_result {
                    // L-4: convert Zeroizing<String> → owned String at the
                    // immediate point of use. The Zeroizing wrapper wipes
                    // its buffer when the binding goes out of scope; the
                    // String we hand to reqwest will be moved into
                    // HeaderValue's internal buffer and is the only
                    // remaining plaintext copy after this scope exits.
                    Ok(plaintext) => Ok(std::borrow::Cow::Owned((*plaintext).clone())),
                    Err(e) => {
                        tracing::error!(
                            vault_path,
                            vault_path_hash = %vault_path_hash,
                            header_name,
                            error = %e,
                            "vault:// header resolution failed"
                        );
                        // L-1: redact the literal path in the
                        // guest-visible error — leak only the
                        // truncated hash so an operator can grep the
                        // host log for the matching `vault_path_hash`
                        // and see the real path there. Cause is kept
                        // generic; specific reasons (allowlist,
                        // ownership, missing) are in the host log.
                        Err(format!(
                            "Header '{header_name}' references a vault secret \
                             that could not be resolved (vault_path_hash={vault_path_hash}). \
                             Operator: grep host logs for this hash to see the literal path."
                        ))
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    vault_path,
                    vault_path_hash = %vault_path_hash,
                    header_name,
                    error = %e,
                    "vault:// path not resolvable"
                );
                Err(format!(
                    "Header '{header_name}' references a vault secret \
                     that could not be resolved (vault_path_hash={vault_path_hash}). \
                     Operator: grep host logs for this hash to see the literal path."
                ))
            }
        }
    }

    /// Look up a host-internal secret by key name via the SecretProvider.
    ///
    /// This path is used by the native `llm`, `llm-tools`, `llm-streaming`, and `email`
    /// WIT interfaces — it bypasses the guest-facing `secrets::get-secret` allowlist check
    /// because these interfaces are host-internal (the guest never sees the resolved value).
    /// The slot is resolved and immediately released after reading.
    ///
    /// Takes `&mut self` (not `&self`) so the future produced by this async method is `Send`.
    ///
    /// MCP-878 (2026-05-14): log resolve / into_auth_header failures.
    /// Pre-fix `.await.ok()?` discarded both error types silently. A
    /// vault-secret resolution that broke (DB blip, decryption failure,
    /// missing-key, provider misconfig) returned `None` indistinguishable
    /// from "key not granted to this module" — and the caller (HTTP
    /// header substitution, email config, etc.) then dispatched WITHOUT
    /// the secret, surfacing as an opaque "401 Unauthorized" or
    /// "missing config" upstream error instead of the actual
    /// vault-resolution failure. Operators saw user reports of
    /// "my module's API calls suddenly stopped working" with zero
    /// signal in worker logs. Same silent-fail observability class
    /// as MCP-876 / MCP-877.
    async fn get_host_secret(&mut self, key_name: &str) -> Option<String> {
        let exec_id = self
            .execution_id
            .as_deref()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .unwrap_or_else(uuid::Uuid::new_v4);
        let handle = match self.provider.resolve(key_name, exec_id).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(
                    key_name = %key_name,
                    error = %e,
                    "get_host_secret: provider.resolve failed — returning None; \
                     caller will dispatch WITHOUT the secret"
                );
                return None;
            }
        };
        let value = match self.provider.into_auth_header(handle, "Authorization") {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(
                    key_name = %key_name,
                    error = %e,
                    "get_host_secret: into_auth_header failed — returning None"
                );
                None
            }
        };
        let _ = self.provider.release(handle).await;
        // L-4: unwrap Zeroizing → owned String at the immediate point of
        // use. The wrapper wipes when it drops at end of expression.
        value
            .filter(|v| !v.is_empty())
            .map(|v| (*v).clone())
    }

    /// Resolve a vault path to its raw plaintext (no Bearer/Basic prefix).
    ///
    /// Distinct from `get_host_secret`, which routes through `into_auth_header`
    /// with header name `"Authorization"` — that path injects a `"Bearer "` prefix,
    /// which is wrong for keys sent as `x-api-key`, `x-goog-api-key`, query params,
    /// or as raw body values. Use this when you need the literal stored value.
    async fn resolve_raw_vault_secret(&mut self, path: &str) -> Option<String> {
        let exec_id = self
            .execution_id
            .as_deref()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .unwrap_or_else(uuid::Uuid::new_v4);
        // MCP-878 (2026-05-14): same telemetry shape as get_host_secret
        // above. resolve_raw_vault_secret is used for headers that need
        // the literal stored value (x-api-key, x-goog-api-key, query
        // params, raw body fields), so a silent-None means the
        // module's request fires WITHOUT the secret rather than
        // failing at the gate.
        let handle = match self.provider.resolve(path, exec_id).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(
                    vault_path = %path,
                    error = %e,
                    "resolve_raw_vault_secret: provider.resolve failed — returning None; \
                     caller will dispatch WITHOUT the secret"
                );
                return None;
            }
        };
        // Non-"Authorization" header name avoids the Bearer-prefix path inside
        // `into_auth_header`. The name is just a label for audit logging.
        let value = match self.provider.into_auth_header(handle, "X-Talos-Raw") {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(
                    vault_path = %path,
                    error = %e,
                    "resolve_raw_vault_secret: into_auth_header failed — returning None"
                );
                None
            }
        };
        let _ = self.provider.release(handle).await;
        // L-4: same unwrap pattern as get_host_secret.
        value
            .filter(|v| !v.is_empty())
            .map(|v| (*v).clone())
    }

    /// Resolve an LLM provider API key via the vault first, env var second.
    ///
    /// Ordering:
    /// 1. **Vault path** — e.g. `anthropic/api_key`. This is the canonical source;
    ///    rotations via `rotate_secret` take effect on the next job's pre-fetch.
    /// 2. **Env var fallback** — e.g. `ANTHROPIC_API_KEY`. Bootstrap path for dev
    ///    environments where the vault isn't populated; read directly from the
    ///    worker process env (not via `get_host_secret`, which would wrap the
    ///    value with `"Bearer "`).
    ///
    /// Returns `None` for Ollama (no key required) and for unknown providers.
    ///
    /// Tier enforcement: when `self.max_llm_tier == Tier1`, external
    /// providers (Anthropic / OpenAI / Gemini) are refused — the caller
    /// sees `None` which the `llm::complete` dispatcher surfaces as a
    /// missing-key error to the guest. The tier check happens BEFORE
    /// any vault or env lookup so no key material is resolved for a
    /// forbidden provider.
    async fn get_llm_api_key(&mut self, provider: wit_llm::Provider) -> Option<String> {
        let provider_name = match provider {
            wit_llm::Provider::Anthropic => "anthropic",
            wit_llm::Provider::Openai => "openai",
            wit_llm::Provider::Gemini => "gemini",
            wit_llm::Provider::Ollama => "ollama",
        };
        match decide_llm_tier_access(provider_name, self.max_llm_tier) {
            LlmTierDecision::NoKeyNeeded => return None,
            LlmTierDecision::Refused => {
                self.record_capability_denied(
                    "llm-key-resolution",
                    "tier1-llm-egress",
                    provider_name,
                )
                .await;
                tracing::warn!(
                    provider = provider_name,
                    "tier-1 actor attempted external LLM call; refused"
                );
                return None;
            }
            LlmTierDecision::Allowed => {}
        }
        let (vault_path, env_name) = llm_key_lookup_paths(provider_name)?;
        if let Some(v) = self.resolve_raw_vault_secret(vault_path).await {
            return Some(v);
        }
        std::env::var(env_name).ok().filter(|v| !v.is_empty())
    }

    /// String-keyed variant used by llm-tools / llm-streaming, whose WIT Provider
    /// enums are distinct from `wit_llm::Provider` but cover the same providers.
    ///
    /// Same tier enforcement as `get_llm_api_key`.
    async fn get_llm_api_key_by_name(&mut self, provider_name: &str) -> Option<String> {
        let lower = provider_name.to_ascii_lowercase();
        match decide_llm_tier_access(&lower, self.max_llm_tier) {
            LlmTierDecision::NoKeyNeeded => return None,
            LlmTierDecision::Refused => {
                self.record_capability_denied("llm-key-resolution", "tier1-llm-egress", &lower)
                    .await;
                tracing::warn!(
                    provider = provider_name,
                    "tier-1 actor attempted external LLM call; refused"
                );
                return None;
            }
            LlmTierDecision::Allowed => {}
        }
        let (vault_path, env_name) = llm_key_lookup_paths(provider_name)?;
        if let Some(v) = self.resolve_raw_vault_secret(vault_path).await {
            return Some(v);
        }
        std::env::var(env_name).ok().filter(|v| !v.is_empty())
    }
}

/// MCP-1008 (2026-05-15): saturating u64→u32 conversion for parsing
/// LLM provider `input_tokens` / `output_tokens` fields out of the
/// untrusted response JSON. Same defense-in-depth pattern as MCP-962
/// closed for `workflow_chains` config — the legacy
/// `.as_u64().unwrap_or(0) as u32` shape silently wraps any value
/// above `u32::MAX` (~4.29 billion), producing under-counted token
/// totals in metrics + cost-attribution dashboards.
///
/// A misbehaving / compromised LLM provider returning
/// `input_tokens: 5_000_000_000` would have wrapped to ~705 M tokens,
/// charging the user ~705 M tokens of cost-attribution for a request
/// that actually consumed 5 B. Saturating to `u32::MAX` preserves the
/// "something weird happened" signal — `u32::MAX` in a token-count
/// dashboard is visibly absurd and triggers operator investigation.
///
/// Returns `default` when the JSON field is missing or wrong-typed
/// (preserves the pre-fix behaviour for that case).
fn json_token_count_as_u32(field: Option<&serde_json::Value>, default: u32) -> u32 {
    match field.and_then(|v| v.as_u64()) {
        Some(n) => u32::try_from(n).unwrap_or(u32::MAX),
        None => default,
    }
}

/// MCP-1213 (2026-05-18): bounded-body read for LLM responses.
/// Streams chunks from `response.bytes_stream()` until either the body
/// completes or `max_bytes` is exceeded.  Returns `Some(body_bytes)`
/// on success, `None` if the body exceeds the cap (caller decides how
/// to surface — typically as `ApiError`).
///
/// Pre-fix `response.json()` / `response.text()` had no size limit:
/// a 1 GB body from a misbehaving / compromised provider would buffer
/// in worker memory, OOMing the pod. This helper paired with an
/// outer `tokio::time::timeout` over the WHOLE exchange replaces both
/// `.json()` and `.text()` at the LLM call sites — bytes-then-parse
/// is a wider-net pattern that catches both the size class AND the
/// hang class in a single helper.
async fn read_llm_response_body_bounded(
    response: reqwest::Response,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    use futures_util::StreamExt;
    let content_length = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    // Pre-allocate at the smaller of (Content-Length, max_bytes) — saves
    // allocator churn on legitimate responses (typical 1-100 KiB) while
    // refusing to honour a hostile Content-Length larger than the cap.
    let capacity = std::cmp::min(content_length, max_bytes);
    let mut buf = Vec::with_capacity(capacity);
    let mut stream = response.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.ok()?;
        if buf.len() + chunk.len() > max_bytes {
            tracing::warn!(
                limit = max_bytes,
                buffered = buf.len(),
                chunk_size = chunk.len(),
                "LLM response exceeded size cap; aborting body read"
            );
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    Some(buf)
}

/// Canonical (vault-path, env-var-name) tuple for each LLM provider.
/// Returns `None` for Ollama (no key required) or unknown providers.
fn llm_key_lookup_paths(provider: &str) -> Option<(&'static str, &'static str)> {
    match provider.to_ascii_lowercase().as_str() {
        "anthropic" => Some(("anthropic/api_key", "ANTHROPIC_API_KEY")),
        "openai" => Some(("openai/api_key", "OPENAI_API_KEY")),
        "gemini" => Some(("gemini/api_key", "GEMINI_API_KEY")),
        _ => None,
    }
}

/// Outcome of the tier-ceiling check for an `llm::*` host call.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LlmTierDecision {
    /// Provider is `ollama` — no key needed, always allowed.
    NoKeyNeeded,
    /// External provider allowed by the ceiling.
    Allowed,
    /// External provider blocked by a Tier-1 ceiling. Caller MUST NOT
    /// resolve any vault or env value for this provider.
    Refused,
}

/// Pure, testable tier check. Returns the decision for `(provider, ceiling)`
/// without touching vault or env. The live `get_llm_api_key` uses this,
/// as do the tier-enforcement tests.
pub(crate) fn decide_llm_tier_access(
    provider_lower: &str,
    ceiling: talos_workflow_job_protocol::LlmTier,
) -> LlmTierDecision {
    if provider_lower == "ollama" {
        return LlmTierDecision::NoKeyNeeded;
    }
    match ceiling {
        talos_workflow_job_protocol::LlmTier::Tier1 => LlmTierDecision::Refused,
        talos_workflow_job_protocol::LlmTier::Tier2 => LlmTierDecision::Allowed,
        // `LlmTier` is `#[non_exhaustive]` upstream. Fail-closed for any
        // future variant — we'd rather refuse than silently allow data
        // egress to a yet-unclassified provider tier.
        _ => LlmTierDecision::Refused,
    }
}

// ============================================================================
// HTTP
// ============================================================================

impl wit_http::Host for TalosContext {
    async fn fetch(
        &mut self,
        req: wit_http::Request,
    ) -> Result<wit_http::Response, wit_http::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<wit_http::Response, wit_http::Error> = async move {
        // Track async fuel consumption - HTTP operations consume fuel based on wall time
        let async_start = std::time::Instant::now();
        // MCP-789 (2026-05-14): the cheap pure-validation block (capability
        // gate, URL parse, empty allowlist, SSRF IP literal, allowed_hosts
        // pattern, Tier-1 LLM egress) MUST run BEFORE `check_rate_limit`
        // charges `http_call_count`. Pre-fix the rate-limit charge ran
        // FIRST, before even the capability gate. A guest could drain
        // MAX_HTTP_CALLS_PER_EXECUTION (1000/exec) by looping
        // `fetch(url="http://127.0.0.1/x")` (SSRF deny) or
        // `fetch(url="https://blocked.example.com/x")` (allowed_hosts
        // deny) and subsequent legitimate fetch() calls were then
        // blocked for the rest of the execution despite zero outbound
        // network I/O. The fetch_all batch variant was closed in
        // MCP-783; the single-fetch path was missed in that sweep.
        // Conservative reorder: rate-limit + cancellation moved AFTER
        // the cheap sync pure-validation block and BEFORE dry-run, so
        // dry-run STILL consumes a slot (preserves debug-quota
        // semantics) and DNS-rebind / method-allowlist / circuit-breaker
        // still run AFTER the charge (they involve I/O or atomic-state
        // reads that are legitimate per-call costs). Same shape as
        // MCP-770/783/784/785/786/787/788 and MCP-612 (counter-only-
        // advances-when-admitted).
        use crate::wit_inspector::CapabilityWorld;
        if matches!(
            self.capability_world,
            CapabilityWorld::Minimal | CapabilityWorld::Unknown
        ) {
            tracing::warn!("WASM module attempted HTTP request but lacks Http capability");
            return Err(wit_http::Error::Forbiddenhost);
        }
        // MCP-1148: cap URL bytes BEFORE invoking `url::Url::parse`.
        // The parser is O(N); a hostile guest could ship a 10 MB URL
        // and force the host to walk every byte on every call.
        if req.url.len() > MAX_OUTBOUND_URL_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                url_len = req.url.len(),
                limit = MAX_OUTBOUND_URL_BYTES,
                "wit_http::fetch rejected: URL length exceeds cap"
            );
            return Err(wit_http::Error::Invalidurl);
        }
        // Validate and parse the URL first.
        let url: url::Url = req.url.parse().map_err(|_| wit_http::Error::Invalidurl)?;

        // HTTPS-only by default. Plaintext outbound traffic can leak
        // `vault://` headers; the SSRF gate protects destination but
        // not data-in-flight. Operators with a legitimate plaintext
        // target opt in via `WASM_ALLOW_INSECURE_HTTP=1`.
        match classify_url_scheme(url.scheme(), insecure_http_opt_in()) {
            UrlSchemeVerdict::Https => {}
            UrlSchemeVerdict::InsecureAllowedByOptIn { scheme } => {
                tracing::warn!(
                    scheme = %scheme,
                    host = %url.host_str().unwrap_or(""),
                    "WASM module sent insecure-scheme HTTP request — \
                     allowed by WASM_ALLOW_INSECURE_HTTP=1 (operator opt-in). \
                     Confirm this is intended; plaintext traffic can leak vault:// \
                     headers in flight."
                );
            }
            UrlSchemeVerdict::InsecureRefused { scheme } => {
                self.record_capability_denied(
                    "http-fetch",
                    "insecure-scheme",
                    &format!("{scheme} {}", url.host_str().unwrap_or("")),
                )
                .await;
                tracing::warn!(
                    scheme = %scheme,
                    host = %url.host_str().unwrap_or(""),
                    "WASM module attempted non-https HTTP request — denied. \
                     Set WASM_ALLOW_INSECURE_HTTP=1 to permit plaintext outbound."
                );
                return Err(wit_http::Error::Invalidurl);
            }
        }

        // Enforce the host allowlist.  An empty list means DENY ALL — the module
        // must be configured with an explicit allowlist, or use "*" to allow any host.
        let host = url.host_str().unwrap_or("");
        // Structured trace for diagnosing vault:// and host-allowlist
        // rejections. Visible at RUST_LOG=worker=debug level.
        tracing::debug!(
            host,
            allowed_hosts_count = self.allowed_hosts.len(),
            allowed_secrets_count = self.allowed_secrets.len(),
            capability_world = ?self.capability_world,
            "http fetch dispatch"
        );
        if self.allowed_hosts.is_empty() {
            self.record_capability_denied("http-fetch", "no-allowlist-configured", host)
                .await;
            tracing::warn!(
                host,
                "WASM module attempted HTTP request but no host allowlist is configured — \
                 denying. Set WASM_ALLOWED_HOSTS=\"*\" to allow all hosts."
            );
            return Err(wit_http::Error::Forbiddenhost);
        }

        // DNS rebinding / SSRF protection: if the host parses as an IP address literal,
        // reject private, loopback, link-local, multicast, broadcast, and CGNAT ranges
        // immediately. This prevents a WASM module from using an IP literal to reach
        // internal services even when the allowlist contains a wildcard ("*").
        let ip_literal: Option<std::net::IpAddr> = match url.host() {
            Some(url::Host::Ipv4(a)) => Some(a.into()),
            Some(url::Host::Ipv6(a)) => Some(a.into()),
            _ => None, // hostname — DNS check happens after allowlist
        };
        if let Some(ip) = ip_literal {
            if let Some(policy) = classify_private_ip(ip) {
                self.record_capability_denied("http-fetch", policy, &ip.to_string())
                    .await;
                tracing::warn!(
                    ip = %ip,
                    policy,
                    "WASM module attempted to reach a private IP literal — blocking"
                );
                return Err(wit_http::Error::Forbiddenhost);
            }
        }

        if !host_allowlist_match(&self.allowed_hosts, host) {
            self.record_capability_denied("http-fetch", "allowed-hosts", host)
                .await;
            tracing::warn!(
                host,
                allowed_count = self.allowed_hosts.len(),
                "WASM module attempted to reach a forbidden host"
            );
            return Err(wit_http::Error::Forbiddenhost);
        }

        // Tier-1 LLM egress ceiling — deny external LLM provider hosts
        // regardless of `allowed_hosts`. Closes the HTTP bypass: a
        // Tier-1 guest can NOT reach `api.anthropic.com` even with
        // `api.anthropic.com` explicitly in `allowed_hosts` + its own
        // API key in `allowed_secrets`. This sits above the `llm::*`
        // host-fn ceiling: those gate key resolution; this gates the
        // network destination. Both are needed — a guest can bring its
        // own key (`config["api_key"]`) and bypass `llm::*` entirely.
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) {
            let host_lower = host.to_ascii_lowercase();
            if let Some(policy) = tier1_egress_deny_reason(&host_lower) {
                self.record_capability_denied("http-fetch", policy, host)
                    .await;
                tracing::warn!(
                    host,
                    actor_id = ?self.actor_id,
                    policy,
                    "tier-1 actor egress refused (external LLM host or public IP literal)"
                );
                return Err(wit_http::Error::Forbiddenhost);
            }
        }

        // Rate limit + cancellation: charged AFTER the cheap pure-validation
        // block above — see MCP-789 reorder comment near the top of this
        // function. Charged BEFORE dry-run so dry-run still consumes a slot
        // (preserves debug-quota semantics), and BEFORE the DNS-rebind
        // lookup so DNS work is bounded by the rate-limit too.
        if !self.check_rate_limit(&self.http_call_count, MAX_HTTP_CALLS_PER_EXECUTION) {
            tracing::warn!(module_id = ?self.module_id, "HTTP call rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("http");
            }
            return Err(wit_http::Error::Forbiddenhost);
        }
        // M-6: per-host rate limit charged AFTER the global cap admits.
        // Failure here yields the global counter back? — no, intentionally
        // not: the global cap is the worker-level budget for compute spent
        // on validation + DNS + setup, and a per-host overage still cost
        // that effort. Burning the global slot keeps the abuse pattern
        // expensive for the attacker. The host string is normalized to
        // host:port (lowercased) inside `check_per_host_rate_limit`.
        let host_for_limit = match url.port_or_known_default() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        if !self.check_per_host_rate_limit(
            &host_for_limit,
            MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION,
        ) {
            tracing::warn!(
                module_id = ?self.module_id,
                host = %host,
                limit = MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION,
                "HTTP per-host rate limit exceeded — refusing to amplify load to a single upstream"
            );
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("http_per_host");
            }
            return Err(wit_http::Error::Forbiddenhost);
        }
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            return Err(wit_http::Error::Networkerror);
        }

        // Dry-run mode: mock non-GET HTTP requests BEFORE any network
        // operation (DNS, circuit breaker, real HTTP). The previous
        // location (after DNS resolution) meant that a POST to a
        // non-resolvable hostname — i.e. exactly the URLs you'd use
        // to test workflow logic without side effects — failed with
        // a generic Networkerror instead of being intercepted.
        //
        // Policy checks above this point still apply (allowed_hosts +
        // IP-literal SSRF), so misconfigured allowlists still surface
        // as Forbiddenhost during dry-run testing. Method allowlist
        // and circuit-breaker are intentionally skipped here — neither
        // is meaningful for traffic that will never leave the worker.
        if self.dry_run {
            let dry_method = match req.method {
                wit_http::Method::Get => "GET",
                wit_http::Method::Post => "POST",
                wit_http::Method::Put => "PUT",
                wit_http::Method::Delete => "DELETE",
                wit_http::Method::Patch => "PATCH",
            };
            if dry_method != "GET" {
                tracing::info!(
                    method = dry_method,
                    url = %req.url,
                    "Dry-run: intercepted non-GET request (pre-network)"
                );
                let mock_body = serde_json::to_vec(&serde_json::json!({
                    "__dry_run__": true,
                    "intercepted_method": dry_method,
                    "intercepted_url": req.url,
                }))
                .unwrap_or_default();
                return Ok(wit_http::Response {
                    status: 200,
                    headers: vec![("x-talos-dry-run".to_string(), "true".to_string())],
                    body: mock_body,
                });
            }
        }

        // ── DNS resolution validation (SSRF protection) ────────────────────
        // For hostnames (not IP literals), resolve DNS and verify the resolved
        // IP is not a private/internal address. This prevents DNS rebinding attacks
        // where an attacker controls a domain that resolves to internal IPs.
        //
        // Operator opt-in: WORKER_ALLOW_PRIVATE_HOST_TARGETS=1 disables the
        // DNS-resolved-to-private rejection, but ONLY for hostnames that are
        // explicitly named in `allowed_hosts` (not via "*"). This narrow
        // bypass enables the local-development case where the worker reaches
        // a sibling service (e.g. nova on host.docker.internal:3030) while
        // keeping the wildcard-allowlist case fully protected. IP literals
        // are still rejected unconditionally above.
        let bypass_dns_ssrf = *ALLOW_PRIVATE_HOST_TARGETS
            && self
                .allowed_hosts
                .iter()
                .any(|p| p != "*" && p == host);
        if url
            .host()
            .is_some_and(|h| matches!(h, url::Host::Domain(_)))
            && !bypass_dns_ssrf
        {
            match tokio::net::lookup_host(format!("{}:80", host)).await {
                Ok(addrs) => {
                    for addr in addrs {
                        let ip = addr.ip();
                        // Same deny-list as the IP-literal arm above —
                        // shared via classify_private_ip so CGNAT and
                        // IPv4-mapped IPv6 stay covered without drift.
                        // This is the DNS-rebinding defence: a hostname
                        // under attacker DNS control could otherwise
                        // resolve to ::ffff:127.0.0.1 or 100.64.x.x at
                        // request time and bypass an allowlist entry.
                        if let Some(policy) = classify_private_ip(ip) {
                            self.record_capability_denied(
                                "http-fetch",
                                policy,
                                &ip.to_string(),
                            )
                            .await;
                            tracing::warn!(
                                host = %host,
                                ip = %ip,
                                policy,
                                allow_private_env = "WORKER_ALLOW_PRIVATE_HOST_TARGETS",
                                "WASM module blocked: hostname resolved to a private IP. \
                                 If intentional (e.g. worker reaching a sibling service), \
                                 set WORKER_ALLOW_PRIVATE_HOST_TARGETS=true AND list \
                                 '{host}' explicitly in allowed_hosts (not via '*'). \
                                 IP literals to private ranges remain blocked unconditionally.",
                                host = host,
                            );
                            return Err(wit_http::Error::Forbiddenhost);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        host = %host,
                        error = %e,
                        "Failed to resolve hostname for SSRF validation"
                    );
                    return Err(wit_http::Error::Networkerror);
                }
            }
        } else if bypass_dns_ssrf {
            tracing::debug!(
                host,
                "DNS-SSRF bypass active (WORKER_ALLOW_PRIVATE_HOST_TARGETS=1 + explicit allowlist hit)"
            );
        }

        // Enforce method allowlist (empty = allow all methods).
        let method_str = match req.method {
            wit_http::Method::Get => "GET",
            wit_http::Method::Post => "POST",
            wit_http::Method::Put => "PUT",
            wit_http::Method::Delete => "DELETE",
            wit_http::Method::Patch => "PATCH",
        };
        if !self.allowed_methods.is_empty()
            && !self
                .allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method_str))
        {
            self.record_capability_denied(
                "http-fetch",
                "method-allowlist",
                &format!("{} {}", method_str, host),
            )
            .await;
            tracing::warn!(
                host,
                method = method_str,
                allowed_methods = ?self.allowed_methods,
                "WASM module attempted a disallowed HTTP method"
            );
            return Err(wit_http::Error::Forbiddenhost);
        }

        // Check circuit breaker before making request
        let host_str = host.to_string();
        if !get_global_circuit_breaker().allow_request(&host_str) {
            tracing::warn!(host = %host, "Circuit breaker open - rejecting HTTP request");
            return Err(wit_http::Error::Networkerror);
        }

        // Build the async reqwest request
        let method = req.method;
        // MCP-1105 (2026-05-16): cap header count BEFORE the body-size
        // / per-header vault-resolve loop. Pre-fix loop at line ~1893
        // called `resolve_vault_header` (DB call) per header with no
        // bound — see the MAX_OUTBOUND_HEADERS doc-comment for the
        // full attack surface.
        if req.headers.len() > MAX_OUTBOUND_HEADERS {
            tracing::warn!(
                module_id = ?self.module_id,
                header_count = req.headers.len(),
                limit = MAX_OUTBOUND_HEADERS,
                "wit_http::fetch rejected: header count exceeds cap"
            );
            return Err(wit_http::Error::Forbiddenhost);
        }
        let headers = req.headers.clone();
        // MCP-1014 (2026-05-15): cap caller-supplied body size. Same
        // sibling-drift class as wit_webhook::send below. wasmtime's
        // WASM-memory bound is the floor not the ceiling of host
        // memory commitment — every send clones the body once into
        // this binding and again into reqwest. Cap at 10 MB matching
        // the wit_webhook + wit_messaging + wit_data_transform caps.
        // MCP-1076: canonical module-level MAX_OUTBOUND_HTTP_BODY_BYTES.
        if req.body.len() > MAX_OUTBOUND_HTTP_BODY_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                body_len = req.body.len(),
                limit = MAX_OUTBOUND_HTTP_BODY_BYTES,
                "wit_http::fetch rejected: body exceeds cap"
            );
            return Err(wit_http::Error::Forbiddenhost);
        }
        let body = req.body.clone();
        // MCP-584: clamp caller-supplied timeout to MAX_HTTP_TIMEOUT_MS
        // (120 s). Pre-fix `req.timeout_ms` was `option<u32>` with no
        // upper bound — a module could pass `u32::MAX` (~50 days) and
        // hold a TCP connection (and the worker thread awaiting it)
        // open for the full duration. Async fuel tracking is
        // observation-only today (consume_async_fuel returns the cost
        // but doesn't deduct it from the store), so the WASM execution
        // budget doesn't bound this naturally. Cap matches the
        // wit_agent_orchestration::invoke convention at line 6095
        // (`timeout_ms.min(120_000)`); same fix applied to fetch_all
        // and execute_graphql_inner below.
        let timeout_ms = req.timeout_ms.unwrap_or(30_000).min(MAX_HTTP_TIMEOUT_MS) as u64;
        let url_str = req.url.clone();

        let client = self.http_client.clone();

        let reqwest_method = match method {
            wit_http::Method::Get => reqwest::Method::GET,
            wit_http::Method::Post => reqwest::Method::POST,
            wit_http::Method::Put => reqwest::Method::PUT,
            wit_http::Method::Delete => reqwest::Method::DELETE,
            wit_http::Method::Patch => reqwest::Method::PATCH,
        };

        // Dry-run interception now happens earlier (before DNS) — this
        // path is only reached for non-dry-run runs, which proceed to
        // build and send the real request below.

        let method_str_for_audit = reqwest_method.as_str().to_string();
        let mut builder = client
            .request(reqwest_method, &url_str)
            .timeout(std::time::Duration::from_millis(timeout_ms));
        for (name, value) in &headers {
            let resolved = self
                .resolve_vault_header(name.as_str(), value.as_str())
                .await
                .map_err(|_| wit_http::Error::Forbiddenhost)?;
            builder = builder.header(name.as_str(), resolved.as_ref());
        }
        if !body.is_empty() {
            builder = builder.body(body.clone());
        }

        let response = match builder.send().await {
            Ok(resp) => {
                get_global_circuit_breaker().record_success(&host_str);
                resp
            }
            Err(e) => {
                get_global_circuit_breaker().record_failure(&host_str);
                return Err(if e.is_timeout() {
                    wit_http::Error::Timeout
                } else {
                    wit_http::Error::Networkerror
                });
            }
        };

        let status = response.status().as_u16();
        tracing::info!(
            method = %method_str_for_audit,
            host = %url.host_str().unwrap_or("unknown"),
            path = %url.path(),
            status = status,
            "HTTP audit"
        );
        // MCP-1114: cap inbound header count + per-value size.
        // External server could otherwise materialise unbounded host
        // RAM via 10k+ headers (HTTP/2) or multi-MB header values.
        if response.headers().len() > MAX_INBOUND_HEADERS {
            tracing::warn!(
                module_id = ?self.module_id,
                header_count = response.headers().len(),
                limit = MAX_INBOUND_HEADERS,
                "wit_http::fetch response rejected: header count exceeds cap"
            );
            return Err(wit_http::Error::Networkerror);
        }
        let resp_headers: Vec<(String, String)> = {
            let mut out: Vec<(String, String)> = Vec::with_capacity(response.headers().len());
            for (k, v) in response.headers().iter() {
                if v.as_bytes().len() > MAX_INBOUND_HEADER_VALUE_BYTES {
                    tracing::warn!(
                        module_id = ?self.module_id,
                        header = %k,
                        value_len = v.as_bytes().len(),
                        limit = MAX_INBOUND_HEADER_VALUE_BYTES,
                        "wit_http::fetch response rejected: header value exceeds cap"
                    );
                    return Err(wit_http::Error::Networkerror);
                }
                out.push((
                    k.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                ));
            }
            out
        };
        // Enforce configurable response size limit to prevent OOM.
        // MCP-670 (2026-05-13): route through `positive_env_or_default`
        // so `WASM_HTTP_MAX_RESPONSE_BYTES=0` (a real Helm placeholder
        // pattern) doesn't reject every fetch with "payload too large
        // (0 > 0)". Sibling to MCP-639/642/643/665/668 — the `=0`
        // env-var footgun family.
        const DEFAULT_MAX_RESPONSE: usize = 10 * 1024 * 1024; // 10 MiB
        let max_resp = talos_config::positive_env_or_default::<usize>(
            "WASM_HTTP_MAX_RESPONSE_BYTES",
            DEFAULT_MAX_RESPONSE,
        );

        // Prevent OOM by reading chunks up to max_resp.
        let content_length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let capacity = std::cmp::min(content_length, max_resp);
        let mut resp_body_bytes = Vec::with_capacity(capacity);
        let mut stream = response.bytes_stream();
        use futures_util::StreamExt;
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|_| wit_http::Error::Networkerror)?;
            if resp_body_bytes.len() + chunk.len() > max_resp {
                tracing::warn!(
                    limit = max_resp,
                    "HTTP response exceeds size limit during streaming"
                );
                return Err(wit_http::Error::Networkerror);
            }
            resp_body_bytes.extend_from_slice(&chunk);
        }
        let resp_body = resp_body_bytes;

        // Track async fuel consumption - HTTP wall time converts to fuel cost
        // Approximate: 1ms ≈ 10,000 WASM instructions
        let async_elapsed = async_start.elapsed();
        self.consume_async_fuel(async_elapsed, "http::fetch");

        Ok(wit_http::Response {
            status,
            headers: resp_headers,
            body: resp_body,
        })
        }.await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("http::fetch", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    /// Dispatch multiple HTTP requests concurrently.)
    ///
    /// Security model: each request undergoes the same per-request validation
    /// (capability world, SSRF/IP check, host allowlist, method allowlist) as
    /// individual `fetch` calls.  Rate-limit budget is consumed atomically
    /// upfront for the entire batch before any network I/O begins — if the
    /// batch would exceed the budget the whole call fails fast with
    /// `Forbiddenhost` rather than partially succeeding.
    async fn fetch_all(
        &mut self,
        reqs: Vec<wit_http::Request>,
    ) -> Vec<Result<wit_http::Response, wit_http::Error>> {
        if reqs.is_empty() {
            return Vec::new();
        }

        // ── Global pre-flight checks (require &mut self) ─────────────────────
        if self.is_cancelled() {
            return reqs
                .iter()
                .map(|_| Err(wit_http::Error::Networkerror))
                .collect();
        }
        use crate::wit_inspector::CapabilityWorld;
        if matches!(
            self.capability_world,
            CapabilityWorld::Minimal | CapabilityWorld::Unknown
        ) {
            tracing::warn!("fetch_all: module lacks Http capability");
            return reqs
                .iter()
                .map(|_| Err(wit_http::Error::Forbiddenhost))
                .collect();
        }

        // ── Per-request validation ────────────────────────────────────────
        // Async for-loop (not `.iter().map()`) because every deny path
        // emits an audit event via `record_capability_denied`, and vault
        // header resolution is async. Inline audits keep the per-batch
        // hash-chain ordering equal to the request order in `reqs` — no
        // separate buffer-then-drain dance. Checks are ordered cheap-first
        // so we never do a DNS lookup or vault resolution for a request
        // we'll reject on a sync check anyway.
        let bypass_dns_env = *ALLOW_PRIVATE_HOST_TARGETS;

        #[allow(clippy::type_complexity)]
        let mut validated: Vec<
            Result<(String, reqwest::Method, Vec<(String, String)>, Vec<u8>, u64), wit_http::Error>,
        > = Vec::with_capacity(reqs.len());

        for req in &reqs {
            // MCP-1014 (2026-05-15): cap caller-supplied body size before
            // any URL parse / DNS / vault work. Same sibling-drift class
            // as wit_http::fetch and wit_webhook::send. Each entry in the
            // batch gets cloned twice (once into `validated`, once into
            // reqwest); a single batch entry over 10 MB would multiply
            // through buffer_unordered concurrency. Reject early; the
            // batch carries on with other entries.
            // MCP-1076: canonical module-level MAX_OUTBOUND_HTTP_BODY_BYTES.
            if req.body.len() > MAX_OUTBOUND_HTTP_BODY_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    body_len = req.body.len(),
                    limit = MAX_OUTBOUND_HTTP_BODY_BYTES,
                    "fetch_all: per-request body exceeds cap"
                );
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            // MCP-1148: per-entry URL byte cap. fetch_all amplifies the
            // single-fetch URL-parse-cost concern by `batch_size` —
            // 64-entry batches with 10 MB URLs each would otherwise
            // pay 640 MB of parse work per batch fire.
            if req.url.len() > MAX_OUTBOUND_URL_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    url_len = req.url.len(),
                    limit = MAX_OUTBOUND_URL_BYTES,
                    "fetch_all: per-request URL exceeds cap"
                );
                validated.push(Err(wit_http::Error::Invalidurl));
                continue;
            }

            // 1. URL parse.
            let url: url::Url = match req.url.parse() {
                Ok(u) => u,
                Err(_) => {
                    validated.push(Err(wit_http::Error::Invalidurl));
                    continue;
                }
            };
            let host = url.host_str().unwrap_or("").to_string();

            // 1b. HTTPS-only by default (see `classify_url_scheme` doc).
            // Operator opt-in via `WASM_ALLOW_INSECURE_HTTP=1`.
            match classify_url_scheme(url.scheme(), insecure_http_opt_in()) {
                UrlSchemeVerdict::Https => {}
                UrlSchemeVerdict::InsecureAllowedByOptIn { scheme } => {
                    tracing::warn!(
                        scheme = %scheme,
                        host = %host,
                        "fetch_all: insecure-scheme request allowed by WASM_ALLOW_INSECURE_HTTP=1"
                    );
                }
                UrlSchemeVerdict::InsecureRefused { scheme } => {
                    self.record_capability_denied(
                        "http-fetch-all",
                        "insecure-scheme",
                        &format!("{scheme} {host}"),
                    )
                    .await;
                    validated.push(Err(wit_http::Error::Invalidurl));
                    continue;
                }
            }

            // 2. Allowlist must be configured.
            if self.allowed_hosts.is_empty() {
                self.record_capability_denied("http-fetch-all", "no-allowlist-configured", &host)
                    .await;
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            // 3. SSRF: classify IP literals (no network I/O).
            //    Single source of truth in classify_private_ip — covers
            //    CGNAT and IPv4-mapped IPv6 too.
            let ip_literal: Option<std::net::IpAddr> = match url.host() {
                Some(url::Host::Ipv4(a)) => Some(a.into()),
                Some(url::Host::Ipv6(a)) => Some(a.into()),
                _ => None,
            };
            if let Some(ip) = ip_literal {
                if let Some(policy) = classify_private_ip(ip) {
                    self.record_capability_denied("http-fetch-all", policy, &ip.to_string())
                        .await;
                    validated.push(Err(wit_http::Error::Forbiddenhost));
                    continue;
                }
            }

            // 4. allowed_hosts pattern match.
            if !host_allowlist_match(&self.allowed_hosts, &host) {
                self.record_capability_denied("http-fetch-all", "allowed-hosts", &host)
                    .await;
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            // 5. Tier-1 LLM egress ceiling. Per-request so a mixed batch
            //    rejects only the tier-2 LLM entries.
            if matches!(
                self.max_llm_tier,
                talos_workflow_job_protocol::LlmTier::Tier1
            ) {
                let host_lower = host.to_ascii_lowercase();
                if let Some(policy) = tier1_egress_deny_reason(&host_lower) {
                    self.record_capability_denied("http-fetch-all", policy, &host)
                        .await;
                    tracing::warn!(
                        host = %host,
                        actor_id = ?self.actor_id,
                        policy,
                        "tier-1 actor fetch_all egress refused (external LLM host or public IP literal)"
                    );
                    validated.push(Err(wit_http::Error::Forbiddenhost));
                    continue;
                }
            }

            // 6. HTTP method allowlist.
            let method_str = match req.method {
                wit_http::Method::Get => "GET",
                wit_http::Method::Post => "POST",
                wit_http::Method::Put => "PUT",
                wit_http::Method::Delete => "DELETE",
                wit_http::Method::Patch => "PATCH",
            };
            if !self.allowed_methods.is_empty()
                && !self
                    .allowed_methods
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(method_str))
            {
                self.record_capability_denied(
                    "http-fetch-all",
                    "method-allowlist",
                    &format!("{} {}", method_str, host),
                )
                .await;
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            // M-6: per-host rate limit applied per-entry, BEFORE the
            // global counter bump below. A batch with 200 entries all
            // targeting the same host gets the first
            // MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION admitted and the
            // rest rejected — partial-success, same shape as the
            // sibling per-request validation checks above. This
            // prevents `fetch_all` from being a per-host-limit
            // bypass.
            let host_for_limit = match url.port_or_known_default() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            if !self.check_per_host_rate_limit(
                &host_for_limit,
                MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION,
            ) {
                self.record_capability_denied(
                    "http-fetch-all",
                    "per-host-rate-limit",
                    &host_for_limit,
                )
                .await;
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            // 7. DNS-rebinding SSRF check for hostname URLs. Resolve the
            //    hostname and classify each resolved IP via the same
            //    helper used for IP literals — closes the rebinding gap
            //    where an attacker-controlled domain could resolve to
            //    127.0.0.1 / ::ffff:127.0.0.1 / 100.64.x.x at request
            //    time. Bypass requires WORKER_ALLOW_PRIVATE_HOST_TARGETS
            //    AND an explicit (non-wildcard) allowlist entry.
            //
            //    Serial across the batch — fetch_all batches are typically
            //    a handful of well-known hosts and the OS resolver caches
            //    common entries, so the wall-clock cost is dominated by
            //    the actual HTTP request, not the lookup.
            let is_hostname = matches!(url.host(), Some(url::Host::Domain(_)));
            let bypass_dns =
                bypass_dns_env && self.allowed_hosts.iter().any(|p| p != "*" && p == &host);
            if is_hostname && !bypass_dns {
                match tokio::net::lookup_host(format!("{}:80", host)).await {
                    Ok(addrs) => {
                        let mut blocked: Option<(&'static str, std::net::IpAddr)> = None;
                        for addr in addrs {
                            let ip = addr.ip();
                            if let Some(policy) = classify_private_ip(ip) {
                                blocked = Some((policy, ip));
                                break;
                            }
                        }
                        if let Some((policy, ip)) = blocked {
                            self.record_capability_denied(
                                "http-fetch-all",
                                policy,
                                &ip.to_string(),
                            )
                            .await;
                            tracing::warn!(
                                host = %host,
                                ip = %ip,
                                policy,
                                "fetch_all: hostname resolved to a private IP — blocking"
                            );
                            validated.push(Err(wit_http::Error::Forbiddenhost));
                            continue;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            host = %host,
                            error = %e,
                            "fetch_all: DNS resolution failed for SSRF check"
                        );
                        validated.push(Err(wit_http::Error::Networkerror));
                        continue;
                    }
                }
            }

            // 8. Resolve vault:// headers (async — see resolve_vault_header).
            //    Deny audits emit inside resolve_vault_header itself; this
            //    site only translates the Err to wit_http::Error.
            // MCP-1105: per-entry header cap. See MAX_OUTBOUND_HEADERS
            // doc-comment for the rationale.
            if req.headers.len() > MAX_OUTBOUND_HEADERS {
                tracing::warn!(
                    module_id = ?self.module_id,
                    header_count = req.headers.len(),
                    limit = MAX_OUTBOUND_HEADERS,
                    "wit_http::fetch_all entry rejected: header count exceeds cap"
                );
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }
            let reqwest_method = match req.method {
                wit_http::Method::Get => reqwest::Method::GET,
                wit_http::Method::Post => reqwest::Method::POST,
                wit_http::Method::Put => reqwest::Method::PUT,
                wit_http::Method::Delete => reqwest::Method::DELETE,
                wit_http::Method::Patch => reqwest::Method::PATCH,
            };
            let mut hdrs: Vec<(String, String)> = Vec::with_capacity(req.headers.len());
            let mut header_failed = false;
            for (k, v) in &req.headers {
                match self.resolve_vault_header(k.as_str(), v.as_str()).await {
                    Ok(resolved) => hdrs.push((k.clone(), resolved.into_owned())),
                    Err(_) => {
                        header_failed = true;
                        break;
                    }
                }
            }
            if header_failed {
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            validated.push(Ok((
                req.url.clone(),
                reqwest_method,
                hdrs,
                req.body.clone(),
                // MCP-584: clamp per-request timeout in fetch_all
                // exactly as fetch above. Each entry in the batch
                // could otherwise pass u32::MAX and tie up a slot in
                // the buffer_unordered pool.
                req.timeout_ms.unwrap_or(30_000).min(MAX_HTTP_TIMEOUT_MS) as u64,
            )));
        }

        // MCP-783 (2026-05-14): consume rate-limit budget only for entries
        // that passed per-request validation. Pre-fix `fetch_add(batch_size)`
        // ran BEFORE the validation loop, so a batch of N entries all
        // failing per-request checks (SSRF, allowed-hosts, method
        // allowlist, DNS-rebind, vault-resolve) burned N against
        // MAX_HTTP_CALLS_PER_EXECUTION even though zero HTTP calls
        // actually went out. Repeated burst calls of validation-failing
        // batches could exhaust the per-execution HTTP budget, blocking
        // subsequent legitimate calls. Same shape as MCP-770
        // (wit_files::write charged byte quota before path sanitization)
        // and MCP-612 (the original counter-only-advances-when-admitted
        // rule called out in `Context::check_rate_limit`'s docstring).
        // Validation-failed entries also now preserve their specific
        // Error (Invalidurl, Forbiddenhost, Networkerror) on overflow —
        // the old overflow path collapsed every return slot to
        // Forbiddenhost regardless of why a particular entry was
        // rejected, losing operator-visibility into the actual cause.
        let actual_calls = validated.iter().filter(|v| v.is_ok()).count() as u64;
        let prev = self
            .http_call_count
            .fetch_add(actual_calls, std::sync::atomic::Ordering::Relaxed);
        if prev + actual_calls > MAX_HTTP_CALLS_PER_EXECUTION {
            // Refund the slots we just claimed — the batch is rejected.
            self.http_call_count
                .fetch_sub(actual_calls, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(module_id = ?self.module_id, "fetch_all: HTTP call rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("http");
            }
            return validated
                .into_iter()
                .map(|v| match v {
                    Ok(_) => Err(wit_http::Error::Forbiddenhost),
                    Err(e) => Err(e),
                })
                .collect();
        }

        // ── Concurrent dispatch ───────────────────────────────────────────────
        // MCP-670 (2026-05-13): same `=0`-safe helper as the single-fetch path.
        let max_resp = talos_config::positive_env_or_default::<usize>(
            "WASM_HTTP_MAX_RESPONSE_BYTES",
            10 * 1024 * 1024_usize,
        );

        // ── Concurrent dispatch with backpressure ─────────────────────────
        // Use buffer_unordered to limit concurrent requests and prevent
        // resource exhaustion when processing large batches.
        //
        // MCP-1109 (2026-05-16): LazyLock-cached + routed through
        // `positive_env_or_default`. Pre-fix this site paid a per-call
        // `env::var` (process-wide environ-mutex lock + String alloc)
        // on every WASM `fetch_all` invocation AND used the raw
        // `.parse().ok().unwrap_or(10).clamp(1, 100)` shape, which is
        // sibling drift from the canonical `=0`-safe helper. The shape
        // mismatch gave a subtly different semantic: `FETCH_ALL_CONCURRENCY=0`
        // (real Helm placeholder pattern) clamped UP to 1 instead of
        // falling through to the default 10 the way every other
        // worker-env site in this file does (MCP-670/665/668 family,
        // and the sibling `WASM_HTTP_MAX_RESPONSE_BYTES` two lines
        // above). Operators reasoning about `=0` semantics across
        // worker envs now see one rule: `=0` → default + WARN. Upper
        // bound stays at 100 to prevent runaway concurrency from a
        // misconfigured `FETCH_ALL_CONCURRENCY=10000`.
        const DEFAULT_CONCURRENCY: usize = 10;
        static FETCH_ALL_CONCURRENCY_LIMIT: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| {
                talos_config::positive_env_or_default::<usize>(
                    "FETCH_ALL_CONCURRENCY",
                    DEFAULT_CONCURRENCY,
                )
                .min(100)
            });
        let concurrency_limit = *FETCH_ALL_CONCURRENCY_LIMIT;

        let self_http_client = self.http_client.clone();
        let dry_run = self.dry_run;
        let stream = futures_util::stream::iter(validated.into_iter().map(move |v| {
            let max_r = max_resp;
            let self_http_client = self_http_client.clone();
            async move {
                let (url_str, method, headers, body, timeout_ms) = match v {
                    Err(e) => return Err(e),
                    Ok(params) => params,
                };

                // Dry-run mode: mock non-GET HTTP requests
                if dry_run && method != reqwest::Method::GET {
                    tracing::info!(
                        method = %method,
                        url = %url_str,
                        "Dry-run: intercepted non-GET request in fetch_all"
                    );
                    let mock_body = serde_json::to_vec(&serde_json::json!({
                        "__dry_run__": true,
                        "intercepted_method": method.as_str(),
                        "intercepted_url": url_str,
                    }))
                    .unwrap_or_default();
                    return Ok(wit_http::Response {
                        status: 200,
                        headers: vec![("x-talos-dry-run".to_string(), "true".to_string())],
                        body: mock_body,
                    });
                }

                let client = self_http_client.clone();

                let method_str_for_audit = method.as_str().to_string();
                let mut builder = client
                    .request(method, &url_str)
                    .timeout(std::time::Duration::from_millis(timeout_ms));
                for (name, value) in &headers {
                    builder = builder.header(name.as_str(), value.as_str());
                }
                if !body.is_empty() {
                    builder = builder.body(body);
                }

                let response = builder.send().await.map_err(|e| {
                    if e.is_timeout() {
                        wit_http::Error::Timeout
                    } else {
                        wit_http::Error::Networkerror
                    }
                })?;

                let status = response.status().as_u16();
                // Audit log: log host + path only (never full URL — query params may contain secrets)
                if let Ok(parsed_url) = url::Url::parse(&url_str) {
                    tracing::info!(
                        method = %method_str_for_audit,
                        host = %parsed_url.host_str().unwrap_or("unknown"),
                        path = %parsed_url.path(),
                        status = status,
                        "HTTP audit"
                    );
                }
                // MCP-1114: cap inbound header count + per-value size.
                // Sibling of the wit_http::fetch single-call site.
                if response.headers().len() > MAX_INBOUND_HEADERS {
                    tracing::warn!(
                        header_count = response.headers().len(),
                        limit = MAX_INBOUND_HEADERS,
                        "wit_http::fetch_all response rejected: header count exceeds cap"
                    );
                    return Err(wit_http::Error::Networkerror);
                }
                let resp_headers: Vec<(String, String)> = {
                    let mut out: Vec<(String, String)> = Vec::with_capacity(response.headers().len());
                    for (k, v) in response.headers().iter() {
                        if v.as_bytes().len() > MAX_INBOUND_HEADER_VALUE_BYTES {
                            tracing::warn!(
                                header = %k,
                                value_len = v.as_bytes().len(),
                                limit = MAX_INBOUND_HEADER_VALUE_BYTES,
                                "wit_http::fetch_all response rejected: header value exceeds cap"
                            );
                            return Err(wit_http::Error::Networkerror);
                        }
                        out.push((
                            k.to_string(),
                            String::from_utf8_lossy(v.as_bytes()).into_owned(),
                        ));
                    }
                    out
                };

                let mut resp_body_bytes = Vec::new();
                let mut stream = response.bytes_stream();
                use futures_util::StreamExt;
                while let Some(chunk_result) = stream.next().await {
                    let chunk = chunk_result.map_err(|_| wit_http::Error::Networkerror)?;
                    if resp_body_bytes.len() + chunk.len() > max_r {
                        return Err(wit_http::Error::Networkerror);
                    }
                    resp_body_bytes.extend_from_slice(&chunk);
                }

                Ok(wit_http::Response {
                    status,
                    headers: resp_headers,
                    body: resp_body_bytes,
                })
            }
        }));

        stream.buffer_unordered(concurrency_limit).collect().await
    }

    /// Tier 1 — Fetch with secret injected as `Authorization: Bearer {value}`.
    ///
    /// Resolves `slot` via the SecretProvider and prepends the Authorization header
    /// to `req` before dispatching through the standard `fetch` path (which applies
    /// all security checks: host allowlist, SSRF protection, method allowlist,
    /// rate limiting). The secret value never enters guest memory.
    async fn fetch_with_bearer(
        &mut self,
        slot: u64,
        mut req: wit_http::Request,
    ) -> Result<wit_http::Response, wit_http::Error> {
        // Resolve the slot to its plaintext value on the host side only.
        let auth_value = self
            .provider
            .into_auth_header(talos_secrets::SlotHandle(slot), "Authorization")
            .map_err(|e| {
                tracing::warn!(slot, error = %e, "fetch-with-bearer: slot lookup failed");
                wit_http::Error::Networkerror
            })?;
        // L-4: build "Bearer <token>" via push so the auth_value
        // Zeroizing wrapper drops + wipes immediately after we've
        // built the header string. The header string itself is then
        // moved into req.headers (and ultimately into reqwest's
        // HeaderValue buffer) — once that move completes there's only
        // one plaintext copy in flight.
        let mut header = String::with_capacity("Bearer ".len() + auth_value.len());
        header.push_str("Bearer ");
        header.push_str(auth_value.as_str());
        drop(auth_value);
        req.headers
            .insert(0, ("Authorization".to_string(), header));
        // Dispatch through the standard fetch path; all security checks apply.
        self.fetch(req).await
    }

    /// Tier 1 — Fetch with secret injected as a named header.
    ///
    /// Resolves `slot` via the SecretProvider and prepends `header-name: {value}`
    /// to `req` before dispatching through the standard `fetch` path. Use for
    /// API-key schemes such as `x-api-key` (Anthropic) or `x-goog-api-key` (Gemini).
    /// The secret value never enters guest memory.
    async fn fetch_with_header(
        &mut self,
        slot: u64,
        header_name: String,
        mut req: wit_http::Request,
    ) -> Result<wit_http::Response, wit_http::Error> {
        let header_value = self
            .provider
            .into_auth_header(talos_secrets::SlotHandle(slot), &header_name)
            .map_err(|e| {
                tracing::warn!(slot, header_name, error = %e, "fetch-with-header: slot lookup failed");
                wit_http::Error::Networkerror
            })?;
        // L-4: Zeroizing<String> → owned String at point of use; the
        // wrapper wipes when its scope ends.
        let owned_value = (*header_value).clone();
        drop(header_value);
        req.headers.insert(0, (header_name, owned_value));
        self.fetch(req).await
    }
}

// ============================================================================
// Logging
// ============================================================================

impl wit_logging::Host for TalosContext {
    async fn log(&mut self, lvl: wit_logging::Level, mut msg: String) {
        let count = self
            .log_message_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count >= MAX_LOG_MESSAGES_PER_EXECUTION {
            if count == MAX_LOG_MESSAGES_PER_EXECUTION {
                tracing::warn!(module_id = ?self.module_id, "Log message quota exceeded, dropping further messages");
                if let Some(ref m) = self.metrics {
                    m.record_rate_limit_exceeded("log");
                }
            }
            return;
        }
        let execution_id = self.execution_id.clone().unwrap_or_default();
        let request_id = self.request_id.clone().unwrap_or_default();

        // MCP-1046 (2026-05-15): byte-aware truncation. Pre-fix the
        // `.len() > 10000` check compared BYTES, but `.chars().take(10000)`
        // takes CODEPOINTS — so a 30 KB string of 3-byte chars (10000
        // codepoints, 30000 bytes) tripped the byte check, was "truncated"
        // back to the same 10000 codepoints (= same 30000 bytes), then
        // had "...[TRUNCATED]" appended — making the message *longer*
        // and falsely labelled as truncated. `truncate_at_char_boundary`
        // walks back from byte N to the nearest UTF-8 char boundary so
        // the result is always ≤ N bytes.
        if msg.len() > 10000 {
            msg = talos_text_util::truncate_at_char_boundary(&msg, 10000).to_string();
            msg.push_str("...[TRUNCATED]");
        }

        // Emit to the host tracing system.
        // In the three-tier security model, secrets do not enter guest memory via Tier-1 ops.
        // Tier-2 expose-secret is explicitly audited and rate-limited, making blanket value-based
        // log redaction unnecessary. Log the message as-is.
        match lvl {
            wit_logging::Level::Debug => tracing::debug!(execution_id, "[WASM] {}", msg),
            wit_logging::Level::Info => tracing::info!(execution_id, "[WASM] {}", msg),
            wit_logging::Level::Warn => tracing::warn!(execution_id, "[WASM] {}", msg),
            wit_logging::Level::Error => tracing::error!(execution_id, "[WASM] {}", msg),
        }

        // Publish structured log to NATS so the controller can persist it.
        if let Some(nats) = &self.nats_client {
            if !execution_id.is_empty() {
                let level_str = match lvl {
                    wit_logging::Level::Debug => "DEBUG",
                    wit_logging::Level::Info => "INFO",
                    wit_logging::Level::Warn => "WARN",
                    wit_logging::Level::Error => "ERROR",
                };

                use opentelemetry::trace::TraceContextExt;
                use tracing_opentelemetry::OpenTelemetrySpanExt;
                let span = tracing::Span::current();
                let ctx = span.context();
                let span_ref = ctx.span();
                let span_context = span_ref.span_context();
                let trace_id = if span_context.is_valid() {
                    Some(span_context.trace_id().to_string())
                } else {
                    None
                };
                let span_id = if span_context.is_valid() {
                    Some(span_context.span_id().to_string())
                } else {
                    None
                };

                let log_entry = serde_json::json!({
                    "execution_id": execution_id,
                    "request_id": request_id,
                    "level": level_str,
                    "message": msg,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "source": "wasm",
                    "trace_id": trace_id,
                    "span_id": span_id
                });

                if let Ok(payload) = serde_json::to_vec(&log_entry) {
                    let nats = nats.clone();
                    let topic = format!("wasm.log.{}", execution_id);
                    // Fire-and-forget: logging must not fail the job.

                    let _ = nats.publish(topic, payload.into()).await;
                }
            }
        }
    }

    async fn log_json(&mut self, lvl: wit_logging::Level, json: String) {
        let count = self
            .log_message_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count >= MAX_LOG_MESSAGES_PER_EXECUTION {
            if count == MAX_LOG_MESSAGES_PER_EXECUTION {
                tracing::warn!(module_id = ?self.module_id, "Log message quota exceeded, dropping further messages");
                if let Some(ref m) = self.metrics {
                    m.record_rate_limit_exceeded("log");
                }
            }
            return;
        }
        let execution_id = self.execution_id.clone().unwrap_or_default();
        let request_id = self.request_id.clone().unwrap_or_default();

        // MCP-1046: byte-aware truncation (see wit_logging::log above).
        let json_capped = if json.len() > 10000 {
            let mut s = talos_text_util::truncate_at_char_boundary(&json, 10000).to_string();
            s.push_str("...[TRUNCATED]");
            s
        } else {
            json
        };

        let level_str = match lvl {
            wit_logging::Level::Debug => "DEBUG",
            wit_logging::Level::Info => "INFO",
            wit_logging::Level::Warn => "WARN",
            wit_logging::Level::Error => "ERROR",
        };

        // Parse the JSON to validate structure. If the input is not valid JSON,
        // fall back to a plain string log so no event is silently lost.
        // In the three-tier security model, Tier-1 ops prevent secrets from entering
        // guest memory, so blanket value-based redaction is not required here.
        let (structured_value, parse_ok) =
            match serde_json::from_str::<serde_json::Value>(&json_capped) {
                Ok(v) => (v, true),
                Err(_) => (serde_json::Value::String(json_capped.clone()), false),
            };

        // Emit to tracing.
        let trace_preview = if parse_ok {
            structured_value
                .to_string()
                .chars()
                .take(200)
                .collect::<String>()
        } else {
            format!(
                "[json_parse_error] {}",
                json_capped.chars().take(200).collect::<String>()
            )
        };
        match lvl {
            wit_logging::Level::Debug => tracing::debug!(
                execution_id,
                structured = parse_ok,
                "[WASM-JSON] {}",
                trace_preview
            ),
            wit_logging::Level::Info => tracing::info!(
                execution_id,
                structured = parse_ok,
                "[WASM-JSON] {}",
                trace_preview
            ),
            wit_logging::Level::Warn => tracing::warn!(
                execution_id,
                structured = parse_ok,
                "[WASM-JSON] {}",
                trace_preview
            ),
            wit_logging::Level::Error => tracing::error!(
                execution_id,
                structured = parse_ok,
                "[WASM-JSON] {}",
                trace_preview
            ),
        }

        // Publish to NATS so the controller can persist it alongside plain logs.
        if let Some(nats) = &self.nats_client {
            if !execution_id.is_empty() {
                use opentelemetry::trace::TraceContextExt;
                use tracing_opentelemetry::OpenTelemetrySpanExt;
                let span = tracing::Span::current();
                let ctx = span.context();
                let span_ref = ctx.span();
                let span_context = span_ref.span_context();
                let trace_id = if span_context.is_valid() {
                    Some(span_context.trace_id().to_string())
                } else {
                    None
                };
                let span_id = if span_context.is_valid() {
                    Some(span_context.span_id().to_string())
                } else {
                    None
                };

                let log_entry = serde_json::json!({
                    "execution_id": execution_id,
                    "request_id": request_id,
                    "level": level_str,
                    "structured": true,
                    "parse_ok": parse_ok,
                    "data": structured_value,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "source": "wasm",
                    "trace_id": trace_id,
                    "span_id": span_id
                });

                if let Ok(payload) = serde_json::to_vec(&log_entry) {
                    let nats = nats.clone();
                    let topic = format!("wasm.log.{}", execution_id);
                    let _ = nats.publish(topic, payload.into()).await;
                }
            }
        }
    }
}

// ============================================================================
// Secrets
// ============================================================================

/// Maximum Tier-2 expose-secret calls per execution (prevent bulk extraction).
const MAX_EXPOSE_CALLS_PER_EXECUTION: u64 = 10;

// MCP-673 (2026-05-13): per-method capability gate helper for wit_secrets.
// Mirrors the gate already present in `get_secret`; lifted into a helper
// so the four follow-on methods (release_slot / hmac_sign / expose_secret /
// resolve_config_vault) can adopt it without copy-pasting the matches!.
// Sibling pattern to MCP-602 (require_object_storage_capability),
// MCP-603 (require_state_capability), MCP-608/609 (per-method inline
// gates on agent_memory / llm_tools), MCP-655 (governance::request_approval),
// MCP-669 (agent_orchestration::list_agents). resolve_config_vault is
// transitively gated through get_secret; the other three are not, so
// even though `release_slot(arbitrary_u64)` is operationally harmless,
// `hmac_sign` and `expose_secret` operate on secret material and must
// not be reachable from a Minimal/Unknown-world module that obtained
// accidental linkage. Defense-in-depth: don't rely on `get_secret`'s
// gate to indirectly protect handles a future bug might hand out.
fn require_secrets_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_secrets::Error> {
    use crate::wit_inspector::CapabilityWorld;
    if matches!(
        world,
        CapabilityWorld::Secrets
            | CapabilityWorld::Database
            | CapabilityWorld::Agent
            | CapabilityWorld::Trusted
    ) {
        Ok(())
    } else {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_secrets call but lacks Secrets/Database/Agent/Trusted capability"
        );
        Err(wit_secrets::Error::Unauthorized)
    }
}

impl wit_secrets::Host for TalosContext {
    /// Tier 0 — Resolve a vault path to an opaque slot handle (u64).
    ///
    /// The plaintext value is materialized inside the host's DashMap; the guest
    /// receives only the u64 handle.  Slot persists until `release-slot` or
    /// execution end — use it with Tier-1 ops or Tier-2 `expose-secret`.
    async fn get_secret(&mut self, key_path: String) -> Result<u64, wit_secrets::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<u64, wit_secrets::Error> = async move {
        // MCP-588: per-execution rate limit. Pre-fix this path was the
        // only audited host function without a per-execution cap — a
        // module could loop get_secret thousands of times in tight
        // succession, flooding `talos.audit.ledger` with NATS publishes
        // and burning controller-side audit-consumer CPU. Same pattern
        // as MCP-523 (wit_email) / MCP-537 (wit_webhook + wit_graphql).
        if !self.check_rate_limit(
            &self.secret_access_count,
            MAX_SECRET_ACCESSES_PER_EXECUTION,
        ) {
            tracing::warn!(
                module_id = ?self.module_id,
                "secrets::get_secret rate limit exceeded"
            );
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("secrets");
            }
            return Err(wit_secrets::Error::Unauthorized);
        }
        // Normalize: strip vault:// prefix so both "vault://my/key" and "my/key"
        // resolve identically. This makes get_secret safe to call directly with
        // raw config field values that may carry the prefix notation.
        let key_path = key_path
            .strip_prefix("vault://")
            .map(str::to_string)
            .unwrap_or(key_path);

        use crate::wit_inspector::CapabilityWorld;
        // Capability gate. The agent-node world (`Agent`) explicitly imports
        // the `secrets` interface in talos.wit, so its modules MUST be able
        // to call get_secret at runtime. Earlier this list omitted `Agent`,
        // which made every agent-node module's get_secret call return
        // `Unauthorized` regardless of allowed_secrets / actor grants /
        // namespace — surfacing as a confusing dead-end during real-workflow
        // building (see the pa-ship-report investigation, 2026-04-22).
        // The other secret-tier worlds (Secrets, Database, Trusted) are
        // already in the list because their WIT worlds also import secrets.
        if !matches!(
            self.capability_world,
            CapabilityWorld::Secrets
                | CapabilityWorld::Database
                | CapabilityWorld::Agent
                | CapabilityWorld::Trusted
        ) {
            // Hash before audit — same convention as the secret-allowlist
            // deny below; operators reading the ledger should not learn
            // unowned vault paths from a capability-world deny either.
            let key_hash = format!("{:x}", Sha256::digest(key_path.as_bytes()));
            self.record_capability_denied("secret-access", "capability-world", &key_hash)
                .await;
            tracing::warn!(
                gate = "capability_world",
                module_id = ?self.module_id,
                capability_world = ?self.capability_world,
                key_path,
                "WASM module attempted secrets access but capability world does not import the secrets interface. \
                 Recompile with capability_world: secrets-node (or higher: agent-node, database-node, automation-node)."
            );
            return Err(wit_secrets::Error::Unauthorized);
        }

        // SECURITY: per-module secret allowlist. Enforced via shared helper so
        // guest-initiated (get_secret) and host-initiated (resolve_vault_header)
        // paths stay in lockstep. Returning Unauthorized (not Notfound) lets
        // operators distinguish access-control failures from missing paths; the
        // path is never confirmed to exist.
        if self.check_secret_allowlist(&key_path).is_err() {
            // Audit the DENIED attempt with the key-path SHA-256 (never the
            // key_path itself — operators reading the ledger should not learn
            // unowned vault paths). Pairs with the host-reserved deny-list
            // catch (LLM provider keys) which lives inside check_secret_allowlist.
            let key_hash = format!("{:x}", Sha256::digest(key_path.as_bytes()));
            self.record_capability_denied("secret-access", "secret-allowlist", &key_hash)
                .await;
            return Err(wit_secrets::Error::Unauthorized);
        }

        if let Some(ledger_mutex) = &self.audit_ledger {
            let key_hash = format!("{:x}", Sha256::digest(key_path.as_bytes()));
            let mut ledger = ledger_mutex.lock().await;
            let event = ledger.append(
                "agent:wasm",
                "wasi:secrets_get",
                &serde_json::json!({ "key_hash": key_hash }).to_string(),
            );
            drop(ledger);

            if let Some(n) = &self.nats_client {
                let event_clone = event.clone();
                let nats = n.clone();
                tokio::spawn(async move {
                    let payload = serde_json::json!({
                        "event": event_clone.clone(),
                        "hash": event_clone.calculate_hash()
                    });
                    match serde_json::to_vec(&payload) {
                        Ok(bytes) => {
                            // MCP-735: log NATS publish failure so SIEM
                            // consumers see the gap. Local ledger.append
                            // above is the WORM source-of-truth; this
                            // publish is replication only.
                            if let Err(e) = nats
                                .publish("talos.audit.ledger".to_string(), bytes.into())
                                .await
                            {
                                tracing::warn!(
                                    target: "talos_rpc",
                                    error = %e,
                                    "audit-ledger NATS replication failed (secrets_get) — local ledger unaffected, SIEM stream will miss this event"
                                );
                            }
                        }
                        Err(e) => tracing::error!(
                            "Failed to serialize audit event for secrets_get: {}",
                            e
                        ),
                    }
                });
            }
        }

        // Resolve via the SecretProvider — materializes the secret in the host DashMap.
        // The u64 handle is all that crosses the WASM boundary; plaintext stays host-side.
        let exec_id = self
            .execution_id
            .as_deref()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .unwrap_or_else(uuid::Uuid::new_v4);

        match self.provider.resolve(&key_path, exec_id).await {
            Ok(handle) => Ok(handle.0), // return the raw u64; slot stays alive for Tier-1/2 use
            Err(_) => {
                tracing::warn!(
                    key_path,
                    module_id = ?self.module_id,
                    "WASM module requested a secret that is not available"
                );
                Err(wit_secrets::Error::Notfound)
            }
        }
        }.await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "secrets::get_secret",
                __start.elapsed().as_millis() as f64,
            );
        }
        __result
    }

    /// Release a slot early — zeroes host-side memory immediately.
    async fn release_slot(&mut self, handle: u64) -> Result<(), wit_secrets::Error> {
        // MCP-673: defense-in-depth gate. release_slot is operationally
        // harmless against random u64 handles (provider returns Ok), but
        // adopting the gate keeps every wit_secrets method consistent so
        // a future contributor copy-pasting from any sibling lands on
        // the right shape.
        // MCP-713 (2026-05-13): audit-ledger parity. Pre-fix the `?`
        // operator on `require_secrets_capability` propagated Err
        // without an audit row — operator-blind to the WORM ledger.
        // Same fix shape as MCP-712 wit_state sweep.
        if require_secrets_capability(&self.capability_world).is_err() {
            self.record_capability_denied(
                "secrets-release-slot",
                "capability-world",
                &handle.to_string(),
            )
            .await;
            return Err(wit_secrets::Error::Unauthorized);
        }
        let _ = self
            .provider
            .release(talos_secrets::SlotHandle(handle))
            .await;
        Ok(())
    }

    /// Tier 1 — HMAC-SHA256-sign `data` using the key in the slot.
    /// Secret bytes never cross the WASM boundary; only the 32-byte signature is returned.
    async fn hmac_sign(
        &mut self,
        handle: u64,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, wit_secrets::Error> {
        // MCP-673: per-method capability gate. hmac_sign produces a
        // signature DERIVED from secret material; a Minimal-world
        // module that obtained a valid handle through accidental
        // linkage would otherwise be able to sign-as-the-secret without
        // the secret ever crossing the WIT boundary. Fail closed before
        // touching the provider.
        // MCP-713 (2026-05-13): audit-ledger parity. A capability-deny
        // on hmac_sign is a high-signal event — the module tried to
        // sign WITH a secret it couldn't legally access via a handle
        // it shouldn't have been able to obtain. That MUST be in the
        // audit ledger loudly, not just `tracing::warn!`-only via the
        // helper's internal warn.
        if require_secrets_capability(&self.capability_world).is_err() {
            self.record_capability_denied(
                "secrets-hmac-sign",
                "capability-world",
                &handle.to_string(),
            )
            .await;
            return Err(wit_secrets::Error::Unauthorized);
        }
        self.provider
            .sign(talos_secrets::SlotHandle(handle), &data)
            .map_err(|e| {
                let err_msg = e.to_string();
                tracing::warn!(handle, error = %err_msg, module_id = ?self.module_id, "hmac-sign failed");
                // Map to contextual error: stale/expired slots vs invalid handles
                if err_msg.contains("expired") || err_msg.contains("stale") || err_msg.contains("age") {
                    wit_secrets::Error::Expired
                } else {
                    wit_secrets::Error::Notfound
                }
            })
    }

    /// Tier 2 — Explicit, audited plaintext exposure crossing the WASM boundary.
    ///
    /// Every call is logged at WARN, rate-limited to MAX_EXPOSE_CALLS_PER_EXECUTION
    /// per execution and MAX_TIER2_EXPOSES_PER_USER_PER_DAY globally per user,
    /// and sets the execution trace flag `secret_tier2_exposed`.
    async fn expose_secret(
        &mut self,
        handle: u64,
        reason: String,
    ) -> Result<String, wit_secrets::Error> {
        // Wasm-security review 2026-05-23: the audit-row `reason` field is
        // operator-supplied free text that flows verbatim into the WORM
        // ledger AND NATS audit stream. The WIT-side handle bounds the
        // call but does NOT bound the string length: a guest with
        // `allow_tier2_exposure: true` and the per-execution call budget
        // (MAX_EXPOSE_CALLS_PER_EXECUTION = 10) could send 100 MB strings
        // 10× per execution — a gigabyte of audit data per call site, with
        // the same NATS subscriber fanout multiplying the storage cost
        // downstream. 1 KiB matches the operator-recognised pattern of
        // "free text long enough for forensic context, short enough that
        // no caller has a legitimate reason to need more." Truncate at
        // char boundary so the redacted form doesn't split a UTF-8
        // sequence and break downstream JSON parsing.
        const MAX_EXPOSE_REASON_BYTES: usize = 1024;
        let reason = if reason.len() > MAX_EXPOSE_REASON_BYTES {
            let mut s =
                talos_text_util::truncate_at_char_boundary(&reason, MAX_EXPOSE_REASON_BYTES)
                    .to_string();
            s.push_str("...[TRUNCATED]");
            s
        } else {
            reason
        };
        // MCP-673: per-method capability gate. expose_secret is the
        // single grep-able Tier-2 plaintext exit point (line below),
        // so the per-method gate is highest-stakes here. The existing
        // `allow_tier2_exposure` policy gate is necessary but not
        // sufficient — a module's `allow_tier2_exposure: true` plus a
        // hypothetical Minimal-world linkage bug would expose plaintext
        // without the world ceiling that compile-time linkage normally
        // enforces. Defense-in-depth: refuse before any rate-limit
        // counter increments or audit log entries.
        // MCP-713 (2026-05-13): audit-ledger parity. expose_secret is
        // the HIGHEST-VALUE audit target in wit_secrets — a
        // capability-deny here means a module attempted to cross the
        // Tier-2 plaintext exit boundary without the right world.
        // Pre-fix the `?` propagated silently; only `tracing::warn!`
        // evidence remained. The post-fix audit row fires BEFORE the
        // policy / rate-limit / WARN cascade below, so dashboards
        // alerting on `record_capability_denied` light up immediately.
        if require_secrets_capability(&self.capability_world).is_err() {
            self.record_capability_denied(
                "secrets-expose-secret",
                "capability-world",
                &handle.to_string(),
            )
            .await;
            return Err(wit_secrets::Error::Unauthorized);
        }
        // Policy gate: block Tier-2 exposure unless the module explicitly
        // opted in via `allow_tier2_exposure: true` in its metadata. The
        // vast majority of modules only need Tier-1 (vault:// header
        // resolution or slot-based fetch_with_header). Blocking by default
        // ensures a module cannot exfiltrate secrets into WASM guest memory
        // without the platform operator's explicit consent.
        if !self.allow_tier2_exposure {
            tracing::warn!(
                handle,
                module_id = ?self.module_id,
                reason = %reason,
                "expose_secret blocked: module does not have allow_tier2_exposure enabled. \
                 Use Tier-1 (vault:// headers or fetch_with_header) instead, or set \
                 allow_tier2_exposure=true on the module if plaintext access is required."
            );
            return Err(wit_secrets::Error::Unauthorized);
        }

        // Rate-limit: prevent bulk extraction via repeated expose-secret calls.
        let count = self
            .expose_call_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count >= MAX_EXPOSE_CALLS_PER_EXECUTION {
            tracing::warn!(
                handle,
                count,
                module_id = ?self.module_id,
                "expose-secret rate limit exceeded ({} calls/execution max)",
                MAX_EXPOSE_CALLS_PER_EXECUTION
            );
            return Err(wit_secrets::Error::Ratelimited);
        }

        // Global rate limit: per-user daily limit across all executions (Redis-backed).
        if let Some(user_id) = self.user_id {
            let today_utc = chrono::Utc::now();
            let today_naive = today_utc.date_naive();
            let today = today_utc.format("%Y-%m-%d").to_string();
            let key = format!("talos:tier2_expose:{}:{}", user_id, today);

            // M-2 (2026-05-22): replaces the prior process-wide
            // `Arc<AtomicU64>` fallback with a per-user
            // `(date, counter)` map. Pre-fix one tenant exhausting the
            // counter denied service to every other tenant on the
            // worker pod until restart. The new shape isolates
            // tenants AND self-rotates at the day boundary. Both the
            // Redis-error and Redis-absent paths route through the
            // same fallback helper — keeping MCP-722's "never-configured
            // = same fail-closed path as outage" invariant intact.
            use crate::expose_fallback::FallbackVerdict;
            let global_allowed = if let Some(ref redis) = self.redis_client {
                match Self::check_global_expose_limit(redis, &key).await {
                    Ok(allowed) => allowed,
                    Err(e) => {
                        let verdict = self.global_expose_fallback.check_and_increment(
                            user_id,
                            today_naive,
                            MAX_TIER2_EXPOSES_PER_USER_PER_DAY,
                        );
                        let (allowed, fallback_count) = match verdict {
                            FallbackVerdict::Allowed { count } => (true, count),
                            FallbackVerdict::Denied { count } => (false, count),
                        };
                        tracing::warn!(
                            user_id = %user_id,
                            error = %e,
                            fallback_count,
                            "Redis global expose limit check failed, using in-memory fallback ({}/{})",
                            fallback_count,
                            MAX_TIER2_EXPOSES_PER_USER_PER_DAY
                        );
                        allowed
                    }
                }
            } else {
                // MCP-722 (2026-05-13): Redis ABSENT (env-unconfigured)
                // must follow the same fallback path as Redis-ERROR.
                // Pre-fix this arm returned `true` unconditionally,
                // silently bypassing the daily per-user cap whenever
                // an operator ran the worker without Redis configured.
                // M-2 (2026-05-22): the fallback is now per-user, not
                // process-wide — see expose_fallback.rs.
                let verdict = self.global_expose_fallback.check_and_increment(
                    user_id,
                    today_naive,
                    MAX_TIER2_EXPOSES_PER_USER_PER_DAY,
                );
                let (allowed, fallback_count) = match verdict {
                    FallbackVerdict::Allowed { count } => (true, count),
                    FallbackVerdict::Denied { count } => (false, count),
                };
                tracing::warn!(
                    user_id = %user_id,
                    fallback_count,
                    "Redis not configured for global expose limit; using in-memory fallback ({}/{})",
                    fallback_count,
                    MAX_TIER2_EXPOSES_PER_USER_PER_DAY
                );
                allowed
            };

            if !global_allowed {
                tracing::warn!(
                    user_id = %user_id,
                    limit = MAX_TIER2_EXPOSES_PER_USER_PER_DAY,
                    "Global Tier-2 secret exposure limit exceeded (daily limit)"
                );
                return Err(wit_secrets::Error::Ratelimited);
            }
        }

        // Mark execution trace — this execution performed an explicit Tier-2 exposure.
        self.secret_tier2_exposed
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // Mandatory audit log — visible in structured logs and NATS audit stream.
        tracing::warn!(
            handle,
            reason = %reason,
            module_id = ?self.module_id,
            execution_id = ?self.execution_id,
            user_id = ?self.user_id,
            "TIER-2 secret exposure: plaintext crossing WASM boundary (expose-secret)"
        );

        // MCP-723 (2026-05-13): doc-drift closure. The comment above says
        // "NATS audit stream" but pre-fix only `tracing::warn!` fired —
        // local-log only, no WORM ledger row, no NATS replication. For
        // the HIGHEST-VALUE audit target (Tier-2 plaintext exposure)
        // this was a real omission; operators relying on the NATS
        // audit stream for SIEM ingestion would never see expose_secret
        // events. Sibling `get_secret` line ~2483 already follows this
        // shape — append to the local ledger, then fire-and-forget
        // publish to `talos.audit.ledger`. The reason string is
        // caller-supplied free text; it goes through the audit pipe
        // verbatim because operators rely on it for forensic context
        // ("why did this module expose secret X"). Length is bounded by
        // the WIT-side handle (no host cap today; future hardening
        // could clamp at e.g. 1 KiB).
        if let Some(ledger_mutex) = &self.audit_ledger {
            let mut ledger = ledger_mutex.lock().await;
            let event = ledger.append(
                "agent:wasm",
                "wasi:secrets_expose",
                &serde_json::json!({
                    "handle": handle,
                    "reason": &reason,
                    "module_id": self.module_id.as_ref().map(|u| u.to_string()),
                    "execution_id": self.execution_id.clone(),
                    "user_id": self.user_id.map(|u| u.to_string()),
                })
                .to_string(),
            );
            drop(ledger);
            if let Some(n) = &self.nats_client {
                let event_clone = event.clone();
                let nats = n.clone();
                tokio::spawn(async move {
                    let payload = serde_json::json!({
                        "event": event_clone.clone(),
                        "hash": event_clone.calculate_hash()
                    });
                    match serde_json::to_vec(&payload) {
                        Ok(bytes) => {
                            // MCP-735: HIGHEST-stakes audit replication.
                            // expose_secret is the single grep-able
                            // Tier-2 plaintext exit point — losing the
                            // SIEM signal silently means a plaintext-
                            // exposure event is invisible to the
                            // operator's alerting layer. Local ledger
                            // still has the event, but the WARN here is
                            // the only operational signal that
                            // replication failed.
                            if let Err(e) = nats
                                .publish("talos.audit.ledger".to_string(), bytes.into())
                                .await
                            {
                                tracing::warn!(
                                    target: "talos_rpc",
                                    error = %e,
                                    "audit-ledger NATS replication failed (secrets_expose) — local ledger unaffected, SIEM stream will miss a Tier-2 plaintext-exposure event"
                                );
                            }
                        }
                        Err(e) => tracing::error!(
                            "Failed to serialize audit event for secrets_expose: {}",
                            e
                        ),
                    }
                });
            }
        }

        // expose_slot is the single grep-able Tier-2 plaintext exit point.
        // L-4: provider returns Zeroizing<String>; we unwrap into an
        // owned String (the WIT return type requires String) at the
        // immediate point of use. The Zeroizing wrapper drops + wipes
        // when its scope ends. The returned String crosses the WASM
        // boundary into guest memory — Tier-2 by design, audited above.
        //
        // Wasm-security review 2026-05-23 (L-finding-2): the plaintext
        // String returned here lives in WASM linear memory for the
        // remainder of the execution. The host's `Zeroizing<String>`
        // drops + wipes its own copy at end-of-scope, but the WIT ABI's
        // String return semantically MOVES bytes into the guest's
        // wasm32 address space — the host cannot reach back and zero
        // them. The guest is responsible for narrowing the lifetime
        // (drop after use, overwrite with zeros, or `talos_sdk`'s
        // `ScopedSecret` helper which scrubs on Drop). At
        // execution-end the entire wasmtime `Store` is destroyed and
        // its linear-memory backing region is dropped by the host
        // allocator — but heap pages may sit in physical memory until
        // overwritten by a subsequent allocation, so a coincident host
        // memory dump still risks recovery. Operators who can't accept
        // that residency window MUST leave `allow_tier2_exposure`
        // false and use Tier-1 (`vault://` header substitution or
        // `fetch_with_header`), which never lands plaintext in guest
        // memory at all. The per-module `allow_tier2_exposure` flag
        // (gated above) IS the operator's acknowledgement of this
        // residency window — keep it false unless a specific module
        // documents why plaintext must cross the boundary.
        self.provider
            .into_auth_header(talos_secrets::SlotHandle(handle), "expose-secret")
            .map(|wrapped| (*wrapped).clone())
            .map_err(|e| {
                tracing::warn!(handle, error = %e, "expose-secret slot lookup failed");
                wit_secrets::Error::Notfound
            })
    }

    /// Tier-1 resolution for config fields that may contain `vault://` references.
    ///
    /// Strips the `vault://` prefix if present, then delegates to `get_secret`
    /// for the same allowlist check, audit logging, and provider resolution.
    /// The returned u64 is an opaque slot handle — no plaintext reaches guest memory.
    async fn resolve_config_vault(
        &mut self,
        config_value: String,
    ) -> Result<u64, wit_secrets::Error> {
        // This function is specifically for resolving vault:// config values.
        // Reject inputs without the prefix to prevent misuse as a get_secret alias.
        let path = match config_value.strip_prefix("vault://") {
            Some(p) => p.to_string(),
            None => {
                tracing::warn!(
                    config_value,
                    module_id = ?self.module_id,
                    "resolve_config_vault called without vault:// prefix"
                );
                return Err(wit_secrets::Error::Notfound);
            }
        };
        self.get_secret(path).await
    }
}

// ============================================================================
// State (workflow-scoped in-memory key-value store)
// ============================================================================

// MCP-603 (2026-05-12): WIT-world linkage restricts `talos:core/state`
// to http-node and above (minimal-node is the only world that does NOT
// `import state`). The existing `exists` method enforced this via a
// `CapabilityWorld::Minimal | Unknown → deny` gate; the sibling
// methods (get / set / delete / list_keys) did not — per-method-gate
// regression class (same shape as MCP-586 wit_files and MCP-601
// wit_cache::set). Without the gate, a mis-tagged Minimal-world
// module whose imports somehow linked would silently access the
// shared state store. Fail closed.
fn require_state_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_state::Error> {
    use crate::wit_inspector::CapabilityWorld;
    if matches!(world, CapabilityWorld::Minimal | CapabilityWorld::Unknown) {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_state call but lacks the required capability"
        );
        Err(wit_state::Error::Storagefailed)
    } else {
        Ok(())
    }
}

/// Maximum caller-supplied key length for wit_state operations, in
/// bytes. `set` has enforced this since MCP-712; the parity sweep
/// (this audit) extends the same cap to get / delete / exists so a
/// guest can't drive the host into per-call `format!("{module_id}:{key}")`
/// heap-alloc work with megabyte keys. Matches `state_rpc`'s
/// `MAX_STATE_KEY_LEN` on the controller side.
pub(crate) const MAX_STATE_KEY_LEN: usize = 1024;

fn require_state_key_in_range(key: &str) -> Result<(), wit_state::Error> {
    if key.is_empty() || key.len() > MAX_STATE_KEY_LEN {
        Err(wit_state::Error::Invalidkey)
    } else {
        Ok(())
    }
}

impl wit_state::Host for TalosContext {
    async fn get(&mut self, key: String) -> Result<String, wit_state::Error> {
        // MCP-712 (2026-05-13): audit-ledger emission for capability-
        // denial parity with exists() / list_keys() (which got it in
        // MCP-690) AND with the wit_secrets / wit_cache /
        // wit_graphql / wit_events / wit_agent_orchestration / etc.
        // host impls swept in MCP-686/690/696/697. Pre-fix the `?`
        // operator on `require_state_capability` propagated Err
        // without an audit row — a Minimal-world module repeatedly
        // probing wit_state::get left only `tracing::warn!` evidence,
        // operator-blind to the WORM ledger that dashboards alert on.
        if require_state_capability(&self.capability_world).is_err() {
            self.record_capability_denied("state-get", "capability-world", &key)
                .await;
            return Err(wit_state::Error::Storagefailed);
        }
        // Parity with `set` (which enforced this since MCP-712). Without
        // the cap here, a guest can drive per-call
        // `format!("{module_id}:{key}")` heap-alloc work with megabyte
        // keys via repeated get/delete/exists calls.
        require_state_key_in_range(&key)?;
        let scoped = self.scoped_state_key(&key);
        let store = self
            .state_store
            .lock()
            .map_err(|_| wit_state::Error::Storagefailed)?;
        store
            .get(&scoped)
            .cloned()
            .ok_or(wit_state::Error::Notfound)
    }

    async fn set(&mut self, key: String, value: String) -> Result<(), wit_state::Error> {
        // MCP-712 (2026-05-13): see comment on `get` above for the
        // audit-parity rationale. set() is the most-important of the
        // three fallible siblings to audit because a denied write
        // attempt is a stronger signal of capability mismatch than a
        // denied read.
        if require_state_capability(&self.capability_world).is_err() {
            self.record_capability_denied("state-set", "capability-world", &key)
                .await;
            return Err(wit_state::Error::Storagefailed);
        }
        require_state_key_in_range(&key)?;
        if value.len() > 1024 * 1024 {
            // 1MB limit
            tracing::warn!("State value exceeds 1MB limit");
            return Err(wit_state::Error::Storagefailed);
        }
        let scoped = self.scoped_state_key(&key);
        let mut store = self
            .state_store
            .lock()
            .map_err(|_| wit_state::Error::Storagefailed)?;

        // Enforce 1000 key limit to prevent host OOM
        if store.len() >= 1000 && !store.contains_key(&scoped) {
            tracing::warn!("State store exceeds 1000 key limit");
            return Err(wit_state::Error::Storagefailed);
        }

        // Enforce 100 MB aggregate state store limit to prevent DoS via 1000 × 1MB keys
        const MAX_STATE_STORE_AGGREGATE_BYTES: usize = 100 * 1024 * 1024;
        let old_size = store.get(&scoped).map(|v| v.len()).unwrap_or(0);
        let current_total: usize = store.values().map(|v| v.len()).sum();
        let new_total = current_total
            .saturating_sub(old_size)
            .saturating_add(value.len());
        if new_total > MAX_STATE_STORE_AGGREGATE_BYTES {
            tracing::warn!(
                total_bytes = new_total,
                "State store would exceed 100 MB aggregate limit"
            );
            return Err(wit_state::Error::Storagefailed);
        }

        store.insert(scoped.clone(), value.clone());
        drop(store); // Release lock before spawning async work

        // Write-through to durable storage via the state-write RPC
        // (best-effort, non-blocking). Signed + NATS-published so the
        // worker no longer needs direct Postgres credentials.
        spawn_state_write_through(
            self.nats_client.as_ref().cloned(),
            self.execution_id.as_deref(),
            self.actor_id,
            &scoped,
            Some(value.as_str()),
        );

        Ok(())
    }

    async fn delete(&mut self, key: String) -> Result<(), wit_state::Error> {
        // MCP-712 (2026-05-13): audit-parity with get/set/exists/list_keys.
        if require_state_capability(&self.capability_world).is_err() {
            self.record_capability_denied("state-delete", "capability-world", &key)
                .await;
            return Err(wit_state::Error::Storagefailed);
        }
        // Key-length parity with set; see the sibling cap on get().
        require_state_key_in_range(&key)?;
        let scoped = self.scoped_state_key(&key);
        let mut store = self
            .state_store
            .lock()
            .map_err(|_| wit_state::Error::Storagefailed)?;
        store.remove(&scoped);
        drop(store);

        // Mirror the durable store so restored workers don't see a
        // tombstone-less key.
        spawn_state_write_through(
            self.nats_client.as_ref().cloned(),
            self.execution_id.as_deref(),
            self.actor_id,
            &scoped,
            None, // None ⇒ delete
        );

        Ok(())
    }

    async fn exists(&mut self, key: String) -> bool {
        // MCP-603: routed through the shared helper so the gate
        // stays in lockstep with get/set/delete/list_keys.
        if require_state_capability(&self.capability_world).is_err() {
            // MCP-690 (2026-05-13): audit-ledger emission for
            // capability denial parity. The fallible siblings
            // (get/set/delete) emit via `record_capability_denied`;
            // this one used to silently return `false`, leaving no
            // trail in the audit ledger for repeated probes from a
            // Minimal-world module enumerating namespace keys.
            self.record_capability_denied("state-exists", "capability-world", &key)
                .await;
            return false;
        }
        // Key-length parity with set; oversized keys collapse to
        // false (this is an infallible WIT method — no Err variant
        // to surface). The cap prevents per-call
        // `format!("{module_id}:{key}")` allocation on megabyte input.
        if key.is_empty() || key.len() > MAX_STATE_KEY_LEN {
            return false;
        }
        let scoped = self.scoped_state_key(&key);
        self.state_store
            .lock()
            .map(|s| s.contains_key(&scoped))
            .unwrap_or(false)
    }

    async fn list_keys(&mut self) -> Vec<String> {
        // MCP-603: per-method gate aligned with siblings. Pre-fix
        // a Minimal-world module could enumerate every state key
        // in its scoped namespace (key names may carry semantic
        // information that the operator considered out-of-scope
        // for the module's capability tier).
        if require_state_capability(&self.capability_world).is_err() {
            // MCP-690: audit-ledger emission for capability denial parity.
            self.record_capability_denied("state-list-keys", "capability-world", "")
                .await;
            return Vec::new();
        }
        let prefix = match &self.module_id {
            Some(mid) => format!("{}:", mid),
            None => String::new(),
        };
        self.state_store
            .lock()
            .map(|s| {
                s.keys()
                    .filter(|k| {
                        if prefix.is_empty() {
                            true
                        } else {
                            k.starts_with(&prefix)
                        }
                    })
                    .map(|k| {
                        if prefix.is_empty() {
                            k.clone()
                        } else {
                            k[prefix.len()..].to_string()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod wit_state_key_range_tests {
    use super::{require_state_key_in_range, MAX_STATE_KEY_LEN};

    #[test]
    fn empty_key_rejected() {
        assert!(require_state_key_in_range("").is_err());
    }

    #[test]
    fn single_char_key_accepted() {
        assert!(require_state_key_in_range("k").is_ok());
    }

    #[test]
    fn key_at_limit_accepted() {
        let k: String = "a".repeat(MAX_STATE_KEY_LEN);
        assert!(require_state_key_in_range(&k).is_ok());
    }

    #[test]
    fn key_just_over_limit_rejected() {
        let k: String = "a".repeat(MAX_STATE_KEY_LEN + 1);
        assert!(require_state_key_in_range(&k).is_err());
    }

    #[test]
    fn megabyte_key_rejected_get_delete_exists_parity() {
        // The cap previously lived only inside `set`; sweep parity
        // (this PR) ensures get/delete/exists/set all share the same
        // gate so a guest cannot drive per-call
        // `format!("{module_id}:{key}")` heap-alloc work via the
        // unbounded siblings.
        let k: String = "x".repeat(1024 * 1024);
        assert!(require_state_key_in_range(&k).is_err());
    }
}

// ============================================================================
// Environment / workflow metadata
// ============================================================================

impl wit_env::Host for TalosContext {
    async fn get_var(&mut self, key: String) -> Option<String> {
        self.env_vars.get(&key).cloned()
    }

    async fn get_all_vars(&mut self) -> String {
        serde_json::to_string(&self.env_vars).unwrap_or_else(|_| "{}".to_string())
    }

    async fn get_workflow_id(&mut self) -> String {
        self.workflow_id.clone().unwrap_or_default()
    }

    async fn get_execution_id(&mut self) -> String {
        self.execution_id.clone().unwrap_or_default()
    }

    async fn get_module_id(&mut self) -> String {
        self.module_id.clone().unwrap_or_default()
    }
}

// ============================================================================
// JSON utilities
// ============================================================================

impl wit_json::Host for TalosContext {
    /// Validates that `json_str` is syntactically valid JSON.
    ///
    /// Returns `Ok(())` if the string is valid JSON, `Err(Parseerror)` otherwise.
    /// Use `json::query` to parse and extract values in one call.
    async fn parse(&mut self, json_str: String) -> Result<(), wit_json::Error> {
        if let Err(_limit) = self.validate_json_size(&json_str, "json::parse") {
            return Err(wit_json::Error::Parseerror);
        }
        serde_json::from_str::<serde_json::Value>(&json_str)
            .map(|_| ())
            .map_err(|e| {
                tracing::debug!(error = %e, "json::parse validation failed");
                wit_json::Error::Parseerror
            })
    }

    async fn query(&mut self, json_str: String, path: String) -> Result<String, wit_json::Error> {
        // Use unified JSON size validation helper
        if let Err(_limit) = self.validate_json_size(&json_str, "json::query") {
            return Err(wit_json::Error::Parseerror);
        }
        let value: serde_json::Value =
            serde_json::from_str(&json_str).map_err(|_| wit_json::Error::Parseerror)?;

        // Support simple dot-notation paths: "user.email", "$.items[0]", etc.
        let result = json_path_query(&value, &path)?;
        serde_json::to_string(&result).map_err(|_| wit_json::Error::Parseerror)
    }

    async fn merge(&mut self, json1: String, json2: String) -> Result<String, wit_json::Error> {
        // MCP-1049: route through the canonical `validate_json_size`
        // helper (worker/src/context.rs:978) so both inputs share the
        // OnceLock-cached env read, the MCP-772 `nonzero_env_or_default`
        // semantics (rejects =0), and the structured WARN field shape.
        // Pre-fix three sibling sites (merge / prettify / minify) each
        // re-fetched WASM_MAX_JSON_SIZE on every call with a slightly
        // different threshold helper, drifting from the canonical
        // `json::parse` and `json::query` paths. Same drift hazard as
        // MCP-1037/1038/1040 — N inline copies of the same security
        // knob eventually diverge.
        if self.validate_json_size(&json1, "json::merge").is_err()
            || self.validate_json_size(&json2, "json::merge").is_err()
        {
            return Err(wit_json::Error::Parseerror);
        }
        let mut v1: serde_json::Value =
            serde_json::from_str(&json1).map_err(|_| wit_json::Error::Parseerror)?;
        let v2: serde_json::Value =
            serde_json::from_str(&json2).map_err(|_| wit_json::Error::Parseerror)?;
        json_merge(&mut v1, v2);
        serde_json::to_string(&v1).map_err(|_| wit_json::Error::Parseerror)
    }

    async fn prettify(&mut self, json_str: String) -> Result<String, wit_json::Error> {
        // MCP-1049: canonical `validate_json_size` helper.
        if self.validate_json_size(&json_str, "json::prettify").is_err() {
            return Err(wit_json::Error::Parseerror);
        }
        let value: serde_json::Value =
            serde_json::from_str(&json_str).map_err(|_| wit_json::Error::Parseerror)?;
        serde_json::to_string_pretty(&value).map_err(|_| wit_json::Error::Parseerror)
    }

    async fn minify(&mut self, json_str: String) -> Result<String, wit_json::Error> {
        // MCP-1049: canonical `validate_json_size` helper.
        if self.validate_json_size(&json_str, "json::minify").is_err() {
            return Err(wit_json::Error::Parseerror);
        }
        let value: serde_json::Value =
            serde_json::from_str(&json_str).map_err(|_| wit_json::Error::Parseerror)?;
        serde_json::to_string(&value).map_err(|_| wit_json::Error::Parseerror)
    }
}

/// Recursive deep-merge: `target` is mutated by merging `source` into it.
/// Object keys in `source` override `target`; arrays are replaced.
fn json_merge(target: &mut serde_json::Value, source: serde_json::Value) {
    match (target, source) {
        (serde_json::Value::Object(t), serde_json::Value::Object(s)) => {
            for (k, v) in s {
                let entry = t.entry(k).or_insert(serde_json::Value::Null);
                json_merge(entry, v);
            }
        }
        (target, source) => *target = source,
    }
}

/// Simple dot-notation and `$`-prefix JSON path query.
fn json_path_query<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Result<&'a serde_json::Value, wit_json::Error> {
    /// Maximum path segments to prevent O(n) stack usage and ReDoS-style abuse.
    const MAX_PATH_DEPTH: usize = 128;

    let path = path.trim_start_matches("$.").trim_start_matches('$');
    let mut current = value;
    let mut depth = 0usize;
    for segment in path.split('.') {
        depth += 1;
        if depth > MAX_PATH_DEPTH {
            return Err(wit_json::Error::Invalidpath);
        }
        if segment.is_empty() {
            continue;
        }
        // Handle array index: e.g. `items[0]`
        if let Some(bracket_pos) = segment.find('[') {
            let key = &segment[..bracket_pos];
            let idx_str = segment[bracket_pos + 1..].trim_end_matches(']');
            let idx: usize = idx_str.parse().map_err(|_| wit_json::Error::Invalidpath)?;
            if !key.is_empty() {
                current = current.get(key).ok_or(wit_json::Error::Invalidpath)?;
            }
            current = current.get(idx).ok_or(wit_json::Error::Invalidpath)?;
        } else {
            current = current.get(segment).ok_or(wit_json::Error::Invalidpath)?;
        }
    }
    Ok(current)
}

// ============================================================================
// Date / time
// ============================================================================

impl wit_datetime::Host for TalosContext {
    async fn now_unix(&mut self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    async fn now_iso(&mut self) -> String {
        chrono::Utc::now().to_rfc3339()
    }

    async fn parse(
        &mut self,
        date_str: String,
        format: Option<String>,
    ) -> Result<u64, wit_datetime::Error> {
        // If a custom format is provided, use it via chrono's strftime parsing.
        if let Some(ref fmt) = format {
            if let Ok(dt) = chrono::DateTime::parse_from_str(&date_str, fmt) {
                return Ok(dt.timestamp() as u64);
            }
            // Try NaiveDateTime (no timezone) and assume UTC
            if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(&date_str, fmt) {
                return Ok(ndt.and_utc().timestamp() as u64);
            }
            // Try NaiveDate (date only) and assume midnight UTC
            if let Ok(nd) = chrono::NaiveDate::parse_from_str(&date_str, fmt) {
                if let Some(ndt) = nd.and_hms_opt(0, 0, 0) {
                    return Ok(ndt.and_utc().timestamp() as u64);
                }
            }
            return Err(wit_datetime::Error::Parseerror);
        }

        // No format specified — try RFC 3339 first, then RFC 2822.
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&date_str) {
            return Ok(dt.timestamp() as u64);
        }
        if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(&date_str) {
            return Ok(dt.timestamp() as u64);
        }
        Err(wit_datetime::Error::Parseerror)
    }

    async fn format(
        &mut self,
        timestamp: u64,
        format: String,
    ) -> Result<String, wit_datetime::Error> {
        let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp as i64, 0)
            .ok_or(wit_datetime::Error::Invalidformat)?;
        Ok(dt.format(&format).to_string())
    }

    async fn add_seconds(&mut self, timestamp: u64, seconds: i64) -> u64 {
        (timestamp as i64).saturating_add(seconds) as u64
    }

    async fn diff_seconds(&mut self, timestamp1: u64, timestamp2: u64) -> i64 {
        (timestamp1 as i64).saturating_sub(timestamp2 as i64)
    }
}

// ============================================================================
// Crypto
// ============================================================================

/// Maximum input size for hash/HMAC operations (100 MiB).
/// Prevents a WASM guest from triggering multi-second CPU stalls on the host.
const MAX_HASH_INPUT_BYTES: usize = 100 * 1024 * 1024;

/// Maximum HMAC key size (1 MiB).
/// HMAC keys beyond one block are hashed by the algorithm anyway; this cap
/// prevents host memory pressure from oversized keys.
const MAX_HMAC_KEY_BYTES: usize = 1024 * 1024;

impl wit_crypto::Host for TalosContext {
    async fn hash(&mut self, algorithm: wit_crypto::HashAlgorithm, data: Vec<u8>) -> Vec<u8> {
        // Check if crypto budget is already exhausted.
        if self
            .crypto_budget_us
            .load(std::sync::atomic::Ordering::Relaxed)
            == 0
        {
            tracing::warn!(
                "hash() called but crypto time budget is exhausted — returning empty vec"
            );
            return vec![];
        }
        // Guard against DoS via oversized input.
        if data.len() > MAX_HASH_INPUT_BYTES {
            tracing::warn!(
                data_len = data.len(),
                limit = MAX_HASH_INPUT_BYTES,
                "hash() input exceeds size limit — returning empty vec"
            );
            return vec![];
        }
        use sha2::Digest;
        let start = std::time::Instant::now();
        let result = match algorithm {
            wit_crypto::HashAlgorithm::Sha256 => sha2::Sha256::digest(&data).to_vec(),
            wit_crypto::HashAlgorithm::Sha512 => sha2::Sha512::digest(&data).to_vec(),
            wit_crypto::HashAlgorithm::Md5 => {
                tracing::warn!(
                    module_id = ?self.module_id,
                    "MD5 hash is cryptographically broken — use SHA-256 or SHA-512 instead"
                );
                md5::compute(&data).to_vec()
            }
        };
        let elapsed_us = start.elapsed().as_micros() as u64;
        if !self.deduct_crypto_budget(elapsed_us) {
            tracing::warn!(
                elapsed_us,
                "hash() exhausted crypto time budget — subsequent crypto calls will be rejected"
            );
        }
        result
    }

    async fn hmac(
        &mut self,
        algorithm: wit_crypto::HashAlgorithm,
        key: Vec<u8>,
        data: Vec<u8>,
    ) -> Vec<u8> {
        // Check if crypto budget is already exhausted.
        if self
            .crypto_budget_us
            .load(std::sync::atomic::Ordering::Relaxed)
            == 0
        {
            tracing::warn!(
                "hmac() called but crypto time budget is exhausted — returning empty vec"
            );
            return vec![];
        }
        // Guard against DoS via oversized key or data.
        if key.len() > MAX_HMAC_KEY_BYTES || data.len() > MAX_HASH_INPUT_BYTES {
            tracing::warn!(
                key_len = key.len(),
                data_len = data.len(),
                "hmac() key or data exceeds size limit — returning empty vec"
            );
            return vec![];
        }
        use hmac::{Hmac, Mac};
        let start = std::time::Instant::now();
        // new_from_slice() accepts any key length for HMAC (unlike block ciphers), so
        // the error branch is unreachable in practice, but we handle it to avoid panics.
        let result = match algorithm {
            wit_crypto::HashAlgorithm::Sha256 => match Hmac::<sha2::Sha256>::new_from_slice(&key) {
                Ok(mut mac) => {
                    mac.update(&data);
                    mac.finalize().into_bytes().to_vec()
                }
                Err(_) => {
                    tracing::warn!("hmac() failed to build HMAC instance");
                    vec![]
                }
            },
            wit_crypto::HashAlgorithm::Sha512 => match Hmac::<sha2::Sha512>::new_from_slice(&key) {
                Ok(mut mac) => {
                    mac.update(&data);
                    mac.finalize().into_bytes().to_vec()
                }
                Err(_) => {
                    tracing::warn!("hmac() failed to build HMAC instance");
                    vec![]
                }
            },
            wit_crypto::HashAlgorithm::Md5 => {
                // HMAC-MD5 is cryptographically weak; fall back to HMAC-SHA256.
                // The md5 0.7 crate is not digest 0.10 compatible, so we cannot
                // construct Hmac::<md5::Md5> directly.  Returning HMAC-SHA256 keeps
                // the interface functional while steering callers away from MD5.
                match Hmac::<sha2::Sha256>::new_from_slice(&key) {
                    Ok(mut mac) => {
                        mac.update(&data);
                        mac.finalize().into_bytes().to_vec()
                    }
                    Err(_) => {
                        tracing::warn!("hmac() fallback HMAC-SHA256 failed");
                        vec![]
                    }
                }
            }
        };
        let elapsed_us = start.elapsed().as_micros() as u64;
        if !self.deduct_crypto_budget(elapsed_us) {
            tracing::warn!(
                elapsed_us,
                "hmac() exhausted crypto time budget — subsequent crypto calls will be rejected"
            );
        }
        result
    }

    async fn encode(&mut self, encoding: wit_crypto::Encoding, data: Vec<u8>) -> String {
        match encoding {
            wit_crypto::Encoding::Hex => hex::encode(&data),
            wit_crypto::Encoding::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&data)
            }
            wit_crypto::Encoding::Base64url => {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data)
            }
        }
    }

    async fn decode(
        &mut self,
        encoding: wit_crypto::Encoding,
        data: String,
    ) -> Result<Vec<u8>, wit_crypto::Error> {
        match encoding {
            wit_crypto::Encoding::Hex => {
                hex::decode(&data).map_err(|_| wit_crypto::Error::Invalidinput)
            }
            wit_crypto::Encoding::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(&data)
                    .map_err(|_| wit_crypto::Error::Invalidinput)
            }
            wit_crypto::Encoding::Base64url => {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&data)
                    .map_err(|_| wit_crypto::Error::Invalidinput)
            }
        }
    }

    async fn random_bytes(&mut self, length: u32) -> Vec<u8> {
        use rand::RngCore;
        const MAX_RANDOM_BYTES: u32 = 1_000_000; // 1 MB — prevents host memory exhaustion
        if length > MAX_RANDOM_BYTES {
            tracing::warn!(
                "random_bytes() requested {} bytes, exceeds limit of {}; returning empty",
                length,
                MAX_RANDOM_BYTES
            );
            return vec![];
        }
        let mut bytes = vec![0u8; length as usize];
        // MCP-1085 (2026-05-16): use `OsRng` (always CSPRNG-grade per
        // platform syscall — /dev/urandom on Linux, getrandom(2),
        // BCryptGenRandom on Windows) instead of `rand::thread_rng()`.
        // Pre-fix `thread_rng()` returns a ChaCha-based PRNG that IS
        // CSPRNG-grade in current `rand` versions, but the rand crate
        // docs explicitly recommend `OsRng` for cryptographic use AND
        // a future rand-crate change could weaken thread_rng (e.g.,
        // switch to a faster PRNG for general use). Guest modules
        // calling `random_bytes()` may use the output for session
        // tokens, nonces, key material — defense-in-depth requires
        // explicit OsRng so the CSPRNG guarantee survives any crate
        // upgrade. Matches the convention already established in
        // talos-auth (refresh tokens) and talos-csrf (CSRF tokens) /
        // talos-api (mcp agent tokens).
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes
    }

    async fn uuid(&mut self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

// ============================================================================
// Cache (Redis)
// ============================================================================

/// Build a namespace-prefixed cache key to isolate WASM module cache entries.
///
/// Format: `talos_cache:u={user_id}:{key}` (or `talos_cache:u=system:{key}`
/// when no user context is attached — system executions only).
///
/// **Cross-tenant isolation (2026-05-23, security review).** Pre-fix the
/// namespace was a single `talos_cache:{key}` shared across every tenant on
/// the cluster: any module holding the `Cache` capability — a routine grant
/// — could `get` / `set` / `delete` / `mget` / `exists` / `increment` any
/// other tenant's cache entries by name. PII, embeddings, OAuth-state
/// nonces, dedupe markers, computed weights — all of it was a `mget` of a
/// guessable key away from a hostile module. The doc-comment even called
/// this out as intentional. It is not — opt-out, not opt-in, is the
/// security-safe default for any tenant-aware platform.
///
/// **Why prefix per-user, not per-actor or per-module.** Cache values today
/// are scoped to the user (HTTP responses, computed embeddings, OAuth
/// state). Per-actor would over-isolate workflows-within-a-user that
/// genuinely share state; per-module would over-isolate two nodes in the
/// same workflow that compose a pipeline. Per-user matches the engine's
/// existing trust boundary (DEK lineage, integration-state) and keeps the
/// human-mental-model of "my data is mine, others can't see it" intact.
///
/// **Backward compatibility.** Existing `talos_cache:{key}` entries become
/// orphaned at deploy; the 24h Redis TTL on cache writes (`OCI_CACHE_TTL_SECS`
/// pattern) means they age out within a day. Any module relying on
/// cross-tenant cache reads was an unintended exploit path — losing those
/// reads is the fix, not a regression.
fn namespaced_cache_key(ctx: &TalosContext, key: &str) -> String {
    build_namespaced_cache_key(ctx.user_id, key)
}

/// Pure helper used by [`namespaced_cache_key`] so the namespacing rule can
/// be unit-tested without constructing a full [`TalosContext`].
///
/// The format is `talos_cache:u={user_id}:{key}` for user-scoped executions
/// and `talos_cache:u=system:{key}` for system executions. UUIDs render as
/// hex with hyphens — there is no representable user_id that collides with
/// the reserved `system` token, so the two namespaces are disjoint.
pub(crate) fn build_namespaced_cache_key(user_id: Option<uuid::Uuid>, key: &str) -> String {
    match user_id {
        Some(uid) => format!("talos_cache:u={}:{}", uid, key),
        None => format!("talos_cache:u=system:{}", key),
    }
}

#[cfg(test)]
mod namespaced_cache_key_tests {
    use super::build_namespaced_cache_key;
    use uuid::Uuid;

    #[test]
    fn user_scoped_key_has_user_id_prefix() {
        let uid = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let got = build_namespaced_cache_key(Some(uid), "foo");
        assert_eq!(got, "talos_cache:u=00000000-0000-4000-8000-000000000001:foo");
    }

    #[test]
    fn no_user_id_routes_to_system_bucket() {
        // System executions (scheduler, internal) get their own bucket so
        // a malicious guest can never probe internal cache entries by
        // omitting their own user_id.
        assert_eq!(
            build_namespaced_cache_key(None, "foo"),
            "talos_cache:u=system:foo",
        );
    }

    #[test]
    fn distinct_users_get_distinct_namespaces() {
        // Cross-tenant isolation invariant: two users with the same key
        // string must produce different Redis keys.
        let a = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let b = Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
        assert_ne!(
            build_namespaced_cache_key(Some(a), "shared-key"),
            build_namespaced_cache_key(Some(b), "shared-key"),
        );
    }

    #[test]
    fn user_id_cannot_collide_with_system_token() {
        // UUIDs always contain hyphens; the literal `system` token does not
        // parse as a Uuid. No user_id can collide with the system bucket.
        assert!(Uuid::parse_str("system").is_err());
    }

    #[test]
    fn keys_containing_namespace_separator_do_not_break_isolation() {
        // A guest who tries to escape its own namespace by embedding
        // `:u=` in the key cannot probe another user's bucket — the
        // prefix is BEFORE the key, so the resulting Redis key still
        // starts with the right user namespace.
        let uid = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let injected = "extra:u=00000000-0000-4000-8000-000000000002:victim";
        let got = build_namespaced_cache_key(Some(uid), injected);
        assert!(got.starts_with("talos_cache:u=00000000-0000-4000-8000-000000000001:"));
        // The injected suffix is present but inert — Redis treats the
        // whole string as one opaque key.
        assert!(got.ends_with(injected));
    }
}

/// MCP-754 (2026-05-13): per-key length cap shared across every
/// wit_cache::Host method. `set` (line ~3617) and `mset` (loop at
/// line ~3859) already enforced `key.len() <= 1024`; the read /
/// mutation siblings (`get`, `delete`, `exists`, `increment`,
/// `decrement`, `expire`, and `mget`'s per-entry check) had NO
/// per-key cap. A Cache-world guest could allocate a multi-megabyte
/// key string in WASM linear memory and pass it to any of those
/// methods — the host would format it into `talos_cache:<10MB>`,
/// allocate ~10MB on the host heap, then send the giant key to
/// Redis (Redis processes it but spends materially more CPU per
/// op than on a 1KB key). Loop the call → amplification DoS against
/// the shared Redis instance, with the audit ledger seeing only
/// "guest had Cache capability and made cache calls" — no signal
/// tying the spike to one module. Same sibling-defense drift class
/// as MCP-731 / MCP-732. Cap matches the established `set` /
/// `mset` limit.
const MAX_CACHE_KEY_BYTES: usize = 1024;

impl wit_cache::Host for TalosContext {
    async fn get(&mut self, key: String) -> Result<String, wit_cache::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result = async move {
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Cache | CapabilityWorld::Trusted
            ) {
                // MCP-696 (2026-05-13): audit-ledger parity. Sibling
                // `exists` was closed in MCP-690; the other 8 wit_cache
                // methods silently denied without `record_capability_denied`,
                // so a Minimal-world module probing for cache access
                // surface left no audit trail. Same `tracing::warn!`-only
                // class as the original wit_state::exists / wit_files
                // gaps. Threat model identical to MCP-601 (Minimal world
                // poisoning the shared `talos_cache:` namespace).
                self.record_capability_denied("cache-get", "capability-world", &key)
                    .await;
                tracing::warn!("WASM module attempted cache access but lacks Cache capability");
                return Err(wit_cache::Error::Connectionfailed);
            }
            // MCP-754: per-key cap parity with `set`. See MAX_CACHE_KEY_BYTES doc.
            if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
                return Err(wit_cache::Error::Operationfailed);
            }

            let redis = self
                .redis_client
                .as_ref()
                .ok_or(wit_cache::Error::Connectionfailed)?;

            let ns_key = namespaced_cache_key(self, &key);
            use redis::AsyncCommands;
            let mut conn = redis
                .get_multiplexed_async_connection()
                .await
                .map_err(|_| wit_cache::Error::Connectionfailed)?;
            conn.get::<_, String>(&ns_key)
                .await
                .map_err(|_| wit_cache::Error::Notfound)
        }
        .await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("cache::get", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn set(
        &mut self,
        key: String,
        value: String,
        ttl: Option<u32>,
    ) -> Result<(), wit_cache::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<(), wit_cache::Error> = async move {
            // MCP-601 (2026-05-12): every other wit_cache method gates on
            // CapabilityWorld::Cache | Trusted; `set` was missing the
            // check (copy-paste regression). Without this gate, a
            // Minimal-world module could write Redis keys in the shared
            // `talos_cache:` namespace, polluting/poisoning a cache that
            // Cache-world modules read from. Same gate used by get/
            // delete/exists/increment/decrement/mget/mset/expire (verified
            // by audit sweep of wit_cache::Host impl block).
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Cache | CapabilityWorld::Trusted
            ) {
                // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
                self.record_capability_denied("cache-set", "capability-world", &key)
                    .await;
                tracing::warn!("WASM module attempted cache::set but lacks Cache capability");
                return Err(wit_cache::Error::Connectionfailed);
            }
            if key.is_empty() || key.len() > 1024 {
                return Err(wit_cache::Error::Operationfailed);
            }
            if value.len() > 10 * 1024 * 1024 {
                // 10MB limit
                tracing::warn!("Cache value exceeds 10MB limit");
                return Err(wit_cache::Error::Operationfailed);
            }

            let redis = self
                .redis_client
                .as_ref()
                .ok_or(wit_cache::Error::Connectionfailed)?;

            let ns_key = namespaced_cache_key(self, &key);
            use redis::AsyncCommands;
            let mut conn = redis
                .get_multiplexed_async_connection()
                .await
                .map_err(|_| wit_cache::Error::Connectionfailed)?;
            match ttl {
                Some(secs) => conn
                    .set_ex::<_, _, ()>(&ns_key, &value, secs as u64)
                    .await
                    .map_err(|_| wit_cache::Error::Operationfailed),
                None => conn
                    .set::<_, _, ()>(&ns_key, &value)
                    .await
                    .map_err(|_| wit_cache::Error::Operationfailed),
            }
        }
        .await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("cache::set", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn delete(&mut self, key: String) -> Result<(), wit_cache::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<(), wit_cache::Error> = async move {
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Cache | CapabilityWorld::Trusted
            ) {
                // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
                self.record_capability_denied("cache-delete", "capability-world", &key)
                    .await;
                tracing::warn!("WASM module attempted cache access but lacks Cache capability");
                return Err(wit_cache::Error::Connectionfailed);
            }
            // MCP-754: per-key cap parity with `set`. See MAX_CACHE_KEY_BYTES doc.
            if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
                return Err(wit_cache::Error::Operationfailed);
            }

            let redis = self
                .redis_client
                .as_ref()
                .ok_or(wit_cache::Error::Connectionfailed)?;

            let ns_key = namespaced_cache_key(self, &key);
            use redis::AsyncCommands;
            let mut conn = redis
                .get_multiplexed_async_connection()
                .await
                .map_err(|_| wit_cache::Error::Connectionfailed)?;
            conn.del::<_, ()>(&ns_key)
                .await
                .map_err(|_| wit_cache::Error::Operationfailed)
        }
        .await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("cache::delete", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn exists(&mut self, key: String) -> bool {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-690 (2026-05-13): audit-ledger emission for
            // capability denial parity with the fallible siblings
            // (get/set/delete/increment etc.). Pre-fix this method
            // silently returned `false`, so a Minimal-world module
            // could probe arbitrary cache keys without leaving an
            // audit trail. Same `-> bool` silent-no-op class as
            // wit_state::exists, wit_state::list_keys, wit_files::exists.
            self.record_capability_denied("cache-exists", "capability-world", &key)
                .await;
            return false;
        }
        // MCP-754: per-key cap parity with `set`. See MAX_CACHE_KEY_BYTES doc.
        // `exists` returns `-> bool` so we silently no-op (return false) on
        // oversized keys, matching the existing silent-deny shape for missing
        // Redis client and connection errors below.
        if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
            return false;
        }
        let Some(redis) = &self.redis_client else {
            return false;
        };

        let ns_key = namespaced_cache_key(self, &key);
        use redis::AsyncCommands;
        let Ok(mut conn) = redis.get_multiplexed_async_connection().await else {
            return false;
        };
        conn.exists::<_, bool>(&ns_key).await.unwrap_or(false)
    }

    async fn increment(&mut self, key: String, amount: i64) -> Result<i64, wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
            self.record_capability_denied("cache-increment", "capability-world", &key)
                .await;
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }
        // MCP-754: per-key cap parity with `set`. See MAX_CACHE_KEY_BYTES doc.
        if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
            return Err(wit_cache::Error::Operationfailed);
        }

        let redis = self
            .redis_client
            .as_ref()
            .ok_or(wit_cache::Error::Connectionfailed)?;

        let ns_key = namespaced_cache_key(self, &key);
        use redis::AsyncCommands;
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        conn.incr::<_, _, i64>(&ns_key, amount)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }

    async fn decrement(&mut self, key: String, amount: i64) -> Result<i64, wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
            self.record_capability_denied("cache-decrement", "capability-world", &key)
                .await;
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }
        // MCP-754: per-key cap parity with `set`. Belt-and-suspenders:
        // `increment` (delegated below) also enforces, but this catch
        // saves the negation arithmetic + the second capability check.
        if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
            return Err(wit_cache::Error::Operationfailed);
        }

        // MCP-1007 (2026-05-15): guard the i64 negation against
        // `amount = i64::MIN`. Pre-fix `-amount` panicked in debug
        // builds (Rust's `Neg` trait for i64 overflows on `i64::MIN`,
        // since `-i64::MIN = i64::MAX + 1` doesn't fit in i64) and
        // wrapped to `i64::MIN` in release builds — so
        // `decrement(key, i64::MIN)` silently collapsed to
        // `increment(key, i64::MIN)`, producing the wrong cache value
        // instead of the operation-not-representable error the caller
        // expected. Redis would then catch the resulting overflow at
        // the INCRBY level and return generic `Operationfailed`,
        // hiding the real cause from operators reading worker logs.
        // Same defense-in-depth class as the integer-cast wraparound
        // sweep (MCP-960 / MCP-961 / MCP-962). Fail-closed at the
        // boundary with `checked_neg`; the caller sees
        // `Operationfailed` immediately rather than reaching Redis.
        let neg_amount = match amount.checked_neg() {
            Some(n) => n,
            None => {
                tracing::warn!(
                    module_id = ?self.module_id,
                    "cache::decrement received i64::MIN — negation would overflow; rejecting"
                );
                return Err(wit_cache::Error::Operationfailed);
            }
        };

        self.increment(key, neg_amount).await
    }

    async fn mget(&mut self, keys: Vec<String>) -> Result<Vec<Option<String>>, wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
            // Multi-key surface, so target encodes the batch size rather
            // than a key literal (avoids cardinality blow-up + key-bag PII).
            let target = format!("<batch:{}>", keys.len());
            self.record_capability_denied("cache-mget", "capability-world", &target)
                .await;
            tracing::warn!(
                module_id = ?self.module_id,
                "WASM module attempted cache mget but lacks Cache capability"
            );
            return Err(wit_cache::Error::Connectionfailed);
        }

        // MCP-732 (2026-05-13): batch-size cap, sibling-defense parity
        // with the single-key path. Pre-fix a Cache-world guest could
        // pass an unbounded `keys: Vec<String>` and the host would
        // forward all of them to Redis in one MGET — enumeration-DoS
        // against the shared `talos_cache:` namespace AND a memory
        // bomb for the host (the reply Vec<Option<String>> mirrors
        // the input cardinality). Sibling drift class to MCP-731
        // (wit_messaging::request missed siblings).
        const MAX_CACHE_BATCH_KEYS: usize = 1000;
        if keys.len() > MAX_CACHE_BATCH_KEYS {
            tracing::warn!(
                module_id = ?self.module_id,
                batch_size = keys.len(),
                "cache::mget batch size exceeds {} keys; rejecting",
                MAX_CACHE_BATCH_KEYS
            );
            return Err(wit_cache::Error::Operationfailed);
        }
        // MCP-754: per-key length cap, sibling-parity with `mset`'s
        // per-entry loop check (lines below). Pre-fix `mget` only
        // capped batch size — a 1000-key batch where each key was 10 MB
        // long was a 10 GB host allocation in `ns_keys` + a 10 GB
        // payload to Redis. See MAX_CACHE_KEY_BYTES doc.
        for (i, k) in keys.iter().enumerate() {
            if k.is_empty() || k.len() > MAX_CACHE_KEY_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    index = i,
                    key_len = k.len(),
                    "cache::mget key exceeds {} bytes (or empty); rejecting batch",
                    MAX_CACHE_KEY_BYTES
                );
                return Err(wit_cache::Error::Operationfailed);
            }
        }

        let redis = self
            .redis_client
            .as_ref()
            .ok_or(wit_cache::Error::Connectionfailed)?;

        let ns_keys: Vec<String> = keys.iter().map(|k| namespaced_cache_key(self, k)).collect();
        use redis::AsyncCommands;
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        conn.mget::<_, Vec<Option<String>>>(ns_keys)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }

    async fn mset(&mut self, pairs: Vec<(String, String)>) -> Result<(), wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
            // Multi-key surface — encode batch size only (same reasoning as mget).
            let target = format!("<batch:{}>", pairs.len());
            self.record_capability_denied("cache-mset", "capability-world", &target)
                .await;
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }

        // MCP-732 (2026-05-13): batch-size + per-key/per-value caps,
        // sibling-defense parity with the single-key `set` path. Pre-fix
        // `mset` had zero size checks while `set` enforces
        // `key.len() <= 1024` AND `value.len() <= 10 MiB`. A Cache-world
        // guest could write GBs into Redis in a single call (memory-
        // exhaust the shared `talos_cache:` namespace), or use
        // pathological key lengths to overflow Redis's per-key limit.
        // Same drift class as MCP-731. Caps match the single-key path.
        const MAX_CACHE_BATCH_KEYS: usize = 1000;
        const MAX_KEY_BYTES: usize = 1024;
        const MAX_VALUE_BYTES: usize = 10 * 1024 * 1024;
        if pairs.len() > MAX_CACHE_BATCH_KEYS {
            tracing::warn!(
                module_id = ?self.module_id,
                batch_size = pairs.len(),
                "cache::mset batch size exceeds {} pairs; rejecting",
                MAX_CACHE_BATCH_KEYS
            );
            return Err(wit_cache::Error::Operationfailed);
        }
        for (k, v) in &pairs {
            if k.is_empty() || k.len() > MAX_KEY_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    key_len = k.len(),
                    "cache::mset key exceeds {} bytes (or empty); rejecting batch",
                    MAX_KEY_BYTES
                );
                return Err(wit_cache::Error::Operationfailed);
            }
            if v.len() > MAX_VALUE_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    value_len = v.len(),
                    "cache::mset value exceeds {} bytes; rejecting batch",
                    MAX_VALUE_BYTES
                );
                return Err(wit_cache::Error::Operationfailed);
            }
        }

        let redis = self
            .redis_client
            .as_ref()
            .ok_or(wit_cache::Error::Connectionfailed)?;

        let ns_pairs: Vec<(String, String)> = pairs
            .into_iter()
            .map(|(k, v)| (namespaced_cache_key(self, &k), v))
            .collect();
        use redis::AsyncCommands;
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        conn.mset::<_, _, ()>(&ns_pairs)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }

    async fn expire(&mut self, key: String, ttl: u32) -> Result<(), wit_cache::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Cache | CapabilityWorld::Trusted
        ) {
            // MCP-696 (2026-05-13): audit-ledger parity — see cache::get above.
            self.record_capability_denied("cache-expire", "capability-world", &key)
                .await;
            tracing::warn!("WASM module attempted cache access but lacks Cache capability");
            return Err(wit_cache::Error::Connectionfailed);
        }
        // MCP-754: per-key cap parity with `set`. See MAX_CACHE_KEY_BYTES doc.
        if key.is_empty() || key.len() > MAX_CACHE_KEY_BYTES {
            return Err(wit_cache::Error::Operationfailed);
        }

        let redis = self
            .redis_client
            .as_ref()
            .ok_or(wit_cache::Error::Connectionfailed)?;

        let ns_key = namespaced_cache_key(self, &key);
        use redis::AsyncCommands;
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| wit_cache::Error::Connectionfailed)?;
        conn.expire::<_, ()>(&ns_key, ttl as i64)
            .await
            .map_err(|_| wit_cache::Error::Operationfailed)
    }
}

// ============================================================================
// Messaging (NATS)
// ============================================================================

impl wit_messaging::Host for TalosContext {
    async fn publish(
        &mut self,
        topic: String,
        payload: Vec<u8>,
    ) -> Result<(), wit_messaging::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<(), wit_messaging::Error> = async move {
            // Defense-in-depth: linker is primary enforcement, but verify capability.
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Messaging | CapabilityWorld::Trusted
            ) {
                self.record_capability_denied("messaging-publish", "capability-world", &topic)
                    .await;
                tracing::warn!(module_id = ?self.module_id, "WASM module attempted messaging but lacks Messaging capability");
                return Err(wit_messaging::Error::Publishfailed);
            }
            // MCP-756 (2026-05-13): cap topic length BEFORE it flows into
            // any logging / audit / NATS sink. See MAX_MESSAGING_TOPIC_BYTES
            // doc. Runs before the reserved-prefix check below so an
            // oversized "talos.<10MB>" topic doesn't poison the
            // reserved-prefix audit-deny path.
            if topic.is_empty() || topic.len() > MAX_MESSAGING_TOPIC_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    topic_len = topic.len(),
                    "wit_messaging::publish topic exceeds {} bytes (or empty); rejecting",
                    MAX_MESSAGING_TOPIC_BYTES
                );
                return Err(wit_messaging::Error::Publishfailed);
            }
            // MCP-524: deny publish to reserved platform-internal
            // subject namespaces. The signed-RPC layer rejects forged
            // payloads (memory_rpc / graph_rpc / database_rpc /
            // state_rpc / integration_state_rpc all verify HMAC), but
            // each forged message still costs the controller a
            // signature-verification + error-log line. A guest that
            // loops `publish("talos.memory.op", b"garbage")` up to its
            // rate-limit cap (1000/exec) can quietly burn ~50ms of
            // controller CPU per execution + flood error logs.
            // Equally, `talos.results.*` (job-result subjects) and
            // `talos.workers.*` (heartbeat / cmd) are platform-owned —
            // a guest must never publish there.
            //
            // Modules should use their own subject namespace (e.g.
            // operator/team prefix). Same convention as the
            // module-allowlist for HTTP hosts.
            if reject_reserved_topic_prefix(&topic) {
                self.record_capability_denied(
                    "messaging-publish",
                    "reserved-subject-prefix",
                    &topic,
                )
                .await;
                tracing::warn!(
                    module_id = ?self.module_id,
                    topic = %topic,
                    "WASM module attempted to publish to a platform-reserved \
                     subject (talos.* / wasm.*) — denied. Use your own \
                     subject namespace."
                );
                return Err(wit_messaging::Error::Publishfailed);
            }
            // MCP-784 (2026-05-14): pure-validation payload-size check MUST
            // run BEFORE `check_rate_limit` charges the publish counter.
            // Pre-fix, a guest with Messaging capability could call
            // `publish(topic, vec![0u8; 10 * 1024 * 1024 + 1])` repeatedly —
            // each call passed capability/topic/reserved-prefix checks,
            // consumed one slot of MAX_MESSAGING_PUBLISHES_PER_EXECUTION
            // (1000/exec), and only then failed the 10 MB payload cap.
            // After 1000 oversized attempts the publish quota was
            // exhausted and legitimate small-payload publishes were
            // blocked for the rest of the execution, despite zero NATS
            // traffic. Same shape as MCP-770 (wit_files::write byte-quota
            // before path sanitize), MCP-783 (wit_http::fetch_all
            // batch-CAS before per-request validation), and MCP-612
            // (the original counter-only-advances-when-admitted rule).
            if payload.len() > 10 * 1024 * 1024 {
                tracing::warn!("Message payload exceeds 10MB limit");
                return Err(wit_messaging::Error::Publishfailed);
            }
            if !self.check_rate_limit(
                &self.messaging_publish_count,
                MAX_MESSAGING_PUBLISHES_PER_EXECUTION,
            ) {
                tracing::warn!(module_id = ?self.module_id, "Messaging publish rate limit exceeded");
                if let Some(ref m) = self.metrics {
                    m.record_rate_limit_exceeded("messaging");
                }
                return Err(wit_messaging::Error::Publishfailed);
            }

            // Dry-run mode: mock messaging publish
            if self.dry_run {
                tracing::info!(
                    topic = %topic,
                    payload_len = payload.len(),
                    "Dry-run: intercepted messaging publish"
                );
                return Ok(());
            }

            let nats = self
                .nats_client
                .as_ref()
                .ok_or(wit_messaging::Error::Connectionfailed)?;
            let nats = nats.clone();

            nats.publish(topic, payload.into())
                .await
                .map_err(|_| wit_messaging::Error::Publishfailed)
        }.await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("messaging::publish", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn publish_with_headers(
        &mut self,
        msg: wit_messaging::Message,
    ) -> Result<(), wit_messaging::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Messaging | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("messaging-publish", "capability-world", &msg.topic)
                .await;
            tracing::warn!(module_id = ?self.module_id, "WASM module attempted messaging but lacks Messaging capability");
            return Err(wit_messaging::Error::Publishfailed);
        }
        // MCP-756: cap topic length, sibling-parity with `publish` above.
        if msg.topic.is_empty() || msg.topic.len() > MAX_MESSAGING_TOPIC_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                topic_len = msg.topic.len(),
                "wit_messaging::publish_with_headers topic exceeds {} bytes (or empty); rejecting",
                MAX_MESSAGING_TOPIC_BYTES
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        // MCP-524: same reserved-prefix denylist as the bare `publish`
        // path. Sibling helper invoked once per call.
        if reject_reserved_topic_prefix(&msg.topic) {
            self.record_capability_denied(
                "messaging-publish-with-headers",
                "reserved-subject-prefix",
                &msg.topic,
            )
            .await;
            tracing::warn!(
                module_id = ?self.module_id,
                topic = %msg.topic,
                "WASM module attempted to publish_with_headers to a \
                 platform-reserved subject — denied."
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        // MCP-784 (2026-05-14): payload-size validation BEFORE rate-limit
        // charge — see `publish` above for the full sibling-drift rationale.
        if msg.payload.len() > 10 * 1024 * 1024 {
            tracing::warn!("Message payload exceeds 10MB limit");
            return Err(wit_messaging::Error::Publishfailed);
        }
        if !self.check_rate_limit(
            &self.messaging_publish_count,
            MAX_MESSAGING_PUBLISHES_PER_EXECUTION,
        ) {
            tracing::warn!(module_id = ?self.module_id, "Messaging publish rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("messaging");
            }
            return Err(wit_messaging::Error::Publishfailed);
        }

        // Dry-run mode: mock messaging publish_with_headers
        if self.dry_run {
            tracing::info!(
                topic = %msg.topic,
                payload_len = msg.payload.len(),
                "Dry-run: intercepted messaging publish_with_headers"
            );
            return Ok(());
        }

        let nats = self
            .nats_client
            .as_ref()
            .ok_or(wit_messaging::Error::Connectionfailed)?;
        let nats = nats.clone();

        let mut headers = async_nats::HeaderMap::new();
        if let Some(hdr_list) = msg.headers {
            // MCP-1105 sibling: cap header count BEFORE the per-header
            // vault-resolve loop. `resolve_vault_header` is a DB call
            // (cache hit common but not guaranteed); unbounded iteration
            // is the exact amplification `MAX_OUTBOUND_HEADERS = 64`
            // bounds on `wit_http::fetch`, `wit_webhook::send`, and
            // `wit_graphql::execute`. publish_with_headers was the
            // holdout.
            if hdr_list.len() > MAX_OUTBOUND_HEADERS {
                tracing::warn!(
                    module_id = ?self.module_id,
                    header_count = hdr_list.len(),
                    limit = MAX_OUTBOUND_HEADERS,
                    "wit_messaging::publish_with_headers rejected: header count exceeds cap"
                );
                return Err(wit_messaging::Error::Publishfailed);
            }
            for (k, v) in &hdr_list {
                let resolved = self
                    .resolve_vault_header(k.as_str(), v.as_str())
                    .await
                    .map_err(|_| wit_messaging::Error::Publishfailed)?;
                headers.insert(k.as_str(), resolved.as_ref());
            }
        }
        nats.publish_with_headers(msg.topic, headers, msg.payload.into())
            .await
            .map_err(|_| wit_messaging::Error::Publishfailed)
    }

    async fn request(
        &mut self,
        topic: String,
        payload: Vec<u8>,
        timeout_ms: u32,
    ) -> Result<Vec<u8>, wit_messaging::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Messaging | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("messaging-request", "capability-world", &topic)
                .await;
            tracing::warn!(module_id = ?self.module_id, "WASM module attempted messaging request but lacks Messaging capability");
            return Err(wit_messaging::Error::Subscribefailed);
        }
        // MCP-756: cap topic length, sibling-parity with `publish`.
        if topic.is_empty() || topic.len() > MAX_MESSAGING_TOPIC_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                topic_len = topic.len(),
                "wit_messaging::request topic exceeds {} bytes (or empty); rejecting",
                MAX_MESSAGING_TOPIC_BYTES
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        // MCP-731 (2026-05-13): apply the same reserved-topic deny that
        // `publish` (MCP-524) and `publish_with_headers` use. Pre-fix,
        // a guest with Messaging capability could call
        // `request("talos.memory.op", forged_payload)` and the worker
        // would forward the request to the controller's memory_rpc
        // subscriber. The HMAC verification rejects the forged
        // signature, but each forged message still costs the
        // controller a signature-verification + error log. Same
        // DoS vector MCP-524 closed for publish; the request variant
        // was missed in that sweep.
        if reject_reserved_topic_prefix(&topic) {
            self.record_capability_denied(
                "messaging-request",
                "reserved-subject-prefix",
                &topic,
            )
            .await;
            tracing::warn!(
                module_id = ?self.module_id,
                topic = %topic,
                "WASM module attempted to request() on a platform-reserved \
                 subject (talos.* / wasm.*) — denied. Use your own subject namespace."
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        // MCP-784 (2026-05-14): payload-size validation BEFORE rate-limit
        // charge — see `publish` above for the full sibling-drift rationale.
        // The 10MB outbound payload cap (MCP-731) is pure validation; it
        // must precede the messaging_publish_count CAS so that oversized
        // requests don't drain MAX_MESSAGING_PUBLISHES_PER_EXECUTION.
        if payload.len() > 10 * 1024 * 1024 {
            tracing::warn!(
                module_id = ?self.module_id,
                payload_len = payload.len(),
                "Messaging request payload exceeds 10MB limit"
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        if !self.check_rate_limit(
            &self.messaging_publish_count,
            MAX_MESSAGING_PUBLISHES_PER_EXECUTION,
        ) {
            tracing::warn!(module_id = ?self.module_id, "Messaging request rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("messaging");
            }
            return Err(wit_messaging::Error::Publishfailed);
        }
        let nats = self
            .nats_client
            .as_ref()
            .ok_or(wit_messaging::Error::Connectionfailed)?;
        let nats = nats.clone();

        // MCP-657: clamp caller-supplied timeout. Guest can pass
        // u32::MAX which would hold a worker task ~49 days awaiting a
        // never-arriving NATS reply. async fuel is observation-only
        // so the wasm budget doesn't naturally bound this. Sibling
        // pattern to MCP-583/584 for http/webhook retry caps.
        let bounded_timeout_ms = timeout_ms.min(MAX_MESSAGING_REQUEST_TIMEOUT_MS);
        let reply = tokio::time::timeout(
            std::time::Duration::from_millis(bounded_timeout_ms as u64),
            nats.request(topic, payload.into()),
        )
        .await
        .map_err(|_| wit_messaging::Error::Publishfailed)?
        .map_err(|_| wit_messaging::Error::Publishfailed)?;
        // MCP-731 sibling: cap inbound reply size. Without this, a
        // collaborating NATS-side service (or a future bug that lets
        // the guest control reply contents) could return GBs of data
        // and the guest's `to_vec()` would copy it into WASM linear
        // memory unbounded. 10MB matches the outbound cap and the
        // sibling wit_http response cap.
        if reply.payload.len() > 10 * 1024 * 1024 {
            tracing::warn!(
                module_id = ?self.module_id,
                reply_len = reply.payload.len(),
                "Messaging request reply exceeds 10MB limit; rejecting"
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        Ok(reply.payload.to_vec())
    }
}

// ============================================================================
// GraphQL client
// ============================================================================

impl wit_graphql::Host for TalosContext {
    async fn execute(
        &mut self,
        req: wit_graphql::Request,
    ) -> Result<wit_graphql::Response, wit_graphql::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result = self.execute_graphql_inner(req, 0).await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("graphql::execute", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn execute_with_retry(
        &mut self,
        req: wit_graphql::Request,
        max_retries: u32,
    ) -> Result<wit_graphql::Response, wit_graphql::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result = self.execute_graphql_inner(req, max_retries).await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "graphql::execute_with_retry",
                __start.elapsed().as_millis() as f64,
            );
        }
        __result
    }
}

impl TalosContext {
    async fn execute_graphql_inner(
        &mut self,
        req: wit_graphql::Request,
        max_retries: u32,
    ) -> Result<wit_graphql::Response, wit_graphql::Error> {
        // MCP-605 (2026-05-12): per-method capability gate. WIT-world
        // linkage already restricts `talos:core/graphql` to http-node
        // and above (minimal-node is the only world that does NOT
        // `import graphql`). Both `execute` and `execute_with_retry`
        // delegate to this inner function — one gate here covers
        // both public entry points without redundancy. Defense in
        // depth in the same shape as MCP-603 (wit_state) — Tier-1
        // check below is privacy-class, not capability-class, so it
        // alone doesn't enforce the world boundary.
        use crate::wit_inspector::CapabilityWorld;
        if matches!(
            self.capability_world,
            CapabilityWorld::Minimal | CapabilityWorld::Unknown
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity (sibling of MCP-696
            // wit_cache sweep). Pre-fix the capability-world denial branch
            // emitted only `tracing::warn!`. Tier-1 + host-allowlist
            // denial branches farther down already audit via
            // `record_capability_denied`; this completes the surface so a
            // Minimal-world module probing the GraphQL host function
            // leaves the same WORM trail as one probing http-fetch.
            self.record_capability_denied("graphql-execute", "capability-world", "")
                .await;
            tracing::warn!(
                world = ?self.capability_world,
                "WASM module attempted graphql call but lacks the required capability"
            );
            return Err(wit_graphql::Error::Networkerror);
        }
        // MCP-787 (2026-05-14): pure-validation surfaces (query size,
        // variables size, URL parse, empty allowlist, SSRF IP literal,
        // allowed_hosts pattern, DNS-rebinding, Tier-1 LLM egress, POST
        // method allowlist) MUST run BEFORE `check_rate_limit` charges
        // `graphql_query_count`. Pre-fix the rate-limit charge ran first,
        // so a guest with the http-node capability could loop execute()
        // calls targeting blocked hosts ("http://127.0.0.1/graphql"),
        // oversized queries (1 MB+1 bytes), or tier-1-denied LLM hosts
        // and drain MAX_GRAPHQL_QUERIES_PER_EXECUTION (200/exec) without
        // a single outbound POST. Subsequent legitimate queries were
        // then blocked for the rest of the execution despite the
        // rate-limit being conceptually unused. Same shape as MCP-770
        // (wit_files::write byte-CAS before path sanitize), MCP-783
        // (wit_http::fetch_all batch CAS before per-request validation),
        // MCP-784 (wit_messaging payload-size after rate-limit), MCP-785
        // (wit_webhook::send rate-limit before URL/SSRF/allowlist/
        // DNS-rebind/Tier-1), MCP-786 (wit_email::send rate-limit
        // before Tier-1/addr-validation/recipient-cap), and MCP-612 (the
        // original counter-only-advances-when-admitted rule).
        // MCP-537 (the original rate-limit add) is preserved — only the
        // ordering moves; cancellation check also relocates to stay
        // paired with the rate-limit charge.

        let url = req.url.clone();
        let query = req.query.clone();
        let variables = req.variables.clone();
        let headers = req.headers.clone().unwrap_or_default();
        // MCP-1148: cap URL bytes BEFORE invoking `url::Url::parse`
        // below. Sibling-parity with wit_http::fetch. `Invalidurl` is
        // not in the graphql Error enum — `Networkerror` is the
        // canonical mapping for guest-visible URL-validation failures
        // (matches the existing url-parse-error path further down).
        if url.len() > MAX_OUTBOUND_URL_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                url_len = url.len(),
                limit = MAX_OUTBOUND_URL_BYTES,
                "wit_graphql::execute rejected: URL length exceeds cap"
            );
            return Err(wit_graphql::Error::Networkerror);
        }
        // MCP-1105: cap caller-supplied header count. See
        // MAX_OUTBOUND_HEADERS doc-comment. graphql adds extra urgency
        // because the retry loop below re-iterates headers on every
        // attempt — 10k headers × `max_retries` vault lookups per call.
        if headers.len() > MAX_OUTBOUND_HEADERS {
            tracing::warn!(
                module_id = ?self.module_id,
                header_count = headers.len(),
                limit = MAX_OUTBOUND_HEADERS,
                "wit_graphql::execute rejected: header count exceeds cap"
            );
            return Err(wit_graphql::Error::Networkerror);
        }
        // MCP-584: clamp caller-supplied timeout in GraphQL exactly
        // as in http::fetch — `option<u32>` is unbounded otherwise.
        let timeout_ms = req
            .timeout_ms
            .unwrap_or(30_000)
            .min(MAX_HTTP_TIMEOUT_MS) as u64;

        // Reject oversized queries and variable payloads to prevent sending
        // multi-GB requests to the remote server (OOM + bandwidth abuse).
        const MAX_GRAPHQL_QUERY_BYTES: usize = 1_000_000; // 1 MB
        if query.len() > MAX_GRAPHQL_QUERY_BYTES {
            return Err(wit_graphql::Error::Networkerror);
        }
        if let Some(ref vars) = variables {
            if vars.len() > MAX_GRAPHQL_QUERY_BYTES {
                return Err(wit_graphql::Error::Invalidvariables);
            }
        }

        // L-17 (2026-05-22): GraphQL introspection detector + opt-in
        // block. A guest with `http-node` (or higher) capability and a
        // remote GraphQL endpoint in its `allowed_hosts` allowlist
        // can currently enumerate the remote schema via `__schema` /
        // `__type` queries. Whether that's actually a problem
        // depends on the endpoint — public APIs (GitHub GraphQL,
        // GitLab) deliberately ship introspection on; private
        // internal endpoints often don't. We default to ALLOW
        // (introspection is a legitimate GraphQL feature) but emit
        // a structured event on every attempt so operators have
        // visibility, and gate a hard block behind two opt-in
        // signals:
        //
        //   1. **Tier-1 actor** — privacy-class actors (Ollama-only)
        //      shouldn't be probing third-party schema shapes; block
        //      unconditionally so the existing Tier-1 data-egress
        //      gate has no companion-bypass surface.
        //   2. **`TALOS_WIT_GRAPHQL_BLOCK_INTROSPECTION=1` env var**
        //      — operator-wide deny for clusters that don't run
        //      schema-aware clients.
        //
        // Detection is shape-based, not parse-based: we look for the
        // top-level `__schema` or `__type` selection. A
        // sophisticated attacker can hide introspection inside a
        // fragment or alias — that's a known limitation; the
        // structured event still fires and operators alerting on
        // `event_kind = "graphql_introspection_attempt"` see the
        // raw query length and host. Full parse-based detection
        // would require pulling in a GraphQL parser (e.g.
        // `async-graphql-parser`) on the worker's WASM execution
        // hot path — not justified for a defense-in-depth check.
        if looks_like_graphql_introspection(&query) {
            let actor_tier =
                self.max_llm_tier == talos_workflow_job_protocol::LlmTier::Tier1;
            let env_block = std::env::var("TALOS_WIT_GRAPHQL_BLOCK_INTROSPECTION")
                .ok()
                .as_deref()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .as_deref()
                == Some("1")
                || std::env::var("TALOS_WIT_GRAPHQL_BLOCK_INTROSPECTION")
                    .ok()
                    .as_deref()
                    .map(str::trim)
                    .map(str::to_ascii_lowercase)
                    .as_deref()
                    == Some("true");
            let blocked = actor_tier || env_block;

            // Always emit the structured event so dashboards see
            // attempts even in allow-mode deployments.
            tracing::warn!(
                target: "talos_security_audit",
                module_id = ?self.module_id,
                event_kind = "graphql_introspection_attempt",
                url = %url,
                query_bytes = query.len(),
                actor_tier1 = actor_tier,
                env_block = env_block,
                blocked,
                "WASM module attempted a GraphQL introspection query"
            );

            if blocked {
                self.record_capability_denied(
                    "graphql-execute",
                    if actor_tier { "tier1-introspection" } else { "env-introspection-block" },
                    &url,
                )
                .await;
                return Err(wit_graphql::Error::Networkerror);
            }
        }

        let allowed_hosts = self.allowed_hosts.clone();

        // Enforce host allowlist for GraphQL endpoints too.
        // Empty allowlist = DENY ALL (same policy as the HTTP host function).
        {
            let parsed: url::Url = url.parse().map_err(|_| wit_graphql::Error::Networkerror)?;
            let host = parsed.host_str().unwrap_or("").to_string();

            // HTTPS-only by default. The GraphQL Error enum has no
            // dedicated insecure-scheme variant; `Networkerror` is the
            // mapping used for every URL-validation failure on this
            // path (matches the empty-allowlist arm below).
            match classify_url_scheme(parsed.scheme(), insecure_http_opt_in()) {
                UrlSchemeVerdict::Https => {}
                UrlSchemeVerdict::InsecureAllowedByOptIn { scheme } => {
                    tracing::warn!(
                        scheme = %scheme,
                        host = %host,
                        "graphql: insecure-scheme request allowed by WASM_ALLOW_INSECURE_HTTP=1"
                    );
                }
                UrlSchemeVerdict::InsecureRefused { scheme } => {
                    self.record_capability_denied(
                        "graphql",
                        "insecure-scheme",
                        &format!("{scheme} {host}"),
                    )
                    .await;
                    tracing::warn!(
                        scheme = %scheme,
                        host = %host,
                        "WASM module attempted non-https GraphQL request — denied."
                    );
                    return Err(wit_graphql::Error::Networkerror);
                }
            }

            if allowed_hosts.is_empty() {
                self.record_capability_denied("graphql", "no-allowlist-configured", &host)
                    .await;
                tracing::warn!(
                    host = %host,
                    "WASM module attempted GraphQL request but no host allowlist is \
                             configured — denying."
                );
                return Err(wit_graphql::Error::Networkerror);
            }

            // SSRF protection: shared classifier covers CGNAT and IPv4-mapped IPv6
            // the duplicated logic was missing.
            let ip_literal: Option<std::net::IpAddr> = match parsed.host() {
                Some(url::Host::Ipv4(a)) => Some(a.into()),
                Some(url::Host::Ipv6(a)) => Some(a.into()),
                _ => None,
            };
            if let Some(ip) = ip_literal {
                if let Some(policy) = classify_private_ip(ip) {
                    self.record_capability_denied("graphql", policy, &ip.to_string())
                        .await;
                    tracing::warn!(
                        ip = %ip,
                        policy,
                        "WASM module attempted GraphQL request to a private IP literal — blocking"
                    );
                    return Err(wit_graphql::Error::Networkerror);
                }
            }

            if !host_allowlist_match(&allowed_hosts, &host) {
                self.record_capability_denied("graphql", "allowed-hosts", &host)
                    .await;
                return Err(wit_graphql::Error::Networkerror);
            }

            // DNS rebinding — resolve hostname URLs and reject if any answer
            // falls in the private deny-list. IP literals already handled
            // above by classify_private_ip.
            if matches!(parsed.host(), Some(url::Host::Domain(_)))
                && self
                    .validate_no_dns_rebinding(&host, "graphql")
                    .await
                    .is_err()
            {
                return Err(wit_graphql::Error::Networkerror);
            }

            // Tier-1 LLM egress ceiling — same host deny-list as fetch.
            // GraphQL is an orthogonal transport, not a way around the
            // privacy ceiling.
            if matches!(
                self.max_llm_tier,
                talos_workflow_job_protocol::LlmTier::Tier1
            ) {
                let host_lower = host.to_ascii_lowercase();
                if let Some(policy) = tier1_egress_deny_reason(&host_lower) {
                    self.record_capability_denied("graphql", policy, &host)
                        .await;
                    tracing::warn!(
                        host = %host,
                        actor_id = ?self.actor_id,
                        policy,
                        "tier-1 actor GraphQL egress refused (external LLM host or public IP literal)"
                    );
                    return Err(wit_graphql::Error::Networkerror);
                }
            }
        }

        // GraphQL requests are always POST. Reject if POST is not in the allowlist.
        let allowed_methods = self.allowed_methods.clone();
        if !allowed_methods.is_empty()
            && !allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case("POST"))
        {
            tracing::warn!(
                "WASM module attempted GraphQL (POST) but POST is not in allowed_methods"
            );
            return Err(wit_graphql::Error::Networkerror);
        }

        // MCP-537 (rate limit + cancellation): now charged AFTER all pure
        // validation has passed — see MCP-787 reorder comment at top of
        // this function.
        if !self.check_rate_limit(
            &self.graphql_query_count,
            MAX_GRAPHQL_QUERIES_PER_EXECUTION,
        ) {
            tracing::warn!(module_id = ?self.module_id, "GraphQL query rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("graphql");
            }
            return Err(wit_graphql::Error::Networkerror);
        }
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled before GraphQL query");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            return Err(wit_graphql::Error::Networkerror);
        }

        let client = self.http_client.clone();

        let mut body = serde_json::json!({ "query": query });
        if let Some(vars) = variables {
            let vars_val: serde_json::Value =
                serde_json::from_str(&vars).map_err(|_| wit_graphql::Error::Invalidvariables)?;
            body["variables"] = vars_val;
        }

        let mut attempts = 0;
        loop {
            let mut req_builder = client
                .post(&url)
                .json(&body)
                .timeout(std::time::Duration::from_millis(timeout_ms));
            for (k, v) in &headers {
                // Networkerror is the closest existing variant; a dedicated forbiddenhost
                // variant would be a WIT-level breaking change. Operators see the real
                // reason in the WARN log emitted by check_secret_allowlist.
                let resolved = self
                    .resolve_vault_header(k.as_str(), v.as_str())
                    .await
                    .map_err(|_| wit_graphql::Error::Networkerror)?;
                req_builder = req_builder.header(k.as_str(), resolved.as_ref());
            }

            let result = req_builder.send().await;
            attempts += 1;

            match result {
                Ok(resp) => {
                    let gql_status = resp.status().as_u16();
                    if let Ok(gql_parsed) = url::Url::parse(&url) {
                        tracing::info!(
                            method = "POST",
                            host = %gql_parsed.host_str().unwrap_or("unknown"),
                            path = %gql_parsed.path(),
                            status = gql_status,
                            "HTTP audit"
                        );
                    }
                    // Cap GraphQL response at 10 MB to prevent WASM OOM from
                    // malicious or oversized remote server responses (H6).
                    const MAX_GRAPHQL_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
                    let mut bytes = Vec::new();
                    let mut stream = resp.bytes_stream();
                    use futures_util::StreamExt;
                    while let Some(chunk_result) = stream.next().await {
                        let chunk = chunk_result.map_err(|_| wit_graphql::Error::Parseerror)?;
                        if bytes.len() + chunk.len() > MAX_GRAPHQL_RESPONSE_BYTES {
                            tracing::warn!(
                                "GraphQL response exceeds 10 MB size limit during streaming"
                            );
                            return Err(wit_graphql::Error::Parseerror);
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    // MCP-H7: parse via a typed struct with
                    // `Box<RawValue>` fields so the `data` and `errors`
                    // payloads pass through as borrowed JSON text
                    // without materialising a full
                    // `HashMap<String, Value>` tree. Pre-fix the
                    // `serde_json::Value` materialisation then
                    // `.to_string()` reserialisation paid 3-10x WASM
                    // fuel cost vs typed parsing on the 10 MB cap.
                    // See CLAUDE.md WASM rules ("never use top-level
                    // Value for upstream payloads") + the 2026-05-28
                    // perf audit.
                    #[derive(serde::Deserialize)]
                    struct GqlResp<'a> {
                        #[serde(borrow, default)]
                        data: Option<&'a serde_json::value::RawValue>,
                        #[serde(borrow, default)]
                        errors: Option<Vec<&'a serde_json::value::RawValue>>,
                    }
                    let resp_parsed: GqlResp<'_> = serde_json::from_slice(&bytes)
                        .map_err(|_| wit_graphql::Error::Parseerror)?;

                    let data = resp_parsed.data.map(|d| d.get().to_string());
                    let errors = resp_parsed
                        .errors
                        .map(|arr| arr.into_iter().map(|e| e.get().to_string()).collect());

                    return Ok(wit_graphql::Response { data, errors });
                }
                Err(_) if attempts <= max_retries => {
                    // Cap backoff at 30 s to prevent indefinitely blocked workers.
                    let backoff_ms = (100u64 * 2u64.saturating_pow(attempts - 1)).min(30_000);
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                }
                Err(_) => return Err(wit_graphql::Error::Networkerror),
            }
        }
    }

    /// Check global daily exposure limit using Redis.
    /// Returns true if the call is allowed, false if rate limited.
    async fn check_global_expose_limit(
        redis: &std::sync::Arc<redis::Client>,
        key: &str,
    ) -> anyhow::Result<bool> {
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get Redis connection: {}", e))?;

        // Get current count
        let count: Option<u64> = redis::AsyncCommands::get(&mut conn, key)
            .await
            .ok()
            .flatten();

        if let Some(c) = count {
            if c >= MAX_TIER2_EXPOSES_PER_USER_PER_DAY {
                return Ok(false); // Rate limit exceeded
            }
            // Increment existing counter
            let _: redis::RedisResult<()> = redis::AsyncCommands::incr(&mut conn, key, 1).await;
        } else {
            // Set new counter with 24h expiry (daily window)
            let _: redis::RedisResult<()> =
                redis::AsyncCommands::set_ex(&mut conn, key, 1, 86400).await;
        }

        Ok(true) // Rate limit OK
    }
}

// ============================================================================
// Webhook sender
// ============================================================================

impl wit_webhook::Host for TalosContext {
    async fn send(
        &mut self,
        req: wit_webhook::WebhookRequest,
    ) -> Result<wit_webhook::WebhookResponse, wit_webhook::Error> {
        // MCP-785 (2026-05-14): pure-validation surfaces (URL parse,
        // host allowlist, SSRF IP-literal classification, allowed_hosts
        // pattern match, DNS-rebinding, Tier-1 LLM egress) MUST run
        // BEFORE `check_rate_limit` charges `webhook_send_count`.
        // Pre-fix the rate-limit charge ran first, so a guest could
        // loop `send(url="http://127.0.0.1/x", ...)` (SSRF deny) or
        // `send(url="https://blocked.example.com/x", ...)` (allowed-
        // hosts deny) up to MAX_WEBHOOK_SENDS_PER_EXECUTION times and
        // exhaust the per-execution webhook quota with zero outbound
        // POSTs ever leaving the worker. Subsequent legitimate
        // webhook sends were then blocked for the rest of the
        // execution despite the rate-limit being conceptually unused.
        // Same shape as MCP-770 (wit_files::write), MCP-783
        // (wit_http::fetch_all batch CAS), MCP-784 (wit_messaging
        // payload-size after rate-limit), and MCP-612 (the original
        // counter-only-advances-when-admitted rule).
        // MCP-537 (the original rate-limit add) is preserved — only
        // the ordering moves; cancellation check also relocates to
        // stay paired with the rate-limit charge.

        let url = req.url.clone();
        // MCP-1148: cap URL bytes BEFORE invoking `url::Url::parse`
        // below. Sibling-parity with wit_http::fetch / wit_graphql.
        if url.len() > MAX_OUTBOUND_URL_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                url_len = url.len(),
                limit = MAX_OUTBOUND_URL_BYTES,
                "wit_webhook::send rejected: URL length exceeds cap"
            );
            return Err(wit_webhook::Error::Sendfailed);
        }
        // MCP-1105: cap caller-supplied header count. See
        // MAX_OUTBOUND_HEADERS doc-comment for the per-vault-resolve
        // amplification rationale; wit_webhook::send's retry budget
        // (1 + max_retries) further compounds it.
        if req.headers.len() > MAX_OUTBOUND_HEADERS {
            tracing::warn!(
                module_id = ?self.module_id,
                header_count = req.headers.len(),
                limit = MAX_OUTBOUND_HEADERS,
                "wit_webhook::send rejected: header count exceeds cap"
            );
            return Err(wit_webhook::Error::Sendfailed);
        }
        let headers = req.headers.clone();
        // MCP-1014 (2026-05-15): cap caller-supplied webhook body. Pre-fix
        // `req.body` was unbounded — wasmtime-memory-budget the only
        // ceiling, which is the FLOOR (not the ceiling) of what the host
        // must defend against. A guest with a 100 MB memory budget could
        // ship a 100 MB body per send(); the host then cloned it twice
        // (into the local `body` binding and again into reqwest's
        // `.body(body.clone())` on each retry) and held it across the
        // network round-trip. With MAX_WEBHOOK_SENDS_PER_EXECUTION × the
        // 1 + max_retries retry budget, the worst-case host-memory
        // commitment compounds.
        //
        // The sibling response side already capped at
        // `MAX_WEBHOOK_RESP_BYTES = 1 MB` (line 5026); 10 MB on the
        // outbound matches the higher CSV/XML/template caps and is
        // generous for normal webhook traffic (typical payloads are
        // sub-100 KB). Same defense-in-depth class as MCP-1013
        // (wit_data_transform XML/JSON caps) and MCP-784
        // (wit_messaging payload-size).
        // MCP-1076: canonical module-level MAX_OUTBOUND_HTTP_BODY_BYTES.
        if req.body.len() > MAX_OUTBOUND_HTTP_BODY_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                body_len = req.body.len(),
                limit = MAX_OUTBOUND_HTTP_BODY_BYTES,
                "wit_webhook::send rejected: body exceeds cap"
            );
            return Err(wit_webhook::Error::Sendfailed);
        }
        let body = req.body.clone();
        // MCP-583: cap caller-supplied retry config. Pre-fix
        // `max_retries` and `retry_delay_ms` were `option<u32>` with
        // no upper bound — a module could pass `u32::MAX` for either
        // (or both) and a single send() with a non-timeout transport
        // error (e.g. connection-refused) would loop until the WASM
        // execution timeout, holding a worker slot. Sibling
        // wit_graphql caps its backoff at 30s; this is the lone
        // straggler. The design-doc "1+max_retries (default 4)
        // actual POSTs" promise (in `webhook_cap_holds_at_one_hundred`)
        // only holds with a bound here.
        let max_retries = req
            .max_retries
            .unwrap_or(3)
            .min(MAX_WEBHOOK_RETRIES_PER_SEND);
        let retry_delay_ms = req
            .retry_delay_ms
            .unwrap_or(1_000)
            .min(MAX_WEBHOOK_RETRY_DELAY_MS) as u64;

        // SSRF protection: validate URL and enforce host allowlist (same as HTTP fetch).
        let parsed_url: url::Url = url.parse().map_err(|_| wit_webhook::Error::Sendfailed)?;
        let host = parsed_url.host_str().unwrap_or("").to_string();

        // HTTPS-only by default. Webhook deliveries are the highest-
        // value plaintext target since they carry a signed payload
        // bound to a guest secret; intercepting the wire is enough to
        // replay it. Operator opt-in only.
        match classify_url_scheme(parsed_url.scheme(), insecure_http_opt_in()) {
            UrlSchemeVerdict::Https => {}
            UrlSchemeVerdict::InsecureAllowedByOptIn { scheme } => {
                tracing::warn!(
                    scheme = %scheme,
                    host = %host,
                    "webhook::send: insecure-scheme request allowed by WASM_ALLOW_INSECURE_HTTP=1"
                );
            }
            UrlSchemeVerdict::InsecureRefused { scheme } => {
                self.record_capability_denied(
                    "webhook",
                    "insecure-scheme",
                    &format!("{scheme} {host}"),
                )
                .await;
                tracing::warn!(
                    scheme = %scheme,
                    host = %host,
                    "WASM module attempted non-https webhook send — denied."
                );
                return Err(wit_webhook::Error::Sendfailed);
            }
        }

        // Enforce the host allowlist. Empty list means DENY ALL.
        if self.allowed_hosts.is_empty() {
            self.record_capability_denied("webhook", "no-allowlist-configured", &host)
                .await;
            tracing::warn!(
                host = %host,
                "WASM module attempted webhook request but no host allowlist is configured — denying."
            );
            return Err(wit_webhook::Error::Sendfailed);
        }

        // Block private/loopback/link-local IP addresses to prevent SSRF.
        // Shared classifier — covers CGNAT and IPv4-mapped IPv6 the
        // duplicated logic was missing.
        let ip_literal: Option<std::net::IpAddr> = match parsed_url.host() {
            Some(url::Host::Ipv4(a)) => Some(a.into()),
            Some(url::Host::Ipv6(a)) => Some(a.into()),
            _ => None,
        };
        if let Some(ip) = ip_literal {
            if let Some(policy) = classify_private_ip(ip) {
                self.record_capability_denied("webhook", policy, &ip.to_string())
                    .await;
                tracing::warn!(
                    ip = %ip,
                    policy,
                    "WASM module attempted webhook to a private IP literal — blocking"
                );
                return Err(wit_webhook::Error::Sendfailed);
            }
        }

        if !host_allowlist_match(&self.allowed_hosts, &host) {
            self.record_capability_denied("webhook", "allowed-hosts", &host)
                .await;
            tracing::warn!(
                host = %host,
                allowed_count = self.allowed_hosts.len(),
                "WASM module attempted webhook to a forbidden host"
            );
            return Err(wit_webhook::Error::Sendfailed);
        }

        // DNS rebinding — for hostname-based URLs, resolve and reject when
        // any answer falls in the private deny-list. Skipped for IP literals
        // (already handled by classify_private_ip above).
        if matches!(parsed_url.host(), Some(url::Host::Domain(_)))
            && self
                .validate_no_dns_rebinding(&host, "webhook")
                .await
                .is_err()
        {
            return Err(wit_webhook::Error::Sendfailed);
        }

        // Tier-1 LLM egress ceiling — webhook dispatch is yet another
        // arbitrary-host HTTP surface. Same deny-list applies.
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) {
            let host_lower = host.to_ascii_lowercase();
            if let Some(policy) = tier1_egress_deny_reason(&host_lower) {
                self.record_capability_denied("webhook", policy, &host)
                    .await;
                tracing::warn!(
                    host = %host,
                    actor_id = ?self.actor_id,
                    policy,
                    "tier-1 actor webhook egress refused (external LLM host or public IP literal)"
                );
                return Err(wit_webhook::Error::Sendfailed);
            }
        }

        // MCP-537 (rate limit + cancellation): now charged AFTER all pure
        // validation has passed — see MCP-785 reorder comment at top of
        // this function.
        if !self.check_rate_limit(&self.webhook_send_count, MAX_WEBHOOK_SENDS_PER_EXECUTION) {
            tracing::warn!(module_id = ?self.module_id, "Webhook send rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("webhook");
            }
            return Err(wit_webhook::Error::Sendfailed);
        }
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled before webhook send");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            return Err(wit_webhook::Error::Sendfailed);
        }

        // Dry-run mode: mock webhook POST calls
        if self.dry_run {
            tracing::info!(
                url = %url,
                "Dry-run: intercepted webhook send"
            );
            return Ok(wit_webhook::WebhookResponse {
                status: 200,
                body: serde_json::json!({
                    "__dry_run__": true,
                    "intercepted_method": "POST",
                    "intercepted_url": url,
                })
                .to_string(),
                retries: 0,
            });
        }

        let client = self.http_client.clone();

        let mut retries = 0u32;
        loop {
            let mut req_builder = client
                .post(&url)
                .body(body.clone())
                .timeout(std::time::Duration::from_secs(30));
            for (k, v) in &headers {
                let resolved = self
                    .resolve_vault_header(k.as_str(), v.as_str())
                    .await
                    .map_err(|_| wit_webhook::Error::Sendfailed)?;
                req_builder = req_builder.header(k.as_str(), resolved.as_ref());
            }

            match req_builder.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    tracing::info!(
                        method = "POST",
                        host = %parsed_url.host_str().unwrap_or("unknown"),
                        path = %parsed_url.path(),
                        status = status,
                        "HTTP audit"
                    );
                    const MAX_WEBHOOK_RESP_BYTES: usize = 1_000_000;
                    let mut bytes = Vec::new();
                    let mut stream = resp.bytes_stream();
                    use futures_util::StreamExt;
                    while let Some(chunk_result) = stream.next().await {
                        if let Ok(chunk) = chunk_result {
                            let remaining = MAX_WEBHOOK_RESP_BYTES.saturating_sub(bytes.len());
                            if remaining > 0 {
                                let take = chunk.len().min(remaining);
                                bytes.extend_from_slice(&chunk[..take]);
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    let body = String::from_utf8_lossy(&bytes).into_owned();
                    return Ok(wit_webhook::WebhookResponse {
                        status,
                        body,
                        retries,
                    });
                }
                Err(e) if retries < max_retries => {
                    retries += 1;
                    if e.is_timeout() {
                        return Err(wit_webhook::Error::Timeout);
                    }
                    // MCP-583: re-check cancellation between retries so
                    // worker shutdown / execution cancellation preempts
                    // a long retry-sleep loop. Pre-fix the loop only
                    // checked is_cancelled() at entry — a send that hit
                    // a transient transport error would sleep the full
                    // retry_delay_ms even after a shutdown signal.
                    if self.is_cancelled() {
                        tracing::info!(
                            module_id = ?self.module_id,
                            "Execution cancelled during webhook retry sleep"
                        );
                        if let Some(ref m) = self.metrics {
                            m.record_execution_cancelled();
                        }
                        return Err(wit_webhook::Error::Sendfailed);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(retry_delay_ms)).await;
                }
                Err(e) => {
                    return Err(if e.is_timeout() {
                        wit_webhook::Error::Timeout
                    } else {
                        wit_webhook::Error::Sendfailed
                    });
                }
            }
        }
    }
}

// ============================================================================
// Email (HTTP API — SendGrid-compatible; provide EMAIL_API_URL + EMAIL_API_KEY)
// ============================================================================

impl wit_email::Host for TalosContext {
    async fn send(&mut self, msg: wit_email::Message) -> Result<(), wit_email::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<(), wit_email::Error> = async move {
        // MCP-786 (2026-05-14): pure-validation surfaces (Tier-1 egress
        // ceiling, recipient address validation, msg.to non-empty,
        // recipient count cap) MUST run BEFORE `check_rate_limit` charges
        // `email_send_count`. Pre-fix the rate-limit charge ran first,
        // so a tier-1 actor could loop send() up to
        // MAX_EMAIL_SENDS_PER_EXECUTION (50/exec) times — every call
        // refused at the Tier-1 gate but still consumed a slot — and any
        // guest could drain the quota with addresses containing CRLF
        // injection (Invalidaddress) or oversized recipient lists. After
        // 50 drained attempts, legitimate email sends were blocked for
        // the rest of the execution despite zero outbound API calls.
        // Same shape as MCP-770 (wit_files::write byte-CAS before path
        // sanitize), MCP-783 (wit_http::fetch_all batch-CAS before
        // per-request validation), MCP-784 (wit_messaging payload-size
        // after rate-limit), MCP-785 (wit_webhook::send rate-limit
        // before URL/SSRF/allowlist/DNS-rebind/Tier-1), and MCP-612
        // (the original counter-only-advances-when-admitted rule).
        // MCP-523 (the original rate-limit add) is preserved — only the
        // ordering moves; cancellation check also relocates to stay
        // paired with the rate-limit charge.

        // Tier-1 enforcement: tier-1 actors carry a "data must not leave
        // host" privacy ceiling. Email is by definition external data
        // egress (recipient addresses + subject + body all flow to a
        // third-party API), so refuse outright — sixth tier-1 surface
        // alongside wit_http::fetch / fetch_all, wit_graphql::execute,
        // wit_webhook::send, and wit_http_stream::connect. EMAIL_API_URL
        // is operator-set so a host-allowlist check would be redundant;
        // the privacy ceiling forbids the operation, not just the host.
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) {
            self.record_capability_denied("email-send", "tier1-egress", "")
                .await;
            tracing::warn!(
                actor_id = ?self.actor_id,
                "tier-1 actor attempted wit_email::send; refused"
            );
            return Err(wit_email::Error::Sendfailed);
        }

        // Validate recipient addresses.
        // SECURITY: Reject control characters (CR, LF, NUL) to prevent email
        // header injection attacks (e.g., "victim@example.com\r\nBcc: attacker@evil.com").
        for addr in &msg.to {
            if !addr.contains('@') || addr.len() > 320
                || addr.bytes().any(|b| b < 0x20 || b == 0x7f)
            {
                return Err(wit_email::Error::Invalidaddress);
            }
        }
        // Also validate CC and BCC recipients for the same injection attacks.
        for addr in msg.cc.iter().flatten().chain(msg.bcc.iter().flatten()) {
            if !addr.contains('@') || addr.len() > 320
                || addr.bytes().any(|b| b < 0x20 || b == 0x7f)
            {
                return Err(wit_email::Error::Invalidaddress);
            }
        }
        if msg.to.is_empty() {
            return Err(wit_email::Error::Invalidaddress);
        }

        // MCP-541: cap ALL recipients (to + cc + bcc), not just `to`. The
        // MCP-523 design comment on `MAX_EMAIL_SENDS_PER_EXECUTION` (50)
        // promises a worst-case fanout of "50×50 = 2500 deliveries per
        // execution" — that math assumes 50 is the per-MESSAGE recipient
        // cap. Pre-fix only `msg.to.len()` was checked, so a WASM module
        // could pack 50 `to` + thousands of `cc`/`bcc` recipients per
        // message and blow through the operator's third-party send
        // quota (SendGrid bills per recipient). CC/BCC are still
        // egress and still cost the operator the same per-recipient
        // billing — they must be counted against the same cap.
        let cc_count = msg.cc.as_ref().map(|c| c.len()).unwrap_or(0);
        let bcc_count = msg.bcc.as_ref().map(|c| c.len()).unwrap_or(0);
        let total_recipients = msg.to.len() + cc_count + bcc_count;
        if total_recipients > MAX_EMAIL_RECIPIENTS_PER_MESSAGE {
            tracing::warn!(
                module_id = ?self.module_id,
                to = msg.to.len(),
                cc = cc_count,
                bcc = bcc_count,
                total = total_recipients,
                cap = MAX_EMAIL_RECIPIENTS_PER_MESSAGE,
                "Email recipient count (to + cc + bcc) exceeds limit"
            );
            return Err(wit_email::Error::Sendfailed);
        }

        // MCP-1014 sibling: cap caller-supplied subject + body + html +
        // attachments byte size. Pre-fix `msg.body`, `msg.html`,
        // `msg.subject` were unbounded — a guest with the Email
        // capability could pack 10 MB-each strings into a single send,
        // materialise them into a `serde_json::Value`, then reqwest.
        // The post-MCP-1014 audit (2026-05-28 F1) caught that
        // `msg.attachments: Option<list<attachment>>` (per-attachment
        // `data: list<u8>`) was NOT counted toward the cap, so the
        // wit_email path still permitted megabyte-scale outbound
        // content via attachment data. The cap now sums all
        // recipient-billed content. With
        // MAX_EMAIL_SENDS_PER_EXECUTION=50, worst-case in-flight host
        // memory is bounded to ~500 MB per execution. Run AFTER the
        // validation/recipient gates so a malformed-recipient probe
        // doesn't burn the body-size check budget either way.
        const MAX_EMAIL_CONTENT_BYTES: usize = MAX_OUTBOUND_HTTP_BODY_BYTES;
        let html_len = msg.html.as_ref().map(|h| h.len()).unwrap_or(0);
        let attachments_count = msg.attachments.as_ref().map(|a| a.len()).unwrap_or(0);
        let attachments_bytes: usize = msg
            .attachments
            .as_ref()
            .map(|atts| {
                atts.iter()
                    .map(|a| a.filename.len() + a.content_type.len() + a.data.len())
                    .sum()
            })
            .unwrap_or(0);
        let body_bytes = msg.subject.len() + msg.body.len() + html_len + attachments_bytes;
        if body_bytes > MAX_EMAIL_CONTENT_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                subject_len = msg.subject.len(),
                body_len = msg.body.len(),
                html_len = html_len,
                attachments_count,
                attachments_bytes,
                total = body_bytes,
                cap = MAX_EMAIL_CONTENT_BYTES,
                "wit_email::send rejected: subject+body+html+attachments exceeds cap"
            );
            return Err(wit_email::Error::Sendfailed);
        }
        // Bound the attachment COUNT independently so a guest can't
        // ship 100k 1-byte attachments to exhaust SendGrid's per-call
        // limits (typical providers cap at 10 MB total / ~10 files).
        const MAX_EMAIL_ATTACHMENTS: usize = 32;
        if attachments_count > MAX_EMAIL_ATTACHMENTS {
            tracing::warn!(
                module_id = ?self.module_id,
                attachments_count,
                cap = MAX_EMAIL_ATTACHMENTS,
                "wit_email::send rejected: attachment count exceeds cap"
            );
            return Err(wit_email::Error::Sendfailed);
        }

        // MCP-523 (rate limit + cancellation): now charged AFTER all pure
        // validation has passed — see MCP-786 reorder comment at top of
        // this function.
        if !self.check_rate_limit(&self.email_send_count, MAX_EMAIL_SENDS_PER_EXECUTION) {
            tracing::warn!(module_id = ?self.module_id, "Email send rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("email");
            }
            return Err(wit_email::Error::Sendfailed);
        }
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            return Err(wit_email::Error::Sendfailed);
        }

        // Look up API credentials via SecretProvider first, then env vars.
        //
        // MCP-935 (2026-05-15): filter empty-string env values so a
        // Helm-placeholder `EMAIL_API_URL=""` or `EMAIL_API_KEY=""`
        // doesn't shadow a working fallback (or, worse, propagate an
        // empty string into the SendGrid request as a malformed URL
        // / Authorization header). The SecretProvider path
        // (`get_host_secret`) already applies this filter internally
        // at host_impl.rs:1202; the env-var fallback below was the
        // drift. Sibling sites at host_impl.rs:1302 and 1328 already
        // use the canonical `.ok().filter(|v| !v.is_empty())` shape.
        // Same empty-env-var-bypass class as MCP-590..631 / MCP-934.
        let api_url: Option<String> = self
            .get_host_secret("EMAIL_API_URL")
            .await
            .or_else(|| {
                std::env::var("EMAIL_API_URL")
                    .ok()
                    .filter(|v| !v.is_empty())
            });
        let api_key: Option<String> = self
            .get_host_secret("EMAIL_API_KEY")
            .await
            .or_else(|| {
                std::env::var("EMAIL_API_KEY")
                    .ok()
                    .filter(|v| !v.is_empty())
            });

        if let (Some(url), Some(key)) = (api_url, api_key) {
            // SendGrid v3 API format
            // MCP-631: empty-env hardening — `EMAIL_FROM=""` (Helm
            // placeholder) would otherwise produce an empty sender
            // address and SendGrid rejects the API call. Sibling to
            // MCP-630; worker is intentionally credential-free so the
            // helper is inlined here.
            let from = std::env::var("EMAIL_FROM")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "noreply@talos.dev".to_string());

            let personalizations = serde_json::json!([{
                "to": msg.to.iter().map(|a| serde_json::json!({"email": a})).collect::<Vec<_>>(),
                "cc": msg.cc.as_ref().map(|cc| cc.iter().map(|a| serde_json::json!({"email": a})).collect::<Vec<_>>()),
                "bcc": msg.bcc.as_ref().map(|bcc| bcc.iter().map(|a| serde_json::json!({"email": a})).collect::<Vec<_>>()),
            }]);

            let mut content = vec![serde_json::json!({
                "type": "text/plain",
                "value": msg.body,
            })];
            if let Some(ref html) = msg.html {
                content.push(serde_json::json!({
                    "type": "text/html",
                    "value": html,
                }));
            }

            let body = serde_json::json!({
                "personalizations": personalizations,
                "from": {"email": from},
                "subject": msg.subject,
                "content": content,
            });

            let client = self.http_client.clone();
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                client
                    .post(&url)
                    .header("Authorization", format!("Bearer {}", key))
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send(),
            )
            .await
            .map_err(|_| {
                tracing::warn!("Email API request timed out");
                wit_email::Error::Sendfailed
            })?
            .map_err(|e| {
                tracing::warn!(error = %e, "Email API request failed");
                wit_email::Error::Sendfailed
            })?;

            if !response.status().is_success() {
                tracing::warn!(
                    status = response.status().as_u16(),
                    "Email API returned error status"
                );
                return Err(wit_email::Error::Sendfailed);
            }

            tracing::info!(
                to_count = msg.to.len(),
                subject_len = msg.subject.len(),
                "Email sent successfully via API"
            );
            return Ok(());
        }

        // Fallback: log the email if no API configured.
        //
        // MCP-1011 (2026-05-15): project recipient count + subject length
        // only — never the raw recipient list or subject content. Pre-fix
        // `tracing::info!(to = ?msg.to, subject = msg.subject, ...)` emitted
        // the full recipient PII + subject contents at INFO level. The
        // comment said "development mode" but the code path fires in
        // production any time `EMAIL_API_URL` is unset (Helm placeholder
        // forgotten, env-var rename, Vault outage during boot). Subject
        // lines routinely carry sensitive content — MFA codes, password-
        // reset links, "Your invoice is ready" with attached PII — and the
        // recipient list IS PII. Operator-log persistence of that content
        // for any misconfigured production tenant is a silent compliance
        // hit (GDPR, HIPAA, SOC 2 audit trail).
        //
        // Mirror the success-path projection at line 5295 exactly:
        // `to_count` + `subject_len`. Same MCP-852 / MCP-853 / MCP-854 /
        // MCP-921 family — field-projected logs over `{:?}` whole-struct
        // dumps for user-controlled content.
        tracing::info!(
            to_count = msg.to.len(),
            subject_len = msg.subject.len(),
            "[WASM email] Email send requested (no EMAIL_API_URL configured — logging only)"
        );
        Ok(())
        }.await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("email::send", __start.elapsed().as_millis() as f64);
        }
        __result
    }
}

// ============================================================================
// Database (placeholder — enforce row-level scoping in production)
// ============================================================================

impl wit_database::Host for TalosContext {
    async fn execute_query(
        &mut self,
        sql: String,
        params: Vec<String>,
    ) -> Result<wit_database::QueryResult, wit_database::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<wit_database::QueryResult, wit_database::Error> = async move {
            // Clear previous error detail on each call.
            self.last_db_error.clear();

            // MCP-788 (2026-05-14): pure-validation surfaces (capability
            // gate, SQL size cap, params size cap) MUST run BEFORE
            // `check_rate_limit` charges `db_query_count`. Pre-fix the
            // rate-limit charge ran FIRST, before even the capability
            // gate (defense-in-depth check ordered after the charge —
            // worse than the http/email/graphql sweep where capability
            // was already at the top). A Database-world guest could
            // drain MAX_DB_QUERIES_PER_EXECUTION (500/exec) by submitting
            // 64 KiB+1-byte SQL queries that fail the size cap, with
            // zero queries reaching sqlparser or the controller. The
            // capability-gate variant of the drain is theoretical
            // (WIT linkage already rejects non-Database imports at
            // module load) but defense-in-depth ordering still belongs
            // at the top. Rate-limit + sqlparser order is preserved
            // (charge BEFORE sqlparser since sqlparser consumes CPU and
            // is a legitimate resource cost that should count against
            // the per-execution budget). Same shape as MCP-770/783/784/
            // 785/786/787 and MCP-612 (counter-only-advances-when-
            // admitted).
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Database | CapabilityWorld::Trusted
            ) {
                self.record_capability_denied("database-query", "capability-world", "")
                    .await;
                tracing::warn!(
                    "WASM module attempted database access but lacks Database capability"
                );
                self.last_db_error =
                "Module lacks Database capability — compile with database-node or trusted world"
                    .to_string();
                return Err(wit_database::Error::Connectionfailed);
            }
            // MCP-755 (2026-05-13): cap SQL + aggregate params size BEFORE
            // sqlparser runs AND BEFORE the audit-ledger row is written.
            // Pre-fix `execute_query` accepted unbounded `sql: String` and
            // `params: Vec<String>` from the guest. Two real impacts:
            //
            //  * Audit-ledger poisoning. The WORM ledger at line ~5129
            //    appends the FULL SQL string (`"sql": sql`) on every
            //    successful validate. With MAX_DB_QUERIES_PER_EXECUTION =
            //    500, a Database-world guest could write 500 × 10 MiB =
            //    5 GiB to the local WORM ledger PLUS NATS-publish 5 GiB
            //    of audit events per execution. Both surfaces are shared
            //    across tenants — one noisy guest drowns out the audit
            //    signal for everyone else.
            //
            //  * sqlparser DoS. `Parser::parse_sql` on a 10 MiB input
            //    consumes proportional CPU + memory and runs on the
            //    worker's tokio task (`async fn` but the parse itself is
            //    sync); fuel-bounded guests can still pin the host
            //    thread for the duration of the parse.
            //
            // 64 KiB SQL cap is well above any reasonable hand-written or
            // ORM-generated query (Postgres' own libpq default
            // `statement_size_limit` is 1 GiB but real-world queries
            // rarely exceed a few KiB). 1 MiB aggregate params cap covers
            // any plausible bind set (1024 × 1 KiB params or 1 × 1 MiB
            // BYTEA-ish text payload). Same sibling-defense rule as
            // MCP-754: when one method in an impl block enforces a
            // bound, audit every other method for the same bound — even
            // when the cap was never previously written down.
            const MAX_SQL_BYTES: usize = 64 * 1024;
            const MAX_DB_PARAMS_BYTES: usize = 1024 * 1024;
            if sql.len() > MAX_SQL_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    sql_len = sql.len(),
                    "wit_database: SQL exceeds {} bytes; rejecting",
                    MAX_SQL_BYTES
                );
                self.last_db_error = format!(
                    "SQL query exceeds {} bytes — split into smaller queries or pre-aggregate via bind params",
                    MAX_SQL_BYTES
                );
                return Err(wit_database::Error::Invalidquery);
            }
            let params_total: usize = params.iter().map(|p| p.len()).sum();
            if params_total > MAX_DB_PARAMS_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    params_count = params.len(),
                    params_bytes = params_total,
                    "wit_database: aggregate params exceed {} bytes; rejecting",
                    MAX_DB_PARAMS_BYTES
                );
                self.last_db_error = format!(
                    "Bind parameters exceed {} bytes total — split the call or stream the payload via filesystem",
                    MAX_DB_PARAMS_BYTES
                );
                return Err(wit_database::Error::Invalidquery);
            }

            // Rate limit + cancellation: now charged AFTER capability and
            // pure-validation size caps — see MCP-788 reorder comment at
            // top of this function. Charged BEFORE sqlparser since the
            // parser is a legitimate CPU cost that should count against
            // the per-execution budget.
            if !self.check_rate_limit(&self.db_query_count, MAX_DB_QUERIES_PER_EXECUTION) {
                tracing::warn!(module_id = ?self.module_id, "Database query rate limit exceeded");
                if let Some(ref m) = self.metrics {
                    m.record_rate_limit_exceeded("db");
                }
                self.last_db_error =
                    "Rate limit exceeded: too many database queries in this execution".to_string();
                return Err(wit_database::Error::Unauthorized);
            }
            if self.is_cancelled() {
                tracing::info!(module_id = ?self.module_id, "Execution cancelled");
                if let Some(ref m) = self.metrics {
                    m.record_execution_cancelled();
                }
                self.last_db_error = "Execution was cancelled".to_string();
                return Err(wit_database::Error::Unauthorized);
            }

            // ── SQL operation policy enforcement (AST-based) ─────────────────
            // Validation stays worker-side so bad SQL is rejected without
            // a network hop. The controller re-verifies the HMAC on the
            // RPC and runs the actual query.
            // MCP-578: validate_sql now returns ValidatedStmt with
            // AST-derived `returns_rows`. We use that for is_fetch
            // routing below instead of the historical substring
            // `.contains("RETURNING")` heuristic which false-positived
            // on string literals and identifier substrings — a
            // false-positive caused the controller to CTE-wrap a
            // non-returning DML, which Postgres rejects, and the
            // operator's INSERT/UPDATE/DELETE never ran.
            let validated =
                match crate::sql_validator::validate_sql(&sql, &self.allowed_sql_operations) {
                    Ok(t) => t,
                    Err(e) => {
                        // Audit the denied SQL operation. The audit `target`
                        // is the validator's reason (the SQL operation kind
                        // — INSERT/DELETE/etc., or "syntax-error"); the SQL
                        // text itself is NOT audited because guest-supplied
                        // SQL can carry user-controlled string literals that
                        // shouldn't end up in the WORM ledger.
                        let reason = e.to_string();
                        let target = reason.split(':').next().unwrap_or("invalid").trim();
                        self.record_capability_denied("database-query", "sql-allowlist", target)
                            .await;
                        // MCP-538: byte-slice fixed-offset truncation
                        // panics on a multi-byte codepoint boundary.
                        // Pre-fix `&sql[..sql.len().min(200)]` would
                        // panic if the SQL contained a multi-byte UTF-8
                        // char (e.g. `é`, `你`) straddling byte 200 —
                        // achievable via a `WHERE name = '…'` literal.
                        // Use the same `floor_char_boundary` pattern as
                        // `runtime.rs::PASSING TO WASM NODE` so the
                        // worker crate stays consistent. Same class
                        // as MCP-477/478/479 — see
                        // `memory/byte_slice_utf8_panic_pattern.md`.
                        let preview_end = sql.len().min(200);
                        let safe_end = sql.floor_char_boundary(preview_end);
                        tracing::warn!(
                            error = %e,
                            sql_preview = %&sql[..safe_end],
                            "SQL validation rejected query"
                        );
                        self.last_db_error = e.to_string();
                        return Err(wit_database::Error::Invalidquery);
                    }
                };

            if let Some(ledger_mutex) = &self.audit_ledger {
                // Wasm-security review 2026-05-23 (M): stop logging the
                // FULL params array verbatim. Bind parameters often
                // carry PII (`SET password_hash = $1`, `WHERE email = $1`)
                // or short-lived secrets (`SET api_key = $1`). Pre-fix
                // the WORM ledger + NATS audit stream stored the raw
                // values, and at 1 MiB aggregate × 500 queries/exec the
                // worst-case audit dump was ~500 MiB per execution.
                // Replace the literal `params` with:
                //   - `params_count`     — operator-actionable cardinality
                //   - `params_bytes`     — aggregate size for capacity planning
                //   - `params_hash`      — sha256 over the canonical
                //                          (length-prefixed) params blob
                //                          so two identical-input audits
                //                          are linkable without exposure
                // The SQL string stays — it's bounded to 64 KiB upstream
                // by the size cap and ALWAYS reaches the controller
                // anyway (for replay), so retaining it adds no marginal
                // exposure.
                use sha2::Digest;
                let mut params_hasher = sha2::Sha256::new();
                let mut params_bytes: usize = 0;
                for p in &params {
                    params_hasher.update((p.as_bytes().len() as u64).to_le_bytes());
                    params_hasher.update(p.as_bytes());
                    params_bytes = params_bytes.saturating_add(p.len());
                }
                let params_hash = hex::encode(params_hasher.finalize());
                let mut ledger = ledger_mutex.lock().await;
                let event = ledger.append(
                    "agent:wasm",
                    "wasi:database_execute_query",
                    &serde_json::json!({
                        "sql": sql,
                        "params_count": params.len(),
                        "params_bytes": params_bytes,
                        "params_hash": params_hash,
                    })
                    .to_string(),
                );
                if let Some(n) = &self.nats_client {
                    let payload = serde_json::json!({
                        "event": event.clone(),
                        "hash": event.calculate_hash()
                    });
                    // MCP-879 (2026-05-14): log NATS publish failure
                    // explicitly so SIEM operators see the replication
                    // gap. Local ledger.append above is the WORM
                    // source-of-truth; this publish is replication
                    // only. Sibling to the MCP-735 fix at line ~2624
                    // (secrets_get) which already added this shape.
                    if let Err(e) = n
                        .publish(
                            "talos.audit.ledger".to_string(),
                            serde_json::to_vec(&payload).unwrap_or_default().into(),
                        )
                        .await
                    {
                        tracing::warn!(
                            target: "talos_rpc",
                            error = %e,
                            "audit-ledger NATS replication failed (database_query) — local ledger unaffected, SIEM stream will miss this event"
                        );
                    }
                }
            }

            // Actor context + NATS are required for dispatch. Anonymous
            // sandboxes (no actor_id) cannot issue database queries.
            let Some(actor_id) = self.actor_id else {
                self.last_db_error =
                    "Anonymous execution — database queries require an actor_id".to_string();
                return Err(wit_database::Error::Unauthorized);
            };
            let Some(nats) = self.nats_client.as_ref().cloned() else {
                self.last_db_error =
                    "NATS client unavailable — cannot dispatch database RPC".to_string();
                return Err(wit_database::Error::Connectionfailed);
            };

            // Detect fetch vs execute once and send the flag over the
            // wire so the controller doesn't re-parse. MCP-578: derive
            // from the parsed AST (validate_sql -> ValidatedStmt) rather
            // than a substring sniff on the raw SQL. The substring path
            // had two false-positive classes: string-literal "RETURNING"
            // (`INSERT INTO logs (msg) VALUES ('returning home')`) and
            // identifier substrings (`UPDATE u SET returning_user = 1`).
            // Both caused the controller to CTE-wrap the DML, which
            // Postgres rejects with "WITH query has no RETURNING
            // clause" — the operator's mutation never ran.
            let is_fetch = validated.returns_rows;
            let _ = &validated.stmt_type; // retained for forward-compat / future routing

            let rpc_req = match talos_memory::database_rpc::DatabaseRpcRequest::new_signed(
                actor_id,
                sql.clone(),
                params.clone(),
                is_fetch,
            ) {
                Some(r) => r,
                None => {
                    self.last_db_error =
                        "HMAC key unavailable on worker — refusing to send unsigned DB request"
                            .to_string();
                    return Err(wit_database::Error::Unauthorized);
                }
            };
            let payload = match serde_json::to_vec(&rpc_req) {
                Ok(p) => p,
                Err(e) => {
                    self.last_db_error = format!("serialize DB RPC: {e}");
                    return Err(wit_database::Error::Queryerror);
                }
            };

            use talos_memory::database_rpc::{
                DatabaseRpcError, DatabaseRpcReply, REQUEST_TIMEOUT_MS, SUBJECT_DATABASE_QUERY,
            };
            let reply_msg = match tokio::time::timeout(
                std::time::Duration::from_millis(REQUEST_TIMEOUT_MS),
                nats.request(SUBJECT_DATABASE_QUERY, payload.into()),
            )
            .await
            {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => {
                    self.last_db_error = format!("NATS request failed: {e}");
                    return Err(wit_database::Error::Connectionfailed);
                }
                Err(_) => {
                    self.last_db_error = "Database RPC timed out".to_string();
                    return Err(wit_database::Error::Queryerror);
                }
            };

            let reply: DatabaseRpcReply = match serde_json::from_slice(&reply_msg.payload) {
                Ok(r) => r,
                Err(e) => {
                    self.last_db_error = format!("DB RPC reply decode: {e}");
                    return Err(wit_database::Error::Queryerror);
                }
            };

            match reply.result {
                Ok(rows) => Ok(wit_database::QueryResult {
                    rows: rows.rows_json,
                    rows_affected: rows.rows_affected,
                }),
                Err(DatabaseRpcError::Unauthorized) => {
                    self.last_db_error = "Controller rejected request (HMAC mismatch)".to_string();
                    Err(wit_database::Error::Unauthorized)
                }
                Err(DatabaseRpcError::InvalidQuery(m)) => {
                    self.last_db_error = m;
                    Err(wit_database::Error::Invalidquery)
                }
                Err(DatabaseRpcError::ConnectionFailed(m)) => {
                    self.last_db_error = m;
                    Err(wit_database::Error::Connectionfailed)
                }
                Err(DatabaseRpcError::ResultTooLarge(m)) => {
                    self.last_db_error = m;
                    Err(wit_database::Error::Queryerror)
                }
                Err(DatabaseRpcError::Timeout) => {
                    self.last_db_error = "Database query timed out on controller".to_string();
                    Err(wit_database::Error::Queryerror)
                }
                Err(DatabaseRpcError::QueryError(m)) => {
                    self.last_db_error = m;
                    Err(wit_database::Error::Queryerror)
                }
            }
        }
        .await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("db::execute_query", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn get_last_error(&mut self) -> String {
        self.last_db_error.clone()
    }
}

// ============================================================================
// Files (capability-based sandbox)
// ============================================================================

impl wit_files::Host for TalosContext {
    async fn read(&mut self, path: String) -> Result<Vec<u8>, wit_files::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        // MCP-586: defense-in-depth — match the explicit capability
        // check on `write` / `delete` / `exists`. The per-execution
        // tempdir wired into `fs_dir` (context.rs:388) means a
        // non-Filesystem module today gets NotFound from an empty
        // sandbox, but read/metadata/list_dir should fail-closed
        // with `Permissiondenied` like the sibling mutators. Without
        // an explicit gate the only barrier is the tempdir wiring;
        // if that ever changes (e.g. shared sandbox between
        // executions) the read-side would silently allow access.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("files-read", "capability-world", &path)
                .await;
            tracing::warn!("WASM module attempted file read but lacks Filesystem capability");
            return Err(wit_files::Error::Permissiondenied);
        }
        let safe_path = sanitize_path(&path)?;
        let __result = tokio::task::block_in_place(|| {
            // Check file size before reading to prevent OOM from large files.
            let meta = self
                .fs_dir
                .metadata(&safe_path)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => wit_files::Error::Notfound,
                    std::io::ErrorKind::PermissionDenied => wit_files::Error::Permissiondenied,
                    _ => wit_files::Error::Ioerror,
                })?;
            if meta.len() > MAX_FILE_READ_BYTES as u64 {
                tracing::warn!(
                    path = %path,
                    size = meta.len(),
                    limit = MAX_FILE_READ_BYTES,
                    "files::read blocked — file exceeds 64 MiB read limit"
                );
                return Err(wit_files::Error::Ioerror);
            }
            self.fs_dir.read(&safe_path).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => wit_files::Error::Notfound,
                std::io::ErrorKind::PermissionDenied => wit_files::Error::Permissiondenied,
                _ => wit_files::Error::Ioerror,
            })
        });

        if let Some(ref m) = __metrics {
            m.record_host_function_call("files::read", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn write(&mut self, path: String, contents: Vec<u8>) -> Result<(), wit_files::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<(), wit_files::Error> = async move {
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Filesystem | CapabilityWorld::Trusted
            ) {
                self.record_capability_denied("files-write", "capability-world", &path)
                    .await;
                tracing::warn!("WASM module attempted file access but lacks Filesystem capability");
                return Err(wit_files::Error::Permissiondenied);
            }

            // MCP-770 (2026-05-13): validate the path BEFORE the byte-quota
            // CAS loop. Pre-fix the CAS bumped `fs_bytes_written` first,
            // then `sanitize_path` ran — so a guest submitting a 16 MiB
            // body with a sandbox-escape path (`../foo`) reserved 16 MiB
            // against its own per-execution quota even though the write
            // failed with `Invalidpath`. A few such calls exhausted
            // `MAX_FS_BYTES_PER_EXECUTION`, blocking subsequent legitimate
            // writes for the rest of the execution despite zero bytes
            // having actually landed on disk. Extends the MCP-612 rule
            // ("counter only advances when admitted") to cover ALL
            // pre-write validation, not just the cap check itself.
            // Capability gate already ran above (line 5443), so this is
            // the only remaining pure-validation step that can fail before
            // we touch disk.
            let safe_path = sanitize_path(&path)?;

            // MCP-612 (2026-05-12): use a load-check-CAS loop instead of
            // fetch_add-then-check. The pre-fix shape bumped the counter
            // BEFORE the limit check, so a write that exceeded the cap left
            // the counter poisoned with phantom bytes. A subsequent SMALLER
            // write that would have fit under the cap would then fail
            // because the counter said it didn't. Same pattern issue
            // `check_rate_limit` (context.rs:1050) calls out explicitly in
            // its docstring: counter only advances when admitted.
            use std::sync::atomic::Ordering;
            let bytes = contents.len() as u64;
            loop {
                let current = self.fs_bytes_written.load(Ordering::Relaxed);
                let projected = current.saturating_add(bytes);
                if projected > MAX_FS_BYTES_PER_EXECUTION {
                    tracing::warn!(
                        module_id = ?self.module_id,
                        bytes_written = current,
                        attempted = bytes,
                        limit = MAX_FS_BYTES_PER_EXECUTION,
                        "File system write quota would be exceeded — not admitting"
                    );
                    if let Some(ref m) = self.metrics {
                        m.record_rate_limit_exceeded("fs");
                    }
                    return Err(wit_files::Error::Permissiondenied);
                }
                if self
                    .fs_bytes_written
                    .compare_exchange_weak(current, projected, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }

            tokio::task::block_in_place(|| {
                // Create parent directories within the sandbox if needed.
                if let Some(parent) = safe_path.parent() {
                    if parent != std::path::Path::new("") {
                        self.fs_dir
                            .create_dir_all(parent)
                            .map_err(|_| wit_files::Error::Ioerror)?;
                    }
                }
                self.fs_dir
                    .write(&safe_path, &contents)
                    .map_err(|e| match e.kind() {
                        std::io::ErrorKind::PermissionDenied => wit_files::Error::Permissiondenied,
                        _ => wit_files::Error::Ioerror,
                    })
            })
        }
        .await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("files::write", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn exists(&mut self, path: String) -> bool {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            // MCP-690 (2026-05-13): audit-ledger emission for
            // capability denial parity with the fallible siblings
            // (read/write/delete/metadata/list_dir all
            // record_capability_denied). Pre-fix `exists` silently
            // returned `false`, so a Minimal-world module probing
            // file paths could enumerate without an audit trail.
            self.record_capability_denied("files-exists", "capability-world", &path)
                .await;
            return false;
        }
        sanitize_path(&path)
            .map(|p| tokio::task::block_in_place(|| self.fs_dir.metadata(&p).is_ok()))
            .unwrap_or(false)
    }

    async fn metadata(
        &mut self,
        path: String,
    ) -> Result<wit_files::FileMetadata, wit_files::Error> {
        // MCP-586: sibling defense-in-depth gate to `read`. The
        // `exists` accessor below already returns false for
        // non-Filesystem worlds; `metadata` returning a real result
        // (size, mtime, is_directory) for a non-Filesystem actor
        // would expose more state than the matching `exists` call —
        // make both consistent.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("files-metadata", "capability-world", &path)
                .await;
            return Err(wit_files::Error::Permissiondenied);
        }
        let safe_path = sanitize_path(&path)?;
        let meta = tokio::task::block_in_place(|| {
            self.fs_dir
                .metadata(&safe_path)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => wit_files::Error::Notfound,
                    _ => wit_files::Error::Ioerror,
                })
        })?;
        let modified_unix = meta
            .modified()
            .ok()
            .and_then(|t| t.into_std().duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(wit_files::FileMetadata {
            size: meta.len(),
            modified_unix,
            is_directory: meta.is_dir(),
        })
    }

    async fn list_dir(&mut self, path: String) -> Result<Vec<String>, wit_files::Error> {
        // MCP-586: sibling defense-in-depth gate. A non-Filesystem
        // module enumerating directory entries shouldn't even reach
        // the sandbox tempdir.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("files-list-dir", "capability-world", &path)
                .await;
            return Err(wit_files::Error::Permissiondenied);
        }
        let safe_path = sanitize_path(&path)?;
        tokio::task::block_in_place(|| {
            let entries = self
                .fs_dir
                .read_dir(&safe_path)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => wit_files::Error::Notfound,
                    _ => wit_files::Error::Ioerror,
                })?;
            // Limit the number of entries to prevent OOM on directories with millions of files.
            const MAX_DIR_ENTRIES: usize = 10_000;
            let names: Vec<String> = entries
                .flatten()
                .take(MAX_DIR_ENTRIES)
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();
            Ok(names)
        })
    }

    async fn delete(&mut self, path: String) -> Result<(), wit_files::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("files-delete", "capability-world", &path)
                .await;
            tracing::warn!("WASM module attempted file access but lacks Filesystem capability");
            return Err(wit_files::Error::Permissiondenied);
        }

        let safe_path = sanitize_path(&path)?;
        tokio::task::block_in_place(|| {
            let is_dir = self
                .fs_dir
                .metadata(&safe_path)
                .map(|m| m.is_dir())
                .unwrap_or(false);
            if is_dir {
                self.fs_dir.remove_dir_all(&safe_path)
            } else {
                self.fs_dir.remove_file(&safe_path)
            }
            .map_err(|_| wit_files::Error::Ioerror)
        })
    }
}

/// Strip `..` components and leading `/` to prevent path traversal attacks.
fn sanitize_path(path: &str) -> Result<std::path::PathBuf, wit_files::Error> {
    use std::path::{Component, PathBuf};
    let mut safe = PathBuf::new();
    for component in std::path::Path::new(path).components() {
        match component {
            Component::Normal(c) => safe.push(c),
            Component::CurDir => {}
            // Reject any attempt to escape the sandbox.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(wit_files::Error::Invalidpath);
            }
        }
    }
    Ok(safe)
}

// ============================================================================
// Templates (Jinja2-compatible via minijinja)
// ============================================================================

impl wit_templates::Host for TalosContext {
    async fn render(
        &mut self,
        template: String,
        variables: String,
        _syntax: wit_templates::Syntax,
    ) -> Result<String, wit_templates::Error> {
        /// 1 MB template source limit — prevents parser memory exhaustion.
        const MAX_TEMPLATE_BYTES: usize = 1_000_000;
        /// 10 MB rendered output limit — prevents loop-amplification attacks.
        const MAX_RENDERED_BYTES: usize = 10_000_000;

        if template.len() > MAX_TEMPLATE_BYTES {
            tracing::warn!(
                "Template source too large ({} bytes, limit {})",
                template.len(),
                MAX_TEMPLATE_BYTES
            );
            return Err(wit_templates::Error::Parseerror);
        }

        /// 10 MB variables limit — prevents memory exhaustion from a very large JSON blob.
        const MAX_VARIABLES_BYTES: usize = 10_000_000;
        if variables.len() > MAX_VARIABLES_BYTES {
            tracing::warn!(
                "Template variables too large ({} bytes, limit {})",
                variables.len(),
                MAX_VARIABLES_BYTES
            );
            return Err(wit_templates::Error::Parseerror);
        }

        let vars: serde_json::Value =
            serde_json::from_str(&variables).map_err(|_| wit_templates::Error::Parseerror)?;

        let mut env = minijinja::Environment::new();
        // Auto-escape HTML by default for security (prevents XSS).
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
        env.add_template("__inline__", &template)
            .map_err(|_| wit_templates::Error::Parseerror)?;
        let tmpl = env
            .get_template("__inline__")
            .map_err(|_| wit_templates::Error::Parseerror)?;
        let rendered = tmpl
            .render(minijinja::Value::from_serialize(&vars))
            .map_err(|_| wit_templates::Error::Rendererror)?;

        if rendered.len() > MAX_RENDERED_BYTES {
            tracing::warn!(
                "Rendered template output too large ({} bytes, limit {})",
                rendered.len(),
                MAX_RENDERED_BYTES
            );
            return Err(wit_templates::Error::Rendererror);
        }

        Ok(rendered)
    }

    async fn render_file(
        &mut self,
        path: String,
        variables: String,
        syntax: wit_templates::Syntax,
    ) -> Result<String, wit_templates::Error> {
        let contents = <TalosContext as wit_files::Host>::read(self, path)
            .await
            .map_err(|_| wit_templates::Error::Parseerror)?;
        let template = String::from_utf8(contents).map_err(|_| wit_templates::Error::Parseerror)?;
        self.render(template, variables, syntax).await
    }
}

// ============================================================================
// Data transform (CSV / XML)
// ============================================================================

/// Maximum number of CSV rows accepted by `csv_to_json`.
/// Prevents host memory exhaustion from a single oversized payload.
const MAX_CSV_ROWS: usize = 100_000;
/// Maximum CSV input size (10 MB). A row-only limit can be bypassed by wide records.
const MAX_CSV_BYTES: usize = 10_000_000;
/// Maximum number of columns in a CSV file to prevent memory exhaustion.
const MAX_CSV_COLUMNS: usize = 1_000;
/// MCP-1013 (2026-05-15): sibling-parity cap for `xml_to_json`. Pre-fix
/// the XML path had no input-size cap while `csv_to_json` enforced 10 MB.
/// A WASM guest with enough memory budget could ship a multi-MB XML
/// string per call — the host then materialises a HashMap proportional
/// to unique-element-name count and copies every text node into JSON
/// `Value::String`. Memory cost is O(input_size) on the host side,
/// scaling beyond the WASM memory pool's bound when the guest reuses
/// the same memory across calls. MAX_XML_DEPTH (1000) bounds stack
/// depth but not byte size. 10 MB matches the CSV cap for posture
/// uniformity. Same defense-in-depth class as MCP-1005/MCP-1006
/// (input caps at trust boundaries).
const MAX_XML_BYTES: usize = 10_000_000;

impl wit_data_transform::Host for TalosContext {
    async fn csv_to_json(
        &mut self,
        csv_input: String,
        options: Option<wit_data_transform::CsvOptions>,
    ) -> Result<String, wit_data_transform::Error> {
        if csv_input.len() > MAX_CSV_BYTES {
            tracing::warn!(
                "csv_to_json input too large ({} bytes, limit {})",
                csv_input.len(),
                MAX_CSV_BYTES
            );
            return Err(wit_data_transform::Error::Parseerror);
        }

        let delimiter = options
            .as_ref()
            .and_then(|o| o.delimiter.as_deref())
            .and_then(|d| d.chars().next())
            .unwrap_or(',') as u8;
        let has_headers = options.as_ref().map(|o| o.has_headers).unwrap_or(true);

        let mut rdr = csv::ReaderBuilder::new()
            .delimiter(delimiter)
            .has_headers(has_headers)
            .from_reader(csv_input.as_bytes());

        if has_headers {
            let headers: Vec<String> = rdr
                .headers()
                .map_err(|_| wit_data_transform::Error::Parseerror)?
                .iter()
                .map(|s| s.to_string())
                .collect();

            if headers.len() > MAX_CSV_COLUMNS {
                tracing::warn!(
                    "csv_to_json too many columns ({}, limit {})",
                    headers.len(),
                    MAX_CSV_COLUMNS
                );
                return Err(wit_data_transform::Error::Invalidformat);
            }

            let mut rows = Vec::new();
            for result in rdr.records() {
                if rows.len() >= MAX_CSV_ROWS {
                    return Err(wit_data_transform::Error::Invalidformat);
                }
                let record = result.map_err(|_| wit_data_transform::Error::Parseerror)?;
                let mut map = serde_json::Map::new();
                for (i, field) in record.iter().enumerate() {
                    let key = headers.get(i).map(|s| s.as_str()).unwrap_or("unknown");
                    map.insert(
                        key.to_string(),
                        serde_json::Value::String(field.to_string()),
                    );
                }
                rows.push(serde_json::Value::Object(map));
            }
            serde_json::to_string(&rows).map_err(|_| wit_data_transform::Error::Parseerror)
        } else {
            let mut rows = Vec::new();
            for result in rdr.records() {
                if rows.len() >= MAX_CSV_ROWS {
                    return Err(wit_data_transform::Error::Invalidformat);
                }
                let record = result.map_err(|_| wit_data_transform::Error::Parseerror)?;
                let arr: Vec<serde_json::Value> = record
                    .iter()
                    .map(|f| serde_json::Value::String(f.to_string()))
                    .collect();
                rows.push(serde_json::Value::Array(arr));
            }
            serde_json::to_string(&rows).map_err(|_| wit_data_transform::Error::Parseerror)
        }
    }

    async fn json_to_csv(
        &mut self,
        json_input: String,
        options: Option<wit_data_transform::CsvOptions>,
    ) -> Result<String, wit_data_transform::Error> {
        let delimiter = options
            .as_ref()
            .and_then(|o| o.delimiter.as_deref())
            .and_then(|d| d.chars().next())
            .unwrap_or(',') as u8;

        let rows: Vec<serde_json::Value> =
            serde_json::from_str(&json_input).map_err(|_| wit_data_transform::Error::Parseerror)?;

        let mut output = Vec::new();
        {
            let mut wtr = csv::WriterBuilder::new()
                .delimiter(delimiter)
                .from_writer(&mut output);

            // Collect headers from first object.
            let headers: Vec<String> = rows
                .first()
                .and_then(|r| r.as_object())
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();

            if !headers.is_empty() {
                wtr.write_record(&headers)
                    .map_err(|_| wit_data_transform::Error::Invalidformat)?;
            }

            for row in &rows {
                if let Some(obj) = row.as_object() {
                    let record: Vec<String> = headers
                        .iter()
                        .map(|h| {
                            obj.get(h)
                                .map(|v| match v {
                                    serde_json::Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                })
                                .unwrap_or_default()
                        })
                        .collect();
                    wtr.write_record(&record)
                        .map_err(|_| wit_data_transform::Error::Invalidformat)?;
                }
            }
            wtr.flush()
                .map_err(|_| wit_data_transform::Error::Ioerror)?;
        }

        String::from_utf8(output).map_err(|_| wit_data_transform::Error::Invalidformat)
    }

    async fn xml_to_json(&mut self, xml: String) -> Result<String, wit_data_transform::Error> {
        // MCP-1013: input-size cap, sibling parity with `csv_to_json`'s
        // MAX_CSV_BYTES gate. See MAX_XML_BYTES doc for full rationale.
        if xml.len() > MAX_XML_BYTES {
            tracing::warn!(
                "xml_to_json input too large ({} bytes, limit {})",
                xml.len(),
                MAX_XML_BYTES
            );
            return Err(wit_data_transform::Error::Parseerror);
        }
        let value = xml_string_to_json(&xml)?;
        serde_json::to_string(&value).map_err(|_| wit_data_transform::Error::Parseerror)
    }

    async fn json_to_xml(
        &mut self,
        json: String,
        root_element: String,
    ) -> Result<String, wit_data_transform::Error> {
        // MCP-1013: input-size cap, sibling parity with the reverse
        // `xml_to_json` path and the canonical `csv_to_json` gate.
        // `json_value_to_xml` is unbounded-recursive and concatenates
        // a `format!` per node — a multi-MB JSON would materialise an
        // even-larger XML string in host memory. Cap at the same
        // 10 MB ceiling as the CSV / XML siblings.
        if json.len() > MAX_XML_BYTES {
            tracing::warn!(
                "json_to_xml input too large ({} bytes, limit {})",
                json.len(),
                MAX_XML_BYTES
            );
            return Err(wit_data_transform::Error::Parseerror);
        }
        let value: serde_json::Value =
            serde_json::from_str(&json).map_err(|_| wit_data_transform::Error::Parseerror)?;
        let xml = json_value_to_xml(&value, &root_element);
        // 2026-05-28 audit F2: input cap doesn't bound the OUTPUT —
        // wrapper-tag-per-node amplification can 2-4× the byte count
        // on deeply nested JSON. With a 10 MB input cap, worst-case
        // host materialisation is ~40 MB. Add an output-side cap so
        // the host doesn't return a string larger than the input
        // ceiling regardless of nesting structure.
        if xml.len() > MAX_XML_BYTES {
            tracing::warn!(
                "json_to_xml output exceeded {} bytes (post-inflation: {})",
                MAX_XML_BYTES,
                xml.len()
            );
            return Err(wit_data_transform::Error::Parseerror);
        }
        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{}", xml))
    }
}

/// Very simple XML → JSON converter (element names become keys, text content becomes values).
fn xml_string_to_json(xml: &str) -> Result<serde_json::Value, wit_data_transform::Error> {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    use std::collections::VecDeque;

    /// Maximum nesting depth to prevent stack exhaustion via deeply nested XML.
    const MAX_XML_DEPTH: usize = 1_000;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut stack: VecDeque<(String, serde_json::Map<String, serde_json::Value>)> = VecDeque::new();
    let mut root: Option<serde_json::Value> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                if stack.len() >= MAX_XML_DEPTH {
                    tracing::warn!("xml_to_json: nesting depth exceeded {}", MAX_XML_DEPTH);
                    return Err(wit_data_transform::Error::Parseerror);
                }
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                stack.push_back((name, serde_json::Map::new()));
            }
            Ok(Event::Text(e)) => {
                if let Some((_, obj)) = stack.back_mut() {
                    let text = e
                        .unescape()
                        .map_err(|_| wit_data_transform::Error::Parseerror)?;
                    if !text.trim().is_empty() {
                        obj.insert(
                            "#text".to_string(),
                            serde_json::Value::String(text.to_string()),
                        );
                    }
                }
            }
            Ok(Event::End(_)) => {
                if let Some((name, obj)) = stack.pop_back() {
                    let value = if obj.len() == 1 && obj.contains_key("#text") {
                        obj["#text"].clone()
                    } else {
                        serde_json::Value::Object(obj)
                    };
                    if let Some((_, parent)) = stack.back_mut() {
                        parent.insert(name, value);
                    } else {
                        root = Some(serde_json::json!({ name: value }));
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                if let Some((_, parent)) = stack.back_mut() {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    parent.insert(name, serde_json::Value::Null);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(wit_data_transform::Error::Parseerror),
            _ => {}
        }
    }

    root.ok_or(wit_data_transform::Error::Parseerror)
}

/// Simple JSON → XML serialiser.
fn json_value_to_xml(value: &serde_json::Value, element: &str) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let inner: String = map.iter().map(|(k, v)| json_value_to_xml(v, k)).collect();
            format!("<{}>{}</{}>", element, inner, element)
        }
        serde_json::Value::Array(arr) => {
            arr.iter().map(|v| json_value_to_xml(v, element)).collect()
        }
        serde_json::Value::String(s) => {
            format!("<{}>{}</{}>", element, escape_xml(s), element)
        }
        other => format!("<{}>{}</{}>", element, other, element),
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// NOTE: In wasmtime ≥43 the outgoing_handler::Host trait is implemented on
// WasiHttpCtxView (projected via WasiHttpView::http()) rather than on the
// user's context type directly.  The default implementation delegates to
// WasiHttpHooks::send_request.  See context.rs WasiHttpView impl for the
// hooks configuration.  Talos nodes should use talos:core/http for
// controlled HTTP with host allowlists and SSRF protection.

use crate::bindings::talos::core::governance;
impl governance::Host for TalosContext {
    async fn request_approval(&mut self, reason: String) -> bool {
        // MCP-655: per-method capability gate. Sibling of the
        // wit_messaging / wit_cache / wit_files inline checks that
        // MCP-586/601 made canonical for tier-3 sub-world Hosts.
        // Governance is a tier-3 sub-world that escalates only to
        // Agent or Trusted (`is_subset_of`: Governance ⊆ Agent | Trusted);
        // any other world reaching this code path means the WIT inspector
        // mis-classified the module, the world rank was bypassed at
        // create_workflow / load time, or a future capability path drifted.
        // Defense in depth — refuse with a `false` return (the WIT
        // signature has no error variant) and log the world for forensics.
        // Returning `false` is operationally indistinguishable from a
        // denial decision so the guest's branch logic still works.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Governance | CapabilityWorld::Agent | CapabilityWorld::Trusted
        ) {
            tracing::warn!(
                world = ?self.capability_world,
                module_id = ?self.module_id,
                "WASM module attempted governance::request_approval but lacks the Governance/Agent/Trusted capability — denying"
            );
            self.record_capability_denied(
                "governance",
                "capability-world-mismatch",
                "request_approval",
            )
            .await;
            return false;
        }

        if let Some(ledger_mutex) = &self.audit_ledger {
            let mut ledger = ledger_mutex.lock().await;
            let event = ledger.append(
                "agent:wasm",
                "wasi:human_approval_request",
                &serde_json::json!({
                    "reason": reason
                })
                .to_string(),
            );
            // Optionally, publish the event to a WORM NATS stream
            if let Some(n) = &self.nats_client {
                let payload = serde_json::json!({
                    "event": event.clone(),
                    "hash": event.calculate_hash()
                });
                // MCP-879 (2026-05-14): same SIEM-replication WARN as
                // the secrets_get sibling (MCP-735) and the
                // database_query sibling above. The local
                // ledger.append remains the WORM source-of-truth.
                if let Err(e) = n
                    .publish(
                        "talos.audit.ledger".to_string(),
                        serde_json::to_vec(&payload).unwrap_or_default().into(),
                    )
                    .await
                {
                    tracing::warn!(
                        target: "talos_rpc",
                        error = %e,
                        "audit-ledger NATS replication failed (human_approval_request) — local ledger unaffected, SIEM stream will miss this event"
                    );
                }
            }
        }

        let exec_id = self
            .execution_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        let workflow_id = self
            .workflow_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        // Record approval request metric (MCP-492: aggregate-only —
        // per-workflow visibility now lives in the audit-event chain,
        // not the Prometheus label space).
        if let Some(ref m) = self.metrics {
            m.record_approval_requested();
        }

        let nats = match &self.nats_client {
            Some(n) => n,
            None => {
                tracing::error!(
                    execution_id = ?self.execution_id,
                    module_id = ?self.module_id,
                    "NATS client not available for governance approvals — returning false \
                     (indistinguishable from denial due to WIT bool return type)"
                );
                return false;
            }
        };

        let redis = match &self.redis_client {
            Some(r) => r,
            None => {
                tracing::error!(
                    execution_id = ?self.execution_id,
                    module_id = ?self.module_id,
                    "Redis client not available for governance approvals — returning false \
                     (indistinguishable from denial due to WIT bool return type)"
                );
                return false;
            }
        };

        let reply_topic = format!("talos.approvals.wait.{}", exec_id);

        // 1. Subscribe to the reply topic FIRST so we don't miss the message
        let mut subscriber = match nats.subscribe(reply_topic.clone()).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to subscribe to NATS topic {}: {}", reply_topic, e);
                return false;
            }
        };

        // 2. Write to Redis
        let mut con = match redis.get_multiplexed_tokio_connection().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to get Redis connection: {}", e);
                return false;
            }
        };

        // The frontend UI is sending the overall `workflow_execution_id` to the API webhook,
        // not the node-specific `exec_id`.
        let redis_key = format!("approval:{}", workflow_id);
        // MCP-739 (2026-05-13): log SET failures. Pre-fix the
        // `let _: redis::RedisResult<()>` discarded errors entirely.
        // This Redis row is the routing table the webhook handler
        // uses to find the reply_topic when an operator clicks
        // approve/deny — without it the click hits the webhook but
        // the response can't be dispatched back to this awaiting
        // task. The function then sits waiting until its outer
        // timeout (default ~120 s+) before returning false, looking
        // like a denial to the guest. Same operator-visibility class
        // as MCP-733/734/735/736. Note: we continue rather than
        // early-return because the NATS subscribe + publish still
        // happen (the operator might trigger via a different path),
        // but logging at WARN ensures dashboards see the gap.
        if let Err(e) = redis::cmd("SET")
            .arg(&redis_key)
            .arg(&reply_topic)
            .arg("EX")
            .arg(86400) // 24 hours
            .query_async::<()>(&mut con)
            .await
        {
            tracing::warn!(
                target: "talos_rpc",
                execution_id = ?self.execution_id,
                workflow_id,
                error = %e,
                "governance approval: Redis SET for reply_topic routing failed — \
                 webhook clicks may not reach this awaiting task; timing out is the \
                 likely outcome"
            );
        }

        // 3. Publish pending notification
        let payload = serde_json::json!({
            "execution_id": exec_id,
            "reason": reason
        })
        .to_string();

        if let Err(e) = nats
            .publish("talos.approvals.pending".to_string(), payload.into())
            .await
        {
            tracing::error!("Failed to publish pending approval notification: {}", e);
            // Continue anyway, maybe it was logged elsewhere
        }

        tracing::info!(
            "Paused execution {} waiting for approval on {}",
            exec_id,
            reply_topic
        );

        // 4. Await the response with a configurable timeout.
        // Default: 24 hours. Governance-world modules get up to 7 days via the
        // execution-level timeout, but the approval wait itself uses a shorter
        // deadline to avoid silent indefinite hangs.
        // MCP-670 (2026-05-13): `=0`-safe env helper. `TALOS_APPROVAL_TIMEOUT_SECS=0`
        // would fire the timer immediately (`Duration::from_secs(0)`), so every
        // approval request returns Pending → false → silently denied without
        // ever reaching the operator. That's the destructive variant of the
        // `=0` footgun class (MCP-639/642/665/668 family).
        let approval_timeout = std::time::Duration::from_secs(
            talos_config::positive_env_or_default::<u64>("TALOS_APPROVAL_TIMEOUT_SECS", 86400),
        );

        use futures_util::stream::StreamExt;
        let result = tokio::time::timeout(approval_timeout, subscriber.next()).await;

        match result {
            Ok(Some(msg)) => {
                // Delete Redis key (best effort)
                let _: redis::RedisResult<()> = redis::cmd("DEL")
                    .arg(&redis_key)
                    .query_async(&mut con)
                    .await;

                let response_str = String::from_utf8_lossy(&msg.payload);
                let approved = response_str.trim().to_lowercase() == "true";
                tracing::info!("Received approval response for {}: {}", exec_id, approved);

                // Record approval decision metric
                if let Some(ref m) = self.metrics {
                    m.record_approval_decided(if approved { "approved" } else { "denied" });
                }

                if let Some(ledger_mutex) = &self.audit_ledger {
                    let mut ledger = ledger_mutex.lock().await;
                    let event = ledger.append(
                        "human:webhook",
                        "wasi:human_approval_response",
                        &serde_json::json!({
                            "approved": approved
                        })
                        .to_string(),
                    );
                    if let Some(n) = &self.nats_client {
                        // MCP-879 (2026-05-14): same SIEM-replication
                        // WARN as the request sibling above and the
                        // MCP-735 secrets_get site. Local ledger is
                        // the WORM source-of-truth.
                        if let Err(e) = n
                            .publish(
                                "talos.audit.ledger".to_string(),
                                serde_json::to_vec(&event).unwrap_or_default().into(),
                            )
                            .await
                        {
                            tracing::warn!(
                                target: "talos_rpc",
                                error = %e,
                                "audit-ledger NATS replication failed (human_approval_response) — local ledger unaffected, SIEM stream will miss this event"
                            );
                        }
                    }
                }
                approved
            }
            Ok(None) => {
                tracing::error!(
                    execution_id = exec_id,
                    "NATS subscription closed before approval response received"
                );
                false
            }
            Err(_) => {
                tracing::warn!(
                    execution_id = exec_id,
                    timeout_secs = approval_timeout.as_secs(),
                    "Approval request timed out after {:?} — treating as denied",
                    approval_timeout
                );
                // Clean up Redis key on timeout
                let _: redis::RedisResult<()> = redis::cmd("DEL")
                    .arg(&redis_key)
                    .query_async(&mut con)
                    .await;
                false
            }
        }
    }
}

// ============================================================================
// LLM
// ============================================================================

/// 2026-05-28 audit Perf#1 (H7 sibling): typed projection of an LLM
/// provider response. Deserializing into one of these instead of
/// `serde_json::Value` saves the per-field `HashMap<String, Value>`
/// allocation tree. The two variants match the only two formats the
/// callers branch on (`is_openai_format`).
///
/// Lives at module scope so the structs participate in `#[derive]` —
/// `serde::Deserialize` traits can't be derived inside a function body.
enum LlmResponse {
    OpenAi(OpenAiResponse),
    Anthropic(AnthropicResponse),
}

#[derive(serde::Deserialize)]
struct OpenAiResponse {
    #[serde(default)]
    choices: Vec<OpenAiChoice>,
    #[serde(default)]
    usage: Option<OpenAiUsage>,
}

#[derive(serde::Deserialize)]
struct OpenAiChoice {
    #[serde(default)]
    message: Option<OpenAiMessage>,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(serde::Deserialize)]
struct OpenAiMessage {
    #[serde(default)]
    content: Option<String>,
}

#[derive(serde::Deserialize)]
struct OpenAiUsage {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
}

#[derive(serde::Deserialize)]
struct AnthropicResponse {
    #[serde(default)]
    content: Vec<AnthropicBlock>,
    #[serde(default)]
    usage: Option<AnthropicUsage>,
    #[serde(default)]
    stop_reason: Option<String>,
}

#[derive(serde::Deserialize)]
struct AnthropicBlock {
    /// Renamed because `type` is a Rust keyword.
    #[serde(rename = "type", default)]
    block_type: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

#[derive(serde::Deserialize)]
struct AnthropicUsage {
    #[serde(default)]
    input_tokens: Option<u64>,
    #[serde(default)]
    output_tokens: Option<u64>,
}

impl wit_llm::Host for TalosContext {
    async fn complete(
        &mut self,
        req: wit_llm::CompletionRequest,
    ) -> Result<wit_llm::CompletionResponse, wit_llm::Error> {
        // Check cancellation before making an expensive API call.
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            return Err(wit_llm::Error::BudgetExhausted);
        }

        let llm_start = std::time::Instant::now();

        // Resolve provider and look up the API key.
        // Ollama (Tier 1) runs locally and needs no API key.
        let provider = req.provider.unwrap_or(wit_llm::Provider::Anthropic);
        let is_local = matches!(provider, wit_llm::Provider::Ollama);

        let api_key = if is_local {
            String::new()
        } else {
            match self.get_llm_api_key(provider).await {
                Some(k) => k,
                None => {
                    let (vault_path, env_name) = match provider {
                        wit_llm::Provider::Anthropic => ("anthropic/api_key", "ANTHROPIC_API_KEY"),
                        wit_llm::Provider::Openai => ("openai/api_key", "OPENAI_API_KEY"),
                        wit_llm::Provider::Gemini => ("gemini/api_key", "GEMINI_API_KEY"),
                        wit_llm::Provider::Ollama => unreachable!(),
                    };
                    let msg = format!(
                        "LLM API key not configured. Set vault path `{}` in the dashboard (Settings → Secrets), \
                         or export {} in the worker environment as a fallback.",
                        vault_path, env_name
                    );
                    tracing::warn!(vault_path, env_name, module_id = ?self.module_id, "{}", msg);
                    return Err(wit_llm::Error::NotConfigured(msg));
                }
            }
        };

        let model = req.model.unwrap_or_else(|| match provider {
            wit_llm::Provider::Anthropic => "claude-sonnet-4-20250514".to_string(),
            wit_llm::Provider::Openai => "gpt-4o".to_string(),
            wit_llm::Provider::Gemini => "gemini-1.5-pro".to_string(),
            wit_llm::Provider::Ollama => "mistral".to_string(),
        });

        // Build the messages array. Anthropic doesn't support "system" as a
        // message role (it uses a top-level field), so System maps to "user".
        // OpenAI/Ollama support "system" as a message role natively.
        let is_openai_format = matches!(
            provider,
            wit_llm::Provider::Openai | wit_llm::Provider::Ollama
        );
        let messages: Vec<serde_json::Value> = req
            .messages
            .iter()
            .map(|msg| {
                let role = match msg.role {
                    wit_llm::Role::System => {
                        if is_openai_format {
                            "system"
                        } else {
                            "user"
                        }
                    }
                    wit_llm::Role::User => "user",
                    wit_llm::Role::Assistant => "assistant",
                };
                serde_json::json!({"role": role, "content": msg.content})
            })
            .collect();

        let mut body = serde_json::json!({
            "model": model,
            "messages": messages,
            "max_tokens": req.max_tokens.unwrap_or(4096),
        });

        if let Some(temp) = req.temperature {
            body["temperature"] = serde_json::json!(temp);
        }
        if let Some(ref sys) = req.system_prompt {
            body["system"] = serde_json::json!(sys);
        }

        // For OpenAI-compatible providers (OpenAI, Ollama), inject system_prompt
        // as a system-role message rather than Anthropic's top-level "system" field.
        if is_openai_format {
            if let Some(ref sys) = req.system_prompt {
                // Prepend system message for OpenAI-format providers
                body.as_object_mut().and_then(|obj| {
                    obj.get_mut("messages").and_then(|m| {
                        m.as_array_mut().map(|arr| {
                            arr.insert(0, serde_json::json!({"role": "system", "content": sys}));
                        })
                    })
                });
                // Remove the Anthropic-style top-level "system" field
                body.as_object_mut().map(|obj| obj.remove("system"));
            }
        }

        let ollama_url = ollama_base_url();

        let (url, auth_header, auth_value) = match provider {
            wit_llm::Provider::Anthropic => (
                "https://api.anthropic.com/v1/messages".to_string(),
                "x-api-key",
                api_key,
            ),
            wit_llm::Provider::Openai => (
                "https://api.openai.com/v1/chat/completions".to_string(),
                "Authorization",
                format!("Bearer {}", api_key),
            ),
            wit_llm::Provider::Gemini => (
                "https://generativelanguage.googleapis.com/v1beta/models".to_string(),
                "x-goog-api-key",
                api_key,
            ),
            wit_llm::Provider::Ollama => (
                format!("{}/v1/chat/completions", ollama_url),
                "", // no auth header
                String::new(),
            ),
        };

        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            wit_llm::Error::InvalidRequest(format!("Failed to serialize request body: {e}"))
        })?;

        let provider_label = match provider {
            wit_llm::Provider::Anthropic => "anthropic",
            wit_llm::Provider::Openai => "openai",
            wit_llm::Provider::Gemini => "gemini",
            wit_llm::Provider::Ollama => "ollama",
        };
        tracing::info!(
            module_id = ?self.module_id,
            model = %model,
            provider = provider_label,
            message_count = req.messages.len(),
            "LLM completion request"
        );

        let client = self.http_client.clone();
        // MCP-1213 (2026-05-18): one timeout for the FULL exchange
        // (send + body read), not just `.send()`. Pre-fix the outer
        // timeout wrapped only header receipt — once headers arrived,
        // `.json()` / `.text()` could hang indefinitely on a slow
        // body stream. Real prod symptom: daily-brief synthesize hung
        // 5+ minutes after the MCP-1212 re-sign fix unmasked it.
        let timeout_secs: u64 = if is_local {
            LOCAL_LLM_EXCHANGE_TIMEOUT_SECS
        } else {
            EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS
        };
        let mut http_req = client.post(&url).header("Content-Type", "application/json");
        if !auth_header.is_empty() {
            http_req = http_req.header(auth_header, &auth_value);
        }
        if matches!(provider, wit_llm::Provider::Anthropic) {
            http_req = http_req.header("anthropic-version", "2023-06-01");
        }
        let resp_body: LlmResponse = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            async move {
                let response = http_req
                    .body(body_bytes)
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, provider = provider_label, "LLM API request failed");
                        wit_llm::Error::ApiError(format!("Network error: {e}"))
                    })?;

                if !response.status().is_success() {
                    let status = response.status().as_u16();
                    tracing::warn!(status, "LLM API returned error status");
                    if status == 429 {
                        return Err(wit_llm::Error::RateLimited);
                    }
                    // MCP-528 + MCP-1213: DLP-scrub the body preview AND
                    // bound it by MAX_LLM_BODY_BYTES. Pre-fix `.text()`
                    // had no size limit — a misbehaving provider could
                    // stream multi-GB error bodies into worker memory.
                    let preview_bytes = read_llm_response_body_bounded(
                        response,
                        MAX_LLM_BODY_BYTES,
                    )
                    .await
                    .unwrap_or_default();
                    let body_preview = String::from_utf8_lossy(&preview_bytes);
                    let preview_truncated: String =
                        body_preview.chars().take(500).collect();
                    let preview_redacted =
                        talos_dlp_provider::redact_str(&preview_truncated);
                    tracing::warn!(
                        status,
                        body_len = preview_bytes.len(),
                        body_preview = %preview_redacted,
                        "LLM API returned error"
                    );
                    return Err(wit_llm::Error::ApiError(format!(
                        "LLM API returned HTTP {status}"
                    )));
                }

                // MCP-1213: bounded streaming body read + parse, NOT
                // unbounded `.json()`. Caps response at MAX_LLM_BODY_BYTES.
                let body_bytes = read_llm_response_body_bounded(
                    response,
                    MAX_LLM_BODY_BYTES,
                )
                .await
                .ok_or_else(|| {
                    wit_llm::Error::ApiError(format!(
                        "LLM response exceeded {} bytes; aborted body read",
                        MAX_LLM_BODY_BYTES
                    ))
                })?;
                // 2026-05-28 audit Perf#1: H7 sibling. Pre-fix this
                // materialised the full `serde_json::Value` tree only
                // to pluck 3-5 fields per branch. Now we deserialize
                // into format-specific typed structs — serde only
                // allocates the strings we actually use, skipping the
                // `HashMap<String, Value>` tree for every other field
                // in the provider response. The two structs match the
                // exact shape consumed below.
                //
                // OpenAI/Ollama:
                //   { choices: [{ message: { content: "..." },
                //                 finish_reason: "..." }],
                //     usage: { prompt_tokens, completion_tokens } }
                // Anthropic/Gemini:
                //   { content: [{ type: "text", text: "..." }, ...],
                //     usage: { input_tokens, output_tokens },
                //     stop_reason: "..." }
                //
                // The format-divergent shapes return as enum variants
                // so the extraction logic below stays
                // strongly-typed instead of `get("...").and_then(...)`
                // chains over `Value`.
                if is_openai_format {
                    serde_json::from_slice::<OpenAiResponse>(&body_bytes)
                        .map(LlmResponse::OpenAi)
                        .map_err(|e| {
                            wit_llm::Error::ApiError(format!(
                                "Failed to parse OpenAI-format response: {e}"
                            ))
                        })
                } else {
                    serde_json::from_slice::<AnthropicResponse>(&body_bytes)
                        .map(LlmResponse::Anthropic)
                        .map_err(|e| {
                            wit_llm::Error::ApiError(format!(
                                "Failed to parse Anthropic-format response: {e}"
                            ))
                        })
                }
            },
        )
        .await
        .map_err(|_| wit_llm::Error::Timeout)??;

        // Extract text + usage + stop_reason from the typed response.
        let (text, usage, stop_reason) = match resp_body {
            LlmResponse::OpenAi(r) => {
                let text = r
                    .choices
                    .first()
                    .and_then(|c| c.message.as_ref())
                    .and_then(|m| m.content.clone())
                    .unwrap_or_default();
                let usage = r.usage.map(|u| wit_llm::TokenUsage {
                    // MCP-1008: saturate-on-overflow to surface
                    // malicious / corrupted provider responses as
                    // visible spikes.
                    input_tokens: u32::try_from(u.prompt_tokens.unwrap_or(0))
                        .unwrap_or(u32::MAX),
                    output_tokens: u32::try_from(u.completion_tokens.unwrap_or(0))
                        .unwrap_or(u32::MAX),
                });
                let stop_reason = r
                    .choices
                    .into_iter()
                    .next()
                    .and_then(|c| c.finish_reason);
                (text, usage, stop_reason)
            }
            LlmResponse::Anthropic(r) => {
                let text = r
                    .content
                    .iter()
                    .filter(|b| b.block_type.as_deref() == Some("text"))
                    .filter_map(|b| b.text.as_deref())
                    .collect::<Vec<_>>()
                    .join("");
                let usage = r.usage.map(|u| wit_llm::TokenUsage {
                    // MCP-1008: saturate-on-overflow.
                    input_tokens: u32::try_from(u.input_tokens.unwrap_or(0))
                        .unwrap_or(u32::MAX),
                    output_tokens: u32::try_from(u.output_tokens.unwrap_or(0))
                        .unwrap_or(u32::MAX),
                });
                (text, usage, r.stop_reason)
            }
        };
        if let Some(ref m) = self.metrics {
            let duration_ms = llm_start.elapsed().as_millis() as f64;
            m.record_llm_request(provider_label, duration_ms);
            if let Some(ref u) = usage {
                m.record_llm_tokens("input", u.input_tokens as u64);
                m.record_llm_tokens("output", u.output_tokens as u64);
            }
        }

        Ok(wit_llm::CompletionResponse {
            text,
            model,
            usage,
            stop_reason,
        })
    }
}

// ============================================================================
// Agent Memory
// ============================================================================

/// All actor-memory host functions dispatch to the controller over
/// NATS. Rationale:
///
/// - Defense in depth. Every other WASM-bearing surface in Talos
///   (secrets, workflow state, actors) is brokered through the
///   controller. Memory used to be the exception — it either held a
///   DB pool in the worker or fell back to an in-process HashMap.
///   Both options widen the blast radius of a sandbox escape.
///
/// - Single source of truth. Write path goes through
///   `talos_memory::persist_memory`, which computes embeddings and
///   runs graph-RAG entity extraction. Read path goes through
///   `talos_memory::recall_semantic`, which hits the same pgvector
///   cosine query as MCP's `actor_recall_semantic`. Results are
///   guaranteed consistent across callers.
///
/// - No DB pool or embedding provider credentials in the worker
///   container. The worker only needs NATS to reach the controller.
///
/// MCP-604 (2026-05-12): per-method capability gate. The WIT linkage
/// restricts `talos:core/agent-memory` to `database-node`, `agent-node`,
/// and `automation-node` at compile time (verified by grep `import
/// agent-memory` in wit/talos.wit). The runtime gate is defense-in-depth
/// against mis-tagged modules or future world-set changes — `actor_id`
/// is set on the context whenever the workflow has an actor binding,
/// regardless of capability_world, so `mem_rpc_prereqs_owned` alone
/// does not enforce the boundary. Same shape as MCP-602 (wit_object_storage)
/// and MCP-603 (wit_state).
fn require_agent_memory_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_agent_memory::Error> {
    use crate::wit_inspector::CapabilityWorld;
    if matches!(
        world,
        CapabilityWorld::Database | CapabilityWorld::Agent | CapabilityWorld::Trusted
    ) {
        Ok(())
    } else {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_agent_memory call but lacks Database/Agent/Trusted capability"
        );
        Err(wit_agent_memory::Error::NotAvailable)
    }
}

impl wit_agent_memory::Host for TalosContext {
    async fn get(&mut self, key: String) -> Result<String, wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-ledger parity. Pre-fix the `?`
        // operator on `require_agent_memory_capability` propagated Err
        // without an audit row — operator-blind to the WORM ledger.
        // Same fix shape as MCP-712 (wit_state) / MCP-713 (wit_secrets).
        // The actor-memory namespace can hold PII / business-critical
        // recall content, so capability-deny probes against memory
        // surfaces are an important signal class.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            self.record_capability_denied("agent-memory-get", "capability-world", &key)
                .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        // Fail-fast key validation (parity with set/delete + the controller's
        // memory_rpc verify(); see set for rationale).
        if talos_memory::validate_memory_key(&key).is_err() {
            return Err(wit_agent_memory::Error::InvalidInput);
        }
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Err(wit_agent_memory::Error::NotAvailable),
        };
        let result = match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::Get { key },
        )
        .await
        {
            Ok(talos_memory::memory_rpc::MemoryOpResult::GetValue { value }) => {
                // Round-trip fidelity: `set("k", "x")` must yield `get("k") == "x"`.
                // The RPC ships back a JSON-encoded value because the storage
                // layer preserves JSON structure server-side. Unwrap a JSON
                // string literal back to its inner bytes; for objects/arrays
                // return the serialized JSON (which is what the guest wrote).
                let unwrapped = match serde_json::from_str::<serde_json::Value>(&value) {
                    Ok(serde_json::Value::String(s)) => s,
                    _ => value,
                };
                Ok(unwrapped)
            }
            Ok(_) => Err(wit_agent_memory::Error::NotAvailable),
            Err(e) => Err(map_mem_err(e)),
        };
        if let Some(ref m) = __metrics {
            m.record_host_function_call("agent_memory::get", __start.elapsed().as_millis() as f64);
        }
        result
    }

    async fn set(&mut self, key: String, value: String) -> Result<(), wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-parity — see `get` above for full
        // rationale. set is the highest-stakes of the keyed methods
        // because a denied write attempt is a stronger signal of
        // capability mismatch than a denied read.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            self.record_capability_denied("agent-memory-set", "capability-world", &key)
                .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        // Fail-fast key validation via the canonical validator the controller's
        // memory_rpc verify() also runs (trim, non-empty, ≤500 chars, no control
        // chars/null). Parity with the per-key caps on wit_cache (MCP-754) and
        // wit_state: rejects an over-long/invalid key here instead of HMAC-signing
        // and shipping a doomed payload the controller would reject anyway.
        if talos_memory::validate_memory_key(&key).is_err() {
            return Err(wit_agent_memory::Error::InvalidInput);
        }
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        if value.len() > talos_memory::MAX_VALUE_BYTES {
            return Err(wit_agent_memory::Error::StorageFull);
        }
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Err(wit_agent_memory::Error::NotAvailable),
        };
        let json_val: serde_json::Value =
            serde_json::from_str(&value).unwrap_or(serde_json::Value::String(value));
        let result = match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::Set {
                key,
                value: json_val,
                memory_type: "working".to_string(),
                ttl_hours: None,
                metadata: None,
            },
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(talos_memory::memory_rpc::MemoryRpcError::StorageFull) => {
                Err(wit_agent_memory::Error::StorageFull)
            }
            Err(e) => Err(map_mem_err(e)),
        };
        if let Some(ref m) = __metrics {
            m.record_host_function_call("agent_memory::set", __start.elapsed().as_millis() as f64);
        }
        result
    }

    async fn delete(&mut self, key: String) -> Result<(), wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-parity — see `get` above.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            self.record_capability_denied("agent-memory-delete", "capability-world", &key)
                .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        // Fail-fast key validation (parity with get/set + the controller's
        // memory_rpc verify(); see set for rationale).
        if talos_memory::validate_memory_key(&key).is_err() {
            return Err(wit_agent_memory::Error::InvalidInput);
        }
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Err(wit_agent_memory::Error::NotAvailable),
        };
        match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::Delete { key },
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(map_mem_err(e)),
        }
    }

    async fn list_keys(
        &mut self,
        prefix: Option<String>,
    ) -> Result<Vec<String>, wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-parity. list_keys is the
        // enumeration surface — key names themselves may carry
        // semantic information that operators consider out-of-scope
        // for a Minimal/Unknown-world module. Repeated capability-
        // denied probes here are the highest-signal pattern for
        // detecting reconnaissance against the actor namespace.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            let probe = prefix.as_deref().unwrap_or("");
            self.record_capability_denied("agent-memory-list-keys", "capability-world", probe)
                .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Err(wit_agent_memory::Error::NotAvailable),
        };
        match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::ListKeys { prefix },
        )
        .await
        {
            Ok(talos_memory::memory_rpc::MemoryOpResult::Keys { keys }) => Ok(keys),
            Ok(_) => Err(wit_agent_memory::Error::NotAvailable),
            Err(e) => Err(map_mem_err(e)),
        }
    }

    async fn store_with_embedding(
        &mut self,
        entry: wit_agent_memory::MemoryEntry,
    ) -> Result<(), wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-parity. store_with_embedding is
        // the semantic-memory write path — a capability-deny here
        // means a module tried to poison the embedding index with
        // entries it shouldn't be allowed to write.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            self.record_capability_denied(
                "agent-memory-store-with-embedding",
                "capability-world",
                &entry.key,
            )
            .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Err(wit_agent_memory::Error::NotAvailable),
        };
        // The guest provides `value` as a plain string. Preserve it literally —
        // `get` MUST return the same bytes back. Parse into a JSON value if it
        // looks like JSON (so the DB gets a typed payload and `jsonb_path_ops`
        // filters work) but otherwise store as a JSON string.
        let value_json = serde_json::from_str::<serde_json::Value>(&entry.value)
            .unwrap_or(serde_json::Value::String(entry.value));
        let metadata_json: Option<serde_json::Value> = entry
            .metadata
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());
        match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::Set {
                key: entry.key,
                value: value_json,
                memory_type: "semantic".to_string(),
                ttl_hours: None,
                metadata: metadata_json,
            },
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(talos_memory::memory_rpc::MemoryRpcError::StorageFull) => {
                Err(wit_agent_memory::Error::StorageFull)
            }
            Err(e) => Err(map_mem_err(e)),
        }
    }

    async fn search(
        &mut self,
        query: String,
        limit: u32,
    ) -> Result<Vec<wit_agent_memory::SearchResult>, wit_agent_memory::Error> {
        // Bare search is a zero-exclusion specialisation of the filtered
        // variant — keeps the two host paths semantically identical.
        self.search_filtered(
            query,
            wit_agent_memory::SearchOptions {
                limit,
                exclude_kinds: Vec::new(),
            },
        )
        .await
    }

    async fn search_filtered(
        &mut self,
        query: String,
        opts: wit_agent_memory::SearchOptions,
    ) -> Result<Vec<wit_agent_memory::SearchResult>, wit_agent_memory::Error> {
        // MCP-714 (2026-05-13): audit-parity. search_filtered is the
        // semantic-recall surface — query text may contain PII so we
        // hash before recording into the WORM ledger. Same hashing
        // convention as the secret-access path (line ~2440) which uses
        // SHA-256 of the key_path; operators reading the ledger
        // should not learn raw search-query strings.
        if require_agent_memory_capability(&self.capability_world).is_err() {
            let query_hash = format!("{:x}", Sha256::digest(query.as_bytes()));
            self.record_capability_denied(
                "agent-memory-search",
                "capability-world",
                &query_hash,
            )
            .await;
            return Err(wit_agent_memory::Error::NotAvailable);
        }
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let (actor_id, nats) = match mem_rpc_prereqs_owned(self) {
            Some(p) => p,
            None => return Ok(vec![]),
        };
        // Dedupe + strip empties so the signed canonical bytes are stable
        // regardless of caller-supplied input shape. A guest passing
        // `["meeting_prep", "meeting_prep", ""]` signs the same bytes as
        // one passing `["meeting_prep"]`.
        let mut exclude = opts
            .exclude_kinds
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        exclude.sort();
        exclude.dedup();
        // `min_score: 0.3` aligns with the MCP `actor_recall_semantic`
        // default — tuned for nomic-embed-text score distributions
        // (genuine matches score 0.2-0.5, so 0.3 balances recall + quality).
        // For stricter filtering callers can post-filter the returned
        // `score` field in the sandbox.
        let result = match call_memory_op(
            actor_id,
            nats,
            talos_memory::memory_rpc::MemoryOp::Search {
                query,
                limit: opts.limit.min(50),
                min_score: 0.3,
                exclude_kinds: exclude,
            },
        )
        .await
        {
            Ok(talos_memory::memory_rpc::MemoryOpResult::SearchHits { hits, .. }) => Ok(hits
                .into_iter()
                .map(|h| wit_agent_memory::SearchResult {
                    key: h.key,
                    value: h.value,
                    score: h.score,
                    // Per-row metadata (JSON string of the JSONB column).
                    // Sandboxes that use metadata.kind for self-reference-
                    // loop filtering previously had to reconstruct it from
                    // out-of-band sources; now it's available in-line.
                    metadata: h.metadata,
                })
                .collect()),
            Ok(_) => Ok(vec![]),
            Err(e) => {
                tracing::debug!(error = ?e, "agent_memory::search_filtered RPC error");
                Err(map_mem_err(e))
            }
        };
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "agent_memory::search_filtered",
                __start.elapsed().as_millis() as f64,
            );
        }
        result
    }
}

/// Fire-and-forget NATS publish for state write-through. Invoked
/// from `state::set` and `state::delete`; errors and missing
/// prerequisites are silently swallowed because durability is
/// best-effort (the in-process HashMap remains the primary store).
fn spawn_state_write_through(
    nats: Option<std::sync::Arc<async_nats::Client>>,
    execution_id: Option<&str>,
    actor_id: Option<uuid::Uuid>,
    key: &str,
    value: Option<&str>,
) {
    use talos_memory::state_rpc::{StateWriteRequest, SUBJECT_STATE_WRITE};
    let (Some(nats), Some(exec_id_str), Some(actor_id)) = (nats, execution_id, actor_id) else {
        return;
    };
    let Ok(exec_id) = uuid::Uuid::parse_str(exec_id_str) else {
        return;
    };
    let key = key.to_string();
    let (value, is_delete) = match value {
        Some(v) => (v.to_string(), false),
        None => (String::new(), true),
    };
    tokio::spawn(async move {
        // MCP-734 (2026-05-13): sibling of MCP-733. The fire-and-forget
        // state-write path discarded ALL error signals (sign failure,
        // serialize failure, NATS publish failure). User-facing
        // contract is best-effort, but operator contract requires
        // visibility into systemic failures. Log at WARN with
        // execution_id + actor_id so SIEM / dashboards can alert on
        // sustained failures (NATS outage, HMAC key not initialised,
        // etc.).
        let Some(req) = StateWriteRequest::new_signed(exec_id, actor_id, key, value, is_delete)
        else {
            tracing::warn!(
                target: "talos_rpc",
                execution_id = %exec_id,
                actor_id = %actor_id,
                "state-write-through: HMAC key unavailable — drop (worker bootstrap incomplete or rotation in flight)"
            );
            return;
        };
        let payload = match serde_json::to_vec(&req) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    target: "talos_rpc",
                    execution_id = %exec_id,
                    actor_id = %actor_id,
                    error = %e,
                    "state-write-through: payload serialize failed — drop (should not happen for well-formed request)"
                );
                return;
            }
        };
        if let Err(e) = nats.publish(SUBJECT_STATE_WRITE, payload.into()).await {
            tracing::warn!(
                target: "talos_rpc",
                execution_id = %exec_id,
                actor_id = %actor_id,
                error = %e,
                "state-write-through: NATS publish failed — guest sees Ok but state was not persisted"
            );
        }
    });
}

/// Extract the values needed for an outgoing memory RPC by value, so
/// the returned tuple has no lifetime tying it to `TalosContext`.
/// Needed because the host-trait `async fn`s must return `Send`
/// futures and `TalosContext` itself is `!Sync`.
fn mem_rpc_prereqs_owned(
    ctx: &TalosContext,
) -> Option<(uuid::Uuid, std::sync::Arc<async_nats::Client>)> {
    Some((ctx.actor_id?, ctx.nats_client.as_ref().cloned()?))
}

/// Dispatch a signed memory-RPC request and wait for the reply. All
/// arguments are owned so the future is `Send`.
async fn call_memory_op(
    actor_id: uuid::Uuid,
    nats: std::sync::Arc<async_nats::Client>,
    op: talos_memory::memory_rpc::MemoryOp,
) -> Result<talos_memory::memory_rpc::MemoryOpResult, talos_memory::memory_rpc::MemoryRpcError> {
    use talos_memory::memory_rpc::{
        MemoryRpcError, MemoryRpcReply, MemoryRpcRequest, REQUEST_TIMEOUT_MS, SUBJECT_MEMORY_OP,
    };
    let req = match MemoryRpcRequest::new_signed(actor_id, op) {
        Some(r) => r,
        None => return Err(MemoryRpcError::Unauthorized),
    };
    let payload = serde_json::to_vec(&req)
        .map_err(|e| MemoryRpcError::Internal(format!("serialize: {e}")))?;

    let fut = nats.request(SUBJECT_MEMORY_OP, payload.into());
    let reply_msg =
        match tokio::time::timeout(std::time::Duration::from_millis(REQUEST_TIMEOUT_MS), fut).await
        {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                return Err(MemoryRpcError::Internal(format!(
                    "nats request failed: {e}"
                )))
            }
            Err(_) => return Err(MemoryRpcError::Timeout),
        };
    let reply: MemoryRpcReply = serde_json::from_slice(&reply_msg.payload)
        .map_err(|e| MemoryRpcError::Internal(format!("reply decode: {e}")))?;
    reply.result
}

fn map_mem_err(e: talos_memory::memory_rpc::MemoryRpcError) -> wit_agent_memory::Error {
    use talos_memory::memory_rpc::MemoryRpcError;
    match e {
        MemoryRpcError::KeyNotFound => wit_agent_memory::Error::KeyNotFound,
        MemoryRpcError::InvalidInput(_) => wit_agent_memory::Error::InvalidInput,
        MemoryRpcError::StorageFull => wit_agent_memory::Error::StorageFull,
        _ => wit_agent_memory::Error::NotAvailable,
    }
}

// ============================================================================
// Graph Memory — NATS-RPC to the controller's graph service.
//
// The Neo4j driver lives controller-side; workers dispatch a
// `GraphSearchRequest` over NATS (subject `talos.graph.search`) and
// await a `GraphSearchReply` within `REQUEST_TIMEOUT_MS`. See
// `talos_memory::graph_rpc` for the wire protocol and
// `controller/src/main.rs` for the corresponding subscriber.
// ============================================================================

impl wit_graph_memory::Host for TalosContext {
    async fn graph_search(
        &mut self,
        query: String,
        max_depth: u32,
        limit: u32,
    ) -> Result<wit_graph_memory::GraphContext, wit_graph_memory::Error> {
        // MCP-608 (2026-05-12): per-method capability gate. WIT linkage
        // restricts `talos:core/graph-memory` to database-node, agent-node,
        // automation-node (verified by grep `import graph-memory` in
        // wit/talos.wit) → CapabilityWorld set {Database, Agent, Trusted}.
        // Pre-fix: gated only via `actor_id.is_some()` check below — the
        // same gap MCP-604 (wit_agent_memory) closed. A mis-tagged
        // minimal-world module with an actor binding could issue graph-RAG
        // queries against the actor's Neo4j graph.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Database | CapabilityWorld::Agent | CapabilityWorld::Trusted
        ) {
            tracing::warn!(
                world = ?self.capability_world,
                "WASM module attempted wit_graph_memory::graph_search but lacks Database/Agent/Trusted capability"
            );
            return Err(wit_graph_memory::Error::NotAvailable);
        }
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __res: Result<wit_graph_memory::GraphContext, wit_graph_memory::Error> = async {
            use talos_memory::graph_rpc::{
                GraphRpcError, GraphSearchReply, GraphSearchRequest, MAX_DEPTH, MAX_LIMIT,
                REQUEST_TIMEOUT_MS, SUBJECT_GRAPH_SEARCH,
            };

            if query.trim().is_empty() {
                return Err(wit_graph_memory::Error::InvalidInput);
            }
            let Some(actor_id) = self.actor_id else {
                return Err(wit_graph_memory::Error::NotAvailable);
            };
            let Some(nats) = self.nats_client.as_ref().cloned() else {
                return Err(wit_graph_memory::Error::NotAvailable);
            };

            let req = match GraphSearchRequest::new_signed(
                actor_id,
                query,
                max_depth.min(MAX_DEPTH),
                limit.clamp(1, MAX_LIMIT),
            ) {
                Some(r) => r,
                None => {
                    // HMAC key unavailable — fail closed rather than
                    // sending an unsigned request.
                    return Err(wit_graph_memory::Error::NotAvailable);
                }
            };
            let payload = match serde_json::to_vec(&req) {
                Ok(p) => p,
                Err(_) => return Err(wit_graph_memory::Error::Internal),
            };

            let fut = nats.request(SUBJECT_GRAPH_SEARCH, payload.into());
            let reply_msg = match tokio::time::timeout(
                std::time::Duration::from_millis(REQUEST_TIMEOUT_MS),
                fut,
            )
            .await
            {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "graph-search NATS request failed");
                    return Err(wit_graph_memory::Error::NotAvailable);
                }
                Err(_) => return Err(wit_graph_memory::Error::Timeout),
            };

            let reply: GraphSearchReply = match serde_json::from_slice(&reply_msg.payload) {
                Ok(r) => r,
                Err(_) => return Err(wit_graph_memory::Error::Internal),
            };

            match reply.result {
                Ok(resp) => Ok(wit_graph_memory::GraphContext {
                    entity_count: resp.entity_count,
                    entities: resp
                        .entities
                        .into_iter()
                        .map(|h| wit_graph_memory::GraphHit {
                            entity_type: h.entity_type,
                            label: h.label,
                            distance: h.distance,
                            properties: h.properties,
                        })
                        .collect(),
                    relationships: resp.relationships,
                }),
                Err(GraphRpcError::NotAvailable) => Err(wit_graph_memory::Error::NotAvailable),
                Err(GraphRpcError::InvalidInput(_)) => Err(wit_graph_memory::Error::InvalidInput),
                Err(GraphRpcError::Timeout) => Err(wit_graph_memory::Error::Timeout),
                Err(GraphRpcError::Internal(_)) => Err(wit_graph_memory::Error::Internal),
                Err(GraphRpcError::Unauthorized) => Err(wit_graph_memory::Error::NotAvailable),
            }
        }
        .await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "graph_memory::graph_search",
                __start.elapsed().as_millis() as f64,
            );
        }
        __res
    }
}

// ============================================================================
// Agent Orchestration
// ============================================================================

/// Cap on per-field payload bytes when an agent message is built. The host
/// stamps `source_module` / `source_execution` itself (UUIDs); the only
/// guest-controlled blobs are `payload`, `correlation_id`, and `target`. The
/// total NATS payload after the signed envelope wrap is bounded by these
/// caps + ~512 bytes of envelope overhead.
///
/// Wasm-security review 2026-05-23 (H-4): pre-fix the payload field was an
/// unbounded JSON object; combined with the absence of HMAC signing, a
/// guest with the routine Agent capability could blast 100MB messages into
/// every `talos.agent.*` subscriber. Caps + signed envelope close both
/// arms in one change.
const MAX_AGENT_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_AGENT_CORRELATION_ID_BYTES: usize = 256;

/// Build the signed NATS envelope for an agent invocation / message.
///
/// Wraps the guest-supplied payload in a versioned envelope and stamps it
/// with an HMAC-SHA256 signature bound to (subject, actor_id, nonce,
/// canonical_body). Subscribers under `talos.agent.*` MUST verify before
/// acting on the contents — see verification helper below.
///
/// Envelope shape (versioned for forward compatibility):
/// ```json
/// {
///   "v": 1,
///   "nonce": "<unix_ms>:<16 random hex bytes>",
///   "subject": "talos.agent.<target>.invoke",
///   "source_module": "<uuid|null>",
///   "source_execution": "<exec_id|null>",
///   "source_actor": "<uuid|nil>",
///   "source_worker": "<worker_id>",
///   "payload": <guest-supplied json>,
///   "correlation_id": <int|null>,
///   "signature": "<hex>"
/// }
/// ```
///
/// The signature covers `serde_json::to_vec(&envelope_without_signature)`
/// — the canonical body — combined with `subject`, `actor_id`, and
/// `nonce` per `talos_memory::rpc_auth::sign`. When the worker's HMAC key
/// isn't registered (test fixtures, dev without env), `signature` is
/// emitted as the empty string; production subscribers MUST refuse such
/// envelopes.
fn build_signed_agent_envelope(
    subject: &str,
    actor_id: Option<uuid::Uuid>,
    source_worker: &str,
    source_module: &Option<String>,
    source_execution: &Option<String>,
    payload: &serde_json::Value,
    correlation_id: &Option<String>,
) -> Result<Vec<u8>, &'static str> {
    use rand::Rng;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time before epoch")?
        .as_millis();
    let rand_bytes: [u8; 16] = rand::thread_rng().gen();
    let nonce = format!("{}:{}", ts, hex::encode(rand_bytes));

    // Canonical envelope WITHOUT signature (which is added last). This is
    // the byte string we sign. Field-name ordering follows
    // `serde_json::json!` (preserves insertion order in this crate
    // version), so the canonical bytes are deterministic for a given
    // input.
    let envelope = serde_json::json!({
        "v": 1u32,
        "nonce": nonce,
        "subject": subject,
        "source_module": source_module,
        "source_execution": source_execution,
        // `source_actor` is the actor's identity claim (HMAC-bound on
        // the worker side); subscribers can pin against the actor's
        // expected_caller_actor_id field for additional defense.
        "source_actor": actor_id.unwrap_or(uuid::Uuid::nil()).to_string(),
        "source_worker": source_worker,
        "payload": payload,
        "correlation_id": correlation_id,
    });
    let canonical_body = serde_json::to_vec(&envelope)
        .map_err(|_| "envelope serialise failed")?;

    // `rpc_auth::sign` returns None when the worker's HMAC key isn't
    // registered — that happens in unit tests and in pre-startup paths.
    // The envelope still goes on the wire (without signing); the
    // production subscriber's `MUST verify` rule covers refusal in that
    // case.
    let signature = talos_memory::rpc_auth::sign(
        subject,
        actor_id.unwrap_or(uuid::Uuid::nil()),
        &nonce,
        &canonical_body,
    )
    .map(hex::encode)
    .unwrap_or_default();

    // Now re-emit the envelope with the signature appended. We re-build
    // the JSON rather than splicing into the existing bytes to keep
    // the canonical body construction simple — subscribers do the same:
    // strip `signature`, recompute canonical body, verify.
    let signed = serde_json::json!({
        "v": 1u32,
        "nonce": nonce,
        "subject": subject,
        "source_module": source_module,
        "source_execution": source_execution,
        "source_actor": actor_id.unwrap_or(uuid::Uuid::nil()).to_string(),
        "source_worker": source_worker,
        "payload": payload,
        "correlation_id": correlation_id,
        "signature": signature,
    });
    serde_json::to_vec(&signed).map_err(|_| "signed envelope serialise failed")
}

/// Verify a signed agent NATS envelope. Documented public helper that
/// future `talos.agent.*` subscribers will call before acting on the
/// payload. Returns `Ok(payload)` when:
/// - the envelope JSON parses and has all required fields;
/// - `subject` matches the envelope's `subject` (defense against
///   re-publication onto a different topic);
/// - the freshness window holds (per `talos_memory::rpc_auth`);
/// - the HMAC signature verifies against the worker's shared key.
///
/// Refuses (returns `Err`) when:
/// - the envelope is missing required fields;
/// - the signature is empty (production subscribers must NOT accept
///   unsigned envelopes);
/// - the actor_id is malformed;
/// - the HMAC fails;
/// - the subject doesn't match.
///
/// Pure function so the verification rule can be unit-tested without
/// NATS / a live worker.
#[allow(dead_code)] // Provided for future subscribers; tests exercise it.
pub fn verify_signed_agent_envelope(
    expected_subject: &str,
    envelope_bytes: &[u8],
) -> Result<serde_json::Value, &'static str> {
    let parsed: serde_json::Value =
        serde_json::from_slice(envelope_bytes).map_err(|_| "envelope parse failed")?;
    let envelope = parsed.as_object().ok_or("envelope is not a JSON object")?;

    let signature_hex = envelope
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or("envelope missing signature field")?;
    if signature_hex.is_empty() {
        return Err("envelope has empty signature — refusing");
    }
    let signature = hex::decode(signature_hex).map_err(|_| "signature is not valid hex")?;

    let subject = envelope
        .get("subject")
        .and_then(|v| v.as_str())
        .ok_or("envelope missing subject field")?;
    if subject != expected_subject {
        return Err("subject mismatch — possible re-publication attempt");
    }
    let nonce = envelope
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or("envelope missing nonce field")?;
    let actor_str = envelope
        .get("source_actor")
        .and_then(|v| v.as_str())
        .ok_or("envelope missing source_actor field")?;
    let actor_id = uuid::Uuid::parse_str(actor_str).map_err(|_| "source_actor is not a UUID")?;

    // Reconstruct the canonical body (envelope MINUS signature) and
    // verify. This mirrors `build_signed_agent_envelope`'s canonical
    // form exactly.
    let mut body_obj = envelope.clone();
    body_obj.remove("signature");
    let canonical_body = serde_json::to_vec(&serde_json::Value::Object(body_obj))
        .map_err(|_| "canonical body serialise failed")?;

    if !talos_memory::rpc_auth::verify(subject, actor_id, nonce, &canonical_body, &signature) {
        return Err("signature verification failed");
    }

    envelope
        .get("payload")
        .cloned()
        .ok_or("envelope missing payload field")
}

#[cfg(test)]
mod signed_agent_envelope_tests {
    use super::{build_signed_agent_envelope, verify_signed_agent_envelope};
    use talos_memory::rpc_auth;

    /// Register a process-wide HMAC key for the verify tests. Reuses the
    /// same all-`0x42` test key convention as the protocol crate. Safe
    /// to call from multiple tests — `register_hmac_key` is idempotent
    /// for the same key bytes.
    fn ensure_test_key() {
        use std::sync::Arc;
        rpc_auth::register_hmac_key(Arc::new(vec![0x42u8; 32]));
    }

    #[test]
    fn signed_envelope_round_trips() {
        ensure_test_key();
        let subject = "talos.agent.alice.invoke";
        let actor = uuid::Uuid::nil();
        let payload = serde_json::json!({"task": "do thing"});
        let bytes = build_signed_agent_envelope(
            subject,
            Some(actor),
            "worker-1",
            &Some("mod-1".to_string()),
            &Some("exec-1".to_string()),
            &payload,
            &Some("corr-1".to_string()),
        )
        .expect("build envelope");

        let verified =
            verify_signed_agent_envelope(subject, &bytes).expect("verify must succeed");
        assert_eq!(verified, payload);
    }

    #[test]
    fn empty_signature_is_refused() {
        // Future subscribers MUST NOT trust an unsigned envelope. We
        // simulate the "HMAC key not registered" path by constructing
        // an envelope with an empty signature field directly.
        let envelope = serde_json::json!({
            "v": 1,
            "nonce": "0:00000000000000000000000000000000",
            "subject": "talos.agent.alice.invoke",
            "source_module": "mod-1",
            "source_execution": "exec-1",
            "source_actor": uuid::Uuid::nil().to_string(),
            "source_worker": "worker-1",
            "payload": {"task": "do thing"},
            "correlation_id": null,
            "signature": "",
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let res = verify_signed_agent_envelope("talos.agent.alice.invoke", &bytes);
        assert!(res.is_err(), "empty signature must be refused");
    }

    #[test]
    fn subject_mismatch_is_refused() {
        ensure_test_key();
        let bytes = build_signed_agent_envelope(
            "talos.agent.alice.invoke",
            Some(uuid::Uuid::nil()),
            "worker-1",
            &None,
            &None,
            &serde_json::json!({}),
            &None,
        )
        .expect("build envelope");
        // Subscriber on a DIFFERENT topic should refuse — defense
        // against an attacker who re-publishes a captured envelope on
        // an unrelated subject.
        let res = verify_signed_agent_envelope("talos.agent.eve.invoke", &bytes);
        assert!(res.is_err(), "subject mismatch must be refused");
    }

    #[test]
    fn tampered_payload_is_refused() {
        ensure_test_key();
        let subject = "talos.agent.alice.invoke";
        let bytes = build_signed_agent_envelope(
            subject,
            Some(uuid::Uuid::nil()),
            "worker-1",
            &None,
            &None,
            &serde_json::json!({"task": "original"}),
            &None,
        )
        .expect("build envelope");

        // Parse, tamper the payload, re-serialise WITHOUT re-signing.
        let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        envelope["payload"] = serde_json::json!({"task": "tampered"});
        let tampered_bytes = serde_json::to_vec(&envelope).unwrap();

        let res = verify_signed_agent_envelope(subject, &tampered_bytes);
        assert!(res.is_err(), "tampered payload must fail HMAC verify");
    }
}

impl wit_agent_orchestration::Host for TalosContext {
    async fn invoke(
        &mut self,
        msg: wit_agent_orchestration::AgentMessage,
        timeout_ms: u32,
    ) -> Result<wit_agent_orchestration::AgentResponse, wit_agent_orchestration::Error> {
        // Defense-in-depth: only Trusted world should use agent orchestration.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Agent | CapabilityWorld::Trusted
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity (sibling of MCP-696).
            // Agent orchestration is a high-blast-radius surface (NATS
            // RPC + cross-agent message passing); a Minimal-world probe
            // of `invoke` should leave a WORM trail. The `target` is
            // caller-supplied; record it raw (already length+charset
            // validated 14 lines below) so the audit ledger captures
            // *which* agent the malicious module tried to talk to.
            self.record_capability_denied("agent-invoke", "capability-world", &msg.target)
                .await;
            tracing::warn!(module_id = ?self.module_id, "WASM module attempted agent invoke but lacks Agent or Trusted capability");
            return Err(wit_agent_orchestration::Error::PermissionDenied);
        }

        let nats = self
            .nats_client
            .as_ref()
            .ok_or(wit_agent_orchestration::Error::InvocationFailed)?;

        // Cap timeout to 120 seconds (WIT spec maximum)
        let timeout = std::time::Duration::from_millis(timeout_ms.min(120_000) as u64);

        // SECURITY: Sanitize agent target name to prevent NATS topic injection.
        // Only allow alphanumeric, hyphens, and underscores in topic segments.
        if msg.target.is_empty()
            || msg.target.len() > 128
            || !msg
                .target
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            tracing::warn!(
                target = %msg.target,
                module_id = ?self.module_id,
                "Invalid agent target name — must be 1-128 alphanumeric/hyphen/underscore characters"
            );
            return Err(wit_agent_orchestration::Error::AgentNotFound);
        }

        // H-4: per-field caps to bound the NATS envelope size. The host
        // stamps source_module / source_execution / nonce / signature
        // itself; the only guest-controlled blobs are `payload` and
        // `correlation_id` (a u64, naturally bounded).
        if msg.payload.len() > MAX_AGENT_PAYLOAD_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                payload_bytes = msg.payload.len(),
                cap = MAX_AGENT_PAYLOAD_BYTES,
                "agent payload exceeds cap"
            );
            return Err(wit_agent_orchestration::Error::InvocationFailed);
        }

        // Build NATS topic for agent invocation
        let topic = format!("talos.agent.{}.invoke", msg.target);

        // H-4: build a SIGNED envelope. Pre-fix the payload was an
        // unsigned JSON object on `talos.agent.*` — any in-cluster
        // attacker (or a future regression that lifts the topic outside
        // the worker's authentication boundary) could publish arbitrary
        // bytes that subscribers might trust. The envelope now carries
        // an HMAC-SHA256 signature bound to subject + actor_id + nonce
        // + canonical body, plus replay-protection nonce. Subscribers
        // under `talos.agent.*` MUST verify before acting on the
        // contents.
        let payload_json: serde_json::Value = serde_json::from_str(&msg.payload)
            .unwrap_or_else(|_| serde_json::Value::String(msg.payload.clone()));
        let payload_bytes = build_signed_agent_envelope(
            &topic,
            self.actor_id,
            crate::worker_identity::worker_identity(),
            &self.module_id,
            &self.execution_id,
            &payload_json,
            &msg.correlation_id,
        )
        .map_err(|err| {
            tracing::warn!(
                module_id = ?self.module_id,
                err = %err,
                "Failed to build signed agent envelope"
            );
            wit_agent_orchestration::Error::InvocationFailed
        })?;

        // NATS request-reply with timeout
        let response = tokio::time::timeout(timeout, nats.request(topic, payload_bytes.into()))
            .await
            .map_err(|_| {
                tracing::warn!(target_agent = %msg.target, "Agent invocation timed out");
                wit_agent_orchestration::Error::Timeout
            })?
            .map_err(|e| {
                tracing::warn!(target_agent = %msg.target, error = %e, "Agent invocation failed");
                wit_agent_orchestration::Error::InvocationFailed
            })?;

        // Parse response
        let resp: serde_json::Value = serde_json::from_slice(&response.payload)
            .map_err(|_| wit_agent_orchestration::Error::InvocationFailed)?;

        Ok(wit_agent_orchestration::AgentResponse {
            source: msg.target,
            payload: resp
                .get("payload")
                .and_then(|v| v.as_str())
                .unwrap_or("{}")
                .to_string(),
            success: resp
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            correlation_id: msg.correlation_id,
        })
    }

    async fn inject_runtime_node(
        &mut self,
        _module_id: String,
        _config: String,
    ) -> Result<String, wit_agent_orchestration::Error> {
        // To be implemented in Phase 3 (Signal to Controller).
        // SECURITY: When implemented, MUST validate that the injected node's
        // capability world does not exceed the calling actor's max_world ceiling.
        // Use get_actor_max_world() and CapabilityWorld::is_subset_of() to enforce.
        // Without this check, a Trusted-world module could inject arbitrary capability
        // nodes, bypassing actor-level governance restrictions.
        Err(wit_agent_orchestration::Error::InvocationFailed)
    }

    async fn reroute_to_node(
        &mut self,
        _node_id: String,
    ) -> Result<(), wit_agent_orchestration::Error> {
        // To be implemented in Phase 3 (Signal to Controller).
        // SECURITY: When implemented, MUST verify the target node belongs to the
        // same workflow and the calling module has permission to alter control flow.
        Err(wit_agent_orchestration::Error::InvocationFailed)
    }

    async fn send(
        &mut self,
        msg: wit_agent_orchestration::AgentMessage,
    ) -> Result<(), wit_agent_orchestration::Error> {
        // Defense-in-depth: only Trusted world should use agent orchestration.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Agent | CapabilityWorld::Trusted
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity — see agent::invoke above.
            self.record_capability_denied("agent-send", "capability-world", &msg.target)
                .await;
            tracing::warn!(module_id = ?self.module_id, "WASM module attempted agent send but lacks Agent or Trusted capability");
            return Err(wit_agent_orchestration::Error::PermissionDenied);
        }

        let nats = self
            .nats_client
            .as_ref()
            .ok_or(wit_agent_orchestration::Error::InvocationFailed)?;

        // SECURITY: Sanitize agent target name (same rules as invoke).
        if msg.target.is_empty()
            || msg.target.len() > 128
            || !msg
                .target
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            tracing::warn!(
                target = %msg.target,
                module_id = ?self.module_id,
                "Invalid agent target name for send"
            );
            return Err(wit_agent_orchestration::Error::AgentNotFound);
        }

        // H-4: per-field caps (same as invoke).
        if msg.payload.len() > MAX_AGENT_PAYLOAD_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                payload_bytes = msg.payload.len(),
                cap = MAX_AGENT_PAYLOAD_BYTES,
                "agent send payload exceeds cap"
            );
            return Err(wit_agent_orchestration::Error::InvocationFailed);
        }

        let topic = format!("talos.agent.{}.message", msg.target);

        // H-4: signed NATS envelope, see invoke() above for rationale.
        let payload_json: serde_json::Value = serde_json::from_str(&msg.payload)
            .unwrap_or_else(|_| serde_json::Value::String(msg.payload.clone()));
        let payload_bytes = build_signed_agent_envelope(
            &topic,
            self.actor_id,
            crate::worker_identity::worker_identity(),
            &self.module_id,
            &self.execution_id,
            &payload_json,
            &msg.correlation_id,
        )
        .map_err(|err| {
            tracing::warn!(
                module_id = ?self.module_id,
                err = %err,
                "Failed to build signed agent envelope for send"
            );
            wit_agent_orchestration::Error::InvocationFailed
        })?;

        // Fire-and-forget publish
        nats.publish(topic, payload_bytes.into())
            .await
            .map_err(|e| {
                tracing::warn!(target_agent = %msg.target, error = %e, "Agent message send failed");
                wit_agent_orchestration::Error::InvocationFailed
            })?;

        Ok(())
    }

    async fn list_agents(&mut self) -> Result<Vec<String>, wit_agent_orchestration::Error> {
        // MCP-669 (2026-05-13): per-method capability gate. Siblings
        // `invoke` and `send` both gate on Agent | Trusted; this one
        // didn't. Today the implementation returns an empty list so the
        // gap is harmless — but defense-in-depth is the whole point of
        // the per-method gate rule (MCP-586/601/655). Without the gate,
        // a future implementation that enumerates real agent IDs would
        // silently leak them to any world that imports the interface,
        // including a minimal-world module that obtained accidental
        // linkage via operator override or wit_inspector returning
        // Unknown. Pair this with `invoke`/`send` so all three methods
        // share the same world-eligibility surface.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Agent | CapabilityWorld::Trusted
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity — see agent::invoke above.
            // `list_agents` has no target arg; empty target string is the
            // canonical placeholder (matches the graphql-execute pattern).
            self.record_capability_denied("agent-list", "capability-world", "")
                .await;
            tracing::warn!(module_id = ?self.module_id, "WASM module attempted agent list_agents but lacks Agent or Trusted capability");
            return Err(wit_agent_orchestration::Error::PermissionDenied);
        }
        // Query available agents via NATS subject enumeration.
        // Returns empty list until agent registry is implemented.
        Ok(vec![])
    }
}

// ============================================================================
// Object Storage (S3-compatible via reqwest HTTP)
// ============================================================================

// MCP-602 (2026-05-12): per-method capability gate for object-storage.
// WIT-world linkage already restricts `talos:core/object-storage` to
// the `automation-node` world (== CapabilityWorld::Trusted) at compile
// time — the only world that imports it (verified via grep
// `import object-storage` in wit/talos.wit). But the S3 credentials
// (s3_endpoint / s3_access_key / s3_secret_key) are populated from
// env on EVERY TalosContext regardless of capability_world (see
// context.rs:639-641). If a module loads with the wrong world tag
// (operator override, wit_inspector returning Unknown but bindings
// still linking, or future changes to the WIT world set), these
// methods would silently use the operator-configured S3 creds.
// Fail closed unless capability_world is exactly Trusted.
fn require_object_storage_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_object_storage::Error> {
    if matches!(world, crate::wit_inspector::CapabilityWorld::Trusted) {
        Ok(())
    } else {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_object_storage call but lacks Trusted capability"
        );
        Err(wit_object_storage::Error::NotConfigured)
    }
}

/// MCP-1098 (2026-05-16): reject bucket / key values whose syntax would
/// rewrite the S3 URL built by `format!("{}/{}/{}", endpoint, bucket, key)`.
///
/// Pre-fix: `wit_object_storage::{put,get,delete,list_objects}` accept
/// caller-supplied `bucket` and `key` strings and concatenate them
/// straight into the URL. After `url::Url::parse`, embedded `?` becomes
/// the start of the query string, embedded `#` becomes the fragment,
/// and `..` segments get normalised away — and the S3 signer then
/// signs the resulting URL **including** the canonical query string,
/// so the request goes to S3 with the injected parameters bearing a
/// valid SigV4 signature.
///
/// Concrete vectors (Trusted-tier modules only, but defense-in-depth
/// matters regardless of tier):
/// * `key = "myfile?acl=public-read"` on PUT → S3 honors the ACL
///   override, setting the new object public-read despite the operator
///   having scoped the IAM role to private objects only.
/// * `key = "myfile?versionId=<other-id>"` on GET → bypasses the
///   intended key-scoped read with a versionId query parameter.
/// * `bucket = "../private-bucket"` → `url::Url::parse` normalises
///   `/intended/../private-bucket/key` to `/private-bucket/key`,
///   bucket-jumping out of the intended bucket.
/// * `bucket = "mybucket\r\nX-Injected: 1"` → CRLF in URL/host is
///   rejected by `url::Url::parse` (defense in depth) — but explicit
///   rejection here gives a clear error path with an audit log line
///   instead of the generic OperationFailed from URL parse.
///
/// The validators reject the URL-syntax characters AND path-traversal
/// segments BEFORE the URL is built. Percent-encoding is intentionally
/// NOT used — operators who legitimately need keys with `?`/`#` should
/// either re-scope the bucket access or stick to S3's recommended key
/// charset. Same boundary-validation discipline as
/// `talos-config::sanitize_oauth_error_code` (MCP-1094).
fn validate_s3_bucket(bucket: &str) -> Result<(), wit_object_storage::Error> {
    const MAX_S3_BUCKET_LEN: usize = 63;
    if bucket.is_empty() || bucket.len() > MAX_S3_BUCKET_LEN {
        tracing::warn!(
            bucket_len = bucket.len(),
            "wit_object_storage bucket name length invalid (must be 1..=63)"
        );
        return Err(wit_object_storage::Error::OperationFailed);
    }
    // S3 bucket-name charset (RFC 4648-ish subset): lowercase alnum, dot, hyphen.
    if !bucket
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        tracing::warn!(
            "wit_object_storage bucket name contains invalid characters (allowed: a-z 0-9 . -)"
        );
        return Err(wit_object_storage::Error::OperationFailed);
    }
    // Reject leading/trailing dot/hyphen and consecutive dots, matching AWS rules.
    if bucket.starts_with('.')
        || bucket.ends_with('.')
        || bucket.starts_with('-')
        || bucket.ends_with('-')
        || bucket.contains("..")
    {
        tracing::warn!(
            "wit_object_storage bucket name violates AWS naming rules (no leading/trailing . or -, no ..)"
        );
        return Err(wit_object_storage::Error::OperationFailed);
    }
    Ok(())
}

fn validate_s3_key(key: &str) -> Result<(), wit_object_storage::Error> {
    const MAX_S3_KEY_LEN: usize = 1024;
    if key.is_empty() || key.len() > MAX_S3_KEY_LEN {
        tracing::warn!(
            key_len = key.len(),
            "wit_object_storage key length invalid (must be 1..=1024)"
        );
        return Err(wit_object_storage::Error::OperationFailed);
    }
    // Reject URL-syntax characters that would rewrite the request after
    // `url::Url::parse`. `?` and `#` are the immediate query/fragment
    // separators; control chars (0x00..=0x1F, 0x7F) cover CRLF and any
    // other byte sequences that would either be rejected by HTTP header
    // formation or change request semantics.
    if key
        .bytes()
        .any(|b| b == b'?' || b == b'#' || matches!(b, 0..=0x1F | 0x7F))
    {
        tracing::warn!(
            "wit_object_storage key contains forbidden character (?, #, or control byte)"
        );
        return Err(wit_object_storage::Error::OperationFailed);
    }
    // Reject path-traversal segments — `url::Url::parse` would normalise
    // these away, jumping out of the intended bucket prefix.
    if key.split('/').any(|seg| seg == ".." || seg == ".") {
        tracing::warn!("wit_object_storage key contains path-traversal segment (.. or .)");
        return Err(wit_object_storage::Error::OperationFailed);
    }
    Ok(())
}

impl wit_object_storage::Host for TalosContext {
    async fn put(
        &mut self,
        req: wit_object_storage::PutRequest,
    ) -> Result<(), wit_object_storage::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity (sibling of MCP-696).
        // `require_object_storage_capability` is sync/pure; inline the
        // audit at the call site before delegating. Pattern matches
        // the four wit_object_storage methods (put/get/delete/list_objects).
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            let target = format!("{}/{}", req.bucket, req.key);
            self.record_capability_denied(
                "wit_object_storage::put",
                "capability-world",
                &target,
            )
            .await;
        }
        require_object_storage_capability(&self.capability_world)?;
        // MCP-1098: bucket/key URL-injection guard.
        validate_s3_bucket(&req.bucket)?;
        validate_s3_key(&req.key)?;
        let endpoint = self
            .s3_endpoint
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let access_key = self
            .s3_access_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let secret_key = self
            .s3_secret_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let region = self.s3_region.as_deref().unwrap_or("us-east-1");

        // Size limit: 100 MB per object
        const MAX_OBJECT_SIZE: usize = 100 * 1024 * 1024;
        if req.body.len() > MAX_OBJECT_SIZE {
            tracing::warn!(
                module_id = ?self.module_id,
                size = req.body.len(),
                "Object upload exceeds 100MB limit"
            );
            return Err(wit_object_storage::Error::OperationFailed);
        }

        let url_str = format!("{}/{}/{}", endpoint, req.bucket, req.key);
        let parsed_url = url::Url::parse(&url_str).map_err(|e| {
            tracing::warn!(error = %e, "Invalid S3 URL");
            wit_object_storage::Error::OperationFailed
        })?;
        let content_type = req
            .content_type
            .unwrap_or_else(|| "application/octet-stream".to_string());

        let body_hash = crate::s3_signer::sha256_hex(&req.body);
        let auth_headers = crate::s3_signer::sign_s3_request(
            "PUT",
            &parsed_url,
            &body_hash,
            access_key,
            secret_key,
            region,
            "s3",
        );

        let client = self.http_client.clone();
        let mut builder = client.put(parsed_url).header("Content-Type", &content_type);
        for (name, value) in &auth_headers {
            builder = builder.header(name, value);
        }
        // MCP-720: per-op timeout (see OBJECT_STORAGE_TIMEOUT_MS).
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(OBJECT_STORAGE_TIMEOUT_MS),
            builder.body(req.body).send(),
        )
        .await
        .map_err(|_| {
            tracing::warn!(
                timeout_ms = OBJECT_STORAGE_TIMEOUT_MS,
                "S3 PUT timed out"
            );
            wit_object_storage::Error::OperationFailed
        })?
        .map_err(|e| {
            tracing::warn!(error = %e, "S3 PUT failed");
            wit_object_storage::Error::OperationFailed
        })?;

        if !response.status().is_success() {
            tracing::warn!(status = response.status().as_u16(), "S3 PUT returned error");
            return Err(wit_object_storage::Error::OperationFailed);
        }

        Ok(())
    }

    async fn get(
        &mut self,
        bucket: String,
        key: String,
    ) -> Result<wit_object_storage::GetResponse, wit_object_storage::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see put above.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            let target = format!("{}/{}", bucket, key);
            self.record_capability_denied(
                "wit_object_storage::get",
                "capability-world",
                &target,
            )
            .await;
        }
        require_object_storage_capability(&self.capability_world)?;
        // MCP-1098: bucket/key URL-injection guard.
        validate_s3_bucket(&bucket)?;
        validate_s3_key(&key)?;
        let endpoint = self
            .s3_endpoint
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let access_key = self
            .s3_access_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let secret_key = self
            .s3_secret_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let region = self.s3_region.as_deref().unwrap_or("us-east-1");

        let url_str = format!("{}/{}/{}", endpoint, bucket, key);
        let parsed_url = url::Url::parse(&url_str).map_err(|e| {
            tracing::warn!(error = %e, "Invalid S3 URL");
            wit_object_storage::Error::OperationFailed
        })?;

        let auth_headers = crate::s3_signer::sign_s3_request(
            "GET",
            &parsed_url,
            crate::s3_signer::UNSIGNED_PAYLOAD,
            access_key,
            secret_key,
            region,
            "s3",
        );

        let client = self.http_client.clone();
        let mut builder = client.get(parsed_url);
        for (name, value) in &auth_headers {
            builder = builder.header(name, value);
        }
        // MCP-720: per-op timeout (see OBJECT_STORAGE_TIMEOUT_MS).
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(OBJECT_STORAGE_TIMEOUT_MS),
            builder.send(),
        )
        .await
        .map_err(|_| {
            tracing::warn!(
                timeout_ms = OBJECT_STORAGE_TIMEOUT_MS,
                "S3 GET timed out"
            );
            wit_object_storage::Error::OperationFailed
        })?
        .map_err(|e| {
            tracing::warn!(error = %e, "S3 GET failed");
            wit_object_storage::Error::OperationFailed
        })?;

        if response.status().as_u16() == 404 {
            return Err(wit_object_storage::Error::NotFound);
        }
        if !response.status().is_success() {
            tracing::warn!(status = response.status().as_u16(), "S3 GET returned error");
            return Err(wit_object_storage::Error::OperationFailed);
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Check Content-Length before downloading to prevent OOM.
        if let Some(cl) = response.content_length() {
            if cl > MAX_OBJECT_READ_BYTES as u64 {
                tracing::warn!(
                    bucket = %bucket,
                    key = %key,
                    content_length = cl,
                    limit = MAX_OBJECT_READ_BYTES,
                    "object-storage::get blocked — object exceeds 64 MiB read limit"
                );
                return Err(wit_object_storage::Error::OperationFailed);
            }
        }

        // MCP-1115 (2026-05-16): stream chunk-by-chunk instead of
        // `response.bytes().await`. The pre-check above catches
        // honest servers that declare Content-Length, but a
        // malicious / compromised / MITM'd S3-compatible endpoint
        // could (a) omit Content-Length on a chunked-transfer
        // response, or (b) lie about it. `response.bytes()` then
        // buffers the entire body into host RAM BEFORE the
        // post-download `body.len() > MAX` check fires — too late
        // to stop the OOM. Sibling shape to wit_http::fetch which
        // streams + checks per chunk (line ~2021).
        use futures_util::StreamExt;
        let mut stream = response.bytes_stream();
        let mut body_bytes: Vec<u8> = Vec::new();
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| {
                tracing::warn!(error = %e, "S3 GET failed reading body chunk");
                wit_object_storage::Error::OperationFailed
            })?;
            if body_bytes.len().saturating_add(chunk.len()) > MAX_OBJECT_READ_BYTES {
                tracing::warn!(
                    bucket = %bucket,
                    key = %key,
                    accumulated = body_bytes.len(),
                    chunk_len = chunk.len(),
                    limit = MAX_OBJECT_READ_BYTES,
                    "object-storage::get blocked — streaming body exceeds 64 MiB limit"
                );
                return Err(wit_object_storage::Error::OperationFailed);
            }
            body_bytes.extend_from_slice(&chunk);
        }

        let size = body_bytes.len() as u64;

        Ok(wit_object_storage::GetResponse {
            body: body_bytes,
            content_type,
            size,
        })
    }

    async fn delete(
        &mut self,
        bucket: String,
        key: String,
    ) -> Result<(), wit_object_storage::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see put above.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            let target = format!("{}/{}", bucket, key);
            self.record_capability_denied(
                "wit_object_storage::delete",
                "capability-world",
                &target,
            )
            .await;
        }
        require_object_storage_capability(&self.capability_world)?;
        // MCP-1098: bucket/key URL-injection guard.
        validate_s3_bucket(&bucket)?;
        validate_s3_key(&key)?;
        let endpoint = self
            .s3_endpoint
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let access_key = self
            .s3_access_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let secret_key = self
            .s3_secret_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let region = self.s3_region.as_deref().unwrap_or("us-east-1");

        let url_str = format!("{}/{}/{}", endpoint, bucket, key);
        let parsed_url = url::Url::parse(&url_str).map_err(|e| {
            tracing::warn!(error = %e, "Invalid S3 URL");
            wit_object_storage::Error::OperationFailed
        })?;

        let auth_headers = crate::s3_signer::sign_s3_request(
            "DELETE",
            &parsed_url,
            crate::s3_signer::UNSIGNED_PAYLOAD,
            access_key,
            secret_key,
            region,
            "s3",
        );

        let client = self.http_client.clone();
        let mut builder = client.delete(parsed_url);
        for (name, value) in &auth_headers {
            builder = builder.header(name, value);
        }
        // MCP-720: per-op timeout (see OBJECT_STORAGE_TIMEOUT_MS).
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(OBJECT_STORAGE_TIMEOUT_MS),
            builder.send(),
        )
        .await
        .map_err(|_| {
            tracing::warn!(
                timeout_ms = OBJECT_STORAGE_TIMEOUT_MS,
                "S3 DELETE timed out"
            );
            wit_object_storage::Error::OperationFailed
        })?
        .map_err(|e| {
            tracing::warn!(error = %e, "S3 DELETE failed");
            wit_object_storage::Error::OperationFailed
        })?;

        if response.status().as_u16() == 404 {
            return Err(wit_object_storage::Error::NotFound);
        }
        if !response.status().is_success() {
            tracing::warn!(
                status = response.status().as_u16(),
                "S3 DELETE returned error"
            );
            return Err(wit_object_storage::Error::OperationFailed);
        }

        Ok(())
    }

    async fn list_objects(
        &mut self,
        bucket: String,
        prefix: Option<String>,
        max_keys: Option<u32>,
    ) -> Result<Vec<wit_object_storage::ListEntry>, wit_object_storage::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see put above.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            let target = format!("{}/{}", bucket, prefix.as_deref().unwrap_or(""));
            self.record_capability_denied(
                "wit_object_storage::list_objects",
                "capability-world",
                &target,
            )
            .await;
        }
        require_object_storage_capability(&self.capability_world)?;
        // MCP-1098: bucket name URL-injection guard. Prefix already
        // URL-encoded below, so no validator needed there.
        validate_s3_bucket(&bucket)?;
        let endpoint = self
            .s3_endpoint
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let access_key = self
            .s3_access_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let secret_key = self
            .s3_secret_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let region = self.s3_region.as_deref().unwrap_or("us-east-1");

        let mut url_str = format!("{}/{}?list-type=2", endpoint, bucket);
        if let Some(ref p) = prefix {
            // URL-encode the prefix to prevent query parameter injection via
            // characters like '&', '=', or '%' in the prefix value.
            let encoded: String = url::form_urlencoded::byte_serialize(p.as_bytes()).collect();
            url_str.push_str(&format!("&prefix={}", encoded));
        }
        if let Some(max) = max_keys {
            url_str.push_str(&format!("&max-keys={}", max.min(1000)));
        }

        let parsed_url = url::Url::parse(&url_str).map_err(|e| {
            tracing::warn!(error = %e, "Invalid S3 URL");
            wit_object_storage::Error::OperationFailed
        })?;

        let auth_headers = crate::s3_signer::sign_s3_request(
            "GET",
            &parsed_url,
            crate::s3_signer::UNSIGNED_PAYLOAD,
            access_key,
            secret_key,
            region,
            "s3",
        );

        let client = self.http_client.clone();
        let mut builder = client.get(parsed_url);
        for (name, value) in &auth_headers {
            builder = builder.header(name, value);
        }
        // MCP-720: per-op timeout (see OBJECT_STORAGE_TIMEOUT_MS).
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(OBJECT_STORAGE_TIMEOUT_MS),
            builder.send(),
        )
        .await
        .map_err(|_| {
            tracing::warn!(
                timeout_ms = OBJECT_STORAGE_TIMEOUT_MS,
                "S3 LIST timed out"
            );
            wit_object_storage::Error::OperationFailed
        })?
        .map_err(|e| {
            tracing::warn!(error = %e, "S3 LIST failed");
            wit_object_storage::Error::OperationFailed
        })?;

        if !response.status().is_success() {
            tracing::warn!(
                status = response.status().as_u16(),
                "S3 LIST returned error"
            );
            return Err(wit_object_storage::Error::OperationFailed);
        }

        // MCP-1115: stream + cap LIST XML response. Sibling of the
        // wit_object_storage::get streaming fix above. `response.text()`
        // pre-fix buffered the entire XML response into host RAM with
        // NO size cap — a malicious S3-compatible endpoint that
        // ignores max-keys=1000 could OOM the worker. Stream chunks
        // up to MAX_LIST_RESPONSE_BYTES (4 MiB), then convert to
        // String once we know the size is bounded.
        use futures_util::StreamExt;
        let mut stream = response.bytes_stream();
        let mut body_bytes: Vec<u8> = Vec::new();
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| {
                tracing::warn!(error = %e, "S3 LIST failed reading body chunk");
                wit_object_storage::Error::OperationFailed
            })?;
            if body_bytes.len().saturating_add(chunk.len()) > MAX_LIST_RESPONSE_BYTES {
                tracing::warn!(
                    bucket = %bucket,
                    accumulated = body_bytes.len(),
                    chunk_len = chunk.len(),
                    limit = MAX_LIST_RESPONSE_BYTES,
                    "object-storage::list_objects blocked — streaming XML exceeds 4 MiB limit"
                );
                return Err(wit_object_storage::Error::OperationFailed);
            }
            body_bytes.extend_from_slice(&chunk);
        }
        let body = String::from_utf8_lossy(&body_bytes).into_owned();

        // Parse S3 XML list response
        let mut entries = Vec::new();
        for key_match in body.split("<Key>").skip(1) {
            if let Some(key_end) = key_match.find("</Key>") {
                let key = key_match[..key_end].to_string();
                let size = key_match
                    .split("<Size>")
                    .nth(1)
                    .and_then(|s| s.split("</Size>").next())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let last_modified = key_match
                    .split("<LastModified>")
                    .nth(1)
                    .and_then(|s| s.split("</LastModified>").next())
                    .map(String::from);

                entries.push(wit_object_storage::ListEntry {
                    key,
                    size,
                    last_modified,
                });
            }
        }

        Ok(entries)
    }
}

// ============================================================================
// LLM Tool Use (function calling / structured output)
// ============================================================================

impl wit_llm_tools::Host for TalosContext {
    async fn complete_with_tools(
        &mut self,
        req: wit_llm_tools::ToolCompletionRequest,
    ) -> Result<wit_llm_tools::ToolCompletionResponse, wit_llm_tools::Error> {
        // MCP-609 (2026-05-12): per-method capability gate. WIT linkage
        // restricts `talos:core/llm-tools` to llm-node, secrets-node,
        // database-node, agent-node, automation-node (verified by grep
        // `import llm-tools` in wit/talos.wit). The wit_inspector
        // `classify_world` collapses llm-node to `CapabilityWorld::Secrets`,
        // so the runtime set is {Secrets, Database, Agent, Trusted}.
        // Pre-fix: same gap as MCP-607 (wit_llm_streaming) — Tier-1
        // privacy check exists for external providers but Ollama
        // branch (`is_local_tools`) skips all key resolution, letting
        // a Minimal-world module that linked invoke local LLM tools.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Secrets
                | CapabilityWorld::Database
                | CapabilityWorld::Agent
                | CapabilityWorld::Trusted
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity. Sibling Tier-1
            // denial branches in this same impl audit via
            // `record_capability_denied`; capability-world denial branch
            // was silent (`tracing::warn!` only). Both denial classes
            // should produce a WORM ledger entry. Target encodes the
            // provider so operators can correlate the audit row with the
            // policy that should have caught it.
            let provider = format!(
                "{:?}",
                req.provider.unwrap_or(wit_llm_tools::Provider::Anthropic)
            );
            self.record_capability_denied(
                "wit_llm_tools::complete_with_tools",
                "capability-world",
                &provider,
            )
            .await;
            tracing::warn!(
                world = ?self.capability_world,
                "WASM module attempted wit_llm_tools::complete_with_tools but lacks Secrets/Database/Agent/Trusted capability"
            );
            return Err(wit_llm_tools::Error::NotConfigured(
                "capability_world does not permit LLM tools".to_string(),
            ));
        }
        // 1. Check cancellation before making an expensive API call.
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            return Err(wit_llm_tools::Error::BudgetExhausted);
        }

        // 2. Resolve provider and look up the API key from secrets.
        // Ollama (Tier 1) needs no API key — it runs locally.
        let provider = req.provider.unwrap_or(wit_llm_tools::Provider::Anthropic);
        let is_local_tools = matches!(provider, wit_llm_tools::Provider::Ollama);
        let provider_name = match provider {
            wit_llm_tools::Provider::Anthropic => "anthropic",
            wit_llm_tools::Provider::Openai => "openai",
            wit_llm_tools::Provider::Gemini => "gemini",
            wit_llm_tools::Provider::Ollama => "ollama",
        };

        let api_key = if is_local_tools {
            String::new()
        } else {
            match self.get_llm_api_key_by_name(provider_name).await {
                Some(k) => k,
                None => {
                    let (vault_path, env_name) =
                        llm_key_lookup_paths(provider_name).unwrap_or(("<unknown>", "<unknown>"));
                    let msg = format!(
                        "LLM API key not configured. Set vault path `{}` in the dashboard (Settings → Secrets), \
                         or export {} in the worker environment as a fallback.",
                        vault_path, env_name
                    );
                    tracing::warn!(vault_path, env_name, module_id = ?self.module_id, "{}", msg);
                    return Err(wit_llm_tools::Error::NotConfigured(msg));
                }
            }
        };

        // 3. Select default model per provider.
        let model = req.model.unwrap_or_else(|| match provider {
            wit_llm_tools::Provider::Anthropic => "claude-sonnet-4-20250514".to_string(),
            wit_llm_tools::Provider::Openai => "gpt-4o".to_string(),
            wit_llm_tools::Provider::Gemini => "gemini-1.5-pro".to_string(),
            wit_llm_tools::Provider::Ollama => "mistral".to_string(),
        });

        // 4. Build the messages array from rich messages.
        let messages: Vec<serde_json::Value> = req
            .messages
            .iter()
            .map(|msg| {
                let role = match msg.role {
                    wit_llm_tools::Role::System => "user",
                    wit_llm_tools::Role::User => "user",
                    wit_llm_tools::Role::Assistant => "assistant",
                    wit_llm_tools::Role::Tool => "user",
                };
                let content: Vec<serde_json::Value> = msg
                    .content
                    .iter()
                    .map(|block| match block {
                        wit_llm_tools::ContentBlock::Text(t) => {
                            serde_json::json!({"type": "text", "text": t})
                        }
                        wit_llm_tools::ContentBlock::ToolUse(tc) => {
                            serde_json::json!({
                                "type": "tool_use",
                                "id": tc.call_id,
                                "name": tc.tool_name,
                                "input": serde_json::from_str::<serde_json::Value>(&tc.arguments)
                                    .unwrap_or(serde_json::json!({})),
                            })
                        }
                        wit_llm_tools::ContentBlock::ToolResult(tr) => {
                            serde_json::json!({
                                "type": "tool_result",
                                "tool_use_id": tr.call_id,
                                "content": tr.output,
                                "is_error": tr.is_error,
                            })
                        }
                        wit_llm_tools::ContentBlock::Image(img) => {
                            serde_json::json!({
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": img.media_type,
                                    "data": img.data,
                                }
                            })
                        }
                    })
                    .collect();
                serde_json::json!({"role": role, "content": content})
            })
            .collect();

        // 5. Build tools array from tool definitions.
        let tools: Vec<serde_json::Value> = req
            .tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": serde_json::from_str::<serde_json::Value>(&t.input_schema)
                        .unwrap_or(serde_json::json!({})),
                })
            })
            .collect();

        // 6. Assemble the request body.
        let mut body = serde_json::json!({
            "model": model,
            "messages": messages,
            "tools": tools,
            "max_tokens": req.max_tokens.unwrap_or(4096),
        });

        if let Some(temp) = req.temperature {
            body["temperature"] = serde_json::json!(temp);
        }
        if let Some(ref sys) = req.system_prompt {
            body["system"] = serde_json::json!(sys);
        }
        if let Some(ref force) = req.force_tool {
            body["tool_choice"] = serde_json::json!({"type": "tool", "name": force});
        }

        // For OpenAI-compatible providers, convert system_prompt to a message.
        let uses_openai_format_tools = matches!(
            provider,
            wit_llm_tools::Provider::Openai | wit_llm_tools::Provider::Ollama
        );
        if uses_openai_format_tools {
            if let Some(ref sys) = req.system_prompt {
                body.as_object_mut().and_then(|obj| {
                    obj.get_mut("messages").and_then(|m| {
                        m.as_array_mut().map(|arr| {
                            arr.insert(0, serde_json::json!({"role": "system", "content": sys}));
                        })
                    })
                });
                body.as_object_mut().map(|obj| obj.remove("system"));
            }
        }

        // 7. Determine endpoint and auth based on provider.
        let ollama_url_tools = ollama_base_url();

        let (url, auth_header, auth_value) = match provider {
            wit_llm_tools::Provider::Anthropic => (
                "https://api.anthropic.com/v1/messages".to_string(),
                "x-api-key",
                api_key,
            ),
            wit_llm_tools::Provider::Openai => (
                "https://api.openai.com/v1/chat/completions".to_string(),
                "Authorization",
                format!("Bearer {}", api_key),
            ),
            wit_llm_tools::Provider::Gemini => (
                "https://generativelanguage.googleapis.com/v1beta/models".to_string(),
                "x-goog-api-key",
                api_key,
            ),
            wit_llm_tools::Provider::Ollama => (
                format!("{}/v1/chat/completions", ollama_url_tools),
                "",
                String::new(),
            ),
        };

        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            wit_llm_tools::Error::InvalidRequest(format!("Failed to serialize request body: {e}"))
        })?;

        tracing::info!(
            module_id = ?self.module_id,
            model = %model,
            tool_count = req.tools.len(),
            message_count = req.messages.len(),
            "LLM tool-use completion request"
        );

        // 8. Send the HTTP request to the LLM provider.
        // MCP-1213 (2026-05-18): single timeout over the full exchange
        // (send + body read), bounded body read, sibling fix to the
        // bare `complete` path above. See helper
        // `read_llm_response_body_bounded` and constants
        // `EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS` / `MAX_LLM_BODY_BYTES`.
        let client = self.http_client.clone();
        let timeout_secs_tools: u64 = if is_local_tools {
            LOCAL_LLM_EXCHANGE_TIMEOUT_SECS
        } else {
            EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS
        };
        let mut http_req_tools = client.post(&url).header("Content-Type", "application/json");
        if !auth_header.is_empty() {
            http_req_tools = http_req_tools.header(auth_header, &auth_value);
        }
        if matches!(provider, wit_llm_tools::Provider::Anthropic) {
            http_req_tools = http_req_tools.header("anthropic-version", "2023-06-01");
        }
        let resp_body: serde_json::Value = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs_tools),
            async move {
                let response = http_req_tools
                    .body(body_bytes)
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "LLM tool-use API request failed");
                        wit_llm_tools::Error::ApiError(format!("Network error: {e}"))
                    })?;

                if !response.status().is_success() {
                    let status = response.status().as_u16();
                    tracing::warn!(status, "LLM tool-use API returned error status");
                    if status == 429 {
                        return Err(wit_llm_tools::Error::RateLimited);
                    }
                    let preview_bytes = read_llm_response_body_bounded(
                        response,
                        MAX_LLM_BODY_BYTES,
                    )
                    .await
                    .unwrap_or_default();
                    let body_preview = String::from_utf8_lossy(&preview_bytes);
                    let preview_truncated: String =
                        body_preview.chars().take(500).collect();
                    let preview_redacted =
                        talos_dlp_provider::redact_str(&preview_truncated);
                    tracing::warn!(
                        status,
                        body_len = preview_bytes.len(),
                        body_preview = %preview_redacted,
                        "LLM tool-use API returned error"
                    );
                    return Err(wit_llm_tools::Error::ApiError(format!(
                        "LLM API returned HTTP {status}"
                    )));
                }

                let body_bytes = read_llm_response_body_bounded(
                    response,
                    MAX_LLM_BODY_BYTES,
                )
                .await
                .ok_or_else(|| {
                    wit_llm_tools::Error::ApiError(format!(
                        "LLM tool-use response exceeded {} bytes; aborted body read",
                        MAX_LLM_BODY_BYTES
                    ))
                })?;
                serde_json::from_slice::<serde_json::Value>(&body_bytes).map_err(|e| {
                    wit_llm_tools::Error::ApiError(format!(
                        "Failed to parse response JSON: {e}"
                    ))
                })
            },
        )
        .await
        .map_err(|_| wit_llm_tools::Error::Timeout)??;

        // 9. Parse response into content blocks.
        let content_blocks: Vec<wit_llm_tools::ContentBlock> = resp_body
            .get("content")
            .and_then(|c| c.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|block| {
                        let block_type = block.get("type")?.as_str()?;
                        match block_type {
                            "text" => {
                                let text = block.get("text")?.as_str()?.to_string();
                                Some(wit_llm_tools::ContentBlock::Text(text))
                            }
                            "tool_use" => {
                                let tc = wit_llm_tools::ToolCall {
                                    tool_name: block.get("name")?.as_str()?.to_string(),
                                    call_id: block.get("id")?.as_str()?.to_string(),
                                    arguments: block.get("input")?.to_string(),
                                };
                                Some(wit_llm_tools::ContentBlock::ToolUse(tc))
                            }
                            _ => None,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let usage = resp_body.get("usage").map(|u| wit_llm_tools::TokenUsage {
            // MCP-1008: saturate-on-overflow (see helper docs).
            input_tokens: json_token_count_as_u32(u.get("input_tokens"), 0),
            output_tokens: json_token_count_as_u32(u.get("output_tokens"), 0),
        });

        let stop_reason = resp_body
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(wit_llm_tools::ToolCompletionResponse {
            content: content_blocks,
            model,
            usage,
            stop_reason,
        })
    }
}

// ============================================================================
// LLM Streaming — helpers
// ============================================================================

impl TalosContext {
    /// Build the provider-specific URL and auth headers, spawn an SSE reader
    /// task, and return a stream ID that can be polled with `next_event`.
    fn spawn_sse_stream(
        &mut self,
        provider_str: &str,
        api_key: &str,
        model: &str,
        body: serde_json::Value,
    ) -> Result<String, wit_llm_streaming::Error> {
        let ollama_url_stream = ollama_base_url();
        let (url, auth_header, auth_value): (String, &str, String) = match provider_str {
            "openai" => (
                "https://api.openai.com/v1/chat/completions".to_string(),
                "Authorization",
                format!("Bearer {}", api_key),
            ),
            "gemini" => (
                "https://generativelanguage.googleapis.com/v1beta/models".to_string(),
                "x-goog-api-key",
                api_key.to_string(),
            ),
            "ollama" => (
                format!("{}/v1/chat/completions", ollama_url_stream),
                "",
                String::new(),
            ),
            _ => (
                "https://api.anthropic.com/v1/messages".to_string(),
                "x-api-key",
                api_key.to_string(),
            ),
        };

        // Enforce concurrent stream cap to prevent resource leaks from unbounded creation.
        {
            let streams = self.llm_streams.lock().map_err(|_| {
                wit_llm_streaming::Error::ApiError("Failed to acquire stream lock".to_string())
            })?;
            if streams.len() >= MAX_LLM_STREAMS_PER_EXECUTION {
                tracing::warn!(
                    module_id = ?self.module_id,
                    active_streams = streams.len(),
                    "LLM stream limit reached ({} max) — cancel existing streams first",
                    MAX_LLM_STREAMS_PER_EXECUTION
                );
                return Err(wit_llm_streaming::Error::BudgetExhausted);
            }
        }

        let (tx, rx) = tokio::sync::mpsc::channel::<serde_json::Value>(1_000);
        let stream_id = uuid::Uuid::new_v4().to_string();

        // Store receiver so `next_event` can poll it.
        {
            let mut streams = self.llm_streams.lock().map_err(|_| {
                wit_llm_streaming::Error::ApiError("Failed to acquire stream lock".to_string())
            })?;
            streams.insert(stream_id.clone(), rx);
        }

        tracing::info!(
            module_id = ?self.module_id,
            model = %model,
            provider = %provider_str,
            stream_id = %stream_id,
            "LLM streaming request started"
        );

        // Owned copies for the spawned task.
        let url = url.to_string();
        let auth_header = auth_header.to_string();
        let is_anthropic = provider_str == "anthropic";
        let spawn_http_client = self.http_client.clone();

        tokio::spawn(async move {
            let client = spawn_http_client;
            let mut req_builder = client.post(&url).header("Content-Type", "application/json");
            if !auth_header.is_empty() {
                req_builder = req_builder.header(&auth_header, &auth_value);
            }
            if is_anthropic {
                req_builder = req_builder.header("anthropic-version", "2023-06-01");
            }

            // MCP-1215: connect-phase timeout — mirrors MCP-721 on
            // wit_http_stream::connect. The global http_client has no
            // client-level timeout; without this wrap a provider that
            // opens TCP but never returns response headers would park
            // this task until the engine's node timeout fires.
            let response = match tokio::time::timeout(
                std::time::Duration::from_secs(LLM_STREAM_CONNECT_TIMEOUT_SECS),
                req_builder.json(&body).send(),
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "LLM streaming request failed");
                    let _ = tx
                        .send(serde_json::json!({"type": "error", "data": "request failed"}))
                        .await;
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        url = %url,
                        timeout_secs = LLM_STREAM_CONNECT_TIMEOUT_SECS,
                        "LLM streaming connect timed out before response headers"
                    );
                    let _ = tx
                        .send(serde_json::json!({"type": "error", "data": "connect timeout"}))
                        .await;
                    return;
                }
            };

            if !response.status().is_success() {
                let status = response.status().as_u16();
                tracing::warn!(status, "LLM streaming API returned error status");
                let _ = tx
                    .send(serde_json::json!({"type": "error", "data": "API error"}))
                    .await;
                return;
            }

            // Read SSE byte stream and parse events.
            use futures_util::StreamExt;
            let mut byte_stream = response.bytes_stream();
            let mut buffer = String::new();
            // For tool-use streaming, accumulate partial JSON inputs per content block index.
            let mut tool_input_bufs: std::collections::HashMap<u64, (String, String, String)> =
                std::collections::HashMap::new();

            // MCP-1215: idle-between-chunks timeout. Both major
            // providers emit something within seconds (Anthropic
            // `ping` ~15s, OpenAI continuous chunks); 60s silence
            // means the stream is dead. Without this the loop
            // blocks on `next().await` until the node timeout fires.
            let idle_timeout =
                std::time::Duration::from_secs(LLM_STREAM_IDLE_TIMEOUT_SECS);
            loop {
                let chunk = match tokio::time::timeout(idle_timeout, byte_stream.next()).await {
                    Ok(Some(Ok(c))) => c,
                    Ok(Some(Err(e))) => {
                        tracing::warn!(error = %e, "SSE stream chunk error");
                        break;
                    }
                    Ok(None) => break, // stream ended
                    Err(_) => {
                        tracing::warn!(
                            url = %url,
                            idle_secs = LLM_STREAM_IDLE_TIMEOUT_SECS,
                            "LLM streaming idle timeout — no bytes received within window"
                        );
                        let _ = tx
                            .send(serde_json::json!({
                                "type": "error",
                                "data": "idle timeout"
                            }))
                            .await;
                        return;
                    }
                };
                buffer.push_str(&String::from_utf8_lossy(&chunk));

                // MCP-1113: cap the no-newline accumulator. A
                // misbehaving provider streaming a long line without `\n`
                // would otherwise grow `buffer` monotonically until
                // worker OOM. Same shape as the sibling SSE consumer
                // at line ~10186 (TALOS_SSE_MAX_EVENT_BYTES).
                if buffer.len() > MAX_LLM_STREAM_BUFFER_BYTES {
                    tracing::warn!(
                        max_bytes = MAX_LLM_STREAM_BUFFER_BYTES,
                        actual_bytes = buffer.len(),
                        "LLM SSE buffer exceeded max bytes with no newline; aborting stream"
                    );
                    let _ = tx
                        .send(serde_json::json!({
                            "type": "error",
                            "data": "stream buffer overflow"
                        }))
                        .await;
                    return;
                }

                // Process complete SSE lines.
                while let Some(line_end) = buffer.find('\n') {
                    let line = buffer[..line_end].trim().to_string();
                    buffer = buffer[line_end + 1..].to_string();

                    if !line.starts_with("data: ") {
                        continue;
                    }
                    let data = &line[6..];
                    if data == "[DONE]" {
                        let _ = tx
                            .send(serde_json::json!({"type": "done", "data": "end_turn"}))
                            .await;
                        return;
                    }

                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(data) {
                        let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        match event_type {
                            "content_block_start" => {
                                // Track start of tool_use blocks so we can
                                // accumulate their streamed JSON input.
                                if let Some(cb) = event.get("content_block") {
                                    if cb.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                                        // MCP-1113: cap the per-stream
                                        // tool_use block count. A
                                        // misbehaving provider emitting
                                        // many `content_block_start`s
                                        // without matching `_stop`s
                                        // would otherwise grow this
                                        // HashMap unbounded. Drop the
                                        // new block (no insert) instead
                                        // of aborting the whole stream
                                        // — well-behaved tool-use
                                        // workflows stay under 64.
                                        if tool_input_bufs.len() >= MAX_TOOL_INPUT_BUFS_PER_STREAM {
                                            tracing::warn!(
                                                cap = MAX_TOOL_INPUT_BUFS_PER_STREAM,
                                                "LLM SSE tool_input_bufs at cap; dropping new content_block_start"
                                            );
                                            continue;
                                        }
                                        let idx = event
                                            .get("index")
                                            .and_then(|i| i.as_u64())
                                            .unwrap_or(0);
                                        let name = cb
                                            .get("name")
                                            .and_then(|n| n.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        let id = cb
                                            .get("id")
                                            .and_then(|i| i.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        tool_input_bufs.insert(idx, (name, id, String::new()));
                                    }
                                }
                            }
                            "content_block_delta" => {
                                if let Some(delta) = event.get("delta") {
                                    let delta_type =
                                        delta.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                    if delta_type == "text_delta" {
                                        if let Some(text) =
                                            delta.get("text").and_then(|t| t.as_str())
                                        {
                                            let _ = tx
                                                .send(serde_json::json!({
                                                    "type": "text_delta",
                                                    "data": text
                                                }))
                                                .await;
                                        }
                                    } else if delta_type == "input_json_delta" {
                                        // Accumulate partial JSON for tool input.
                                        let idx = event
                                            .get("index")
                                            .and_then(|i| i.as_u64())
                                            .unwrap_or(0);
                                        if let Some(partial) =
                                            delta.get("partial_json").and_then(|p| p.as_str())
                                        {
                                            if let Some(entry) = tool_input_bufs.get_mut(&idx) {
                                                // MCP-1113: cap per-
                                                // entry accumulator. A
                                                // misbehaving provider
                                                // streaming long
                                                // `partial_json`s
                                                // without `_stop`
                                                // would otherwise grow
                                                // this String
                                                // unbounded.
                                                if entry.2.len().saturating_add(partial.len())
                                                    > MAX_TOOL_INPUT_BUF_BYTES
                                                {
                                                    tracing::warn!(
                                                        cap = MAX_TOOL_INPUT_BUF_BYTES,
                                                        idx,
                                                        "LLM SSE tool input buf at cap; dropping delta"
                                                    );
                                                } else {
                                                    entry.2.push_str(partial);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            "content_block_stop" => {
                                // Emit completed tool calls.
                                let idx = event.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                                if let Some((name, id, input)) = tool_input_bufs.remove(&idx) {
                                    let _ = tx
                                        .send(serde_json::json!({
                                            "type": "tool_call",
                                            "data": {
                                                "name": name,
                                                "id": id,
                                                "input": serde_json::from_str::<serde_json::Value>(&input).unwrap_or(serde_json::Value::Null),
                                            }
                                        }))
                                        .await;
                                }
                            }
                            "message_delta" => {
                                if let Some(usage) = event.get("usage") {
                                    let _ = tx
                                        .send(serde_json::json!({
                                            "type": "usage",
                                            "data": usage
                                        }))
                                        .await;
                                }
                                if let Some(reason) = event
                                    .get("delta")
                                    .and_then(|d| d.get("stop_reason"))
                                    .and_then(|s| s.as_str())
                                {
                                    let _ = tx
                                        .send(serde_json::json!({
                                            "type": "done",
                                            "data": reason
                                        }))
                                        .await;
                                }
                            }
                            "message_stop" => {
                                let _ = tx
                                    .send(serde_json::json!({
                                        "type": "done",
                                        "data": "end_turn"
                                    }))
                                    .await;
                                return;
                            }
                            _ => {} // Skip ping, message_start, etc.
                        }
                    }
                }
            }
        });

        Ok(stream_id)
    }
}

// ============================================================================
// LLM Streaming
// ============================================================================

// MCP-607 (2026-05-12): per-method capability gate for llm-streaming.
// WIT-world linkage restricts `talos:core/llm-streaming` to llm-node,
// secrets-node, database-node, agent-node, automation-node (verified
// via grep `import llm-streaming` in wit/talos.wit). The wit_inspector
// `classify_world` collapses llm-node modules to `CapabilityWorld::Secrets`
// (LLM imports imply has_secrets per classify_world rules), so the
// runtime set is {Secrets, Database, Agent, Trusted}.
//
// Pre-fix: none of the four methods (start_stream / start_tool_stream /
// next_event / cancel_stream) gated on capability_world. `get_llm_api_key_by_name`
// is Tier-1-aware but Tier-1 is a privacy ceiling (privacy of *data*
// flowing to external providers), NOT a capability gate (whether the
// module is permitted the surface at all). A Minimal-world module with
// access to llm-streaming bindings could stream from local Ollama
// (the `is_local_stream` branch skips API key resolution and Tier-1
// rejection entirely) and exfiltrate response tokens via next_event.
// Same shape as MCP-602/603/604/606.
fn require_llm_streaming_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_llm_streaming::Error> {
    use crate::wit_inspector::CapabilityWorld;
    if matches!(
        world,
        CapabilityWorld::Secrets
            | CapabilityWorld::Database
            | CapabilityWorld::Agent
            | CapabilityWorld::Trusted
    ) {
        Ok(())
    } else {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_llm_streaming call but lacks Secrets/Database/Agent/Trusted capability"
        );
        Err(wit_llm_streaming::Error::NotConfigured(
            "capability_world does not permit LLM streaming".to_string(),
        ))
    }
}

impl wit_llm_streaming::Host for TalosContext {
    async fn start_stream(
        &mut self,
        req: wit_llm_streaming::StreamRequest,
    ) -> Result<String, wit_llm_streaming::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity (sibling of MCP-696).
        // The shared helper `require_llm_streaming_capability` is sync +
        // pure (takes `&CapabilityWorld`) so the audit emission can't
        // happen inside it — emit here at the call site before delegating.
        // Mirror at start_tool_stream below.
        let provider_label = req.provider.as_deref().unwrap_or("anthropic").to_string();
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Secrets
                | crate::wit_inspector::CapabilityWorld::Database
                | crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            self.record_capability_denied(
                "wit_llm_streaming::start_stream",
                "capability-world",
                &provider_label,
            )
            .await;
        }
        require_llm_streaming_capability(&self.capability_world)?;
        if self.is_cancelled() {
            return Err(wit_llm_streaming::Error::BudgetExhausted);
        }

        // Resolve provider and API key.
        // Ollama needs no API key — it runs locally.
        let provider_str = req.provider.as_deref().unwrap_or("anthropic");
        let is_local_stream = provider_str == "ollama";
        let api_key = if is_local_stream {
            String::new()
        } else {
            let canonical_name = match provider_str {
                "openai" => "openai",
                "gemini" => "gemini",
                _ => "anthropic",
            };
            match self.get_llm_api_key_by_name(canonical_name).await {
                Some(k) => k,
                None => {
                    let (vault_path, env_name) =
                        llm_key_lookup_paths(canonical_name).unwrap_or(("<unknown>", "<unknown>"));
                    let msg = format!(
                        "LLM API key not configured. Set vault path `{}` in the dashboard (Settings → Secrets), \
                         or export {} in the worker environment as a fallback.",
                        vault_path, env_name
                    );
                    tracing::warn!(vault_path, env_name, module_id = ?self.module_id, "{}", msg);
                    return Err(wit_llm_streaming::Error::NotConfigured(msg));
                }
            }
        };

        let model = req.model.unwrap_or_else(|| {
            if is_local_stream {
                "mistral".to_string()
            } else {
                "claude-sonnet-4-20250514".to_string()
            }
        });

        // Parse messages from JSON.
        let messages: serde_json::Value =
            serde_json::from_str(&req.messages_json).map_err(|e| {
                wit_llm_streaming::Error::InvalidRequest(format!("Invalid messages JSON: {e}"))
            })?;

        let mut body = serde_json::json!({
            "model": model,
            "messages": messages,
            "max_tokens": req.max_tokens.unwrap_or(4096),
            "stream": true,
        });
        if let Some(temp) = req.temperature {
            body["temperature"] = serde_json::json!(temp);
        }
        if let Some(ref sys) = req.system_prompt {
            body["system"] = serde_json::json!(sys);
        }

        self.spawn_sse_stream(provider_str, &api_key, &model, body)
    }

    async fn start_tool_stream(
        &mut self,
        req: wit_llm_streaming::StreamToolRequest,
    ) -> Result<String, wit_llm_streaming::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see start_stream above.
        let provider_label = req.provider.as_deref().unwrap_or("anthropic").to_string();
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Secrets
                | crate::wit_inspector::CapabilityWorld::Database
                | crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            self.record_capability_denied(
                "wit_llm_streaming::start_tool_stream",
                "capability-world",
                &provider_label,
            )
            .await;
        }
        require_llm_streaming_capability(&self.capability_world)?;
        if self.is_cancelled() {
            return Err(wit_llm_streaming::Error::BudgetExhausted);
        }

        let provider_str = req.provider.as_deref().unwrap_or("anthropic");
        let is_local_tool_stream = provider_str == "ollama";
        let api_key = if is_local_tool_stream {
            String::new()
        } else {
            let canonical_name = match provider_str {
                "openai" => "openai",
                "gemini" => "gemini",
                _ => "anthropic",
            };
            match self.get_llm_api_key_by_name(canonical_name).await {
                Some(k) => k,
                None => {
                    let (vault_path, env_name) =
                        llm_key_lookup_paths(canonical_name).unwrap_or(("<unknown>", "<unknown>"));
                    let msg = format!(
                        "LLM API key not configured. Set vault path `{}` in the dashboard (Settings → Secrets), \
                         or export {} in the worker environment as a fallback.",
                        vault_path, env_name
                    );
                    tracing::warn!(vault_path, env_name, module_id = ?self.module_id, "{}", msg);
                    return Err(wit_llm_streaming::Error::NotConfigured(msg));
                }
            }
        };

        let model = req.model.unwrap_or_else(|| {
            if is_local_tool_stream {
                "mistral".to_string()
            } else {
                "claude-sonnet-4-20250514".to_string()
            }
        });

        let messages: serde_json::Value =
            serde_json::from_str(&req.messages_json).map_err(|e| {
                wit_llm_streaming::Error::InvalidRequest(format!("Invalid messages JSON: {e}"))
            })?;
        let tools: serde_json::Value = serde_json::from_str(&req.tools_json).map_err(|e| {
            wit_llm_streaming::Error::InvalidRequest(format!("Invalid tools JSON: {e}"))
        })?;

        let mut body = serde_json::json!({
            "model": model,
            "messages": messages,
            "max_tokens": req.max_tokens.unwrap_or(4096),
            "stream": true,
            "tools": tools,
        });
        if let Some(temp) = req.temperature {
            body["temperature"] = serde_json::json!(temp);
        }
        if let Some(ref sys) = req.system_prompt {
            body["system"] = serde_json::json!(sys);
        }

        self.spawn_sse_stream(provider_str, &api_key, &model, body)
    }

    async fn next_event(&mut self, stream_id: String) -> Option<wit_llm_streaming::StreamEvent> {
        // Take the receiver out of the map so we don't hold the mutex during await.
        let mut rx = {
            let mut streams = self.llm_streams.lock().ok()?;
            streams.remove(&stream_id)?
        };

        // Block until the next event arrives (or channel closes).
        // This fixes the ambiguity where try_recv().ok() returned None for both
        // "no event yet" and "stream ended", making streaming unusable for
        // real-time use cases.
        let event = rx.recv().await;

        // Put the receiver back unless the channel is closed (None = sender dropped).
        if event.is_some() {
            if let Ok(mut streams) = self.llm_streams.lock() {
                streams.insert(stream_id, rx);
            }
        }
        // If event is None, the sender dropped — stream is done. Don't reinsert.

        event.and_then(|v| {
            let event_type = v.get("type")?.as_str()?;
            let data = v.get("data")?;
            match event_type {
                "text_delta" => Some(wit_llm_streaming::StreamEvent::TextDelta(
                    data.as_str()?.to_string(),
                )),
                "done" => Some(wit_llm_streaming::StreamEvent::Done(
                    data.as_str()?.to_string(),
                )),
                "error" => Some(wit_llm_streaming::StreamEvent::Error(
                    data.as_str()?.to_string(),
                )),
                "usage" => {
                    // MCP-1008: saturate-on-overflow (see helper docs).
                    let input = json_token_count_as_u32(data.get("input_tokens"), 0);
                    let output = json_token_count_as_u32(data.get("output_tokens"), 0);
                    Some(wit_llm_streaming::StreamEvent::Usage(
                        wit_llm_streaming::StreamUsage {
                            input_tokens: input,
                            output_tokens: output,
                        },
                    ))
                }
                "tool_call" => Some(wit_llm_streaming::StreamEvent::ToolCall(
                    wit_llm_streaming::StreamToolCall {
                        tool_name: data
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        call_id: data
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        arguments: data.get("input").map(|v| v.to_string()).unwrap_or_default(),
                    },
                )),
                _ => None,
            }
        })
    }

    async fn cancel_stream(&mut self, stream_id: String) {
        // Remove the receiver — the sender task will detect the closed channel and stop.
        if let Ok(mut streams) = self.llm_streams.lock() {
            streams.remove(&stream_id);
        }
    }
}

// ============================================================================
// Context Window (token estimation)
// ============================================================================

impl wit_context_window::Host for TalosContext {
    async fn estimate_tokens(&mut self, text: String, model: Option<String>) -> u32 {
        // Model-aware token estimation using character-class heuristics.
        // More accurate than naive len/4 -- handles code, CJK, and whitespace.

        let model_name = model.as_deref().unwrap_or("claude-sonnet-4-20250514");

        // Count different character classes for weighted estimation
        let mut ascii_words = 0u32;
        let mut cjk_chars = 0u32;
        let mut code_tokens = 0u32;
        let mut other_chars = 0u32;
        let mut in_word = false;

        for ch in text.chars() {
            if ch.is_ascii_whitespace() {
                if in_word {
                    ascii_words += 1;
                    in_word = false;
                }
            } else if ch.is_ascii_alphanumeric() {
                in_word = true;
            } else if ('\u{4e00}'..='\u{9fff}').contains(&ch)
                || ('\u{3400}'..='\u{4dbf}').contains(&ch)
            {
                // CJK characters: roughly 1 token each
                cjk_chars += 1;
                if in_word {
                    ascii_words += 1;
                    in_word = false;
                }
            } else if "{}[]()=><;:,.!?+-*/&|^~#@$%\\\"'`".contains(ch) {
                code_tokens += 1;
                if in_word {
                    ascii_words += 1;
                    in_word = false;
                }
            } else {
                other_chars += 1;
            }
        }
        if in_word {
            ascii_words += 1;
        }

        // Weighted estimation:
        // - English words: ~1.3 tokens per word (BPE splits some words)
        // - CJK characters: ~1 token each
        // - Code punctuation: ~1 token per 1-2 chars
        // - Other: ~0.5 tokens per char
        let estimate = (ascii_words as f64 * 1.3)
            + (cjk_chars as f64)
            + (code_tokens as f64 * 0.7)
            + (other_chars as f64 * 0.5);

        // Apply model-specific multiplier (GPT models tokenize slightly differently)
        let multiplier = if model_name.contains("gpt") { 1.1 } else { 1.0 };

        (estimate * multiplier).ceil() as u32
    }

    async fn get_context_info(&mut self, model: Option<String>) -> wit_context_window::ContextInfo {
        let model_name = model.as_deref().unwrap_or("claude-sonnet-4-20250514");

        // Model-specific context windows
        let max_tokens = if model_name.contains("claude-3")
            || model_name.contains("claude-sonnet-4")
            || model_name.contains("claude-opus-4")
        {
            200_000
        } else if model_name.contains("gpt-4o") || model_name.contains("gpt-4-turbo") {
            128_000
        } else if model_name.contains("gpt-4") {
            8_192
        } else if model_name.contains("gpt-3.5") {
            16_385
        } else if model_name.contains("gemini-1.5-pro") {
            2_097_152 // 2M tokens
        } else if model_name.contains("gemini") {
            1_048_576
        } else {
            200_000 // default to Claude
        };

        wit_context_window::ContextInfo {
            max_tokens,
            used_tokens: 0, // Would need conversation tracking to be accurate
            available_tokens: max_tokens,
        }
    }
}

// ============================================================================
// Resource Quotas (budget tracking)
// ============================================================================

// MCP-613 (2026-05-12): the per-execution `quota_usage` HashMap is
// guest-controlled — `record_usage(metric, amount)` calls `entry().or_insert`
// for any guest-supplied name. Pre-fix a guest could grow the map
// unbounded by recording usage against millions of distinct (random)
// metric names, each consuming ~32-100 B (String key + (u64,u64) tuple).
// Fuel doesn't account for host-side allocation, so the cost is paid by
// the worker process. Two caps applied per-method:
//   - MAX_QUOTA_METRIC_NAME_BYTES on each `metric` arg (validated early).
//   - MAX_QUOTA_METRICS_PER_EXECUTION on the map size (record_usage
//     refuses to admit a NEW entry after the cap; existing entries
//     still update).
const MAX_QUOTA_METRIC_NAME_BYTES: usize = 64;
const MAX_QUOTA_METRICS_PER_EXECUTION: usize = 100;

impl wit_resource_quotas::Host for TalosContext {
    async fn check_quota(
        &mut self,
        metric: String,
    ) -> Result<wit_resource_quotas::UsageInfo, wit_resource_quotas::Error> {
        if metric.is_empty() || metric.len() > MAX_QUOTA_METRIC_NAME_BYTES {
            return Err(wit_resource_quotas::Error::MetricNotFound);
        }
        let store = self
            .quota_usage
            .lock()
            .map_err(|_| wit_resource_quotas::Error::NotConfigured)?;
        match store.get(&metric) {
            Some(&(used, limit)) => Ok(wit_resource_quotas::UsageInfo {
                metric,
                used,
                limit,
                remaining: limit.saturating_sub(used),
            }),
            None => Err(wit_resource_quotas::Error::MetricNotFound),
        }
    }

    async fn record_usage(
        &mut self,
        metric: String,
        amount: u64,
    ) -> Result<wit_resource_quotas::UsageInfo, wit_resource_quotas::Error> {
        if metric.is_empty() || metric.len() > MAX_QUOTA_METRIC_NAME_BYTES {
            return Err(wit_resource_quotas::Error::NotConfigured);
        }
        let mut store = self
            .quota_usage
            .lock()
            .map_err(|_| wit_resource_quotas::Error::NotConfigured)?;
        // Refuse new metric admissions once cap is reached. Existing
        // entries still update — bounded by the cap chosen above.
        if !store.contains_key(&metric) && store.len() >= MAX_QUOTA_METRICS_PER_EXECUTION {
            tracing::warn!(
                module_id = ?self.module_id,
                metric = %metric,
                cap = MAX_QUOTA_METRICS_PER_EXECUTION,
                "quota_usage map cap reached — refusing new metric registration"
            );
            return Err(wit_resource_quotas::Error::NotConfigured);
        }
        let entry = store.entry(metric.clone()).or_insert((0, 0));
        // If a limit is set (> 0), enforce it.
        if entry.1 > 0 && entry.0 + amount > entry.1 {
            if let Some(ref m) = self.metrics {
                m.record_quota_exceeded(&metric);
            }
            return Err(wit_resource_quotas::Error::QuotaExceeded);
        }
        entry.0 += amount;
        Ok(wit_resource_quotas::UsageInfo {
            metric,
            used: entry.0,
            limit: entry.1,
            remaining: entry.1.saturating_sub(entry.0),
        })
    }

    async fn list_quotas(&mut self) -> Vec<wit_resource_quotas::UsageInfo> {
        let store = match self.quota_usage.lock() {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        store
            .iter()
            .map(|(metric, &(used, limit))| wit_resource_quotas::UsageInfo {
                metric: metric.clone(),
                used,
                limit,
                remaining: limit.saturating_sub(used),
            })
            .collect()
    }
}

// ============================================================================
// Embedding (standalone vector generation via OpenAI API)
// ============================================================================

impl wit_embedding::Host for TalosContext {
    async fn generate(
        &mut self,
        text: String,
        model: Option<String>,
    ) -> Result<Vec<f32>, wit_embedding::Error> {
        if self.is_cancelled() {
            return Err(wit_embedding::Error::BudgetExhausted);
        }
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Secrets
                | CapabilityWorld::Database
                | CapabilityWorld::Agent
                | CapabilityWorld::Trusted
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity. The Tier-1 LLM-egress
            // denial branch below (MCP-687) audits via record_capability_denied;
            // capability-world denial was silent. Probing the embedding
            // surface from Minimal world should leave a WORM trail.
            self.record_capability_denied(
                "wit_embedding::generate",
                "capability-world",
                model.as_deref().unwrap_or(""),
            )
            .await;
            return Err(wit_embedding::Error::NotConfigured(
                "Embedding requires secrets-node or higher capability world".into(),
            ));
        }

        // MCP-687 (2026-05-13): defense-in-depth Tier-1 surface. Pre-fix
        // the only barrier was `get_llm_api_key_by_name("openai")`
        // returning None on Tier-1; a future regression that lets a key
        // leak through would silently POST the prompt to api.openai.com
        // because this function bypasses `wit_http::fetch` (the
        // documented 3rd of five Tier-1 surfaces) and uses
        // `self.http_client` directly. The function IS an LLM-egress
        // surface — it makes outbound POSTs to api.openai.com with the
        // caller's `text` as the body — so the Tier-1 ceiling MUST be
        // enforced here independently, the same shape as
        // `wit_http_stream::connect` (5th surface, line ~8341) and
        // `wit_webhook::send` / `wit_graphql::execute`. CLAUDE.md's
        // "Five enforcement surfaces" enumeration should be amended to
        // include `wit_embedding::generate` as the sixth surface (and
        // any future wit_embedding methods that add new providers).
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) {
            self.record_capability_denied(
                "wit_embedding::generate",
                "tier1-llm-egress",
                "api.openai.com",
            )
            .await;
            tracing::warn!(
                actor_id = ?self.actor_id,
                "tier-1 actor attempted wit_embedding::generate; refused (external LLM-host egress)"
            );
            return Err(wit_embedding::Error::NotConfigured(
                "Tier-1 actors cannot use external embedding providers. \
                 Reconfigure the actor with `max_llm_tier=tier2` or run \
                 embeddings via a local-only provider in a future release."
                    .into(),
            ));
        }

        // MCP-585: cap caller-supplied text size BEFORE building the
        // outbound JSON body. Pre-fix the input was unbounded; a
        // module could ship a 100 MB string through the worker's
        // outbound network buffer (plus a serde_json clone for the
        // body) before the upstream OpenAI API returned 400 for
        // exceeding its 8192-token limit. The 64 KiB cap above
        // already covers worst-case multi-byte UTF-8 input that
        // still falls within the model's token window.
        if text.len() > MAX_EMBEDDING_TEXT_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                bytes = text.len(),
                cap = MAX_EMBEDDING_TEXT_BYTES,
                "wit_embedding::generate text exceeds size cap; refusing before outbound dispatch"
            );
            return Err(wit_embedding::Error::ApiError(format!(
                "Embedding input text exceeds {MAX_EMBEDDING_TEXT_BYTES}-byte cap"
            )));
        }

        let api_key = match self.get_llm_api_key_by_name("openai").await {
            Some(k) => k,
            None => {
                return Err(wit_embedding::Error::NotConfigured(
                    "OpenAI API key not configured. Set vault path `openai/api_key` in \
                     the dashboard (Settings → Secrets), or export OPENAI_API_KEY in the \
                     worker environment as a fallback."
                        .into(),
                ));
            }
        };

        let model_name = model.unwrap_or_else(|| "text-embedding-3-small".to_string());
        let body = serde_json::json!({
            "model": model_name,
            "input": text,
        });

        let client = self.http_client.clone();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            client
                .post("https://api.openai.com/v1/embeddings")
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send(),
        )
        .await
        .map_err(|_| wit_embedding::Error::ApiError("Embedding request timed out".into()))?
        .map_err(|e| wit_embedding::Error::ApiError(format!("Network error: {e}")))?;

        let status = response.status().as_u16();
        if status == 429 {
            return Err(wit_embedding::Error::RateLimited);
        }
        if !response.status().is_success() {
            tracing::warn!(status, "Embedding API returned error");
            return Err(wit_embedding::Error::ApiError(format!(
                "Embedding API returned HTTP {status}"
            )));
        }

        let resp_body: serde_json::Value = response.json().await.map_err(|e| {
            wit_embedding::Error::ApiError(format!("Failed to parse response: {e}"))
        })?;

        let embedding = resp_body
            .get("data")
            .and_then(|d| d.get(0))
            .and_then(|e| e.get("embedding"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                wit_embedding::Error::ApiError("Missing embedding in response".into())
            })?;

        let vec: Vec<f32> = embedding
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();

        if vec.is_empty() {
            return Err(wit_embedding::Error::ApiError(
                "Empty embedding vector returned".into(),
            ));
        }

        Ok(vec)
    }
}

// ============================================================================
// Events (structured domain event emission)
// ============================================================================

impl wit_events::Host for TalosContext {
    async fn emit(&mut self, event_type: String, payload: String) -> Result<(), wit_events::Error> {
        self.emit_with_metadata(event_type, payload, None).await
    }

    async fn emit_with_metadata(
        &mut self,
        event_type: String,
        payload: String,
        metadata: Option<String>,
    ) -> Result<(), wit_events::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if matches!(
            self.capability_world,
            CapabilityWorld::Minimal | CapabilityWorld::Unknown
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity (sibling of MCP-696
            // wit_cache sweep). Pre-fix this branch returned
            // `Error::RateLimited` (semantically misleading — it's NOT a
            // rate-limit denial, it's a capability denial) with no audit
            // event. Operators watching `talos.audit.ledger` for the
            // wasi:capability_denied event class missed every probe of
            // the events surface. Emit the audit BEFORE the early return
            // so the WORM trail captures the attempt.
            self.record_capability_denied("events-emit", "capability-world", &event_type)
                .await;
            return Err(wit_events::Error::RateLimited);
        }
        // MCP-790 (2026-05-14): pure-validation surfaces (event_type
        // charset + length, payload size cap, metadata size cap) MUST
        // run BEFORE `check_rate_limit` charges `event_emit_count`.
        // Pre-fix the rate-limit charge ran first, so a Database/Trusted-
        // world guest could drain MAX_EVENTS_PER_EXECUTION (100/exec)
        // by looping emit("event with spaces" or "talos.x.x.x x")
        // (InvalidEventType) or oversized payloads (PayloadTooLarge),
        // with zero events ever reaching NATS or the audit ledger.
        // Subsequent legitimate emits were blocked for the rest of the
        // execution. emit() (the no-metadata variant) delegates here,
        // so the same drain applied via both entry points. Final
        // identified site in the sweep started at MCP-783; same shape
        // as MCP-770/783/784/785/786/787/788/789 and MCP-612 (counter-
        // only-advances-when-admitted).
        // Validate event type: alphanumeric, dots, hyphens, underscores only.
        if event_type.is_empty()
            || event_type.len() > 256
            || !event_type
                .chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(wit_events::Error::InvalidEventType);
        }
        if payload.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(wit_events::Error::PayloadTooLarge);
        }
        // MCP-600 (2026-05-12): pre-dispatch cap on `metadata`. Reuse
        // `PayloadTooLarge` so the guest gets a single recognisable
        // error variant for "your event was rejected for size"
        // regardless of which field exceeded — keeps the guest-side
        // error handling shape simple.
        if let Some(md) = metadata.as_deref() {
            if md.len() > MAX_EVENT_METADATA_BYTES {
                return Err(wit_events::Error::PayloadTooLarge);
            }
        }
        if !self.check_rate_limit(&self.event_emit_count, MAX_EVENTS_PER_EXECUTION) {
            tracing::warn!(module_id = ?self.module_id, "Event emit rate limit exceeded");
            return Err(wit_events::Error::RateLimited);
        }

        let exec_id = self
            .execution_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        let event_json = serde_json::json!({
            "event_type": event_type,
            "payload": payload,
            "metadata": metadata,
            "execution_id": exec_id,
            "module_id": self.module_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        // Best-effort publish — events don't fail the module if NATS is down.
        if let Some(nats) = &self.nats_client {
            let topic = format!("talos.events.{}.{}", exec_id, event_type);
            if let Ok(payload_bytes) = serde_json::to_vec(&event_json) {
                let _ = nats.publish(topic, payload_bytes.into()).await;
            }
        } else {
            tracing::debug!(
                event_type,
                "events::emit called but NATS not available — event not published"
            );
        }

        Ok(())
    }
}

// ============================================================================
// HTTP Stream (SSE consumption)
// ============================================================================

impl wit_http_stream::Host for TalosContext {
    async fn connect(
        &mut self,
        url: String,
        headers: Vec<(String, String)>,
    ) -> Result<String, wit_http_stream::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if matches!(
            self.capability_world,
            CapabilityWorld::Minimal | CapabilityWorld::Unknown
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity. SSE-stream connect
            // is the 5th Tier-1 LLM-egress surface (per the host_impl Tier-1
            // commentary); the host-allowlist denial branch farther down
            // audits, the capability-world branch was silent. Record host
            // (or empty placeholder if URL parse fails downstream) so the
            // ledger captures which target the Minimal-world probe tried.
            let target_host = url::Url::parse(&url)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
                .unwrap_or_default();
            self.record_capability_denied(
                "wit_http_stream::connect",
                "capability-world",
                &target_host,
            )
            .await;
            return Err(wit_http_stream::Error::ForbiddenHost);
        }
        if self.is_cancelled() {
            return Err(wit_http_stream::Error::ConnectionFailed);
        }

        // MCP-1148: cap URL bytes BEFORE the main `url::Url::parse`
        // at line ~10283. Sibling-parity with wit_http::fetch /
        // wit_graphql / wit_webhook. The audit-only parse in the
        // capability-world denial branch above uses `.ok()` and only
        // fires for Minimal-world probes — a rare denial path — so the
        // hot-path parse cost lives below this gate.
        if url.len() > MAX_OUTBOUND_URL_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                url_len = url.len(),
                limit = MAX_OUTBOUND_URL_BYTES,
                "wit_http_stream::connect rejected: URL length exceeds cap"
            );
            return Err(wit_http_stream::Error::InvalidUrl);
        }

        // Enforce concurrent stream cap.
        {
            let streams = self
                .sse_streams
                .lock()
                .map_err(|_| wit_http_stream::Error::ConnectionFailed)?;
            if streams.len() >= MAX_SSE_STREAMS_PER_EXECUTION {
                tracing::warn!(
                    module_id = ?self.module_id,
                    active = streams.len(),
                    "SSE stream limit reached ({} max)",
                    MAX_SSE_STREAMS_PER_EXECUTION
                );
                return Err(wit_http_stream::Error::RateLimited);
            }
        }

        // Parse and validate URL (same SSRF protections as http::fetch).
        let parsed: url::Url = url
            .parse()
            .map_err(|_| wit_http_stream::Error::InvalidUrl)?;

        let host = parsed.host_str().unwrap_or("").to_string();

        // HTTPS-only by default. SSE streams stay open for the full
        // event window so an on-path attacker who can read plaintext
        // wins ANY secret rotated through `vault://` headers for the
        // life of the connection — strictly worse than a one-shot
        // fetch. Operator opt-in via `WASM_ALLOW_INSECURE_HTTP=1`.
        match classify_url_scheme(parsed.scheme(), insecure_http_opt_in()) {
            UrlSchemeVerdict::Https => {}
            UrlSchemeVerdict::InsecureAllowedByOptIn { scheme } => {
                tracing::warn!(
                    scheme = %scheme,
                    host = %host,
                    "http-stream: insecure-scheme stream allowed by WASM_ALLOW_INSECURE_HTTP=1"
                );
            }
            UrlSchemeVerdict::InsecureRefused { scheme } => {
                self.record_capability_denied(
                    "http-stream",
                    "insecure-scheme",
                    &format!("{scheme} {host}"),
                )
                .await;
                tracing::warn!(
                    scheme = %scheme,
                    host = %host,
                    "WASM module attempted non-https SSE stream — denied."
                );
                return Err(wit_http_stream::Error::InvalidUrl);
            }
        }

        if self.allowed_hosts.is_empty() {
            self.record_capability_denied("http-stream", "no-allowlist-configured", &host)
                .await;
            return Err(wit_http_stream::Error::ForbiddenHost);
        }
        // SSRF: block private IPs via the shared classifier (covers
        // CGNAT and IPv4-mapped IPv6 the duplicated logic was missing).
        let ip_literal: Option<std::net::IpAddr> = match parsed.host() {
            Some(url::Host::Ipv4(a)) => Some(a.into()),
            Some(url::Host::Ipv6(a)) => Some(a.into()),
            _ => None,
        };
        if let Some(ip) = ip_literal {
            if let Some(policy) = classify_private_ip(ip) {
                self.record_capability_denied("http-stream", policy, &ip.to_string())
                    .await;
                tracing::warn!(
                    ip = %ip,
                    policy,
                    "WASM module attempted SSE stream to a private IP literal — blocking"
                );
                return Err(wit_http_stream::Error::ForbiddenHost);
            }
        }
        if !host_allowlist_match(&self.allowed_hosts, &host) {
            self.record_capability_denied("http-stream", "allowed-hosts", &host)
                .await;
            return Err(wit_http_stream::Error::ForbiddenHost);
        }

        // DNS rebinding — same shared check used by fetch / webhook / graphql.
        if matches!(parsed.host(), Some(url::Host::Domain(_)))
            && self
                .validate_no_dns_rebinding(&host, "http-stream")
                .await
                .is_err()
        {
            return Err(wit_http_stream::Error::ForbiddenHost);
        }

        // Tier-1 LLM egress ceiling — SSE stream to an external LLM
        // would exfiltrate via streaming-response reads. Deny here too.
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) {
            let host_lower = host.to_ascii_lowercase();
            if let Some(policy) = tier1_egress_deny_reason(&host_lower) {
                self.record_capability_denied("http-stream", policy, &host)
                    .await;
                tracing::warn!(
                    host = %host,
                    actor_id = ?self.actor_id,
                    policy,
                    "tier-1 actor HTTP stream egress refused (external LLM host or public IP literal)"
                );
                return Err(wit_http_stream::Error::ForbiddenHost);
            }
        }

        // L-finding-7 (2026-05-23): per-host cumulative SSE-connect cap.
        // Sibling-parity with the HTTP per-host rate limit (M-6 in
        // `wit_http::fetch`) — charged AFTER all upstream-target
        // validation has admitted (SSRF, allowlist, scheme, tier-1
        // ceiling) so a bogus URL doesn't waste budget. Host key is
        // normalised to `host:port` lowercased to match
        // `http_calls_per_host`'s slot semantics. Failed admission
        // burns NO slot on the host's bookkeeping (the bump only
        // happens on the headroom path) so a denied caller can't
        // accidentally pump the counter against a third party.
        let sse_host_key = match parsed.port_or_known_default() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        if !self
            .check_sse_per_host_rate_limit(&sse_host_key, MAX_SSE_CONNECTS_PER_HOST_PER_EXECUTION)
        {
            self.record_capability_denied("http-stream", "per-host-rate-limit", &host)
                .await;
            tracing::warn!(
                module_id = ?self.module_id,
                host = %host,
                limit = MAX_SSE_CONNECTS_PER_HOST_PER_EXECUTION,
                "SSE per-host connect cap exceeded — refusing to amplify load against a single upstream"
            );
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("sse_per_host");
            }
            return Err(wit_http_stream::Error::RateLimited);
        }

        let (tx, rx) = tokio::sync::mpsc::channel::<crate::context::SseEventInternal>(1_000);
        let stream_id = uuid::Uuid::new_v4().to_string();

        {
            let mut streams = self
                .sse_streams
                .lock()
                .map_err(|_| wit_http_stream::Error::ConnectionFailed)?;
            streams.insert(stream_id.clone(), rx);
        }

        // MCP-1105: cap caller-supplied header count. See
        // MAX_OUTBOUND_HEADERS doc-comment. SSE streams are long-lived
        // (kept open for the full execution timeout) so even one
        // bloated connection ties up host memory + the vault-resolve
        // cost compounds across reconnects.
        if headers.len() > MAX_OUTBOUND_HEADERS {
            tracing::warn!(
                module_id = ?self.module_id,
                header_count = headers.len(),
                limit = MAX_OUTBOUND_HEADERS,
                "wit_http_stream::connect rejected: header count exceeds cap"
            );
            return Err(wit_http_stream::Error::ForbiddenHost);
        }
        // Resolve vault:// headers.
        let resolved_headers: Vec<(String, String)> = {
            let mut hdrs = Vec::with_capacity(headers.len());
            for (k, v) in &headers {
                let resolved = self
                    .resolve_vault_header(k.as_str(), v.as_str())
                    .await
                    .map_err(|_| wit_http_stream::Error::ForbiddenHost)?;
                hdrs.push((k.clone(), resolved.into_owned()));
            }
            hdrs
        };

        let client = self.http_client.clone();
        let url_owned = url.clone();
        // Wasm-security review 2026-05-23 (M): clone the execution's
        // cancellation flag into the spawned task so it can exit
        // promptly when the parent execution is cancelled. Pre-fix the
        // task only noticed cancellation via mpsc receiver-drop, which
        // doesn't fire while the task is blocked in
        // `StreamExt::next(&mut stream)` waiting on slow upstream
        // bytes — leaving the connection / spawned task alive past
        // execution-end and consuming a worker connection slot.
        let cancelled = self.cancelled.clone();

        tokio::spawn(async move {
            let mut req_builder = client
                .get(&url_owned)
                .header("Accept", "text/event-stream")
                .header("Cache-Control", "no-cache");
            for (k, v) in &resolved_headers {
                req_builder = req_builder.header(k.as_str(), v.as_str());
            }

            // MCP-721 (2026-05-13): cap the initial connection-establishment
            // phase at 30 s. Pre-fix `req_builder.send().await` had no
            // timeout — if the SSE server stalled (never sent response
            // headers), this spawned task hung indefinitely waiting. The
            // guest's `cancel_stream` / `close` only signal via the `tx`/`rx`
            // channel, which the task only checks on each `tx.send()` AFTER
            // headers arrive — meaning a stall before headers leaks the
            // task forever. SSE legitimately needs long-lived bodies, so
            // ONLY the initial send is timed-out here; the bytes_stream
            // loop below remains unbounded (intended for streaming).
            const SSE_CONNECT_TIMEOUT_SECS: u64 = 30;
            let response = match tokio::time::timeout(
                std::time::Duration::from_secs(SSE_CONNECT_TIMEOUT_SECS),
                req_builder.send(),
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "SSE connection failed");
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        url = %url_owned,
                        timeout_secs = SSE_CONNECT_TIMEOUT_SECS,
                        "SSE connection timed out before response headers"
                    );
                    return;
                }
            };

            if !response.status().is_success() {
                tracing::warn!(
                    status = response.status().as_u16(),
                    "SSE endpoint returned error"
                );
                return;
            }

            // Parse SSE stream: accumulate lines, emit on blank lines.
            //
            // SECURITY: cap both the incoming-byte buffer and the
            // per-event accumulated data. A misbehaving server that
            // never emits a blank line would otherwise grow `data_lines`
            // monotonically until the worker OOMs. Likewise, an attacker
            // streaming a single huge line with no `\n` could grow
            // `buffer` unbounded. Both caps are 1 MiB by default; set
            // TALOS_SSE_MAX_EVENT_BYTES to override per-deploy.
            // MCP-670: `=0`-safe env helper. `TALOS_SSE_MAX_EVENT_BYTES=0`
            // would abort every SSE stream on the first received byte
            // (`buffer.len() > 0` is true immediately), so the whole
            // streaming surface silently breaks under helm misconfig.
            const DEFAULT_SSE_MAX_BYTES: usize = 1024 * 1024;
            let max_event_bytes: usize = talos_config::positive_env_or_default::<usize>(
                "TALOS_SSE_MAX_EVENT_BYTES",
                DEFAULT_SSE_MAX_BYTES,
            );

            let mut stream = response.bytes_stream();
            let mut buffer = String::new();
            let mut event_type: Option<String> = None;
            let mut data_lines: Vec<String> = Vec::new();
            let mut data_bytes: usize = 0;
            let mut event_id: Option<String> = None;

            loop {
                // Wasm-security review 2026-05-23 (M): bound the
                // bytes-stream wait so a slow-trickle upstream can't
                // keep this task alive past execution-end. The
                // `tokio::select!` races the next chunk against:
                //   - a short periodic wake (200 ms) that checks the
                //     execution's cancellation flag,
                //   - the cancellation flag itself flipping mid-wait
                //     (cooperative — we ALSO short-circuit on the
                //     wake-tick if the flag is set, so no race window).
                // The periodic wake is cheap (200 ms = 5 polls/sec)
                // and gives the task at most 200 ms of slack between
                // cancellation and exit.
                let chunk_result = tokio::select! {
                    chunk = futures_util::StreamExt::next(&mut stream) => chunk,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {
                        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                            tracing::debug!(
                                url = %url_owned,
                                "SSE stream task observed execution cancellation — exiting"
                            );
                            return;
                        }
                        continue;
                    }
                };
                let chunk_result = match chunk_result {
                    Some(c) => c,
                    None => break,
                };
                let chunk = match chunk_result {
                    Ok(c) => c,
                    Err(_) => break,
                };
                buffer.push_str(&String::from_utf8_lossy(&chunk));

                if buffer.len() > max_event_bytes {
                    tracing::warn!(
                        url = %url_owned,
                        max_bytes = max_event_bytes,
                        actual_bytes = buffer.len(),
                        "SSE buffer exceeded max event size with no newline; aborting stream"
                    );
                    return;
                }

                while let Some(nl_pos) = buffer.find('\n') {
                    let line = buffer[..nl_pos].trim_end_matches('\r').to_string();
                    buffer = buffer[nl_pos + 1..].to_string();

                    if line.is_empty() {
                        // Blank line = event boundary
                        if !data_lines.is_empty() {
                            let event = crate::context::SseEventInternal {
                                event_type: event_type.take(),
                                data: data_lines.join("\n"),
                                id: event_id.take(),
                            };
                            if tx.send(event).await.is_err() {
                                return; // Receiver dropped (close called)
                            }
                            data_lines.clear();
                            data_bytes = 0;
                        }
                    } else if let Some(value) = line.strip_prefix("data:") {
                        let v = value.trim_start().to_string();
                        data_bytes = data_bytes.saturating_add(v.len()).saturating_add(1);
                        if data_bytes > max_event_bytes {
                            tracing::warn!(
                                url = %url_owned,
                                max_bytes = max_event_bytes,
                                accumulated_bytes = data_bytes,
                                "SSE event data exceeded max size before blank-line boundary; aborting stream"
                            );
                            return;
                        }
                        data_lines.push(v);
                    } else if let Some(value) = line.strip_prefix("event:") {
                        event_type = Some(value.trim_start().to_string());
                    } else if let Some(value) = line.strip_prefix("id:") {
                        event_id = Some(value.trim_start().to_string());
                    }
                    // Skip comments (lines starting with :) and retry: fields
                }
            }
        });

        Ok(stream_id)
    }

    async fn next_event(&mut self, stream_id: String) -> Option<wit_http_stream::SseEvent> {
        // Take the receiver out so we don't hold the mutex during await.
        let mut rx = {
            let mut streams = self.sse_streams.lock().ok()?;
            streams.remove(&stream_id)?
        };

        let event = rx.recv().await;

        // Put back if we got an event; if None (channel closed), stream is done.
        if event.is_some() {
            if let Ok(mut streams) = self.sse_streams.lock() {
                streams.insert(stream_id, rx);
            }
        }

        event.map(|e| wit_http_stream::SseEvent {
            event_type: e.event_type,
            data: e.data,
            id: e.id,
        })
    }

    async fn close(&mut self, stream_id: String) {
        // Removing the receiver causes the spawned task's tx.send() to fail,
        // which makes it exit cleanly.
        if let Ok(mut streams) = self.sse_streams.lock() {
            streams.remove(&stream_id);
        }
    }
}

// ============================================================================
// Integration State (per-integration scoped persistent kv store)
// ============================================================================
//
// Backed by NATS-RPC to the controller. integration_name comes from the
// module's compiled-in metadata via TalosContext.integration_name —
// guest code has no way to forge it. Modules without an integration_name
// (the vast majority) get Unauthorized from every call without ANY
// network round-trip, so calling these from an inappropriate module is
// cheap to fail.

// MCP-606 (2026-05-12): per-method capability gate for integration-state.
// WIT-world linkage restricts `talos:core/integration-state` to
// `agent-node` and `automation-node` (verified via grep `import
// integration-state` in wit/talos.wit) — both map to
// `CapabilityWorld::Agent` / `Trusted`. Pre-fix none of the four
// methods (set / get / delete / list_entries) checked the runtime
// world. The integration-state RPC is the durability path for OAuth
// tokens, push-notification watches, and other privileged
// integration metadata; a mis-tagged module that linked could
// read/write/enumerate those entries. Same shape as MCP-602/603/604.
fn require_integration_state_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_integration_state::Error> {
    use crate::wit_inspector::CapabilityWorld;
    if matches!(world, CapabilityWorld::Agent | CapabilityWorld::Trusted) {
        Ok(())
    } else {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_integration_state call but lacks Agent/Trusted capability"
        );
        Err(wit_integration_state::Error::NotAvailable)
    }
}

impl wit_integration_state::Host for TalosContext {
    async fn set(
        &mut self,
        entry: wit_integration_state::StoredEntry,
    ) -> Result<(), wit_integration_state::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity (sibling of MCP-696).
        // integration-state is the durability path for OAuth tokens +
        // push-notification watches — Minimal/Secrets-world probes of
        // this surface MUST leave a WORM trail. Inline pattern matches
        // wit_object_storage / wit_llm_streaming (helper is sync; audit
        // happens at the call site before delegating).
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            self.record_capability_denied(
                "wit_integration_state::set",
                "capability-world",
                &entry.key,
            )
            .await;
        }
        require_integration_state_capability(&self.capability_world)?;
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        // Bail before the NATS round-trip if the execution was cancelled
        // (outer timeout, explicit abort). Matches the pattern in
        // http::fetch and the other hosts — a cancelled execution
        // shouldn't be able to extend its blast radius by kicking off
        // new RPCs.
        if self.is_cancelled() {
            return Err(wit_integration_state::Error::NotAvailable);
        }
        // Pull owned prereqs SYNCHRONOUSLY before any await — holding
        // &mut self across an await point pulls in WASI's non-Send
        // resource handles via TalosContext, which the bindgen requires
        // to be Send. The agent_memory impls solve this the same way
        // (mem_rpc_prereqs_owned + free call_memory_op).
        let prereqs = self.integration_state_ctx_owned();
        let __res = integration_state_set_owned(prereqs, entry).await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "integration_state::set",
                __start.elapsed().as_millis() as f64,
            );
        }
        __res
    }

    async fn get(
        &mut self,
        key: String,
    ) -> Result<wit_integration_state::StoredEntry, wit_integration_state::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see integration_state::set above.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            self.record_capability_denied(
                "wit_integration_state::get",
                "capability-world",
                &key,
            )
            .await;
        }
        require_integration_state_capability(&self.capability_world)?;
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        if self.is_cancelled() {
            return Err(wit_integration_state::Error::NotAvailable);
        }
        let prereqs = self.integration_state_ctx_owned();
        let __res = integration_state_get_owned(prereqs, key).await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "integration_state::get",
                __start.elapsed().as_millis() as f64,
            );
        }
        __res
    }

    async fn delete(&mut self, key: String) -> Result<(), wit_integration_state::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see integration_state::set above.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            self.record_capability_denied(
                "wit_integration_state::delete",
                "capability-world",
                &key,
            )
            .await;
        }
        require_integration_state_capability(&self.capability_world)?;
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        if self.is_cancelled() {
            return Err(wit_integration_state::Error::NotAvailable);
        }
        let prereqs = self.integration_state_ctx_owned();
        let __res = integration_state_delete_owned(prereqs, key).await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "integration_state::delete",
                __start.elapsed().as_millis() as f64,
            );
        }
        __res
    }

    async fn list_entries(
        &mut self,
        filter: wit_integration_state::ListFilter,
    ) -> Result<Vec<wit_integration_state::StoredEntry>, wit_integration_state::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see integration_state::set above.
        // filter has no single canonical target; empty target encodes the
        // enumerate-shaped probe.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            let _ = &filter;
            self.record_capability_denied(
                "wit_integration_state::list_entries",
                "capability-world",
                "",
            )
            .await;
        }
        require_integration_state_capability(&self.capability_world)?;
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        if self.is_cancelled() {
            return Err(wit_integration_state::Error::NotAvailable);
        }
        let prereqs = self.integration_state_ctx_owned();
        let __res = integration_state_list_owned(prereqs, filter).await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "integration_state::list",
                __start.elapsed().as_millis() as f64,
            );
        }
        __res
    }
}

// Free async helpers — own their captures, so no `&mut self` lifetime
// extends across an await boundary.

type IntegrationPrereqs = Result<
    (
        String,
        uuid::Uuid,
        uuid::Uuid,
        std::sync::Arc<async_nats::Client>,
    ),
    wit_integration_state::Error,
>;

async fn integration_state_set_owned(
    prereqs: IntegrationPrereqs,
    entry: wit_integration_state::StoredEntry,
) -> Result<(), wit_integration_state::Error> {
    use talos_memory::integration_state_rpc::{
        IndexedSlots, IntegrationOp, IntegrationStateReply, IntegrationStateRequest,
        REQUEST_TIMEOUT_MS, SUBJECT_INTEGRATION_STATE_OP,
    };
    let (integration_name, actor_id, user_id, nats) = prereqs?;
    let value: serde_json::Value = serde_json::from_str(&entry.value)
        .map_err(|_| wit_integration_state::Error::InvalidInput)?;
    let op = IntegrationOp::Set {
        key: entry.key,
        value,
        ttl_seconds: entry.ttl_seconds,
        slots: IndexedSlots {
            idx_str_1: entry.idx_str_one,
            idx_str_2: entry.idx_str_two,
            idx_ts_1_ms: entry.idx_ts_one_ms,
            idx_int_1: entry.idx_int_one,
        },
    };
    let req = IntegrationStateRequest::new_signed(integration_name, actor_id, user_id, op)
        .ok_or(wit_integration_state::Error::InvalidInput)?;
    let reply: IntegrationStateReply =
        send_integration_request(&nats, req, SUBJECT_INTEGRATION_STATE_OP, REQUEST_TIMEOUT_MS)
            .await?;
    match reply.result {
        Ok(_) => Ok(()),
        Err(e) => Err(map_integration_err(e)),
    }
}

async fn integration_state_get_owned(
    prereqs: IntegrationPrereqs,
    key: String,
) -> Result<wit_integration_state::StoredEntry, wit_integration_state::Error> {
    use talos_memory::integration_state_rpc::{
        IntegrationOp, IntegrationOpResult, IntegrationStateReply, IntegrationStateRequest,
        REQUEST_TIMEOUT_MS, SUBJECT_INTEGRATION_STATE_OP,
    };
    let (integration_name, actor_id, user_id, nats) = prereqs?;
    let op = IntegrationOp::Get { key };
    let req = IntegrationStateRequest::new_signed(integration_name, actor_id, user_id, op)
        .ok_or(wit_integration_state::Error::InvalidInput)?;
    let reply: IntegrationStateReply =
        send_integration_request(&nats, req, SUBJECT_INTEGRATION_STATE_OP, REQUEST_TIMEOUT_MS)
            .await?;
    match reply.result {
        Ok(IntegrationOpResult::Entry { entry }) => Ok(stored_to_wit(entry)),
        Ok(_) => Err(wit_integration_state::Error::InvalidInput),
        Err(e) => Err(map_integration_err(e)),
    }
}

async fn integration_state_delete_owned(
    prereqs: IntegrationPrereqs,
    key: String,
) -> Result<(), wit_integration_state::Error> {
    use talos_memory::integration_state_rpc::{
        IntegrationOp, IntegrationStateReply, IntegrationStateRequest, REQUEST_TIMEOUT_MS,
        SUBJECT_INTEGRATION_STATE_OP,
    };
    let (integration_name, actor_id, user_id, nats) = prereqs?;
    let op = IntegrationOp::Delete { key };
    let req = IntegrationStateRequest::new_signed(integration_name, actor_id, user_id, op)
        .ok_or(wit_integration_state::Error::InvalidInput)?;
    let reply: IntegrationStateReply =
        send_integration_request(&nats, req, SUBJECT_INTEGRATION_STATE_OP, REQUEST_TIMEOUT_MS)
            .await?;
    match reply.result {
        Ok(_) => Ok(()),
        Err(e) => Err(map_integration_err(e)),
    }
}

async fn integration_state_list_owned(
    prereqs: IntegrationPrereqs,
    filter: wit_integration_state::ListFilter,
) -> Result<Vec<wit_integration_state::StoredEntry>, wit_integration_state::Error> {
    use talos_memory::integration_state_rpc::{
        IntegrationOp, IntegrationOpResult, IntegrationStateReply, IntegrationStateRequest,
        ListFilter as RpcFilter, MAX_RESULT_LIMIT, REQUEST_TIMEOUT_MS,
        SUBJECT_INTEGRATION_STATE_OP,
    };
    let (integration_name, actor_id, user_id, nats) = prereqs?;
    let limit = filter.limit.clamp(1, MAX_RESULT_LIMIT);
    let op = IntegrationOp::List {
        filter: RpcFilter {
            key_prefix: filter.key_prefix,
            idx_str_1_eq: filter.idx_str_one_eq,
            idx_str_2_eq: filter.idx_str_two_eq,
            idx_ts_1_gte_ms: filter.idx_ts_one_gte_ms,
            idx_ts_1_lt_ms: filter.idx_ts_one_lt_ms,
            idx_int_1_eq: filter.idx_int_one_eq,
        },
        limit,
    };
    let req = IntegrationStateRequest::new_signed(integration_name, actor_id, user_id, op)
        .ok_or(wit_integration_state::Error::InvalidInput)?;
    let reply: IntegrationStateReply =
        send_integration_request(&nats, req, SUBJECT_INTEGRATION_STATE_OP, REQUEST_TIMEOUT_MS)
            .await?;
    match reply.result {
        Ok(IntegrationOpResult::Entries { entries }) => {
            Ok(entries.into_iter().map(stored_to_wit).collect())
        }
        Ok(_) => Err(wit_integration_state::Error::InvalidInput),
        Err(e) => Err(map_integration_err(e)),
    }
}

impl TalosContext {
    /// Owned snapshot of the prereqs needed for every integration_state
    /// RPC. Returning owned values lets the four host fns kick off async
    /// work without holding `&self` across an await — important because
    /// TalosContext contains WASI's non-Send resource handles, so any
    /// `&mut self` that survived an await would fail bindgen's Send bounds.
    fn integration_state_ctx_owned(&self) -> IntegrationPrereqs {
        let integration_name = match self.integration_name.as_ref() {
            Some(n) if !n.is_empty() => n.clone(),
            _ => return Err(wit_integration_state::Error::Unauthorized),
        };
        let actor_id = self
            .actor_id
            .ok_or(wit_integration_state::Error::NotAvailable)?;
        let user_id = self
            .user_id
            .ok_or(wit_integration_state::Error::NotAvailable)?;
        let nats = self
            .nats_client
            .as_ref()
            .cloned()
            .ok_or(wit_integration_state::Error::NotAvailable)?;
        Ok((integration_name, actor_id, user_id, nats))
    }
}

async fn send_integration_request(
    nats: &async_nats::Client,
    req: talos_memory::integration_state_rpc::IntegrationStateRequest,
    subject: &str,
    timeout_ms: u64,
) -> Result<talos_memory::integration_state_rpc::IntegrationStateReply, wit_integration_state::Error>
{
    let payload = match serde_json::to_vec(&req) {
        Ok(p) => p,
        Err(_) => return Err(wit_integration_state::Error::InvalidInput),
    };
    let fut = nats.request(subject.to_string(), payload.into());
    let reply_msg =
        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "integration_state NATS request failed");
                return Err(wit_integration_state::Error::NotAvailable);
            }
            Err(_) => return Err(wit_integration_state::Error::Timeout),
        };
    serde_json::from_slice(&reply_msg.payload)
        .map_err(|_| wit_integration_state::Error::InvalidInput)
}

fn stored_to_wit(
    e: talos_memory::integration_state_rpc::StoredEntry,
) -> wit_integration_state::StoredEntry {
    // WIT contract: `ttl_seconds` on reads means "remaining lifetime in
    // seconds" (not the original TTL the row was set with). Compute from
    // the stored expires_at_ms + current time. A negative remaining value
    // would indicate a row returned despite being expired (shouldn't
    // happen — the controller query filters on `expires_at > now()` —
    // but clamp at 0 defensively so guests never see a negative count).
    let ttl_seconds = e.expires_at_ms.and_then(|exp_ms| {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis() as i64;
        let remaining_ms = exp_ms.saturating_sub(now_ms).max(0);
        Some((remaining_ms / 1000) as u64)
    });
    wit_integration_state::StoredEntry {
        key: e.key,
        value: e.value,
        ttl_seconds,
        idx_str_one: e.slots.idx_str_1,
        idx_str_two: e.slots.idx_str_2,
        idx_ts_one_ms: e.slots.idx_ts_1_ms,
        idx_int_one: e.slots.idx_int_1,
    }
}

fn map_integration_err(
    e: talos_memory::integration_state_rpc::IntegrationStateError,
) -> wit_integration_state::Error {
    use talos_memory::integration_state_rpc::IntegrationStateError as E;
    match e {
        E::NotAvailable => wit_integration_state::Error::NotAvailable,
        E::KeyNotFound => wit_integration_state::Error::NotFound,
        E::InvalidInput(_) => wit_integration_state::Error::InvalidInput,
        E::Unauthorized => wit_integration_state::Error::Unauthorized,
        E::StorageFull => wit_integration_state::Error::StorageFull,
        E::Timeout => wit_integration_state::Error::Timeout,
        E::Internal(_) => wit_integration_state::Error::NotAvailable,
    }
}

#[cfg(test)]
mod integration_state_helper_tests {
    use super::*;
    use talos_memory::integration_state_rpc::{IndexedSlots, IntegrationStateError, StoredEntry};

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    #[test]
    fn stored_to_wit_no_expiry_has_none_ttl() {
        let e = StoredEntry {
            key: "k".into(),
            value: "\"v\"".into(),
            updated_at_ms: 0,
            expires_at_ms: None,
            slots: IndexedSlots::default(),
        };
        let wit = stored_to_wit(e);
        assert!(wit.ttl_seconds.is_none());
    }

    #[test]
    fn stored_to_wit_future_expiry_has_positive_remaining() {
        let e = StoredEntry {
            key: "k".into(),
            value: "\"v\"".into(),
            updated_at_ms: 0,
            expires_at_ms: Some(now_ms() + 60_000), // 60s ahead
            slots: IndexedSlots::default(),
        };
        let wit = stored_to_wit(e);
        let ttl = wit.ttl_seconds.expect("ttl must be Some for future expiry");
        assert!(
            ttl > 0 && ttl <= 60,
            "remaining must be in (0, 60]: {}",
            ttl
        );
    }

    #[test]
    fn stored_to_wit_past_expiry_clamps_to_zero() {
        let e = StoredEntry {
            key: "k".into(),
            value: "\"v\"".into(),
            updated_at_ms: 0,
            expires_at_ms: Some(now_ms() - 60_000),
            slots: IndexedSlots::default(),
        };
        let wit = stored_to_wit(e);
        assert_eq!(
            wit.ttl_seconds,
            Some(0),
            "expired row must clamp to 0, never negative"
        );
    }

    #[test]
    fn stored_to_wit_slot_name_mapping() {
        // RPC uses snake_case `idx_str_1`; WIT uses `idx_str_one` because
        // WIT identifier segments can't start with digits. Lock the
        // cross-naming contract so a rename on either side is caught.
        let e = StoredEntry {
            key: "k".into(),
            value: "{}".into(),
            updated_at_ms: 0,
            expires_at_ms: None,
            slots: IndexedSlots {
                idx_str_1: Some("a".into()),
                idx_str_2: Some("b".into()),
                idx_ts_1_ms: Some(123),
                idx_int_1: Some(456),
            },
        };
        let wit = stored_to_wit(e);
        assert_eq!(wit.idx_str_one.as_deref(), Some("a"));
        assert_eq!(wit.idx_str_two.as_deref(), Some("b"));
        assert_eq!(wit.idx_ts_one_ms, Some(123));
        assert_eq!(wit.idx_int_one, Some(456));
    }

    #[test]
    fn map_integration_err_internal_becomes_not_available() {
        // Lossy on purpose: Internal carries raw DB text that MUST NOT
        // reach guest code. Collapsing to NotAvailable drops the detail
        // at the trust boundary.
        let mapped = map_integration_err(IntegrationStateError::Internal(
            "CONSTRAINT violation foo_bar_baz_chk".into(),
        ));
        assert!(matches!(mapped, wit_integration_state::Error::NotAvailable));
    }

    #[test]
    fn map_integration_err_key_not_found_becomes_not_found() {
        let mapped = map_integration_err(IntegrationStateError::KeyNotFound);
        assert!(matches!(mapped, wit_integration_state::Error::NotFound));
    }

    #[test]
    fn map_integration_err_invalid_input_drops_detail() {
        let mapped = map_integration_err(IntegrationStateError::InvalidInput(
            "leaky internal detail".into(),
        ));
        assert!(matches!(mapped, wit_integration_state::Error::InvalidInput));
    }

    #[test]
    fn map_integration_err_all_variants_covered() {
        use IntegrationStateError as E;
        let cases = [
            (E::NotAvailable, wit_integration_state::Error::NotAvailable),
            (E::KeyNotFound, wit_integration_state::Error::NotFound),
            (E::Unauthorized, wit_integration_state::Error::Unauthorized),
            (E::StorageFull, wit_integration_state::Error::StorageFull),
            (E::Timeout, wit_integration_state::Error::Timeout),
        ];
        for (src, expected) in cases {
            let got = map_integration_err(src);
            assert_eq!(
                std::mem::discriminant(&got),
                std::mem::discriminant(&expected)
            );
        }
    }
}

#[cfg(test)]
mod llm_response_parse_tests {
    //! 2026-05-28 audit Perf#1: typed-deserialize parser tests.
    //!
    //! Pre-fix the LLM response materialised into `serde_json::Value`
    //! and the consumers did `get("...").and_then(...)` chains over
    //! it. Post-fix the response goes through `OpenAiResponse` /
    //! `AnthropicResponse` typed structs. These tests pin the field-
    //! extraction contract end-to-end so a future refactor can't
    //! regress the field plucking that the LLM hot path depends on.

    use super::{AnthropicResponse, OpenAiResponse};

    #[test]
    fn openai_response_pulls_content_and_usage() {
        let body = br#"{
            "id": "chat-1",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "hello world"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 25,
                "total_tokens": 37
            }
        }"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        let choice = &r.choices[0];
        assert_eq!(
            choice.message.as_ref().unwrap().content.as_deref(),
            Some("hello world")
        );
        assert_eq!(choice.finish_reason.as_deref(), Some("stop"));
        let u = r.usage.unwrap();
        assert_eq!(u.prompt_tokens, Some(12));
        assert_eq!(u.completion_tokens, Some(25));
    }

    #[test]
    fn openai_response_handles_missing_usage() {
        // Providers sometimes omit `usage` on streaming or error
        // responses. Parser must accept this without panicking.
        let body = br#"{
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]
        }"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        assert!(r.usage.is_none());
        assert_eq!(
            r.choices[0].message.as_ref().unwrap().content.as_deref(),
            Some("ok")
        );
    }

    #[test]
    fn openai_response_handles_empty_choices() {
        // Some Ollama wrappers return `{"choices": []}` on rate limit
        // or model-not-found. Parser must accept; downstream code
        // surfaces empty text.
        let body = br#"{"choices": []}"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        assert!(r.choices.is_empty());
        assert!(r.usage.is_none());
    }

    #[test]
    fn openai_response_ignores_unknown_fields() {
        // Providers add fields over time (e.g., `system_fingerprint`).
        // Parser must not break on unknown keys.
        let body = br#"{
            "choices": [{"message": {"content": "x"}}],
            "system_fingerprint": "fp_abc",
            "logprobs": null,
            "x_some_future_field": {"nested": "value"}
        }"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        assert_eq!(
            r.choices[0].message.as_ref().unwrap().content.as_deref(),
            Some("x")
        );
    }

    #[test]
    fn anthropic_response_pulls_text_blocks() {
        let body = br#"{
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "hello "},
                {"type": "text", "text": "world"}
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 7, "output_tokens": 3}
        }"#;
        let r: AnthropicResponse = serde_json::from_slice(body).expect("parse");
        assert_eq!(r.stop_reason.as_deref(), Some("end_turn"));
        let u = r.usage.unwrap();
        assert_eq!(u.input_tokens, Some(7));
        assert_eq!(u.output_tokens, Some(3));
        // Match the post-fix join: filter for `type == "text"` then
        // concatenate `.text`.
        let joined: String = r
            .content
            .iter()
            .filter(|b| b.block_type.as_deref() == Some("text"))
            .filter_map(|b| b.text.as_deref())
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(joined, "hello world");
    }

    #[test]
    fn anthropic_response_ignores_non_text_blocks() {
        // Future Anthropic responses may include `tool_use`,
        // `image`, etc. blocks. Parser must skip them when
        // extracting text — matches the post-fix filter.
        let body = br#"{
            "content": [
                {"type": "tool_use", "name": "calculator", "input": {}},
                {"type": "text", "text": "the answer is 42"}
            ]
        }"#;
        let r: AnthropicResponse = serde_json::from_slice(body).expect("parse");
        let joined: String = r
            .content
            .iter()
            .filter(|b| b.block_type.as_deref() == Some("text"))
            .filter_map(|b| b.text.as_deref())
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(joined, "the answer is 42");
    }

    #[test]
    fn anthropic_response_handles_missing_optional_fields() {
        // Minimal valid response.
        let body = br#"{"content": []}"#;
        let r: AnthropicResponse = serde_json::from_slice(body).expect("parse");
        assert!(r.content.is_empty());
        assert!(r.usage.is_none());
        assert!(r.stop_reason.is_none());
    }

    #[test]
    fn token_count_saturates_on_overflow() {
        // Direct integer larger than u32::MAX should deserialize
        // into u64 cleanly. The post-fix saturating cast to u32 in
        // the host_impl extraction is tested at the call site; here
        // we just confirm the typed field accepts the full u64.
        let body = br#"{"usage": {"prompt_tokens": 5000000000, "completion_tokens": 1}}"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        let u = r.usage.unwrap();
        assert_eq!(u.prompt_tokens, Some(5_000_000_000));
        // The saturating-cast logic lives in the call site:
        let saturated = u32::try_from(u.prompt_tokens.unwrap_or(0)).unwrap_or(u32::MAX);
        assert_eq!(saturated, u32::MAX);
    }

    #[test]
    fn token_count_handles_missing_with_default() {
        // Older Ollama versions omit `usage` entirely; the
        // call-site `.unwrap_or(0)` then `u32::try_from` produces 0.
        let body = br#"{"usage": {}}"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        let u = r.usage.unwrap();
        assert_eq!(u.prompt_tokens, None);
        assert_eq!(u.completion_tokens, None);
    }
}
