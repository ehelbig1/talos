//! `graphql` host interface plus the L-17 shape-based introspection
//! query detector.

use super::*;

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
        if b == b'_'
            && bytes.get(i + 1).copied() == Some(b'_')
            && has_introspection_token_at(after_brace, i)
        {
            return true;
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
        if bytes[i] == b'_'
            && bytes.get(i + 1).copied() == Some(b'_')
            && has_introspection_token_at(body, i)
        {
            return true;
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
        let s = strip_graphql_string_literals(r#"f(desc: """fragment X on Q { __schema }""") {}"#);
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
        assert!(looks_like_graphql_introspection(
            "{ __schema { types { name } } }"
        ));
    }

    #[test]
    fn detects_top_level_type_query() {
        assert!(looks_like_graphql_introspection(
            "{ __type(name: \"User\") { name } }"
        ));
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
        let timeout_ms = req.timeout_ms.unwrap_or(30_000).min(MAX_HTTP_TIMEOUT_MS) as u64;

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
            let actor_tier = self.max_llm_tier == talos_workflow_job_protocol::LlmTier::Tier1;
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
                    if actor_tier {
                        "tier1-introspection"
                    } else {
                        "env-introspection-block"
                    },
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
            if let Some((ip, policy)) = denied_ip_literal(&parsed) {
                self.record_capability_denied("graphql", policy, &ip.to_string())
                    .await;
                tracing::warn!(
                    ip = %ip,
                    policy,
                    "WASM module attempted GraphQL request to a private IP literal — blocking"
                );
                return Err(wit_graphql::Error::Networkerror);
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
        if !self.check_rate_limit(&self.graphql_query_count, MAX_GRAPHQL_QUERIES_PER_EXECUTION) {
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
    pub(crate) async fn check_global_expose_limit(
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
