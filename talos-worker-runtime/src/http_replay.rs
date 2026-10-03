//! Recorded HTTP answers for a REHEARSAL (`test_module`).
//!
//! A module's cost and its handling of a real response could, until this
//! existed, be measured only by calling the real service. With an
//! [`HttpReplay`] on the context, `http::fetch` / `fetch_all` are answered
//! from recorded responses instead of a socket: no DNS lookup, no connection,
//! no secret resolved. Everything that decides whether the request MAY be
//! made still runs first (capability world, `allowed_hosts`, the egress
//! posture, the write ceiling, the rate limits, `allowed_methods`), so a
//! request the sandbox would refuse is refused here too.
//!
//! Answers are given IN ORDER: the Nth request gets the Nth fixture. A
//! fixture may name the method and a substring of the URL it expects; a
//! request that does not match is refused and the mismatch is recorded, so a
//! module that calls a different endpoint than the one rehearsed cannot be
//! handed the wrong body.
//!
//! # Who can set this
//!
//! Only code running in the controller process that builds a
//! [`crate::runtime::SecurityPolicy`] by hand. It is not a field of any wire
//! message: a dispatched job cannot carry one, and the worker binary never
//! constructs one (pinned by `worker/src/http_replay_pin.rs`).

use std::sync::Mutex;

/// The most fixtures one rehearsal may carry.
pub const MAX_FIXTURES: usize = 64;
/// The most bytes all fixture bodies together may hold.
pub const MAX_TOTAL_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Longest `url_contains` accepted.
const MAX_MATCH_CHARS: usize = 512;
const MAX_HEADERS: usize = 32;

/// One recorded answer.
#[derive(Debug, Clone)]
pub struct HttpFixture {
    /// The verb the request must use (`GET`, `POST`, …), when given.
    pub method: Option<String>,
    /// A substring the request URL must contain, when given.
    pub url_contains: Option<String>,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// What happened to one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// Answered by the fixture at this index with this status.
    Answered { fixture: usize, status: u16 },
    /// The next fixture expects a different request.
    Mismatch { fixture: usize, expected: String },
    /// Every fixture has been used.
    Exhausted,
}

/// One request the module made, as far as it is safe to show: the host and
/// path, never the query string or the body (either can carry a credential
/// reference or personal data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayedCall {
    pub method: &'static str,
    pub host: String,
    pub path: String,
    pub request_bytes: usize,
    pub outcome: ReplayOutcome,
}

/// Why a request was not answered, in words for the host diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayMiss(pub String);

#[derive(Debug, Default)]
struct Progress {
    next: usize,
    calls: Vec<ReplayedCall>,
}

/// The recorded answers and the record of what was asked.
#[derive(Debug)]
pub struct HttpReplay {
    fixtures: Vec<HttpFixture>,
    progress: Mutex<Progress>,
}

impl HttpReplay {
    /// Refuses a set that is empty, too large, or malformed, so a rehearsal
    /// never starts with fixtures it would silently ignore.
    pub fn new(fixtures: Vec<HttpFixture>, max_response_bytes: usize) -> Result<Self, String> {
        if fixtures.is_empty() {
            return Err("http_fixtures is empty: give at least one recorded response, or omit it to make real requests".to_string());
        }
        if fixtures.len() > MAX_FIXTURES {
            return Err(format!(
                "http_fixtures holds {} responses; the most is {MAX_FIXTURES}",
                fixtures.len()
            ));
        }
        let mut total = 0usize;
        for (i, f) in fixtures.iter().enumerate() {
            if !(100..=599).contains(&f.status) {
                return Err(format!(
                    "http_fixtures[{i}].status {} is not an HTTP status",
                    f.status
                ));
            }
            if let Some(m) = &f.method {
                if !matches!(m.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
                    return Err(format!(
                        "http_fixtures[{i}].method must be one of GET, POST, PUT, PATCH, DELETE"
                    ));
                }
            }
            if f.url_contains
                .as_ref()
                .is_some_and(|u| u.is_empty() || u.chars().count() > MAX_MATCH_CHARS)
            {
                return Err(format!(
                    "http_fixtures[{i}].url_contains must be 1 to {MAX_MATCH_CHARS} characters"
                ));
            }
            if f.headers.len() > MAX_HEADERS {
                return Err(format!(
                    "http_fixtures[{i}] has more than {MAX_HEADERS} headers"
                ));
            }
            if f.body.len() > max_response_bytes {
                return Err(format!(
                    "http_fixtures[{i}].body is {} bytes; a real response over {max_response_bytes} bytes is refused, so this one could never arrive",
                    f.body.len()
                ));
            }
            total = total.saturating_add(f.body.len());
        }
        if total > MAX_TOTAL_BODY_BYTES {
            return Err(format!(
                "http_fixtures bodies total {total} bytes; the most is {MAX_TOTAL_BODY_BYTES}"
            ));
        }
        Ok(Self {
            fixtures,
            progress: Mutex::new(Progress::default()),
        })
    }

    /// As [`Self::new`], held to the cap a real response is held to
    /// (`WASM_HTTP_MAX_RESPONSE_BYTES`): a recording larger than that could
    /// never have arrived.
    pub fn for_rehearsal(fixtures: Vec<HttpFixture>) -> Result<Self, String> {
        Self::new(fixtures, crate::host::wasi_http::max_response_bytes())
    }

    /// The answer for the next request, or why there is none. Either way the
    /// request is recorded. A mismatch does NOT use up the fixture.
    pub fn answer(
        &self,
        method: &'static str,
        url: &url::Url,
        request_bytes: usize,
    ) -> Result<HttpFixture, ReplayMiss> {
        let mut p = self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = p.calls.len() + 1;
        let host = url.host_str().unwrap_or("").to_string();
        let path = url.path().to_string();
        let (outcome, result) = match self.fixtures.get(p.next) {
            None => (
                ReplayOutcome::Exhausted,
                Err(ReplayMiss(format!(
                    "request {n} ({method} {host}{path}) has no recorded response left: {} were given and all are used",
                    self.fixtures.len()
                ))),
            ),
            Some(f) => {
                let method_ok = f.method.as_deref().is_none_or(|m| m == method);
                let url_ok = f.url_contains.as_deref().is_none_or(|u| url.as_str().contains(u));
                if method_ok && url_ok {
                    let fixture = p.next;
                    p.next += 1;
                    (ReplayOutcome::Answered { fixture, status: f.status }, Ok(f.clone()))
                } else {
                    let expected = format!(
                        "{}{}",
                        f.method.as_deref().map(|m| format!("{m} ")).unwrap_or_default(),
                        f.url_contains.as_deref().map(|u| format!("a URL containing '{u}'")).unwrap_or_else(|| "any URL".to_string())
                    );
                    (
                        ReplayOutcome::Mismatch {
                            fixture: p.next,
                            expected: expected.clone(),
                        },
                        Err(ReplayMiss(format!(
                            "request {n} is {method} {host}{path}, but recorded response {} expects {expected}",
                            p.next
                        ))),
                    )
                }
            }
        };
        p.calls.push(ReplayedCall {
            method,
            host,
            path,
            request_bytes,
            outcome,
        });
        result
    }

    /// Every request made, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<ReplayedCall> {
        self.progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .calls
            .clone()
    }

    /// How many fixtures there are and how many were never used.
    #[must_use]
    pub fn unused(&self) -> (usize, usize) {
        let used = self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next;
        (self.fixtures.len(), self.fixtures.len() - used)
    }
}

/// Most responses one run's capture keeps.
pub const MAX_CAPTURED: usize = MAX_FIXTURES;

/// One response a real run received, in the shape a fixture has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedResponse {
    pub method: &'static str,
    pub host: String,
    /// The URL path, without the query string (which can carry identifiers).
    pub path: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Default)]
struct CaptureState {
    responses: Vec<CapturedResponse>,
    bytes: usize,
    /// Responses that did not fit [`MAX_CAPTURED`] or the byte limit.
    dropped: usize,
}

/// The responses a real `test_module` run received, kept so they can be
/// replayed later as `http_fixtures`. Only the RESPONSE is kept: the request's
/// headers and body carry resolved secrets and are never recorded. Bounded by
/// count and by total body bytes; what does not fit is counted, not kept.
pub struct HttpCapture {
    max_total_bytes: usize,
    state: Mutex<CaptureState>,
}

impl HttpCapture {
    /// A capture holding at most [`MAX_TOTAL_BODY_BYTES`] of bodies, so that
    /// everything it keeps can be handed back as one fixture set.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(MAX_TOTAL_BODY_BYTES)
    }

    #[must_use]
    pub fn with_limit(max_total_bytes: usize) -> Self {
        Self {
            max_total_bytes,
            state: Mutex::new(CaptureState::default()),
        }
    }

    /// Keep one response, or count it as dropped when it does not fit.
    pub fn record(
        &self,
        method: &'static str,
        url: &url::Url,
        status: u16,
        headers: &[(String, String)],
        body: &[u8],
    ) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.responses.len() >= MAX_CAPTURED
            || state.bytes.saturating_add(body.len()) > self.max_total_bytes
        {
            state.dropped += 1;
            return;
        }
        state.bytes += body.len();
        let content_type = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.clone());
        state.responses.push(CapturedResponse {
            method,
            host: url.host_str().unwrap_or_default().to_string(),
            path: url.path().to_string(),
            status,
            content_type,
            body: body.to_vec(),
        });
    }

    /// What was kept, in the order the responses arrived, and how many were
    /// dropped for not fitting.
    #[must_use]
    pub fn taken(&self) -> (Vec<CapturedResponse>, usize) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        (state.responses.clone(), state.dropped)
    }
}

/// Counts only: a captured body is somebody's data and is never printed.
impl std::fmt::Debug for HttpCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("HttpCapture")
            .field("responses", &state.responses.len())
            .field("bytes", &state.bytes)
            .field("dropped", &state.dropped)
            .finish()
    }
}

impl Default for HttpCapture {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(
        method: Option<&str>,
        contains: Option<&str>,
        status: u16,
        body: &str,
    ) -> HttpFixture {
        HttpFixture {
            method: method.map(str::to_string),
            url_contains: contains.map(str::to_string),
            status,
            headers: vec![],
            body: body.as_bytes().to_vec(),
        }
    }
    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }
    const CAP: usize = 1024;

    #[test]
    fn answers_are_given_in_order_and_then_run_out() {
        let r = HttpReplay::new(
            vec![
                fixture(None, None, 200, "one"),
                fixture(None, None, 404, "two"),
            ],
            CAP,
        )
        .unwrap();
        assert_eq!(
            r.answer("GET", &url("https://a.test/x"), 0).unwrap().body,
            b"one"
        );
        assert_eq!(
            r.answer("POST", &url("https://a.test/y"), 3)
                .unwrap()
                .status,
            404
        );
        let miss = r.answer("GET", &url("https://a.test/z"), 0).unwrap_err();
        assert!(
            miss.0.contains("request 3") && miss.0.contains("no recorded response left"),
            "{}",
            miss.0
        );
        assert_eq!(r.unused(), (2, 0));
        let calls = r.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[1].outcome,
            ReplayOutcome::Answered {
                fixture: 1,
                status: 404
            }
        );
        assert_eq!(calls[2].outcome, ReplayOutcome::Exhausted);
    }

    #[test]
    fn a_request_the_fixture_does_not_expect_is_refused_and_keeps_the_fixture() {
        let r = HttpReplay::new(
            vec![fixture(Some("POST"), Some("/transactions/get"), 200, "{}")],
            CAP,
        )
        .unwrap();
        // Wrong endpoint, then wrong verb: neither is handed the body.
        let miss = r
            .answer("POST", &url("https://bank.test/accounts/get"), 0)
            .unwrap_err();
        assert!(
            miss.0
                .contains("expects POST a URL containing '/transactions/get'"),
            "{}",
            miss.0
        );
        assert!(r
            .answer("GET", &url("https://bank.test/transactions/get"), 0)
            .is_err());
        assert_eq!(r.unused(), (1, 1), "a mismatch does not use the fixture up");
        assert_eq!(
            r.answer("POST", &url("https://bank.test/transactions/get"), 0)
                .unwrap()
                .status,
            200
        );
    }

    #[test]
    fn the_record_carries_no_query_string() {
        let r = HttpReplay::new(vec![fixture(None, None, 200, "")], CAP).unwrap();
        r.answer("GET", &url("https://a.test/path?token=secret-value"), 0)
            .unwrap();
        let call = &r.calls()[0];
        assert_eq!(
            (call.host.as_str(), call.path.as_str()),
            ("a.test", "/path")
        );
        assert!(!format!("{call:?}").contains("secret-value"));
    }

    #[test]
    fn a_malformed_or_oversized_set_is_refused_at_the_start() {
        let ok = || fixture(None, None, 200, "x");
        assert!(HttpReplay::new(vec![], CAP).unwrap_err().contains("empty"));
        assert!(HttpReplay::new(vec![ok(); MAX_FIXTURES + 1], CAP).is_err());
        assert!(HttpReplay::new(vec![fixture(None, None, 99, "x")], CAP).is_err());
        assert!(HttpReplay::new(vec![fixture(None, None, 600, "x")], CAP).is_err());
        assert!(HttpReplay::new(vec![fixture(Some("HEAD"), None, 200, "x")], CAP).is_err());
        assert!(
            HttpReplay::new(vec![fixture(Some("post"), None, 200, "x")], CAP).is_err(),
            "the verb is written as the gate writes it"
        );
        assert!(HttpReplay::new(vec![fixture(None, Some(""), 200, "x")], CAP).is_err());
        let big = "x".repeat(CAP + 1);
        assert!(HttpReplay::new(vec![fixture(None, None, 200, &big)], CAP)
            .unwrap_err()
            .contains("could never arrive"));
        assert!(HttpReplay::new(vec![ok(); MAX_FIXTURES], CAP).is_ok());
        let near = "x".repeat(MAX_TOTAL_BODY_BYTES / 2 + 1);
        assert!(HttpReplay::new(
            vec![
                fixture(None, None, 200, &near),
                fixture(None, None, 200, &near)
            ],
            usize::MAX
        )
        .unwrap_err()
        .contains("total"));
    }

    #[test]
    fn a_capture_keeps_the_response_and_nothing_of_the_request() {
        let capture = HttpCapture::new();
        let url = url::Url::parse("https://api.example.test/v1/items?token=abc&cursor=9").unwrap();
        capture.record(
            "POST",
            &url,
            200,
            &[
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Set-Cookie".to_string(), "session=1".to_string()),
            ],
            br#"{"items":[]}"#,
        );
        let (kept, dropped) = capture.taken();
        assert_eq!(dropped, 0);
        assert_eq!(
            kept,
            vec![CapturedResponse {
                method: "POST",
                host: "api.example.test".to_string(),
                path: "/v1/items".to_string(),
                status: 200,
                content_type: Some("application/json".to_string()),
                body: br#"{"items":[]}"#.to_vec(),
            }],
            "no query string, and only the content type of the headers"
        );
    }

    #[test]
    fn what_does_not_fit_is_counted_not_kept() {
        let url = url::Url::parse("https://api.example.test/a").unwrap();
        let capture = HttpCapture::with_limit(10);
        capture.record("GET", &url, 200, &[], b"12345678");
        capture.record("GET", &url, 200, &[], b"123"); // 11 bytes in all: over
        capture.record("GET", &url, 200, &[], b"12"); // fits
        let (kept, dropped) = capture.taken();
        assert_eq!((kept.len(), dropped), (2, 1));

        let capture = HttpCapture::new();
        for _ in 0..(MAX_CAPTURED + 3) {
            capture.record("GET", &url, 204, &[], b"");
        }
        let (kept, dropped) = capture.taken();
        assert_eq!((kept.len(), dropped), (MAX_CAPTURED, 3));
    }
}
