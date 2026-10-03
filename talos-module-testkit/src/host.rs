//! What a test sets up, and what it can read back afterwards.
//!
//! All of it is per THREAD. The test harness runs each test on its own
//! thread, so one test's responses, memory and clock are never seen by
//! another, and nothing needs resetting.

use crate::talos::core::{http as wit_http, llm as wit_llm};
use std::cell::RefCell;
use std::collections::BTreeMap;

type HttpHandler =
    Box<dyn FnMut(&wit_http::Request) -> Result<wit_http::Response, wit_http::Error>>;
type LlmHandler = Box<
    dyn FnMut(&wit_llm::CompletionRequest) -> Result<wit_llm::CompletionResponse, wit_llm::Error>,
>;

#[derive(Default)]
struct State {
    http: Option<HttpHandler>,
    http_seen: Vec<wit_http::Request>,
    memory: BTreeMap<String, String>,
    memory_fails: bool,
    secrets: BTreeMap<String, Vec<u8>>,
    secrets_denied: Vec<String>,
    slots: Vec<Option<Vec<u8>>>,
    now_unix: Option<u64>,
    llm: Option<LlmHandler>,
    llm_seen: Vec<wit_llm::CompletionRequest>,
    log: Vec<(crate::talos::core::logging::Level, String)>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

/// Outbound HTTP. With no responder set every request fails with
/// `Networkerror`: a test never reaches a network.
pub mod http {
    use super::{wit_http, with};

    /// Answer every request with `f`.
    pub fn respond_with(
        f: impl FnMut(&wit_http::Request) -> Result<wit_http::Response, wit_http::Error> + 'static,
    ) {
        with(|s| s.http = Some(Box::new(f)));
    }

    /// Answer every request with this status and body.
    pub fn respond(status: u16, body: impl Into<Vec<u8>>) {
        let body = body.into();
        respond_with(move |_| Ok(response(status, body.clone())));
    }

    /// A response with no headers.
    #[must_use]
    pub fn response(status: u16, body: impl Into<Vec<u8>>) -> wit_http::Response {
        wit_http::Response {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// Every request made so far on this thread, in order.
    #[must_use]
    pub fn requests() -> Vec<wit_http::Request> {
        with(|s| s.http_seen.clone())
    }

    pub(crate) fn answer(req: &wit_http::Request) -> Result<wit_http::Response, wit_http::Error> {
        // The handler is taken out while it runs, so a handler that itself
        // makes a request fails that request instead of panicking on a
        // re-entrant borrow.
        let handler = with(|s| {
            s.http_seen.push(req.clone());
            s.http.take()
        });
        let Some(mut handler) = handler else {
            return Err(wit_http::Error::Networkerror);
        };
        let out = handler(req);
        with(|s| {
            if s.http.is_none() {
                s.http = Some(handler);
            }
        });
        out
    }
}

/// Actor memory: a key/value store.
pub mod memory {
    use super::with;

    pub fn put(key: &str, value: impl Into<String>) {
        let value = value.into();
        with(|s| s.memory.insert(key.to_string(), value));
    }
    pub fn remove(key: &str) {
        with(|s| s.memory.remove(key));
    }
    #[must_use]
    pub fn get(key: &str) -> Option<String> {
        with(|s| s.memory.get(key).cloned())
    }
    #[must_use]
    pub fn keys() -> Vec<String> {
        with(|s| s.memory.keys().cloned().collect())
    }
    /// Make every memory call fail with `NotAvailable` (the store cannot be
    /// reached), which is a different answer from "the key is not there".
    pub fn fail(on: bool) {
        with(|s| s.memory_fails = on);
    }

    pub(crate) fn failing() -> bool {
        with(|s| s.memory_fails)
    }
    pub(crate) fn matching(prefix: Option<&str>) -> Vec<(String, String)> {
        with(|s| {
            s.memory
                .iter()
                .filter(|(k, _)| prefix.is_none_or(|p| k.starts_with(p)))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
    }
}

/// Secrets. A path that was neither [`put`](secrets::put) nor
/// [`deny`](secrets::deny)-ed resolves to
/// [`TEST_KEY`](crate::talos::core::secrets::TEST_KEY).
pub mod secrets {
    use super::with;

    pub fn put(path: &str, value: impl Into<Vec<u8>>) {
        let value = value.into();
        with(|s| s.secrets.insert(path.to_string(), value));
    }
    /// Make `get_secret(path)` answer `Notfound`.
    pub fn deny(path: &str) {
        with(|s| s.secrets_denied.push(path.to_string()));
    }

    pub(crate) fn open(path: &str) -> Option<u64> {
        with(|s| {
            if s.secrets_denied.iter().any(|d| d == path) {
                return None;
            }
            let value = s
                .secrets
                .get(path)
                .cloned()
                .unwrap_or_else(|| crate::talos::core::secrets::TEST_KEY.to_vec());
            s.slots.push(Some(value));
            Some(s.slots.len() as u64)
        })
    }
    pub(crate) fn slot(handle: u64) -> Option<Vec<u8>> {
        with(|s| {
            let i = usize::try_from(handle).ok()?.checked_sub(1)?;
            s.slots.get(i).cloned().flatten()
        })
    }
    pub(crate) fn release(handle: u64) -> bool {
        with(|s| {
            let Some(i) = usize::try_from(handle).ok().and_then(|h| h.checked_sub(1)) else {
                return false;
            };
            match s.slots.get_mut(i) {
                Some(slot @ Some(_)) => {
                    *slot = None;
                    true
                }
                _ => false,
            }
        })
    }
}

/// The clock the `datetime` functions read. Unset, it is the system clock.
pub mod clock {
    use super::with;

    pub fn set_unix(seconds: u64) {
        with(|s| s.now_unix = Some(seconds));
    }
    pub(crate) fn now_unix() -> u64 {
        with(|s| s.now_unix).unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        })
    }
}

/// The model. With no responder set every completion fails with
/// `NotConfigured`.
pub mod llm {
    use super::{wit_llm, with};

    pub fn respond_with(
        f: impl FnMut(
                &wit_llm::CompletionRequest,
            ) -> Result<wit_llm::CompletionResponse, wit_llm::Error>
            + 'static,
    ) {
        with(|s| s.llm = Some(Box::new(f)));
    }

    /// Answer every completion with this text.
    pub fn respond(text: &str) {
        let text = text.to_string();
        respond_with(move |req| {
            Ok(wit_llm::CompletionResponse {
                text: text.clone(),
                model: req
                    .model
                    .clone()
                    .unwrap_or_else(|| "test-model".to_string()),
                usage: None,
                stop_reason: Some("stop".to_string()),
            })
        });
    }

    #[must_use]
    pub fn requests() -> Vec<wit_llm::CompletionRequest> {
        with(|s| s.llm_seen.clone())
    }

    pub(crate) fn answer(
        req: &wit_llm::CompletionRequest,
    ) -> Result<wit_llm::CompletionResponse, wit_llm::Error> {
        let handler = with(|s| {
            s.llm_seen.push(req.clone());
            s.llm.take()
        });
        let Some(mut handler) = handler else {
            return Err(wit_llm::Error::NotConfigured(
                "no model is set up in this test".to_string(),
            ));
        };
        let out = handler(req);
        with(|s| {
            if s.llm.is_none() {
                s.llm = Some(handler);
            }
        });
        out
    }
}

/// What the module logged.
pub mod log {
    use super::with;
    use crate::talos::core::logging::Level;

    #[must_use]
    pub fn lines() -> Vec<(Level, String)> {
        with(|s| s.log.clone())
    }
    pub(crate) fn push(level: Level, msg: &str) {
        with(|s| s.log.push((level, msg.to_string())));
    }
}
