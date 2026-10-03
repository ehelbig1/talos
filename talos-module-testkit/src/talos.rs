//! The host bindings, mirrored. Paths, type names, field names and function
//! signatures follow what `wit-bindgen` generates from `wit/talos.wit`
//! (records as structs with snake_case fields, enum cases in CamelCase of the
//! WIT spelling, records and strings passed by reference).
//!
//! Only the interfaces listed in [`MIRRORED`] exist here. A module that uses
//! another one does not compile against this crate until it is added.

/// The interfaces mirrored here and every function each one has, in the
/// WIT's own spelling. `tests::every_mirrored_function_is_in_the_wit` holds
/// this table to `wit/talos.wit` in both directions.
pub const MIRRORED: &[(&str, &[&str])] = &[
    (
        "http",
        &[
            "fetch",
            "fetch-all",
            "fetch-with-bearer",
            "fetch-with-header",
        ],
    ),
    ("logging", &["log", "log-json"]),
    (
        "secrets",
        &[
            "get-secret",
            "release-slot",
            "hmac-sign",
            "expose-secret",
            "resolve-config-vault",
        ],
    ),
    (
        "datetime",
        &[
            "now-unix",
            "now-iso",
            "parse",
            "format",
            "add-seconds",
            "diff-seconds",
            "local-offset-seconds",
        ],
    ),
    (
        "llm",
        &["complete", "complete-json", "complete-with-options"],
    ),
    (
        "agent-memory",
        &[
            "set",
            "get",
            "get-entry",
            "delete",
            "list-keys",
            "store-with-embedding",
            "search",
            "search-filtered",
        ],
    ),
];

pub mod core {
    pub mod http {
        use crate::host;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Method {
            Get,
            Post,
            Put,
            Delete,
            Patch,
        }
        #[derive(Clone, Debug)]
        pub struct Request {
            pub method: Method,
            pub url: String,
            pub headers: Vec<(String, String)>,
            pub body: Vec<u8>,
            pub timeout_ms: Option<u32>,
        }
        #[derive(Clone, Debug)]
        pub struct Response {
            pub status: u16,
            pub headers: Vec<(String, String)>,
            pub body: Vec<u8>,
        }
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Error {
            Invalidurl,
            Timeout,
            Networkerror,
            Forbiddenhost,
        }
        impl std::fmt::Display for Error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self:?}")
            }
        }
        impl std::error::Error for Error {}

        pub fn fetch(req: &Request) -> Result<Response, Error> {
            host::http::answer(req)
        }
        pub fn fetch_all(reqs: &[Request]) -> Vec<Result<Response, Error>> {
            reqs.iter().map(host::http::answer).collect()
        }
        /// The host adds `Authorization: Bearer <secret>`; here the request
        /// is answered as written.
        pub fn fetch_with_bearer(_slot: u64, req: &Request) -> Result<Response, Error> {
            host::http::answer(req)
        }
        /// The host adds the named header from the secret; here the request
        /// is answered as written.
        pub fn fetch_with_header(
            _slot: u64,
            _header_name: &str,
            req: &Request,
        ) -> Result<Response, Error> {
            host::http::answer(req)
        }
    }

    pub mod logging {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Level {
            Debug,
            Info,
            Warn,
            Error,
        }
        pub fn log(lvl: Level, msg: &str) {
            crate::host::log::push(lvl, msg);
        }
        pub fn log_json(lvl: Level, json: &str) {
            crate::host::log::push(lvl, json);
        }
    }

    pub mod secrets {
        use crate::host;
        use hmac::{Hmac, Mac};

        /// What a secret path resolves to when the test set nothing for it.
        pub const TEST_KEY: &[u8] = b"talos-module-testkit-default-secret";

        /// HMAC-SHA256, as the host's `hmac-sign` computes it. Not part of
        /// the bindings: for a test that needs the signature a module will
        /// check.
        #[must_use]
        pub fn test_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
            // HMAC takes a key of any length, so `new_from_slice` cannot fail.
            let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key)
                .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Error {
            Notfound,
            Unauthorized,
            Expired,
            Decryptionfailed,
            Ratelimited,
        }
        impl std::fmt::Display for Error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self:?}")
            }
        }
        impl std::error::Error for Error {}

        pub fn get_secret(key_path: &str) -> Result<u64, Error> {
            host::secrets::open(key_path).ok_or(Error::Notfound)
        }
        pub fn release_slot(handle: u64) -> Result<(), Error> {
            if host::secrets::release(handle) {
                Ok(())
            } else {
                Err(Error::Notfound)
            }
        }
        pub fn hmac_sign(handle: u64, data: &[u8]) -> Result<Vec<u8>, Error> {
            host::secrets::slot(handle)
                .map(|key| test_hmac(&key, data))
                .ok_or(Error::Notfound)
        }
        /// Always refused, as on every dispatch path in production.
        pub fn expose_secret(_handle: u64, _reason: &str) -> Result<String, Error> {
            Err(Error::Unauthorized)
        }
        /// `vault://<path>` opens that path; anything else is `Notfound`.
        pub fn resolve_config_vault(config_value: &str) -> Result<u64, Error> {
            config_value
                .trim()
                .strip_prefix("vault://")
                .and_then(host::secrets::open)
                .ok_or(Error::Notfound)
        }
    }

    pub mod datetime {
        use chrono::{Offset, TimeZone};

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Error {
            Parseerror,
            Invalidformat,
        }
        impl std::fmt::Display for Error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self:?}")
            }
        }
        impl std::error::Error for Error {}

        fn at(timestamp: u64) -> Option<chrono::DateTime<chrono::Utc>> {
            chrono::DateTime::from_timestamp(i64::try_from(timestamp).ok()?, 0)
        }

        pub fn now_unix() -> u64 {
            crate::host::clock::now_unix()
        }
        pub fn now_iso() -> String {
            at(now_unix())
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_default()
        }
        /// RFC 3339 when `format` is `None`, else a `strftime` pattern read
        /// as UTC.
        pub fn parse(date_str: &str, format: Option<&str>) -> Result<u64, Error> {
            let seconds = match format {
                None => chrono::DateTime::parse_from_rfc3339(date_str)
                    .map_err(|_| Error::Parseerror)?
                    .timestamp(),
                Some(f) => chrono::NaiveDateTime::parse_from_str(date_str, f)
                    .map_err(|_| Error::Parseerror)?
                    .and_utc()
                    .timestamp(),
            };
            u64::try_from(seconds).map_err(|_| Error::Parseerror)
        }
        pub fn format(timestamp: u64, format: &str) -> Result<String, Error> {
            use std::fmt::Write as _;
            let t = at(timestamp).ok_or(Error::Invalidformat)?;
            let mut out = String::new();
            write!(out, "{}", t.format(format)).map_err(|_| Error::Invalidformat)?;
            Ok(out)
        }
        pub fn add_seconds(timestamp: u64, seconds: i64) -> u64 {
            timestamp.saturating_add_signed(seconds)
        }
        pub fn diff_seconds(timestamp1: u64, timestamp2: u64) -> i64 {
            i64::try_from(timestamp1)
                .unwrap_or(i64::MAX)
                .saturating_sub(i64::try_from(timestamp2).unwrap_or(i64::MAX))
        }
        /// The zone's offset from UTC at that moment, from the IANA database.
        /// The name must be written exactly (`America/New_York`).
        pub fn local_offset_seconds(zone: &str, timestamp: u64) -> Result<i32, Error> {
            if zone.is_empty() || zone.len() > 64 {
                return Err(Error::Invalidformat);
            }
            let tz: chrono_tz::Tz = zone.parse().map_err(|_| Error::Invalidformat)?;
            if tz.name() != zone {
                return Err(Error::Invalidformat);
            }
            let t = at(timestamp).ok_or(Error::Invalidformat)?;
            Ok(tz
                .offset_from_utc_datetime(&t.naive_utc())
                .fix()
                .local_minus_utc())
        }
    }

    pub mod llm {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Provider {
            Anthropic,
            Openai,
            Gemini,
            Ollama,
        }
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Role {
            System,
            User,
            Assistant,
        }
        #[derive(Clone, Debug)]
        pub struct Message {
            pub role: Role,
            pub content: String,
        }
        #[derive(Clone, Debug)]
        pub struct CompletionRequest {
            pub provider: Option<Provider>,
            pub model: Option<String>,
            pub messages: Vec<Message>,
            pub max_tokens: Option<u32>,
            pub temperature: Option<f32>,
            pub system_prompt: Option<String>,
        }
        #[derive(Clone, Copy, Debug)]
        pub struct TokenUsage {
            pub input_tokens: u32,
            pub output_tokens: u32,
        }
        #[derive(Clone, Debug)]
        pub struct CompletionResponse {
            pub text: String,
            pub model: String,
            pub usage: Option<TokenUsage>,
            pub stop_reason: Option<String>,
        }
        #[derive(Clone, Debug)]
        pub enum Error {
            NotConfigured(String),
            RateLimited,
            InvalidRequest(String),
            ApiError(String),
            Timeout,
            BudgetExhausted,
        }
        impl std::fmt::Display for Error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self:?}")
            }
        }
        impl std::error::Error for Error {}

        pub fn complete(req: &CompletionRequest) -> Result<CompletionResponse, Error> {
            crate::host::llm::answer(req)
        }
        pub fn complete_json(
            req: &CompletionRequest,
            _json_schema: Option<&str>,
        ) -> Result<CompletionResponse, Error> {
            crate::host::llm::answer(req)
        }
        pub fn complete_with_options(
            req: &CompletionRequest,
            _options: Option<&str>,
        ) -> Result<CompletionResponse, Error> {
            crate::host::llm::answer(req)
        }
    }

    pub mod agent_memory {
        use crate::host::memory;

        #[derive(Clone, Debug)]
        pub struct MemoryEntry {
            pub key: String,
            pub value: String,
            pub metadata: Option<String>,
        }
        #[derive(Clone, Debug)]
        pub struct SearchResult {
            pub key: String,
            pub value: String,
            pub score: f32,
            pub metadata: Option<String>,
        }
        #[derive(Clone, Debug)]
        pub struct MemoryEntryDetail {
            pub value: String,
            pub created_at_unix: u64,
            pub expires_at_unix: Option<u64>,
            pub memory_type: String,
        }
        #[derive(Clone, Debug)]
        pub struct SearchOptions {
            pub limit: u32,
            pub exclude_kinds: Vec<String>,
        }
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Error {
            NotAvailable,
            KeyNotFound,
            StorageFull,
            InvalidInput,
        }
        impl std::fmt::Display for Error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self:?}")
            }
        }
        impl std::error::Error for Error {}

        fn reachable() -> Result<(), Error> {
            if memory::failing() {
                Err(Error::NotAvailable)
            } else {
                Ok(())
            }
        }

        pub fn set(key: &str, value: &str) -> Result<(), Error> {
            reachable()?;
            memory::put(key, value);
            Ok(())
        }
        pub fn get(key: &str) -> Result<String, Error> {
            reachable()?;
            memory::get(key).ok_or(Error::KeyNotFound)
        }
        pub fn get_entry(key: &str) -> Result<Option<MemoryEntryDetail>, Error> {
            reachable()?;
            Ok(memory::get(key).map(|value| MemoryEntryDetail {
                value,
                created_at_unix: 0,
                expires_at_unix: None,
                memory_type: "episodic".to_string(),
            }))
        }
        pub fn delete(key: &str) -> Result<(), Error> {
            reachable()?;
            memory::remove(key);
            Ok(())
        }
        pub fn list_keys(prefix: Option<&str>) -> Result<Vec<String>, Error> {
            reachable()?;
            Ok(memory::matching(prefix)
                .into_iter()
                .map(|(k, _)| k)
                .collect())
        }
        pub fn store_with_embedding(entry: &MemoryEntry) -> Result<(), Error> {
            reachable()?;
            memory::put(&entry.key, entry.value.clone());
            Ok(())
        }
        /// There is no embedding here: an entry matches when its value
        /// contains the query, ignoring case, and scores 1.0.
        pub fn search(query: &str, limit: u32) -> Result<Vec<SearchResult>, Error> {
            reachable()?;
            let q = query.to_lowercase();
            Ok(memory::matching(None)
                .into_iter()
                .filter(|(_, v)| v.to_lowercase().contains(&q))
                .take(limit as usize)
                .map(|(key, value)| SearchResult {
                    key,
                    value,
                    score: 1.0,
                    metadata: None,
                })
                .collect())
        }
        /// As [`search`]; `exclude_kinds` has nothing to act on, since
        /// entries here carry no metadata.
        pub fn search_filtered(
            query: &str,
            opts: &SearchOptions,
        ) -> Result<Vec<SearchResult>, Error> {
            search(query, opts.limit)
        }
    }
}
