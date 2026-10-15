//! `logging` host interface.
//!
//! Guest log text is relayed to the worker's `tracing` output and, over NATS,
//! to the controller's execution log. Two rules (E-12, 2026-10-14):
//!
//! * every CONTROL character a guest writes — C0 (`\n`, `\r`, ESC, …), DEL
//!   and C1 — is written as its escape (`\n` → `\\n`, ESC → `\\u{1b}`) by
//!   [`neutralise_log_text`], so a message cannot start a fabricated log line
//!   or send terminal escape sequences to whoever reads a text log;
//! * the bytes one execution relays are bounded by
//!   [`MAX_LOG_BYTES_PER_EXECUTION`] (1 MiB), beside the existing
//!   10 000-message count and [`MAX_LOG_MESSAGE_BYTES`] per message.

use super::*;

// ============================================================================
// Logging
// ============================================================================

/// Write every control character in `text` as its Rust escape. ONE home for
/// guest log text; borrowed unchanged when there is none (the common case).
pub(crate) fn neutralise_log_text(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// [`neutralise_log_text`] over every string (and object key) of a parsed
/// `log-json` payload, which is relayed as structured data.
fn neutralise_log_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            if let std::borrow::Cow::Owned(clean) = neutralise_log_text(s) {
                *s = clean;
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(neutralise_log_json),
        serde_json::Value::Object(map) => {
            if map.keys().any(|k| k.chars().any(char::is_control)) {
                let entries = std::mem::take(map);
                for (k, v) in entries {
                    map.insert(neutralise_log_text(&k).into_owned(), v);
                }
            }
            map.values_mut().for_each(neutralise_log_json);
        }
        _ => {}
    }
}

/// Cap `text` at [`MAX_LOG_MESSAGE_BYTES`] (char boundary, marked), then
/// neutralise it, then cap again — the escapes can lengthen it. The first cap
/// bounds the work done on an oversized guest string.
fn bounded_log_text(text: &str) -> String {
    fn cap(s: &str) -> String {
        if s.len() > MAX_LOG_MESSAGE_BYTES {
            let mut t =
                talos_text_util::truncate_at_char_boundary(s, MAX_LOG_MESSAGE_BYTES).to_string();
            t.push_str("...[TRUNCATED]");
            t
        } else {
            s.to_string()
        }
    }
    let first = cap(text);
    let clean = neutralise_log_text(&first);
    if clean.len() > MAX_LOG_MESSAGE_BYTES + "...[TRUNCATED]".len() {
        cap(&clean)
    } else {
        clean.into_owned()
    }
}

impl TalosContext {
    /// Charge `bytes` against this execution's guest log budget. `false` ⇒
    /// drop the message; the first refusal is logged once.
    fn admit_log_bytes(&self, bytes: usize) -> bool {
        let bytes = bytes as u64;
        let before = self
            .log_bytes
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        if before.saturating_add(bytes) <= MAX_LOG_BYTES_PER_EXECUTION {
            return true;
        }
        if before <= MAX_LOG_BYTES_PER_EXECUTION {
            tracing::warn!(
                module_id = ?self.module_id,
                budget_bytes = MAX_LOG_BYTES_PER_EXECUTION,
                "Log byte budget exceeded, dropping further messages"
            );
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("log");
            }
        }
        false
    }
}

impl wit_logging::Host for TalosContext {
    async fn log(&mut self, lvl: wit_logging::Level, msg: String) {
        self.host_call("logging::log");
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
        // the result is always ≤ N bytes. E-12 (2026-10-14): control
        // characters are then written as escapes, and the bytes are charged
        // against the execution's log budget.
        let msg = bounded_log_text(&msg);
        if !self.admit_log_bytes(msg.len()) {
            return;
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
        self.host_call("logging::log-json");
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
        let json_capped = if json.len() > MAX_LOG_MESSAGE_BYTES {
            let mut s = talos_text_util::truncate_at_char_boundary(&json, MAX_LOG_MESSAGE_BYTES)
                .to_string();
            s.push_str("...[TRUNCATED]");
            s
        } else {
            json
        };
        if !self.admit_log_bytes(json_capped.len()) {
            return;
        }

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
        // E-12: every string the payload carries is neutralised (control
        // characters written as escapes) before it is logged or relayed.
        let (structured_value, parse_ok) =
            match serde_json::from_str::<serde_json::Value>(&json_capped) {
                Ok(mut v) => {
                    neutralise_log_json(&mut v);
                    (v, true)
                }
                Err(_) => (
                    serde_json::Value::String(bounded_log_text(&json_capped)),
                    false,
                ),
            };

        // Emit to tracing.
        let trace_preview = match &structured_value {
            serde_json::Value::String(s) if !parse_ok => format!(
                "[json_parse_error] {}",
                s.chars().take(200).collect::<String>()
            ),
            v => v.to_string().chars().take(200).collect::<String>(),
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

#[cfg(test)]
mod guest_log_bound_tests {
    use super::*;
    use crate::bindings::talos::core::logging::Host as _;
    use crate::wit_inspector::CapabilityWorld;
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    fn ctx() -> TalosContext {
        TalosContext::new(
            CapabilityWorld::Minimal,
            vec![],
            vec![],
            128,
            HashMap::new(),
            None,
            None,
            false,
            None,
            std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
            talos_workflow_job_protocol::LlmTier::default(),
            None,
        )
        .expect("test context")
    }

    /// E-12: a guest newline cannot start a fabricated log line, and ESC /
    /// DEL / C1 cannot reach a terminal. Ordinary text is untouched.
    #[test]
    fn control_characters_are_written_as_escapes() {
        assert_eq!(
            neutralise_log_text("ok\n[WASM] forged line"),
            "ok\\n[WASM] forged line"
        );
        assert_eq!(neutralise_log_text("a\r\tb"), "a\\r\\tb");
        assert_eq!(neutralise_log_text("\u{1b}[31mred"), "\\u{1b}[31mred");
        assert_eq!(
            neutralise_log_text("x\u{7f}\u{9b}y\u{0}"),
            "x\\u{7f}\\u{9b}y\\u{0}"
        );
        for clean in ["plain text", "ünïcode — ✓ 日本", ""] {
            assert!(matches!(
                neutralise_log_text(clean),
                std::borrow::Cow::Borrowed(_)
            ));
        }
        let out = neutralise_log_text("\n\u{1b}\u{7f}\u{85}");
        assert!(!out.chars().any(char::is_control), "{out:?}");
    }

    #[test]
    fn a_log_json_payload_is_neutralised_in_every_string_and_key() {
        let mut v = serde_json::json!({
            "msg": "a\nb",
            "nested": [{"k\u{1b}": "\u{1b}[2J"}],
            "n": 1
        });
        neutralise_log_json(&mut v);
        assert_eq!(
            v,
            serde_json::json!({
                "msg": "a\\nb",
                "nested": [{"k\\u{1b}": "\\u{1b}[2J"}],
                "n": 1
            })
        );
    }

    #[test]
    fn a_message_stays_within_its_byte_cap_after_escaping() {
        let out = bounded_log_text(&"\n".repeat(MAX_LOG_MESSAGE_BYTES * 2));
        assert!(out.len() <= MAX_LOG_MESSAGE_BYTES + "...[TRUNCATED]".len());
        assert!(out.ends_with("...[TRUNCATED]"));
        assert!(!out.contains('\n'));
        assert_eq!(bounded_log_text("short"), "short");
    }

    /// E-12: one execution relays at most `MAX_LOG_BYTES_PER_EXECUTION` of
    /// guest log, through `log` and `log-json` alike; the message count alone
    /// used to allow ~100 MB.
    #[tokio::test]
    async fn the_log_byte_budget_bounds_an_execution() {
        let mut c = ctx();
        let big = "x".repeat(MAX_LOG_MESSAGE_BYTES);
        let mut sent = 0u64;
        while c.log_bytes.load(Ordering::Relaxed) <= MAX_LOG_BYTES_PER_EXECUTION {
            c.log(wit_logging::Level::Info, big.clone()).await;
            sent += 1;
            assert!(sent < 1_000, "the budget never closed");
        }
        // ~105 messages of 10 000 B, far below the 10 000-message count.
        assert!(sent < 200, "sent {sent}");
        assert!(!c.admit_log_bytes(1), "the budget is spent");
        // `log-json` draws on the same budget.
        let before = c.log_bytes.load(Ordering::Relaxed);
        c.log_json(wit_logging::Level::Info, "{\"a\":1}".into())
            .await;
        assert!(c.log_bytes.load(Ordering::Relaxed) > before);
        assert!(!c.admit_log_bytes(1));

        // CONTROL: a fresh execution admits a message, and is charged the
        // neutralised length.
        let fresh = ctx();
        assert!(fresh.admit_log_bytes(100));
        let mut f = ctx();
        f.log(wit_logging::Level::Info, "a\nb".into()).await;
        assert_eq!(f.log_bytes.load(Ordering::Relaxed), "a\\nb".len() as u64);
    }
}
