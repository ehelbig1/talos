//! `logging` host interface.

use super::*;

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
