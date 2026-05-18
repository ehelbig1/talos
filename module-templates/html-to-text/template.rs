// HTML → visible-text extractor.
//
// Built for the fetch → extract → LLM pattern (competitive watch, content
// monitoring, RAG ingestion) where raw HTML is too noisy and too WASM-fuel-
// expensive for the LLM to process directly. A real-world pricing page is
// 100–1000 KB of analytics scripts wrapping a few KB of actual content;
// feeding the raw HTML to an LLM either trips fuel limits or buries the
// signal in noise.
//
// Design decisions:
//
// 1. Byte-level scanner with case-insensitive `eq_ignore_ascii_case` for
//    `<script>` / `<style>` / `<!--` detection — no allocation per
//    comparison, no regex dependency, no `to_lowercase()` clone. The
//    pre-extraction watch-semgrep prototype that built this primitive
//    burned 50M fuel on `s.to_lowercase()` on a 183KB input.
//
// 2. Hard cap on input bytes (`MAX_INPUT_BYTES`, default 60_000). Pricing
//    and positioning content is overwhelmingly in the first ~50KB of any
//    well-built marketing page; the rest is below-the-fold trackers and
//    deferred scripts. This is the single biggest WASM-fuel lever.
//
// 3. Output cap on visible characters (`MAX_VISIBLE_CHARS`, default
//    8_000 ≈ 2000 LLM tokens). The scanner stops walking input once the
//    cap is reached — short-circuit, not post-truncate.
//
// 4. UTF-8 boundary safety on the input cap. Walking back to the nearest
//    `is_char_boundary` prevents the panic class fixed in engine commit
//    e45e04e (an em-dash crossing byte 4096 in INJECT_CONTEXT memories).
//
// 5. Reads HTML from upstream via three fallbacks in order:
//    (a) caller-overridden `INPUT_FIELD` path
//    (b) `__accumulated__.fetch` (matches the http-request module's
//        engine-merged shape when this node has multiple parents)
//    (c) top-level `body` (matches single-parent passthrough)
//    (d) `input.body` (legacy nested wrapping)
//    All four covered so the module slots in without forcing the caller
//    to reshape upstream output.

use serde::Deserialize;
use serde_json::{json, Value};
use talos_sdk_macros::talos_module;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Config {
    #[serde(rename = "MAX_INPUT_BYTES", alias = "max_input_bytes")]
    max_input_bytes: Option<u64>,
    #[serde(rename = "MAX_VISIBLE_CHARS", alias = "max_visible_chars")]
    max_visible_chars: Option<u64>,
    #[serde(rename = "INPUT_FIELD", alias = "input_field")]
    input_field: Option<String>,
}

#[derive(Deserialize, Default)]
struct Input {
    #[serde(default)]
    config: Config,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

const DEFAULT_MAX_INPUT_BYTES: usize = 60_000;
const DEFAULT_MAX_VISIBLE_CHARS: usize = 8_000;
const FLOOR_MAX_INPUT_BYTES: usize = 1024;
const CEIL_MAX_INPUT_BYTES: usize = 5_000_000;
const FLOOR_MAX_VISIBLE_CHARS: usize = 256;
const CEIL_MAX_VISIBLE_CHARS: usize = 100_000;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let parsed: Input = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON input: {}", e))?;
    let config = parsed.config;

    let max_input_bytes = config
        .max_input_bytes
        .map(|n| (n as usize).clamp(FLOOR_MAX_INPUT_BYTES, CEIL_MAX_INPUT_BYTES))
        .unwrap_or(DEFAULT_MAX_INPUT_BYTES);
    let max_visible_chars = config
        .max_visible_chars
        .map(|n| (n as usize).clamp(FLOOR_MAX_VISIBLE_CHARS, CEIL_MAX_VISIBLE_CHARS))
        .unwrap_or(DEFAULT_MAX_VISIBLE_CHARS);

    let extra_value = Value::Object(parsed.extra);
    let html_full = locate_html(&extra_value, config.input_field.as_deref())
        .ok_or_else(|| {
            "missing HTML body in upstream input. Tried (in order): \
             INPUT_FIELD override, __accumulated__.fetch, body, input.body. \
             Set INPUT_FIELD to the path your upstream uses (e.g. \
             '__accumulated__.my-fetch-node'), or wire this node directly \
             after an http-request node."
                .to_string()
        })?;

    let original_length = html_full.len();

    // Walk back to a UTF-8 char boundary so we never split inside a
    // multi-byte sequence — same defensive pattern as the engine's
    // input-preview truncation (engine commit e45e04e, controller r247).
    let cap = max_input_bytes.min(html_full.len());
    let mut safe_cap = cap;
    while safe_cap > 0 && !html_full.is_char_boundary(safe_cap) {
        safe_cap -= 1;
    }
    let html = &html_full[..safe_cap];

    let (text, visible_chars, scanned_bytes) =
        extract_visible_text(html, max_visible_chars);

    let final_text = if visible_chars >= max_visible_chars {
        format!("{}...(visible-char cap {} reached)", text, max_visible_chars)
    } else if html_full.len() > max_input_bytes {
        format!(
            "{}...(input capped at {} of {} bytes)",
            text, max_input_bytes, original_length
        )
    } else {
        text
    };

    Ok(json!({
        "body": final_text,
        "body_length": final_text.len(),
        "original_length": original_length,
        "input_capped_to": safe_cap,
        "scanned_bytes": scanned_bytes,
        "visible_chars": visible_chars,
    })
    .to_string())
}

/// Locate the HTML body in the upstream input. Tries the caller's
/// `INPUT_FIELD` override first, then walks the standard fallback chain.
fn locate_html<'a>(extra: &'a Value, override_field: Option<&str>) -> Option<&'a str> {
    if let Some(path) = override_field.filter(|s| !s.is_empty()) {
        if let Some(s) = lookup_path(extra, path).and_then(|v| v.as_str()) {
            return Some(s);
        }
    }
    // (a) __accumulated__.fetch — multi-parent case from http-request
    if let Some(s) = extra
        .get("__accumulated__")
        .and_then(|a| a.get("fetch"))
        .and_then(|v| v.as_str())
    {
        return Some(s);
    }
    // (b) top-level body — direct passthrough
    if let Some(s) = extra.get("body").and_then(|v| v.as_str()) {
        return Some(s);
    }
    // (c) input.body — legacy nested wrapping
    if let Some(s) = extra
        .get("input")
        .and_then(|i| i.get("body"))
        .and_then(|v| v.as_str())
    {
        return Some(s);
    }
    None
}

/// Walk a dotted path like `__accumulated__.fetch.body` against a JSON
/// value. Returns the leaf or None if any segment is missing.
fn lookup_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

/// Find the byte offset AFTER the next `</tag>` close, case-insensitive
/// on the tag name. Used to skip past `<script>...</script>` and
/// `<style>...</style>` blocks without copying the haystack.
fn find_close_offset(haystack: &[u8], close_lower: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + close_lower.len() <= haystack.len() {
        if haystack[i..i + close_lower.len()].eq_ignore_ascii_case(close_lower) {
            // Walk past the next '>' to handle attrs on closing tags
            // (rare but valid HTML).
            let mut j = i + close_lower.len();
            while j < haystack.len() && haystack[j] != b'>' {
                j += 1;
            }
            return Some(if j < haystack.len() { j + 1 } else { haystack.len() });
        }
        i += 1;
    }
    None
}

/// Single-pass HTML → visible-text extraction. Byte-level scanner with
/// short-circuit when the visible-char cap is reached. Returns
/// `(text, visible_chars_collected, total_bytes_scanned)`.
fn extract_visible_text(html: &str, max_chars: usize) -> (String, usize, usize) {
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(max_chars * 2);
    let mut visible = 0usize;
    let mut last_was_space = true;
    let mut i = 0usize;

    while i < bytes.len() && visible < max_chars {
        let b = bytes[i];
        if b == b'<' {
            let after = i + 1;
            let is_script = after + 6 <= bytes.len()
                && bytes[after..after + 6].eq_ignore_ascii_case(b"script")
                && (bytes[after + 6] == b' '
                    || bytes[after + 6] == b'>'
                    || bytes[after + 6] == b'/');
            let is_style = after + 5 <= bytes.len()
                && bytes[after..after + 5].eq_ignore_ascii_case(b"style")
                && (bytes[after + 5] == b' '
                    || bytes[after + 5] == b'>'
                    || bytes[after + 5] == b'/');
            let is_comment = after + 3 <= bytes.len() && &bytes[after..after + 3] == b"!--";

            if is_script {
                if let Some(off) = find_close_offset(&bytes[i..], b"</script") {
                    i += off;
                } else {
                    i = bytes.len();
                }
                if !last_was_space {
                    out.push(' ');
                    last_was_space = true;
                    visible += 1;
                }
                continue;
            }
            if is_style {
                if let Some(off) = find_close_offset(&bytes[i..], b"</style") {
                    i += off;
                } else {
                    i = bytes.len();
                }
                if !last_was_space {
                    out.push(' ');
                    last_was_space = true;
                    visible += 1;
                }
                continue;
            }
            if is_comment {
                let mut j = i + 4;
                while j + 3 <= bytes.len() && &bytes[j..j + 3] != b"-->" {
                    j += 1;
                }
                i = if j + 3 <= bytes.len() { j + 3 } else { bytes.len() };
                continue;
            }

            // Generic tag — skip until '>'.
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'>' {
                j += 1;
            }
            i = if j < bytes.len() { j + 1 } else { bytes.len() };
            if !last_was_space {
                out.push(' ');
                last_was_space = true;
                visible += 1;
            }
            continue;
        }

        // Visible byte/char path — fast for ASCII, char-boundary-safe
        // for multi-byte UTF-8.
        if b < 0x80 {
            let ch = b as char;
            i += 1;
            if ch.is_whitespace() {
                if !last_was_space {
                    out.push(' ');
                    last_was_space = true;
                    visible += 1;
                }
            } else {
                out.push(ch);
                last_was_space = false;
                visible += 1;
            }
        } else if html.is_char_boundary(i) {
            let ch = html[i..].chars().next().unwrap_or('\u{FFFD}');
            i += ch.len_utf8();
            if ch.is_whitespace() {
                if !last_was_space {
                    out.push(' ');
                    last_was_space = true;
                    visible += 1;
                }
            } else {
                out.push(ch);
                last_was_space = false;
                visible += 1;
            }
        } else {
            i += 1;
        }
    }

    (out.trim().to_string(), visible, i)
}
