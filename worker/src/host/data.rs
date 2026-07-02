//! Pure data-manipulation host interfaces: `json`, `datetime`,
//! `templates` (minijinja) and `data-transform` (CSV / XML).

use super::*;

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
        if self
            .validate_json_size(&json_str, "json::prettify")
            .is_err()
        {
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

/// Panic-safe strftime formatting of a Unix timestamp for a guest-supplied
/// format string.
///
/// SECURITY: `format` is guest-controlled. chrono's `DelayedFormat` Display
/// impl returns `fmt::Error` for malformed strftime specifiers (e.g. "%",
/// "%Q", "%:::::z"), and `.to_string()` turns that into a **panic**
/// (`write!(...).expect("a Display implementation returned an error
/// unexpectedly")`). A guest must never be able to panic a host function —
/// depending on unwind/abort behaviour that is at best a per-job crash and at
/// worst a process abort taking down co-resident tenants. Formatting via
/// `write!` into a String surfaces the formatting error as `Err(())` instead.
/// Pure + testable so the no-panic guarantee is regression-locked.
fn format_unix_timestamp(timestamp: u64, format: &str) -> Result<String, ()> {
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp as i64, 0).ok_or(())?;
    use std::fmt::Write as _;
    let mut out = String::new();
    write!(out, "{}", dt.format(format)).map_err(|_| ())?;
    Ok(out)
}

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
        format_unix_timestamp(timestamp, &format).map_err(|_| wit_datetime::Error::Invalidformat)
    }

    async fn add_seconds(&mut self, timestamp: u64, seconds: i64) -> u64 {
        (timestamp as i64).saturating_add(seconds) as u64
    }

    async fn diff_seconds(&mut self, timestamp1: u64, timestamp2: u64) -> i64 {
        (timestamp1 as i64).saturating_sub(timestamp2 as i64)
    }
}

#[cfg(test)]
mod datetime_format_tests {
    use super::format_unix_timestamp;

    #[test]
    fn malformed_strftime_returns_err_not_panic() {
        // Each of these makes chrono's `DelayedFormat::to_string()` PANIC
        // (verified against chrono 0.4.44). The host fn must surface them as
        // Err — a guest-supplied format string can never panic the host.
        for bad in ["%", "%Q", "%-", "%:::::z", "%%%"] {
            assert!(
                format_unix_timestamp(0, bad).is_err(),
                "expected Err (not panic) for malformed format {bad:?}",
            );
        }
    }

    #[test]
    fn valid_strftime_formats_correctly() {
        assert_eq!(
            format_unix_timestamp(0, "%Y-%m-%d %H:%M:%S").unwrap(),
            "1970-01-01 00:00:00"
        );
        // Literal text with no specifiers is passed through.
        assert_eq!(
            format_unix_timestamp(0, "literal text").unwrap(),
            "literal text"
        );
        // A double-percent escape is valid and renders a literal '%'.
        assert_eq!(format_unix_timestamp(0, "%%").unwrap(), "%");
    }

    #[test]
    fn out_of_range_timestamp_returns_err_not_panic() {
        // i64::MAX seconds is far beyond chrono's representable range, so
        // from_timestamp returns None → Err, never panic. (Note u64::MAX as
        // i64 is -1, a valid timestamp, so it must NOT be used here.)
        assert!(format_unix_timestamp(i64::MAX as u64, "%Y").is_err());
    }
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

        // Per-render instruction budget. The input (1 MB), variables (10 MB),
        // and output (10 MB) caps don't bound a template that burns CPU
        // WITHOUT growing output — e.g. `{% for i in range(100000000) %}{%
        // endfor %}` — which runs synchronously on the host async thread and
        // can starve co-resident jobs until the per-job wall-clock timeout
        // fires. `set_fuel` makes such a template fail fast with a render
        // error instead. Deliberately generous (the per-job timeout remains
        // the ultimate bound): far above any legitimate template, low enough
        // to cut an unbounded loop early.
        const MAX_RENDER_FUEL: u64 = 50_000_000;

        let mut env = minijinja::Environment::new();
        env.set_fuel(Some(MAX_RENDER_FUEL));
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

#[cfg(test)]
mod template_fuel_tests {
    // Validates the `set_fuel` mechanism `render` relies on: a template that
    // burns CPU without growing output (so the byte caps don't catch it) must
    // be cut by the fuel budget. Uses a low budget so the test is instant; the
    // production budget (`MAX_RENDER_FUEL`) is generous but the mechanism is
    // identical.
    #[test]
    fn fuel_bound_cuts_a_runaway_loop_but_not_a_cheap_template() {
        let mut env = minijinja::Environment::new();
        env.set_fuel(Some(10_000));
        env.add_template("runaway", "{% for i in range(100000000) %}{% endfor %}")
            .unwrap();
        let r = env
            .get_template("runaway")
            .unwrap()
            .render(minijinja::context! {});
        assert!(
            r.is_err(),
            "fuel-bounded runaway loop must error, not run to completion"
        );

        // A cheap template still renders fine under the same budget.
        env.add_template("ok", "hello {{ 1 + 1 }}").unwrap();
        assert_eq!(
            env.get_template("ok")
                .unwrap()
                .render(minijinja::context! {})
                .unwrap(),
            "hello 2"
        );
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
