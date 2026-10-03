// Canonical catalog module: read one JSON API and keep only the fields named.
//
// Most "read integration" modules are the same three steps: one request with
// a credential, find the list in the response, keep a few fields of each
// entry. This does those three from config, so a new read integration needs
// no new module.
//
// The response is never built into a tree. A streaming pass walks to the
// list named by ROWS_AT and, for each entry, materialises only the fields in
// FIELDS; everything else is skipped without being allocated. That is what
// keeps the fuel cost near the cost of tokenising the bytes, and it is why a
// field that was not asked for cannot appear in the output.
//
// The module never holds a credential. A header value or a string inside
// BODY may be a `vault://` reference; the host replaces it at the socket, and
// only for a host and a secret this module copy has been granted.
//
// One request, bounded: at most MAX_ROWS entries are kept (the rest are
// counted and reported as `truncated`). There is no paging; a list longer
// than one page is the workflow's job (TOP carries the cursor out).

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};
use talos_sdk_macros::talos_module;

const DEFAULT_MAX_ROWS: usize = 100;
const ROWS_CEILING: usize = 1000;
const MAX_FIELDS: usize = 32;
const MAX_PATH_SEGMENTS: usize = 8;
const MAX_HEADERS: usize = 16;

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(rename = "URL")]
    url: Option<String>,
    #[serde(rename = "METHOD")]
    method: Option<String>,
    #[serde(rename = "HEADERS", default)]
    headers: Map<String, Value>,
    #[serde(rename = "BODY")]
    body: Option<Value>,
    #[serde(rename = "ROWS_AT")]
    rows_at: Option<String>,
    #[serde(rename = "FIELDS")]
    fields: Option<Value>,
    #[serde(rename = "TOP")]
    top: Option<Value>,
    #[serde(rename = "MAX_ROWS")]
    max_rows: Option<Value>,
    #[serde(rename = "TIMEOUT_MS")]
    timeout_ms: Option<Value>,
}

/// One field to keep: where it is in an entry, and the name it is given.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pick {
    path: Vec<String>,
    name: String,
}

#[derive(Debug, PartialEq)]
struct Plan {
    url: String,
    post: bool,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    rows_at: Vec<String>,
    fields: Vec<Pick>,
    top: Vec<Pick>,
    max_rows: usize,
    timeout_ms: Option<u32>,
}

/// A dotted path as its segments. Empty input is the empty path.
fn path(spec: &str, what: &str) -> Result<Vec<String>, String> {
    if spec.is_empty() {
        return Ok(Vec::new());
    }
    let segments: Vec<String> = spec.split('.').map(str::to_string).collect();
    if segments.iter().any(String::is_empty) {
        return Err(format!("{what} '{spec}' has an empty segment"));
    }
    if segments.len() > MAX_PATH_SEGMENTS {
        return Err(format!("{what} '{spec}' is deeper than {MAX_PATH_SEGMENTS} levels"));
    }
    Ok(segments)
}

/// FIELDS / TOP: a list of paths (each kept under its own last segment) or an
/// object of output name → path.
fn picks(spec: Option<&Value>, what: &str, required: bool) -> Result<Vec<Pick>, String> {
    let mut out = Vec::new();
    match spec {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for item in items {
                let p = item.as_str().ok_or_else(|| format!("{what} entries must be strings, got {item}"))?;
                let segments = path(p, what)?;
                let name = segments.last().cloned().ok_or_else(|| format!("{what} has an empty entry"))?;
                out.push(Pick { path: segments, name });
            }
        }
        Some(Value::Object(map)) => {
            for (name, p) in map {
                let p = p.as_str().ok_or_else(|| format!("{what}.{name} must be a path string, got {p}"))?;
                let segments = path(p, what)?;
                if segments.is_empty() || name.is_empty() {
                    return Err(format!("{what}.{name} must name a field"));
                }
                out.push(Pick { path: segments, name: name.clone() });
            }
        }
        Some(other) => return Err(format!("{what} must be a list of paths or an object of name → path, got {other}")),
    }
    if required && out.is_empty() {
        return Err(format!("Missing {what}: name at least one field to keep"));
    }
    if out.len() > MAX_FIELDS {
        return Err(format!("{what} names {} fields; the limit is {MAX_FIELDS}", out.len()));
    }
    let mut names: Vec<&str> = out.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    if let Some(dup) = names.windows(2).find(|w| w[0] == w[1]) {
        return Err(format!("{what} gives two fields the name '{}'", dup[0]));
    }
    Ok(out)
}

fn whole_number(v: Option<&Value>, what: &str) -> Result<Option<u64>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| format!("{what} must be a whole number, got {v}")),
    }
}

fn plan(cfg: Config) -> Result<Plan, String> {
    let url = cfg.url.filter(|u| !u.trim().is_empty()).ok_or("Missing URL config")?;
    if !url.starts_with("https://") {
        return Err("URL must start with https://".to_string());
    }
    let post = match cfg.method.as_deref().map(str::to_ascii_uppercase).as_deref() {
        None | Some("GET") => false,
        Some("POST") => true,
        Some(other) => return Err(format!("METHOD must be GET or POST, got '{other}': this module reads")),
    };
    if cfg.headers.len() > MAX_HEADERS {
        return Err(format!("HEADERS has {} entries; the limit is {MAX_HEADERS}", cfg.headers.len()));
    }
    let mut headers = Vec::with_capacity(cfg.headers.len() + 1);
    for (name, value) in &cfg.headers {
        let value = value.as_str().ok_or_else(|| format!("HEADERS.{name} must be a string, got {value}"))?;
        if name.eq_ignore_ascii_case("content-type") && post {
            return Err("HEADERS must not set Content-Type: a POST body is sent as application/json".to_string());
        }
        headers.push((name.clone(), value.to_string()));
    }
    let body = match (post, cfg.body) {
        (false, None | Some(Value::Null)) => Vec::new(),
        (false, Some(_)) => return Err("BODY is only sent with METHOD POST".to_string()),
        (true, body) => {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
            serde_json::to_vec(&body.unwrap_or_else(|| Value::Object(Map::new()))).map_err(|e| format!("BODY could not be written as JSON: {e}"))?
        }
    };
    let max_rows = match whole_number(cfg.max_rows.as_ref(), "MAX_ROWS")? {
        None => DEFAULT_MAX_ROWS,
        Some(n) if (1..=ROWS_CEILING as u64).contains(&n) => n as usize,
        Some(n) => return Err(format!("MAX_ROWS must be between 1 and {ROWS_CEILING}, got {n}")),
    };
    let timeout_ms = match whole_number(cfg.timeout_ms.as_ref(), "TIMEOUT_MS")? {
        None => None,
        Some(n) => Some(u32::try_from(n).map_err(|_| format!("TIMEOUT_MS {n} is too large"))?),
    };
    let rows_at = path(cfg.rows_at.as_deref().unwrap_or(""), "ROWS_AT")?;
    let top = picks(cfg.top.as_ref(), "TOP", false)?;
    if rows_at.is_empty() && !top.is_empty() {
        return Err("TOP needs ROWS_AT: with no ROWS_AT the response itself is the list, and a list has no fields beside it".to_string());
    }
    Ok(Plan {
        url,
        post,
        headers,
        body,
        rows_at,
        fields: picks(cfg.fields.as_ref(), "FIELDS", true)?,
        top,
        max_rows,
        timeout_ms,
    })
}

// ------------------------------------------------------------ the projection

/// What the pass collected.
#[derive(Default, Debug)]
struct Found {
    rows: Vec<Value>,
    /// Entries in the list, kept or not.
    total: usize,
    /// Whether ROWS_AT led to a list (or a single object) at all.
    located: bool,
    top: Map<String, Value>,
}

/// Looks `rest` up inside an already-built value.
fn lookup<'v>(value: &'v Value, rest: &[String]) -> Option<&'v Value> {
    rest.iter().try_fold(value, |v, key| v.get(key))
}

/// Keeps the picked fields of ONE object and skips the rest. A pick whose
/// path ends at a key takes that key's whole value; picks that go deeper
/// descend without building what lies beside them.
struct PickSeed<'a> {
    picks: Vec<(&'a [String], &'a str)>,
    out: &'a mut Map<String, Value>,
}

impl<'de> DeserializeSeed<'de> for PickSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for PickSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            let here: Vec<(&[String], &str)> = self
                .picks
                .iter()
                .filter(|(p, _)| p.first() == Some(&key))
                .map(|(p, name)| (&p[1..], *name))
                .collect();
            if here.is_empty() {
                map.next_value::<IgnoredAny>()?;
            } else if here.iter().any(|(rest, _)| rest.is_empty()) {
                // Someone wants this value whole: build it once and answer
                // every pick under this key from it.
                let value: Value = map.next_value()?;
                for (rest, name) in here {
                    if let Some(found) = lookup(&value, rest) {
                        self.out.insert(name.to_string(), found.clone());
                    }
                }
            } else {
                map.next_value_seed(PickSeed { picks: here, out: &mut *self.out })?;
            }
        }
        Ok(())
    }
    // Anything that is not an object holds none of the picked fields.
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> { Ok(()) }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> { Ok(()) }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> { Ok(()) }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> { Ok(()) }
    fn visit_str<E>(self, _: &str) -> Result<(), E> { Ok(()) }
    fn visit_unit<E>(self) -> Result<(), E> { Ok(()) }
}

fn row_of(fields: &[Pick], picked: Map<String, Value>) -> Value {
    // Every row has every field: one that was absent is null, not missing.
    let mut row = Map::with_capacity(fields.len());
    for f in fields {
        row.insert(f.name.clone(), picked.get(&f.name).cloned().unwrap_or(Value::Null));
    }
    Value::Object(row)
}

/// The list itself: keeps the first `max_rows` entries' picked fields and
/// counts the rest without building them.
struct RowsSeed<'a> {
    fields: &'a [Pick],
    max_rows: usize,
    found: &'a mut Found,
}

impl<'de> DeserializeSeed<'de> for RowsSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for RowsSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a list of objects, or one object")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        self.found.located = true;
        let picks: Vec<(&[String], &str)> = self.fields.iter().map(|p| (p.path.as_slice(), p.name.as_str())).collect();
        loop {
            if self.found.rows.len() >= self.max_rows {
                if seq.next_element::<IgnoredAny>()?.is_none() {
                    break;
                }
                self.found.total += 1;
                continue;
            }
            let mut picked = Map::new();
            if seq.next_element_seed(PickSeed { picks: picks.clone(), out: &mut picked })?.is_none() {
                break;
            }
            self.found.total += 1;
            self.found.rows.push(row_of(self.fields, picked));
        }
        Ok(())
    }
    /// ROWS_AT named one object: it is the only row.
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<(), A::Error> {
        self.found.located = true;
        let picks: Vec<(&[String], &str)> = self.fields.iter().map(|p| (p.path.as_slice(), p.name.as_str())).collect();
        let mut picked = Map::new();
        PickSeed { picks, out: &mut picked }.visit_map(map)?;
        self.found.total = 1;
        self.found.rows.push(row_of(self.fields, picked));
        Ok(())
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> { Ok(()) }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> { Ok(()) }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> { Ok(()) }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> { Ok(()) }
    fn visit_str<E>(self, _: &str) -> Result<(), E> { Ok(()) }
    fn visit_unit<E>(self) -> Result<(), E> { Ok(()) }
}

/// Walks from the top of the response toward ROWS_AT, picking TOP fields on
/// the way at the first level and skipping every other branch.
struct WalkSeed<'a> {
    rows_at: &'a [String],
    plan: &'a Plan,
    found: &'a mut Found,
    /// TOP is read at the top level only.
    at_top: bool,
}

impl<'de> DeserializeSeed<'de> for WalkSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        // The end of the path: this value is the list. (A plan with no
        // ROWS_AT has no TOP either, so the top of the response qualifies.)
        if self.rows_at.is_empty() {
            return RowsSeed { fields: &self.plan.fields, max_rows: self.plan.max_rows, found: self.found }.deserialize(d);
        }
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for WalkSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON object on the way to ROWS_AT")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let top_picks: Vec<(&[String], &str)> =
            if self.at_top { self.plan.top.iter().map(|p| (p.path.as_slice(), p.name.as_str())).collect() } else { Vec::new() };
        while let Some(key) = map.next_key::<String>()? {
            let toward_rows = self.rows_at.first() == Some(&key);
            let top_here: Vec<(&[String], &str)> =
                top_picks.iter().filter(|(p, _)| p.first() == Some(&key)).map(|(p, name)| (&p[1..], *name)).collect();
            if toward_rows && top_here.is_empty() {
                map.next_value_seed(WalkSeed { rows_at: &self.rows_at[1..], plan: self.plan, found: &mut *self.found, at_top: false })?;
            } else if !top_here.is_empty() {
                // A TOP field (and possibly the way to the rows) under one
                // key: build this value once and read both from it.
                let value: Value = map.next_value()?;
                for (rest, name) in top_here {
                    if let Some(v) = lookup(&value, rest) {
                        self.found.top.insert(name.to_string(), v.clone());
                    }
                }
                if toward_rows {
                    if let Some(rows) = lookup(&value, &self.rows_at[1..]) {
                        RowsSeed { fields: &self.plan.fields, max_rows: self.plan.max_rows, found: &mut *self.found }
                            .deserialize(rows)
                            .map_err(serde::de::Error::custom)?;
                    }
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> { Ok(()) }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> { Ok(()) }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> { Ok(()) }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> { Ok(()) }
    fn visit_str<E>(self, _: &str) -> Result<(), E> { Ok(()) }
    fn visit_unit<E>(self) -> Result<(), E> { Ok(()) }
}

fn project(plan: &Plan, body: &[u8]) -> Result<Found, String> {
    let mut found = Found::default();
    let mut de = serde_json::Deserializer::from_slice(body);
    WalkSeed { rows_at: &plan.rows_at, plan, found: &mut found, at_top: true }
        .deserialize(&mut de)
        .map_err(|e| format!("the response is not JSON this module can read: {e}"))?;
    de.end().map_err(|e| format!("the response has trailing content after its JSON: {e}"))?;
    Ok(found)
}

fn host_of(url: &str) -> &str {
    url.trim_start_matches("https://").split(['/', '?', '#']).next().unwrap_or("")
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    let plan = plan(envelope.config)?;

    let req = talos::core::http::Request {
        method: if plan.post { talos::core::http::Method::Post } else { talos::core::http::Method::Get },
        url: plan.url.clone(),
        headers: plan.headers.clone(),
        body: plan.body.clone(),
        timeout_ms: plan.timeout_ms,
    };
    let host = host_of(&plan.url);
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("request to {host} failed: {e:?}"))?;
    if !(200..300).contains(&resp.status) {
        // The body of an error response is not echoed: it can repeat what
        // was sent, and what was sent carried a credential.
        return Err(format!("{host} answered HTTP {}", resp.status));
    }
    let found = project(&plan, &resp.body)?;
    if !found.located {
        let at = if plan.rows_at.is_empty() { "the top of the response".to_string() } else { format!("'{}'", plan.rows_at.join(".")) };
        return Err(format!("{host} answered, but there is no list or object at {at} (ROWS_AT)"));
    }
    let count = found.rows.len();
    serde_json::to_string(&serde_json::json!({
        "rows": found.rows,
        "count": count,
        "total": found.total,
        "truncated": found.total > count,
        "top": found.top,
        "status": resp.status,
    }))
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use talos_module_testkit::host;

    fn run_with(config: Value) -> Result<Value, String> {
        run(json!({ "config": config }).to_string()).map(|out| serde_json::from_str(&out).unwrap())
    }

    /// A response in the shape most list APIs use: the list under a key,
    /// paging fields beside it, and far more in each entry than is wanted.
    fn listing() -> Value {
        json!({
            "data": {
                "items": [
                    {"id": "a1", "title": "First", "owner": {"name": "Ada", "email": "ada@example.test", "internal": {"flags": [1, 2, 3]}},
                     "amount": 12.5, "tags": ["x", "y"], "private_note": "never asked for"},
                    {"id": "a2", "title": "Second", "owner": {"name": "Lin"}, "amount": 3, "private_note": "never asked for"},
                    {"id": "a3", "title": null, "owner": null, "private_note": "never asked for"}
                ],
                "next_cursor": "c-2"
            },
            "meta": {"total": 3, "request_id": "r-1"},
            "unrelated": {"deep": [{"x": 1}, {"x": 2}]}
        })
    }

    fn base() -> Value {
        json!({
            "URL": "https://api.example.test/v1/items?limit=3",
            "ROWS_AT": "data.items",
            "FIELDS": {"id": "id", "title": "title", "owner": "owner.name", "amount": "amount"},
            "TOP": {"next": "data.next_cursor", "total": "meta.total"}
        })
    }

    #[test]
    fn only_the_named_fields_are_kept_and_an_absent_one_is_null() {
        host::http::respond(200, listing().to_string());
        let out = run_with(base()).unwrap();
        assert_eq!(
            out["rows"],
            json!([
                {"id": "a1", "title": "First", "owner": "Ada", "amount": 12.5},
                {"id": "a2", "title": "Second", "owner": "Lin", "amount": 3},
                {"id": "a3", "title": null, "owner": null, "amount": null}
            ])
        );
        assert_eq!((out["count"].clone(), out["total"].clone(), out["truncated"].clone()), (json!(3), json!(3), json!(false)));
        assert_eq!(out["top"], json!({"next": "c-2", "total": 3}));
        assert_eq!(out["status"], 200);
        let text = out.to_string();
        for unasked in ["never asked for", "ada@example.test", "request_id", "unrelated"] {
            assert!(!text.contains(unasked), "{unasked} was not asked for: {text}");
        }
    }

    #[test]
    fn rows_past_the_limit_are_counted_not_kept() {
        let many: Vec<Value> = (0..250).map(|i| json!({"id": i, "pad": "x".repeat(50)})).collect();
        host::http::respond(200, json!({"rows": many}).to_string());
        let out = run_with(json!({"URL": "https://api.example.test/r", "ROWS_AT": "rows", "FIELDS": ["id"], "MAX_ROWS": 40})).unwrap();
        assert_eq!(out["count"], 40);
        assert_eq!(out["total"], 250);
        assert_eq!(out["truncated"], true);
        assert_eq!(out["rows"][39], json!({"id": 39}));
    }

    #[test]
    fn the_response_may_itself_be_the_list_or_one_object() {
        host::http::respond(200, r#"[{"id": 1, "x": {"y": "deep"}}, 7, "text", null, {"id": 2}]"#);
        let out = run_with(json!({"URL": "https://api.example.test/r", "FIELDS": {"id": "id", "y": "x.y"}})).unwrap();
        // An entry that is not an object has none of the fields.
        assert_eq!(out["rows"][0], json!({"id": 1, "y": "deep"}));
        assert_eq!(out["rows"][1], json!({"id": null, "y": null}));
        assert_eq!(out["total"], 5);

        host::http::respond(200, r#"{"profile": {"id": 9, "name": "one record", "secret": "s"}}"#);
        let out = run_with(json!({"URL": "https://api.example.test/me", "ROWS_AT": "profile", "FIELDS": ["id", "name"]})).unwrap();
        assert_eq!(out["rows"], json!([{"id": 9, "name": "one record"}]));
        assert_eq!(out["count"], 1);
    }

    #[test]
    fn a_whole_value_and_a_field_inside_it_can_both_be_kept() {
        host::http::respond(200, listing().to_string());
        let mut cfg = base();
        cfg["FIELDS"] = json!({"owner": "owner", "owner_name": "owner.name", "first_flag_holder": "owner.internal"});
        let out = run_with(cfg).unwrap();
        assert_eq!(out["rows"][0]["owner_name"], "Ada");
        assert_eq!(out["rows"][0]["owner"]["email"], "ada@example.test");
        assert_eq!(out["rows"][0]["first_flag_holder"], json!({"flags": [1, 2, 3]}));
        assert_eq!(out["rows"][2]["owner"], Value::Null);
    }

    /// The request is what the config says, and a vault reference leaves the
    /// module as the reference: the host, not the module, replaces it.
    #[test]
    fn the_request_carries_references_not_credentials() {
        host::http::respond(200, r#"{"rows": []}"#);
        let out = run_with(json!({
            "URL": "https://api.example.test/search",
            "METHOD": "post",
            "HEADERS": {"Authorization": "vault://example/api_key"},
            "BODY": {"client_secret": "vault://example/secret", "query": {"since": "2026-01-01"}},
            "ROWS_AT": "rows", "FIELDS": ["id"], "TIMEOUT_MS": 5000
        }))
        .unwrap();
        assert_eq!(out["count"], 0);
        assert_eq!(out["truncated"], false);
        let sent = host::http::requests();
        assert_eq!(sent.len(), 1, "one request, no paging");
        assert!(matches!(sent[0].method, talos::core::http::Method::Post));
        assert_eq!(sent[0].url, "https://api.example.test/search");
        assert_eq!(sent[0].timeout_ms, Some(5000));
        assert!(sent[0].headers.contains(&("Authorization".to_string(), "vault://example/api_key".to_string())));
        assert!(sent[0].headers.contains(&("Content-Type".to_string(), "application/json".to_string())));
        let body: Value = serde_json::from_slice(&sent[0].body).unwrap();
        assert_eq!(body, json!({"client_secret": "vault://example/secret", "query": {"since": "2026-01-01"}}));

        // A GET sends no body and no content type.
        host::http::respond(200, "[]");
        run_with(json!({"URL": "https://api.example.test/r", "FIELDS": ["id"]})).unwrap();
        let get = &host::http::requests()[1];
        assert!(matches!(get.method, talos::core::http::Method::Get));
        assert!(get.body.is_empty() && get.headers.is_empty());
    }

    #[test]
    fn a_failed_request_names_the_host_and_status_and_not_the_body() {
        host::http::respond(401, r#"{"error": "bad key vault-value-echoed-back"}"#);
        let err = run_with(base()).unwrap_err();
        assert_eq!(err, "api.example.test answered HTTP 401");

        // No responder: the kit refuses every request, as a dead network would.
        host::http::respond_with(|_| Err(talos::core::http::Error::Timeout));
        let err = run_with(base()).unwrap_err();
        assert!(err.starts_with("request to api.example.test failed"), "{err}");
    }

    #[test]
    fn a_response_without_the_list_says_where_it_looked() {
        host::http::respond(200, r#"{"data": {"other": []}}"#);
        let err = run_with(base()).unwrap_err();
        assert!(err.contains("no list or object at 'data.items'"), "{err}");

        host::http::respond(200, "<html>not json</html>");
        let err = run_with(base()).unwrap_err();
        assert!(err.contains("not JSON"), "{err}");

        host::http::respond(200, r#"{"data": {"items": []}} trailing"#);
        assert!(run_with(base()).unwrap_err().contains("trailing"));
    }

    #[test]
    fn a_config_that_cannot_mean_what_it_says_is_refused_before_any_request() {
        host::http::respond(200, "[]");
        let cases = [
            (json!({"FIELDS": ["id"]}), "Missing URL"),
            (json!({"URL": "http://api.example.test/r", "FIELDS": ["id"]}), "https://"),
            (json!({"URL": "https://a.test/r"}), "Missing FIELDS"),
            (json!({"URL": "https://a.test/r", "FIELDS": []}), "Missing FIELDS"),
            (json!({"URL": "https://a.test/r", "FIELDS": ["a..b"]}), "empty segment"),
            (json!({"URL": "https://a.test/r", "FIELDS": {"x": 1}}), "must be a path string"),
            (json!({"URL": "https://a.test/r", "FIELDS": ["a.id", "b.id"]}), "two fields the name 'id'"),
            (json!({"URL": "https://a.test/r", "FIELDS": ["id"], "METHOD": "DELETE"}), "this module reads"),
            (json!({"URL": "https://a.test/r", "FIELDS": ["id"], "BODY": {"a": 1}}), "only sent with METHOD POST"),
            (json!({"URL": "https://a.test/r", "FIELDS": ["id"], "MAX_ROWS": 0}), "between 1 and 1000"),
            (json!({"URL": "https://a.test/r", "FIELDS": ["id"], "MAX_ROWS": 5000}), "between 1 and 1000"),
            (json!({"URL": "https://a.test/r", "FIELDS": ["id"], "MAX_ROWS": "10"}), "whole number"),
            (json!({"URL": "https://a.test/r", "FIELDS": ["id"], "HEADERS": {"X": 1}}), "must be a string"),
            (json!({"URL": "https://a.test/r", "FIELDS": ["id"], "TOP": ["total"]}), "TOP needs ROWS_AT"),
            (json!({"URL": "https://a.test/r", "FIELDS": ["id"], "METHOD": "POST", "HEADERS": {"content-type": "text/plain"}}), "must not set Content-Type"),
        ];
        for (cfg, want) in cases {
            let err = run_with(cfg.clone()).unwrap_err();
            assert!(err.contains(want), "{cfg}: {err}");
        }
        assert!(host::http::requests().is_empty(), "nothing was sent for a refused config");
    }

    /// The pass skips what it was not asked for at any depth, including
    /// strings that look like structure.
    #[test]
    fn skipped_content_cannot_disturb_what_is_kept() {
        host::http::respond(
            200,
            r#"{"noise": "{\"items\": [{\"id\": \"fake\"}]}", "items": [{"id": "real", "blob": {"items": [{"id": "nested"}], "s": "]}"}}], "more": [[[{"items": 1}]]]}"#,
        );
        let out = run_with(json!({"URL": "https://api.example.test/r", "ROWS_AT": "items", "FIELDS": ["id"]})).unwrap();
        assert_eq!(out["rows"], json!([{"id": "real"}]));
    }
}
