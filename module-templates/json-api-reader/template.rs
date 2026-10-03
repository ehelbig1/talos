// Canonical catalog module: read one JSON API and keep only the fields named.
//
// Most "read integration" modules are the same three steps: one request with
// a credential, find the list in the response, keep a few fields of each
// entry. This does those three from config, so a new read integration needs
// no new module.
//
// Nothing is built into a tree, the response or the output. One pass walks
// to the list named by ROWS_AT and, for each entry, finds the fields in
// FIELDS; their text is validated and copied into the output, and everything
// else is stepped over without being parsed. That is what keeps the fuel
// cost near the cost of reading the bytes once, and it is why a field that
// was not asked for cannot appear in the output.
//
// The module never holds a credential. A header value or a string inside
// BODY may be a `vault://` reference; the host replaces it at the socket, and
// only for a host and a secret this module copy has been granted.
//
// One request, bounded: at most MAX_ROWS entries are kept (the rest are
// counted and reported as `truncated`). There is no paging; a list longer
// than one page is the workflow's job (TOP carries the cursor out).

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
//
// No tree is built, for the response or for the output. The pass walks to
// the list named by ROWS_AT with a scanner that only finds where each value
// ends (`skip_value`: it tracks strings and bracket depth and looks at
// nothing else). For a field that is kept, the text of its value is
// validated by serde_json and then copied into the output as it stands.
//
// Why it is built this way — measured on this module compiled as the
// platform compiles it, 2026-10-03, for 350-byte entries of 15 fields:
//
//   * the first version built a `serde_json::Value` per kept field and per
//     row: about 52,000 fuel per kept row, nearly all of it allocation;
//   * and when a TOP field shared its first key with ROWS_AT (the paging
//     cursor beside the list — the usual layout) it built that whole branch,
//     list included: about 86,000 fuel per entry, and a 1,000-entry response
//     could not finish inside the per-node ceiling whatever MAX_ROWS said.
//
// The figures for this version are in talos.json (`recommended_fuel`).
//
// What that trades away: text that is stepped over is not checked to be
// valid JSON. A response that is malformed only inside a part this module
// was told to ignore is read as if that part were well formed. Everything
// the output depends on IS checked — the objects on the way to ROWS_AT, the
// list, each kept entry's own structure and every kept value — and no input
// can make the scan read out of bounds or fail to advance.

/// Where a value is in the response: `start..end`.
type Span = (usize, usize);

/// What the pass collected.
struct Found {
    /// The kept rows, already written as JSON objects separated by ','.
    rows: Vec<u8>,
    /// Rows kept.
    count: usize,
    /// Entries in the list, kept or not.
    total: usize,
    /// Whether ROWS_AT led to a list (or a single object) at all.
    located: bool,
    /// For each TOP field, where its value is, once it has been seen.
    top: Vec<Option<Span>>,
}

const TRUNCATED: &str = "the response ends in the middle of a JSON value";
const NOT_JSON: &str = "the response is not JSON this module can read";

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t')
}

/// The first index at or after `i` that is not JSON whitespace.
fn skip_space(b: &[u8], mut i: usize) -> usize {
    while b.get(i).copied().is_some_and(is_space) {
        i += 1;
    }
    i
}

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGHS: u64 = 0x8080_8080_8080_8080;

/// Whether any of the eight bytes of `word` equals `byte`.
fn has_byte(word: u64, byte: u8) -> bool {
    let diff = word ^ (ONES * u64::from(byte));
    diff.wrapping_sub(ONES) & !diff & HIGHS != 0
}

/// `i` is at a string's opening quote: the index just past its closing one.
fn skip_string(b: &[u8], i: usize) -> Result<usize, String> {
    let mut j = i + 1;
    loop {
        // Eight bytes at a time while none of them is a quote or a
        // backslash: long text (a message body, a description) is most of
        // the bytes of many responses.
        while let Some(word) = b.get(j..j + 8).and_then(|chunk| <[u8; 8]>::try_from(chunk).ok()) {
            let word = u64::from_le_bytes(word);
            if has_byte(word, b'"') || has_byte(word, b'\\') {
                break;
            }
            j += 8;
        }
        // The next quote or backslash is within eight bytes, or the text
        // ends first.
        let stop = j + 8;
        while j < stop {
            match b.get(j) {
                None => return Err(TRUNCATED.to_string()),
                Some(b'"') => return Ok(j + 1),
                // An escape is two bytes as far as finding the end goes: the
                // escaped byte can be a quote and must not end the string.
                Some(b'\\') => j += 2,
                Some(_) => j += 1,
            }
        }
    }
}

/// `i` is at the first byte of a value: the index just past the value.
/// Finds the end and checks nothing else about what is inside.
fn skip_value(b: &[u8], i: usize) -> Result<usize, String> {
    match b.get(i) {
        None => Err(TRUNCATED.to_string()),
        Some(b'"') => skip_string(b, i),
        Some(b'{' | b'[') => {
            let mut depth = 0usize;
            let mut j = i;
            while let Some(&byte) = b.get(j) {
                match byte {
                    b'"' => {
                        j = skip_string(b, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            Err(TRUNCATED.to_string())
        }
        Some(_) => {
            // A number, true, false or null: up to the next delimiter.
            let mut j = i;
            while b.get(j).is_some_and(|&byte| !is_space(byte) && !matches!(byte, b',' | b'}' | b']')) {
                j += 1;
            }
            if j == i {
                Err(format!("{NOT_JSON}: a ',' or a closing bracket where a value should be"))
            } else {
                Ok(j)
            }
        }
    }
}

/// Accepts any JSON value and keeps nothing. Driven through
/// `deserialize_any`, so serde_json parses every token in full — escapes,
/// surrogate pairs, UTF-8, number ranges — which its own skipper does not.
struct Valid;

impl<'de> serde::de::DeserializeSeed<'de> for Valid {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for Valid {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(Valid)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while map.next_key_seed(Valid)?.is_some() {
            map.next_value_seed(Valid)?;
        }
        Ok(())
    }
}

/// The text of the value at `span`, once serde_json has accepted all of it.
/// This is the only way response text reaches the output.
fn checked(b: &[u8], span: Span) -> Result<&[u8], String> {
    use serde::de::DeserializeSeed;
    let text = &b[span.0..span.1];
    let mut de = serde_json::Deserializer::from_slice(text);
    Valid.deserialize(&mut de).and_then(|()| de.end()).map_err(|e| format!("{NOT_JSON}: {e}"))?;
    Ok(text)
}

/// Steps over a value that is not what was needed there (an object or a
/// list was). That place is structure the output depends on, so a scalar
/// there is validated; a list is only stepped over, since validating it
/// could cost the whole response for what is a mistake in the config.
fn skip_checked(b: &[u8], i: usize) -> Result<usize, String> {
    let end = skip_value(b, i)?;
    if b.get(i) != Some(&b'[') {
        checked(b, (i, end))?;
    }
    Ok(end)
}

/// An object key as it is written in the response.
struct Key<'a> {
    /// The bytes between the quotes.
    raw: &'a [u8],
    /// The whole token, quotes included.
    quoted: &'a [u8],
    /// Whether the key has an escape in it.
    escaped: bool,
}

impl Key<'_> {
    /// Whether this key is `name`. A key with no escape is compared as
    /// bytes; one with an escape is decoded first (rare, and a path segment
    /// never needs one to be written).
    fn is(&self, name: &str) -> bool {
        if self.escaped {
            serde_json::from_slice::<String>(self.quoted).is_ok_and(|decoded| decoded == name)
        } else {
            self.raw == name.as_bytes()
        }
    }
}

/// Steps to the next member of an object. `*pos` is just past the `{`
/// (`first`) or just past the previous member's value; the result is the
/// member's key and the index its value starts at, or `None` at the closing
/// brace, with `*pos` left just past it. The caller sets `*pos` to the end
/// of the value before calling again.
fn next_member<'a>(b: &'a [u8], pos: &mut usize, first: bool) -> Result<Option<(Key<'a>, usize)>, String> {
    let mut i = skip_space(b, *pos);
    match b.get(i) {
        None => return Err(TRUNCATED.to_string()),
        Some(b'}') => {
            *pos = i + 1;
            return Ok(None);
        }
        Some(b',') if !first => i = skip_space(b, i + 1),
        Some(_) if first => {}
        Some(_) => return Err(format!("{NOT_JSON}: object members not separated by ','")),
    }
    if b.get(i) != Some(&b'"') {
        return Err(format!("{NOT_JSON}: an object member that does not start with a quoted key"));
    }
    let end = skip_string(b, i)?;
    let raw = b.get(i + 1..end - 1).ok_or(TRUNCATED)?;
    let key = Key { raw, quoted: &b[i..end], escaped: raw.contains(&b'\\') };
    let colon = skip_space(b, end);
    if b.get(colon) != Some(&b':') {
        return Err(format!("{NOT_JSON}: an object key that is not followed by ':'"));
    }
    Ok(Some((key, skip_space(b, colon + 1))))
}

/// Steps to the next element of an array; the same contract as
/// [`next_member`], with the closing bracket ending it.
fn next_element(b: &[u8], pos: &mut usize, first: bool) -> Result<Option<usize>, String> {
    let i = skip_space(b, *pos);
    match b.get(i) {
        None => Err(TRUNCATED.to_string()),
        Some(b']') => {
            *pos = i + 1;
            Ok(None)
        }
        Some(b',') if !first => Ok(Some(skip_space(b, i + 1))),
        Some(_) if first => Ok(Some(i)),
        Some(_) => Err(format!("{NOT_JSON}: list entries not separated by ','")),
    }
}

/// The picks still in play at one level, as a set of indexes into the list
/// of picks. At most `MAX_FIELDS` (32) picks, so the set is one word and
/// narrowing it allocates nothing.
type PickSet = u32;

fn every_pick(picks: &[Pick]) -> PickSet {
    if picks.len() >= 32 {
        u32::MAX
    } else {
        (1u32 << picks.len()) - 1
    }
}

/// Of the picks in `set`, each `depth` segments into its path, those whose
/// next segment is `key`: the ones whose path ends there, and the ones that
/// go deeper.
fn matching(picks: &[Pick], set: PickSet, depth: usize, key: &Key) -> (PickSet, PickSet) {
    let (mut ends, mut deeper) = (0, 0);
    let mut rest = set;
    while rest != 0 {
        let index = rest.trailing_zeros() as usize;
        let bit = 1u32 << index;
        rest &= !bit;
        let path = &picks[index].path;
        if path.get(depth).is_some_and(|segment| key.is(segment)) {
            if path.len() == depth + 1 {
                ends |= bit;
            } else {
                deeper |= bit;
            }
        }
    }
    (ends, deeper)
}

/// Records where the picked fields of the value at `i` are, stepping over
/// the rest of it; returns the index just past the value. A pick whose path
/// ends at a key takes that key's whole value; picks that go deeper descend.
/// Anything that is not an object holds none of the picked fields. When a
/// key is repeated, the last occurrence that has the field is the one kept.
fn pick(b: &[u8], i: usize, picks: &[Pick], set: PickSet, depth: usize, slots: &mut [Option<Span>]) -> Result<usize, String> {
    if b.get(i) != Some(&b'{') {
        return skip_checked(b, i);
    }
    let mut pos = i + 1;
    let mut first = true;
    while let Some((key, start)) = next_member(b, &mut pos, first)? {
        first = false;
        let (ends, deeper) = matching(picks, set, depth, &key);
        pos = if deeper != 0 { pick(b, start, picks, deeper, depth + 1, slots)? } else { skip_value(b, start)? };
        let mut rest = ends;
        while rest != 0 {
            let index = rest.trailing_zeros() as usize;
            rest &= !(1u32 << index);
            slots[index] = Some((start, pos));
        }
    }
    Ok(pos)
}

/// Writes one row: every field, in the order FIELDS names them, with `null`
/// for one that was absent.
fn write_row(out: &mut Vec<u8>, b: &[u8], names: &[Vec<u8>], slots: &[Option<Span>]) -> Result<(), String> {
    out.push(b'{');
    for (index, slot) in slots.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&names[index]);
        match slot {
            Some(span) => out.extend_from_slice(checked(b, *span)?),
            None => out.extend_from_slice(b"null"),
        }
    }
    out.push(b'}');
    Ok(())
}

/// Each pick's output name as it is written in an object: `"name":`.
fn written_names(picks: &[Pick]) -> Result<Vec<Vec<u8>>, String> {
    picks
        .iter()
        .map(|p| {
            let mut name = serde_json::to_vec(&p.name).map_err(|e| e.to_string())?;
            name.push(b':');
            Ok(name)
        })
        .collect()
}

/// The list at `i`: keeps the first `max_rows` entries' picked fields and
/// counts the rest. One object is the only row. Anything else is not a
/// list, and `located` stays false.
fn rows(b: &[u8], i: usize, plan: &Plan, found: &mut Found) -> Result<usize, String> {
    let names = written_names(&plan.fields)?;
    let all = every_pick(&plan.fields);
    let mut slots: Vec<Option<Span>> = vec![None; plan.fields.len()];
    let mut keep = |start: usize, slots: &mut [Option<Span>], found: &mut Found| -> Result<usize, String> {
        slots.fill(None);
        let end = pick(b, start, &plan.fields, all, 0, slots)?;
        if found.count > 0 {
            found.rows.push(b',');
        }
        write_row(&mut found.rows, b, &names, slots)?;
        found.count += 1;
        Ok(end)
    };
    match b.get(i) {
        Some(b'[') => {
            found.located = true;
            let mut pos = i + 1;
            let mut first = true;
            while let Some(start) = next_element(b, &mut pos, first)? {
                first = false;
                pos = if found.count < plan.max_rows { keep(start, &mut slots, found)? } else { skip_value(b, start)? };
                found.total += 1;
            }
            Ok(pos)
        }
        Some(b'{') => {
            found.located = true;
            found.total += 1;
            keep(i, &mut slots, found)
        }
        _ => skip_checked(b, i),
    }
}

/// Walks from the value at `i`, `depth` keys into ROWS_AT, toward the list.
/// `top` is the TOP fields whose paths have matched every key so far; their
/// values are recorded on the way and every other branch is stepped over.
fn walk(b: &[u8], i: usize, plan: &Plan, depth: usize, top: PickSet, found: &mut Found) -> Result<usize, String> {
    let Some(next) = plan.rows_at.get(depth) else {
        // The end of the path: this value is the list. A TOP field can lie
        // inside it only when it is one object (the one-row case); those
        // few are read in a pass of their own.
        if top != 0 && b.get(i) == Some(&b'{') {
            pick(b, i, &plan.top, top, depth, &mut found.top)?;
        }
        return rows(b, i, plan, found);
    };
    if b.get(i) != Some(&b'{') {
        return skip_checked(b, i);
    }
    let mut pos = i + 1;
    let mut first = true;
    while let Some((key, start)) = next_member(b, &mut pos, first)? {
        first = false;
        let (ends, deeper) = matching(&plan.top, top, depth, &key);
        pos = if key.is(next) {
            walk(b, start, plan, depth + 1, deeper, found)?
        } else if deeper != 0 {
            pick(b, start, &plan.top, deeper, depth + 1, &mut found.top)?
        } else {
            skip_value(b, start)?
        };
        let mut rest = ends;
        while rest != 0 {
            let index = rest.trailing_zeros() as usize;
            rest &= !(1u32 << index);
            found.top[index] = Some((start, pos));
        }
    }
    Ok(pos)
}

/// The module's output for `body`: `rows`, `count`, `total`, `truncated`,
/// `top` and `status`, or `None` when ROWS_AT led to no list.
fn project(plan: &Plan, body: &[u8], status: u16) -> Result<Option<String>, String> {
    let mut found = Found { rows: Vec::new(), count: 0, total: 0, located: false, top: vec![None; plan.top.len()] };
    let start = skip_space(body, 0);
    let end = walk(body, start, plan, 0, every_pick(&plan.top), &mut found)?;
    if skip_space(body, end) != body.len() {
        return Err(format!("{NOT_JSON}: trailing content after its JSON"));
    }
    if !found.located {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(found.rows.len() + 160);
    out.extend_from_slice(b"{\"rows\":[");
    out.extend_from_slice(&found.rows);
    out.extend_from_slice(format!("],\"count\":{},\"total\":{},\"truncated\":{},\"top\":{{", found.count, found.total, found.total > found.count).as_bytes());
    let names = written_names(&plan.top)?;
    let mut wrote = false;
    for (index, slot) in found.top.iter().enumerate() {
        // A TOP field the response does not have is left out, not null.
        let Some(span) = slot else { continue };
        if wrote {
            out.push(b',');
        }
        out.extend_from_slice(&names[index]);
        out.extend_from_slice(checked(body, *span)?);
        wrote = true;
    }
    out.extend_from_slice(format!("}},\"status\":{status}}}").as_bytes());
    // Every piece is serde_json's own writing or text it accepted.
    String::from_utf8(out).map(Some).map_err(|_| NOT_JSON.to_string())
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
    project(&plan, &resp.body, resp.status)?.ok_or_else(|| {
        let at = if plan.rows_at.is_empty() { "the top of the response".to_string() } else { format!("'{}'", plan.rows_at.join(".")) };
        format!("{host} answered, but there is no list or object at {at} (ROWS_AT)")
    })
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

    // ---------------------------------------------- the scanner, on its own

    fn plan_of(config: Value) -> Plan {
        plan(serde_json::from_value(config).unwrap()).unwrap()
    }

    fn projected(config: Value, body: &[u8]) -> Result<Option<Value>, String> {
        let text = project(&plan_of(config), body, 200)?;
        Ok(text.map(|t| serde_json::from_str(&t).expect("the output is always JSON")))
    }

    fn lookup<'v>(value: &'v Value, path: &[String]) -> Option<&'v Value> {
        path.iter().try_fold(value, |v, key| v.get(key))
    }

    /// What the module must produce, computed the plain way: parse the whole
    /// response into a tree and look each path up in it.
    fn by_full_parse(plan: &Plan, doc: &Value) -> Option<Value> {
        let row = |entry: &Value| {
            Value::Object(plan.fields.iter().map(|f| (f.name.clone(), lookup(entry, &f.path).cloned().unwrap_or(Value::Null))).collect())
        };
        let (rows, total): (Vec<Value>, usize) = match lookup(doc, &plan.rows_at)? {
            Value::Array(entries) => (entries.iter().take(plan.max_rows).map(row).collect(), entries.len()),
            entry @ Value::Object(_) => (vec![row(entry)], 1),
            _ => return None,
        };
        let top: Map<String, Value> =
            plan.top.iter().filter_map(|t| lookup(doc, &t.path).map(|v| (t.name.clone(), v.clone()))).collect();
        Some(json!({"count": rows.len(), "truncated": total > rows.len(), "rows": rows, "total": total, "top": top, "status": 200}))
    }

    /// A small deterministic generator: no clock, no crate.
    struct Gen(u64);

    impl Gen {
        fn next(&mut self, below: u64) -> u64 {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % below
        }
        fn text(&mut self) -> String {
            // Everything a skipper can trip on: quotes, backslashes,
            // brackets, a control character, text outside ASCII, and lengths
            // on both sides of the eight-byte step.
            const PIECES: [&str; 12] = ["a", "\"", "\\", "{", "]", ",", ":", "é", "日本", "\n", " ", "xyzw"];
            (0..self.next(22)).map(|_| PIECES[self.next(12) as usize]).collect()
        }
        fn value(&mut self, depth: u32) -> Value {
            const KEYS: [&str; 7] = ["id", "name", "owner", "items", "n", "a b", "q\"k"];
            match self.next(if depth > 3 { 6 } else { 9 }) {
                0 => Value::Null,
                1 => json!(self.next(2) == 0),
                2 => json!(self.next(1_000_000) as i64 - 500_000),
                3 => json!(self.next(100_000) as f64 / 64.0),
                4 | 5 => json!(self.text()),
                6 => Value::Array((0..self.next(5)).map(|_| self.value(depth + 1)).collect()),
                _ => Value::Object((0..self.next(6)).map(|_| (KEYS[self.next(7) as usize].to_string(), self.value(depth + 1))).collect()),
            }
        }
    }

    /// The scanner and a full parse give the same output, for responses and
    /// configs it was not written against: 400 generated documents, written
    /// compactly and pretty-printed, under six configs.
    #[test]
    fn the_scan_agrees_with_a_full_parse_of_the_response() {
        let configs = [
            json!({"URL": "https://a.test/r", "ROWS_AT": "data.items", "FIELDS": {"id": "id", "name": "name", "owner": "owner.name"}, "TOP": {"next": "data.n", "who": "owner.id"}}),
            json!({"URL": "https://a.test/r", "ROWS_AT": "items", "FIELDS": {"all": "owner", "inner": "owner.items", "n": "n"}, "MAX_ROWS": 2}),
            json!({"URL": "https://a.test/r", "FIELDS": ["id", "a b", "q\"k"]}),
            json!({"URL": "https://a.test/r", "ROWS_AT": "owner", "FIELDS": ["id", "items"], "TOP": {"inside": "owner.name", "whole": "owner", "beside": "n"}}),
            json!({"URL": "https://a.test/r", "ROWS_AT": "data.items", "FIELDS": ["id"], "TOP": {"branch": "data"}}),
            json!({"URL": "https://a.test/r", "ROWS_AT": "owner.items.items", "FIELDS": {"x": "owner.owner.id", "y": "name"}}),
        ];
        let mut gen = Gen(7);
        let (mut located, mut compared) = (0, 0);
        for round in 0..400 {
            let mut doc = gen.value(0);
            // Half the time, the shape the configs are about.
            if round % 2 == 0 {
                let items: Vec<Value> = (0..gen.next(6)).map(|_| gen.value(1)).collect();
                doc = json!({"data": {"items": items, "n": gen.value(2)}, "items": gen.value(1), "owner": gen.value(1), "n": gen.value(2)});
            }
            for written in [serde_json::to_vec(&doc).unwrap(), serde_json::to_vec_pretty(&doc).unwrap()] {
                for config in &configs {
                    let want = by_full_parse(&plan_of(config.clone()), &doc);
                    let got = projected(config.clone(), &written).unwrap_or_else(|e| panic!("{e}\n{}", String::from_utf8_lossy(&written)));
                    assert_eq!(got, want, "config {config}\nresponse {}", String::from_utf8_lossy(&written));
                    compared += 1;
                    located += usize::from(want.is_some());
                }
            }
        }
        // The comparison is not over documents that never reach a list.
        assert!(located > compared / 5, "only {located} of {compared} located a list");
    }

    /// No input makes the scan panic, read out of bounds or loop, and when it
    /// answers, the answer is JSON: every prefix of a response, and every
    /// single-byte change to one, under two configs.
    #[test]
    fn a_broken_response_is_refused_or_read_and_never_worse() {
        let good = br#"{"data": {"items": [{"id": "a\"1", "owner": {"name": "Ada \\ L"}, "tags": ["x", {"y": [1, 2.5e3, -4]}], "note": "a longer piece of text, past eight bytes"}, {"id": 2}], "n": "c-2"}, "meta": {"total": 2}}"#;
        let configs = [
            json!({"URL": "https://a.test/r", "ROWS_AT": "data.items", "FIELDS": ["id", "owner.name", "tags"], "TOP": {"next": "data.n", "total": "meta.total"}}),
            json!({"URL": "https://a.test/r", "ROWS_AT": "data", "FIELDS": ["items", "n"], "TOP": {"all": "data"}}),
        ];
        let mut answered = 0;
        for config in &configs {
            for cut in 0..good.len() {
                // Ok or Err; `projected` itself asserts an Ok is JSON.
                let _ = projected(config.clone(), &good[..cut]);
            }
            for at in 0..good.len() {
                for byte in [b'"', b'\\', b'{', b'}', b'[', b']', b',', b':', b' ', b'x', 0x00, 0xff] {
                    let mut changed = good.to_vec();
                    changed[at] = byte;
                    answered += usize::from(matches!(projected(config.clone(), &changed), Ok(Some(_))));
                }
            }
            assert!(projected(config.clone(), good).unwrap().is_some());
        }
        // Many changes land in text that is stepped over or leave valid JSON.
        assert!(answered > 100, "{answered}");
    }

    #[test]
    fn a_kept_value_is_validated_and_stepped_over_text_is_not() {
        let fields_id = || json!({"URL": "https://a.test/r", "ROWS_AT": "rows", "FIELDS": ["id"]});
        // Kept, and not valid JSON: refused. A leading zero, a lone
        // surrogate, a raw control character, bytes that are not UTF-8.
        for bad in [&br#"{"rows": [{"id": 01}]}"#[..], br#"{"rows": [{"id": "\ud800"}]}"#, b"{\"rows\": [{\"id\": \"a\x01b\"}]}", b"{\"rows\": [{\"id\": \"\xff\"}]}", br#"{"rows": [{"id": tru}]}"#] {
            let err = projected(fields_id(), bad).unwrap_err();
            assert!(err.contains("not JSON"), "{err}");
        }
        // The same text where it is stepped over is not looked at: the
        // stated cost of not parsing what is thrown away.
        let out = projected(fields_id(), br#"{"junk": 01, "rows": [{"id": 7, "other": tru}], "more": "\ud800"}"#).unwrap().unwrap();
        assert_eq!(out["rows"], json!([{"id": 7}]));
        // The structure the output depends on is checked wherever it is.
        for bad in [&br#"{"rows": [{"id": 1} {"id": 2}]}"#[..], br#"{"rows": [{"id" 1}]}"#, br#"{"rows": [{id: 1}]}"#, br#"{"rows": [{"id": 1}"#, br#"{"rows": 01}"#] {
            assert!(projected(fields_id(), bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_key_written_with_an_escape_is_still_that_key() {
        let out = projected(
            json!({"URL": "https://a.test/r", "ROWS_AT": "rows", "FIELDS": ["name"], "TOP": {"n": "next"}}),
            br#"{"next": "c", "rows": [{"name": "Ada", "name2": "no"}]}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(out["rows"], json!([{"name": "Ada"}]));
        assert_eq!(out["top"], json!({"n": "c"}));
    }

    /// The paging cursor beside the list is the usual layout. It is found on
    /// the way down; a TOP field that IS the branch holding the list, or one
    /// inside the single object ROWS_AT names, is found too.
    #[test]
    fn a_top_field_beside_around_or_inside_the_list_is_found() {
        host::http::respond(200, listing().to_string());
        let mut cfg = base();
        cfg["TOP"] = json!({"next": "data.next_cursor", "branch": "data", "first_meta": "meta"});
        let out = run_with(cfg).unwrap();
        assert_eq!(out["count"], 3);
        assert_eq!(out["top"]["next"], "c-2");
        assert_eq!(out["top"]["branch"]["items"][1]["id"], "a2");
        assert_eq!(out["top"]["first_meta"], json!({"total": 3, "request_id": "r-1"}));

        host::http::respond(200, r#"{"profile": {"id": 9, "plan": {"tier": "pro"}}, "v": 2}"#);
        let out = run_with(json!({"URL": "https://api.example.test/me", "ROWS_AT": "profile", "FIELDS": ["id"], "TOP": {"tier": "profile.plan.tier", "v": "v", "absent": "profile.nope"}})).unwrap();
        assert_eq!(out["rows"], json!([{"id": 9}]));
        assert_eq!(out["top"], json!({"tier": "pro", "v": 2}), "a TOP field the response lacks is left out");
    }

    #[test]
    fn eight_bytes_at_a_time_finds_the_same_end_as_one_at_a_time() {
        for byte in [b'"', b'\\', 0x00, 0x7f, 0x80, 0xff] {
            for position in 0..8 {
                let mut bytes = [b'a'; 8];
                assert!(!has_byte(u64::from_le_bytes(bytes), byte));
                bytes[position] = byte;
                assert!(has_byte(u64::from_le_bytes(bytes), byte), "{byte:#x} at {position}");
            }
        }
        // A closing quote, and an escaped quote before it, at every offset.
        for length in 0..40 {
            for escape_at in 0..=length {
                let mut text = vec![b'"'];
                text.extend(std::iter::repeat(b'x').take(escape_at));
                text.extend_from_slice(b"\\\"");
                text.extend(std::iter::repeat(b'y').take(length - escape_at));
                text.push(b'"');
                let end = text.len();
                text.extend_from_slice(b", \"after\"");
                assert_eq!(skip_string(&text, 0), Ok(end), "{}", String::from_utf8_lossy(&text));
            }
        }
        assert!(skip_string(b"\"never closed\\\"", 0).is_err());
    }
}
