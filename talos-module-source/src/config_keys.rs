//! The config keys a module's source reads, and whether its schema declares
//! them.
//!
//! A `config_schema` is what an installer reads to configure a node, and it
//! is written by hand apart from the code, so it drifts: a key renamed in the
//! source and not in the schema is a node configured with a key nothing reads
//! (`create-calendar-event` declares `TITLE`; its source reads `SUMMARY`).
//!
//! Over the source before its `#[cfg(test)]` module, comments removed, a key
//! is read by a field `#[serde(rename = "KEY")]` of a struct whose name
//! contains `Config`, or by `config.get("KEY")` / `cfg["KEY"]` (a value named
//! `config…`, `cfg…` or `conf…`). The schema rules are [`schema_mismatch`]:
//!
//! 1. every key the source reads is a property of `config_schema`, with a
//!    non-empty `description`;
//! 2. where the module has such a typed config struct (the shape
//!    `make new-template` writes), every declared property is read: a
//!    property nothing reads is a setting that does nothing.

use crate::literals::{before_tests, without_comments};
use std::collections::BTreeSet;

/// The config keys a source reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeysRead {
    /// Whether a typed `…Config` struct with renamed fields was found: then
    /// the keys are the whole set the module can read, and a key outside
    /// them is read by nothing.
    pub typed: bool,
    /// Every key read, by struct field or by lookup.
    pub keys: BTreeSet<String>,
}

/// Whether `s` is spelt as a config key: `UPPER_CASE`, digits and `_`, starting with a letter.
pub fn is_key(s: &str) -> bool {
    s.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        && s.bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// The quoted key right after `at` in `code`, if it is one.
fn quoted_key_at(code: &str, at: usize) -> Option<&str> {
    let rest = code[at..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let key = &rest[..rest.find('"')?];
    is_key(key).then_some(key)
}

/// The keys a typed config struct reads, and whether there is one. `code` is
/// the source with comments removed.
fn struct_keys(code: &str) -> (bool, BTreeSet<String>) {
    let mut keys = BTreeSet::new();
    let mut any = false;
    let mut from = 0;
    while let Some(at) = code[from..].find("struct ") {
        let start = from + at + "struct ".len();
        from = start;
        let name: String = code[start..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.contains("Config") {
            continue;
        }
        let Some(open) = code[start..].find('{').map(|o| start + o) else {
            continue;
        };
        // A unit or tuple struct has no `{` before its `;` or `(`.
        if code[start..open].contains(';') || code[start..open].contains('(') {
            continue;
        }
        let mut depth = 0usize;
        let mut close = code.len();
        for (k, c) in code[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = open + k;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &code[open..close];
        let mut found_here = false;
        let mut f = 0;
        while let Some(r) = body[f..].find("rename") {
            let after = f + r + "rename".len();
            f = after;
            let rest = body[after..].trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let offset = body.len() - rest.len();
                if let Some(key) = quoted_key_at(body, offset) {
                    keys.insert(key.to_string());
                    found_here = true;
                }
            }
        }
        any |= found_here;
    }
    (any, keys)
}

/// The keys read by `config.get("KEY")` or `cfg["KEY"]`. `code` is the source
/// with comments removed.
fn lookup_keys(code: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for (opener, len) in [(".get(", 5usize), ("[", 1usize)] {
        let mut from = 0;
        while let Some(at) = code[from..].find(opener) {
            let at = from + at;
            from = at + len;
            let before: String = code[..at]
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let lower = before.to_ascii_lowercase();
            if !(lower.starts_with("config")
                || lower.starts_with("cfg")
                || lower.starts_with("conf"))
            {
                continue;
            }
            if let Some(key) = quoted_key_at(code, at + len) {
                keys.insert(key.to_string());
            }
        }
    }
    keys
}

/// Every config key a module's source reads, and whether through a typed
/// struct.
#[must_use]
pub fn keys_read(source: &str) -> KeysRead {
    let code = without_comments(before_tests(source));
    let (typed, mut keys) = struct_keys(&code);
    keys.extend(lookup_keys(&code));
    KeysRead { typed, keys }
}

/// What is wrong with one module's `config_schema`, if anything: a sentence
/// per problem, for a person.
#[must_use]
/// The config keys a module refuses to run without: each `KEY` of a string
/// literal `Missing KEY config` in the body, the wording `ok_or("Missing KEY
/// config")` that every template and lane module uses. A key read on one
/// branch only (`match mode { "grant" => cfg.step.ok_or("Missing STEP config") }`)
/// is listed too — the scan cannot see the branch — so a reader treats the
/// answer as advice about a node's config, not as proof of a failed run.
pub fn required_keys(source: &str) -> BTreeSet<String> {
    let code = without_comments(before_tests(source));
    let mut out = BTreeSet::new();
    for (_, lit) in crate::literals::literals(&code) {
        let Some(rest) = lit.strip_prefix("Missing ") else {
            continue;
        };
        let key: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if is_key(&key) && rest[key.len()..].starts_with(" config") {
            out.insert(key);
        }
    }
    out
}

pub fn schema_mismatch(schema: &serde_json::Value, source: &str) -> Vec<String> {
    let KeysRead { typed, keys: read } = keys_read(source);
    let props = schema
        .get("properties")
        .and_then(serde_json::Value::as_object);
    let declared: BTreeSet<String> = props
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default();
    let mut problems = Vec::new();
    for key in read.iter().filter(|k| !declared.contains(*k)) {
        problems.push(format!("its source reads the config key {key}, which `config_schema` does not declare: add it, with a description"));
    }
    for (key, spec) in props.into_iter().flatten() {
        if read.contains(key)
            && !spec
                .get("description")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|d| !d.trim().is_empty())
        {
            problems.push(format!(
                "`config_schema` declares {key} without a description: say what it does"
            ));
        }
    }
    if typed {
        for key in declared.iter().filter(|k| !read.contains(*k)) {
            problems.push(format!("`config_schema` declares {key}, which its source never reads: remove it, or read it"));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(keys: &[(&str, &str)]) -> serde_json::Value {
        let props: serde_json::Map<String, serde_json::Value> = keys
            .iter()
            .map(|(k, d)| {
                (
                    (*k).to_string(),
                    serde_json::json!({"type": "string", "description": d}),
                )
            })
            .collect();
        serde_json::json!({"type": "object", "properties": props})
    }

    const TYPED: &str = "#[derive(Deserialize)]\nstruct Config {\n    #[serde(rename = \"PROJECT\")]\n    project: Option<String>,\n    #[serde(rename=\"LIMIT\")]\n    limit: Option<u32>,\n}\n";

    #[test]
    fn the_rules_refuse_what_they_are_for() {
        assert!(schema_mismatch(&schema(&[("PROJECT", "p"), ("LIMIT", "l")]), TYPED).is_empty());
        // Read, not declared.
        let p = schema_mismatch(&schema(&[("PROJECT", "p")]), TYPED);
        assert!(
            p.len() == 1 && p[0].contains("LIMIT") && p[0].contains("does not declare"),
            "{p:?}"
        );
        // Declared, never read (a typed struct exists).
        let p = schema_mismatch(
            &schema(&[("PROJECT", "p"), ("LIMIT", "l"), ("SPARE", "s")]),
            TYPED,
        );
        assert!(
            p.len() == 1 && p[0].contains("SPARE") && p[0].contains("never reads"),
            "{p:?}"
        );
        // Declared without a description.
        let p = schema_mismatch(&schema(&[("PROJECT", " "), ("LIMIT", "l")]), TYPED);
        assert!(
            p.len() == 1 && p[0].contains("PROJECT") && p[0].contains("description"),
            "{p:?}"
        );
        // A lookup is read too; with no typed struct, an extra declared key is not judged.
        let looked = "let a = config.get(\"TOPIC\"); let b = cfg[\"SERVER_URL\"]; let c = other.get(\"NOT_CONFIG\");";
        assert!(schema_mismatch(
            &schema(&[("TOPIC", "t"), ("SERVER_URL", "s"), ("EXTRA", "e")]),
            looked
        )
        .is_empty());
        let p = schema_mismatch(&schema(&[("TOPIC", "t")]), looked);
        assert!(p.len() == 1 && p[0].contains("SERVER_URL"), "{p:?}");
        // Comments and tests are not the module; a struct that is not a config is not read.
        let noise = "// config.get(\"IN_COMMENT\")\nstruct Item {\n    #[serde(rename = \"NOT_CONFIG\")]\n    x: u8,\n}\n#[cfg(test)]\nmod tests { fn t() { config.get(\"IN_TEST\"); } }";
        assert!(schema_mismatch(&schema(&[]), noise).is_empty());
    }

    #[test]
    fn the_keys_read_say_whether_they_are_the_whole_set() {
        let typed = keys_read(TYPED);
        assert!(typed.typed);
        assert_eq!(
            typed.keys.iter().cloned().collect::<Vec<_>>(),
            ["LIMIT", "PROJECT"]
        );
        let looked = keys_read("let a = config.get(\"TOPIC\");");
        assert!(!looked.typed);
        assert_eq!(looked.keys.iter().cloned().collect::<Vec<_>>(), ["TOPIC"]);
        // A key is UPPER_CASE; a lower-case lookup is a field, not a setting.
        assert!(keys_read("let a = config.get(\"items\");").keys.is_empty());
        // A struct named for the envelope, not the config, is not one.
        assert!(!keys_read("struct Envelope { #[serde(rename = \"KEY\")] k: u8 }").typed);
        // A tuple struct named Config reads nothing.
        assert!(!keys_read("struct Config(u8); struct ConfigUnit;").typed);
    }

    #[test]
    fn a_required_key_is_the_one_a_missing_config_message_names() {
        let src = "let a = cfg.site.ok_or(\"Missing SITE_URL config\")?;\nlet b = cfg.k.ok_or(\"Missing KEY config (the Atlassian site)\")?;\nlet c = x.ok_or(\"Missing value\")?;\n// ok_or(\"Missing IN_COMMENT config\")\n#[cfg(test)] mod t { fn f() { ok_or(\"Missing IN_TEST config\"); } }";
        let keys = required_keys(src);
        assert_eq!(
            keys.iter().map(String::as_str).collect::<Vec<_>>(),
            ["KEY", "SITE_URL"]
        );
    }
}
