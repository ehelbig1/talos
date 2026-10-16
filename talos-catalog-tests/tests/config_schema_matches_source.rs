//! A template's `config_schema` names the config keys its source reads, and
//! describes each.
//!
//! The schema is what an installer reads to configure a node, and it is
//! written by hand apart from the code, so it drifts: a key renamed in the
//! source and not in the schema is a node configured with a key nothing reads
//! (`create-calendar-event` declares `TITLE`; its source reads `SUMMARY`).
//!
//! Over the source before its `#[cfg(test)]` module, comments removed:
//!
//! 1. every key the source reads is a property of `config_schema`, with a
//!    non-empty `description`. A key is read by a field
//!    `#[serde(rename = "KEY")]` of a struct whose name contains `Config`, or
//!    by `config.get("KEY")` / `cfg["KEY"]` (a value named `config…`, `cfg…`
//!    or `conf…`);
//! 2. where the module has such a typed config struct (the shape
//!    `make new-template` writes), every declared property is read: a
//!    property nothing reads is a setting that does nothing.
//!
//! Templates written before this gate that do not meet it are listed in
//! `PREDATING`, which only shrinks.

use std::collections::BTreeSet;

/// Measured 2026-10-16. Each is a schema that says something the module does not do.
const PREDATING: &[&str] = &[
    "create-calendar-event",
    "gcp-run-job-execute",
    "google-calendar-webhook",
    "google-mail-webhook",
    "send-gmail",
    "slack-webhook-listener",
];

/// The source with `//` and `/* */` comments blanked, string literals kept.
fn without_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let start = i;
            i += 1;
            while i < b.len() && b[i] != b'"' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
            out.push_str(&src[start..i]);
        } else if src[i..].starts_with("//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if src[i..].starts_with("/*") {
            let end = src[i + 2..].find("*/").map_or(b.len(), |e| i + 2 + e + 2);
            i = end;
        } else {
            let ch = src[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn is_key(s: &str) -> bool {
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

/// The keys a typed config struct reads, and whether there is one.
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

/// The keys read by `config.get("KEY")` or `cfg["KEY"]`.
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

/// What is wrong with one template's schema, if anything.
fn mismatch(schema: &serde_json::Value, source: &str) -> Vec<String> {
    let code = without_comments(source.split("#[cfg(test)]").next().unwrap_or(source));
    let (typed, mut read) = struct_keys(&code);
    read.extend(lookup_keys(&code));
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

#[test]
fn every_template_declares_the_config_keys_its_source_reads() {
    let mut wrong = Vec::new();
    let mut read = 0;
    for dir in talos_catalog_tests::template_dirs() {
        let slug = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let (Ok(manifest), Ok(source)) = (
            std::fs::read_to_string(dir.join("talos.json")),
            std::fs::read_to_string(dir.join("template.rs")),
        ) else {
            continue;
        };
        read += 1;
        let m: serde_json::Value =
            serde_json::from_str(&manifest).unwrap_or_else(|e| panic!("{slug}: {e}"));
        let problems = mismatch(&m["config_schema"], &source);
        if PREDATING.contains(&slug.as_str()) {
            assert!(
                !problems.is_empty(),
                "{slug} meets the gate now: take it off PREDATING"
            );
            continue;
        }
        wrong.extend(problems.into_iter().map(|p| format!("{slug}: {p}")));
    }
    assert!(read > 50, "read only {read} templates");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_rules_refuse_what_they_are_for() {
    let schema = |keys: &[(&str, &str)]| {
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
    };
    let typed = "#[derive(Deserialize)]\nstruct Config {\n    #[serde(rename = \"PROJECT\")]\n    project: Option<String>,\n    #[serde(rename=\"LIMIT\")]\n    limit: Option<u32>,\n}\n";
    assert!(mismatch(&schema(&[("PROJECT", "p"), ("LIMIT", "l")]), typed).is_empty());
    // Read, not declared.
    let p = mismatch(&schema(&[("PROJECT", "p")]), typed);
    assert!(
        p.len() == 1 && p[0].contains("LIMIT") && p[0].contains("does not declare"),
        "{p:?}"
    );
    // Declared, never read (a typed struct exists).
    let p = mismatch(
        &schema(&[("PROJECT", "p"), ("LIMIT", "l"), ("SPARE", "s")]),
        typed,
    );
    assert!(
        p.len() == 1 && p[0].contains("SPARE") && p[0].contains("never reads"),
        "{p:?}"
    );
    // Declared without a description.
    let p = mismatch(&schema(&[("PROJECT", " "), ("LIMIT", "l")]), typed);
    assert!(
        p.len() == 1 && p[0].contains("PROJECT") && p[0].contains("description"),
        "{p:?}"
    );
    // A lookup is read too; with no typed struct, an extra declared key is not judged.
    let looked = "let a = config.get(\"TOPIC\"); let b = cfg[\"SERVER_URL\"]; let c = other.get(\"NOT_CONFIG\");";
    assert!(mismatch(
        &schema(&[("TOPIC", "t"), ("SERVER_URL", "s"), ("EXTRA", "e")]),
        looked
    )
    .is_empty());
    let p = mismatch(&schema(&[("TOPIC", "t")]), looked);
    assert!(p.len() == 1 && p[0].contains("SERVER_URL"), "{p:?}");
    // Comments and tests are not the module; a struct that is not a config is not read.
    let noise = "// config.get(\"IN_COMMENT\")\nstruct Item {\n    #[serde(rename = \"NOT_CONFIG\")]\n    x: u8,\n}\n#[cfg(test)]\nmod tests { fn t() { config.get(\"IN_TEST\"); } }";
    assert!(mismatch(&schema(&[]), noise).is_empty());
}
