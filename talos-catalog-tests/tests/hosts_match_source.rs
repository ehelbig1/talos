//! A template's granted hosts are the hosts its source addresses, no more and
//! no fewer.
//!
//! `allowed_hosts` is written by hand in `talos.json`, apart from the code
//! that makes the requests, so the two drift. Both directions cost:
//!
//! * **called, not granted** — the worker refuses the request
//!   (`forbiddenhost`) and the part the module wanted is "unread" on every
//!   run. `gcp-binauthz-evidence` shipped in the authoring lane granting two of
//!   the four hosts its source calls (found 2026-10-16).
//! * **granted, not called** — a grant nothing uses is reach the module has
//!   for no reason: the least-privilege rule, broken quietly.
//!
//! So, over each template's source before its `#[cfg(test)]` module, string
//! literals only (comments are not code):
//!
//! 1. in a network world, every host a literal addresses as `http(s)://host`
//!    is in `allowed_hosts`, unless the literal's line says
//!    `// host-not-requested: <why>` (a URL kept as data — a link for a person,
//!    a JSON-LD context — and never fetched);
//! 2. every granted host other than `*` is named in some string literal, with
//!    or without a scheme (`"sandbox.plaid.com"` counts: the URL is built from
//!    it).
//!
//! A `*` grant is narrowed by the installer and is not judged here. Templates
//! that were written before this gate and do not meet it are listed in
//! `PREDATING`, which only shrinks.

use std::collections::BTreeSet;

/// Worlds a module can make an HTTP request from.
const NETWORK_WORLDS: &[&str] = &[
    "http-node",
    "network-node",
    "secrets-node",
    "agent-node",
    "messaging-node",
    "automation-node",
    "governance-node",
    "database-node",
];

/// Templates that grant hosts their source never names (measured 2026-10-16).
/// Each is a least-privilege gap to close: narrow its grant, then take it off.
const PREDATING: &[&str] = &[
    "create-calendar-event",
    "google-calendar-webhook",
    "google-mail-webhook",
    "send-gmail",
    "send-slack-message",
    "slack-webhook-listener",
];

const MARKER: &str = "host-not-requested:";

/// The contents of every string literal in `src`, with the line each starts
/// on. Line and block comments (nested), char literals and lifetimes are
/// skipped; raw strings (`r"…"`, `r#"…"#`) and byte strings are read whole.
fn literals(src: &str) -> Vec<(usize, String)> {
    let b = src.as_bytes();
    let (mut i, mut line, mut out) = (0usize, 1usize, Vec::new());
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    while i < b.len() {
        match b[i] {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 0usize;
                while i < b.len() {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        if b[i] == b'\n' {
                            line += 1;
                        }
                        i += 1;
                    }
                }
            }
            b'r' | b'b' if i == 0 || !ident(b[i - 1]) => {
                // r"…", r#"…"#, br"…", b"…"
                let mut j = i + 1;
                if b[i] == b'b' && b.get(j) == Some(&b'r') {
                    j += 1;
                }
                let raw = b[i] == b'r' || b.get(i + 1) == Some(&b'r');
                let hashes = b[j..].iter().take_while(|&&c| c == b'#').count();
                if raw && b.get(j + hashes) == Some(&b'"') {
                    let start = j + hashes + 1;
                    let close = format!("\"{}", "#".repeat(hashes));
                    let end = src[start..].find(&close).map_or(b.len(), |e| start + e);
                    out.push((line, src[start..end].to_string()));
                    line += src[start..end].matches('\n').count();
                    i = (end + close.len()).min(b.len());
                } else if !raw && b[i] == b'b' && b.get(i + 1) == Some(&b'"') {
                    i += 1; // the quote is read as an ordinary string next
                } else {
                    i += 1;
                }
            }
            b'"' => {
                let (start_line, mut j, mut text) = (line, i + 1, String::new());
                while j < b.len() && b[j] != b'"' {
                    if b[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if b[j] == b'\n' {
                        line += 1;
                    }
                    // Literals are UTF-8 source; push by char boundary.
                    let ch = src[j..].chars().next().unwrap_or(' ');
                    text.push(ch);
                    j += ch.len_utf8();
                }
                out.push((start_line, text));
                i = j + 1;
            }
            b'\'' => {
                // A char literal ('x', '\n', '\''); otherwise a lifetime.
                let rest = &src[i + 1..];
                let mut chars = rest.chars();
                match (chars.next(), chars.next()) {
                    (Some('\\'), _) => i += 1 + rest[1..].find('\'').map_or(1, |e| e + 2),
                    (Some(c), Some('\'')) => i += 2 + c.len_utf8(),
                    _ => i += 1,
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Hosts a literal addresses with a scheme, lower-cased.
fn addressed(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for scheme in ["https://", "http://"] {
        let mut rest = text;
        while let Some(at) = rest.find(scheme) {
            let after = &rest[at + scheme.len()..];
            let host: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                .collect();
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            if !host.is_empty() {
                out.push(host);
            }
            rest = after;
        }
    }
    out
}

/// Whether `host` appears in `text` as a whole host, not inside a longer one.
fn names(text: &str, host: &str) -> bool {
    let is_host_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '.';
    text.match_indices(host).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + host.len()..].chars().next();
        before.is_none_or(|c| !is_host_char(c))
            && after.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-'))
    })
}

/// What is wrong with one template's grant, if anything.
fn mismatch(world: &str, granted: &[String], source: &str) -> Vec<String> {
    let code = source.split("#[cfg(test)]").next().unwrap_or(source);
    let lines: Vec<&str> = code.lines().collect();
    let lits = literals(code);
    let mut problems = Vec::new();
    let star = granted.iter().any(|h| h == "*");
    if NETWORK_WORLDS.contains(&world) && !star {
        let mut missing = BTreeSet::new();
        for (line, text) in &lits {
            let marked = lines.get(line - 1).is_some_and(|l| l.contains(MARKER));
            for host in addressed(text) {
                if !marked && !granted.iter().any(|g| g.eq_ignore_ascii_case(&host)) {
                    missing.insert(host);
                }
            }
        }
        for host in missing {
            problems.push(format!(
                "its source addresses https://{host} but `allowed_hosts` does not grant it: the worker will refuse the request. Grant it, or if the URL is data and never fetched, end its line with `// {MARKER} <why>`"
            ));
        }
    }
    for host in granted.iter().filter(|h| *h != "*") {
        if !lits
            .iter()
            .any(|(_, text)| names(text, &host.to_ascii_lowercase()))
        {
            problems.push(format!(
                "`allowed_hosts` grants {host}, which its source never names: a grant nothing uses. Remove it"
            ));
        }
    }
    problems
}

fn templates() -> Vec<(String, String, Vec<String>, String)> {
    let mut out = Vec::new();
    for dir in talos_catalog_tests::template_dirs() {
        let (Ok(manifest), Ok(source)) = (
            std::fs::read_to_string(dir.join("talos.json")),
            std::fs::read_to_string(dir.join("template.rs")),
        ) else {
            continue;
        };
        let m: serde_json::Value =
            serde_json::from_str(&manifest).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        let world = m["capability_world"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let granted = m["allowed_hosts"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|h| h.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        out.push((
            dir.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            world,
            granted,
            source,
        ));
    }
    out.sort();
    out
}

#[test]
fn every_template_grants_the_hosts_its_source_addresses_and_no_others() {
    let all = templates();
    assert!(all.len() > 50, "found only {} templates", all.len());
    let mut wrong = Vec::new();
    for (slug, world, granted, source) in &all {
        let problems = mismatch(world, granted, source);
        if PREDATING.contains(&slug.as_str()) {
            assert!(
                !problems.is_empty(),
                "{slug} meets the gate now: take it off PREDATING"
            );
            continue;
        }
        wrong.extend(problems.into_iter().map(|p| format!("{slug}: {p}")));
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    for slug in PREDATING {
        assert!(
            all.iter().any(|(s, ..)| s == slug),
            "{slug} is on PREDATING and is not a template any more"
        );
    }
}

#[test]
fn the_rules_refuse_what_they_are_for() {
    let g = |hs: &[&str]| hs.iter().map(|h| (*h).to_string()).collect::<Vec<_>>();
    // Called and granted, both ways: nothing to say.
    assert!(mismatch(
        "http-node",
        &g(&["api.example.com"]),
        r#"const API: &str = "https://api.example.com/v1";"#
    )
    .is_empty());
    // Called, not granted.
    let p = mismatch(
        "http-node",
        &g(&["api.example.com"]),
        r#"let u = "https://other.example.com/x"; let a = "https://api.example.com";"#,
    );
    assert!(
        p.len() == 1 && p[0].contains("other.example.com") && p[0].contains("refuse"),
        "{p:?}"
    );
    // Granted, not named anywhere.
    let p = mismatch(
        "http-node",
        &g(&["api.example.com", "spare.example.com"]),
        r#"let u = "https://api.example.com";"#,
    );
    assert!(p.len() == 1 && p[0].contains("spare.example.com"), "{p:?}");
    // A host named without a scheme counts as used: the URL is built from it.
    assert!(mismatch(
        "http-node",
        &g(&["sandbox.example.com"]),
        r#"let h = "sandbox.example.com"; let u = format!("https://{h}/x");"#
    )
    .is_empty());
    // A longer host does not name a shorter one.
    assert_eq!(
        mismatch(
            "http-node",
            &g(&["example.com"]),
            r#"let u = "https://api.example.com.evil.test";"#
        )
        .len(),
        2
    );
    // Comments are not code: a URL in one is neither a call nor a use.
    assert_eq!(mismatch("http-node", &g(&["api.example.com"]), "// see \"https://api.example.com\"\n/* \"https://x.example\" */"), vec![
        "`allowed_hosts` grants api.example.com, which its source never names: a grant nothing uses. Remove it".to_string()
    ]);
    // A URL kept as data says so on its line.
    let marked = r#"let a = "https://api.example.com"; let link = "https://example.org/page"; // host-not-requested: a link for the reader"#;
    assert!(mismatch("http-node", &g(&["api.example.com"]), marked).is_empty());
    // A decider calls nothing: a documentation link is not a request.
    assert!(mismatch(
        "minimal-node",
        &g(&[]),
        r#"let source = "https://docs.example.com/guide";"#
    )
    .is_empty());
    // `*` is the installer's to narrow.
    assert!(mismatch(
        "http-node",
        &g(&["*"]),
        r#"let u = "https://anything.example.com";"#
    )
    .is_empty());
    // The tests are not the module.
    assert!(mismatch("http-node", &g(&["api.example.com"]), "const A: &str = \"https://api.example.com\";\n#[cfg(test)]\nmod tests { const X: &str = \"https://fixture.example.com\"; }").is_empty());
    // Raw strings, escaped quotes, char literals and lifetimes are read correctly.
    let tricky = "fn f<'a>(s: &'a str) -> char { let _q = '\"'; let _r = r#\"https://raw.example.com\"#; let _e = \"say \\\"https://esc.example.com\\\"\"; 'x' }";
    let p = mismatch("http-node", &g(&[]), tricky);
    assert!(
        p.iter().any(|m| m.contains("raw.example.com"))
            && p.iter().any(|m| m.contains("esc.example.com")),
        "{p:?}"
    );
}
