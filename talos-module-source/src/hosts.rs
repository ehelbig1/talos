//! A module's granted hosts are the hosts its source addresses, no more and
//! no fewer.
//!
//! `allowed_hosts` is written by hand in a manifest, apart from the code
//! that makes the requests, so the two drift. Both directions cost:
//!
//! * **called, not granted** — the worker refuses the request
//!   (`forbiddenhost`) and the part the module wanted is "unread" on every
//!   run. `gcp-binauthz-evidence` shipped in the authoring lane granting two of
//!   the four hosts its source calls (found 2026-10-16).
//! * **granted, not called** — a grant nothing uses is reach the module has
//!   for no reason: the least-privilege rule, broken quietly.
//!
//! So, over the module's source before its `#[cfg(test)]` module, string
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
//! A `*` grant is narrowed by the installer and is not judged here.
//!
//! This guards least privilege, so its rules are mutation-tested: each
//! clause of [`mismatch`] fails [`tests::the_rules_refuse_what_they_are_for`]
//! when it is turned off.

use crate::literals::{before_tests, literals};
use std::collections::BTreeSet;

/// Worlds a module can make an HTTP request from.
pub const NETWORK_WORLDS: &[&str] = &[
    "http-node",
    "network-node",
    "secrets-node",
    "agent-node",
    "messaging-node",
    "automation-node",
    "governance-node",
    "database-node",
];

/// What a line says when the URL on it is data and never fetched.
pub const MARKER: &str = "host-not-requested:";

/// Hosts a literal addresses with a scheme, lower-cased.
#[must_use]
pub fn addressed(text: &str) -> Vec<String> {
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
#[must_use]
pub fn names(text: &str, host: &str) -> bool {
    let is_host_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '.';
    text.match_indices(host).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + host.len()..].chars().next();
        before.is_none_or(|c| !is_host_char(c))
            && after.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-'))
    })
}

/// The hosts a module's source addresses with a scheme (rule 1's population),
/// sorted, without the ones whose line carries [`MARKER`]. Tests are not the
/// module, and comments are not code.
#[must_use]
pub fn addressed_in_source(source: &str) -> BTreeSet<String> {
    let code = before_tests(source);
    let lines: Vec<&str> = code.lines().collect();
    let mut out = BTreeSet::new();
    for (line, text) in literals(code) {
        let marked = lines.get(line - 1).is_some_and(|l| l.contains(MARKER));
        if marked {
            continue;
        }
        out.extend(addressed(&text));
    }
    out
}

/// What is wrong with one module's grant, if anything: a sentence per
/// problem, for a person.
#[must_use]
pub fn mismatch(world: &str, granted: &[String], source: &str) -> Vec<String> {
    let code = before_tests(source);
    let lits = literals(code);
    let mut problems = Vec::new();
    let star = granted.iter().any(|h| h == "*");
    if NETWORK_WORLDS.contains(&world) && !star {
        for host in addressed_in_source(source) {
            if !granted.iter().any(|g| g.eq_ignore_ascii_case(&host)) {
                problems.push(format!(
                    "its source addresses https://{host} but `allowed_hosts` does not grant it: the worker will refuse the request. Grant it, or if the URL is data and never fetched, end its line with `// {MARKER} <why>`"
                ));
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn g(hs: &[&str]) -> Vec<String> {
        hs.iter().map(|h| (*h).to_string()).collect()
    }

    #[test]
    fn the_rules_refuse_what_they_are_for() {
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
        // A quoted URL in a comment is not a call (the case one mutation of
        // the comment handling survived until it was added).
        assert!(mismatch(
            "http-node",
            &g(&[]),
            "// let u = \"https://only.in.a.comment.example\";"
        )
        .is_empty());
        // The marker on a line applies to every literal on it, and to no other line.
        let two_lines = "let a = \"https://data.example.com\"; // host-not-requested: a link\nlet b = \"https://call.example.com\";";
        let p = mismatch("http-node", &g(&[]), two_lines);
        assert!(p.len() == 1 && p[0].contains("call.example.com"), "{p:?}");
    }

    #[test]
    fn the_addressed_population_is_what_rule_one_judges() {
        let src = "let a = \"https://a.example\"; let b = \"http://B.example/x\"; // host-not-requested: data\nlet c = \"https://c.example\"; let d = \"c.example\";\n#[cfg(test)] const T: &str = \"https://t.example\";";
        assert_eq!(
            addressed_in_source(src).into_iter().collect::<Vec<_>>(),
            ["c.example"]
        );
    }

    #[test]
    fn a_host_is_named_whole_or_not_at_all() {
        assert!(names("x https://api.example.com/v1 y", "api.example.com"));
        assert!(names("api.example.com", "api.example.com"));
        // A sub-domain does not name its parent.
        assert!(!names("https://api.example.com", "example.com"));
        assert!(!names("notexample.com", "example.com"));
        assert!(!names("example.community", "example.com"));
        assert!(names("https://example.com:443/x", "example.com"));
    }
}
