//! HTML-entity repair for caller-supplied Rust source, applied ONLY where it
//! cannot corrupt the program.
//!
//! # Why this exists
//!
//! Some MCP clients HTML-encode source before sending it, because they
//! misinterpret `serde_json`'s `<` escapes in a prior response. The
//! common case is angle brackets in generics: `HashMap<K, V>` arrives as
//! `HashMap&lt;K, V&gt;`, which is not valid Rust and fails to compile with a
//! message that says nothing about encoding. Repairing that is a real
//! convenience.
//!
//! # Why the obvious repair is wrong
//!
//! The pre-existing repair was a bare `.replace("&lt;", "<")` chain over the
//! WHOLE source. That is lossy and silent: a Rust string literal may
//! legitimately contain `&amp;`, and rewriting it to `&` changes what the
//! compiled module DOES rather than whether it compiles.
//!
//! The worst case is not hypothetical and not obscure. The function most
//! likely to contain those literals is an HTML escaper:
//!
//! ```ignore
//! '&' => out.push_str("&amp;"),   // becomes out.push_str("&")
//! '<' => out.push_str("&lt;"),    // becomes out.push_str("<")
//! ```
//!
//! Both rewritten forms are valid Rust, so the module compiles and every
//! "does it build" check passes — while the escaper has become a no-op that
//! emits the character it was supposed to neutralise. A module escaping
//! caller-influenced text into an operator's console or mail client would
//! silently stop doing so. `&#39;` is the only member of the set whose
//! rewrite tends to fail the build (it can unbalance a char literal), which
//! is luck rather than a guard.
//!
//! # The rule
//!
//! Decode in CODE regions; never inside a string literal, a char literal, or
//! a comment. Inside those, the bytes are the author's and are left exactly
//! as received. Outside them an HTML entity is not valid Rust anyway, so a
//! decode there can only ever repair client damage.
//!
//! Comments are treated as author bytes too: a doc comment explaining
//! `&amp;` must keep saying `&amp;`.

use std::borrow::Cow;

/// The six entities the historical repair chain handled.
///
/// This set is PREFIX-FREE — no member is a prefix of another — which is what
/// makes a first-match scan correct regardless of the order they appear in
/// here. An earlier revision of this comment claimed the longest-first
/// ordering was load-bearing; it is not, and reordering the table survives
/// every test, so the claim was unprovable. The property that IS load-bearing
/// is pinned by `the_entity_set_is_prefix_free`: add an entity that is a
/// prefix of another (or vice versa) and the scan would silently decode the
/// shorter one and leave the remainder as text.
const ENTITIES: &[(&str, char)] = &[
    ("&quot;", '"'),
    ("&apos;", '\''),
    ("&#39;", '\''),
    ("&amp;", '&'),
    ("&lt;", '<'),
    ("&gt;", '>'),
];

/// Outcome of a decode pass. `decoded` counts repairs actually made;
/// `preserved_in_literal` counts entity sequences left untouched because they
/// sat inside a literal or a comment — the number the old chain would have
/// corrupted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDecode<'a> {
    pub source: Cow<'a, str>,
    pub decoded: usize,
    pub preserved_in_literal: usize,
}

impl SourceDecode<'_> {
    /// True when the repair changed the source the caller sent.
    #[must_use]
    pub fn changed(&self) -> bool {
        self.decoded > 0
    }

    /// A one-line, caller-facing note, or `None` when nothing is worth
    /// saying. Reported so a repair is never invisible: a caller whose client
    /// mangles source should be able to see that it happened, and a caller
    /// whose literals were preserved should be able to see that too.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        match (self.decoded, self.preserved_in_literal) {
            (0, 0) => None,
            (0, p) => Some(format!(
                "{p} HTML entity sequence(s) were left as written because they sit inside a string, char literal or comment"
            )),
            (d, 0) => Some(format!(
                "repaired {d} HTML entity sequence(s) in code (your client appears to HTML-encode source)"
            )),
            (d, p) => Some(format!(
                "repaired {d} HTML entity sequence(s) in code; left {p} as written inside a string, char literal or comment"
            )),
        }
    }
}

/// Byte offset regions of `src` that are author bytes (string literal, char
/// literal, or comment) and must never be rewritten.
///
/// A single forward scan. Handles line comments, block comments (nested, as
/// rustc does), plain and byte strings with backslash escapes, raw and raw
/// byte strings with any hash count, and char literals.
///
/// Char literals are tracked for ONE reason: a `'"'` literal would otherwise
/// open a phantom string and desynchronise the rest of the scan. An entity
/// cannot fit in a char literal, so nothing is decoded there either way. A
/// lifetime (`&'a str`) is not a literal and is correctly not treated as one,
/// because the closing quote never arrives within the lookahead.
fn protected_regions(src: &str) -> Vec<(usize, usize)> {
    let b = src.as_bytes();
    let n = b.len();
    let mut out: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;

    while i < n {
        // Line comment
        if b[i] == b'/' && i + 1 < n && b[i + 1] == b'/' {
            let start = i;
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            out.push((start, i));
            continue;
        }
        // Block comment, nested
        if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
            let start = i;
            let mut depth = 1usize;
            i += 2;
            while i < n && depth > 0 {
                if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            out.push((start, i));
            continue;
        }
        // Raw string: r"..." / r#"..."# / br"..." / br#"..."#
        if b[i] == b'r' || (b[i] == b'b' && i + 1 < n && b[i + 1] == b'r') {
            let mut j = if b[i] == b'b' { i + 2 } else { i + 1 };
            let hash_start = j;
            while j < n && b[j] == b'#' {
                j += 1;
            }
            let hashes = j - hash_start;
            if j < n && b[j] == b'"' {
                let start = i;
                j += 1;
                // Closing is `"` followed by exactly `hashes` `#`.
                loop {
                    if j >= n {
                        break;
                    }
                    if b[j] == b'"' {
                        let mut k = j + 1;
                        let mut seen = 0usize;
                        while k < n && seen < hashes && b[k] == b'#' {
                            k += 1;
                            seen += 1;
                        }
                        if seen == hashes {
                            j = k;
                            break;
                        }
                    }
                    j += 1;
                }
                out.push((start, j));
                i = j;
                continue;
            }
        }
        // Plain or byte string
        if b[i] == b'"' || (b[i] == b'b' && i + 1 < n && b[i + 1] == b'"') {
            let start = i;
            let mut j = if b[i] == b'b' { i + 2 } else { i + 1 };
            while j < n {
                if b[j] == b'\\' {
                    j += 2;
                    continue;
                }
                if b[j] == b'"' {
                    j += 1;
                    break;
                }
                j += 1;
            }
            out.push((start, j));
            i = j;
            continue;
        }
        // Char literal (or a lifetime, which we deliberately do not consume).
        if b[i] == b'\'' {
            let mut j = i + 1;
            if j < n && b[j] == b'\\' {
                j += 2;
                // Escapes may be long: '\u{1F600}'
                while j < n && b[j] != b'\'' && b[j] != b'\n' && j - i < 12 {
                    j += 1;
                }
            } else {
                // One char, which may be multi-byte UTF-8.
                while j < n && (b[j] & 0xC0) == 0x80 {
                    j += 1;
                }
                j += 1;
            }
            if j < n && b[j] == b'\'' {
                out.push((i, j + 1));
                i = j + 1;
                continue;
            }
            // No closing quote in range: a lifetime. Step over the tick only.
            i += 1;
            continue;
        }
        i += 1;
    }

    out
}

#[inline]
fn in_protected(regions: &[(usize, usize)], pos: usize) -> bool {
    regions
        .binary_search_by(|&(s, e)| {
            if pos < s {
                std::cmp::Ordering::Greater
            } else if pos >= e {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Repair HTML entities in caller-supplied Rust source, outside literals and
/// comments only.
///
/// Returns the source borrowed and unchanged when there is nothing to repair,
/// so the common path allocates nothing.
#[must_use]
pub fn decode_entities_outside_literals(src: &str) -> SourceDecode<'_> {
    // Cheap bail: no entity marker at all.
    if !src.contains('&') {
        return SourceDecode {
            source: Cow::Borrowed(src),
            decoded: 0,
            preserved_in_literal: 0,
        };
    }

    let regions = protected_regions(src);
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut decoded = 0usize;
    let mut preserved = 0usize;
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some((pat, ch)) = ENTITIES
                .iter()
                .find(|(p, _)| src[i..].starts_with(*p))
                .copied()
            {
                if in_protected(&regions, i) {
                    preserved += 1;
                    out.push_str(pat);
                } else {
                    decoded += 1;
                    out.push(ch);
                }
                i += pat.len();
                continue;
            }
        }
        // Copy one UTF-8 character.
        let start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
            i += 1;
        }
        out.push_str(&src[start..i]);
    }

    if decoded == 0 {
        return SourceDecode {
            source: Cow::Borrowed(src),
            decoded: 0,
            preserved_in_literal: preserved,
        };
    }

    SourceDecode {
        source: Cow::Owned(out),
        decoded,
        preserved_in_literal: preserved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repairs_encoded_generics_in_code() {
        let src = "fn f(m: HashMap&lt;K, V&gt;) -> bool { a &amp;&amp; b }";
        let d = decode_entities_outside_literals(src);
        assert_eq!(d.source, "fn f(m: HashMap<K, V>) -> bool { a && b }");
        // &lt; &gt; and two &amp; = four repairs.
        assert_eq!(d.decoded, 4);
        assert_eq!(d.preserved_in_literal, 0);
        assert!(d.changed());
    }

    /// THE regression this module exists for. An HTML escaper written the
    /// obvious way must survive byte-for-byte: the old chain rewrote every
    /// one of these to the bare character, leaving a no-op escaper that still
    /// compiled.
    #[test]
    fn an_html_escaper_survives_byte_for_byte() {
        let src = r#"
fn esc(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}
"#;
        let d = decode_entities_outside_literals(src);
        assert_eq!(d.source, src, "escaper literals must not be rewritten");
        assert_eq!(d.decoded, 0);
        assert_eq!(d.preserved_in_literal, 4);
        assert!(!d.changed());
    }

    #[test]
    fn raw_strings_are_preserved_at_every_hash_count() {
        let src = r####"
let a = r"&amp;";
let b = r#"&lt;tag&gt;"#;
let c = r##"&quot;x&quot;"##;
"####;
        let d = decode_entities_outside_literals(src);
        assert_eq!(d.source, src);
        assert_eq!(d.decoded, 0);
        assert_eq!(d.preserved_in_literal, 5);
    }

    #[test]
    fn comments_keep_their_bytes() {
        let src = "// use &amp; here\n/* and &lt; here */\nlet x = 1;";
        let d = decode_entities_outside_literals(src);
        assert_eq!(d.source, src);
        assert_eq!(d.decoded, 0);
        assert_eq!(d.preserved_in_literal, 2);
    }

    #[test]
    fn nested_block_comments_do_not_leak() {
        let src = "/* outer /* inner &amp; */ still comment &lt; */ let a = b &amp;&amp; c;";
        let d = decode_entities_outside_literals(src);
        assert!(d
            .source
            .contains("/* outer /* inner &amp; */ still comment &lt; */"));
        assert!(d.source.ends_with("let a = b && c;"));
        assert_eq!(d.decoded, 2);
        assert_eq!(d.preserved_in_literal, 2);
    }

    /// A `'"'` char literal must not open a phantom string. Without char
    /// handling the scanner desynchronises and the rest of the file is
    /// treated as one long literal — so the generic below would go unrepaired.
    #[test]
    fn a_quote_char_literal_does_not_desynchronise_the_scan() {
        let src = r#"let q = '"'; let m: Vec&lt;u8&gt; = vec![];"#;
        let d = decode_entities_outside_literals(src);
        assert_eq!(d.source, r#"let q = '"'; let m: Vec<u8> = vec![];"#);
        assert_eq!(d.decoded, 2);
    }

    #[test]
    fn a_lifetime_is_not_a_char_literal() {
        let src = "fn f&lt;'a&gt;(s: &amp;'a str) -> &amp;'a str { s }";
        let d = decode_entities_outside_literals(src);
        assert_eq!(d.source, "fn f<'a>(s: &'a str) -> &'a str { s }");
        assert_eq!(d.decoded, 4);
        assert_eq!(d.preserved_in_literal, 0);
    }

    #[test]
    fn escaped_quote_inside_a_string_does_not_end_it() {
        let src = r#"let s = "a \" &amp; b"; let t: Vec&lt;u8&gt; = vec![];"#;
        let d = decode_entities_outside_literals(src);
        assert!(d.source.contains(r#""a \" &amp; b""#));
        assert!(d.source.contains("Vec<u8>"));
        assert_eq!(d.decoded, 2);
        assert_eq!(d.preserved_in_literal, 1);
    }

    #[test]
    fn clean_source_is_borrowed_and_unchanged() {
        let src = "fn main() { println!(\"hello\"); }";
        let d = decode_entities_outside_literals(src);
        assert!(matches!(d.source, Cow::Borrowed(_)));
        assert_eq!(d.decoded, 0);
        assert_eq!(d.preserved_in_literal, 0);
        assert_eq!(d.note(), None);
    }

    #[test]
    fn entities_sharing_a_prefix_are_each_decoded_whole() {
        // `&amp;` and `&apos;` share `&a` without either being a prefix of
        // the other; both must decode to their own character.
        let src = "let x = a &amp; b; let y = c &apos; d;";
        let d = decode_entities_outside_literals(src);
        assert_eq!(d.source, "let x = a & b; let y = c ' d;");
        assert_eq!(d.decoded, 2);
    }

    /// The invariant the first-match scan actually rests on. If a future
    /// entity is added that is a prefix of an existing one, a first match on
    /// the shorter would decode it and leave the remainder as stray text —
    /// silently, in the caller's source. Reordering the table cannot fix
    /// that; only keeping the set prefix-free can.
    #[test]
    fn the_entity_set_is_prefix_free() {
        for (i, (a, _)) in ENTITIES.iter().enumerate() {
            for (j, (b, _)) in ENTITIES.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    !a.starts_with(b),
                    "entity {a:?} has {b:?} as a prefix — a first-match scan would decode \
                     {b:?} and leave the rest of {a:?} as stray text in the caller's source"
                );
            }
        }
    }

    #[test]
    fn the_note_states_both_halves() {
        let src = "let a = b &amp;&amp; c; let s = \"&lt;\";";
        let d = decode_entities_outside_literals(src);
        let note = d.note().expect("a repair and a preserve must be reported");
        assert!(note.contains("repaired 2"));
        assert!(note.contains("left 1"));
    }

    #[test]
    fn byte_strings_are_preserved() {
        let src = r##"let a = b"&amp;"; let b = br#"&lt;"#; let c: Vec&lt;u8&gt; = vec![];"##;
        let d = decode_entities_outside_literals(src);
        assert!(d.source.contains(r#"b"&amp;""#));
        assert!(d.source.contains(r##"br#"&lt;"#"##));
        assert!(d.source.contains("Vec<u8>"));
        assert_eq!(d.decoded, 2);
        assert_eq!(d.preserved_in_literal, 2);
    }

    #[test]
    fn multibyte_source_is_not_split() {
        let src = "let s = \"— ünïcode &amp; more\"; let v: Vec&lt;u8&gt; = vec![];";
        let d = decode_entities_outside_literals(src);
        assert!(d.source.contains("— ünïcode &amp; more"));
        assert!(d.source.contains("Vec<u8>"));
        assert_eq!(d.decoded, 2);
        assert_eq!(d.preserved_in_literal, 1);
    }
}
