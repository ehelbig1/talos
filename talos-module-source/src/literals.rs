//! The string literals of a Rust source, and the source without its comments.

/// The source before its `#[cfg(test)]` module: the module, not its tests.
#[must_use]
pub fn before_tests(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}

/// The contents of every string literal in `src`, with the line each starts
/// on. Line and block comments (nested), char literals and lifetimes are
/// skipped; raw strings (`r"…"`, `r#"…"#`) and byte strings are read whole.
/// An escape sequence in an ordinary string is dropped, not decoded (`\"`
/// leaves no quote behind): what is read is the hosts and keys a literal
/// carries, not its exact value.
#[must_use]
pub fn literals(src: &str) -> Vec<(usize, String)> {
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

/// The source with `//` and `/* */` comments blanked, string literals kept.
/// A blanked block comment keeps its line breaks, so a line of the result is
/// the same line of the source.
#[must_use]
pub fn without_comments(src: &str) -> String {
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
            out.extend(src[i..end].chars().filter(|&c| c == '\n'));
            i = end;
        } else {
            let ch = src[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Whether the module body (before its tests, comments out) holds a string
/// literal that is exactly `text`: the way a module declares a contract it
/// takes part in, such as the fields of a sender's verdict.
pub fn names_literal(source: &str, text: &str) -> bool {
    literals(&without_comments(before_tests(source)))
        .iter()
        .any(|(_, lit)| lit == text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_are_read_with_their_lines_and_comments_are_not_code() {
        let src = "let a = \"one\";\n// \"not\"\n/* \"nor\n this\" */ let b = \"two\";";
        assert_eq!(
            literals(src),
            vec![(1, "one".to_string()), (4, "two".to_string())]
        );
    }

    #[test]
    fn a_blanked_block_comment_keeps_its_line_breaks() {
        let src = "a /* one\n two\n three */ b\n// four\nc";
        assert_eq!(without_comments(src), "a \n\n b\n\nc");
    }

    #[test]
    fn raw_byte_escaped_and_char_forms_are_told_apart() {
        let src = "fn f<'a>(s: &'a str) -> char { let _q = '\"'; let _r = r#\"raw \"x\"\"#; let _b = b\"bytes\"; let _e = \"say \\\"hi\\\"\"; 'x' }";
        let texts: Vec<String> = literals(src).into_iter().map(|(_, t)| t).collect();
        assert_eq!(texts, ["raw \"x\"", "bytes", "say hi"]);
    }

    #[test]
    fn a_multi_line_literal_counts_its_lines_once() {
        let src = "let a = \"x\ny\";\nlet b = \"z\";";
        assert_eq!(
            literals(src),
            vec![(1, "x\ny".to_string()), (3, "z".to_string())]
        );
    }

    #[test]
    fn comments_are_blanked_and_strings_kept() {
        assert_eq!(
            without_comments("a // \"c\"\nb /* d */ \"// e\""),
            "a \nb  \"// e\""
        );
    }

    #[test]
    fn the_tests_are_cut_off() {
        assert_eq!(before_tests("mod a;\n#[cfg(test)]\nmod t;"), "mod a;\n");
        assert_eq!(before_tests("mod a;"), "mod a;");
    }

    #[test]
    fn a_literal_is_named_whole_in_the_body_only() {
        let src = "let v = json!({\"parts_sent\": 1}); // \"parts_total\"\n#[cfg(test)] mod t { const X: &str = \"notifications\"; }";
        assert!(names_literal(src, "parts_sent"));
        assert!(
            !names_literal(src, "parts_total"),
            "a comment is not the module"
        );
        assert!(
            !names_literal(src, "notifications"),
            "a test is not the module"
        );
        assert!(!names_literal(src, "parts"), "whole, not a prefix");
    }
}
