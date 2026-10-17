//! Whether a module reads the process's own clock.
//!
//! The sandbox gives a module the time through the `datetime` host interface
//! (`datetime::now_unix()`, `now_iso()`), which every capability world
//! imports and which a test drives through `talos_module_testkit::host::clock`.
//! A module that reads `chrono::Utc::now()`, `chrono::Local::now()` or
//! `std::time::SystemTime::now()` instead gets the worker's wall clock, which
//! no test can set: `commitments` (authoring lane, 2026-10-17) passed its
//! round-trip test for fourteen days and then failed it, because the
//! fixture's due date had expired by the real calendar and the test had no
//! clock to pin.
//!
//! So, over the module before its `#[cfg(test)]` module, comments out and
//! string literals skipped: no line calls one of [`OWN_CLOCK_CALLS`] as a
//! whole word. `Instant::now()` is not on the list: it is a monotonic
//! duration, never a date, and a module may time its own work with it.
//!
//! Limits: a string is recognised as the compile lint recognises one (an
//! ordinary `"…"` with escapes); the one raw string that both holds an inner
//! `"` and names a call would be read as code, and refused rather than
//! admitted. There is no opt-out marker: a module that wants a date takes it
//! from the host.

use crate::lint::find_word_outside_string;
use crate::literals::{before_tests, without_comments};
use std::fmt;

/// The calls that read the process's own clock. A new one is added here and
/// nowhere else.
pub const OWN_CLOCK_CALLS: &[&str] = &["Utc::now", "Local::now", "SystemTime::now"];

/// One line of a module that reads the process's own clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnClockRead {
    /// 1-based line of the source.
    pub line: usize,
    /// The call found, one of [`OWN_CLOCK_CALLS`].
    pub call: &'static str,
}

impl fmt::Display for OwnClockRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {} reads the process's own clock (`{}`): take the time from \
             `datetime::now_unix()`, which a test can set",
            self.line, self.call
        )
    }
}

/// Every line of the module (before its tests) that calls one of
/// [`OWN_CLOCK_CALLS`] outside a comment or a string literal, in line order,
/// one finding per line and call.
#[must_use]
pub fn own_clock_reads(source: &str) -> Vec<OwnClockRead> {
    let code = without_comments(before_tests(source));
    let mut out = Vec::new();
    for (index, line) in code.lines().enumerate() {
        for call in OWN_CLOCK_CALLS {
            if find_word_outside_string(line, call).is_some() {
                out.push(OwnClockRead {
                    line: index + 1,
                    call,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(source: &str) -> Vec<(usize, &'static str)> {
        own_clock_reads(source)
            .into_iter()
            .map(|r| (r.line, r.call))
            .collect()
    }

    #[test]
    fn each_own_clock_call_is_found_on_its_line_with_or_without_its_path() {
        let src = "fn run() {\n    let a = Utc::now();\n    let b = chrono::Local::now();\n    \
                   let c = std::time::SystemTime::now()\n        .duration_since(UNIX_EPOCH);\n}\n";
        assert_eq!(
            lines(src),
            vec![(2, "Utc::now"), (3, "Local::now"), (4, "SystemTime::now")]
        );
    }

    #[test]
    fn a_call_in_a_comment_a_string_or_the_tests_is_not_a_reading() {
        let src = "// Utc::now() would be wrong here\n\
                   /* SystemTime::now()\n   over two lines */\n\
                   let why = \"never Local::now()\";\n\
                   let t = datetime::now_unix();\n\
                   #[cfg(test)]\nmod tests {\n    fn pin() { let _ = Utc::now(); }\n}\n";
        assert_eq!(lines(src), vec![]);
    }

    #[test]
    fn a_line_after_a_block_comment_keeps_its_number() {
        let src = "/* one\n two */\nlet a = Utc::now();\n";
        assert_eq!(lines(src), vec![(3, "Utc::now")]);
    }

    #[test]
    fn the_call_is_a_whole_word_and_a_monotonic_instant_is_allowed() {
        let src = "let i = Instant::now();\nlet s = MyUtc::now();\nlet n = Utc::nowish();\n\
                   let u = Utc::now_or_never();\n";
        assert_eq!(lines(src), vec![]);
    }

    #[test]
    fn a_call_passed_as_a_function_is_a_reading_too() {
        assert_eq!(
            lines("let f = items.iter().map(|_| Utc::now);\n"),
            vec![(1, "Utc::now")]
        );
    }

    #[test]
    fn a_finding_says_what_to_do_instead() {
        let text = own_clock_reads("let a = Utc::now();")[0].to_string();
        assert!(
            text.contains("line 1")
                && text.contains("`Utc::now`")
                && text.contains("datetime::now_unix()"),
            "{text}"
        );
    }

    #[test]
    fn a_string_that_holds_a_call_and_a_later_real_call_on_one_line() {
        assert_eq!(
            lines("let a = (\"Utc::now()\", Utc::now());"),
            vec![(1, "Utc::now")]
        );
    }
}
