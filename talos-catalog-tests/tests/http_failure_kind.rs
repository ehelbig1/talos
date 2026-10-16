//! A template that makes an HTTP request keeps the KIND of a failed one in
//! what it reports.
//!
//! The host hands a module one of four words when a request does not get an
//! answer: a timeout, a network error, a refused host, a bad URL. The
//! platform decides from that word whether to try again
//! (`talos_retry_intelligence::classify_error`): a timeout and a network error
//! are retried, a refusal is not. A module's error message is the only place
//! the word can travel, so a template that maps the error away
//! (`.map_err(|_| "could not be reached")`) turns every network blip into an
//! unretried failure of unknown cause.
//!
//! Observed 2026-10-12: `github-workflow-run` did exactly that, unreachable
//! polls in a busy hour failed the CI watcher four times, and the owner was
//! paged about the pager. Three other templates had the same line.
//!
//! This is a source check, because the property is about every call site,
//! including ones no behavioural test happens to drive.

fn template_sources() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = talos_catalog_tests::template_dirs()
        .into_iter()
        .filter_map(|dir| {
            let slug = dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            std::fs::read_to_string(dir.join("template.rs"))
                .ok()
                .map(|text| (slug, text))
        })
        .collect();
    out.sort();
    out
}

/// The lines in `source` where the result of an HTTP call has its error
/// thrown away: `http::fetch(…)` followed, before the statement ends, by a
/// `map_err` whose closure ignores its argument.
fn discarded_fetch_errors(source: &str) -> Vec<usize> {
    const CALL: &str = "http::fetch(";
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = source[from..].find(CALL) {
        let start = from + at;
        // The statement the call is in: up to the next `;`.
        let end = source[start..]
            .find(';')
            .map_or(source.len(), |i| start + i);
        let statement: String = source[start..end].split_whitespace().collect();
        if statement.contains(".map_err(|_|") {
            found.push(source[..start].lines().count().max(1));
        }
        from = start + CALL.len();
    }
    found
}

#[test]
fn no_template_throws_away_the_kind_of_a_failed_request() {
    let sources = template_sources();
    assert!(sources.len() > 20, "the templates were not found");
    let mut offenders = Vec::new();
    let mut calls = 0;
    for (slug, text) in &sources {
        calls += text.matches("http::fetch(").count();
        for line in discarded_fetch_errors(text) {
            offenders.push(format!("module-templates/{slug}/template.rs:{line}"));
        }
    }
    assert!(calls > 10, "no HTTP calls were found to check ({calls})");
    assert!(
        offenders.is_empty(),
        "these calls map an HTTP failure to a message without its kind; write \
         `.map_err(|e| format!(\"… ({{e:?}})\"))` so a timeout or a network error is retried:\n  {}",
        offenders.join("\n  ")
    );
}

/// The check finds what it is for, and leaves the kept kind alone.
#[test]
fn the_check_sees_a_discarded_kind_across_lines_and_not_a_kept_one() {
    let discarded =
        "let r = talos::core::http::fetch(&req)\n        .map_err(|_| \"down\".to_string())?;";
    assert_eq!(discarded_fetch_errors(discarded), vec![1]);
    let second_line = "x();\nlet r = http::fetch(&req).map_err(|_| \"down\".to_string())?;";
    assert_eq!(discarded_fetch_errors(second_line), vec![2]);
    let kept = "let r = http::fetch(&req).map_err(|e| format!(\"down ({e:?})\"))?;";
    assert!(discarded_fetch_errors(kept).is_empty());
    // A later, unrelated statement that ignores an error is not this call's.
    let unrelated = "let r = http::fetch(&req)?;\nlet n = parse(x).map_err(|_| \"bad\")?;";
    assert!(discarded_fetch_errors(unrelated).is_empty());
}
