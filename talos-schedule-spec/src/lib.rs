//! What a workflow schedule must be before it is stored, in one place.
//!
//! Until 2026-10-15 the checks a cron expression and a timezone pass before
//! a `workflow_schedules` row is written lived in each handler: MCP
//! `create_schedule` / `update_schedule`, `deploy_workflow`,
//! `promote_workflow`, and the GraphQL schedule mutations each called the
//! three validators (and spelled the 60-second floor) themselves, and
//! `import_platform_state` called none of them — it stored any non-empty
//! cron and any timezone, counted the row as imported, and on a workflow
//! that already had a schedule replaced it in place (security review
//! 2026-10-14, G-10).
//!
//! [`ScheduleSpec`] is the answer. Its only constructor,
//! [`ScheduleSpec::validated`], runs every check; a repository write that
//! takes one cannot be handed a schedule that skipped them, and it carries
//! the first `next_trigger_at` so a new row is due without waiting for the
//! scheduler's start-up backfill.
//!
//! The parse helpers here are the ones the scheduler itself runs, so
//! "stored" and "fires" agree on what is valid: `talos-scheduler` re-exports
//! them. This crate is a leaf (no database, no engine) so the repository
//! crates can require a [`ScheduleSpec`] without depending on the scheduler,
//! which depends on them.

use chrono::{DateTime, Utc};

/// The shortest interval a stored schedule may fire at: once a minute. A
/// five-field cron cannot express anything shorter; the check stays for a
/// parser that one day accepts a seconds field.
pub const MIN_SCHEDULE_INTERVAL_SECS: u64 = 60;

/// Why a schedule was refused. `Display` is the sentence a caller is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleSpecError {
    /// The cron expression: wrong field count, unparseable, or more often
    /// than [`MIN_SCHEDULE_INTERVAL_SECS`].
    Cron(String),
    /// The timezone is not an IANA identifier.
    Timezone(String),
}

impl std::fmt::Display for ScheduleSpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cron(msg) => f.write_str(msg),
            Self::Timezone(msg) => write!(
                f,
                "{msg}. Use an IANA timezone identifier like 'UTC', 'America/New_York', or \
                 'Europe/London'."
            ),
        }
    }
}

impl std::error::Error for ScheduleSpecError {}

/// Every check a cron expression passes before it is stored: five or six
/// fields, a parse with the scheduler's own parser, and no more often than
/// once a minute. The error is the sentence the caller is shown.
///
/// # Errors
/// The first check the expression fails.
pub fn validate_schedule_cron(cron_expression: &str) -> Result<(), String> {
    let field_count = cron_expression.split_whitespace().count();
    if !(5..=6).contains(&field_count) {
        return Err("Invalid cron expression: must have 5 or 6 space-separated fields".to_string());
    }
    validate_cron(cron_expression)?;
    validate_cron_min_interval(cron_expression, MIN_SCHEDULE_INTERVAL_SECS)
}

/// A schedule every check has passed: the only value a schedule writer
/// takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleSpec {
    cron_expression: String,
    timezone: String,
    next_trigger_at: DateTime<Utc>,
}

impl ScheduleSpec {
    /// Check `cron_expression` ([`validate_schedule_cron`]) and `timezone`
    /// ([`validate_timezone`]), and compute the first time the schedule is
    /// due. Both are trimmed first.
    ///
    /// # Errors
    /// The first check that fails, as the sentence a caller is shown.
    pub fn validated(cron_expression: &str, timezone: &str) -> Result<Self, ScheduleSpecError> {
        let cron_expression = cron_expression.trim();
        let timezone = timezone.trim();
        validate_schedule_cron(cron_expression).map_err(ScheduleSpecError::Cron)?;
        validate_timezone(timezone).map_err(ScheduleSpecError::Timezone)?;
        let next_trigger_at =
            calculate_next_trigger(cron_expression, timezone).map_err(ScheduleSpecError::Cron)?;
        Ok(Self {
            cron_expression: cron_expression.to_string(),
            timezone: timezone.to_string(),
            next_trigger_at,
        })
    }

    /// The cron expression, as checked.
    #[must_use]
    pub fn cron_expression(&self) -> &str {
        &self.cron_expression
    }

    /// The IANA timezone, as checked.
    #[must_use]
    pub fn timezone(&self) -> &str {
        &self.timezone
    }

    /// The first time the schedule is due, computed when it was checked.
    #[must_use]
    pub fn next_trigger_at(&self) -> DateTime<Utc> {
        self.next_trigger_at
    }
}

#[cfg(test)]
mod schedule_spec_tests {
    use super::*;

    #[test]
    fn a_valid_schedule_carries_its_first_due_time() {
        let spec = ScheduleSpec::validated(" 0 9 * * 1-5 ", "America/New_York").expect("valid");
        assert_eq!(spec.cron_expression(), "0 9 * * 1-5");
        assert_eq!(spec.timezone(), "America/New_York");
        assert!(spec.next_trigger_at() > Utc::now());
    }

    #[test]
    fn a_seconds_field_is_refused_as_a_cron_fault() {
        // croner 2.x refuses a leading seconds field; whatever the parser
        // says, it is never stored.
        let err = ScheduleSpec::validated("* * * * * *", "UTC").expect_err("refused");
        assert!(matches!(err, ScheduleSpecError::Cron(_)), "{err:?}");
    }

    #[test]
    fn the_field_count_message_is_the_one_callers_were_shown() {
        let err = ScheduleSpec::validated("* * * *", "UTC").expect_err("refused");
        assert_eq!(
            err.to_string(),
            "Invalid cron expression: must have 5 or 6 space-separated fields"
        );
    }

    #[test]
    fn an_unknown_timezone_is_refused_with_the_iana_hint() {
        let err = ScheduleSpec::validated("0 9 * * *", "Mars/Olympus_Mons").expect_err("refused");
        assert!(matches!(err, ScheduleSpecError::Timezone(_)), "{err:?}");
        assert!(
            err.to_string().contains("IANA timezone identifier"),
            "{err}"
        );
    }

    #[test]
    fn once_a_minute_is_the_floor_and_is_accepted() {
        assert!(ScheduleSpec::validated("* * * * *", "UTC").is_ok());
        assert!(validate_cron_min_interval("* * * * *", MIN_SCHEDULE_INTERVAL_SECS + 1).is_err());
    }
}

/// Calculate the next trigger time for a cron expression in the given timezone.
///
/// Returns `None` if the cron expression is invalid or no future occurrence can
/// be computed.
pub fn calculate_next_trigger(
    cron_expression: &str,
    timezone: &str,
) -> Result<DateTime<Utc>, String> {
    // MCP-959 (2026-05-15): delegate to the capped + reflection-
    // scrubbed timezone validator so this sibling-of-`validate_timezone`
    // entry point shares the same length cap and never echoes the
    // rejected value into the error message.
    let tz = parse_timezone(timezone)?;

    // MCP-1020 (2026-05-15): delegate cron parse through the
    // length-capped + reflection-scrubbed helper, sibling pattern to
    // `parse_timezone`.
    let cron = parse_cron(cron_expression)?;

    next_trigger_after(&cron, tz, Utc::now())
}

/// The first occurrence of `cron`, read in `tz`, strictly after `after`.
///
/// The one place the scheduler asks the cron library "when next?", with the
/// instant passed in so the answer can be tested: until 2026-10-06 every
/// caller read `Utc::now()` inside, and the only tests asserted `is_ok()`.
/// `dst_behaviour_tests` pins what this returns across both daylight-saving
/// transitions — read it before changing the `croner` version.
pub fn next_trigger_after(
    cron: &croner::Cron,
    tz: chrono_tz::Tz,
    after: DateTime<Utc>,
) -> Result<DateTime<Utc>, String> {
    cron.find_next_occurrence(&after.with_timezone(&tz), false)
        .map(|next| next.with_timezone(&Utc))
        .map_err(|e| format!("Failed to calculate next occurrence: {}", e))
}

/// Up to `n` consecutive occurrences after `after`; stops at the first the
/// library cannot produce.
pub fn next_n_triggers_after(
    cron: &croner::Cron,
    tz: chrono_tz::Tz,
    after: DateTime<Utc>,
    n: usize,
) -> Vec<DateTime<Utc>> {
    let mut out = Vec::with_capacity(n);
    let mut cursor = after;
    for _ in 0..n {
        match next_trigger_after(cron, tz, cursor) {
            Ok(next) => {
                out.push(next);
                cursor = next;
            }
            Err(_) => break,
        }
    }
    out
}

#[cfg(test)]
mod dst_behaviour_tests {
    use super::*;

    fn fires(expr: &str, tz: &str, after: &str, n: usize) -> Vec<String> {
        let cron = parse_cron(expr).expect("expression parses");
        let tz = parse_timezone(tz).expect("timezone parses");
        let after: DateTime<Utc> = after.parse().expect("an RFC 3339 instant");
        next_n_triggers_after(&cron, tz, after, n)
            .iter()
            .map(|t| t.format("%m-%dT%H:%MZ").to_string())
            .collect()
    }

    const NY: &str = "America/New_York";

    // Spring forward, New York, 2027-03-14: 02:00 EST becomes 03:00 EDT
    // (07:00Z). The hour 02:00–02:59 does not exist that day.

    /// A daily job in the hour BEFORE the gap fires once. croner 3.0.1 and
    /// 4.0.1 both fire it a second time at the end of the gap (measured
    /// 2026-10-06: `0 1 * * *` also at 03:00 EDT; in London, `0 0 * * *` also
    /// at 02:00 BST) — a duplicate run of whatever the schedule starts. This
    /// is the test that holds the dependency at 2.x.
    #[test]
    fn a_daily_job_in_the_hour_before_the_spring_gap_fires_once() {
        assert_eq!(
            fires("0 1 * * *", NY, "2027-03-13T12:00:00Z", 3),
            ["03-14T06:00Z", "03-15T05:00Z", "03-16T05:00Z"]
        );
        assert_eq!(
            fires("45 1 * * *", NY, "2027-03-13T12:00:00Z", 3),
            ["03-14T06:45Z", "03-15T05:45Z", "03-16T05:45Z"]
        );
        // London's gap is 01:00–02:00 on 2027-03-28, so its hour before is 00.
        assert_eq!(
            fires("0 0 * * *", "Europe/London", "2027-03-27T12:00:00Z", 3),
            ["03-28T00:00Z", "03-28T23:00Z", "03-29T23:00Z"]
        );
    }

    /// A daily job INSIDE the gap fires once, at the gap's end, and is back
    /// at its own time the next day.
    #[test]
    fn a_daily_job_inside_the_spring_gap_fires_once_at_its_end() {
        assert_eq!(
            fires("30 2 * * *", NY, "2027-03-13T12:00:00Z", 3),
            ["03-14T07:00Z", "03-15T06:30Z", "03-16T06:30Z"]
        );
    }

    /// A sub-hourly job runs every real half hour straight across the gap.
    #[test]
    fn a_sub_hourly_job_crosses_the_spring_gap_without_a_hole() {
        assert_eq!(
            fires("*/30 * * * *", NY, "2027-03-14T06:10:00Z", 4),
            [
                "03-14T06:30Z",
                "03-14T07:00Z",
                "03-14T07:30Z",
                "03-14T08:00Z"
            ]
        );
        assert_eq!(
            fires("25,55 6-22 * * *", NY, "2027-03-14T03:00:00Z", 3),
            ["03-14T03:25Z", "03-14T03:55Z", "03-14T10:25Z"]
        );
    }

    /// A wall-clock job keeps its local time across both changes: 08:00 is
    /// 13:00Z in winter and 12:00Z in summer.
    #[test]
    fn a_wall_clock_job_keeps_its_local_time_across_both_changes() {
        assert_eq!(
            fires("0 8 * * 1-5", NY, "2027-03-12T14:00:00Z", 2),
            ["03-15T12:00Z", "03-16T12:00Z"]
        );
        assert_eq!(
            fires("0 8 * * 1-5", NY, "2026-10-30T13:30:00Z", 3),
            ["11-02T13:00Z", "11-03T13:00Z", "11-04T13:00Z"]
        );
    }

    // Fall back, New York, 2026-11-01: 02:00 EDT becomes 01:00 EST (06:00Z).
    // The hour 01:00–01:59 happens twice (05:00Z–06:59Z).

    /// A daily job in the repeated hour fires once, on its first pass.
    #[test]
    fn a_daily_job_in_the_repeated_autumn_hour_fires_once() {
        assert_eq!(
            fires("30 1 * * *", NY, "2026-10-31T12:00:00Z", 3),
            ["11-01T05:30Z", "11-02T06:30Z", "11-03T06:30Z"]
        );
    }

    /// RECORDED, NOT ENDORSED. croner 2.2 does not fire a sub-daily job
    /// during the second pass of the repeated hour: a half-hourly job goes
    /// from 05:30Z to 07:00Z, and an hourly one from 05:00Z to 07:00Z. croner
    /// 4.0.1 fires through it (06:00Z, 06:30Z), which is the better answer —
    /// when the duplicate in the first test above is fixed upstream and the
    /// dependency moves, this test is the one that should change.
    #[test]
    fn a_sub_daily_job_pauses_for_the_repeated_autumn_hour() {
        assert_eq!(
            fires("*/30 * * * *", NY, "2026-11-01T04:40:00Z", 6),
            [
                "11-01T05:00Z",
                "11-01T05:30Z",
                "11-01T07:00Z",
                "11-01T07:30Z",
                "11-01T08:00Z",
                "11-01T08:30Z"
            ]
        );
        assert_eq!(
            fires("0 * * * *", NY, "2026-11-01T03:40:00Z", 5),
            [
                "11-01T04:00Z",
                "11-01T05:00Z",
                "11-01T07:00Z",
                "11-01T08:00Z",
                "11-01T09:00Z"
            ]
        );
    }

    /// The syntax the scheduler accepts: five fields. croner 4 by default
    /// also accepts a leading seconds field and a trailing year, and refuses
    /// the `5/5` step shorthand that 2.x accepts — either would change which
    /// stored schedules parse.
    #[test]
    fn the_accepted_syntax_is_five_fields() {
        for accepted in ["5/5 * * * *", "@daily", "0 9 * * MON-FRI", "0 0 * * 7"] {
            assert!(validate_cron(accepted).is_ok(), "{accepted}");
        }
        for refused in [
            "0 0 * * * *",
            "0 0 0 1 1 * 2030",
            "/10 * * * *",
            "60 * * * *",
            "",
        ] {
            assert!(validate_cron(refused).is_err(), "{refused:?}");
        }
    }
}

/// Validate that a cron expression is parseable.
pub fn validate_cron(cron_expression: &str) -> Result<(), String> {
    // MCP-1020 (2026-05-15): share the capped + scrubbed parse path so
    // future callers that bypass the boundary length cap still get the
    // defense-in-depth treatment. Same pattern as MCP-958/959 for
    // timezone validation.
    parse_cron(cron_expression).map(|_| ())
}

/// Calculate the next `n` trigger occurrences in UTC. Useful for surfacing a
/// concrete preview of the schedule to the user (cron expressions like
/// `0 9 * * 1-5` are opaque to most readers; `Mon Apr 21 09:00 UTC, ...` is not).
///
/// Returns up to `n` occurrences. Stops early on iteration error rather than
/// returning a partial-then-failed Result, since this is a best-effort preview.
pub fn calculate_next_n_triggers(
    cron_expression: &str,
    timezone: &str,
    n: usize,
) -> Result<Vec<DateTime<Utc>>, String> {
    if n == 0 {
        return Ok(Vec::new());
    }
    // MCP-959 (2026-05-15): same delegation as `calculate_next_trigger`.
    let tz = parse_timezone(timezone)?;
    // MCP-1020 (2026-05-15): sibling cron-parse helper.
    let cron = parse_cron(cron_expression)?;

    Ok(next_n_triggers_after(&cron, tz, Utc::now(), n))
}

/// Validate that a cron expression fires no more frequently than `min_secs` apart.
///
/// Computes two consecutive occurrences from now and checks the gap.
/// Returns an error if the interval is shorter than `min_secs`.
pub fn validate_cron_min_interval(cron_expression: &str, min_secs: u64) -> Result<(), String> {
    // MCP-1020 (2026-05-15): sibling cron-parse helper.
    let cron = parse_cron(cron_expression)?;

    let now = Utc::now();
    let next1 = cron
        .find_next_occurrence(&now, false)
        .map_err(|e| format!("Failed to calculate next occurrence: {}", e))?;
    let next2 = cron
        .find_next_occurrence(&next1, false)
        .map_err(|e| format!("Failed to calculate second occurrence: {}", e))?;

    let interval_secs = (next2 - next1).num_seconds();
    if interval_secs < min_secs as i64 {
        return Err(format!(
            "Schedule interval is too frequent ({} seconds). Minimum allowed interval is {} seconds.",
            interval_secs, min_secs
        ));
    }
    Ok(())
}

/// Validate that a timezone string is a valid IANA timezone.
///
/// MCP-958 (2026-05-15): cap caller-supplied length at 64 chars and
/// scrub the rejected value out of the error message. Pre-fix:
/// (1) `chrono_tz::Tz`'s `FromStr` impl walks ~600 IANA entries with
///     a memcmp per candidate; the early-exit on first-byte mismatch
///     keeps that bounded in practice, but there was no upstream
///     length cap so a multi-MB timezone string flowed through every
///     caller (MCP schedules.rs `validate_optional_string` and the
///     GraphQL `create_schedule` / `update_schedule` mutations both
///     forwarded raw caller input). MCP-414 / MCP-844 capped
///     `cron_expression` at 256 chars at the boundary for exactly
///     this DoS-by-unbounded-input class; this is the missing
///     timezone sibling.
/// (2) The error message echoed the rejected `timezone` value into
///     `format!("Invalid timezone: {}", timezone)`. An attacker could
///     reflect arbitrary content (up to the body cap) back through
///     the error response and the structured log — same reflection
///     class as the MCP-852/853/854 secrets-in-debug-print sweep,
///     just at the user-facing error surface. Now the error names
///     only the byte length, not the content.
///
/// 64 chars covers every IANA timezone identifier (longest legitimate
/// entry is `America/Argentina/ComodRivadavia` at 32 chars).
///
/// MCP-959 (2026-05-15): extracted the parse-or-reject body into
/// `parse_timezone` so `calculate_next_trigger` and
/// `calculate_next_n_triggers` can share the same length cap +
/// scrubbed error path (both previously called `timezone.parse()`
/// directly with the un-scrubbed echo).
pub fn validate_timezone(timezone: &str) -> Result<(), String> {
    parse_timezone(timezone).map(|_| ())
}

/// Length-cap + parse helper shared by `validate_timezone` and the
/// scheduler `calculate_next_*` helpers. Keeps the 64-char cap and
/// the reflection-scrub in a single place.
pub fn parse_timezone(timezone: &str) -> Result<chrono_tz::Tz, String> {
    const MAX_TIMEZONE_LEN: usize = 64;
    if timezone.len() > MAX_TIMEZONE_LEN {
        return Err(format!(
            "Invalid timezone: input length {} exceeds {} char cap; \
             use an IANA timezone identifier like 'UTC' or 'America/New_York'",
            timezone.len(),
            MAX_TIMEZONE_LEN
        ));
    }
    timezone
        .parse::<chrono_tz::Tz>()
        .map_err(|_| format!("Invalid timezone: {}", timezone))
}

/// MCP-1020 (2026-05-15): length-cap + parse helper for cron
/// expressions, sibling to `parse_timezone`. Pre-fix all four
/// public entry points (`validate_cron`, `validate_cron_min_interval`,
/// `calculate_next_trigger`, `calculate_next_n_triggers`) called
/// `croner::Cron::new(cron).parse()` directly. The four current callers
/// (talos-api create_schedule/update_schedule capping at 256, talos-mcp-
/// handlers schedules.rs / advanced.rs deploy_workflow / promote_workflow
/// capping at 200) all cap at the boundary, but the validator should
/// defend itself — any NEW caller that forgets the boundary cap would
/// flow multi-MB strings into the croner parser AND into a reflection-
/// shaped error message (`format!("Invalid cron expression: {}", e)`
/// where `e` may echo offending input). Same exact pattern MCP-958/959
/// closed for timezone validation. 256-char cap matches the canonical
/// GraphQL surface upper bound; longest legitimate cron is ~50 chars
/// (full vixie-cron 6-field with named day-of-week + months) so the
/// cap is operator-comfortable. Error message names byte length only
/// when cap is hit so the rejected value doesn't reflect through.
pub fn parse_cron(cron_expression: &str) -> Result<croner::Cron, String> {
    const MAX_CRON_LEN: usize = 256;
    if cron_expression.len() > MAX_CRON_LEN {
        return Err(format!(
            "Invalid cron expression: input length {} exceeds {} char cap",
            cron_expression.len(),
            MAX_CRON_LEN
        ));
    }
    croner::Cron::new(cron_expression)
        .parse()
        .map_err(|e| format!("Invalid cron expression: {}", e))
}

#[cfg(test)]
mod cron_validation_tests {
    //! MCP-1020: pins the length-cap + scrubbed-error invariants on
    //! the cron parse helper so future callers that bypass the
    //! boundary cap still get the defense-in-depth treatment.
    use super::*;

    #[test]
    fn accepts_canonical_cron_expressions() {
        assert!(validate_cron("0 9 * * *").is_ok());
        assert!(validate_cron("*/5 * * * *").is_ok());
        // Per-minute schedule
        assert!(validate_cron("* * * * *").is_ok());
    }

    #[test]
    fn rejects_oversized_cron_with_length_only_error() {
        let oversized = "* ".repeat(200) + "*";
        let err = validate_cron(&oversized).expect_err("oversized must reject");
        // Error message names byte length only; no reflection of input.
        assert!(
            err.contains("exceeds 256 char cap"),
            "expected length cap message, got: {err}"
        );
        // The rejected content must NOT appear in the error.
        assert!(
            !err.contains("* * * * * * * * * *"),
            "error must not echo rejected cron content: {err}"
        );
    }

    #[test]
    fn rejects_garbage_cron_with_natural_error() {
        // Short-but-invalid cron should still get a parser error
        // (natural croner error, bounded by the 256-char cap).
        let err = validate_cron("not a cron").expect_err("garbage must reject");
        assert!(
            err.starts_with("Invalid cron expression:"),
            "expected natural parse error prefix, got: {err}"
        );
    }

    #[test]
    fn calculate_next_trigger_rejects_oversized_cron() {
        let oversized = "* ".repeat(200) + "*";
        let err = calculate_next_trigger(&oversized, "UTC")
            .expect_err("oversized cron must reject in next_trigger path too");
        assert!(err.contains("exceeds 256 char cap"));
    }

    #[test]
    fn validate_cron_min_interval_rejects_oversized_cron() {
        let oversized = "* ".repeat(200) + "*";
        let err = validate_cron_min_interval(&oversized, 60)
            .expect_err("oversized cron must reject in min-interval path");
        assert!(err.contains("exceeds 256 char cap"));
    }

    #[test]
    fn calculate_next_n_triggers_rejects_oversized_cron() {
        let oversized = "* ".repeat(200) + "*";
        let err = calculate_next_n_triggers(&oversized, "UTC", 3)
            .expect_err("oversized cron must reject in next_n path");
        assert!(err.contains("exceeds 256 char cap"));
    }

    #[test]
    fn accepts_max_length_cron() {
        // Exactly at the cap: should reach the croner parser. The
        // parser will reject (it's a long stream of asterisks), but
        // via the natural "Invalid cron expression:" path, not the
        // length-cap path.
        let at_cap = "*".repeat(256);
        let err = validate_cron(&at_cap).expect_err("invalid cron content rejects");
        assert!(
            !err.contains("exceeds 256 char cap"),
            "at-cap input should reach parser, not length gate: {err}"
        );
    }
}
