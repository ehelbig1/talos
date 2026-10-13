//! The engine options for a run of an execution ROW.
//!
//! Four things in this crate build an engine for a row of
//! `workflow_executions`: a fresh trigger, a replay, a retry, and the resume
//! kernel (crash recovery, and the resume of a run paused on an approval or
//! a wait node). Until 2026-10-13 only the first knew whether the run was a
//! dry run, because only it had the caller's flag in hand. The other three
//! built an ordinary engine, so a rehearsal that paused, was retried, was
//! replayed, or was caught mid-flight by a controller restart came back as a
//! real run: its stubbed sends were made and its action links were minted.
//!
//! The mode is now on the row ([`RunMode`]), and this is the one place an
//! engine's options are made from a row: the mode is an argument, so it
//! cannot be left out. The pin test below holds every engine build in this
//! crate to it.

use talos_engine::builder::EngineOpts;
use talos_workflow_repository::RunMode;
use uuid::Uuid;

/// Options for an engine that runs the execution row whose mode is
/// `run_mode`.
///
/// `actor` and `workflow_default_actor` are what
/// [`talos_engine::builder::UnboundEngineOpts::with_effective_actor`] takes:
/// the gate-resolved (or originally stamped) actor, and the workflow's bound
/// default as its fallback.
#[must_use]
pub(crate) fn engine_opts_for_row(
    workflow_id: Uuid,
    graph_json: String,
    actor: Option<Uuid>,
    workflow_default_actor: Option<Uuid>,
    run_mode: RunMode,
) -> EngineOpts {
    EngineOpts::for_run(workflow_id, graph_json)
        .with_effective_actor(actor, workflow_default_actor)
        .with_dry_run(run_mode.is_dry_run())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dry_run_row_gets_a_dry_run_engine_and_a_real_row_a_real_one() {
        let (wf, actor, fallback) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let dry = engine_opts_for_row(wf, "{}".into(), Some(actor), None, RunMode::DryRun);
        assert!(dry.dry_run, "a dry-run row was given an ordinary engine");
        assert_eq!(dry.workflow_id, wf);
        assert_eq!(dry.effective_actor_id, Some(actor));

        let real = engine_opts_for_row(wf, "{}".into(), None, Some(fallback), RunMode::Real);
        assert!(!real.dry_run);
        assert_eq!(real.effective_actor_id, Some(fallback));
    }

    /// Every engine this crate builds for a row is built here. A build
    /// written out by hand elsewhere is a build that can forget the mode,
    /// which is how a resumed rehearsal became a real run.
    #[test]
    fn no_other_file_in_this_crate_builds_engine_options_for_a_run() {
        let sources = [
            ("approval_resume.rs", include_str!("approval_resume.rs")),
            ("crash_recovery.rs", include_str!("crash_recovery.rs")),
            ("replay.rs", include_str!("replay.rs")),
            ("retry.rs", include_str!("retry.rs")),
            ("trigger.rs", include_str!("trigger.rs")),
            ("lib.rs", include_str!("lib.rs")),
        ];
        for (file, source) in sources {
            let built_by_hand: Vec<usize> = source
                .lines()
                .enumerate()
                .filter(|(_, line)| !line.trim_start().starts_with("//"))
                .filter(|(_, line)| {
                    line.contains("EngineOpts::for_run(")
                        || line.contains("EngineOpts::for_skip_load(")
                })
                .map(|(i, _)| i + 1)
                .collect();
            assert!(
                built_by_hand.is_empty(),
                "{file} builds engine options itself at line(s) {built_by_hand:?}. Use \
                 run_mode::engine_opts_for_row, which takes the row's RunMode: an engine built \
                 without it runs a dry run for real."
            );
        }
        // Each of the four builds through it, and each passes the mode it
        // READ: the row's own, or (a fresh trigger) the caller's flag, which
        // is also what it created the row with. None passes a constant: a
        // resume that said `RunMode::Real` would compile, pass every other
        // test here, and run a paused rehearsal for real.
        for (file, reads) in [
            ("crash_recovery.rs", "RunMode::from_dry_run(row.dry_run)"),
            ("retry.rs", "RunMode::from_dry_run(exec.dry_run)"),
            ("replay.rs", "RunMode::from_dry_run(orig.dry_run)"),
            ("trigger.rs", "RunMode::from_dry_run(dry_run)"),
        ] {
            let source = sources.iter().find(|(f, _)| *f == file).unwrap().1;
            assert!(
                source.contains("engine_opts_for_row("),
                "{file} no longer builds its engine through engine_opts_for_row"
            );
            assert!(
                source.contains(reads),
                "{file} no longer takes its run mode from `{reads}`"
            );
            for constant in ["RunMode::Real", "RunMode::DryRun"] {
                assert!(
                    !source.contains(constant),
                    "{file} names the constant {constant}: a run's mode is read from its row \
                     (or, for a fresh trigger, from the caller's flag), never assumed"
                );
            }
        }
        // A fresh trigger uses the caller's flag twice: for the row it
        // creates and for the engine it builds. One without the other is a
        // row that disagrees with its run.
        let trigger = sources.iter().find(|(f, _)| *f == "trigger.rs").unwrap().1;
        assert_eq!(
            trigger.matches("RunMode::from_dry_run(dry_run)").count(),
            2,
            "trigger.rs must create the row and build the engine from the same flag"
        );
    }
}
