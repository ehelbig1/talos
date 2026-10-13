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

/// Whether the outputs a resumed run is seeded with show that the run was
/// started as a DRY RUN.
///
/// The row's own flag ([`RunMode`]) is the record, and it decides for every
/// run created since the column existed. This is for the rows it cannot
/// speak for: a dry run that was started BEFORE the column and is still
/// paused has `dry_run = false`, and on that flag alone its resume would be
/// a real run, with every stub lifted. Its completed nodes say otherwise.
///
/// The evidence is the worker's dry-run report on a node output
/// ([`talos_workflow_job_protocol::read_dry_run_report`]). Only the output of
/// a PLAIN MODULE node counts, because only there is it unforgeable: the
/// worker writes the report on every module output of a dry run and REMOVES
/// a module's own copy on an ordinary run. The trigger seed is caller data,
/// and a system node can forward caller data, so a report-shaped value there
/// proves nothing and is ignored. (Nothing a caller plants could do worse
/// than stub their own run, but a rule that can be steered is not a rule.)
///
/// It only ever moves a run TOWARD a dry run. One module output with a
/// report is enough: an ordinary run has none.
#[must_use]
pub(crate) fn seed_shows_a_dry_run(
    seed: &std::collections::HashMap<Uuid, serde_json::Value>,
    is_plain_module_node: impl Fn(&Uuid) -> bool,
) -> bool {
    seed.iter().any(|(node_id, output)| {
        is_plain_module_node(node_id)
            && talos_workflow_job_protocol::read_dry_run_report(output).is_some()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dry run paused before the row could record its mode: the row says
    /// "real", and the outputs its nodes had already committed say it was a
    /// rehearsal.
    #[test]
    fn a_completed_module_output_with_the_workers_report_is_evidence_of_a_dry_run() {
        use serde_json::json;
        let (trigger, module, system) =
            (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let is_module = |id: &Uuid| *id == module;
        let report = json!({ "stubbed_calls": 1, "by_surface": { "http": 1 } });
        let seed = |entries: &[(Uuid, serde_json::Value)]| {
            entries
                .iter()
                .cloned()
                .collect::<std::collections::HashMap<_, _>>()
        };

        // The worker's report on a module output: a dry run.
        assert!(seed_shows_a_dry_run(
            &seed(&[(module, json!({ "sent": true, "__dry_run__": report }))]),
            is_module
        ));
        // Zero stubbed calls is still a report: the worker writes it on
        // every module output of a dry run.
        assert!(seed_shows_a_dry_run(
            &seed(&[(
                module,
                json!({ "__dry_run__": { "stubbed_calls": 0, "by_surface": {} } })
            )]),
            is_module
        ));

        // An ordinary run's outputs: none.
        assert!(!seed_shows_a_dry_run(
            &seed(&[(module, json!({ "sent": true }))]),
            is_module
        ));
        assert!(!seed_shows_a_dry_run(&seed(&[]), is_module));
        // The stub RESPONSE a module is handed carries `true` under the key;
        // a module that echoes it has not produced a report.
        assert!(!seed_shows_a_dry_run(
            &seed(&[(module, json!({ "__dry_run__": true }))]),
            is_module
        ));

        // Caller data proves nothing: a report-shaped value in the trigger
        // seed, or forwarded by a system node, is not the worker's.
        assert!(!seed_shows_a_dry_run(
            &seed(&[
                (trigger, json!({ "__dry_run__": report })),
                (system, json!({ "__dry_run__": report })),
                (module, json!({ "sent": true })),
            ]),
            is_module
        ));
    }

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
        // The resume kernel also asks the run's own completed outputs, for
        // the rows the flag cannot speak for.
        let resume = sources
            .iter()
            .find(|(f, _)| *f == "crash_recovery.rs")
            .unwrap()
            .1;
        assert!(
            resume.contains("seed_shows_a_dry_run("),
            "the resume kernel no longer reads the seed for evidence of a dry run"
        );
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
