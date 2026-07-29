//! Unit coverage for the probe's pure core.
//!
//! Every test drives [`probe_graph`] — the shipping function — against a real
//! `graph_json` document parsed by the real engine loader. Nothing here
//! re-implements binding, evaluation, or branching, which is the point: the
//! tests exist to make the REUSE mutations fail.
//!
//! The mutation guards the plan calls for, and where they land:
//!
//! * bind the multi-parent scope by UUID instead of label →
//!   `multi_parent_scope_is_keyed_by_node_label` fails.
//! * skip `unwrap_output` → `envelope_shaped_parent_output_is_unwrapped` fails.
//! * evaluate with a fresh `rhai::Engine` instead of `rhai_helpers` →
//!   `operation_limit_is_inherited_from_the_production_sandbox` fails (a
//!   default `rhai::Engine` has NO operation cap, so the runaway expression
//!   would succeed instead of erroring).
//! * hand-roll the envelope instead of `build_judge_envelope` →
//!   `probe_matches_dispatch_inline_judge` fails.

use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// Graph fixtures
// ─────────────────────────────────────────────────────────────────────────────

const MODULE: &str = "11111111-1111-4111-8111-111111111111";

/// A graph with one module parent feeding an `inline_judge`.
fn single_parent_graph(expr: &str, threshold: Option<f64>, on_failure: &str) -> String {
    let mut data = json!({ "verdict_expr": expr, "on_failure": on_failure });
    if let Some(t) = threshold {
        data["pass_threshold"] = json!(t);
    }
    json!({
        "nodes": [
            { "id": "coverage", "type": MODULE, "data": {} },
            { "id": "coverage_judge", "type": "system:inline_judge", "kind": "inline_judge", "data": data },
        ],
        "edges": [ { "source": "coverage", "target": "coverage_judge" } ],
    })
    .to_string()
}

/// The coverage-judge shape: two parents feeding one `inline_judge`.
fn multi_parent_graph(expr: &str) -> String {
    json!({
        "nodes": [
            { "id": "classify", "type": MODULE, "data": {} },
            { "id": "feedback", "type": MODULE, "data": {} },
            { "id": "coverage_judge", "type": "system:inline_judge", "kind": "inline_judge",
              "data": { "verdict_expr": expr, "on_failure": "error" } },
        ],
        "edges": [
            { "source": "classify", "target": "coverage_judge" },
            { "source": "feedback", "target": "coverage_judge" },
        ],
    })
    .to_string()
}

fn wf() -> Uuid {
    Uuid::new_v4()
}

fn case(name: &str, v: JsonValue) -> ProbeCase {
    ProbeCase {
        name: name.to_string(),
        binding: CaseBinding::SingleParent(v),
    }
}

fn parents_case(name: &str, v: JsonValue) -> ProbeCase {
    ProbeCase {
        name: name.to_string(),
        binding: CaseBinding::Parents(v.as_object().cloned().expect("object")),
    }
}

fn input(node: &str, cases: Vec<ProbeCase>) -> ProbeInput {
    ProbeInput {
        workflow_id: wf(),
        node_ref: node.to_string(),
        cases,
        verdict_expr_override: None,
    }
}

/// A verdict expression in the real shape — score/passed/reasoning/feedback.
const COVERAGE_EXPR: &str = r#"#{ score: if covered >= total { 1.0 } else { 0.2 },
     passed: covered >= total, reasoning: "coverage", feedback: "" }"#;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Arity binding
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn single_parent_binds_the_output_unwrapped_and_unkeyed() {
    let g = single_parent_graph(COVERAGE_EXPR, None, "error");
    let out = probe_graph(
        &g,
        &input(
            "coverage_judge",
            vec![
                case("full", json!({ "covered": 5, "total": 5 })),
                case("under", json!({ "covered": 2, "total": 5 })),
            ],
        ),
    )
    .expect("probe runs");

    assert_eq!(out.parents, vec!["coverage".to_string()]);
    assert_eq!(
        out.cases[0].scope_source,
        ScopeSource::SingleParentUnwrapped
    );
    // The PARENT'S FIELDS are the scope variables — not the parent's label.
    assert_eq!(out.cases[0].scope_keys, vec!["covered", "total"]);
    assert!(out.cases[0].passed_effective);
    assert!(!out.cases[1].passed_effective);
    assert_eq!(out.cases[1].branch, Branch::Error);
}

#[test]
fn multi_parent_scope_is_keyed_by_node_label() {
    let expr = r#"#{ score: if classify.classifications.len() >= feedback.count { 1.0 } else { 0.0 },
        passed: classify.classifications.len() >= feedback.count,
        reasoning: "coverage", feedback: "" }"#;
    let g = multi_parent_graph(expr);
    let out = probe_graph(
        &g,
        &input(
            "coverage_judge",
            vec![
                parents_case(
                    "covered",
                    json!({
                        "classify": { "classifications": ["a", "b"] },
                        "feedback": { "count": 2 },
                    }),
                ),
                parents_case(
                    "under_covered",
                    json!({
                        "classify": { "classifications": ["a"] },
                        "feedback": { "count": 2 },
                    }),
                ),
            ],
        ),
    )
    .expect("probe runs");

    assert_eq!(out.cases[0].scope_source, ScopeSource::MultiParentLabeled);
    // The LABELS are the scope variables. Binding by UUID (the
    // `gather_inputs` fallback when a label is missing) would make both
    // `classify` and `feedback` unbound and every case would eval-error.
    let mut keys = out.cases[0].scope_keys.clone();
    keys.sort();
    assert_eq!(keys, vec!["classify", "feedback"]);
    assert_eq!(out.cases[0].eval_error, None, "labels must be bound");
    assert!(out.cases[0].passed_effective);
    assert!(!out.cases[1].passed_effective);
    assert!(out.summary.can_fail, "the judge CAN reject — not saturated");
}

#[test]
fn unknown_parent_label_errors_loudly_and_names_the_real_parents() {
    let g = multi_parent_graph(COVERAGE_EXPR);
    let err = probe_graph(
        &g,
        &input(
            "coverage_judge",
            vec![parents_case(
                "typo",
                json!({ "classifier": {}, "feedback": {} }),
            )],
        ),
    )
    .expect_err("unknown label must reject");
    let msg = err.to_string();
    assert!(msg.contains("classifier"), "{msg}");
    assert!(
        msg.contains("classify"),
        "must name the real parents: {msg}"
    );
    assert!(msg.contains("feedback"), "{msg}");
    assert_eq!(err.jsonrpc_code(), -32602);
}

#[test]
fn missing_parent_errors_rather_than_silently_changing_arity() {
    let g = multi_parent_graph(COVERAGE_EXPR);
    let err = probe_graph(
        &g,
        &input(
            "coverage_judge",
            vec![parents_case("partial", json!({ "classify": {} }))],
        ),
    )
    .expect_err("a missing parent must reject");
    let msg = err.to_string();
    assert!(msg.contains("missing parent 'feedback'"), "{msg}");
    assert!(msg.contains("single-parent binding"), "{msg}");
}

/// The trap, pointed the other way: a label-keyed case on a ONE-parent node
/// would bind the label as a scope variable production never binds, so an
/// expression reading `coverage.covered` would PASS here and abort at
/// runtime. That false pass is the exact failure this tool exists to prevent.
#[test]
fn label_keyed_case_on_a_single_parent_node_is_refused() {
    let g = single_parent_graph(COVERAGE_EXPR, None, "error");
    let err = probe_graph(
        &g,
        &input(
            "coverage_judge",
            vec![parents_case(
                "wrong_shape",
                json!({ "coverage": { "covered": 1, "total": 5 } }),
            )],
        ),
    )
    .expect_err("label-keyed on a single-parent node must reject");
    let msg = err.to_string();
    assert!(msg.contains("exactly ONE parent"), "{msg}");
    assert!(msg.contains("coverage"), "{msg}");
}

#[test]
fn bare_case_on_a_multi_parent_node_is_refused() {
    let g = multi_parent_graph(COVERAGE_EXPR);
    let err = probe_graph(
        &g,
        &input(
            "coverage_judge",
            vec![case("bare", json!({ "covered": 1 }))],
        ),
    )
    .expect_err("bare binding on a multi-parent node must reject");
    let msg = err.to_string();
    assert!(msg.contains("KEYED BY NODE LABEL"), "{msg}");
    assert!(msg.contains("classify"), "{msg}");
}

#[test]
fn a_judge_with_no_parents_is_refused_with_the_reason() {
    let g = json!({
        "nodes": [
            { "id": "solo", "type": "system:inline_judge", "kind": "inline_judge",
              "data": { "verdict_expr": COVERAGE_EXPR, "on_failure": "error" } },
        ],
        "edges": [],
    })
    .to_string();
    let err = probe_graph(&g, &input("solo", vec![case("x", json!({}))]))
        .expect_err("no parents must reject");
    assert!(err.to_string().contains("no incoming edges"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. unwrap_output parity
// ─────────────────────────────────────────────────────────────────────────────

/// The engine strips the `{config, input: {...}}` worker envelope before
/// binding. A probe that bound the raw value would put `config`/`input` in
/// scope and leave `covered`/`total` unbound.
#[test]
fn envelope_shaped_parent_output_is_unwrapped() {
    let g = single_parent_graph(COVERAGE_EXPR, None, "error");
    let wrapped = json!({
        "covered": 5,
        "total": 5,
        "input": { "covered": 5, "total": 5 },
    });
    let out = probe_graph(&g, &input("coverage_judge", vec![case("wrapped", wrapped)]))
        .expect("probe runs");
    assert_eq!(out.cases[0].eval_error, None);
    let mut keys = out.cases[0].scope_keys.clone();
    keys.sort();
    assert_eq!(
        keys,
        vec!["covered", "total"],
        "the engine's unwrap_output must have stripped the envelope"
    );
    assert!(out.cases[0].passed_effective);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Verdict parse + threshold
// ─────────────────────────────────────────────────────────────────────────────

/// Pins the doc corrected at `engine_dispatch_subflow.rs`: a non-object
/// verdict does NOT error. It parses with four malformed fields and routes as
/// an ordinary rejection.
#[test]
fn non_object_verdict_is_malformed_four_and_routes_as_rejection() {
    let g = single_parent_graph("true", None, "error");
    let out = probe_graph(
        &g,
        &input("coverage_judge", vec![case("bare_true", json!({}))]),
    )
    .expect("probe runs");
    let c = &out.cases[0];
    assert_eq!(c.eval_error, None, "a bare `true` evaluates fine");
    assert_eq!(c.raw_verdict, Some(json!(true)));
    assert_eq!(c.malformed_field_count, 4);
    assert_eq!(c.score, 0.0);
    assert!(!c.passed_effective);
    assert_eq!(c.branch, Branch::Error);
    assert_eq!(c.envelope["__error"], json!(true));
    assert!(!c.verdict_present, "a bare bool carries no verdict");
}

/// The commonest authoring mistake: writing the CONDITION as the whole
/// `verdict_expr`. It evaluates fine, rejects every input, and would be
/// certified as "a real gate" by a `can_fail` that only looked at
/// `passed_effective` — the exact misleading-report class this tool exists to
/// catch, pointed at the tool itself.
#[test]
fn a_bare_condition_expression_rejects_everything_and_is_not_can_fail() {
    let g = single_parent_graph("covered >= total", None, "error");
    let out = probe_graph(
        &g,
        &input(
            "coverage_judge",
            vec![
                case("full", json!({ "covered": 5, "total": 5 })),
                case("under", json!({ "covered": 1, "total": 5 })),
            ],
        ),
    )
    .expect("probe runs");

    // BOTH cases reject — including the one that should obviously pass.
    assert_eq!(out.cases[0].raw_verdict, Some(json!(true)));
    assert!(!out.cases[0].passed_effective, "even `true` rejects");
    assert!(!out.cases[1].passed_effective);
    for c in &out.cases {
        assert_eq!(c.eval_error, None, "the expression itself is fine");
        assert!(!c.verdict_present);
    }

    assert!(
        !out.summary.can_fail,
        "rejecting EVERY input is not evidence the rubric discriminates"
    );
    assert_eq!(out.summary.verdictless_rejections, 2, "counted separately");
    assert_eq!(out.summary.eval_errors, 0, "not an evaluation failure");
    assert!(!out.summary.all_pass);
}

/// A rejection with SOME malformed fields is still a real rubric rejection —
/// the exclusion must key on "carried no verdict", not on "malformed at all".
#[test]
fn a_partially_malformed_but_real_rejection_still_counts_as_can_fail() {
    // No `reasoning`, no `feedback` → malformed 2, but `passed` is genuine.
    let g = single_parent_graph("#{ score: 0.2, passed: false }", None, "error");
    let out =
        probe_graph(&g, &input("coverage_judge", vec![case("x", json!({}))])).expect("probe runs");
    assert_eq!(out.cases[0].malformed_field_count, 2);
    assert!(out.cases[0].verdict_present);
    assert!(out.summary.can_fail, "the rubric really did reject");
    assert_eq!(out.summary.verdictless_rejections, 0);
}

/// `carries_a_verdict` reads the verdict directly — the one spot in this
/// crate that does. Cross-check it against the real parse so a change to
/// `from_collapsed`'s accessors fails here instead of silently re-arming the
/// false `can_fail`.
#[test]
fn verdict_presence_matches_from_collapsed() {
    // Carries nothing usable → `from_collapsed` defaults BOTH gate fields.
    for v in [
        json!(true),
        json!(42),
        json!("verdict"),
        json!([1, 2]),
        json!({}),
        json!(null),
        json!({ "reasoning": "why", "feedback": "fix" }),
        json!({ "score": "0.5", "passed": "true" }), // present but wrong-typed
    ] {
        assert!(!carries_a_verdict(&v), "{v}");
        let parsed = JudgeVerdict::from_collapsed(&v);
        assert_eq!(parsed.score, 0.0, "{v}");
        assert!(!parsed.passed, "{v}");
        assert!(parsed.malformed_field_count >= 2, "{v}");
    }
    // Carries at least one → the parse reflects the input, not a default.
    assert!(carries_a_verdict(&json!({ "score": 0.75 })));
    assert!((JudgeVerdict::from_collapsed(&json!({ "score": 0.75 })).score - 0.75).abs() < 1e-9);
    assert!(carries_a_verdict(&json!({ "passed": true })));
    assert!(JudgeVerdict::from_collapsed(&json!({ "passed": true })).passed);
}

/// The evaluator pushes `ctx` / `inputs` AFTER the parent keys, so a parent
/// LABELLED `ctx` is shadowed — `ctx.field` reads the whole context, not that
/// parent. Production does the same thing (the envelope assert pins it); what
/// must not happen is the probe listing `ctx` as a usable variable, since
/// diagnosing exactly this class of trap is the tool's job.
#[test]
fn a_parent_labelled_ctx_is_reported_as_shadowed() {
    let expr =
        r#"#{ score: 1.0, passed: ctx.marker == "from_parent", reasoning: "", feedback: "" }"#;
    let g = json!({
        "nodes": [
            { "id": "ctx", "type": MODULE, "data": {} },
            { "id": "other", "type": MODULE, "data": {} },
            { "id": "j", "type": "system:inline_judge", "kind": "inline_judge",
              "data": { "verdict_expr": expr, "on_failure": "error" } },
        ],
        "edges": [ { "source": "ctx", "target": "j" }, { "source": "other", "target": "j" } ],
    })
    .to_string();
    let bound = json!({ "ctx": { "marker": "from_parent" }, "other": { "x": 1 } });
    let out =
        probe_graph(&g, &input("j", vec![parents_case("c", bound.clone())])).expect("probe runs");
    let c = &out.cases[0];

    assert!(c.scope_keys.contains(&"ctx".to_string()));
    assert_eq!(
        c.shadowed_scope_keys,
        vec!["ctx".to_string()],
        "the key is bound but unreachable — say so"
    );
    assert!(
        !c.passed_effective,
        "`ctx.marker` reads the context object, not the parent"
    );
    // ...and the engine agrees, which is why the probe reports rather than
    // "fixes" the collision.
    let mut engine = ParallelWorkflowEngine::new();
    engine.set_expression_evaluator(Arc::new(
        talos_engine::expression_evaluator::RhaiEvaluator::new(),
    ));
    assert_eq!(
        c.envelope,
        engine.dispatch_inline_judge(bound, expr, None, "error")
    );
    assert!(
        RESERVED_SCOPE_NAMES.contains(&"inputs"),
        "the sibling reserved name is covered by the same rule"
    );
}

#[test]
fn not_applicable_true_false_and_mistyped() {
    let abstain = r#"#{ score: 1.0, passed: true, not_applicable: total == 0,
        reasoning: "", feedback: "" }"#;
    let g = single_parent_graph(abstain, None, "error");
    let out = probe_graph(
        &g,
        &input(
            "coverage_judge",
            vec![
                case("empty", json!({ "total": 0 })),
                case("busy", json!({ "total": 4 })),
            ],
        ),
    )
    .expect("probe runs");
    assert!(out.cases[0].not_applicable);
    assert_eq!(out.cases[0].malformed_field_count, 0);
    assert!(!out.cases[1].not_applicable);
    assert!(out.summary.can_abstain);
    // Abstention changes RECORDING, never routing — both still pass.
    assert!(out.cases[0].passed_effective && out.cases[1].passed_effective);
    assert!(out.summary.all_pass);
    assert!(!out.summary.can_fail);

    // Mistyped: the author meant to abstain and got the type wrong. Reads
    // false AND counts as malformed — the whole reason the field is echoed.
    let mistyped = r#"#{ score: 1.0, passed: true, not_applicable: "true",
        reasoning: "", feedback: "" }"#;
    let g = single_parent_graph(mistyped, None, "error");
    let out =
        probe_graph(&g, &input("coverage_judge", vec![case("x", json!({}))])).expect("probe runs");
    assert!(!out.cases[0].not_applicable);
    assert_eq!(out.cases[0].malformed_field_count, 1);
}

#[test]
fn threshold_can_flip_a_self_declared_pass_to_a_rejection() {
    let expr = r#"#{ score: 0.6, passed: true, reasoning: "ok", feedback: "" }"#;
    let g = single_parent_graph(expr, Some(0.8), "error");
    let out =
        probe_graph(&g, &input("coverage_judge", vec![case("x", json!({}))])).expect("probe runs");
    let c = &out.cases[0];
    assert!(c.passed_raw, "the verdict declared itself passing");
    assert_eq!(c.pass_threshold, Some(0.8));
    assert!(!c.passed_effective, "0.6 < 0.8 → the gate rejects");
    assert!(out.summary.can_fail);
}

#[test]
fn passthrough_on_failure_reports_the_passthrough_branch() {
    let expr = r#"#{ score: 0.1, passed: false, reasoning: "weak", feedback: "more" }"#;
    let g = single_parent_graph(expr, None, "passthrough");
    let out = probe_graph(
        &g,
        &input("coverage_judge", vec![case("x", json!({ "a": 1 }))]),
    )
    .expect("probe runs");
    let c = &out.cases[0];
    assert_eq!(c.branch, Branch::Passthrough);
    assert_eq!(c.envelope["__judge_rejected__"], json!(true));
    assert_eq!(c.envelope["a"], json!(1), "parent output forwarded");
    assert!(c.envelope.get("__error").is_none());
}

/// An expression failure is NOT a demonstration that the judge can fail: a
/// broken expression rejects everything for the wrong reason.
#[test]
fn expression_failure_is_reported_and_excluded_from_can_fail() {
    // `missing_var` is not in scope — the runtime aborts identically.
    let g = single_parent_graph("missing_var > 3", None, "error");
    let out = probe_graph(
        &g,
        &input("coverage_judge", vec![case("x", json!({ "a": 1 }))]),
    )
    .expect("probe runs");
    let c = &out.cases[0];
    assert!(c.eval_error.is_some());
    assert_eq!(c.branch, Branch::Error);
    assert!(c.raw_verdict.is_none());
    assert!(c.envelope["error_message"]
        .as_str()
        .unwrap()
        .starts_with("InlineJudge expression failed:"));
    assert!(!out.summary.can_fail, "a broken expr is not a working gate");
    assert_eq!(out.summary.eval_errors, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Summary math
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn summary_reports_can_fail_can_abstain_and_all_pass() {
    let expr = r#"#{ score: if n > 0 { 1.0 } else { 0.0 }, passed: n > 0,
        not_applicable: n == -1, reasoning: "", feedback: "" }"#;
    let g = single_parent_graph(expr, None, "error");
    let out = probe_graph(
        &g,
        &input(
            "coverage_judge",
            vec![
                case("pass", json!({ "n": 3 })),
                case("fail", json!({ "n": 0 })),
                case("abstain", json!({ "n": -1 })),
            ],
        ),
    )
    .expect("probe runs");
    assert_eq!(out.summary.cases, 3);
    assert!(out.summary.can_fail);
    assert!(out.summary.can_abstain);
    assert!(!out.summary.all_pass);
    assert_eq!(out.summary.eval_errors, 0);

    // The saturated shape: every case passes, nothing abstains, nothing fails.
    let g = single_parent_graph(
        r#"#{ score: 1.0, passed: true, reasoning: "", feedback: "" }"#,
        None,
        "error",
    );
    let out = probe_graph(
        &g,
        &input(
            "coverage_judge",
            vec![case("a", json!({})), case("b", json!({ "n": 0 }))],
        ),
    )
    .expect("probe runs");
    assert!(out.summary.all_pass);
    assert!(!out.summary.can_fail);
    assert!(!out.summary.can_abstain);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Caps + node resolution + override
// ─────────────────────────────────────────────────────────────────────────────

// ── parse_cases: the wire-shape gate the MCP handler delegates to ──────────

#[test]
fn parse_cases_reads_both_shapes_and_defaults_the_name() {
    let cases = parse_cases(&[
        json!({ "input": { "covered": 1 } }),
        json!({ "name": "  named  ", "parents": { "a": 1, "b": 2 } }),
    ])
    .expect("both shapes parse");
    assert_eq!(cases[0].name, "case_0", "index-defaulted");
    assert!(matches!(cases[0].binding, CaseBinding::SingleParent(_)));
    assert_eq!(cases[1].name, "named", "trimmed");
    assert!(matches!(cases[1].binding, CaseBinding::Parents(_)));
}

#[test]
fn parse_cases_rejects_ambiguous_empty_and_oversized_input() {
    // Both shapes at once is ambiguous — which arity did the caller mean?
    let err = parse_cases(&[json!({ "input": 1, "parents": {} })]).unwrap_err();
    assert!(err.contains("both 'input' and 'parents'"), "{err}");
    // Neither.
    let err = parse_cases(&[json!({ "name": "x" })]).unwrap_err();
    assert!(err.contains("must set 'input'"), "{err}");
    // Wrong container type.
    let err = parse_cases(&[json!("just a string")]).unwrap_err();
    assert!(err.contains("must be an object"), "{err}");
    let err = parse_cases(&[json!({ "parents": [1, 2] })]).unwrap_err();
    assert!(err.contains("keyed by parent node label"), "{err}");
    // Caps, enforced here so every protocol inherits them.
    assert!(parse_cases(&[]).unwrap_err().contains("at least one case"));
    let many: Vec<JsonValue> = (0..=MAX_CASES).map(|_| json!({ "input": {} })).collect();
    assert!(parse_cases(&many).unwrap_err().contains("at most 20 cases"));
}

#[test]
fn more_than_twenty_cases_is_refused() {
    let g = single_parent_graph(COVERAGE_EXPR, None, "error");
    let cases: Vec<ProbeCase> = (0..=MAX_CASES)
        .map(|i| case(&i.to_string(), json!({})))
        .collect();
    let err = probe_graph(&g, &input("coverage_judge", cases)).expect_err("21 cases must reject");
    assert!(err.to_string().contains("at most 20 cases"));
    assert_eq!(err.jsonrpc_code(), -32602);
}

#[test]
fn zero_cases_is_refused() {
    let g = single_parent_graph(COVERAGE_EXPR, None, "error");
    let err = probe_graph(&g, &input("coverage_judge", vec![])).expect_err("0 cases must reject");
    assert!(matches!(err, ProbeError::NoCases));
}

/// The persisted validator allows 8 KiB; the probe must not re-cap below it
/// or long-but-legal judges become unprobeable.
#[test]
fn an_expression_longer_than_2000_chars_still_probes() {
    let padding = " ".repeat(3000);
    let expr = format!(
        r#"#{{ score: 1.0, passed: true, reasoning: "{}", feedback: "" }}"#,
        "x".repeat(2500)
    );
    let expr = format!("{expr}{padding}");
    assert!(expr.len() > 2000);
    assert!(expr.len() <= talos_workflow_types::MAX_RHAI_EXPRESSION_BYTES);
    let g = single_parent_graph(&expr, None, "error");
    let out = probe_graph(&g, &input("coverage_judge", vec![case("x", json!({}))]))
        .expect("a >2000-char expression still probes");
    assert!(out.cases[0].passed_effective);
}

#[test]
fn override_is_held_to_the_persisted_validators_bound() {
    let g = single_parent_graph(COVERAGE_EXPR, None, "error");
    let mut i = input("coverage_judge", vec![case("x", json!({}))]);
    i.verdict_expr_override = Some("x".repeat(talos_workflow_types::MAX_RHAI_EXPRESSION_BYTES + 1));
    let err = probe_graph(&g, &i).expect_err("oversized override must reject");
    assert!(err.to_string().contains("at most 8192 bytes"), "{err}");

    i.verdict_expr_override = Some("   ".to_string());
    let err = probe_graph(&g, &i).expect_err("blank override must reject");
    assert!(err.to_string().contains("empty or whitespace-only"));
}

/// The iterate-on-a-fix loop: probe a candidate expression without writing
/// it to the graph, and have the outcome SAY the graph wasn't what ran.
#[test]
fn override_runs_instead_of_the_graph_expression_and_is_flagged() {
    // The persisted expression can never fail.
    let g = single_parent_graph(
        r#"#{ score: 1.0, passed: true, reasoning: "", feedback: "" }"#,
        None,
        "error",
    );
    let mut i = input("coverage_judge", vec![case("under", json!({ "n": 0 }))]);
    let out = probe_graph(&g, &i).expect("probe runs");
    assert!(!out.used_expr_override);
    assert!(!out.summary.can_fail, "the persisted judge is saturated");

    i.verdict_expr_override = Some(
        r#"#{ score: if n > 0 { 1.0 } else { 0.0 }, passed: n > 0, reasoning: "", feedback: "" }"#
            .to_string(),
    );
    let out = probe_graph(&g, &i).expect("probe runs");
    assert!(out.used_expr_override, "the caller must be told");
    assert!(out.summary.can_fail, "the candidate fix CAN reject");
}

#[test]
fn node_resolves_by_label_or_by_engine_uuid() {
    let g = single_parent_graph(COVERAGE_EXPR, None, "error");
    let by_label = probe_graph(&g, &input("coverage_judge", vec![case("x", json!({}))]))
        .expect("resolves by label");
    // The digest's probe pointer carries the engine UUID from `judge_scores`.
    let by_uuid = probe_graph(
        &g,
        &input(&by_label.node_id.to_string(), vec![case("x", json!({}))]),
    )
    .expect("resolves by engine uuid");
    assert_eq!(by_uuid.node_id, by_label.node_id);
    assert_eq!(by_uuid.node_label, "coverage_judge");
}

#[test]
fn unknown_node_names_the_graphs_judge_nodes() {
    let g = multi_parent_graph(COVERAGE_EXPR);
    let err = probe_graph(&g, &input("nope", vec![case("x", json!({}))]))
        .expect_err("unknown node must reject");
    let msg = err.to_string();
    assert!(msg.contains("coverage_judge"), "{msg}");
    assert!(!msg.contains("classify"), "only judge nodes listed: {msg}");
}

#[test]
fn a_subworkflow_judge_node_points_at_the_contract_tool() {
    let g = json!({
        "nodes": [
            { "id": "brief", "type": MODULE, "data": {} },
            { "id": "brief_judge", "type": "system:judge", "kind": "judge",
              "data": { "judge_workflow_id": MODULE, "rubric": "is it good" } },
        ],
        "edges": [ { "source": "brief", "target": "brief_judge" } ],
    })
    .to_string();
    let err = probe_graph(&g, &input("brief_judge", vec![case("x", json!({}))]))
        .expect_err("a sub-workflow judge is not probeable here");
    let msg = err.to_string();
    assert!(msg.contains("test_subworkflow_contract"), "{msg}");
}

#[test]
fn internal_errors_do_not_leak_detail() {
    let err = ProbeError::Internal("relation \"judge_scores\" does not exist".to_string());
    assert_eq!(err.user_facing_message(), "Internal error");
    assert_eq!(err.jsonrpc_code(), -32000);
    // ...and a cross-tenant probe is indistinguishable from a missing one.
    assert_eq!(
        ProbeError::WorkflowNotFound.user_facing_message(),
        "workflow not found or access denied"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Mutation guards: sandbox limits + envelope parity
// ─────────────────────────────────────────────────────────────────────────────

/// The probe's fidelity claim rests on inheriting the PRODUCTION Rhai limits.
/// A fresh `rhai::Engine` has no operation cap, so an expression that aborts
/// at runtime would silently succeed in the probe — certifying a judge that
/// errors on every real run. 1000 operations is the
/// `rhai_helpers::RHAI_ENGINE` ceiling.
#[test]
fn operation_limit_is_inherited_from_the_production_sandbox() {
    let runaway = r#"let n = 0; for i in 0..100000 { n += 1; }
        #{ score: 1.0, passed: true, reasoning: "", feedback: "" }"#;
    let g = single_parent_graph(runaway, None, "error");
    let out =
        probe_graph(&g, &input("coverage_judge", vec![case("x", json!({}))])).expect("probe runs");
    let c = &out.cases[0];
    let err = c
        .eval_error
        .as_deref()
        .expect("the 1000-operation cap must abort this expression");
    assert!(
        err.to_lowercase().contains("operation"),
        "expected an operations-limit abort, got: {err}"
    );
    assert_eq!(c.branch, Branch::Error);
    assert!(!out.summary.can_fail);
}

/// `eval` is disabled and there is no module resolver in the production
/// sandbox — a probe that built its own engine would likely restore both.
#[test]
fn dynamic_code_execution_stays_disabled() {
    let g = single_parent_graph(r#"eval("1 + 1")"#, None, "error");
    let out =
        probe_graph(&g, &input("coverage_judge", vec![case("x", json!({}))])).expect("probe runs");
    assert!(
        out.cases[0].eval_error.is_some(),
        "eval() must not be callable"
    );
}

/// The end-to-end fidelity pin: for the same bound inputs, the probe's
/// envelope must equal what `ParallelWorkflowEngine::dispatch_inline_judge`
/// produces with the production evaluator wired — the function the scheduler
/// actually calls. Any drift in threshold handling, branch selection, or
/// envelope keys fails here.
#[test]
fn probe_matches_dispatch_inline_judge() {
    let cases: Vec<(&str, Option<f64>, &str, JsonValue)> = vec![
        // (expr, threshold, on_failure, parent output)
        (
            r#"#{ score: 1.0, passed: true, reasoning: "ok", feedback: "" }"#,
            None,
            "error",
            json!({ "covered": 5, "total": 5 }),
        ),
        (
            r#"#{ score: 0.6, passed: true, reasoning: "meh", feedback: "more" }"#,
            Some(0.8),
            "error",
            json!({ "covered": 3, "total": 5 }),
        ),
        (
            r#"#{ score: 0.1, passed: false, reasoning: "weak", feedback: "redo" }"#,
            None,
            "passthrough",
            json!({ "covered": 0, "total": 5, "__judge_rejected__": false }),
        ),
        (
            r#"#{ score: 1.0, passed: true, not_applicable: true, reasoning: "empty", feedback: "" }"#,
            None,
            "passthrough",
            json!({ "n": 0 }),
        ),
        ("true", None, "error", json!({ "n": 1 })),
        ("missing_var", None, "error", json!({ "n": 1 })),
    ];

    for (expr, threshold, on_failure, parent) in cases {
        let g = single_parent_graph(expr, threshold, on_failure);
        let probed = probe_graph(
            &g,
            &input("coverage_judge", vec![case("c", parent.clone())]),
        )
        .expect("probe runs");

        // The production path, with the real Rhai evaluator wired.
        let mut engine = ParallelWorkflowEngine::new();
        engine.set_expression_evaluator(Arc::new(
            talos_engine::expression_evaluator::RhaiEvaluator::new(),
        ));
        let produced = engine.dispatch_inline_judge(parent.clone(), expr, threshold, on_failure);

        assert_eq!(
            probed.cases[0].envelope, produced,
            "probe envelope diverged from dispatch_inline_judge for expr `{expr}`"
        );
    }
}
