//! The ONE Rhai sandbox builder for the whole workspace.
//!
//! Every `rhai::Engine` that will **evaluate** a stored or caller-authored
//! expression is constructed here, by [`sandboxed_engine`], so the
//! sandboxing contract is applied in exactly one place instead of being
//! re-typed per call site.
//!
//! # Why this crate exists
//!
//! Before 2026-07-29 there were four hand-rolled `rhai::Engine::new()`
//! configurations in the workspace and they had already drifted apart:
//!
//! | site | ops | call levels | string | array | map | print/debug |
//! |---|---|---|---|---|---|---|
//! | `talos-engine` shared engine | 1 000 | 16 | 65 536 | 500 | 500 | discarded (#613) |
//! | `scheduler_handlers::evaluate_dispatch_expression` | 10 000 | — | — | — | — | **stdout** |
//! | `talos-api` `testRhaiExpression` | 1 000 | 16 | 65 536 | 500 | — | **stdout** |
//!
//! The two `stdout` cells were a live DLP hole. `rhai::Engine::new()` wires
//! `print` and `debug` to `println!`, i.e. straight to the controller's
//! stdout and therefore its container logs, and every variable in an
//! expression's scope is upstream-node output — post-interpolation secrets,
//! email bodies, whatever the workflow carries. A stored dispatch
//! expression of `print(inputs); "some-workflow"` dumped the entire node
//! input past every DLP boundary the persistence path applies. #613 fixed
//! the shared engine; this crate closes the rest and makes the config
//! structurally un-driftable.
//!
//! # Why a leaf crate and not `talos-workflow-engine-core`
//!
//! The contract these limits implement is documented in
//! `talos-workflow-engine-core::expression` (the `ExpressionEvaluator`
//! trait's "Sandboxing contract" section), which made `-core` the obvious
//! candidate home. It does not work:
//!
//! * `talos-engine` **depends on** `talos-workflow-engine`, so the builder
//!   cannot live in `talos-engine` — `scheduler_handlers.rs` could not
//!   reach it without a dependency cycle.
//! * `-core` is depended on by 25 crates **including `worker/`**, the
//!   credential-free WASM runtime, which today links no scripting engine
//!   at all. Putting `rhai` in `-core` would pull it into the worker
//!   build for zero benefit.
//!
//! A leaf crate whose only dependency is `rhai` has neither problem: every
//! rhai-using crate can depend on it unconditionally, nothing else pays
//! for it, and no cycle is possible.
//!
//! # The lint
//!
//! `scripts/lint-structural.sh` check 63 asserts (a) this file installs the
//! `on_print` / `on_debug` discards and (b) no other file in the workspace
//! calls `rhai::Engine::new()`. A unit test cannot observe process stdout
//! from inside the same process without fd surgery, which is why the
//! discard half is a lint rather than a test.

#![forbid(unsafe_code)]

use rhai::Engine;

/// Maximum call / recursion depth. Bounds stack growth from a
/// pathological nested-call expression.
pub const MAX_CALL_LEVELS: usize = 16;

/// Maximum size (bytes) of any string **produced during** evaluation.
///
/// Note this bounds string *operations* (concatenation, formatting), not
/// the size of values pushed into scope by the caller — a 1 MB upstream
/// node output can still be read and compared, it just cannot be grown.
pub const MAX_STRING_SIZE: usize = 65_536;

/// Maximum number of elements in an array built during evaluation.
pub const MAX_ARRAY_SIZE: usize = 500;

/// Maximum number of properties in an object map built during evaluation.
pub const MAX_MAP_SIZE: usize = 500;

/// Operation cap for [`SandboxProfile::Expression`].
pub const EXPRESSION_MAX_OPERATIONS: u64 = 1_000;

/// Operation cap for [`SandboxProfile::Dispatch`].
pub const DISPATCH_MAX_OPERATIONS: u64 = 10_000;

/// Which operation budget a sandboxed engine gets.
///
/// Everything **except** the operation cap is identical across profiles —
/// the caps below, no dynamic `eval`, no module resolver, and the
/// `print`/`debug` discard are the non-negotiable contract. A profile
/// exists only to name a deliberate operation-budget divergence, so that
/// a divergence can never again be incidental.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxProfile {
    /// The default, and the budget the sandboxing contract in
    /// `talos-workflow-engine-core::expression` documents: 1 000
    /// operations.
    ///
    /// Covers edge conditions, retry conditions, retry-delay
    /// expressions, `Synthesize` transforms, judge `verdict_expr`s,
    /// actor approval-policy trigger conditions, and the
    /// `testRhaiExpression` authoring preview.
    Expression,

    /// `DynamicDispatch` node expressions: 10 000 operations.
    ///
    /// **This 10× divergence is inherited, not derived.** It arrived
    /// with `talos-workflow-engine/src/scheduler_handlers.rs` in
    /// `d50359c` ("fold talos-workflow-engine workspace into main repo")
    /// — the file was added whole from the sibling repo, so there is no
    /// commit that introduces the number, no design doc that justifies
    /// it, and (until this crate) no test that pinned it. Dispatch
    /// expressions in practice are property paths like
    /// `classifier.output.route`, which cost single-digit operations, so
    /// nothing observed needs the extra budget.
    ///
    /// It is nonetheless kept, as a NAMED profile rather than silently
    /// normalised to 1 000, because narrowing a live operation cap is the
    /// one change here that can only ever break a working stored
    /// expression. This change set is a no-behaviour-change security fix
    /// (it closes a stdout hole and *adds* the missing depth/size caps);
    /// re-budgeting dispatch expressions downward is a separate decision
    /// that wants its own blast-radius check against stored graphs.
    Dispatch,
}

impl SandboxProfile {
    /// The operation cap this profile grants.
    #[must_use]
    pub const fn max_operations(self) -> u64 {
        match self {
            Self::Expression => EXPRESSION_MAX_OPERATIONS,
            Self::Dispatch => DISPATCH_MAX_OPERATIONS,
        }
    }
}

/// Build a fully sandboxed `rhai::Engine`.
///
/// This is the only sanctioned way to construct an engine that will
/// **evaluate** an expression. A compile-only syntax check does not need
/// it: `rhai::Engine::new_raw()` registers no standard package and leaves
/// the `print`/`debug` handlers as `None`, so it cannot write to stdout
/// even in principle, and `Engine::compile` never dispatches a function
/// call at all.
///
/// The configuration applied, in full:
///
/// * `max_operations` — per [`SandboxProfile`]; bounds evaluation latency.
/// * `max_call_levels` = [`MAX_CALL_LEVELS`]; bounds stack growth.
/// * `max_string_size` = [`MAX_STRING_SIZE`],
///   `max_array_size` = [`MAX_ARRAY_SIZE`],
///   `max_map_size` = [`MAX_MAP_SIZE`]; bound memory growth.
/// * `disable_symbol("eval")` — no dynamic code execution, so a stored
///   expression cannot construct code at runtime and bypass the
///   save-time syntax check.
/// * `DummyModuleResolver` — `import` fails at evaluation time.
///   `Engine::new()` installs a `FileModuleResolver` (filesystem
///   access!), so this is a removal, not merely an explicit default.
/// * `on_print` / `on_debug` **discarded** — see the crate docs. Discarded
///   rather than `disable_symbol`ed: silencing keeps `print` a callable
///   no-op returning unit, so an expression that already contains one
///   keeps evaluating to the same verdict. Disabling the symbol would
///   turn it into a PARSE ERROR and convert a working stored expression
///   into a node failure on deploy.
#[must_use]
pub fn sandboxed_engine(profile: SandboxProfile) -> Engine {
    let mut engine = Engine::new();

    // Runaway-script bounds.
    engine.set_max_operations(profile.max_operations());
    engine.set_max_call_levels(MAX_CALL_LEVELS);
    engine.set_max_string_size(MAX_STRING_SIZE);
    engine.set_max_array_size(MAX_ARRAY_SIZE);
    engine.set_max_map_size(MAX_MAP_SIZE);

    // SECURITY: no dynamic code execution.
    engine.disable_symbol("eval");

    // SECURITY: no module resolver. `Engine::new()` installs a
    // `FileModuleResolver`, so replacing it with the dummy actively
    // removes filesystem reach rather than restating a default.
    engine.set_module_resolver(rhai::module_resolvers::DummyModuleResolver);

    // DLP: `Engine::new()` wires `print`/`debug` to `println!` — the same
    // stdout stream `tracing`'s `fmt::layer()` writes to, so anything they
    // emit lands in the controller's container logs. Discard both.
    engine.on_print(|_| {});
    engine.on_debug(|_, _, _| {});

    engine
}

#[cfg(test)]
mod config_parity_tests {
    use super::*;

    /// Pin every limit, per profile. This is the mutation guard: changing
    /// a cap in the builder without changing it here fails the suite, and
    /// changing both is then a visible, reviewable decision.
    #[test]
    fn expression_profile_limits_are_pinned() {
        let e = sandboxed_engine(SandboxProfile::Expression);
        assert_eq!(e.max_operations(), 1_000, "expression op cap");
        assert_eq!(e.max_call_levels(), 16, "call depth");
        assert_eq!(e.max_string_size(), 65_536, "string size");
        assert_eq!(e.max_array_size(), 500, "array size");
        assert_eq!(e.max_map_size(), 500, "map size");
    }

    /// The 10× dispatch budget, pinned so the decision recorded in
    /// [`SandboxProfile::Dispatch`]'s docs cannot drift silently in
    /// either direction. Before this crate the number lived only in a
    /// doc comment restating the literal on the line below it.
    #[test]
    fn dispatch_profile_differs_only_in_the_operation_cap() {
        let d = sandboxed_engine(SandboxProfile::Dispatch);
        assert_eq!(d.max_operations(), 10_000, "dispatch op cap (see docs)");

        // Every OTHER limit is identical to the Expression profile — the
        // profile names an operation-budget divergence and nothing else.
        let e = sandboxed_engine(SandboxProfile::Expression);
        assert_eq!(d.max_call_levels(), e.max_call_levels());
        assert_eq!(d.max_string_size(), e.max_string_size());
        assert_eq!(d.max_array_size(), e.max_array_size());
        assert_eq!(d.max_map_size(), e.max_map_size());
    }

    /// The constants and the engine the builder returns must agree — a
    /// consumer reading `MAX_STRING_SIZE` to size its own buffer must get
    /// the number the sandbox actually enforces.
    #[test]
    fn public_constants_match_the_built_engine() {
        for profile in [SandboxProfile::Expression, SandboxProfile::Dispatch] {
            let e = sandboxed_engine(profile);
            assert_eq!(e.max_operations(), profile.max_operations());
            assert_eq!(e.max_call_levels(), MAX_CALL_LEVELS);
            assert_eq!(e.max_string_size(), MAX_STRING_SIZE);
            assert_eq!(e.max_array_size(), MAX_ARRAY_SIZE);
            assert_eq!(e.max_map_size(), MAX_MAP_SIZE);
        }
    }
}

#[cfg(test)]
mod sandbox_behaviour_tests {
    use super::*;

    /// `eval` must be a parse error, not a callable function — otherwise a
    /// stored expression can construct code at runtime and bypass the
    /// save-time syntax check entirely.
    #[test]
    fn dynamic_eval_is_disabled() {
        for profile in [SandboxProfile::Expression, SandboxProfile::Dispatch] {
            let e = sandboxed_engine(profile);
            assert!(
                e.eval::<i64>(r#"eval("1 + 1")"#).is_err(),
                "eval must be blocked under {profile:?}"
            );
        }
    }

    /// `import` must fail: the dummy resolver replaces the
    /// `FileModuleResolver` that `Engine::new()` installs, so an
    /// expression cannot reach the filesystem.
    #[test]
    fn module_import_is_blocked() {
        for profile in [SandboxProfile::Expression, SandboxProfile::Dispatch] {
            let e = sandboxed_engine(profile);
            assert!(
                e.eval::<i64>(r#"import "std" as s; 1"#).is_err(),
                "import must be blocked under {profile:?}"
            );
        }
    }

    /// The operation cap actually bites, per profile — a busy loop is
    /// terminated rather than stalling the engine thread.
    #[test]
    fn the_operation_cap_terminates_a_runaway_loop() {
        for profile in [SandboxProfile::Expression, SandboxProfile::Dispatch] {
            let e = sandboxed_engine(profile);
            let err = e
                .eval::<i64>("let i = 0; loop { i += 1; } i")
                .expect_err("a `loop {}` with no exit must hit the operation cap");
            assert!(
                err.to_string().to_lowercase().contains("operation"),
                "{profile:?}: expected an operations-exceeded error, got: {err}"
            );
        }
    }

    /// `print` / `debug` are silenced but remain CALLABLE no-ops returning
    /// unit, so an expression that already contains one keeps producing
    /// exactly the same value. This is the half of the #613 fix a unit
    /// test can observe; that the output goes nowhere is enforced by
    /// lint check 63.
    #[test]
    fn print_and_debug_stay_callable_no_ops() {
        for profile in [SandboxProfile::Expression, SandboxProfile::Dispatch] {
            let e = sandboxed_engine(profile);
            assert_eq!(
                e.eval::<i64>(r#"print("sk-not-a-real-key"); 7"#)
                    .unwrap_or_else(|err| panic!(
                        "{profile:?}: print must not be a parse error: {err}"
                    )),
                7,
                "{profile:?}: print must not change the expression's value"
            );
            assert_eq!(
                e.eval::<i64>(r#"debug("sk-not-a-real-key"); 7"#)
                    .unwrap_or_else(|err| panic!(
                        "{profile:?}: debug must not be a parse error: {err}"
                    )),
                7,
                "{profile:?}: debug must not change the expression's value"
            );
        }
    }

    /// Ordinary expressions — the shapes real workflows store — evaluate
    /// identically under both profiles. Routing a call site to a profile
    /// must not change what a normal expression does.
    #[test]
    fn ordinary_expressions_agree_across_profiles() {
        let scripts = [
            "1 + 1",
            "if 5 > 3 { 10 } else { 20 }",
            r#""ab".len() + 1"#,
            "let a = [1, 2, 3]; a.len()",
        ];
        for script in scripts {
            let a = sandboxed_engine(SandboxProfile::Expression).eval::<i64>(script);
            let b = sandboxed_engine(SandboxProfile::Dispatch).eval::<i64>(script);
            assert_eq!(
                a.as_ref().ok(),
                b.as_ref().ok(),
                "profiles disagreed on `{script}`"
            );
            assert!(a.is_ok(), "`{script}` should evaluate: {a:?}");
        }
    }
}
