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
//! `—` means the site did not set that limit, which is NOT the same as
//! unbounded in every column. `rhai::Limits::new()` leaves `num_operations`
//! and all three size caps at `None` — genuinely unbounded — but
//! `call_stack_depth` defaults to 64 in release builds (8 in debug). So
//! pinning `max_call_levels` to 16 tightens the dispatch site in production
//! rather than adding a cap where none existed.
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
//! # Size-cap semantics
//!
//! [`MAX_STRING_SIZE`] / [`MAX_ARRAY_SIZE`] / [`MAX_MAP_SIZE`] are easy to
//! misread as "bounds what the script BUILDS". They are not. What rhai
//! actually does (verified against rhai 1.24 `src/eval/data_check.rs`, and
//! pinned by `dispatch_size_cap_semantics` in
//! `talos-workflow-engine/src/scheduler_handlers.rs`):
//!
//! * The caps are **not** applied when the host pushes a value into scope.
//!   A 1 MB upstream node output lands in scope fine, and a *pure read* or
//!   *property navigation* of it — `route`, `inputs.route`,
//!   `nested.body`, `arr[0]`, `big == "z"` — succeeds.
//! * They **are** applied to the result of every function/operator call and
//!   to the `&mut` receiver of every method call. So a METHOD CALL on an
//!   oversized scope value fails: `big.len()`, `big.contains("x")`,
//!   `arr.len()`, `arr.filter(…)`, `wide.len()` →
//!   `ErrorDataTooLarge` ("Length of string too large", …).
//! * The accounting is **aggregate and recursive** (`calc_data_sizes` sums
//!   every nested string length, array element and map property). So
//!   `inputs.len()` fails when the total string content anywhere under
//!   `inputs` exceeds 64 KiB — even though `inputs` itself has five keys.
//!
//! Consequence for anyone routing a NEW call site through this builder: if
//! that site previously had no size caps, the caps are an observable change
//! for expressions that call a method on a large payload, and the failure
//! surfaces as a node error. Check the site's stored expressions before
//! routing it, the way `SandboxProfile::Dispatch` records having done.
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

/// Maximum total string bytes in a checked value.
///
/// Read the crate-level "Size-cap semantics" section before assuming what
/// this bounds — it is NOT only values the script builds.
pub const MAX_STRING_SIZE: usize = 65_536;

/// Maximum total array elements in a checked value.
///
/// See the crate-level "Size-cap semantics" section.
pub const MAX_ARRAY_SIZE: usize = 500;

/// Maximum total object-map properties in a checked value.
///
/// See the crate-level "Size-cap semantics" section.
pub const MAX_MAP_SIZE: usize = 500;

/// Operation cap for [`SandboxProfile::Expression`].
pub const EXPRESSION_MAX_OPERATIONS: u64 = 1_000;

/// Operation cap for [`SandboxProfile::Dispatch`].
pub const DISPATCH_MAX_OPERATIONS: u64 = 10_000;

/// Which operation budget a sandboxed engine gets.
///
/// Everything **except** the operation cap is identical across profiles —
/// the size caps, `max_call_levels`, no dynamic `eval`, no module resolver,
/// and the `print`/`debug` discard are the non-negotiable contract. A
/// profile exists only to name a deliberate operation-budget divergence, so
/// that a divergence can never again be incidental. In particular a profile
/// is **not** a place to relax a size cap: see the crate-level "Size-cap
/// semantics" section for what those caps do and do not reach, and read it
/// before routing a previously-uncapped site through this builder.
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
    /// normalised to 1 000, because narrowing a live operation cap can only
    /// ever break a working stored expression, never fix one. Re-budgeting
    /// dispatch expressions downward is a separate decision that wants its
    /// own blast-radius check against stored graphs.
    ///
    /// **The size caps ARE narrowed here, and that is a real behaviour
    /// change** — this site previously set no `max_string_size` /
    /// `max_array_size` / `max_map_size` / `max_call_levels` at all, so an
    /// expression calling a method on an oversized payload
    /// (`inputs.body.contains(…)` on a 100 KB body, `items.len()` on a
    /// 600-element array) now errors where it used to route. See the
    /// crate-level "Size-cap semantics" section for exactly which shapes,
    /// and `dispatch_size_cap_semantics` in
    /// `talos-workflow-engine/src/scheduler_handlers.rs` for the pin.
    ///
    /// It is accepted rather than deferred like the op cap, on two grounds:
    ///
    /// * **Blast radius measured, not assumed.** The live deployment stores
    ///   ZERO dispatch expressions (2026-07-29: no `dispatch_expression`
    ///   key in any row of `workflows` or `workflow_versions`), so nothing
    ///   observable regresses. Re-measure before assuming that still holds
    ///   on another deployment.
    /// * **Uncapped was a real hazard, not merely untidy.** With no string
    ///   cap, `let s = "x"; loop { s += s; }` reaches gigabytes inside the
    ///   10 000-operation budget — ~30 doublings, ~100 operations — so a
    ///   stored dispatch expression could OOM the controller. Every other
    ///   expression site has enforced these caps since long before this
    ///   crate; dispatch was the outlier.
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
    ///
    /// The import target is a REAL FILE, by ABSOLUTE path, and that is the
    /// whole point. `import "std"` — the obvious spelling — proves nothing:
    /// `FileModuleResolver` would also fail it, because there is no
    /// `std.rhai` on disk to resolve. Deleting `set_module_resolver` from
    /// the builder left such a test green (verified by mutation, 2026-07-29),
    /// i.e. the filesystem-reach removal this test exists to guard was not
    /// actually guarded. `FileModuleResolver::get_file_path` skips its
    /// `base_path` for an absolute path, so this import SUCCEEDS on an
    /// `Engine::new()` default resolver and can only fail on the dummy —
    /// which is what makes the assertion load-bearing.
    #[test]
    fn module_import_cannot_reach_a_real_file_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "talos-rhai-sandbox-import-probe-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let module = dir.join("probe.rhai");
        std::fs::write(&module, "export const answer = 42;").expect("write module");
        // rhai appends the `.rhai` extension itself.
        let import_path = dir.join("probe");
        let import_path = import_path.to_string_lossy().replace('\\', "/");

        // Control: the default resolver DOES load it — so the script below is
        // a genuine filesystem reach, not a no-op that fails for other
        // reasons. If this ever stops holding, the test below is vacuous
        // again and must be rewritten, not deleted.
        let script = format!(r#"import "{import_path}" as m; m::answer"#);
        let control = rhai::Engine::new().eval::<i64>(&script);
        assert_eq!(
            control.as_ref().ok().copied(),
            Some(42),
            "control: Engine::new()'s FileModuleResolver should have loaded \
             {import_path}.rhai — got {control:?}"
        );

        for profile in [SandboxProfile::Expression, SandboxProfile::Dispatch] {
            let e = sandboxed_engine(profile);
            assert!(
                e.eval::<i64>(&script).is_err(),
                "{profile:?}: the sandbox must not resolve a module from disk"
            );
            // The plain relative spelling stays blocked too.
            assert!(
                e.eval::<i64>(r#"import "std" as s; 1"#).is_err(),
                "import must be blocked under {profile:?}"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
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

#[cfg(test)]
mod why_the_size_caps_matter {
    /// The evidence behind accepting the size caps at the previously-uncapped
    /// dispatch site (see [`super::SandboxProfile::Dispatch`]): without a
    /// `max_string_size`, the 10 000-operation budget is nowhere near enough
    /// to bound MEMORY. Each doubling costs a handful of operations, so a
    /// stored expression could grow a string until the controller OOMs.
    ///
    /// This is the one place in the workspace that deliberately builds a raw
    /// `rhai::Engine::new()` besides the builder itself — it reconstructs the
    /// PRE-#614 dispatch config in order to demonstrate what it allowed. Do
    /// not copy it; production engines come from
    /// [`super::sandboxed_engine`]. (Lint check 63 skips this file, which is
    /// why it compiles here and nowhere else.)
    #[test]
    fn an_uncapped_engine_grows_megabytes_inside_the_operation_budget() {
        let mut e = rhai::Engine::new();
        e.set_max_operations(10_000);
        e.disable_symbol("eval");
        e.set_module_resolver(rhai::module_resolvers::DummyModuleResolver);
        e.on_print(|_| {});
        e.on_debug(|_, _, _| {});

        let bytes = e
            .eval::<i64>(r#"let s = "x"; for i in 0..24 { s += s; } s.len()"#)
            .expect("24 doublings fit inside a 10 000-operation budget");
        assert_eq!(bytes, 1 << 24, "16 MiB from a 1-byte seed");

        // The same script under the real builder is refused.
        let sandboxed = super::sandboxed_engine(super::SandboxProfile::Dispatch);
        let err = sandboxed
            .eval::<i64>(r#"let s = "x"; for i in 0..24 { s += s; } s.len()"#)
            .expect_err("the string cap must refuse unbounded growth");
        assert!(
            err.to_string().to_lowercase().contains("string"),
            "expected a string-too-large error, got: {err}"
        );
    }
}
