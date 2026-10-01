# 2026-10-01 — a fuel budget can state what a byte costs

**Context.** `fuel_budget` sizes a module's `max_fuel` as
`baseline + 60 K per item + 2 fuel per input byte`, times a safety factor,
clamped to [1 M, 50 M]. Four tools take one (`compile_custom_sandbox`,
`hot_update_module`, `install_module_from_catalog`, `add_node_to_workflow`),
and so does a template's `recommended_fuel`.

**Measured.** A module that fetched 20 Gmail messages of about 60 KB was
budgeted 7.3 M; reading them took about 50 M, and its first rehearsal ran out.
A staged probe build over 10 messages (684 KB) put the cost per byte at:
receiving the HTTP body ~1.2, UTF-8 validation ~2.5, typed JSON parse ~7,
base64 decode ~30 per input character, scanning text or HTML ~36. So a module
that only fetches and typed-parses costs about 11 per byte; one that decodes
or scans what it fetched, 30–40 per byte it touches. Rewriting the loops
(iterator → indexed) and replacing the `base64` crate with a table decoder
changed nothing; only touching fewer bytes did.

The 2-per-byte default is not wrong for what it was calibrated on — small
typed items, where the fixed 60 K per item carries the cost (a 2 KB item is
budgeted about 32 fuel per byte overall). It fails for LARGE items, where the
per-byte term should dominate and does not.

**Change.** `fuel_budget` (and `recommended_fuel`) take an optional
`fuel_per_byte` (integer, clamped to 1–100, default 2).
`scaffold::compute_max_fuel_with_rates` is the formula with the rate stated;
the existing functions delegate to it with the default, so every budget
written before computes exactly what it did (pinned). The model-reply term
keeps the default rate. One shared sentence, `FUEL_PER_BYTE_GUIDANCE`, is the
field's description in all four tool schemas, and carries the measured
figures; a test fails if a tool that takes a `fuel_budget` does not declare
the field. The worked example in `compile_custom_sandbox`'s description was
arithmetically wrong (it said 2.5 M base for 20 × 8 KB; the formula gives
1.57 M) and is corrected.

**Decided.** The default stays 2. Raising it would move every limit that is
recomputed from a default-shaped budget, and the inverse translation
("handles ~N items") with it, for modules that are sized correctly today.

**Not built: fuel checkpoints.** The other half of this finding was that
nothing shows where a module's fuel went (it took two probe compiles and 14
rehearsals after three wrong guesses). A host function cannot report fuel
under the current bindings: host calls receive the context, not the store. It
would take registering one function with store access (as the gated
`wasi:http` handler is) plus a sink for guest log lines, which `test_module`
does not return today. Recorded as its own piece of work.

**Tests.** Formula: default rate is byte-identical to the old functions; a
stated rate scales the byte term only; clamps; overflow. Handler: a budget
without the field is unchanged, a non-integer is not a rate, stated rates size
the measured cases, and all four tools declare the field with the shared
sentence.
