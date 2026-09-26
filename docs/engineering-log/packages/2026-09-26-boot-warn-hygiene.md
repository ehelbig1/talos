# 2026-09-26 — two WARNs that fired on every healthy boot

**Why.** The live verification of #960
(`docs/engineering-log/verification/2026-09-26-pr-960-live-verification.md`)
classified every WARN since the deploy. Two fired on every boot of a healthy
stack and described nothing wrong. That is check 69's trap: steady-state noise
teaches operators to skip WARNs.

## 1. `TALOS_MASTER_KEY_PREVIOUS env var is set to empty`

**Measured.** 1 line per controller boot. #960 made compose transport
`TALOS_MASTER_KEY_PREVIOUS: ${TALOS_MASTER_KEY_PREVIOUS:-}` so a key rotation
works from `.env`. Outside a rotation the variable is therefore always set and
empty. Of every variable read through `talos_config::read_env_or_file`, it is
the only one compose transports as `${VAR:-}`. The chart's optional
`secretKeyRef` leaves an absent key unset, so it does not produce the line.

**Decided.** `read_env_or_file` keeps the WARN for the case it was written for
(MCP-597): an empty `<VAR>` in front of a configured `<VAR>_FILE`, where the
operator should learn which source was used. With no file configured, an empty
value means "not configured", exactly like an unset one (check 73's rule), so it
logs at DEBUG. One home: `empty_env_shadows_a_file`. The return value is
unchanged in every case; only the log level moves.

**Deliberately NOT done.** Dropping the compose transport: #960 added it so the
staged master-key rotation can be driven from `.env`, and check 97 wants a
no-default variable transported.

## 2. `WIT world over-declared … declared_world=agent-node detected_world=agent`

**Measured.** 3 lines per boot, and 3 of 3 in the retained log have this
pair. That is the SAME world: `CapabilityWorld`'s `Display` is the short form
(`agent`) while sources declare the `-node` form, and the check compared the two
as strings with `eq_ignore_ascii_case`. Every exact match in `-node` spelling
fell through to the subset test, passed it, and was reported as benign
over-declaration.

**Decided.** One verdict in `talos-capability-world` (check 33's home for world
comparisons): `classify_world_declaration(declared, &detected) ->
WorldDeclaration { Matches, OverDeclared, Escalation }`. It keeps the old string
arm first, so nothing that used to match stops matching. Then it compares
PARSED worlds, but only when the declaration parses to a known world, because
`Unknown == Unknown` must never read as a match. The compile path's step 8a is
now the free function `reconcile_declared_world` (body moved verbatim), which
returns the failed `CompilationResult` on an escalation. That makes the
compile-time bait-and-switch refusal testable without a `cargo component` build;
nothing tested it before.

**Behaviour change, stated.** Only the same-world-other-spelling case moves, from
a WARN to silence. The escalation (refusal) set is unchanged, including every
`Unknown` case.

**Proof.** Every world in `CapabilityWorld::ALL`, in both spellings, is
`Matches`. The escalation arm is a security gate, so its mutations were proved:

| Mutation | Caught by |
|---|---|
| drop the `declared != Unknown` guard | `unknown_on_either_side_fails_closed` |
| every non-match is `OverDeclared` | escalation tests in both crates |
| the compile path never takes the refusal arm | `an_escalation_refuses_the_compile`, `an_unknown_detected_world_refuses_the_compile` |
| revert to the string compare (the defect) | `both_spellings_of_every_world_match` |

**Stated limits.** Neither log line is captured by a test: the level choice is
pinned through the pure helpers. The call from `compile_to_wasm` into
`reconcile_declared_world` is not driven by any test, because driving it needs
a real component build. This was already true of the inline block it replaced.
