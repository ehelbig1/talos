# 2026-09-30 — a missing memory key no longer writes a WARN

**Defect.** Both signed-RPC handlers that return an error to the worker
(`talos.memory.op`, `talos.integration_state.op`) wrote an unconditional
`warn!("<label>: op failed")` carrying the error's `Debug`. `record_rpc_metric`
already logs every completion at a level derived from `RpcOutcome::class()`
(served → debug, declined → info, finding → warn; the class is also the
`class` metric label `TalosRPCSubjectFailing` selects on). So a declined
outcome produced TWO lines, the louder one contradicting the class decision.
The common case is `KeyNotFound` from the first `agent_memory::get` of a key
that has never been written — the documented "no memory yet" path. Seen live
on 2026-09-30 when the essay pipeline first read `essay_topics/covered`.

**Measured.** Over 7 days on the reference fleet (Prometheus,
`increase(talos_rpc_calls_total[7d])`): `talos.memory.op` 67 `ok`, 2
`not_found`; `talos.integration_state.op` none. Small in volume; each one was a
WARN on a fleet whose clean boot now produces one WARN.

**Fix.** ONE home `talos_rpc_subscribers::kernel::log_op_error`: the detail
line is `warn!` for a `Finding` and `debug!` otherwise (the `info!` "rpc
declined" line from `record_rpc_metric` already records the event, and the
counter counts it). Both handlers call it. The target and the rendered message
(`"memory RPC: op failed"`, `"integration-state RPC: op failed"`) are
unchanged, so existing log filters still match; an `outcome` field is added.

**Decisions.**
* **Declined goes to DEBUG, not INFO.** INFO would keep two lines per declined
  call; the error `Debug` for a decline (an `InvalidInput` reason) is useful
  only when debugging a module.
* **Findings keep the detail at WARN** — `Internal`, `Timeout`, `Unauthorized`
  and the rest carry a cause an operator needs.
* **No metric or alert change.** The counter already partitions these.

**Guards.** `the_op_error_line_is_loud_only_for_a_finding` drives the helper
over every `RpcOutcome` with and without the integration field;
`both_op_error_sites_route_through_the_helper` is a TEXTUAL pin over `lib.rs`
(no hand-written `op failed` line, exactly two helper calls) — on
`origin/main` the first count is 2, so it fails on the pre-fix tree.

**Stated limit.** The handlers themselves are not driven (they need NATS and
Postgres); the pin is what ties the helper to both call sites.

**Also on 2026-09-30, live config, not code.** `content-pipeline-weekly`'s
`weekly_idea` node gained `PROVIDER_OPTIONS.response_format` = a `json_schema`
(seven required keys, 4–6 sections of `{heading, bullets}`, length caps),
which the worker passes to Ollama's `format` as a grammar constraint.
`RESPONSE_FORMAT=json` alone was rehearsed first and returned valid JSON with
`call_to_action` missing, so JSON mode fixes syntax only. The node output
shape is unchanged (`{content, __memory_write__}`).
