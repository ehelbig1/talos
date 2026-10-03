# test_module's description says what a run can reach

2026-10-03

## Why

`test_module`'s description said a run with no `actor_id` "defaults to
Tier-1 (local-egress-only)", so a module that calls an external API "will
fail with a network error unless the actor permits public egress". That was
the posture before 2026-09-10. Since then an in-process run with no actor has
public egress to the module's own granted hosts (and can never reach a
private address); checked on the reference deployment on 2026-10-03, where a
calendar read with no `actor_id` returned 200.

The description sent a caller looking for an actor they did not need, and
said nothing about the case that does refuse: an actor whose egress is
local-only gets no network at all in an in-process run.

## What changed

* `TEST_MODULE_NETWORK_NOTE` is the passage, as one constant: no actor →
  the module's granted public hosts, no external LLM provider; a bound actor
  → that actor's posture, with a local-only (or unreadable) scope meaning no
  network for the run; never a private address.
* A test holds each claim in the note to `in_process_egress_posture`, the
  function that decides it, so the posture cannot change without the note.
  A second holds the description to the note and to the absence of the
  sentences it replaced.
* `in_process_egress_posture`'s doc comment had ended up attached to the
  function above it (a function was inserted between the two); it is back on
  its own function.

## Not changed

The behaviour. `run_sandbox` and scratch sessions use the same posture
function; their descriptions did not carry the stale claim.
