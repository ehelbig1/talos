# A rehearsal can read an actor's memory without changing it (2026-10-14)

A keeper module that reads `work/kinds` with `agent_memory::get_entry` was
rehearsed through `test_module` and read an empty memory, while the actor held
the key. The only way to see it work on real state was a real run, which sends
notifications and writes.

## Found: the brief's premise is half right

* **`test_module` already takes `actor_id`.** It checks ownership and scopes
  every `agent_memory` call to that actor. In production the controller's
  in-process runtime has a NATS client, so those reads reach the actor's
  memory over the signed memory RPC, as a worker's do. Without `actor_id`, the
  run's actor is the caller's user id, which is no actor, so reads come back
  empty. That is the observed empty read, and the tool's description says so.
* **"Writes stay unapplied, as today" is not today.** With `actor_id`, a
  rehearsal's writes are applied: `set`, `delete` and `store_with_embedding`
  host calls go to the actor's live memory, and a returned `__memory_write__`
  is persisted through the engine's own hook. The code says so ("these are
  real durable writes, not simulated ones"). So a rehearsal could read real
  state only by also changing it.

The gap is a rehearsal that reads the actor's memory and writes nothing.

## Decided (built)

* **`test_module(memory_writes: "apply" | "discard")`**, with `actor_id`.
  `"apply"`, the default, is what an actor-scoped rehearsal has always done.
  With `"discard"`:
  * reads reach the actor as before;
  * each write is answered `Ok` and NOT sent. This happens after everything
    that decides whether the write MAY be made has run: the capability world,
    the actor's write ceiling and key validation. A write the ceiling refuses
    is still refused. The guest sees a write succeed; the actor's memory does
    not change;
  * a `__memory_write__` in the output is reported, not persisted.
* **The reply's `memory` lists what the run touched**, whenever an actor's
  memory is reached: `keys_read`, `prefixes_listed`, the number of searches,
  and the writes asked for (`op`, `key`), with `writes_applied`. Keys only:
  never a value, never a search query. At most 256 keys and 64 writes listed;
  the rest are counted.
* **One home:** `talos_worker_runtime::memory_rehearsal::MemoryRehearsal`,
  carried on `SecurityPolicy` and set on the context like `http_replay`. It is
  not a field of any wire message, so a dispatched job cannot carry one. The
  hooks are in the memory host functions themselves (`host/memory.rs`), the
  same functions a workflow run calls.
* **An unknown `memory_writes` value is refused** before the module is
  loaded.

## The operator's decision

**Does a rehearsal against an actor's memory need anything beyond
ownership?** And separately: should `"discard"` be the default for an
actor-scoped rehearsal?

* Ownership: built (it already was). The caller must own the actor; another
  user's actor reads exactly as a nonexistent one.
* Options beyond it: (1) nothing more; (2) one audit line per rehearsal naming
  the actor and the number of keys read (never the keys or values);
  (3) refuse a rehearsal for an actor whose write ceiling is `readonly` unless
  writes are discarded.
* Default: keeping `"apply"` changes nothing for existing callers. Making
  `"discard"` the default makes a rehearsal safe by default, but changes what
  `test_module(actor_id)` does to anyone who uses it to seed memory.

**Recommendation:** (2) ownership plus one audit line, as the brief proposes,
and make `"discard"` the default. A rehearsal that changes live state should be
the deliberate act, not the accident; `"apply"` stays one word away.

**Not built pending the answer:** the audit line, and any change of default.

## Mutations (memory access, tenancy)

* **M1.** Drop the discard return in the host `set`. **Red**: the discarded
  `set` lands a row.
* **M2.** Treat every actor as owned in `handle_test_module`. **Red**: the
  stranger's call goes past the check (to "Module not found").
* Both restored and touched; green.

## Tests

`controller/tests/memory_rehearsal_tests.rs`. These are integration tests: the
production memory host functions, signed RPC over a real NATS
(`TALOS_TEST_NATS_URL`), the real `spawn_memory_rpc_subscriber`, and Postgres.
The assertions are on the database. They form one test function with six
scenarios, because the memory crypto hook and HMAC key are process-wide (the
shape `rpc_write_ceiling_tests` uses):

* with `"discard"`, `get_entry` reads the actor's key, `set` and `delete`
  answer `Ok` and change no row, and the report names the keys and no value;
* with `"apply"`, the write lands, as before;
* without an actor, nothing is read, as before;
* a stranger's `test_module` with another user's actor gets the answer a
  nonexistent actor gets;
* an unknown `memory_writes` value is refused;
* with `"discard"`, a readonly actor's write is still refused.

Also `memory_rehearsal` unit tests (report shape, bounds) and
`memory_writes_is_apply_discard_or_refused`.

A real module could not be driven end to end: the workspace has no compiled
`.wasm` fixture and building one needs the component toolchain. What is
driven is every host function such a module calls, on the context
`test_module` builds.

## Stated limits

* `run_sandbox` also takes `actor_id` and is not given `memory_writes`; the
  brief named `test_module`.
* A host-call write is answered `Ok` without a round trip, so a write the
  CONTROLLER would refuse but the worker would not (its ceiling unset while
  the controller's is set) reads as accepted in a discarding rehearsal.
* `graph_search` (the `graph-memory` interface) is not recorded in the report.
