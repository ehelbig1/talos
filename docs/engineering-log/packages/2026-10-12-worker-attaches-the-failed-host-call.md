# The worker says a module's last call failed, when the module does not (2026-10-12)

A module that returns `Err("failed")` after a network error reaches the
controller as a failure classified `unknown`: not retried, and shown to the
operator as "unclassified". Five catalog templates were changed on
2026-10-12 to keep the HTTP failure kind in their own text
(`2026-10-12-templates-keep-http-failure-kind.md`); a module outside the
catalog still drops it. That record named this as the more complete fix.

## What already existed, and its bound

The worker latches the class of the last host-side HTTP failure and appends
`[reason_class=<token>]` to the module's error, but ONLY when the error text
carries the WIT discriminant the class explains (`networkerror`, …). That
bound is deliberate and is unchanged. Both classifiers check their transient
bucket before `auth_failure`, so a class stamped onto unrelated text turns
`401 Unauthorized [reason_class=dns]` into a retried failure, and the latch
is cleared by a later HTTP success and by nothing else.

## Decided

**A second, weaker marker: `[after_host_failure=<kind>]`.** It carries the
same fact with a weaker claim, and is bounded twice.

1. **The worker emits it only when the failed HTTP call was the LAST thing
   the module did with the outside world.** `TalosContext::host_call`, the
   hook every host function starts with, sets
   `acted_since_network_failure`; latching a failure clears it. A module
   that swallowed a failed fetch, then read memory or called a model, and
   then failed, has acted since and gets no marker. Logging and the pure
   helpers (`logging::`, `json::`, `templates::`, `datetime::`) do not
   count: a module that logs the failure it is about to return has done
   nothing else.
2. **A classifier consults it LAST.** `classify_error` reads it after every
   existing rule, at the point it used to return `unknown`. Text that says
   `401`, `fuel exhausted` or `forbiddenhost` classifies exactly as before.

**Six kinds** (`talos_reason_class::after_host_failure::AfterHostFailure`),
derived from the latched class's `Family`:

| kind | from | `classify_error` | retried |
|---|---|---|---|
| `unreachable` | DNS, TLS, connect, send, response stream | `network_transient` | yes |
| `late` | the per-request deadline | `timeout` | yes |
| `denied` | every policy refusal and size cap | `capability_denied` | no |
| `breaker` | the circuit breaker | `circuit_open` | no |
| `badurl` | an unusable URL | `invalid_url` | no |
| `credential` | a `vault://` header that could not be resolved | `missing_secret` | no |

A cancellation has no kind. A local-LLM deadline class is never rendered
weakly: those carry their own retry caps, decided from the strong marker.

**The vocabulary is its own, and chosen to match no prose rule.** Four
classifiers read failure text by substring. Writing the class token itself
(`timeout`, `secret-lookup`) would have them read the MARKER as a cause:
`timeout` matches the timeout rule, which runs before `auth_failure`. Each
consumer has a test that the key and the six words alone classify as nothing.

**No wire change.** The marker is text in the error, inside the signed
`output_payload`, as the strong marker is. `JobResult`, its signing payload
and both snapshots are untouched.

**The alert classifier reads two kinds** (`unreachable` → `network`,
`late` → `timeout`), so the alert for a bare failure after a network error
says "a service it calls could not be reached". A refusal's weak marker
does not say which gate refused, and each gate has its own class and dedup
key, so it stays `other`.

**Dependencies.** `talos-worker-runtime` and `talos-retry-intelligence` now
depend on `talos-reason-class`, a zero-dependency leaf. The retry crate had
it as a dev-dependency only; its hand mirror of the strong tokens and the
drift pin are left as they were.

## Deliberately NOT done

* **Carrying the host.** A hostname is free text, and
  `timeout-service.example.test` in a failure message is exactly what the
  substring rules cannot tell from a cause. The alert therefore still cannot
  name the service.
* **A field on `JobResult`.** Text suffices, and a field would be a signed
  wire change for the same information.
* **Dropping or widening the strong marker's bound.** Its own comment
  explains why both are wrong.
* **Teaching the failure-analysis classifier or the worker's in-process
  transient gate the weak marker.** Both are unchanged; the words are inert
  to them.

## Stated limits

* A module error longer than about 2,000 characters loses its marker to
  `sanitize_error_message`'s truncation, as it does the strong one.
* A swallowed failure followed only by logging, then an unrelated failure
  with unrecognisable text, is still attributed to the network failure and
  retried, for a node that may retry at all (read-only or idempotent).
* An alert row for a bare failure that used to be `other`, keyed by a
  fingerprint of its text, now opens under the `network` or `timeout` class.

## Tests

* `talos-reason-class`: round trip; every class token has a kind or is the
  cancellation; only `unreachable` and `late` are transient; the weak marker
  is not readable as the strong one.
* Worker, pure: a bare error gets the weak marker for each kind; an error
  that names the failure keeps the strong one; a module that acted since
  gets none; nothing latched, a cancellation and a model timeout get none.
* Worker, through the production `fetch`: a failed call followed by nothing
  is marked; logging does not change that; a memory read withholds it; a new
  failure starts the watch again; a refused host is `denied`.
* `classify_error`: the table above; the same text without the marker is
  `unknown`; the marker never outranks `401`, fuel, `404`, `429` or
  `forbiddenhost`; the strong marker wins beside it; the words are inert.
* Alert classifier: the two kinds, the rest `other`, and text wins.

**Mutations**, each restored (file hashes equal) and green after:

| mutation | caught by |
|---|---|
| the classifier consults the weak marker first | `the_weak_marker_never_outranks_what_the_message_says` |
| `denied` reads as transient | `a_bare_failure_is_classified_by_the_weak_marker` |
| the worker ignores whether the module acted since | the pure test and the `fetch` test |
| a host call after the failure is never noticed | the `fetch` test |
| logging counts as acting | the `fetch` test |

**Not tested:** a real WASM module returning a bare error through
`execute_job`, and a retry actually happening in the dispatcher on the new
class. Each side of both boundaries is tested.
