# `test_module` captures real responses and shows where fuel went

2026-10-03

## What was wrong

* A rehearsal (`http_fixtures`, #1052) needs a recorded response, and the only
  way to get one was to write it by hand. The first rehearsal on the deployed
  stack used a hand-built 153 KB recording.
* `test_module` reports how much fuel a run used and nothing about where.
  Finding that a Gmail reader spent its fuel decoding bodies took two probe
  compiles and fourteen rehearsals with early exits (2026-10-01).

## What changed

**`capture_http: true`** — a real run that keeps the responses `http::fetch`
and `fetch_all` received (`talos_worker_runtime::http_replay::HttpCapture`) and
returns them as `http_captured.http_fixtures`, in the shape `http_fixtures`
takes (method, `url_contains` = the path, status, content type, body). A test
pins that shape contract: a rendered capture is accepted by the fixture parser
and answers the same requests.

**`fuel_profile: true`** — the run's fuel charged to the host calls it was
spent between (`talos_worker_runtime::fuel_profile::FuelProfile`). The runtime
installs a wasmtime call hook for that run only; at each guest→host transition
it reads the fuel left and charges what the guest burned to the host call that
preceded the stretch. Every host function names itself with one line
(`self.host_call("http::fetch")`, 114 functions, added mechanically); one that
does not is reported as `other`.

## Decisions

* **Only the response is captured.** The request's headers and body carry
  resolved secrets and are never recorded; the URL is kept as host and path,
  without the query string. Pinned by a test that sends a credential-shaped
  header, body and query and finds none of them in the capture.
* **Captured bodies are redacted on the way out** with
  `talos_dlp_provider::redact_json` / `redact_str`, the redaction stored module
  output passes. A response from a token endpoint must not hand a credential
  to the caller. Stated cost: a redacted body differs from what the module saw.
* **Bounded.** 64 responses and 8 MiB of bodies (what one fixture set may
  hold); what does not fit is counted (`not_captured`). A non-text body is
  counted and left out.
* **A capturing run is not retried**, so a response is captured once.
* **Capturing a rehearsal is refused** (nothing is sent, so nothing arrives).
* **Controller-side only.** Neither option is on the wire. The worker states
  `None` for `http_capture` and `fuel_profile` on both policies it builds, and
  `worker/src/rehearsal_pin.rs` now pins all three rehearsal fields.
* **The hook observes; it does not charge.** A control test runs the same
  guest with and without a profile and gets the same fuel.
* **Cost when off:** one `&'static str` store per host call (the label). The
  hook is not installed.
* **`fetch_all` is captured in request order**, after the join, because that
  is the order a rehearsal answers a batch in.

## Measured

A guest component that burns 1,000 loop iterations, calls
`datetime::now-unix`, then burns 50,000: the profile charges the second
stretch to `datetime::now-unix`, more than twenty times the first, names one
host call, and `accounted` equals the fuel the run consumed.

## Stated limits

* The profile's resolution is the host call. Fuel burned between two host
  calls is one number; a module that makes one call and then does everything
  gets one large row.
* Redaction is pattern- and key-based. A capture is real account data until
  someone replaces it; the tool says so and does not anonymise.
* Webhook, GraphQL, streaming and `wasi:http` responses are not captured.
* The handler wiring is covered by unit tests of the parse and render
  functions and by the runtime tests, not by a test that drives `test_module`
  end to end.

## Tests

`talos-worker-runtime`: `fuel_profile::tests` (4), capture bounds and shape,
a real loopback fetch whose request is not captured. `worker`:
`tests/fuel_profile_tests.rs` (real component, hook, labels; control),
`rehearsal_pin`. `talos-mcp-handlers`: observer parsing, capture rendering and
the fixture shape contract, profile rendering.
