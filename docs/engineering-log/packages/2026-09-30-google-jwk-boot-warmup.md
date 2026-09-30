# 2026-09-30 — Google push keys are fetched at boot, and a failed fetch says why

**Defect.** The Google push-JWT verifier fetched Google's public keys lazily,
on the first push that needed one. After a controller restart that first push
is the head of Pub/Sub's redelivery backlog, and when that fetch failed the
verifier opened its 60 s backoff and refused the backlog with 401. On
2026-09-30 18:36, 81 s after a deploy, one failed fetch refused **94** Gmail
pushes (Pub/Sub redelivered them; nothing was lost, but each was delayed and
each became a refusal). And the failure could not be diagnosed: the WARN
carried only reqwest's outermost layer, `error sending request for url (...)`,
which does not say whether DNS, the connect, TLS or a timeout failed.

**Measured** (Prometheus, 30 days, reference host): 126 controller lifetimes,
95 of which fetched keys. **25 (26%) failed their FIRST fetch**, and in 25 of
the 26 lifetimes with any failure it was the first fetch that failed; 36
failed and 99 successful fetches in total. The first fetch happened between 1 s
and 22 min after boot (it waits for the first push), so "the network was not up
yet" does not explain it. Today's two restarts both failed. **The root cause is
still unknown** — the old log could not show it — and this package does not
claim one.

A second finding on the way: Gmail's receiver built its OWN verifier
(`PubsubJwtVerifier::new` → `GoogleOidcVerifier::new()`) while Google Cloud push
had another, so a process held two key caches for one public key set and paid
two first fetches.

**Fix.**
* `talos_http_utils::trusted_client::error_chain` — an error and every
  `source()`, joined, repeats skipped, bounded to 512 chars. The JWK fetch
  failure now carries it, plus `elapsed_ms`, so the next failure names its layer.
* `GoogleOidcVerifier::warm` — at most three attempts, at 0 s, 2 s and 10 s,
  under the same single-flight lock as the on-demand path; returns
  `JwkWarmup::{Warmed, AlreadyWarm, GaveUp}`. A failed attempt logs INFO while
  another follows and WARN on the last, where the on-demand path takes over.
* ONE shared `GoogleOidcVerifier` per controller, handed to both receivers
  (`PubsubJwtVerifier::with_shared_verifier`), and warmed by a fire-and-forget
  spawn at boot when either receiver is enabled (the house pattern of the
  embedding and LLM warm-ups). Boot neither waits for nor fails on it.

**Decisions.**
* **Three attempts, not a retry loop.** Every attempt counts on
  `talos_google_jwk_refresh_total{outcome}`, and `TalosGoogleJwkRefreshFailing`
  (`>= 5` failed in 15 m, `for: 0m`) was derived from the on-demand path's cap
  of one failure per minute. Three quick attempts plus that cap need two
  minutes of continuous failure to reach five. **Stated shift**: in a real
  outage at boot the alert can now fire after ~2 min instead of ~5. The rule is
  unchanged.
* **The warm-up does not wait out a backoff window** — it is capped at three
  attempts, so it cannot hammer Google.
* **The 2 s connect-timeout override is NOT changed**, although it is stricter
  than the house 5 s and is a plausible cause: changing it without evidence
  would be a second variable. The error chain will say whether failures are
  connect timeouts; that decides it.
* **No new metric.** The existing refresh counter already records every
  attempt; the warm-up outcome is a log line.
* **Sharing the cache is safe**: it holds only Google's public keys; audience
  and service account stay per-call and per-receiver, and refusals are still
  counted per integration.

**Guards.**
* `talos-http-utils`: `error_chain` over a synthetic chain (repeats skipped,
  bound) and over a real reqwest connect failure (a cause below the top layer).
* `google_jwt` tests against a loopback JWK endpoint serving a real RSA key:
  the first request dropped, the warm-up's second succeeds, and a push signed
  with that key then verifies with NO further request; three failures give up,
  leave the backoff open, and a push then adds no request; fresh keys make the
  warm-up a no-op; a failed fetch reports its cause (reverting to
  `e.to_string()` fails it — shown).
* `the_controller_shares_and_warms_one_key_cache` — a TEXTUAL pin over
  `controller/src/bootstrap/services.rs` (one `GoogleOidcVerifier::new()`, no
  `PubsubJwtVerifier::new(`, the shared constructor, the GCP receiver given the
  shared cache, one `warm()`); it fails on `main`.

**Stated limits.**
* The warm-up is proven against a loopback server, not Google; the live read
  after deploy is the proof it runs at boot.
* It helps when the first-fetch failure is transient. If the cause is
  persistent, three attempts fail and behaviour is exactly as before — but the
  WARN now names the cause.
* A push that arrives within the first seconds, while an attempt is failing,
  can still be refused, as before.
