# 2026-09-30 — the Google key fetch no longer fails on a cold name lookup

Follows [`2026-09-30-google-jwk-boot-warmup.md`](2026-09-30-google-jwk-boot-warmup.md),
which left the root cause of the failed first fetch unknown and deliberately
did not touch the verifier's 2 s connect timeout until the new error chain
said what was failing.

**What the error chain said.** The first boot after that package deployed
(2026-09-30 22:29 UTC):

```
JWK boot warm-up attempt failed; retrying error=... client error (Connect): operation timed out elapsed_ms=2001 attempt=1
JWK boot warm-up succeeded after a retry attempt=2      (68 ms after it started)
```

A connect-phase timeout at exactly the 2 s limit, and a retry two seconds later
that completed in 68 ms.

**Measured** (reference host, `curl` timings from inside the controller
container, 2026-10-01 00:1x UTC):

* `www.googleapis.com/oauth2/v3/certs`, first request after hours idle:
  name lookup **2.016 s**, then connect 18 ms, TLS 21 ms, total 2.074 s. The
  next two requests: lookup 2 ms, total 56 ms.
* Ten other Google hostnames, first lookup then repeat: **7 of 10 first
  lookups took 2.01–2.13 s**; the three that did not (`oauth2`, `gmail`,
  `accounts`) are names the platform resolves all day. Every repeat lookup:
  2–3 ms.
* Twelve freshly started containers on the same network, name already cached:
  lookup 2–3 ms, total 58–71 ms. A new container is not the trigger; a name
  the resolver has not seen recently is.

reqwest's connect timeout covers the name lookup, so against a 2 s limit a
cold lookup always failed, and the failed attempt's own lookup warmed the
cache for the retry. Every other `connect_timeout(` call in the workspace sets
5 s or more; this verifier was the only one below the house value.

**Change.** The 2 s override is removed. `jwk_http_client_builder()` is the one
builder the verifier uses: the shared hardened builder (house 5 s connect
timeout) under the unchanged 5 s total `JWK_FETCH_TIMEOUT_SECS`. A cold lookup
plus the fetch is about 2.2 s, inside that budget.

**Decisions.**
* **The total stays 5 s.** It bounds how long a push can wait on the
  single-flight fetch, and it is under Pub/Sub's default 10 s acknowledgement
  deadline.
* **The boot warm-up and its two retries stay.** They still move the first
  fetch ahead of the redelivery backlog, and a network that is not up at boot
  still needs a second attempt.
* **No lint.** Population one: the only connect timeout below the house value.

**Guard.** `a_fetch_survives_a_cold_name_lookup` builds the verifier's client
from the production builder plus a resolver that answers after 2.2 s, and
verifies a signed push through it. With the 2 s limit restored it fails with
the production error, `client error (Connect): operation timed out`.

**Stated limits.**
* Why a cold lookup takes two seconds here was not investigated. It is a
  property of this host's Docker Desktop resolver; another deployment may not
  have it, and there the change does nothing.
* The 25 first-fetch failures counted over 30 days carried no cause in their
  log lines. They are attributed to this by inference from one diagnosed
  failure and the lookup measurements, not by their own evidence.
* A lookup slower than about 4.9 s still fails the fetch; the warm-up retry
  and the 60 s backoff then apply as before.

**Verify after deploy.** The boot line should read
`Google push-JWT keys fetched at boot attempts=1`. On a boot where the name is
cold, the fetch takes about two seconds instead of failing.
