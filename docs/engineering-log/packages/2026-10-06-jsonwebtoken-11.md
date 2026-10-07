# `jsonwebtoken` 10 → 11 (2026-10-06)

Backlog item, last of the authentication group
(`2026-10-06-major-version-backlog.md`). The library signs and verifies the
session token (`talos-auth`), verifies Google's push tokens
(`talos-integration-helpers::google_jwt`, used by Gmail and Google Cloud),
and cross-checks the GitHub App token in tests. Seven crates inherit it from
the workspace table, so the bump is one line.

## Measured

A throwaway harness linked 10.4.0 and 11.1.0 side by side, both with the
features the workspace uses (`rust_crypto`, `use_pem`), and ran 117
token/validation pairs through each:

* **Session configuration** — HS256, expiry checked, `nbf` not checked,
  `exp` and `sub` required, issuer `talos`, audience left to the caller.
* **Google configuration** — RS256, an audience, issuer
  `https://accounts.google.com`, 60 s leeway; including a token signed HS256
  with the RSA public key as the secret (refused by both as the wrong
  algorithm).
* **Encoding** — the same claims and key give byte-identical HS256 and RS256
  tokens from both, and each verifies the other's RS256.

One kind of difference, in 6 of the 117: a header parameter the library does
not know, whose value is NOT a string (a boolean, a number, an object), was
a parse error in 10 and is ignored in 11. Version 10 already ignored unknown
parameters whose value is a string. Such a token still needs a valid
signature under the verifier's key, so this widens what a holder of the key
may put in a header and nothing else.

## Changed

* `jsonwebtoken = "11.1"` in the workspace table. Lockfile: that one package
  moves; no package arrives or leaves.
* `Algorithm` is `non_exhaustive` from 11. `algorithm_name` (the start-up
  self-test's log label) gains a wildcard arm that reports `unrecognised`.
  It was the only line in the workspace that stopped compiling.
* `the_session_verifier_accepts_and_refuses_what_it_is_recorded_to`
  (`talos-auth`): 34 tokens made by hand, each driven through the real
  `AuthService::verify_token`. Until now the session verifier's rules were
  tested through tokens the service itself issued, which cannot be expired,
  mis-issued, or signed another way. `base64` is a dev-dependency of the
  crate for it.

## Mutation proof

The verifier is an authentication gate. Seven mutations of `verify_token`,
each applied alone; the new test fails on every one:

| Mutation | Row that fails |
|---|---|
| expiry not checked | expired 90 s ago |
| issuer not pinned | `iss` wrong |
| a wrong audience allowed | `aud` wrong |
| signature not checked | expired 90 s ago (and the signature rows) |
| any HMAC algorithm accepted | signed HS384 with the service's secret |
| leeway widened to an hour | expired 90 s ago |
| leeway removed | expired 30 s ago |

The fifth survived the first draft: a row whose HEADER said HS384 over an
HS256 signature is refused for its signature whether or not the algorithm
is pinned. Two rows genuinely signed HS384 and HS512 with the right secret
were added, and they are what pins it.

## Found, not changed here

Both are what the verifier did before this change and does after it. The
test records them as accepted and says so beside each row.

* **A session token with no `iss` is accepted.** `set_issuer` refuses a
  wrong issuer and does not require the claim; `Claims::iss` defaults to
  empty; nothing checks it after decoding. The audience has the opposite
  treatment (`JWT_REQUIRE_AUD`). Every token the service issues carries
  `iss`, so requiring it needs no migration window — but it is a change to
  what is accepted, and belongs in its own package.
* **`crit` is not honoured** by either library version. RFC 7515 §4.1.11
  says a token naming a critical header extension the verifier does not
  understand must be refused. Talos issues no such header.

Both need a token already validly signed with this deployment's key.

## Not done

* No table of the same kind for the Google verifier. Its refusals (wrong
  audience, wrong issuer, expired, HS256, `none`, tampered signature,
  missing or unknown key id) already have a test each in
  `google_jwt`, written against tokens signed by a made-up RSA key.
