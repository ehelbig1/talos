# The token verifiers require `iss` and refuse `crit` (2026-10-06)

Follow-up to `2026-10-06-jsonwebtoken-11.md`, whose verdict table recorded
two things the session verifier accepted and should not have. Both needed a
token already validly signed with the deployment's key, so this closes a
gap in the rules, not a known way in.

## Changed

* **`iss` is a required claim of a session token.** `set_issuer(["talos"])`
  refuses a wrong issuer and lets a token with NO issuer through;
  `Claims::iss` defaults to empty and nothing checked it after decoding.
  `verify_token` now lists `iss` in the required claims beside `exp` and
  `sub`.
* **A header naming critical extensions is refused**, by both verifiers:
  the session verifier (`refuse_critical_extensions`) and the Google
  push-token verifier (`google_jwt::verify_signed`, counted under the
  existing `invalid` refusal reason — no new metric label). RFC 7515
  §4.1.11 requires it of a verifier that does not understand the named
  extensions; these understand none, and `jsonwebtoken` parses `crit`
  without acting on it. Any `crit` is a refusal, an empty list included
  (the RFC forbids producing one).
* The two post-decode rules of the session verifier (the `crit` refusal and
  the audience check) are one closure, `admit`, called on the current-
  algorithm path and on the previous-algorithm path.

## No migration window

A session token lives 15 minutes and has one issuing site, which has
stamped `iss: "talos"` since at least 2026-05-18 (the oldest commit that
touches the line). No token without it can still be unexpired. Talos issues
no `crit` header and Google's push tokens carry none.

## Tests

* The verdict table (`talos-auth`) flips its two "recorded, not endorsed"
  rows to refused and grows to 39 tokens: an empty `iss`, an `iss` list,
  `crit` naming a parameter the library knows, an empty `crit` list, and a
  `crit` that is not a list.
* `a_token_on_the_previous_algorithm_meets_the_same_rules` (`talos-auth`):
  six tokens signed with a configured previous algorithm. That path is a
  second decode call and had no test of its own.
* `a_token_naming_critical_extensions_is_rejected` (`google_jwt`): three
  `crit` values on an otherwise valid RS256 token are refused, and the same
  token without `crit` verifies.

## Mutation proof

Eight mutations, each applied alone; a test fails on every one:

| Mutation | Test that fails |
|---|---|
| `iss` not required | no `iss` (both `talos-auth` tests) |
| `crit` never refused, session | header with `crit` |
| previous-algorithm path skips `admit` | previous path: `aud` wrong |
| `admit` drops the `crit` rule | header with `crit` |
| `admit` drops the audience rule | `aud` wrong |
| an empty `crit` list allowed, session | header with an empty `crit` list |
| `crit` never refused, Google | `crit ["made_up"]` |
| an empty `crit` list allowed, Google | `crit []` |

## Not done

* `Claims::iss` keeps `#[serde(default)]` in `talos-auth-types`. The
  verifier is where the requirement is enforced; the struct is also built
  by hand in tests and by the issuing site.
* A token with no `aud` is still accepted unless `JWT_REQUIRE_AUD=true`.
  That switch is an operator decision already recorded in the code and is
  not changed here.
