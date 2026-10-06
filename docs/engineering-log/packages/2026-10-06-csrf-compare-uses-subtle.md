# The CSRF token comparison uses `subtle`; `constant_time_eq` is no longer a direct dependency (2026-10-06)

First item of the major-version backlog
(`2026-10-06-major-version-backlog.md`): `constant_time_eq` 0.3 → 0.6.

## Measured

Three crates declared `constant_time_eq = "0.3"`. One used it: `talos-csrf`,
at three sites (the double-submit check, the GraphQL check and the rotation
grace path). `controller` and `talos-google-calendar` declared it and called
it nowhere.

Bumping `talos-csrf` to 0.6 would have put two versions in the lockfile:
`totp-rs` 5.7 needs `^0.3`, and `totp-rs` 6 needs `^0.4`, so neither agrees
with 0.6. Ten crates already depend on `subtle`, the comparison the house
rule names.

## Changed

* `talos-csrf` compares tokens with `subtle::ConstantTimeEq`, through one
  helper, `tokens_match`, that all three sites call.
* The two unused declarations are removed.
* `constant_time_eq` stays in the lockfile only as a dependency of `totp-rs`.
  No package was added or changed version.

Behaviour is the same: both comparisons return unequal at once for tokens of
different lengths (the length of a CSRF token is not secret) and otherwise
take time independent of where the tokens differ.

## Mutation testing

The comparison is the CSRF gate, so each guard was mutated and
`cargo test -p talos-csrf --lib` and `controller --test csrf_integration_tests`
run against it. All six were caught:

| Mutation | Caught by |
|---|---|
| the helper always says equal | four tests |
| the helper compares lengths only | `tokens_match_only_when_every_byte_matches`, the last-byte middleware test |
| the helper compares the first 32 bytes | the last-byte middleware test |
| the double-submit site skips the comparison | the last-byte and mismatch middleware tests |
| the GraphQL site skips the comparison | the last-byte middleware test |
| the grace path admits any cached header | `grace_requires_cookie_to_match_rotated_to_token` |

Before this change the only mismatch test used tokens of different lengths,
which a comparison of lengths alone also refuses, and no test sent a
mismatched token through the GraphQL middleware. The new middleware tests use
64-character tokens that differ in the last byte, and a prefix.

## Found on the way (not changed here)

`talos-oauth` has its own hand-written `constant_time_eq`. It folds the two
lengths into one byte, so inputs whose lengths differ by a multiple of 256,
with zero bytes in the extra part, compare as equal. Its inputs are
fixed-length hex digests, so this cannot be reached today. Proposed as its
own task.
