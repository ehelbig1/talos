# The OAuth session-binding comparison uses `subtle` (2026-10-06)

The task proposed in `2026-10-06-csrf-compare-uses-subtle.md` ("Found on the
way").

## The defect

`talos-oauth` had a hand-written `constant_time_eq(a, b)`, called at the two
places a callback's browser binding is checked: the login flow
(`OAuthService::validate_state_token`) and the integration connect flow
(`connect_binding::check_connect_binding`). It began

```rust
let mut diff: u8 = (a.len() ^ b.len()) as u8;
```

and then XORed the bytes over the longer length, reading the shorter input as
zeros past its end. The cast keeps the low eight bits of the length
difference, so two inputs whose lengths differ by a multiple of 256, with zero
bytes in the extra part, compared as EQUAL: `constant_time_eq(b"", &[0u8; 256])`
was `true`.

## Latent, not live

Both call sites pass two SHA-256 hex digests: the stored
`session_binding_hash` and `hash_oauth_session_binding(nonce)` of the presented
cookie. Each is 64 ASCII hex characters, and hex contains no NUL byte, so no
input reaches the wrong answer today. It was a wrong answer in a helper an
authentication decision rests on, waiting for a caller with other inputs.

## Changed

* `constant_time_eq` is now `subtle::ConstantTimeEq` (`a.ct_eq(b).into()`).
  The name, the `pub(crate)` visibility and both call sites are unchanged.
* `talos-oauth` declares `subtle = "2.4"`. No package was added to the
  lockfile: `subtle` 2.6.1 was already there (thirteen other crates declare it); the
  only lockfile change is the new edge from `talos-oauth`.
* The doc comment no longer says "`subtle` is not a workspace dep".
* New test `a_length_difference_that_is_a_multiple_of_256_is_unequal`. It
  fails on the old helper (`assertion failed: !constant_time_eq(b"", &[0u8; 256])`).

## Behaviour difference

The old helper read every byte of the longer input even when the lengths
differed. `subtle`'s slice comparison returns unequal as soon as the lengths
differ, without reading a byte, and is constant-time only for inputs of equal
length. That is acceptable here because the lengths are public: both inputs
are SHA-256 hex digests, always 64 bytes. A future caller that compares
values whose LENGTH is secret must not use this helper.

For the inputs that occur (two 64-byte digests) the result is the same as
before.

## Mutation testing

The comparison gates an authentication decision, so each guard was mutated,
the tests run, and the tree restored. All caught:

| Mutation | Run against | Caught by |
|---|---|---|
| the helper returns `true` | `cargo test -p talos-oauth --lib` | five tests, among them `mismatched_cookie_rejected` and `only_the_matching_browser_passes_the_check` |
| the helper compares lengths only | same | four tests, among them `mismatched_cookie_rejected` and `only_the_matching_browser_passes_the_check` |
| the helper compares only the shared prefix (no length check) | same | `constant_time_eq_matches_semantics_of_equality`, the new test |
| the helper is the old length-folding code | same | the new test, and only it |
| the login site skips the comparison (`validate_state_token`) | `cargo test -p controller --test oauth_tests` | `test_oauth_state_session_binding_enforced` |
| the connect site skips the comparison (`check_connect_binding`) | `cargo test -p talos-oauth --lib` | `only_the_matching_browser_passes_the_check` |

The login-site mutation is NOT caught by `talos-oauth`'s own unit tests (67
passed with the comparison skipped). Only the controller's testcontainer test
sees that site. See "Found on the way".

## The catalog template

`module-templates/jwt-validator/template.rs` has its own `constant_time_eq`
for the HS256 signature. It does not have this defect: it compares the
lengths as `usize` first (`if a.len() != b.len() { return false; }`) and folds
only the bytes of two equal-length inputs. Removing that length check is
caught by the template's existing test
`end_to_end_a_forged_token_fails_on_its_signature_before_anything_else` (the
empty-signature case). The template is unchanged.

## Deliberately NOT done

* **A 256-multiple test in the template.** There is no length arithmetic in
  it to pin, and its length check is already guarded. Editing a catalog
  template's source for a test of a defect it does not have was not worth a
  change to a published template.
* **Moving the template to `subtle`.** `subtle` is not in the module
  dependency allowlist (`talos-compilation/src/dependency_allowlist.rs`), and
  the template's comparison is correct.
* **Inlining `ct_eq` at the two call sites and deleting the helper.** One
  helper keeps the comparison in one place, as `tokens_match` does in
  `talos-csrf`.
* **A workspace-shared comparison helper.** Each crate's helper is two lines
  over `subtle`; a shared crate would add a dependency edge to save none.

## Swept

Every other hand-written comparison in the tree
(`git grep -nE "fn [a-z_]*(constant_time|ct_eq|secure_compare|timing_safe|const_time)"`,
and the XOR-fold shape `acc | (x ^ y)` / `diff |=`):

* `jwt-validator` template: correct, above.
* `talos_secrets_manager::kek_providers_share_key`: folds two
  `Zeroizing<[u8; 32]>` with no length check. The lengths are equal by type,
  so it is correct. Not changed.

No other site folds a length into a narrower integer.

## Found on the way (not changed here)

`talos-oauth`'s `session_binding_tests::binding_accepts` is a test-local copy
of the decision inside `validate_state_token` (stored hash present or not,
cookie present or not, then the comparison). The six unit tests that go
through it exercise the real hash and the real comparison, but not the real
call site, which is why skipping the comparison there leaves all 67 unit
tests green. The site is guarded in CI by the controller's
`test_oauth_state_session_binding_enforced`, which needs a database. Moving
the decision into one function that both `validate_state_token` and the unit
tests call (the shape `check_connect_binding` already has) would let the unit
tests guard it too. Proposed as its own task.

## One home

`talos_oauth::constant_time_eq` for the two binding checks in `talos-oauth`.
The comparison itself is `subtle::ConstantTimeEq`.
