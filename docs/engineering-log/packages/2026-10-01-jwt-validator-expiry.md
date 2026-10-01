# 2026-10-01 — the catalog JWT Validator refuses an expired token

**Defect.** `module-templates/jwt-validator` verified the signature and then
"checked expiry" with `if exp == 0 { error }` and nothing else, under a
comment saying the wall clock is unavailable to a module. It is available
(every world links WASI clocks). So a correctly signed token that expired at
any time in the past came back `{"valid": true}`.

**Proved on the shipped source**, run natively with a real HMAC-SHA256 behind
the stubbed host: a token signed with the right key and `exp: 1` (1970)
returns `Ok({"claims":{"exp":1,"sub":"u1"},"valid":true})`.

**Latent on this fleet.** One installed copy, referenced by 0 workflows.

**Fix.** After the signature is verified:
* `exp` present → refused from `exp + leeway` onward.
* `exp` absent → refused unless the node sets `ALLOW_NO_EXPIRY: true`. A token
  with no expiry is valid forever; that is the caller's choice, not a default.
* `nbf` present → refused until `nbf − leeway`.
* A present `exp` / `nbf` that is not a finite number is refused, not ignored.
* `LEEWAY_SECS` (0–300, default 60); an out-of-range or non-integer value is
  an error rather than a wider window.
* The header's `alg` must be `HS256`. The signature check is always
  HMAC-SHA256 whatever the header says, so this is not what stops a forgery;
  it refuses a token whose issuer signs with something else.
* The documented `ALGORITHM` key was never read. It is now: any value other
  than `HS256` fails the node instead of being verified as HS256 in silence.
* An unreadable clock is an error, never "valid".

**Order kept.** The signature is checked before any claim, so an unsigned
token learns nothing about claim validation (pinned).

**Behaviour changes, stated.** A token past its `exp`, a token with no `exp`
(without the opt-in), a token before its `nbf`, and a header `alg` other than
`HS256` are now refused. All four were accepted before.

**Guards.** 11 unit tests in the template, three of them through `run` with a
real HMAC. Mutation-checked, 9 applied, 9 caught: time check removed; `>=` →
`>` at the expiry boundary; no-expiry accepted by default; header algorithm
check removed; `nbf` check disabled; non-numeric `exp` treated as absent;
leeway unbounded; config `ALGORITHM` check removed; signature check removed.

**Stated limits.**
* CI compiles catalog templates and does not run their tests; these were run
  natively with the host bindings stubbed. The fix is not driven in a worker.
* Installed copies do not change until reinstalled.
* Only HS256. No `aud` / `iss` matching beyond `REQUIRED_CLAIMS` presence.
