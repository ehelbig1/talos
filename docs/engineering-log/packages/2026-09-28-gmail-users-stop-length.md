# 2026-09-28 — Gmail `users.stop` never worked (411 Length Required)

**Why.** After the RFC 0013 phase-3 deploy, the controller's boot log carried a
new WARN: `users.stop returned error status=411 Length Required`, logged during
the Gmail watch renewal.

**Measured.**
- `GmailWatchApiClient::users_stop` POSTed with no body, so no
  `Content-Length` went on the wire. The code has had this shape since at least
  2026-05-18.
- Google's front end over HTTP/1.1, probed with NO credentials, so no watch was
  touched:

  | Request | Answer |
  |---|---|
  | POST, no length | 411 |
  | `Content-Length: 0` | 401 (past the length check, refused on the fake token) |
  | `Content-Type` alone | 411 |

  Over HTTP/2 both requests get 401, because there the stream end carries the
  length; that is why a casual curl does not reproduce it. reqwest here speaks
  HTTP/1.1.
- **Three callers** (`watch.rs`):
  - **Renewal** (harmless): `users.watch` replaces the watch anyway, but every
    renewal logs a WARN. LIVE.
  - **Disconnect** and **cleanup**: both delete our row even when stop fails,
    which the code's own comments call an orphaned watch. Google keeps pushing
    to Pub/Sub until the watch expires (≤7 days). LATENT here: 0
    `gmail_integration_audit_log` rows, no disconnect events, 2 integrations
    connected.
- **Other bodyless POSTs** in non-test code: GitHub's installation-token mint
  and Slack's `auth.revoke`. Neither API enforces a length the way Google's
  front end does, and neither is live on this fleet. Left alone.

**Decided.** `.header(CONTENT_LENGTH, "0")` on the stop request, with the reason
at the call site. There is still no body; Gmail's `users.stop` takes none.

**Proof.** `api::tests::users_stop_sends_an_explicit_zero_content_length`
captures the raw request head on a loopback listener, using the PRODUCTION
client via a test-only `with_base_url`. It asserts `POST /users/me/stop` with
exactly one `content-length: 0`, so a duplicate header added by the client would
fail it as well. On the unfixed code it fails with no `content-length` at all.
`talos-gmail` passes 22/22; clippy and rustfmt are clean.

**Stated limits.**
- Not driven against Google with a real token: that would stop the operator's
  live watch. The live check after deploy is that the next renewal logs no
  `users.stop returned error`.
- A probe mistake worth keeping: zsh passed `${h:+-H "$h"}` to curl as ONE
  word, so a "with header" probe silently sent no header and appeared to
  contradict the fix. A literal `-H` settled it.
