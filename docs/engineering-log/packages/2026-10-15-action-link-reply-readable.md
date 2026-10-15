# 2026-10-15 — a tapped action link's reply can be read by the phone

**Context.** Every one-tap action (Post, Tick) from the ntfy web client showed
"TypeError: Failed to fetch" although the action had worked: the comment was
posted, the box ticked. The client's `fetch` is cross-origin; the action link
answered with no `Access-Control-Allow-Origin` for the ntfy origin (it is not on
`ALLOWED_ORIGIN`), so the browser sent the POST, the link acted, and the reply
was hidden from the page. Observed on AXP-1051, five taps in a row.

**Decided.** `/action-links/…` answers `Access-Control-Allow-Origin: *` and NO
`Access-Control-Allow-Credentials`, on the request and on its preflight
(`is_capability_link_path`, `cors_answer` in `controller/src/bootstrap/router.rs`).
Every other route keeps the allow-listed, credentialed echo unchanged.

Why this is safe: the token in the path is the link's only credential, and no
cookie or header is honoured there; a cross-origin POST reached the link before
this change too (a simple request is sent whatever the response headers say),
so who can act is unchanged. What becomes readable is the reply page: done,
already used or invalid, and the link's label, which is already not private
(2026-10-13, action-links address record).

**Deliberately NOT done.**
* Adding the ntfy origin to `ALLOWED_ORIGIN`: that list is credentialed and
  covers the whole API, so it would let that origin read any reply as the owner.
* A configured origin for action links: `*` without credentials gives the same
  guarantee with nothing to keep in step with the phone's client.
* The other capability routes (`/approvals`, `/corrections`, suspension
  approvals): they are posted from Talos's own confirmation page (same origin).

**Tests.** `capability_link_cors_tests` (controller binary): the real middleware
on a stub router, POST and preflight, for an action link and for `/graphql`.
Mutation-proved: widening the path to every route, allowing credentials on an
action link, and sending credentials unconditionally each fail a test.
