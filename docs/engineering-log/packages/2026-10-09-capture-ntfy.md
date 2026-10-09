# capture-ntfy: the second capture adapter (2026-10-09)

The operator moved phone messages from Home Assistant to a self-hosted ntfy
server, keeping Home Assistant for the home. ntfy has four kinds of
notification action (view, http, broadcast, copy) and none takes typed text,
so the reply box goes. Capture moves to an inbox topic the owner publishes to
from the ntfy app.

## Decided

* **`capture-ntfy` v1.0.0**, a reader under the `captured` contract: one GET
  of `/<topic>/json?poll=1&since=<now − 26 h>`, ntfy's message id as the key,
  the message (or the title, when there is no message) as the text.
* **A token is required.** The adapter refuses to run without `AUTH_HEADER`:
  a capture topic anyone can publish to would let anyone put lines on the
  owner's list. `capture-home-assistant` relies on the owner's Home Assistant
  login for the same property.
* **A corrupt line fails the node** rather than being skipped: a shorter list
  that looks complete is worse than a failed run. A non-message event or a
  line older than the window is counted in `ignored`.
* The contract block was copied unchanged; `capture_contract.rs` now has two
  adapters to compare, so its identical-blocks and same-rules legs bite.

## Measured

* `make check-catalog-fuel TEMPLATE=capture-ntfy`: 713,311 of 3,786,000
  (18.8%) for a recorded day of twenty lines.
* Against the operator's server (ntfy v2.28.0, deny-all) with a throwaway
  user: anonymous publish and read 403; a user's publish to its own topic
  200, to another topic 403; a poll with `since=<unix seconds>` returned the
  line as `{id (12 chars), time (int), event: "message", topic, message}`.

## Stated limits

* The server must keep messages at least 26 hours (`cache-duration`); the
  default 12 hours would lose lines typed the previous morning.
* `since` is a timestamp, not a duration, because the documentation lists
  `10m` and `30s` but not hours.
