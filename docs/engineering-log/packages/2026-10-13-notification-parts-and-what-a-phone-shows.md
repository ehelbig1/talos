# Notifications in several parts: what was documented, and the contract change left to the operator

2026-10-13

## Observed

A notification body is cut at 1500 characters (`MAX_BODY_CHARS`, the
contract block). A composer with more to say returns `parts`, and each
workflow carries a hand-wired chain
`compose → links → part1 → send1 → part2 → send2 → …`. Nine workflows carry
it. When one composer needed a fifth part, eight workflows were edited by
hand (two nodes and two edges each), and a composer that outgrows its
workflow's chain loses its last part without a word: the part with the
buttons.

Two more, about the phone and not the platform:

* A 599-character body was complete in the app and stopped at about 430
  characters in the notification. A button under long content sits under a
  part of it.
* A notification with `link` opens that address when tapped, so tapping to
  read the rest of a long message opened a tracker page.

## Done here (no contract change)

* `docs/notification-contract.md`, new section "What a phone shows is not
  what was sent": the two observations, the pattern that came out of them
  (content first with no button and no `link`; then a short message of its
  own that asks the question and carries the buttons), the chain as it is
  wired today, and its two properties (a fixed length the composer does not
  know; one `action_links` node covers every part).
* A test pinning the second property:
  `placeholders_inside_every_part_of_a_list_are_replaced_and_counted_once`
  (`talos_workflow_engine_core::action_links`). The brief asked to "make
  sure" the node replaces placeholders inside every element of a list and
  that `__action_links_report__` counts across it. It already did: the
  substitution walks the whole output and the requests are one top-level
  list. Nothing was changed; it is now pinned.

## NOT done: the contract change is the operator's decision

The contract block is byte-identical in every adapter and
`notification_contract.rs` holds it so. Changing it changes what every
compose node may return. It was not touched. What is proposed:

**1. An ordered list beside the single object.**
`notifications: [ … ]` (1 to 6) beside `notification`. An adapter sends them
in order, one request each, and stops at the first that fails. Giving both
is refused. Each element is held to the existing per-notification rules.

**2. What the adapter returns.** Two shapes were considered:

* *(recommended)* A failed part FAILS the node, as a refused single
  notification does today ("a refusal by the service fails the node"), with
  a message that says how far it got ("part 3 of 5: host answered 500; parts
  1-2 were delivered"). `continue_on_error` and error edges then work as for
  any failure. On success the verdict gains `parts_total` and `parts_sent`,
  and its existing fields are sums across the parts.
* A success verdict with `sent: [true, true, false]`. Every reader of the
  verdict must then inspect the list to learn the send failed, and a
  workflow that only checks `sent` reads a half-sent message as sent.

**3. Bounds.** Six parts (the hand-built limit). One outbound request per
part, so the worst case is six times `TIMEOUT_MS` (default 10 s, max 30 s):
the node's `timeout_secs` must cover it, and the adapter should refuse a
list whose worst case its own budget cannot cover rather than be cut off
mid-list. Fuel: `make check-catalog-fuel` must rehearse the largest list.

**4. Retries.** A notify node is not retried by default: its module allows
`POST`, and a state-changing module gets no blind retry
(`default_max_retries_for_module`). With an explicit `retry_count`, a retry
resends the parts already delivered, because an adapter keeps nothing
between attempts. The doc should say: do not set `retry_count` on a node
that sends a list.

**5. Per-action "stay".** Every action is sent to ntfy with `clear: true`,
so the first button tapped dismisses a notification that carried two or
three. A contract field per action (`keep: true`, "the notification stays
after this action is used") would map to `clear: false` in `notify-ntfy`;
`notify-home-assistant` cannot do it and would report it, as it reports
`one_tap_actions`. This is separable from the list.

**The decision asked for:** whether to add (1), which shape for (2), the
bound in (3), and whether to add (5). Until then the chain stays, and the
doc tells a composer how not to lose its last part.

## Why not build it ahead of the decision

A changed contract block has to land in every adapter in one commit with the
contract test, the fixtures and the fuel rehearsal. Built on the wrong
answer to (2) it is rework in every one of those.
