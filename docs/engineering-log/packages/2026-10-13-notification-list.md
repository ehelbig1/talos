# The notification contract carries an ordered list

2026-10-13. Decides what `2026-10-13-notification-parts-and-what-a-phone-shows.md`
left to the operator, who asked for the choice to be made.

## What was wrong

A message longer than one notification (1500 characters) was sent by a
hand-wired chain in every workflow,
`compose → links → part1 → send1 → part2 → send2 → …`: a small module per
part, the adapter again per part, a conditional edge into each send. Nine
workflows carried it. A fifth part meant editing eight workflows by hand,
and a composer that outgrew its workflow's chain lost its last part, the one
with the buttons, without a word.

Separately, every action was sent to ntfy with `clear: true`, so the first
button tapped dismissed a notification that carried two or three.

## Decided

**`notifications: [ … ]` beside `notification`**, an ordered list of 1 to 6
(`MAX_PARTS`; six was the longest chain built by hand). Never both. ONE send
node delivers it.

**A failed part fails the node.** The alternative considered was a success
verdict with `sent: [true, true, false]`. That makes every reader of the
verdict inspect a list to learn the send failed, and a workflow that checks
only `sent` reads a half-sent message as sent. Failing is the contract's
existing rule for a refused single notification, and it keeps
`continue_on_error` and error edges working as for any failure. The error
says how far it got ("notification 3 of 5 was not delivered: …. 2 delivered
before it, none after"), and tells the reader not to retry. One notification
fails with exactly the adapter's own words, as before.

**In order, stop at the first failure.** This is what the chain did,
including "the buttons arrive only if everything before them did".

**Refused whole, before anything is sent**: an empty list, more than six,
both keys given, or any one part that breaks a per-notification rule. Half a
message is not what was composed.

**The order, the stop and the error text are in the contract block**
(`check_notifications`, `Verdict::count`, `send_in_order`), so the adapters
cannot disagree on them. An adapter supplies only how one part is sent and
what its service can do.

**The verdict gains `parts_total`, `parts_sent` and `kept_actions`.** For a
list the counts are sums.

**Per-action `keep`.** `notify-ntfy` sends `clear: false` for it;
`notify-home-assistant` cannot and reports `kept_actions: 0`, as it reports
`one_tap_actions: 0`. Default false: nothing changes for a composer that
does not ask.

**Retries: said, not prevented.** A notify node gets no retry by default
(its module allows POST). With an explicit `retry_count` a retry resends the
delivered parts; an adapter keeps nothing between attempts and cannot stop
that. The doc, the manifests and the error say not to.

## Measured

`make check-catalog-fuel`, both adapters, with the recorded run replaced by
the largest message the contract allows (six parts, each a 1500-character
body, a title, a link, a tag and three actions):

| | fuel used | old limit | new limit | used |
|---|---:|---:|---:|---:|
| `notify-ntfy` | 2,125,068 | 1,000,000 (exhausted) | 4,420,000 | 48.1% |
| `notify-home-assistant` | 2,130,350 | 1,000,000 (exhausted) | 4,420,000 | 48.2% |

The old single-notification run used 172,047. `recommended_fuel` is now
`expected_items: 6, bytes_per_item: 3000, fuel_per_byte: 100,
safety_multiplier: 2.0`: this module costs about 137 fuel per input byte
(it cleans every character of every body), far above the default rate of 2.

## Deliberately NOT done

* **The chain is not removed from anything.** A `sendN` node receiving a
  single `notification` behaves as before. Moving the nine workflows to one
  send node is the operator's, on the running stack.
* **No adapter-side total time budget.** Each part has `TIMEOUT_MS`; the
  node's `timeout_secs` must cover `parts × TIMEOUT_MS`, and the doc says
  six parts at the default leave nothing to spare.
* **No resume-from-part.** A failed list is not resent from where it
  stopped.
* **An installed copy does not change until it is reinstalled** from the
  catalog (versions `notify-ntfy` v1.1.0, `notify-home-assistant` v1.2.0).

## Tests

* `talos-catalog-tests/tests/notification_contract.rs` (8, +3): the block is
  still byte-identical; the verdict's field list; a list delivered in order,
  one request each, the buttons in the last part only, counts summed, `keep`
  reported per service; a failed second part stops the third and fails the
  node with how far it got, while one notification fails in the adapter's
  own words; the bounds, both keys, a bad part, `skip` and a dry run, with
  nothing sent for a refused list.
* `notify-ntfy`'s own tests (+1): `keep` is `clear: false`, the default
  unchanged.
* `talos_workflow_engine_core::action_links` already pins that one
  `action_links` node covers every part.

## One home

The contract block, identical in `module-templates/notify-*/template.rs`.
`docs/notification-contract.md`. `CLAUDE.md` carries the rule.
