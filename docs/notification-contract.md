# The notification contract

A workflow decides what to tell its owner. Which service carries the message
to a phone is a separate choice, and one that will change. So the two are
kept apart by a contract:

* the node that COMPOSES a message returns a `notification` object in a
  fixed, service-neutral shape;
* the node that SENDS it runs a `notify-*` adapter module, one per service,
  each of which reads that shape and returns the same verdict.

Changing service is `swap_node_module` on the send node plus that adapter's
config. Nothing that composes, decides or stores anything changes.

Adapters today: `notify-ntfy`, `notify-home-assistant`.

## What a compose node returns

```jsonc
{
  "notification": {
    "title": "Morning",                  // optional, cut at 120 characters
    "body": "Three things today.",       // required; line breaks kept; cut at 1500
    "priority": "normal",                // low | normal | high (default normal)
    "tag": "morning",                    // optional; a later message with the
                                         // same tag replaces the earlier one,
                                         // where the service can
    "link": "https://…",                 // optional; opened when the message is tapped
    "actions": [                         // optional; at most 3
      { "title": "Done",                 // cut at 40 characters
        "link": "https://…",             // what the action opens, or POSTs to
        "one_tap": true,                 // act in the background where the
                                         // service can; the link must then be
                                         // one that acts on a POST
        "keep": true }                   // using this action leaves the
                                         // notification where it is, where
                                         // the service can (default false)
    ]
  },
  "skip": false                          // true: send nothing, and say so
}
```

A message in several parts is `notifications` instead: an ordered list of 1
to 6 objects of that same shape.

```jsonc
{ "notifications": [ { "body": "…" }, { "body": "…" },
                     { "body": "Post it?", "actions": [ … ] } ] }
```

Give one or the other, never both.

Rules every adapter applies, from one shared block of source:

* A missing `notification`, an empty `body` or an unknown `priority` FAILS
  the node. Nothing is sent in place of what was composed.
* A link that is not `https://` is not sent, and is counted. A link is where
  a single-use capability travels; plain http would carry it in the clear.
  This is also what happens to an action link that could not be minted and
  fell back to `#` or a `mailto:`.
* An action with no title, an unusable link, or past the third is dropped
  and counted.
* No service vocabulary: no topic, no entity id, no device name. Those are
  the adapter's config.
* A list is sent in order, one request per notification, and **stops at the
  first that fails**: a later part (the one with the buttons) arrives only if
  everything before it did. A failed part FAILS the node, as a refused
  single notification does, and the error says how far it got
  ("notification 3 of 5 was not delivered: …. 2 delivered before it, none
  after"). `continue_on_error` and error edges work as for any failure.
* A list is refused WHOLE, before anything is sent, if it is empty, longer
  than six, given together with `notification`, or if any one part breaks a
  rule above. Half a message is not what was composed.

## What every adapter returns

```jsonc
{ "provider": "ntfy",       // which adapter delivered
  "sent": true, "skipped": false, "dry_run": false,
  "status": 200,            // the service's HTTP status; null when nothing was sent
  "parts_total": 1,         // notifications composed
  "parts_sent": 1,          // notifications delivered (0 on a dry run or a skip)
  "actions_sent": 2, "actions_dropped": 1,
  "one_tap_actions": 1,     // actions delivered as a background POST
  "kept_actions": 0,        // actions the service keeps the notification for
  "link_sent": true, "link_dropped": false,
  "tag_sent": false }       // whether this service was given the tag
```

For a list the counts are sums over its parts, `link_sent`, `link_dropped`
and `tag_sent` say whether that was so for any part, and `status` is the last
answer. On success `parts_sent` equals `parts_total`; a list that stops
part-way is an error, not a verdict.

`one_tap_actions`, `kept_actions` and `tag_sent` are the three things a
service may not be able to do. They are reported rather than hidden so a workflow can tell
which it got. A refusal by the service fails the node with the host and the
status, never the response body.

## Actions that act: action links

To make an action DO something, give it an action link
(`docs/action-links.md`): the compose node asks for links with
`__action_links__` and writes `talos-action:<id>` as an action's `link`; an
`action_links` node between compose and send replaces each with a real
https URL. With `one_tap: true`:

| Adapter | A tap on the action | `keep: true` |
|---|---|---|
| `notify-ntfy` | the phone POSTs to the link in the background; the workflow starts. One tap. | the notification stays (`kept_actions` counts it); without it, the first action used dismisses the notification |
| `notify-home-assistant` | opens the link; the confirmation page is shown. Two taps. | not available: the notification is dismissed (`kept_actions` is 0) |

```
compose  ──►  action_links  ──►  send (notify-*)
```

## What a phone shows is not what was sent

Two things learned from messages that were delivered whole and still did not
work. Both are about the phone, so they hold whichever adapter sends.

* **A notification shows less than the message holds.** A body is cut at
  1500 characters by the contract, but a notification stops showing it long
  before that: a 599-character body was complete inside the app and ended at
  about 430 characters in the notification itself. A button under a long
  body therefore sits under a part of it. The reader answers a question they
  could not finish reading.
* **A `link` takes over the tap.** A notification with `link` opens that
  address when it is tapped. Tapping to read the rest of a long message then
  opens the link (a tracker page, say) instead of the message.

So, for anything longer than a few lines:

1. **Send the content first, with no button and no `link`.** Tapping it
   opens the message, which is what the reader wants to do with it.
2. **Then send a short message of its own that asks the question and
   carries the buttons.** Short enough to be shown whole (a few lines), so
   the buttons sit under all of it.

A `link` belongs on a short message whose whole point is the place it opens.

### Several parts

One notification is one body of at most 1500 characters. A composer with
more to say returns `notifications`, the ordered list above, and ONE send
node delivers it:

```
compose → links → send (notify-*)
```

* **Order and failure** are the adapter's: in order, one request each, and
  nothing after a part that failed.
* **The `action_links` node covers every part.** It replaces
  `talos-action:<id>` wherever it appears in the composer's output,
  including inside each element of the list and each action's `link`, and
  its `__action_links_report__` counts across the whole output.
* **Time.** Each part is one request with its own `TIMEOUT_MS` (10 seconds
  by default, 30 at most). The send node's `timeout_secs` must cover the
  worst case, `parts × TIMEOUT_MS`: six parts at the default is the default
  node timeout of 60 seconds, with nothing to spare. Raise `timeout_secs`
  or lower `TIMEOUT_MS` for a long list.
* **Do not set `retry_count` on a node that sends a list.** An adapter
  keeps nothing between attempts, so a retry sends the delivered parts
  again. A notify node is not retried unless you ask: its module allows
  `POST`, and a module that changes state gets no retry by default.

Before 2026-10-13 a list was a hand-wired chain,
`compose → links → part1 → send1 → part2 → send2 → …`, with a small module
per part and a conditional edge into each send. That chain still works (each
`sendN` receives a single `notification`), but its length is fixed in the
workflow and the composer does not know it: a composer that returns one part
more than the chain has nodes for loses its last part, the one with the
buttons, without a word. Move such a workflow to one send node and
`notifications`.

## Adding an adapter

1. `module-templates/notify-<service>/template.rs`: copy the contract block
   (between the `notification contract` markers) from an existing adapter
   UNCHANGED, and write the service's config, request body and `run`.
2. `talos.json` with `allowed_hosts: []`, `requires_secrets: []`,
   `allowed_methods: ["POST"]`; `fixtures/` with a recorded run.
3. Add it to `ADAPTERS` in
   `talos-catalog-tests/tests/notification_contract.rs`, and to `SENDERS` in
   `talos-catalog-tests/tests/delivery_verdict.rs` (every `notify-*` sender
   is driven there, and its verdict read as the engine reads it).

That test fails if two adapters' contract blocks differ by a byte, if a
`notify-*` template is missing from the list, if adapters disagree on a
verdict for the same notification, or if one installs able to reach
anything. A change to the contract is a change to the block in every
adapter, in one commit.

## What an adapter may add: a reply box

A place to type an answer is something one service has and another does not,
so it is not in the `notification` object. It is adapter config:
`notify-home-assistant` takes `REPLY_TITLE`, and every notification that node
sends then carries a text field with that label. What is typed does not come
back through the adapter. The companion app raises an event inside Home
Assistant (`mobile_app_notification_action`, action `REPLY`, with
`reply_text`), and an automation there keeps or forwards it; a workflow reads
it back with a `capture-*` adapter (`docs/capture-contract.md`, which has the
automation). The box
takes one of the three action places: with three composed actions the last
is not sent, and is counted in `actions_dropped`.

Swapping to an adapter with no such setting loses the box and nothing else.

## What the platform records of a send

The verdict above is the only trace of a message having left: the adapter's
HTTP call leaves nothing behind, and a node's output is encrypted at rest. So
the engine reads the verdict when the send node completes
(`talos_workflow_engine_core::delivery_verdict`) and, for a send that
happened on a real run, writes one `message_deliveries` row: the workflow,
execution and node, the `provider` word, `parts_total`, `parts_sent`,
`actions_sent`, `one_tap_actions`, `kept_actions`, and how the run was
started. No recipient, no address, no text.

Nothing is written for a dry run (the engine's own flag, before the output is
read), a skip, or a verdict with no part sent. A verdict outside the bounds
above (more than 64 parts, a provider word that is not lowercase ASCII) is
counted as malformed and not written; `talos-catalog-tests/tests/notification_contract.rs`
holds every adapter's real verdict readable by the engine, so a change to the
block that the reader does not follow fails CI.

The MCP tool `get_message_engagement` reads that table and sets action-link
taps against the executions that sent them: per workflow, sends, parts,
actions, executions, executions whose messages carried an action, executions
with at least one tap, and taps, with the sends also given per provider.
`tap_rate` is `executions_tapped / executions_with_actions`: a message with no
action cannot be tapped, so a plain report is not read as ignored. Rehearsals
(`started_by_kind = test`) are left out. A new adapter needs nothing beyond
returning the verdict unchanged.

The four fields the engine recognises a send by (`provider`, `sent`,
`parts_total`, `parts_sent`), with `skipped`, `dry_run` and `actions_sent`,
are the **delivery verdict every sender of a message returns**
(`docs/building-blocks.md`, "Sender"), not only a `notify-*` adapter. The
HTML email sender returns them beside its Gmail ids, with `provider: "gmail"`,
one part, and the action links in its body as `actions_sent`.
`talos-catalog-tests/tests/delivery_verdict.rs` drives every message sender
and reads its verdict through the engine's reader.

## What is not in the contract

Email. The morning message is HTML mail through the delivery pattern
(`docs/delivery-node-pattern.md`), which carries far more than a
notification can. A notification is a short prompt to act; when both are
wanted, a workflow composes both. The email sender does return the delivery
verdict above, so its sends are counted with the notifications; what it
reads (`{subject, html}`) and the rules it applies are its own.
