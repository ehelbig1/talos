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
        "one_tap": true }                // act in the background where the
                                         // service can; the link must then be
                                         // one that acts on a POST
    ]
  },
  "skip": false                          // true: send nothing, and say so
}
```

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

## What every adapter returns

```jsonc
{ "provider": "ntfy",       // which adapter delivered
  "sent": true, "skipped": false, "dry_run": false,
  "status": 200,            // the service's HTTP status; null when nothing was sent
  "actions_sent": 2, "actions_dropped": 1,
  "one_tap_actions": 1,     // actions delivered as a background POST
  "link_sent": true, "link_dropped": false,
  "tag_sent": false }       // whether this service was given the tag
```

`one_tap_actions` and `tag_sent` are the two things a service may not be
able to do. They are reported rather than hidden so a workflow can tell
which it got. A refusal by the service fails the node with the host and the
status, never the response body.

## Actions that act: action links

To make an action DO something, give it an action link
(`docs/action-links.md`): the compose node asks for links with
`__action_links__` and writes `talos-action:<id>` as an action's `link`; an
`action_links` node between compose and send replaces each with a real
https URL. With `one_tap: true`:

| Adapter | A tap on the action |
|---|---|
| `notify-ntfy` | the phone POSTs to the link in the background; the workflow starts. One tap. |
| `notify-home-assistant` | opens the link; the confirmation page is shown. Two taps. |

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
more to say returns `parts`, an array of notifications, and the workflow
sends them one after another with a chain of nodes:

```
compose → links → part1 → send1 → part2 → send2 → …
```

`partN` is a small module that picks part N out of the composer's output and
returns it as `notification`; `sendN` is the adapter again. Each
`partN → sendN` edge is conditional on `notify == true` and each
`sendN → part(N+1)` edge is plain, so a part is sent only after the one
before it was, and a failed send stops the rest.

Two things to know about that chain:

* **The chain has a fixed length and the composer does not know it.** A
  composer that returns one part more than the workflow has nodes for loses
  its LAST part without a word, and the last part is the one that carries
  the buttons. Give the composer the number of parts its workflow can send
  (a config key) and have it fail, or fold the overflow into the last part,
  rather than return more.
* **The `action_links` node already covers every part.** It replaces
  `talos-action:<id>` wherever it appears in the composer's output,
  including inside each element of `parts` and each action's `link`, and its
  `__action_links_report__` counts across the whole output. One
  `action_links` node before the first `part` node is enough.

## Adding an adapter

1. `module-templates/notify-<service>/template.rs`: copy the contract block
   (between the `notification contract` markers) from an existing adapter
   UNCHANGED, and write the service's config, request body and `run`.
2. `talos.json` with `allowed_hosts: []`, `requires_secrets: []`,
   `allowed_methods: ["POST"]`; `fixtures/` with a recorded run.
3. Add it to `ADAPTERS` in
   `talos-catalog-tests/tests/notification_contract.rs`.

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

## What is not in the contract

Email. The morning message is HTML mail through the delivery pattern
(`docs/delivery-node-pattern.md`), which carries far more than a
notification can. A notification is a short prompt to act; when both are
wanted, a workflow composes both.
