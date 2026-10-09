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
it from wherever that automation put it, with a reader of its own. The box
takes one of the three action places: with three composed actions the last
is not sent, and is counted in `actions_dropped`.

Swapping to an adapter with no such setting loses the box and nothing else.

## What is not in the contract

Email. The morning message is HTML mail through the delivery pattern
(`docs/delivery-node-pattern.md`), which carries far more than a
notification can. A notification is a short prompt to act; when both are
wanted, a workflow composes both.
