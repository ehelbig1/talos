# Action links

A link in a message Talos composes that, when you confirm it, starts one
workflow with one fixed payload. "Done", "keep", "drop", "hold this time".

## What it looks like

In the email:

```html
<a href="https://your-talos.example/action-links/3f9c…">done</a>
```

Opening it shows a page that names what it does and which workflow it
starts, with a Confirm button. Confirming starts the workflow once. Opening
it again says it has already been done.

## Why there is a confirmation page

Mail scanners and link previewers open links. If opening a link acted, a
scanner could mark your tasks done. So opening shows the page and only the
button acts. A push notification with an action button can submit directly,
which is the one-tap form; email cannot.

## Wiring it into a workflow

Put an `action_links` node between the node that composes the message and
the node that sends it:

```
compose → links → send
```

```
add_action_links_node(
  workflow_id, node_id: "links",
  targets: { "list": "<id of the workflow that applies list changes>" },
  ttl_hours: 72,
  connect_from: "compose", connect_to: "send")
```

`targets` is the list of workflows a link from this node may start. You
write it; a module cannot add to it.

## What the compose module returns

```json
{
  "subject": "Your morning",
  "html": "… <a href=\"talos-action:done-12\">done</a> …",
  "__action_links__": [
    { "id": "done-12",
      "target": "list",
      "label": "Done: call the dentist",
      "payload": { "op": "done", "item": 12 },
      "fallback": "mailto:me+todo@example.com?subject=done%2012" }
  ]
}
```

| Field | Meaning |
|---|---|
| `id` | Names the placeholder `talos-action:<id>`. 1–40 of `A-Z a-z 0-9 _ -`, unique in the output. |
| `target` | One of the node's target names. Never a workflow id. |
| `label` | What the confirmation page says. Up to 160 characters. |
| `payload` | The trigger input the workflow receives. A JSON object, up to 8 KB. Never a credential. |
| `fallback` | Optional `mailto:` or `https:` link used if the link cannot be minted. |

The node returns the same output with every placeholder replaced,
`__action_links__` removed, and a report:

```json
"__action_links_report__": {
  "available": true, "requested": 3, "minted": 2,
  "not_minted": [ { "id": "x", "reason": "unknown_target", "fell_back": true } ]
}
```

Reasons: `unknown_target`, `workflow_not_owned`, `payload_not_an_object`,
`payload_too_large`, `label_empty`, `too_many_links` (64 per run),
`unavailable`.

The node never fails the run. If links cannot be minted at all, every
placeholder becomes its fallback (or `#`) and the message still sends.

## What the target workflow sees

Its trigger input is the payload, exactly. It starts through the same gates
as `trigger_workflow`: the platform pause, whether the workflow is enabled,
its actor's budget and ceilings, its input schema, its concurrency limit. If
one of those refuses, the page says so and the link can be used again.

Treat the payload as you would any trigger input: validate it. The label and
the payload come from the same module, so a module you would not trust to
start the target workflow should not be upstream of this node.

## Security properties

* The token is 256 random bits and only its hash is stored.
* A link belongs to the user whose run minted it and can only start a
  workflow that user owns.
* A link works once. The claim is taken before the workflow is started, so
  submitting it twice at the same moment starts it once.
* Links expire: 72 hours by default, 14 days at most.
* The address carries the token as its last path segment. The bundled nginx
  writes no access-log line for it; a proxy you put in front should not log
  it either.
* The minted address travels in the node's output to the send node, so it is
  in the stored execution output, readable by the owner.
