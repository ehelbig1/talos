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

If the workflow already has an edge `compose → send`, the call REPLACES it:
`compose → links` is plain, and `links → send` keeps the type and condition
of the edge it replaced, so a send that was conditional on `notify == true`
is still conditional. The reply lists what was replaced (`replaced_edges`).
With no such edge, the two edges are added. If several edges would be
replaced and they do not carry the same condition, the call is refused: wire
that one by hand with `add_edge` / `remove_edge`.

Calling the tool again for a `node_id` that already exists changes what the
node may start, and nothing else: `targets` is replaced by the list given,
`ttl_hours` is changed when given, and no edge and no other setting of the
node (`continue_on_error`, for one) is touched. `connect_from` /
`connect_to` are not applied to an existing node, and the reply says so.

The node can also be written when the workflow is created:

```
create_workflow(name, nodes: [
  { id: "compose", module_id: "…" },
  { id: "links", node_type: "action_links",
    targets: { "list": "<workflow id>" }, ttl_hours: 72 },
  { id: "send", module_id: "…" } ],
  edges: [ { source: "compose", target: "links" },
           { source: "links", target: "send", condition: "notify == true" } ])
```

`targets` is the list of workflows a link from this node may start. You
write it; a module cannot add to it.

The same rule applies whichever tool writes it (`add_action_links_node`,
`update_node_config`, an import, a copy, the web editor): 1 to 16 entries,
each a name of 1 to 40 letters, digits, `_` and `-` mapped to the id of a
workflow of yours. A write that breaks it is refused and names the node and
the entry; for a workflow, "does not exist" and "is not yours" are one
answer. A target the workflow already names is not asked about again when
something else in the graph is edited, so a workflow whose target you have
since deleted stays editable; the link for it is simply not minted (below).

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

Reasons: `unknown_target`, `workflow_not_owned`, `workflow_archived`,
`payload_not_an_object`, `payload_too_large`, `label_empty`, `too_many_links`
(64 per run), `unavailable`, `dry_run`, `link_address_misconfigured` (see "The
address a link is on").

A target is checked every time a link is made, not only when the node was
written. One that was deleted since, or is no longer yours, is
`workflow_not_owned`; one you have archived is `workflow_archived`. Either
way no link exists for it and its placeholder becomes the fallback.

The node never fails the run. If links cannot be minted at all, every
placeholder becomes its fallback (or `#`) and the message still sends.

If the node above it failed and was continued past (`continue_on_error`), the
node passes that failure on unchanged, with a report that says nothing was
minted. It is not itself a failed node. Put a condition on the edge to the
send node (`is_error == false`) if a failed compose should send nothing.
### Under a dry run

A dry run (`test_workflow`, `call_workflow` or `trigger_workflow` with
`dry_run: true`) mints no link. A link starts a real workflow, and a
rehearsal's payload is rehearsal data, so the node asks the link store for
nothing: every request falls back and is reported with the reason `dry_run`,
and no token is stored. The reply's `dry_run` block names the node and how
many links it left unminted (`action_links_not_minted`).

To see a message with working links, run the workflow for real.

The execution row records that the run is a dry run. So a dry run that pauses
and is resumed (an approval, a wait node), is recovered after a controller
restart, or is retried is still a dry run when it reaches an `action_links`
node, and a replay of a dry run is a dry run.

## What the target workflow sees

Its trigger input is the payload, exactly. It starts through the same gates
as `trigger_workflow`: the platform pause, whether the workflow is enabled,
its actor's budget and ceilings, its input schema, its concurrency limit. If
one of those refuses, the page says so and the link can be used again.

Treat the payload as you would any trigger input: validate it. The label and
the payload come from the same module, so a module you would not trust to
start the target workflow should not be upstream of this node.

## What the page shows, and where it travels

The confirmation page shows the link's `label` and the NAME of the workflow
it starts. The page after a confirmation shows the label again. Both are
there so that the person confirming knows what will start.

So a label is not private to the message it was written for. Whoever opens
the link sees it, and it travels over whatever address the link is on, along
with the token in the link's path. On a deployment whose public address is a
third-party tunnel, that tunnel carries all three. Write a label that says
what the action does ("Mark done", "Start the review") and keep names, ticket
titles and anything else you would not put on a public page out of it. The
same goes for the name of a workflow that a link starts.

## The address a link is on

By default a link is minted on the deployment's public address (the same one
webhooks and approval links use; see `docs/local-public-url.md`).

An operator can put action links on an address of their own, for example one
that is reachable only on a private network:

```
TALOS_ACTION_LINKS_BASE_URL=https://talos.private.example
```

* It must be `https://` and a scheme and host only (a port is allowed): no
  path, query, fragment or user information.
* Unset, nothing changes.
* A value that does not meet the rule mints NOTHING. Every request falls back
  with the reason `link_address_misconfigured`, no token is stored, and the
  controller logs an error naming the variable. It is never replaced by the
  public address: the setting exists to keep links off that address.
* The setting only decides where a link points. The address has to reach this
  deployment's `/action-links/` route for the link to work, and making it do
  so (DNS, a private proxy) is the operator's. A token is found by its hash,
  so links minted before and after a change of address all still resolve.
* It applies to action links only. Approval and correction links, webhooks
  and OAuth callbacks stay on the public address.

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
