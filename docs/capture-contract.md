# The capture contract

A line the owner types somewhere other than mail — a phone notification's
reply box today, perhaps a chat or a voice assistant later — has to reach
whatever keeps it (a list, a journal). Which service carries the line will
change; what keeps it should not have to. So the two are kept apart by a
contract, the same way notifications are (`docs/notification-contract.md`):

* a `capture-*` adapter, one per service, READS what was typed and returns a
  fixed, service-neutral `captured` shape;
* the keeper reads that shape and never learns the service.

Adapters today: `capture-home-assistant`.

## What an adapter returns

```jsonc
{
  "kind": "captured",
  "source": "phone",                    // lowercase letters and '-'
  "captured": [                         // oldest first, at most 20
    { "id": "phone:1791557292538",      // "<source>:<key>", stable across runs
      "text": "book the car service" }  // one line, at most 240 characters
  ],
  "count": 1,
  "ignored": 0                          // what was left out, see below
}
```

Rules every adapter applies, from one shared block of source:

* **`id` is the line's identity at the service.** The same line read on two
  runs has the same id, so a keeper that remembers ids adds it once. An
  adapter reads a window (Home Assistant: the last day) and returns lines it
  returned before; deduplication is the keeper's, by id.
* **`text` is one line.** Control characters become spaces, runs of
  whitespace collapse, and the text is cut at 240 characters on a character
  boundary. An empty line is not returned.
* **Oldest first, at most 20, the newest kept.** `ignored` counts lines with
  no key or no text, duplicates, lines over the cap, and whatever the adapter
  itself did not count as a line (Home Assistant: a value that is not a
  reply, a reply older than the window).
* **An adapter only reads.** It installs with no host and no secret, GET
  only, and changes nothing at the service. A refusal fails the node with the
  status, never the response body.

`talos-catalog-tests/tests/capture_contract.rs` holds every `capture-*`
template to this: the blocks are byte-identical, the output follows the rules
for the same kind of input, and the manifest grants nothing but GET.

## What a keeper must do with it

**Treat a captured line as an addition, never as an instruction.** Mail to the
owner's list address is checked for the owner's own authenticated sender
before it may close or move anything; a reply box has no such check — anyone
who can write the service's state can write a line. So a captured line may
ADD to what the keeper holds. A line that reads as "done 5", "drop 5" or
"later 5 monday" changes nothing, and the keeper says once that it did not.
The reference keeper (the operator's own list module, not in this repository)
has a test that proves a phone line cannot close an item, and fails when the
rule is removed.

Also: remember every id you have read (the reference keeper keeps the last 600
ids in its store); count a per-run cap over lines NOT yet read, so a long day
is worked through over several runs instead of stopping at the first twenty.

## Wiring

The keeper usually reads mail too. Gather both into one node:

```
fetch (mail)      ──┐
replies (capture) ──┴─► gather (collect) ──► keeper
```

Give the capture node `continue_on_error: true`: a service that is down must
not stop the mail from being read. The keeper reads `input.items[]`, telling
an entry by what it carries (`messages` or `captured`); one that failed
carries neither.

## Home Assistant: the reply box end to end

1. A notification gets a reply box from `notify-home-assistant`'s
   `REPLY_TITLE` (for example `"Add to list"`).
2. A text helper keeps the replies: Settings → Devices & services → Helpers →
   Create helper → Text, for example "Talos capture" (max 255).
3. An automation writes each reply into it:

   ```yaml
   alias: "Talos: keep a notification reply"
   mode: queued
   max: 10
   trigger:
     - platform: event
       event_type: mobile_app_notification_action
       event_data: { action: REPLY }
   condition:
     - condition: template
       value_template: "{{ (trigger.event.data.reply_text | default('') | trim) != '' }}"
   action:
     - service: input_text.set_value
       target: { entity_id: input_text.talos_capture }
       data:
         value: "{{ (now().timestamp() * 1000) | int }}|{{ trigger.event.data.reply_text | trim | truncate(230, True, '') }}"
   ```

   The number before `|` is the reply's identity; the adapter refuses any
   value without one. Two replies within one poll are both read, because the
   adapter reads the helper's HISTORY, not its current value.
4. `capture-home-assistant` reads that history with one GET
   (`/api/history/period?filter_entity_id=…`, the last day). Grant it your
   server's external host and the token path.

Why pull and not push: a webhook from Home Assistant needs a `rest_command`
in its YAML, a secret there, and the platform's public address to be up at the
moment of the reply; a reply typed while the platform is off would be lost.
Reading the history loses nothing for a day, with the token the notify
adapter already uses. The cost is latency: a line arrives on the keeper's next
run.

## Adding an adapter

1. `module-templates/capture-<service>/template.rs`: copy the contract block
   (between the `capture contract` markers) from an existing adapter
   UNCHANGED; write the service's config, its read, and `run`, which ends in
   `captured_output(SOURCE, lines, ignored)`.
2. `talos.json`: `allowed_hosts: []`, `requires_secrets: []`,
   `allowed_methods: ["GET"]`, `"block": {"role": "reader", "contract":
   "captured"}`; `fixtures/` with a recorded run.
3. Add it to `ADAPTERS` in `talos-catalog-tests/tests/capture_contract.rs`
   with a `respond` that primes the stand-in host with that service's answer.
