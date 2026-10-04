# The home-control contract

A workflow decides what should happen at home. Which system makes it happen
is a separate choice. The two meet at one node:

* a node upstream returns `commands` in service-neutral words;
* the node that acts runs a `control-*` adapter module, which maps those
  words to one system and refuses anything its config does not name.

Adapter today: `control-home-assistant`. There is only one, so the
neutrality of this shape is a design intent and not yet a tested property
(the notification contract has two adapters and a test that holds them
together; this one will get the same test with its second adapter).

## What an upstream node returns

```jsonc
{
  "commands": [                                   // at most 8 are run
    { "target": "office_lights", "action": "turn_off" },
    { "target": "thermostat", "action": "set_temperature", "value": 20.5 },
    { "target": "bedtime", "action": "run" }      // a scene or a script
  ],
  "skip": false                                   // true: do nothing, and say so
}
```

Actions: `turn_on`, `turn_off`, `toggle`, `run`, `set_temperature`.

A target is a NAME the workflow's author chose (`office_lights`), never a
system's identifier. Nothing upstream of the adapter — a compose module, a
model's output, a stored memory — carries an entity id.

## The allow-list

The adapter's `TARGETS` config is the only place a neutral name becomes a
real device, and it lists what each may do:

```jsonc
"TARGETS": {
  "office_lights": { "entity": "light.office", "allow": ["turn_on", "turn_off"] },
  "thermostat":    { "entity": "climate.hall", "allow": ["set_temperature"], "min": 16, "max": 24 }
}
```

A command is REFUSED, and nothing is sent for it, when its target is not in
the map (`unknown_target`), the target does not allow the action
(`action_not_allowed`), the action is not one the contract defines
(`unknown_action`), a temperature is missing, has no bounds configured or is
outside them (`value_missing`, `target_has_no_bounds`,
`value_out_of_range`). A lock, a garage door or an alarm that is not in the
map cannot be reached by anything a workflow emits, including a model that
writes an entity id as a target.

## What an adapter returns

```jsonc
{ "provider": "home-assistant", "skipped": false, "dry_run": false,
  "done": 1, "refused": 1, "failed": 0, "unchanged": 0, "not_run": 0,
  "results": [ { "target": "office_lights", "action": "turn_off", "status": "done", "changed": 1 },
               { "target": "garage", "action": "turn_on", "status": "refused", "reason": "unknown_target" } ] }
```

`done` means the system ACCEPTED the command. That is not the same as
something happening: Home Assistant accepts a command for an entity that
does not exist. So a `done` result carries `changed`, how many things the
system says changed, and the verdict counts `unchanged`, the done commands
that changed nothing. `changed: 0` is a mistyped entity in `TARGETS`, or a
thing that was already in the state asked for. An adapter whose system does
not say omits `changed`.

`DRY_RUN` defaults to true: an adapter reports what it would do and sends
nothing until the node's config turns it off. One command failing is
recorded and the rest continue.

## Deciding who may command

The adapter enforces WHAT may be done. WHEN it may be done without the
owner is the workflow's decision: put an approval gate or an action link in
front of the node for anything the owner should confirm, and give the
workflow's actor the narrowest ceilings that still let it run.
