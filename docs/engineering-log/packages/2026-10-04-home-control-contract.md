# Home control: neutral commands, an allow-list, one adapter

2026-10-04

The operator asked for Home Assistant to be Talos's first control target,
and for anything that talks to an outside service to be replaceable later.

## What was added

* `docs/home-control-contract.md`: an upstream node returns
  `commands: [{target, action, value?}]` in neutral words.
* `control-home-assistant` (catalog template): maps each neutral target to
  an entity through its `TARGETS` config and refuses everything else.

## Decisions

**The config is the allow-list.** A command reaches the house only when its
target is in `TARGETS` and that target lists the action. Nothing upstream
carries an entity id, so a model that writes one as a target is refused as
`unknown_target`. Temperature needs both bounds configured; a target with
none refuses it.

**A closed action set.** `turn_on`, `turn_off`, `toggle`, `run`,
`set_temperature`. A general "call any service with any data" adapter would
make the allow-list meaningless.

**`DRY_RUN` defaults to true**, the house pattern for a module that changes
something (`gmail-modify`).

**Results carry the neutral names only.** No entity id, no response body.

**One adapter is not a proven contract.** The notification contract was
built with two adapters and a test that holds them together. This has one,
because there is no second home system here to write against. The document
says so; the cross-adapter test comes with the second adapter.

**No approval is built in.** The adapter decides what may be done; whether
it may be done without the owner is the workflow's (an approval gate or an
action link in front of the node).

## Measured

`make check-catalog-fuel TEMPLATE=control-home-assistant`, eight commands
(the maximum): 343,386 fuel of a declared 1,638,000 (21.0%).

## Tests

Six, in the template: the three request shapes; eight refusals with nothing
sent; the dry-run default and `skip`; a failure recorded while the batch
continues; the command limit; config refusals, including an entity id that
tries to carry a second field.

## Not verified

Never run against a real Home Assistant. The worker refuses a home-network
address, so `BASE_URL` must be the external https address. Not deployed, and
no workflow uses it.
