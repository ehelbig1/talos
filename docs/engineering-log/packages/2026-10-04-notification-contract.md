# Notifications: one contract, one adapter per service

2026-10-04

The operator asked for a phone notification channel with buttons, and, while
it was being built on Home Assistant, that anything talking to an outside
service be built so the service can be changed later ("perhaps home
assistant is no longer used and I want to switch to ntfy").

## What was added

* **The contract** (`docs/notification-contract.md`): a compose node returns
  `notification: {title?, body, priority?, tag?, link?, actions?[{title,
  link, one_tap?}]}`; every adapter returns the same verdict.
* **Two adapters**, both catalog templates: `notify-ntfy` and
  `notify-home-assistant`. Each installs with no host and no secret, POST
  only.
* **A cross-adapter test** (`talos-catalog-tests/tests/notification_contract.rs`).
* A section in `docs/adding-an-integration.md` for a service with a fixed
  token, which the guide did not cover.

## Decisions

**Two adapters, built together.** One adapter and a document saying another
could be written is a promise. Two adapters read by one test is the property.
Writing the second changed the first: `tag` and `one_tap` turned out to be
things one service can do and the other cannot, so both became REPORTED
fields of the verdict (`tag_sent`, `one_tap_actions`) instead of silent
differences.

**The seam is the send node's module.** The platform already swaps a node's
module (`swap_node_module`) and already separates compose from send
(`docs/delivery-node-pattern.md`). No new platform mechanism: the contract
is a data shape and a test.

**The contract block is copied, and pinned byte-identical.** A catalog
template is one self-contained source file compiled on its own; templates
cannot share a crate. So the block that reads and checks a notification is
the same text in every adapter, and the test fails on any difference. A
change to the contract is therefore one commit touching every adapter.

**https only.** A link that is not `https://` is not sent. An action link is
a single-use capability; and a failed mint leaves `#` or a `mailto:`, which
must not become a button.

**A missing or empty notification fails the node.** `skip: true` is the way
to send nothing.

**No connection type, no controller code.** Both services authenticate with
a fixed token. The owner stores it; the installed copy is granted its exact
path and the one host.

**One tap.** ntfy's `http` action makes the phone POST in the background;
`/action-links/{token}` acts on a POST with no body, so an action link
marked `one_tap` starts its workflow on one tap. Home Assistant's
notification actions open a link; a background POST there needs an
automation inside Home Assistant, which is the operator's configuration and
is not built.

## Measured

Built through the production compile path and run against the recorded
fixtures (`make check-catalog-fuel`), three actions, the contract's maximum:

| Template | Fuel used | Declared limit | Used |
|---|---|---|---|
| notify-ntfy | 171,472 | 1,000,000 | 17.1% |
| notify-home-assistant | 172,522 | 1,000,000 | 17.3% |

## Tests

* `notify-ntfy` (6), `notify-home-assistant` (4): the request each service
  receives, link and action refusals, skip, dry run, config refusals, and an
  error that names the host and status and not the body.
* Contract (5): identical blocks; every `notify-*` directory is in the list;
  the same notification gets the same verdict; the same refusals; every
  manifest installs able to reach nothing.

## Not verified

* Neither adapter has been run against a real server. The ntfy and Home
  Assistant request formats are written from their documented APIs; the
  fixtures are made-up responses. The first real send is the proof.
* The worker refuses a home-network address, so the Home Assistant adapter
  needs the external https address; not exercised.
* Not deployed.
