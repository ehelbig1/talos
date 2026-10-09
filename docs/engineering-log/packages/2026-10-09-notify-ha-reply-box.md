# A reply box on a Home Assistant notification (2026-10-09)

The operator's list had gone a week with nothing captured: adding to it meant
sending an email, and he never did. He asked for a place to type on the phone.
The companion app can show a text field under a notification; the adapter had
no way to ask for one.

## Decided

* **`REPLY_TITLE` on `notify-home-assistant`** (template v1.1.0). Set, every
  notification that node sends carries one more action,
  `{action: "REPLY", title, behavior: "textInput"}`: Android shows a text
  field for the action named `REPLY`, iOS for `behavior: textInput`. Unset or
  blank, the request body is byte-identical to v1.0.0 (the two existing body
  tests still pass unchanged).
* **Adapter config, not the contract.** A reply box is something one service
  has and another does not. The `notification` object and the shared contract
  block are untouched, `notify-ntfy` is untouched, and
  `talos-catalog-tests/tests/notification_contract.rs` passes as it was.
  `docs/notification-contract.md` gains a section saying where such a thing
  goes.
* **The box takes one of the three action places.** The companion app shows
  three. With three composed actions the last is not sent and is counted in
  `actions_dropped`; `actions_sent` counts composed actions only. One home:
  `actions_shown`.
* **The typed text does not come back through the adapter.** The app raises
  `mobile_app_notification_action` (action `REPLY`, `reply_text`) inside Home
  Assistant. What reads it is the workflow owner's: on the reference fleet an
  automation keeps it in a text helper and a private reader module pulls that
  helper's history with a GET. Nothing in this repository reads a reply.

## Deliberately NOT done

* **A `reply` action in the contract.** It would need a meaning for an
  adapter that has no text field, and a neutral way to say where the text
  goes. One service has it today; a second one is when to decide the shape.
* **A webhook for Home Assistant to POST replies to.** It needs a
  `rest_command` in Home Assistant's YAML, a secret there, and the public
  tunnel to be up at the moment of the reply; a reply typed while the
  platform is off would be lost. Pulling the helper's history loses nothing
  for a day.
* **A verdict field for the box.** The verdict struct is inside the contract
  block; adding one changes every adapter.

## Measured

* `make check-catalog-fuel TEMPLATE=notify-home-assistant`, with the recorded
  run now carrying three actions and `REPLY_TITLE`: 174,439 of 1,000,000
  (17.4%).
* `cargo test -p talos-catalog-tests`: 153 template tests and the 5 contract
  tests pass; the new test is
  `a_reply_box_is_added_from_config_and_takes_one_action_place`.
* Live, 2026-10-09, sent through Home Assistant directly (not through this
  adapter): a notification with `{action: "REPLY", title, behavior:
  "textInput"}` was accepted. A simulated `mobile_app_notification_action`
  event was kept by the automation and read into the list by a real run.

## Stated limits

* The adapter with `REPLY_TITLE` has not sent to a live server; the installed
  copy is v1.0.0 until this merges, deploys and is reinstalled.
* A `REPLY_TITLE` longer than 40 characters, or with a control character, is
  refused before anything is sent, not trimmed.
