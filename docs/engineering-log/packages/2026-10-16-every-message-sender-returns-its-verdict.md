# Every message sender returns its verdict (2026-10-16)

`2026-10-16-the-engine-records-what-was-sent.md` made the engine record a
send from the `notify-*` adapter's verdict and left email out: the HTML email
sender returned `sent`, `message_id`, `thread_id` and nothing the engine could
read as a send. Email is where most of what Talos says to its owner goes (the
Sunday review, the morning dispatch, the briefings), so a table of phone
sends alone measured the short prompts and missed the substance, and an
"engagement rate" from it would have described the smaller channel and been
read as the whole.

## Decided

- **The verdict is a rule of the sender role, not of the notification
  contract.** `docs/building-blocks.md` ("Sender"): a sender of a message to
  a person (`notify-*`, `send-*`) returns `provider`, `sent`, `skipped`,
  `dry_run`, `parts_total`, `parts_sent`, `actions_sent`. The notification
  contract extends that shape with what a phone service may or may not do
  (`one_tap_actions`, `kept_actions`, `tag_sent`); the email sender returns
  the base beside its Gmail ids. Folding email INTO the notification contract
  was declined: that contract is about a composed `notification` and its
  rules, none of which an email reads.
- **`send-html-email` returns the verdict additively**, v1.1.0. `provider` is
  `gmail` (the adapters name the service: `ntfy`, `home-assistant`), one
  email is one part, and `actions_sent` is the number of `/action-links/`
  paths in the body, the address every minted action link carries
  (`docs/action-links.md`); an unminted fallback (`#`, `mailto:`) is not one.
  The count is one pass over the body with no allocation and stops at the
  verdict's bound (1024), so no body can make its own send unrecordable.
  `message_id`, `thread_id`, `to`, `subject` and `rfc822_bytes` are unchanged
  for the consumers that read them.
- **The report's rate is over messages that could be tapped.**
  `MessageEngagementRow` gained `executions_with_actions` (executions whose
  sends carried at least one action) and `tap_rate =
  executions_tapped / executions_with_actions`, `null` when nothing carried
  one. An email with no buttons can be sent and never tapped; over every
  execution, a workflow that mails a plain report would have read as ignored.
- **Sends are given per provider; taps are not.** `providers:
  [{provider, sends, parts_sent, actions_sent, one_tap_actions}]` per
  workflow, from a second bounded statement over the same window. A run that
  sent by two services minted its action links once, for the run, so a tap
  cannot be attributed to one of them; splitting it would have counted it
  twice or guessed.
- **A message sender is held to the verdict by test.**
  `talos-catalog-tests/tests/delivery_verdict.rs` lists every message sender
  (`notify-ntfy`, `notify-home-assistant`, `send-html-email`), runs each with
  a message carrying one action link and reads the real output through
  `talos_workflow_engine_core::delivery_verdict::read_delivery_verdict`: a
  send is `Sent` with the provider's word and one action, a skip and a dry run
  are `NothingSent`. A template that declares the sender role with a
  `notify-` or `send-` name and is not in the list fails the build.

## Deliberately NOT done

- **No second contract block.** A contract (the standard's sense) is a doc, a
  block of source copied into every adapter and a `_contract.rs` test. The
  verdict is seven JSON fields a sender builds in one place; a shared block
  for them would be churn in the two adapters that already build theirs
  inside the notification block, for no rule the test above does not hold.
- **`provider` is the service, not "email".** The report groups by the word
  the sender gives, and `gmail` says which adapter sent; a second email
  service would be a second word, both of them email. A channel grouping
  (phone / mail) is a reader's concern, left until a second mail sender exists.
- **No read-state from Gmail.** Talos reads the owner's Gmail and could ask
  whether a sent message still carries the unread label, a real read signal
  no phone channel offers. It would mean recording the message id on the row
  (an identifier, not content) and a reader that polls. Left until the first
  weeks of send rows show whether taps alone say anything about mail.
- **`control-home-assistant` and `gmail-modify` return no verdict.** Both
  declare the sender role, neither sends a message to a person: one switches
  a device, one moves labels. The rule and the test are scoped by name
  (`notify-`, `send-`), which is the role standard's own convention for its
  contracts.
- **No backfill, no migration.** The table and the reader's recognition are
  unchanged; an installed copy of the email sender from before this package
  returns the old shape and is read as `NotASend`, which the hook test pins.

## Measured

- Senders on the catalog: five templates declare the role; three send a
  message to a person and all three now return the verdict.
- `make check-catalog-fuel TEMPLATE=send-html-email` on the recorded run
  (10,592-byte body): 754,641 fuel, 14.8% of the declared 5,115,000; the
  2026-10-12 recording of the same body used 681,355, so the `str::matches`
  pass over the body costs about 7 fuel per byte. `recommended_fuel` (55 fuel
  per byte, ×1.5) was left as declared.

## Latent vs live

Live only after the fleet's installed copies of `send-html-email` are
reinstalled from the catalog (installed copies do not refresh; see
`memory/installed_catalog_copies_never_refresh.md`). Until then each email
send node runs the old copy and is not counted, and the report's population
note says so. A mix of old and new copies is safe: the old shape is
`NotASend`, never a wrong row.

## Stated limits

- A tap on an email's link is set against the run, not the email: if the same
  run also sent a notification, the tap is the run's, and the per-provider
  breakdown says only how many sends each service made.
- `actions_sent` for email counts the action-links path in the body, however
  it got there. A composer that writes the path in prose would be counted;
  none does, and the count is a measurement, not a control.
- The verdict rule is held by name. A message sender named outside
  `notify-*` / `send-*` would need adding to the test's prefixes.

## One home

- The rule: `docs/building-blocks.md`, "Sender"; recorded in CLAUDE.md (the
  notification-contract bullet).
- The reader: `talos_workflow_engine_core::delivery_verdict` (unchanged).
- The email sender's verdict: `module-templates/send-html-email/template.rs`
  (`PROVIDER`, `count_action_links`).
- The test: `talos-catalog-tests/tests/delivery_verdict.rs`.
- The report: `AnalyticsRepository::message_engagement` (`ProviderSends`,
  `executions_with_actions`), rendered with `tap_rate` by
  `talos-mcp-handlers/src/analytics.rs::handle_get_message_engagement`.
