# 2026-10-12 — a Google Calendar watch channel can be created and stopped from MCP

**Why.** A watch channel was created by a session-authenticated REST route
used by the settings page and by nothing else. An agent wiring a workflow to
a calendar (`set_push_channel_workflow` exists since this morning) had to ask
a person to click first.

**Decided.**
- **Two tools, `create_gcal_watch_channel(integration_id?, calendar_id?)` and
  `delete_gcal_watch_channel(channel_id)`**, thin handlers over the
  push-channel set, like the Jira pair added the same day. A create with no
  delete would leave an agent able to make what it cannot undo.
- **The work is in `talos_google_calendar::provision`**, behind
  `GcalPushProvisioner` (a `PushChannelProvisioner`, holding the service; the
  inventory stays pool-only). `GoogleCalendarService::provision_watch_channel`
  and `remove_watch_channel` are what the tools reach.
- **Whose connection.** A named connection is read with the caller's user id
  and must be active; another user's is "no such connection", and Google is
  not asked. With none named, the caller's one active connection is used;
  with several, the refusal lists the caller's OWN connection ids (ten at
  most) and nothing is made.
- **An existing channel is handed back as it is.** `create_watch_channel`
  re-points an existing channel's MODULE at whatever it is given, and the
  settings page gives it nothing. This path looks first and returns the
  channel with `created: false`, so asking for a channel that exists never
  changes what it starts.
- **An address Google cannot deliver to is refused before Google is asked**,
  in words (`NotDeliverable`). The rule moved to one function,
  `watch::webhook_url_is_deliverable`, which the service's own create uses
  too; `provision::default_webhook_url` is the one place the address is
  built, and the REST create uses it.
- **`PushChannelProvisioner::create_channel_on(user, target, resource)`**, a
  provided method: the default refuses a resource (an integration whose
  channel covers the whole connection must not make a channel on something
  other than what was named), and Jira keeps it. Google Calendar implements
  it with the calendar as the resource. The Jira provisioner is not touched.
- **A stop says when there was nothing to stop.** The service's
  `stop_watch_channel` is idempotent and reports success for a channel that
  is not the caller's; `remove_watch_channel` reads the channel first and
  answers `ChannelNotFound`.
- **`stop_watch_channel` uses `watch_api_client()`** like create, renew and
  sync, so a test can stand in for Google. Found by the first run of the new
  test: its stop was sent to Google with a test token. Unset, it is the same
  client as before. The compensating stop inside a failed create still builds
  Google's client directly; it runs in a spawned task and is not changed here.
- **The set is built after the calendar service** in the controller's wiring
  (it was beside the Atlassian service): the provisioner needs the service.

**Deliberately NOT done.**
- **No tool for Gmail or Google Cloud channels.** Gmail's create calls
  `users.watch` and takes a label filter; Google Cloud's hands back a push
  endpoint that carries the channel's token, which an MCP reply should not.
  Each is its own decision.
- **No generic `create_push_channel(integration, …)`.** The Jira tools are
  named for their integration and these follow them.
- **`created` can be `true` twice** if two creates for one calendar race past
  the "already watched?" read: the service's create lock makes one channel,
  and the second caller is told it created it. The channel and its bindings
  are right; the word is not.

**Tests.**
- `controller/tests/gcal_watch_provision_tests` (6): a channel is made only on
  the caller's own active connection; with several connections one must be
  named and the refusal names only the caller's; an existing channel bound to
  a module and a workflow is handed back with both bindings and Google is not
  asked again; an undeliverable address and a calendar id that is not one are
  refused before Google is asked; a channel is stopped only by its owner and
  a missing one is said to be missing; the set creates and deletes by
  integration name.
- Unit: the calendar-id rule; every refusal's kind and words; the trait's
  default refusing a resource; the tool's optional arguments (what is not a
  name is refused, not read as "not given").
- Mutations, each applied and reverted, each caught: a named connection is
  not asked whose it is (2 tests fail); a disconnected connection is
  accepted; an existing channel is created again (2); with several
  connections the first is taken; a stop does not ask whether the channel is
  the caller's (2); an undeliverable address is passed on.

**Not verified, stated.** No channel was created at Google by this change. The
two MCP handlers were not called over MCP: they are argument parsing and
wording over `PushChannelInventorySet::create_channel_on` / `delete_channel`,
which the database test drives by integration name. The `NeedsReconnect`
classification (Google refusing the credentials) is not driven; it reads
`looks_like_oauth_failure` over the create's error.

**One home.** `provision::provision_watch_channel` for the create,
`provision::default_webhook_url` for the address,
`watch::webhook_url_is_deliverable` for whether Google can reach it.
