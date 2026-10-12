# 2026-10-12 — the settings page shows and sets a watch channel's workflow

**Why.** A Google Calendar or Gmail watch can start a workflow, and the
binding could be set over MCP or REST only. The channel tables on the
settings page had no control for it and did not show one that existed: a
channel that started a workflow on every change looked the same as one that
started nothing. For Gmail the list had carried `workflow_id` since the
integration was written and the table never read it.

**Decided.**
- **One picker**, `watch-channels/WorkflowBindingSelect`, a native select
  with an accessible name per row ("Workflow started by <what is watched>").
  It reports the choice; the panel makes the `PUT …/workflow` request.
- **A bound channel is never shown as unbound.** When the bound workflow is
  not in the owner's list (deleted, or the list has not loaded), the picker
  shows the id — "Not found (…)" once the list is in — and keeps it
  selected. "None" is shown only for a channel with no binding.
- **What the server holds is what is shown.** The change is applied to the
  cached row at once; a refusal puts the row back and says why (the server's
  own sentence), and the list is re-read either way.
- **Gmail's row says what the binding costs**: with a module and a workflow
  both bound, "not run while a workflow is bound" under the module's name,
  because on a Gmail watch the workflow is started instead of the module.
- **The workflow list is the `Workflows` query other settings panels use**,
  cut down to id and name by the hook's `select`.

**Deliberately NOT done.**
- **Google Cloud channels.** Their bind route is in a pull request that had
  not merged when this was written; the picker is one more cell on that
  table when it has.
- **No picker in the create dialogs.** A channel is created, then bound.
- **`Workflows` returns each workflow's graph too.** Asking for names only
  is a new query and a regenerated client; the existing one is already what
  two other panels on this page load.

**Tests.** `GoogleCalendarWatchChannels.test.tsx` (5) and
`GmailWatchChannels.test.tsx` (3), through the panels against a mocked
server: the bound workflow is shown by name; an unbound channel shows None;
picking one sends `{workflow_id}` to that channel's route and None sends
`null`; a refusal leaves the picker on what the server holds and reports the
server's sentence; a binding whose workflow is not in the list is shown as
not found, not as None (mutation: remove that option, the test fails); the
Gmail note appears only when both are bound.

**Not verified, stated.** The page was not opened in a browser: layout at
narrow widths and the look of the select beside the existing buttons are
unseen. The refusal test passes with or without the optimistic rollback,
because the re-read restores the row either way; it holds the outcome, not
the mechanism.
