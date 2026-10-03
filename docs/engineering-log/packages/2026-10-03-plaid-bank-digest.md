# Reading connected banks: `plaid-bank-digest` and `plaid-money-summary` (2026-10-03)

**What existed.** Banks could be connected from Settings (three are, in
production). Nothing read them: the one reader module was a sandbox prototype
bound to a single hand-linked item.

**What this adds.**
* Catalog template `plaid-bank-digest` (http-node, POST to `production.plaid.com`
  / `sandbox.plaid.com` only): one bank per node, `/transactions/get` paged by
  offset (500 a page, at most 10 pages, the cap reported as `truncated`), with
  `/accounts/get` as the fallback for balances when transactions are refused.
* Catalog template `plaid-money-summary` (minimal-node): combines the digests
  that a Collect node gathers.
* `talos-plaid-connect`: a disconnect of a bank connected in the OTHER Plaid
  environment is ended here only (`removal_at`), and a bank's token entry is
  named "Plaid access token (<bank>)".

**Decisions.**
* **Stateless.** `/transactions/get` over a fixed window, not `/transactions/sync`
  with a stored cursor: no state to keep or corrupt, and the reader actor stays
  `readonly` (a readonly actor's `__memory_write__` is refused, so a stored
  ledger would have needed `write`). Nothing is stored between runs.
* **Cached balances.** The balances come with `/transactions/get`
  (`/accounts/get` as fallback), not `/accounts/balance/get`, which forces a
  live refresh at the bank and is billed per call.
* **One node per bank**, each with its own `vault://plaid/access_token/{item}`
  reference in config. The module grant is `plaid/access_token/*`, which
  permits and does not deliver; the config reference is what delivers that one
  token to that one node. A bank connected later is not read until a node is
  added for it (stated limit).
* **`ACCESS_TOKEN` must be exactly that reference.** Anything else is refused
  before a request is built, so a token pasted into a workflow is never sent.
  `PLAID_ENV` has no default.
* **A digest leaves the module, not the statement:** balances, weekly totals,
  per-category weekly totals, last week's five largest items, monthly charges.
  Account numbers and masks are not carried.
* **Money is added in whole cents**; amounts are converted once on the way in
  and once on the way out.
* **Unknown is not zero.** An unread balance is `null`. In the summary, cash,
  what is owed on cards and the months of cash are `null` unless every
  expected bank arrived and every balance was read; spending from the banks
  that were read is still given, marked `partial`.
* **Transfers and credit-card payments are left out of spending** (Plaid
  categories `TRANSFER_IN`, `TRANSFER_OUT`, `LOAN_PAYMENTS_CREDIT_CARD_PAYMENT`)
  and their totals reported beside it. Stated limit: a payment to a person
  made as a transfer is left out too.
* **The usual week is a median** of the earlier weeks, not a mean, and is not
  stated from fewer than four. Weeks before a bank's history begins (no
  transactions at any bank, at the far end) are not counted as zero weeks.
* **A monthly charge** is the same merchant at the same price (within 5% or 50
  cents) 26 to 35 days apart. It is reported as new only in the week its
  second charge lands, so a stateless reader reports it once. A different
  price at the same merchant a month earlier makes it a price change.
  Stated limits: yearly charges are not found; a merchant whose label changes
  from charge to charge is not matched.
* **A later page that fails makes the transactions unavailable** rather than
  summing the pages that arrived; the balances are kept.
* **Plaid's error body is discarded**; only its `error_type` and `error_code`
  are kept (the body can repeat request fields).
* **Disconnect across environments:** not sent to Plaid. Measured on the dev
  deployment: a sandbox bank disconnected after the switch to production was
  sent to the production host and refused with `INVALID_ACCESS_TOKEN`.

**Measured.** The combiner on three synthetic digests (17.5 KB): 3.6 M fuel.
Rendering only the rows that are shown took it from 4.5 M.

**Tests.** The templates carry their own tests (12 and 7), run natively
against a stand-in for the host bindings; they are not run by CI, like every
template's. `controller/tests/plaid_connect_tests` gains the cross-environment
disconnect (fails with the old behaviour: `/item/remove` is sent).

**Not covered.** No test drives the reader against Plaid; the first live read
is the check for the response shapes.
