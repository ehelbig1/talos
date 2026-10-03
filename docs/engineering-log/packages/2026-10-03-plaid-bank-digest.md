# Reading connected banks: `plaid-bank-digest` and `plaid-money-summary` (2026-10-03)

**What existed.** Banks could be connected from Settings (three are, in
production). Nothing read them: the one reader module was a sandbox prototype
bound to a single hand-linked item.

**What this adds.**
* Catalog template `plaid-bank-digest` (http-node, POST to `production.plaid.com`
  / `sandbox.plaid.com` only): one bank per node, ONE `/transactions/get`
  request for the newest 300 rows, with `/accounts/get` as the fallback for
  balances when transactions are refused.
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
  day-to-day spending per category per week, last week's five largest
  day-to-day items, monthly charges. Found on the first live read: a bank puts
  account digits inside names ("CHECKING ...1234", "AUTO PAY XXXXXXX5678"), so
  any word of an account or transaction name carrying four or more digits is
  dropped (`display_name`), and the replacement character is removed.
* **Fixed costs (housing, utilities, loans) are one weekly total**, not a
  category beside a usual week and not among the largest items: they are
  monthly, so a week-by-week comparison of them says nothing.
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
  cents) 26 to 35 days apart, THREE times running. On the first live read two
  equal purchases a month apart (a pizza order, a ride) were listed as monthly
  charges; two is chance, three is not. The window is 14 weeks, which always
  holds three charges of a monthly subscription.
* **A new monthly charge** is reported only in the week its second charge
  lands (so a stateless reader reports it once), only from $1, and as a price
  change only when it is that merchant's one running series and another price
  was charged a month before it. A merchant billing two things at once is two
  charges, not a price change (also from the live read).
* **A month of spending is the monthly charges once plus the rest averaged by
  week.** Averaging everything by week overstated it by 9% on live data: a
  14-week window holds four rent payments but 3.2 months.
  Stated limits: yearly charges are not found; a merchant whose label changes
  from charge to charge is not matched; a monthly bill whose amount varies by
  more than 5% (a utility) is not a monthly charge here and is averaged by week.
* **The work is bounded by rows, not pages.** Measured on live responses:
  about 110,000 fuel per transaction (they are about 2 KB each and most of it
  is skipped fields), so 300 rows fit under the 50 M per-node ceiling with
  room. A bank with more than 300 rows in the window is reported `truncated`
  and only the weeks read whole are counted (a week counts when it begins
  after the oldest row's day); if the rows are not newest first, or not one
  whole week was read, the transactions are unavailable and the balances are
  still given. One request also means no partial-page state.
* **Plaid's error body is discarded**; only its `error_type` and `error_code`
  are kept (the body can repeat request fields).
* **Disconnect across environments:** not sent to Plaid. Measured on the dev
  deployment: a sandbox bank disconnected after the switch to production was
  sent to the production host and refused with `INVALID_ACCESS_TOKEN`.

**Measured.** Live, three banks: 41, 216 and 33 rows at 4.8 M, 23.0 M and
3.8 M fuel; the combiner 3.7 M. The combiner on three synthetic digests
(17.5 KB): 3.6 M fuel; rendering only the rows that are shown took it from
4.5 M.

**Tests.** The templates carry their own tests (12 and 7), run natively
against a stand-in for the host bindings; they are not run by CI, like every
template's. `controller/tests/plaid_connect_tests` gains the cross-environment
disconnect (fails with the old behaviour: `/item/remove` is sent).

**Live check (2026-10-03).** The same source runs on the dev platform as two
modules behind a three-bank workflow: all three banks read, six accounts, a
complete summary, no word with four or more digits in any returned name.

**Not covered.** No automated test drives the reader against Plaid. The
truncated path (more than 300 rows) has not been seen live.
