# Connecting bank accounts (Plaid)

Talos reads balances and transactions through [Plaid](https://plaid.com). The
bank sign-in happens in Plaid's own window (Plaid Link); the bank password goes
to Plaid and the bank, never to Talos.

## What lives where

| Piece | Where |
|---|---|
| Starting a sign-in, saving a connection | `talos-plaid-connect`: `POST /api/plaid/link-token`, `POST /api/plaid/connect` (session auth + CSRF) |
| The Settings card ("Bank accounts") | provider registry entry `plaid`; listing and disconnect are the generic integration paths |
| Connection records | `plaid_items` (one row per Plaid Item: one bank sign-in, possibly several accounts) |
| Access tokens | vault `plaid/access_token/{item_id}`, owned by the user; never sent to the browser |
| App credentials for reader modules | vault `plaid/client_id`, `plaid/secret`, rewritten from the server's settings on every connect |
| Reading a bank | catalog template `plaid-bank-digest`: one node per bank, read-only POSTs to Plaid, returns balances and a digest of the transactions |
| Combining banks | catalog template `plaid-money-summary`: pure computation over the digests |

Disconnecting from Settings hides the row, calls Plaid's `/item/remove` (the
connection stops working and no longer counts against the plan's Item limit),
and deletes the access token from the vault.

A connection made in the other Plaid environment (a sandbox bank left over
after the switch to production) is ended here only: its token is deleted and
the log says it was not removed at Plaid, because this server has neither that
environment's host nor its app secret. A sandbox connection left at Plaid
costs nothing; a production one left this way has to be removed in the Plaid
dashboard.

## Plaid dashboard

1. Request Production access in the Launch Center. Teams created on or after
   2026-04-15 can use the free Trial: up to 10 Production Items.
2. Products: Transactions. Balances come with every connection.
3. Complete the company and security profile. Banks that sign in through
   OAuth (Wells Fargo, Citi, Chase, Capital One, U.S. Bank, PNC, Schwab, …)
   are enabled only after it; Plaid says most within hours.
4. No redirect URI is needed while Link is used from a desktop browser: OAuth
   banks open in a pop-up. Production redirect URIs must be HTTPS.

## Server settings

All three or none (`talos-plaid` refuses a partial configuration at boot):

```
PLAID_ENV=production        # or sandbox
PLAID_CLIENT_ID=…
PLAID_SECRET=…              # the secret for THAT environment
```

Changing `PLAID_ENV` does not move existing connections: sandbox connections
stay listed as "(sandbox)" and should be disconnected; each bank is connected
again in production.

## Content security policy

The production web server (`frontend/nginx.conf`, the chart's frontend
ConfigMap) allows exactly Plaid Link's script URL, its iframe on
`cdn.plaid.com`, and Plaid's API hosts. Plaid's guidance also lists
`'unsafe-inline'` for scripts; it is deliberately not added. The development
server sets no policy. Link has not been exercised under the production
policy.

## Reading the banks in a workflow

Each bank's access token appears in the secrets list as
"Plaid access token (<bank>)" at `plaid/access_token/{item_id}`.

1. Use an actor with `max_llm_tier = tier1` and `egress_scope = public` (bank
   data can reach no outside model), `max_write_ceiling = readonly` and
   `http_verb_ceiling = write` (Plaid's reads are POSTs; nothing else the
   actor does may change anything).
2. One `plaid-bank-digest` node per bank: `PLAID_ENV`, `ACCESS_TOKEN` =
   `vault://plaid/access_token/{item_id}`, `INSTITUTION`, `TIME_ZONE`. Set
   `continue_on_error` so a bank that needs reconnecting does not hide the
   others. The module refuses anything but that reference in `ACCESS_TOKEN`,
   so a token cannot be pasted into a workflow.
3. Join them with a Collect node and follow it with `plaid-money-summary`
   (`BANKS` = the institutions expected).

The reader builds the request with `vault://` references; the host replaces
them when the request is sent, so the module never holds a credential, and
what it returns is a digest: balances, weekly totals, the week's largest
day-to-day items and the charges that repeat monthly. Banks put account digits
inside names ("CHECKING ...1234"), so any word of a name carrying four or more
digits is dropped. Nothing is stored between runs.

The reader makes one request for the newest 300 transactions. A bank with more
than that in the window is reported `truncated`, and only the weeks that were
read whole are counted.

A total that rests on a bank that could not be read is `null`, not a partial
sum: cash and the months of cash covered need every bank.

A connected bank is not read until a node is added for it.
