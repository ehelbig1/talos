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

Disconnecting from Settings hides the row, calls Plaid's `/item/remove` (the
connection stops working and no longer counts against the plan's Item limit),
and deletes the access token from the vault.

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
