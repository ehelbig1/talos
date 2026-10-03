# Plaid Link: one sign-in window at a time (2026-10-03)

**Seen on first use.** Clicking Connect on the Bank accounts card ended with
two Plaid Link windows stacked on each other.

**Most likely cause, not proven.** Starting a sign-in takes a second or two
(a link token from the server, then Plaid's script from its CDN) and the page
showed nothing during that time, so a second click started a second sign-in.
The card's button calls the handler once per click (one `onClick`, no
bubbling parent), and the script is loaded once, so two windows needs two
calls. The controller does not log successful link-token requests, so the
count of calls was not available to confirm it.

**Fix.** `openPlaidLink` refuses a call while a window is open or opening
("A bank sign-in window is already open"); the connect handler ignores a
click while one is in flight and shows "Opening the bank sign-in…" at once.
An `onExit` after the promise settled is ignored.

**Test.** A second `openPlaidLink` while the first is open rejects and creates
no second window; after the first closes a new one can start. Fails on the
previous code (two windows are created).

**Stated limit.** Not exercised in a browser against Plaid; the operator's
retry is the check.
