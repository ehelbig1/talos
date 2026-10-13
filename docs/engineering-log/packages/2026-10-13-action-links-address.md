# An address of the operator's own for action links (2026-10-13)

An action link's page shows the link's `label`, and the link is built on the
deployment's one public address. On a stack whose public address is a
third-party tunnel, a label a module wrote (which can hold a ticket title or
a name) crosses that tunnel, as does the token. Authors had been making every
label generic to avoid it.

## What the page shows (read in `talos-webhooks/src/action_links.rs`)

The confirmation page: the label and the target workflow's NAME. The page
after a confirmation: the label again. So three things travel over the
link's address: the token (its path), the label, the workflow name. The
brief named the label; the workflow name is the same exposure.

## Decided

* **`TALOS_ACTION_LINKS_BASE_URL`**, read only through
  `talos_config::action_links_base_url`, parsed by the pure
  `parse_action_links_base`:
  * unset or blank: no override, and the mint is byte-identical to before
    (the public address, resolved per call);
  * `https://host[:port]`: links are minted on it, and the public address is
    not even resolved;
  * anything else: an error. http, a path, a query, a fragment, userinfo,
    whitespace, a trailing slash.
* **An unusable value mints nothing; it does not fall back.** The setting
  exists to keep links off the public address, so "ignore a bad value and use
  the default", which is what `TALOS_PUBLIC_BASE_URL` does, would send links
  out on exactly the address the operator set it to avoid. The minter decides
  the address BEFORE writing anything: every request is answered
  `link_address_misconfigured`, no token row is written, and an error names
  the variable and the reason (not the value). The node's report carries the
  reason; the message still sends, with fallbacks. Same shape as
  `ATLASSIAN_WEBHOOK_BASE_URL`, which is refused and never replaced.
* **https only.** A link's path is a capability token.
* **The same strict origin rule as the other address settings**
  (`is_valid_frontend_url`), so a trailing slash is refused here as it is
  there.
* **Action links only.** Approval links, correction links, webhooks and OAuth
  callbacks stay on the public address.
* **The label's visibility is now stated** in `docs/action-links.md` and in
  `add_action_links_node`'s description: it is shown on the page, so it
  travels over the link's address; so does the target workflow's name.

Nothing about a link's use changed: a GET still does nothing, a link is still
claimed once, and it still expires.

## The operator's decision this item contains: hiding the label

The brief asked to consider a per-link "do not show the label after use".

1. **Nothing more** (this change): say plainly that the label is shown, and
   give the operator an address of their own.
2. **A per-link flag that drops the label from the page shown after a
   confirmation.** The confirmation page must keep it, or the page stops
   being honest about what will start. So the label still crosses the
   address once, on the GET. The flag would save the second crossing only.
3. **Hide it on the confirmation page too.** Not offered: the person
   confirming would not know what they are starting.

Recommendation: 1. Option 2 adds a field to the token row, the request shape
and the page for half of one exposure, and the address setting removes the
whole of it for a deployment that needs it. Nothing was built for 2.

## Mutations (the address of a capability URL)

| Mutation | Caught by |
|---|---|
| `link_base` answers an unusable setting with the public address | unit test, and the DB test (a link came back on the fallback address) |
| `parse_action_links_base` accepts `http://` | unit test, and the DB test |

Each restored and touched; all pass.

## Tests

* `talos-config` `action_links_base_tests` (3): no override; an https origin
  as given; every other shape refused, with which of the two reasons.
* `talos-engine` `link_base_tests` (3): no setting is the public address;
  the operator's wins and the public one is not asked for; an unusable one is
  an error.
* `talos-execution-repository`: `action_url` with an address that has a port.
* `controller/tests/action_links_tests.rs` (+2), real rows:
  * a link minted under either address opens the same page, and each is
    still claimed exactly once;
  * the minter with an unusable setting returns
    `link_address_misconfigured` for every request and writes no row; with a
    usable one the link is on that address.

The environment variable itself is not set in any test: the environment
belongs to the whole test process. `mint` reads it and calls
`mint_with_setting`, which the tests call with a parsed value.

## Stated limits

* The setting decides where a link POINTS. Whether that address reaches this
  deployment's `/action-links/` route is the operator's to arrange and is not
  checked: a link on an address that goes nowhere is a dead link. Not built:
  a startup probe of the address.
* The chart has no value for it (it has none for `TALOS_PUBLIC_BASE_URL`
  either); it is set as an extra environment variable.
* A wrong value is discovered at the first mint, not at boot.
* `get_public_url_status` does not show it.

## Rule added to CLAUDE.md

One line under the action-links rule in "WASM Module Development Rules": the
setting, that an unusable value mints nothing, and that the label and the
workflow name are shown on the page.
