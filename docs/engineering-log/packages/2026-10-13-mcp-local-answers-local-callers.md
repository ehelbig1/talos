# The tokenless MCP route answers a caller on the same machine, and nobody else

2026-10-13

## What was wrong

`/mcp/local` has no token. Outside production it runs every tool as the
first user in the database. Its one condition was the build mode
(`!talos_config::is_production()`), which says whether the route is mounted
and nothing about who can reach it.

Two things put the controller's port behind another address, and both
forwarded this route:

* **The public tunnel of a development stack.** The tunnel forwards every
  path to `controller:8000`. `docs/local-public-url.md` said "all its
  public-path handlers carry their own auth"; this one carries none.
* **A reverse proxy in front of a non-production build.** Both nginx
  configurations proxy `/mcp` by prefix, which matches `/mcp/local`, and
  `docker-compose.prod.yml` runs `RUST_ENV: staging`.

**Observed, live.** On a development stack with the tunnel up, an
`initialize` request to the tunnel's address for `/mcp/local` was answered
`200` with the server's banner. `/mcp` on the same address answered `401`.
So anyone who learned the tunnel's hostname could recall any actor's memory,
read any execution's outputs, change workflows and start them, as the first
user. The tunnel's own request log held its last 200 requests (about three
hours); the only requests to `/mcp*` in it were this probe. That is the
whole of what is known about earlier use: the controller's tool-call line
does not record where a call came from.

## Decided

**A request is answered only when nothing about it says it came from
somewhere else** (`talos_mcp_handlers::local_caller`, a layer on both verbs
of the route):

1. No forwarding header: `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`,
   `X-Forwarded-Proto`, `X-Real-IP`, `Via`. A tunnel or proxy adds one, and
   the caller behind it cannot remove it.
2. `Host` names this machine: `localhost`, a `127.0.0.0/8` address or
   `[::1]`, any port. Exactly one `Host`; for HTTP/2 the request target's
   authority. A proxy that passes the public name through fails here, and so
   does a web page whose name was re-pointed at `127.0.0.1` (DNS rebinding),
   which the browser sends under the page's own name.
3. `Origin`, when present, is an `http(s)://` loopback origin. `null` is not.

**Headers, not the peer address.** Under compose a request from the host and
a request from the tunnel's container both arrive from the bridge network, so
the peer address cannot tell them apart.

**A refusal is a bare `404`**, which is what a production build answers for
the path. It is counted on `talos_mcp_auth_total{outcome="local_route_refused"}`
(a new value of `McpAuthOutcome`, seeded at zero like the others) and logged
at WARN under `talos_audit` with `event_kind = "mcp_local_refused"` and the
reason (`forwarded`, `host_not_local`, `origin_not_local`). No header value
is logged; each is the caller's text.

**The route is a function** (`local_router`), so the tests drive it as
`create_router` mounts it rather than a copy of it.

## Deliberately NOT done

* **No token on the local route.** `scripts/confirm-deploy.sh`, the drill
  reporter and every local coding session use it without one, and that is
  what it is for. Whether a session should get less than the whole platform
  is a separate question, with options, put to the operator the same day.
* **No setting that widens the `Host` list** (a service name, a tunnel
  name). A caller that is not on the machine has `/mcp` and an agent token.
  A setting here would be the next way this route ends up public.
* **`docker-compose.prod.yml` keeps `RUST_ENV: staging`.** Its header
  explains why; the header now says the route is mounted and who it answers.
* **The settings page of the web UI still prints a local endpoint** built
  from the page's own origin. Opened on a non-local address it prints an
  address that now answers `404`. Not changed here.
* **No alert rule on the new counter value.** Recorded as a follow-up; the
  runbook names the series.

## Tests

* `talos-mcp-handlers` `local_caller::tests` (5): the loopback names; 22
  names that are not (look-alikes, service names, private addresses,
  userinfo, bad ports, IPv4-mapped IPv6, two `Host` headers); HTTP/2
  authority; each forwarding header; `Origin`.
* `controller/tests/mcp_local_route_caller_tests.rs` (4), real database, the
  route as mounted: a local caller is served under five spellings of `Host`
  and with a local `Origin`; thirteen requests from elsewhere each get an
  empty `404`; the event stream follows the same rule; no `Host` at all is
  not served. Three of the four failed before the layer existed ("the public
  name as Host was served").

Mutations, each caught and then restored:

| Mutation | Caught by |
|---|---|
| layer removed from the route | 3 of the 4 database tests |
| forwarding headers ignored | `a_forwarding_header_marks_a_request_whatever_its_host_says` |
| any single `Host` accepted | `any_other_name_is_not`, `an_http2_request_is_judged_by_its_authority` |
| `Origin` ignored | `a_browser_is_served_only_for_a_page_from_this_machine` |
| `localhost` matched by prefix | `any_other_name_is_not`, and the `Origin` test |

## Stated limits

* This is reachability, not authentication. A process on the machine, or one
  on the same container network that sends `Host: localhost`, is served as
  the first user. The local route is operator-equivalent to whoever can
  reach the port.
* A proxy configured to BOTH rewrite `Host` to a loopback name AND strip its
  own forwarding headers defeats it. Neither nginx configuration in this
  repository nor the tunnel's default does either.
* An operator's own port-forward (`ssh -L`, `kubectl port-forward`) reads as
  local, which is the intent.
* A stack running a build from before this change, with a tunnel up, is
  still exposed until it is redeployed or the tunnel is stopped.

## One home

`talos_mcp_handlers::local_caller::{not_local, local_callers_only}`.
`CLAUDE.md` ("HTTP middleware & router rules") carries the rule: no route
without auth on the strength of the build mode alone.
