# 2026-10-01 — the dev controller port is published on both loopback families

**Defect.** `docker-compose.yml` published the controller on
`127.0.0.1:8000` only. On macOS `localhost` resolves to `::1` first, so a
client that does not fall back to IPv4 is refused. Observed: after a
controller restart an MCP client configured with `http://localhost:8000/mcp`
stayed `ECONNREFUSED` for the rest of the session while `curl` and the
browser reached the same URL.

**Measured.**
* `curl http://127.0.0.1:8000/health` → 200; `curl http://[::1]:8000/health`
  → refused.
* Node 24 `fetch('http://localhost:8000/health')` → 200 with address-family
  fallback, `ECONNREFUSED` with `--no-network-family-autoselection`.
* A throwaway container published on `127.0.0.1` and `[::1]`: both families
  answer, and the no-fallback client gets 200.

**Fix.** The controller service publishes `[::1]:8000:8000` beside
`127.0.0.1:8000:8000`. Still loopback only.

**Not changed.** The other published ports (Postgres, Redis, NATS, MinIO,
observability): their clients are given `127.0.0.1` or run inside the compose
network. Why that MCP client did not fall back was not investigated; it is
not Talos code.

**Stated limit.** Takes effect at the next `make up`. A host with IPv6
loopback disabled would fail to bind `[::1]`; none is known here.

**Guard.** None beyond `docker compose config`; the behaviour was shown with
the throwaway container above.
