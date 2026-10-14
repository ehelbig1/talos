# Memory read grants

A memory read grant is a bearer token that reads **one key of one actor's
memory**, and nothing else. It is how to hand a single document to a session
or a program that must not have the rest of the platform.

## Why not MCP access

MCP access is the operator's own. Through it a caller can recall any key of
any actor you own, read every execution's outputs, write memory and change
workflows. An MCP agent token cannot be limited to a set of tools, to
read-only, to one actor or to a key prefix, and it does not expire. Telling a
session "read only this" over MCP is an instruction to the session, not a
fact about what it holds.

A grant is the fact. Its scope is fixed when you make it; the holder sends
the token and no other input, so there is nothing to widen.

## Making one

```
create_memory_read_grant(
  actor_id: "<actor>", key: "briefs/approved",
  label: "brief for one build session",
  ttl_hours: 24,          // 1 to 168; default 24
  max_reads: 5)           // optional; omitted = any number until it expires
```

The reply carries the token **once**. Only its hash is stored. It also says
whether anything is stored under the key now (`key_present`): a typo makes a
grant that reads nothing.

`list_memory_read_grants` shows each grant, whether it is live, expired,
revoked or used up, and how many times and when it was last read.
`revoke_memory_read_grant(grant_id)` ends one at once.

## Reading through one

```
GET <address>/memory-grants/document
Authorization: Bearer <token>
```

```json
{ "key": "briefs/approved", "value": { … }, "memory_type": "semantic",
  "updated_at": "2026-10-13T09:00:00+00:00" }
```

The token goes in the `Authorization` header and nowhere else. A token in a
URL is recorded by proxies, tunnels and access logs; this endpoint does not
read one from the path or the query.

Every request that reads nothing gets the same `404` with the same body: an
unknown, malformed, expired, revoked or used-up token, and a key with nothing
stored under it. A holder learns nothing about what else exists.

## What a grant is, exactly

* **One actor, one exact key.** Not a prefix. Two documents are two grants.
* **Read-only.** There is no write through a grant.
* **Short-lived.** 24 hours unless you ask for more, seven days at most.
* **Checked on every read**, in one statement: not revoked, not expired,
  reads left, and the actor still yours. The read is counted by that same
  statement, so a read limit holds when the last read is raced for.
* **Recorded.** Making and revoking a grant are written to the admin event
  log with the key. Each read is counted on the grant.
* **Not redacted.** The document is returned as `actor_recall` returns it.
  Making a grant is your decision that this document may leave, including
  for an actor whose model tier otherwise keeps its data on the host.
* **Bounded in number.** 50 live grants per user.

## Making it the session's ONLY access

A grant limits what its token can do. It does not take away what the session
can already reach. On the controller's own machine the tokenless
`/mcp/local` route answers, with everything.

So run the session where it cannot reach the controller's port: another
machine, a container without the port, a cloud session. From there the
public address serves `/memory-grants/document` to the token, asks `/mcp`
for an agent token, and answers `/mcp/local` with `404`.
