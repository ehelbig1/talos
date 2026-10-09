# `query_paginated` on a database login of its own

`query_paginated` is the platform-admin MCP tool that runs SQL its caller
writes. Before it runs, the SQL passes a parsed gate (one read, allow-listed
functions, public tables not withheld). It then runs in a read-only transaction
as the role `talos_admin_read`, which is granted SELECT on the tables the tool
may read and nothing else.

Out of the box the session behind that role is the controller's own database
connection (`DATABASE_URL`). On a deployment where that is a superuser, a
statement that set the role back would be a superuser. The gate refuses every
way of doing that the project knows of; this setting removes what is behind it.

## Setting it up

1. As a superuser, make a login for the tool alone:

   ```sql
   CREATE ROLE talos_admin_query LOGIN PASSWORD '<a long random password>'
       NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
   GRANT talos_admin_read TO talos_admin_query;
   ```

   Do not grant it anything else, make it own anything, or add it to another
   role. Every call checks this and is refused otherwise.

2. Give the controller its URL. It has the same form as `DATABASE_URL`, with
   this login's user and password. In production it must pin
   `sslmode=require`, `verify-ca` or `verify-full`, as `DATABASE_URL` must.

   * docker compose: `TALOS_ADMIN_QUERY_DATABASE_URL=postgres://talos_admin_query:<password>@postgres:5432/talos`
     in `.env`.
   * k3s install: `TALOS_ADMIN_QUERY_DATABASE_URL=…` in `/etc/talos/install.env`,
     then re-run `install.sh`.
   * Helm: `bootstrapSecret.data.TALOS_ADMIN_QUERY_DATABASE_URL`.
   * A secrets mount: `TALOS_ADMIN_QUERY_DATABASE_URL_FILE=/path/to/file`.

3. Restart the controller. Its log says `query_paginated connects as its own
   login` (never the URL). On a misconfigured value it logs an error instead,
   and every call is refused until the value is fixed or removed.

## What changes

* Each call opens a connection as the login and closes it afterwards, under the
  same `statement_timeout` as the controller's pool (`DB_STATEMENT_TIMEOUT_SECS`)
  and with `application_name = talos_admin_query`. Measured: about 4 ms more
  per call than the pool (the connection and its password exchange).
* A login that cannot be used is never replaced by the pool. The call is
  refused with what is wrong:
  * the login is unreachable or the password is wrong;
  * it is the pool's own user;
  * it is a superuser;
  * it has CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS;
  * it belongs to another role;
  * it owns an object or holds a grant of its own.
* Removing the setting returns the tool to the controller's connection.

The design, the measurements and what is deliberately not done are in
`docs/engineering-log/packages/2026-10-09-query-paginated-own-login.md`.
