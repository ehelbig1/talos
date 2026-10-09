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

## Setting it up: one command

From the repository checkout on the host that runs the stack:

```bash
scripts/setup-admin-query-login.sh --compose          # docker compose (.env in the current directory)
scripts/setup-admin-query-login.sh --compose --env-file /path/to/.env
sudo scripts/setup-admin-query-login.sh --k3s         # the k3s install
```

It does the steps below for you:

* Inside the running controller container,
  `controller admin-query-login provision` makes `talos_admin_query`, or
  gives it a new password if it exists.
  * The password is 24 random bytes, generated there.
  * Postgres receives only its SCRAM verifier, so the password is in no
    statement, server log or `pg_stat_statements` row.
  * The login is put back to LOGIN only, and is checked the way every call
    checks it.
* The URL comes back on a pipe and goes straight into `.env` (mode 600), or
  into the k3s bootstrap Secret and `/etc/talos/install.env`. It is never
  printed.
* The controller is restarted, and its log is checked for `query_paginated
  connects as its own login`.

**If provisioning fails**, nothing else is changed, and the message says why.
The usual reason on a managed Postgres is that the controller's database user
may not create roles; a superuser then runs step 1 below by hand.

**Running it again rotates the password.** Until the restart finishes, the
running controller refuses `query_paginated` calls; nothing else is affected.

**`--remove`** takes the setting out, restarts, and runs
`controller admin-query-login disable`, so a copy of the old URL no longer
logs in.

The controller needs CREATEROLE (or superuser) on its database user for
this, and the role `talos_admin_read` must exist (migration
`20261008200000`).

## Setting it up by hand

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

   Use a hex password (`openssl rand -hex 24`) so it needs no URL escaping.

   * docker compose: `TALOS_ADMIN_QUERY_DATABASE_URL=postgres://talos_admin_query:<password>@postgres:5432/talos`
     in `.env`, then `docker compose up -d controller`. A plain `restart`
     does not re-read `.env`.
   * An existing k3s install: re-running `install.sh` does NOT update the
     bootstrap Secret (it is create-once). Patch it instead; the helper also
     restarts the controller:
     `echo -n "$URL" | sudo scripts/patch-bootstrap-secret.sh TALOS_ADMIN_QUERY_DATABASE_URL=-`.
     Add the same line to `/etc/talos/install.env` too, so a fresh install
     carries it.
   * Helm: `bootstrapSecret.data.TALOS_ADMIN_QUERY_DATABASE_URL`.
   * A secrets mount: `TALOS_ADMIN_QUERY_DATABASE_URL_FILE=/path/to/file`.

3. The controller's start-up log says `query_paginated connects as its own
   login` (never the URL). On a misconfigured value it logs an error instead,
   and every call is refused until the value is fixed or removed.

4. Check the tool is really using the login. The query gate refuses
   `current_user` and `session_user`, so ask the database instead. Run any
   read through `query_paginated` (`SELECT count(*) AS n FROM workflows`).
   Then, as a superuser, run `ALTER ROLE talos_admin_query NOLOGIN;` and run
   the read again: it must be refused with "no connection could be made as
   it". Finally run `ALTER ROLE talos_admin_query LOGIN;` and the read works
   again.

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
