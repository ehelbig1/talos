# `test_secret_access` says "stored" when a dispatch would read one (2026-10-13)

Left open by `2026-10-13-quickstart-grant-check.md`: the presence gate of
`test_secret_access` checked one exact path with `created_by = caller`,
while a dispatch reads with `owner_user_id IS NULL OR owner_user_id = caller
OR created_by = caller`.

## What was wrong

For an ownerless secret (`owner_user_id IS NULL`), which a dispatch delivers
to every user, the tool answered `vault_presence: false`, "No secret stored
at path … Add it in the dashboard", and `would_succeed: false`. It told the
operator to add a secret that was there, about a read that succeeds.

## Decided

* `SecretsManager::secret_exists_by_path` is replaced by
  `dispatch_readable_secret_exists`, under the dispatch's ownership rule. It
  is the exact-path twin of `list_dispatch_readable_key_paths`. The old
  function had one caller, this gate.
* The gate's two sentences say what was asked: whether a secret "this user's
  dispatch can read" is stored at the path.
* `existing_secret_key_paths` (the batch read used by the manifest import,
  the connections listing and a GraphQL mutation) is NOT changed: it answers
  "which of these did this user create", and its callers act on the user's
  own secrets.

## Tenancy

Widening an ownership rule is the kind of change that can start answering
for someone else's rows. Pinned against real rows: another user's secret at
the path reads `false`, and the tool's whole reply for it is identical,
with the two path names masked, to its reply for a path nobody holds.

An ownerless secret now reads as stored, for every user. That discloses
nothing a dispatch does not: a module granted the path is handed the value.

## Mutations (whose secrets count)

| Mutation | Caught by |
|---|---|
| no ownership rule | the database test (another user's path reads stored) |
| the creator only (the behaviour before) | the database test (the ownerless path reads missing) |
| owner or creator, without the ownerless secrets | the database test (same) |

## Not measured

How many ownerless secrets the live stack holds: the platform-admin query
tool refuses the `secrets` table by design. Both writers of `secrets` rows
bind the creating user to both ownership columns, so through the platform
the old and new rules differ only for an ownerless row.
