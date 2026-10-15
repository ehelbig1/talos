-- `actors.secret_grants` is dropped (security review 2026-10-14, C-3).
--
-- The column was written by the MCP tool `grant_secret_access` and read by
-- nothing that decides access: no engine, worker or resolver consulted it.
-- An operator who granted an actor `foo/bar` was told "granted" and nothing
-- changed — configured authorization that does nothing — and any future
-- reader would have turned the stored strings (never checked against what the
-- granting user could read) into real grants. The tool, its repository write,
-- the summary field and the clone copy are removed with it.
--
-- Measured on the reference deployment: 0 of 13 actors held an entry.

ALTER TABLE actors DROP COLUMN IF EXISTS secret_grants;
