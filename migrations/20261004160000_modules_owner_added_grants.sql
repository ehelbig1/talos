-- Which entries of a module's three grant lists its OWNER added.
--
-- A catalog reinstall keeps an installed copy's grants only within the new
-- template's own grant, so a template that removes a host or a secret path
-- narrows every copy (2026-09-29). That rule also dropped every grant the
-- owner had added on purpose with update_module_hosts / _methods / _secrets,
-- and for a template that installs with NO host and NO secret — the owner is
-- meant to add them — a reinstall wiped the copy back to reaching nothing.
--
-- These columns record the entries the owner added, so a reinstall can keep
-- exactly those while template-inherited entries still narrow with the
-- template. Written only by the one permission writer and by the install
-- writer; an entry is here only while it is also in its grant column.
--
-- No backfill: which of an existing copy's entries the owner added is not
-- recorded anywhere, and guessing it would mark a template-inherited entry
-- as the owner's. An existing widening is recorded the next time the owner
-- sets it.
ALTER TABLE modules
    ADD COLUMN IF NOT EXISTS owner_added_hosts   TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS owner_added_methods TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS owner_added_secrets TEXT[] NOT NULL DEFAULT '{}';
