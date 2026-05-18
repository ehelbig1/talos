-- Ensure node_templates.name is unique so startup can use upsert to keep
-- template code in sync with the binary (built with include_str!).
-- Remove any accidental duplicates first (keep the physically-latest row per name).
-- In practice duplicates cannot exist (old seed used IF NOT EXISTS), but this
-- is defensive in case of a partial migration or manual data entry.
DELETE FROM node_templates a
    USING node_templates b
WHERE a.ctid < b.ctid
    AND a.name = b.name;

ALTER TABLE node_templates
    ADD CONSTRAINT node_templates_name_key UNIQUE (name);
