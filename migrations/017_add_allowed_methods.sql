-- Add per-module HTTP method allowlist.
--
-- `allowed_methods` is an optional restriction layered on top of `allowed_hosts`.
-- Empty array = allow all methods (default, preserves existing behaviour).
-- Non-empty = only the listed methods (e.g. '{"GET"}') are permitted.
--
-- This is enforced at runtime in the worker's `http::fetch` and `graphql::execute`
-- host functions after the host allowlist check passes.

ALTER TABLE wasm_modules ADD COLUMN IF NOT EXISTS allowed_methods TEXT[] NOT NULL DEFAULT '{}';
