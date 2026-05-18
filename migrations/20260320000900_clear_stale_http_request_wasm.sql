-- Clear stale precompiled_wasm for module templates whose code was updated
-- after the binary was last compiled.  Without this the runtime serves old
-- WASM that lacks Phase 3 safety enforcement (SANITIZE_FOR_LLM,
-- MAX_CONTENT_LENGTH for http-request; BLOCKED_PATTERNS, OUTPUT_SCHEMA,
-- MAX_OUTPUT_TOKENS_ENFORCED for llm-inference).
--
-- The seeder now NULLs precompiled_wasm automatically when code_template
-- changes (matching on IS DISTINCT FROM), so this migration only needs to
-- repair the binaries that were already cached before that seeder fix landed.

UPDATE node_templates
SET    precompiled_wasm = NULL
WHERE  name IN ('http-request', 'llm-inference')
  AND  precompiled_wasm IS NOT NULL;
