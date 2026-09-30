# 2026-09-30 — a refused LLM call names its real cause

**Defect.** The worker answers a refused LLM call with `NotConfigured` for three
different reasons, and two layers each rendered it as "set the API key":

1. **Worker, all five external-provider call sites** (`complete*`,
   `complete-with-tools`, `start-stream`, `start-tool-stream`, `embedding`):
   `get_llm_api_key*` returns `None` both when the key is missing AND when the
   actor's `max_llm_tier = tier1` refuses the external provider, and each site
   rendered "LLM API key not configured. Set vault path `anthropic/api_key` …"
   for both. A tier-1 actor calling Anthropic was told to add a key — the one
   remedy that must not be taken, because the ceiling exists to keep the data
   on the host. The code recorded the ambiguity in a comment rather than
   resolving it.
2. **The LLM Inference catalog template** wrapped every `NotConfigured` detail
   in "Operator must set the provider's vault key (e.g. anthropic/api_key for
   anthropic). Verify with `list_secrets`" — wrong for the ceiling refusal and
   for #999's "model not proven local" refusal. Seen live 2026-09-30.

**Fix.**
* `LlmKeyUnavailable::{CeilingRefused, Missing}` — `classify(provider,
  ceiling)` recovers the reason EXACTLY from the same pure
  `decide_llm_tier_access` the key lookup used, so no second lookup and no
  guess. `message()` names the remedy for each: raise the ceiling or use a
  local model, vs. the vault path and env var.
  `TalosContext::llm_key_unavailable_message` is the one home; all five sites
  call it, replacing four hand-copied `format!` blocks and a fifth literal.
  It logs the missing-key WARN only for a missing key: the ceiling refusal is
  already recorded (capability denial + WARN) inside the lookup that refused.
* The template passes the host's detail through verbatim:
  `LLM provider '<p>' refused the call: <detail>`.

**Decisions.**
* **The metric label is NOT split.** `wasm_llm_failures_total{outcome=
  "not_configured"}` still covers all three; a new label would split a closed,
  pre-seeded set for a distinction the ceiling refusals already carry as
  capability-denied events. `LlmFailure::NotConfigured`'s doc now says so.
* **The key lookup's signature is NOT changed** (`Option<String>`): the reason
  is a pure function of `(provider, ceiling)`, so it is recovered at the call
  site instead of threading a new type through five callers and tests.

**Guards.**
* `a_tier1_refusal_names_the_ceiling_not_a_missing_key_on_every_path` drives
  `complete`, `complete-with-tools`, `start-stream` and `start-tool-stream`
  for a tier-1 actor calling Anthropic and asserts each message names
  `max_llm_tier is tier1` and `set_actor_llm_tier_ceiling` and does NOT say
  `Set vault path`. Deterministic: a ceiling refusal resolves no key, so an
  exported `ANTHROPIC_API_KEY` cannot change the answer. On `main` every path
  returned the "Set vault path" sentence (the removed blocks).
* `a_missing_key_and_a_ceiling_refusal_are_told_apart` — the classifier and
  the missing-key sentence (pure; the tier-2 path is env-dependent end to end).
* `make check-catalog`: all 75 templates compile, `llm-inference` included.

**Stated limits.**
* The embedding site is covered by the shared helper, not by its own driven
  test.
* The template's unit tests are not run by CI (it is a `cdylib` outside the
  workspace; `check-catalog` compiles it) — the wording lives in the worker,
  where it is tested.
* **An installed copy does not refresh** (`installed_catalog_copies_never_refresh`):
  the operator's installed `llm-inference` (14 live nodes) keeps the old
  wording until it is reinstalled with `install_module_from_catalog`
  (`name: "llm-inference"`), which preserves its grants and fuel. The worker
  half takes effect on deploy regardless.
