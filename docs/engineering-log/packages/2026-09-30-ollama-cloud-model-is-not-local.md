# 2026-09-30 — an Ollama cloud model is not local

**Defect.** Talos treats every Ollama call as local inference. The worker's
tier-1 gate (`decide_llm_tier_access`) answers `NoKeyNeeded` for provider
`ollama` and nothing further is checked; the controller's
`talos_llm::OllamaClient` is the path every "local" controller job takes. Neither
held for an Ollama CLOUD model: Ollama serves `glm-5.3-flash:cloud` (and any
`-cloud` tag) by forwarding the prompt to `https://ollama.com`. A
`max_llm_tier = tier1` actor pointed at one would have sent its data off the
host through the one provider the tier-1 gate trusted, with no refusal and no
denial record.

**Measured.** Reference host 2026-09-30: Ollama 0.35.0, one cloud model pulled
(`glm-5.3-flash:cloud`, listed with `remote_host: "https://ollama.com"`, 317
bytes on disk), and **zero** workflow nodes naming it — the 16 LLM nodes use
`qwen3.6:latest` (13) and `qwen2.5-coder:14b` (3), and the controller's
configured models are `qwen3.6` and `qwen2.5-coder:7b`. **Latent**: nothing was
sent. `/api/show` on this version does NOT expose `remote_host`; `/api/tags`
does.

**Fix.** ONE home `talos_local_inference::locality::model_locality` (the crate
both processes already share for the local gate and deadlines):
* **Remote** when the tag is `cloud` or ends in `-cloud` (decided without a
  request), or when `/api/tags` lists the model with a non-empty
  `remote_host` — which also covers an `ollama cp` alias whose name no longer
  says "cloud".
* **Unlisted** when the listing does not contain the name: the check can vouch
  only for what it can see, and Ollama answers an unknown name with 404 anyway.
* **Err** when the listing cannot be read (never cached).
* Names compare trimmed, lower-cased, with `:latest` appended when untagged.
* The listing is cached per base URL for 30 s (`TAGS_CACHE_TTL`), with one
  extra read when a name misses a cached listing (a model pulled since);
  5 s fetch deadline; the lock is held across the fetch so callers share it.

Worker: `TalosContext::admit_local_model`, called from all four local paths
(`complete*` via `complete_inner`, `complete-with-tools`, `start-stream`,
`start-tool-stream`) BEFORE the local-inference gate, only when
`ceiling_requires_local_model` — i.e. whenever `decide_llm_tier_access` would
refuse an external provider named `ollama-cloud` (tier-1, and any future
unclassified tier). Refusal: capability denial with policy `tier1-llm-egress`
(remote) or `tier1-llm-locality-unverified` (unlisted / unreadable), target =
model name bounded to 128 chars, WARN, and `NotConfigured` to the guest — the
same shape as the existing tier-1 external-provider refusal.

Controller: `OllamaClient::chat` refuses any such model for EVERY caller, before
the gate, with `talos_audit` event `local_llm_model_refused`. Its callers
(consolidation and reflection over actor memory, graph-RAG extraction — the
path `TALOS_GRAPH_RAG_TIER1_LOCAL_OK` admits for tier-1 — evaluation, the
teacher audit, `local_llm_complete`) all treat the answer as local inference.

**Decisions.**
* **Refuse, not reroute or warn.** A cloud model a tier-1 actor names is a
  configuration the ceiling forbids; there is no local model to substitute.
* **Tier-2 is not checked in the worker**: a cloud model there is an external
  provider, which that ceiling already allows. The controller client checks
  every call because it has no tier and is local by contract.
* **Unlisted is refused**, and the cost was argued: Ollama returns 404 for such
  a name, so a legitimate call loses nothing; what it closes is a name form the
  listing lookup does not recognise.
* **Unreadable is refused** — the house rule that a gate which cannot read its
  rule refuses. If `/api/tags` fails, the chat on the same backend would too.
* **The error never says `HTTP 400`**: two `OllamaClient` callers retry on that
  string; the listing failure reads `status N`.
* **Not changed**: `warm_model` (boot warm-up sends a fixed one-token prompt
  carrying no data), `list_models` / `pull_model` / `delete_model`, the
  worker's local-inference gate (a cloud model still takes a local slot on
  tier-2 — harmless, stated).

**Cost.** At most one local `GET /api/tags` per process per 30 s, plus one per
first sight of a newly pulled model; only tier-1 worker calls and controller
calls pay it. The existing fleet's models are all listed, so no call on this
fleet changes outcome.

**Guards.**
* `talos-local-inference`: unit tests of the name and listing decision, and
  `tests/locality_fetch.rs` against a loopback `/api/tags` (one read per TTL,
  re-read on a cached miss, an unreadable read is an error and is not cached,
  a 200 without `models` is unreadable).
* `talos-llm`: `a_model_not_proven_local_is_never_sent` (cloud tag, `-cloud`
  tag, alias, unlisted — each asserting ZERO chat requests reached the mock)
  and `an_unreadable_model_list_refuses`; the file's existing tests on model
  `m` are the control.
* worker: `a_tier1_call_to_a_model_not_proven_local_is_refused_on_every_path`
  drives all four WIT entry points and asserts nothing reached the backend;
  `a_local_model_under_tier1_and_a_cloud_model_under_tier2_are_admitted` is
  the control; `the_local_model_decision_admits_only_proven_local` covers the
  unreadable arm and the policy vocabulary. The worker mock Ollama now answers
  `/api/tags` as Ollama does, listing its mock models as local.

**Mutations (a tier-1 privacy gate, so each guard is proven): 12 applied, 12
caught.** Removing the controller check; reading Unlisted as Local; ignoring
the cloud tag; ignoring `remote_host`; admitting an unreadable listing in the
worker and in the controller; removing the check from each of the four worker
paths separately; not checking tier-1 at all; reading a 200 without `models`
as an empty listing. **M11 first read as a SURVIVOR and was not one**: the
nextest filter `-p talos-local-inference locality` matches TEST names, and the
fetch tests in `tests/locality_fetch.rs` do not contain "locality", so they
never ran; re-run against the whole crate it is caught by
`a_body_without_a_models_list_is_unreadable`. A name filter can silently
exclude the test a mutation is aimed at.

**Stated limits.**
* The check trusts the LOCAL Ollama's own listing. An operator who can edit the
  host Ollama can also point `OLLAMA_URL` anywhere; that is outside this gate.
* An Ollama that forwards models without `remote_host` in `/api/tags` and
  without a cloud tag would not be detected — no such form exists on 0.35.0.
* The per-process cache means a model re-pointed to a cloud source by
  `ollama cp` within 30 s of a cached read is judged by the old answer for at
  most that window.
* No metric; the denial ledger row and the `talos_audit` line are the record.
* Live proof is by the tests; nothing was sent to a cloud model to show it.
