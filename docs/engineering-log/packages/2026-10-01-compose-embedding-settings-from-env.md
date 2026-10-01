# 2026-10-01 — the compose embedding settings can be set from `.env`

**Defect.** `docker-compose.yml` set the controller's `EMBEDDING_API_URL` to
the literal `"http://ollama:11434/v1/embeddings"` under a comment saying
"Override EMBEDDING_API_URL / EMBEDDING_API_KEY to switch providers".
A literal cannot be overridden from `.env`, and `EMBEDDING_API_KEY` was not
passed to the container at all — so the documented way to switch embedding
provider did nothing. `EMBEDDING_TIMEOUT_SECS` and
`TALOS_EMBEDDING_MAX_IN_FLIGHT` (documented knobs with defaults) were not
passed either. The only way to change any of them was a compose override
file.

**Why it came up.** Measured the same day: the host's own Ollama embeds a
1,500-character text in 0.03 s against the in-stack CPU embedder's 1.6 s, with
the same model digest and the same retrieval results. Using it needs
`EMBEDDING_API_URL` to be settable.

**Fix.** `EMBEDDING_API_URL: ${EMBEDDING_API_URL:-http://ollama:11434/v1/embeddings}`,
and `EMBEDDING_API_KEY`, `EMBEDDING_TIMEOUT_SECS`,
`TALOS_EMBEDDING_MAX_IN_FLIGHT` passed as `${VAR:-}`.

**Inert when unset.** Rendered with `docker compose config`: with nothing set
the URL is byte-identical to before and the other three are empty, which each
reader treats as unset (`env_nonempty` for the key; a failed parse falls back
to the default for the timeout; `parse_max_in_flight` maps empty to the
default, pinned by its unit test). With the variables set, the rendered values
are the ones given.

**Not changed.** The worker (it does not embed). `EMBEDDING_MODEL` /
`EMBEDDING_DIMENSIONS` (already overridable). The tier-1 rule: a tier-1
actor's text is embedded only by a host-local provider, whatever URL is set.

**Guard.** None beyond the render check above and lint check 97's transport
rule; compose is not exercised by a test.
