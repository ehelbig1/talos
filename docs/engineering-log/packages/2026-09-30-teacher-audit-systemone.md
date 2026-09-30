# 2026-09-30 — the teacher audit can score a local System One model

**Why.** Ollama 0.35.0 added System One (`POST /v1/systemone`, docs
"Decision"): a local model scores a fixed set of options and returns the
choice, a probability per option and a confidence, generating one token.
That is exactly what the classifier nodes do by prompting a chat model for
JSON. Whether it is BETTER here is a measurement, and the teacher audit is
where that measurement belongs: it already runs server-side, local-only,
over the human-corrected ("gold") slice, logs no example text, and stores
aggregate results. Baselines already stored (chat teacher `qwen3.6:latest`):
`inbox-classifier-personal` **22 / 95 = 23.2 %**, `ops-severity`
**20 / 26 = 76.9 %** — the gold slice is corrections, i.e. the rows the LLM
got wrong, so it is a hard set by construction.

**Why not evaluate it any other way.** The examples are encrypted at rest
(`ml_examples.features_enc`, org DEK), so a host script cannot read them, and
`ml_sample_examples` would decrypt them into an agent's context — off the
host, which the tier-1 posture of the inbox actor forbids. The audit reads
them inside the controller and returns only counts and example keys.

**Change.**
* `talos_llm::OllamaClient::system_one_choice(model, state, instructions,
  options)` — the #999 local-only check (a cloud model is refused before
  anything is sent), the process's local-inference gate, a 120 s deadline, a
  capped body read; 2–26 non-blank options and a non-empty input are required
  (the API's bounds); options are sent with null descriptions (System One then
  uses the name); a returned choice outside the options is an error.
* `talos_ml::TeacherBackend::{Chat, SystemOne { model }}` passed to
  `start_teacher_audit`; `TeacherRequest.labels` carries the label set to the
  transport. The System One transport sends the teacher prompt as
  `instructions` (labels + few-shot anchors) and the spotlit example as
  `state`, and returns `{"label": choice}` — so parsing, scoring, aggregation
  and the ≤100-row / 3-error / progress contract are the chat teacher's,
  unchanged.
* Storage: a System One report lives at `teacher_audit.systemone`; the chat
  teacher's stays the top level, and a chat (re-)audit CARRIES a stored
  `systemone` across rather than erasing it. The report's `teacher` block
  gains `backend`.
* MCP `ml_teacher_audit` gains `backend` (`chat` default | `systemone`) and
  `systemone_model` (REQUIRED for `systemone` — no default: the docs' `nimble`
  and the pulled `nimble:9b` differ, and a guessed name would fail late).

**Decisions.**
* **A comparison, never a replacement.** The scheduled auto-audit and every
  reader of `teacher_audit` see the chat teacher exactly as before; the one
  per-model in-flight slot still serialises audits.
* **No classifier node uses System One yet.** Wiring it into a node is a new
  worker host capability (a WIT change) and is decided on the audit's result,
  not before.
* **Probabilities and confidence are not stored in the audit** — the audit's
  question is agreement with the human label; they are returned by the client
  for the node work that may follow.

**Guards.** `talos-llm`: the request is a `choice` question over exactly the
options with null descriptions and the answer is the choice plus the asked
options' probabilities; a choice not offered is an error; a cloud model and
malformed options/input are refused with zero requests sent.
`controller/tests/teacher_audit_backend_tests.rs` (CTRL_TESTS harness): a chat
audit stores the top level; a System One audit stores `systemone`, receives
the label set, and leaves the chat report intact; a chat re-audit keeps
`systemone`; a blank System One model is refused with nothing stamped.
**Stated: the controller DB test was not run locally** — the local migrated
templates are 14 migrations behind (incl. the `encryption_keys` wrap-format
pair `SecretsManager` needs) and bringing one up to date means DDL on the
operator's server; CI's integration shards run it on a fresh template.

**Measured before building.** `POST /v1/systemone` with `nimble:9b` on this
host (synthetic ticket, no user data): `choice: archive`, p = 0.95, confidence
0.79, 1 output token, 6 s including the model's cold load.
