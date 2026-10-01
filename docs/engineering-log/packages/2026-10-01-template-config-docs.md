# 2026-10-01 — template config keys the schema did not show; `Gmail: List Messages` can return `To`

**Defect 1.** A template's `config_schema` is what `get_module_info` and the
node editor show. Three keys read by shipped templates were not in it:
* LLM Inference `USER_PROMPT` — without it the node sends its WHOLE input to
  the model as the user message, every earlier node's output included. It is
  the only way to send specific fields, and could be found only by reading the
  template source.
* LLM Inference `ALLOW_EMPTY_TEMPLATE_VARS` — named in the node's own error
  message, absent from the schema.
* HTTP Request `MAX_RESPONSE_BYTES`.
Echo/Debug documented none of its three keys.

**Defect 2.** `Gmail: List Messages` returned From / Subject / Date / snippet
only, so anything about SENT mail (where From is always the owner) needed a
custom module.

**Fix.**
* The four schemas document the keys, from the code that reads them.
* `Gmail: List Messages` takes `EXTRA_HEADERS` (array or comma-separated
  string, at most 6, letters/digits/`-` only since a name goes into the request
  URL). Each is returned under its lower-case name (`Reply-To` → `reply_to`),
  empty when absent. A malformed name, a name that would overwrite a fixed
  field, or too many names is an ERROR, not an ignored setting. Unset: the
  request URL and each entry are unchanged.
* Same template: header names are matched without regard to case, and the
  error-body preview is cut on a character boundary (it sliced bytes).

**Measured.** 75 templates. Keys read through `#[serde(rename = "KEY")]`: 52
in 6 templates, 3 undocumented (above), 0 after.

**Guard.** `talos_compilation::catalog` test
`a_config_key_a_template_deserializes_by_name_is_in_its_config_schema` — fails
on the pre-fix schema, with a floor so a scan that stops matching fails. The
Gmail helpers have 5 unit tests in the template (run natively with the host
bindings stubbed; CI compiles templates but does not run their tests — stated
limit). `make check-catalog`: 75 of 75 compile.

**Recorded, NOT fixed — seven older templates whose schema and code disagree.**
They read `config.get("KEY")`, which the guard does not cover, and none is used
by a live workflow here (0 references each). Making schema and code agree means
choosing which is right per template and cannot be checked against the real
service without side effects, so it is left for a decision:
* `create-calendar-event` — schema requires `OAUTH_TOKEN_SECRET`, `TITLE`;
  code requires `ACCESS_TOKEN`, `SUMMARY` and reads `DESCRIPTION`.
* `send-gmail` — schema requires `OAUTH_TOKEN`; code reads `ACCESS_TOKEN`.
* `google-mail-webhook` — schema requires `OAUTH_TOKEN_SECRET`; code reads
  `ACCESS_TOKEN`.
* `google-calendar-webhook` — schema `CALENDAR_ID`, `OAUTH_TOKEN`; code reads
  `CALENDAR_IDS`.
* `slack-webhook-listener` — schema requires `SIGNING_SECRET_PATH` (unread);
  code reads `VERIFICATION_TOKEN`, `USER_FILTER`, `BOT_TOKEN`, `ENRICH_EVENTS`.
* `network-scanner` — schema requires `PORTS` and documents `BANNER_GRAB`
  (both unread); code reads `INCLUDE_BANNER`.
* `jwt-validator` — `ALGORITHM` documented, unread (the signature is always
  checked as HMAC-SHA256). Its `exp` handling is a separate, more serious
  finding with its own record.

`gcp-run-job-execute` reads `COMMAND` only to refuse it; correct as written.

**After deploy.** Installed copies of the four templates do not change until
reinstalled (`install_module_from_catalog`, `dry_run` first).
