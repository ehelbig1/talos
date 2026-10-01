# 2026-10-01 — `install_module_from_catalog` accepts the display name it shows

**Defect.** Every report names an installed copy by its display name
(`get_catalog_status`, `session_start.catalog_drift`, the drift tip:
`Gmail: List Messages`). `install_module_from_catalog` refused that name —
"Invalid module name: only alphanumeric characters and hyphens are allowed" —
and gave no hint that the slug (`gmail-list-messages`) was wanted. The
resolver behind the check (`resolve_catalog_template_dir`) has matched display
names since 2026-09-30; the check in front of it refused them first.

**Fix.** The pre-check is `catalog_template_key`: trimmed, non-empty, at most
128 bytes, no control characters (the shared `talos_validation` rule), and not
shaped like a path. Either form then goes to the one resolver. The tool's
schema and its not-found error name both forms.

**Decisions.**
* Path safety stays where it was: the resolver never joins a key onto the
  catalog path unless it is one safe component (`no_key_escapes_the_catalog`,
  unchanged). The pre-check is a bound, not that control.
* A path-shaped key (`..`, a leading `/`, `\` or `.`) is still refused. The
  resolver would not leave the catalog for one, but it matches by slug, so
  `./llm-inference/..` would otherwise install LLM Inference (found by the
  first draft of the test).
* The key is echoed in error text and log fields, hence the length bound and
  the control-character rule.

**Measured.** 75 templates; the longest display name is 32 bytes. One contains
`/` (`Echo/Debug`), several a colon or parentheses.

**Guards.** `catalog_template_resolver_tests`: three punctuated display names
accepted and resolved (also padded, also by slug); empty / oversized /
control-character keys refused; path-shaped keys refused; the resolver's
existing escape test.

**Stated limit.** The handler body after the resolver is not driven by a test
(it compiles and writes); the supplied key is used there only in messages and
as a fallback the resolved directory name always pre-empts.
