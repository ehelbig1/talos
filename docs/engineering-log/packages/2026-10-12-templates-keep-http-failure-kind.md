# 2026-10-12 — catalog templates keep the kind of a failed HTTP request

**What happened.** The owner was sent "workflow 'talos-ci-watch' failed:
unclassified failure (node 'read')". The CI watcher polls GitHub every ten
minutes; four of six polls between 12:10Z and 12:50Z failed with
`api.github.com could not be reached`, each failing the workflow and raising an
alert. The host was awake and under heavy local build load.

**Cause.** `github-workflow-run` reported a failed request as
`.map_err(|_| "api.github.com could not be reached")`. The host had told the
module WHICH way the request failed (`timeout`, `networkerror`,
`forbiddenhost`, `invalidurl`); the module threw the word away. The dispatcher
decides whether to try again from `talos_retry_intelligence::classify_error`
over the failure text, which matches those words. With none in the text the
class is `unknown`: not transient, not retried, and rendered to the operator as
"unclassified". The reader is GET-only, so the retries it was entitled to were
never used.

**Population.** `grep 'fetch(&…).map_err(|_|'` over `module-templates/`:
`github-workflow-run`, `notify-ntfy`, `notify-home-assistant`, `gmail-modify`.
A fifth, `control-home-assistant`, dropped the kind from a per-entity reason
(not an error). The two `capture-*` templates already kept it. So a phone
notification lost to one network blip was not retried either, whatever the
send node's `retry_count` said.

**Decided.**
- The five templates write the kind into the message (`({e:?})`).
- `talos-catalog-tests/tests/http_failure_kind.rs`: a source check over every
  template, because the property is about every call site, with a self-test
  that it sees the pattern across lines and ignores a kept kind.
- A rule in `CLAUDE.md` (WASM module rules).

**Deliberately NOT done.**
- **The classifier was not taught "could not be reached".** That phrase is
  module prose; a refused host says it too, and retrying a refusal is wrong.
  The kind is the fact, and the module has it.
- **The worker does not attach the last host-call failure to a job's error.**
  That would classify a module that says nothing at all, and is the more
  complete fix; it changes the signed result and is a package of its own.
- **Installed copies are not refreshed by this change.** A copy installed from
  the catalog keeps the source it was installed with until it is reinstalled.

**Tests.** The source check and its self-test; `github-workflow-run` and
`notify-ntfy` each assert the three kinds appear in their message;
`talos-retry-intelligence` asserts what those messages classify as
(`network_transient`, `timeout`, `capability_denied`) and that the old message
is `unknown`.

**Not verified.** No live network failure has been retried on this change.
Why `api.github.com` was unreachable from the worker during that hour was not
established; local build load on the same machine is the suspected cause, not
a measured one.
