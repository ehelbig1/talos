# `Send HTML Email (Gmail)` does not send a blank email, and honours `skip` (2026-10-12)

With neither `subject` nor `html` in its input the catalog template
`send-html-email` sent a "(no subject)" email with an empty body. It also
ignored `skip: true` from the composing node. One blank email reached the
owner.

## Decided

* **`skip: true` sends nothing.** The output is
  `{sent: false, skipped: true, dry_run, to}`. Read from the upstream node's
  output (`input.skip`) and, for a stand-alone run, from the root. Only the
  boolean `true` skips, as in the `notify-*` adapters.
* **An input with no `html` is an error**, never a blank email: missing,
  empty, whitespace only, or not a string. The message names what the
  upstream node must return. Checked ahead of `DRY_RUN`, so a rehearsal fails
  the same way the send would.
* **`skip` is checked first.** A composer that skips usually returns no
  content, and that must not be the error.
* **A missing `subject` still defaults to "(no subject)".** A message with a
  body and no subject is a message; the observed defect was the empty body.

## Behaviour that changed for a workflow

A send node whose upstream returns no `html` now FAILS where it used to send
a blank email. A workflow that relied on the blank send has to return
`skip: true` instead.

## Tests

The template's own (`talos-catalog-tests`, `make test-templates`), through
`run` against the test kit's host: a composed message is sent once with its
subject and body; five blank inputs are refused and nothing reaches Gmail,
including under `DRY_RUN`; `skip` sends nothing with or without content, and
`false`, `"true"`, `1` and `null` do not skip; a dry run sends nothing; CRLF
in the subject is refused and a non-ASCII subject is encoded; a failed send
names how it failed and never echoes the reply. With the two guards removed,
the blank and skip tests fail.

The template had no tests before this.

## Measured, and left for its own change

Building the template through the production compile path and running it in
the worker runtime against a made-up recording (`make check-catalog-fuel`):

| `html` bytes | fuel used |
|---:|---:|
| 300 | 182,924 |
| 29,606 | 6,223,725 |
| 59,186 | 12,311,204 |

About 206 fuel per byte of body. At the default 1,000,000 limit the template
cannot send a message much over 4 KB; a 30 KB newsletter exhausts it. The
cost is the `serde_json::Value` parse of the whole input, three copies of
the body and a per-character base64 encoder under `opt-level = "z"`.

No `recommended_fuel` and no `fixtures/` are added here: a declared limit
sized for the 300-byte recording would say nothing true about a real
message. Making the template cheaper and then declaring a measured limit is
a separate change.

## Deliberately NOT done

* **A `validate_workflow` warning for a send node whose upstream can return
  `skip`.** Which modules can return `skip` is not declared anywhere a
  validator can read. The sender now honours it itself.
* **A template version bump.** An installed copy does not refresh from the
  catalog; an owner reinstalls to get this.

## Stated limits

The older `send-gmail` template (config-driven subject and body) is
unchanged and has no tests.
