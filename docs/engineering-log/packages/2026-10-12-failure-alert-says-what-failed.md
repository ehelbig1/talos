# The alert for a failed workflow says the workflow could not run, and why (2026-10-12)

The phone alert read `workflow 'talos-ci-watch' failed: unclassified failure
(node 'read')`. The owner read it as "a pull request failed and Talos could
not classify why". It was the watcher itself failing to reach its source.

## Decided

* **The title leads with what the workflow is for, and says "could not
  run".** With a description:
  `<first sentence of the description> — could not run: <cause> (workflow
  '<name>', node '<node>')`. Without:
  `Workflow '<name>' could not run: <cause> (node '<node>')`.
  "Failed" beside a workflow's name was the ambiguity: a watcher's name is
  the name of the thing it watches.
* **`plain_cause(class)`: one sentence per error class**, a clause that
  completes "could not run: ". 26 classes have one; `other`, and any class
  added later without one, get `UNRECOGNISED_CAUSE`: "the cause was not
  recognised (the error is in the alert's details)".
* **`ErrorClass::label` is unchanged** and no longer in the title. It is the
  operator vocabulary; `severity_raw` still carries the class and `raw`
  still carries the redacted excerpt.
* **No error text in the title.** Only the class, the redacted name, node and
  purpose, and a count.
* **"after N attempts"** is read from the dispatcher's own closing line
  (`Job failed after {n} attempts`), for 2 to 100. One attempt is not said.
* **The purpose** is the description's first sentence, at most 90
  characters, DLP-redacted like the name. `w.description` is added to the
  reconciler's read (the same `LEFT JOIN`).
* **The dedup key is unchanged**, so an open alert keeps its row and its
  occurrence count.

## Deliberately NOT done

* **Naming the service** ("GitHub was unreachable"). The host is only in the
  error text, and lifting a hostname out of free text into a title is the
  thing the "no raw error text" rule exists to prevent. When the worker
  attaches the failed host to a job's failure in a structured form, the
  title can carry it.
* **Changing the classifier.** A message that fell to `other` still does.

## A consumer to check

Anything that matched the old title text. Nothing in this repository does.
A workflow outside it that parses alert titles (the alert-triage workflow
reads alerts and composes the phone message) would see the new wording.

## Tests

`self_monitor` unit tests: the exact title for a network failure with and
without a description, node and attempt count; an unrecognised cause says so
in words and carries none of the error text; every class either classifier
can produce has its own sentence, and only `other` falls to the unrecognised
one; the purpose (first sentence, a version number is not a sentence end,
bounded); the attempt count.

The reconciler's query was prepared against the migrated schema by check
88's database leg.

## Stated limits

`reconcile_tick` has no database test, before or after this. What is tested
is every function the title is built from.
