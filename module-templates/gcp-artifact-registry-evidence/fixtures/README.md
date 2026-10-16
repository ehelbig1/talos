# Recorded run

The run of this template's test `what_the_reader_hands_on_is_judged_when_every_row_says`: one project with the scanning API on, its repositories and their findings, in 5 requests.
Made-up data, the test's own; no real project, account or address is in it.

`http.json` and `config.json` are kept by `talos_module_testkit::recorded_run::keep`
at the end of that test. A normal `cargo test` fails when they no longer match
what the test serves; `make record-template TEMPLATE=gcp-artifact-registry-evidence` rewrites them.

`make check-catalog-fuel TEMPLATE=gcp-artifact-registry-evidence` builds the template the way the
platform does, runs it against this recording (nothing is sent), and fails if
the fuel used is above 80% of the limit `talos.json` declares.
