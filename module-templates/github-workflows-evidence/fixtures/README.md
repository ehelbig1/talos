# Recorded run

The run of this template's test `it_reads_each_repositorys_active_workflow_files_and_hands_on_their_steps`: an installation's repositories, their Actions workflows, and each active workflow's file, in 5 requests.
Made-up data, the test's own; no real project, account or address is in it.

`http.json` and `config.json` are kept by `talos_module_testkit::recorded_run::keep`
at the end of that test. A normal `cargo test` fails when they no longer match
what the test serves; `make record-template TEMPLATE=github-workflows-evidence` rewrites them.

`make check-catalog-fuel TEMPLATE=github-workflows-evidence` builds the template the way the
platform does, runs it against this recording (nothing is sent), and fails if
the fuel used is above 80% of the limit `talos.json` declares.
