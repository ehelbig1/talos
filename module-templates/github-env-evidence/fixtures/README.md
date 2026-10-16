# Recorded run

The run of this template's test `it_reads_the_installations_repositories_and_what_protects_each_environment`: an installation's repositories, their deployment environments and each one's protection rules, in 4 requests.
Made-up data, the test's own; no real project, account or address is in it.

`http.json` and `config.json` are kept by `talos_module_testkit::recorded_run::keep`
at the end of that test. A normal `cargo test` fails when they no longer match
what the test serves; `make record-template TEMPLATE=github-env-evidence` rewrites them.

`make check-catalog-fuel TEMPLATE=github-env-evidence` builds the template the way the
platform does, runs it against this recording (nothing is sent), and fails if
the fuel used is above 80% of the limit `talos.json` declares.
