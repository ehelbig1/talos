# Recorded run

The run of this template's test `the_projects_facts_are_collected_with_gets_only_in_the_shape_the_check_reads`: one project's workload identity pools and providers, IAM policies, alert policies and log-based metrics, in 6 requests.
Made-up data, the test's own; no real project, account or address is in it.

`http.json` and `config.json` are kept by `talos_module_testkit::recorded_run::keep`
at the end of that test. A normal `cargo test` fails when they no longer match
what the test serves; `make record-template TEMPLATE=gcp-wif-evidence` rewrites them.

`make check-catalog-fuel TEMPLATE=gcp-wif-evidence` builds the template the way the
platform does, runs it against this recording (nothing is sent), and fails if
the fuel used is above 80% of the limit `talos.json` declares.
