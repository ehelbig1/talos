# Recorded run

The run of this template's test `the_policies_are_read_with_a_get_and_only_what_the_rules_need_is_handed_on`: one project's notification channels and alerting policies, in 2 requests.
Made-up data, the test's own; no real project, account or address is in it.

`http.json` and `config.json` are kept by `talos_module_testkit::recorded_run::keep`
at the end of that test. A normal `cargo test` fails when they no longer match
what the test serves; `make record-template TEMPLATE=gcp-alerting-evidence` rewrites them.

`make check-catalog-fuel TEMPLATE=gcp-alerting-evidence` builds the template the way the
platform does, runs it against this recording (nothing is sent), and fails if
the fuel used is above 80% of the limit `talos.json` declares.
