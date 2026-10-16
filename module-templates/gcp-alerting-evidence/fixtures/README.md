# Recorded run

Made-up data, taken from this template's own test of the same name's shape:
one project's notification channels and alerting policies, the security ones picked by a display-name prefix, in 2 GET requests. No real project, account or
address is in it.

`config.json` is the node config for the run (the token is a placeholder: the
run is answered from `http.json` and nothing is sent).

`make check-catalog-fuel TEMPLATE=gcp-alerting-evidence` builds the template the way the
platform does, runs it against this recording, and fails if the fuel used is
above 80% of the limit `talos.json` declares.
