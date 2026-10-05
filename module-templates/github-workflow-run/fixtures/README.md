# Recorded run

Made-up data with the shape and size of a real reply (about 370 KB): the 30
newest runs of a made-up repository's `quality.yml` on every branch, in the
mix of branches, events and states a real listing had — the newest finished
run on `main` concluded `failure`. Every value was replaced; only field names, enumerations and
timestamps' format are GitHub's.

`config.json` is the node config, `input.json` the upstream output (none),
`http.json` GitHub's answer, and `grants.json` the host the rehearsal may
address. Nothing is sent: the run is answered from `http.json`.

`make check-catalog-fuel TEMPLATE=github-workflow-run` builds the template
the way the platform does, runs it against this recording, and fails if the
fuel used is above 80% of the limit `talos.json` declares.
