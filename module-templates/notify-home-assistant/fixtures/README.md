# Recorded run

Made-up data: the largest message the contract allows. `notifications` holds
six parts, each with a title, a 1,500-character body, a link, a tag and three
actions, with the reply box from config, each answered by a made-up 200. The
fuel limit in `talos.json` is sized from this run, so it covers the longest
list.

`input.json` is the upstream node's output, `config.json` the node config,
`http.json` the service's answer, and `grants.json` names the host the
rehearsal may address — this template installs with no allowed hosts.
Nothing is sent: the run is answered from `http.json`.

`make check-catalog-fuel TEMPLATE=notify-home-assistant` builds the template the way the
platform does, runs it against this recording, and fails if the fuel used is
above 80% of the limit `talos.json` declares.
