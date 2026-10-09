# Recorded run

Made-up data: one notification with a title, a body, a link and three
actions (the most the contract allows) and a reply box from config, so the
run builds the largest message this adapter can, answered by a made-up 200.

`input.json` is the upstream node's output, `config.json` the node config,
`http.json` the service's answer, and `grants.json` names the host the
rehearsal may address — this template installs with no allowed hosts.
Nothing is sent: the run is answered from `http.json`.

`make check-catalog-fuel TEMPLATE=notify-home-assistant` builds the template the way the
platform does, runs it against this recording, and fails if the fuel used is
above 80% of the limit `talos.json` declares.
