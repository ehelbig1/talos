# Recorded run

Made-up data: a day's history of the reply helper with twenty replies (the
most one run returns) after the helper's first value, as Home Assistant's
history API returns it with `minimal_response`.

`config.json` pins the clock (`NOW_MS`) so every reply is inside the window,
and `grants.json` names the host the rehearsal may address — this template
installs with no allowed hosts. Nothing is sent: the run is answered from
`http.json`.

`make check-catalog-fuel TEMPLATE=capture-home-assistant` builds the template
the way the platform does, runs it against this recording, and fails if the
fuel used is above 80% of the limit `talos.json` declares.
