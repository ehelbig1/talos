# Recorded run

Made-up data: a day of an inbox topic with twenty lines (the most one run
returns), as ntfy's poll answers it (`/<topic>/json?poll=1`, one JSON object
per line).

`config.json` pins the clock (`NOW_MS`) so every line is inside the window,
and `grants.json` names the host the rehearsal may address — this template
installs with no allowed hosts. Nothing is sent: the run is answered from
`http.json`.

`make check-catalog-fuel TEMPLATE=capture-ntfy` builds the template the way
the platform does, runs it against this recording, and fails if the fuel used
is above 80% of the limit `talos.json` declares.
