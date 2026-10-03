# Recorded run

Made-up data: 100 entries of about 370 bytes each (a 37 KB response), three
fields kept from each entry and one beside the list. This is the "100 entries"
case the template's description quotes.

`http.json` is the response, `config.json` the node config, and `grants.json`
names the host the rehearsal may address — this template installs with no
allowed hosts, so a run needs one from somewhere. Nothing is sent: the run is
answered from `http.json`.

`make check-catalog-fuel TEMPLATE=json-api-reader` builds the template the way
the platform does, runs it against this recording, and fails if the fuel used
is above 80% of the limit `talos.json` declares.
