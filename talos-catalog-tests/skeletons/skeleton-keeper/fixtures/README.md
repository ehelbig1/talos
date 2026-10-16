# No recorded run

A keeper reads its own memory key before it writes, and the fuel check's
rehearsal has no actor memory to read, so a keeper has no `http.json` and its
fuel is not checked. Declare `recommended_fuel` in `talos.json` from its
bounds (MAX_KEPT entries of FIELD_CHARS each, read and written once a run).
