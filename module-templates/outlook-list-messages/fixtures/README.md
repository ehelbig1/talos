# Recorded run

Made-up data with the shape and size of a real Graph reply (about 30 KB):
the 25 newest messages of a made-up inbox (`MAX_RESULTS` at its cap of 25),
with the eight fields the module asks for (`$select`) plus the `@odata.etag`
Graph adds to each, and an `@odata.nextLink` saying the folder holds more in
the window — so the run reports `truncated: true`. Messages carry one to nine
recipients and previews of 120 to 255 characters (Graph's `bodyPreview`
maximum). Every value was replaced: ids, links and addresses are made up
(`example.com` / `.org` / `.net`); only field names and formats are Graph's.

`config.json` is the node config (a literal, made-up `AUTH_HEADER`, since the
rehearsal resolves no vault reference) and `http.json` Graph's one answer.
There is no `input.json` (the module reads no upstream output) and no
`grants.json` (the manifest already grants `graph.microsoft.com`). Nothing is
sent: the run is answered from `http.json`.

## Sizing

`recommended_fuel` is sized for 25 messages of about 2 KB each, at 30 fuel a
byte — the rate measured for JSON made of many short fields (a message is
mostly short fields: addresses, names, flags), not the default of 2, which
under-sizes it. Measured on 2026-10-08 (figures are not stable across compiler
versions): this recording (about 1.2 KB a message) used 2.37 M fuel; the same
25 messages grown to about 2 KB each (12 recipients, 130-character subjects,
255-character previews: a 49 KB reply) used 4.67 M, about half the declared
limit. Fuel grows with the size of the reply, mostly in parsing it.

`make check-catalog-fuel TEMPLATE=outlook-list-messages` builds the template
the way the platform does, runs it against this recording, and fails if the
fuel used is above 80% of the limit `talos.json` declares.
