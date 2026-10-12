# Recorded run

Made-up data: one HTML message of about 10 KB (a heading and a hundred short
paragraphs), answered by a made-up 200 from the Gmail send endpoint.

`input.json` is the upstream compose node's output, `config.json` the node
config (a made-up bearer value, not a vault reference), and `http.json` the
service's answer. Nothing is sent: the run is answered from `http.json`.

The module's cost grows with the size of `html`: it parses the body out of
its input and base64-encodes the whole message. Measured 2026-10-12 on the
template built with the production profile:

| `html` bytes | fuel used |
|---:|---:|
| 300 | 108,198 |
| 10,592 (this recording) | 681,355 |
| 29,606 | 1,674,446 |
| 60,056 | 3,301,417 |
| 118,346 | 6,415,588 |

About 54 fuel per byte. `talos.json` declares a limit for a 60 KB message
(5,115,000); a longer one needs the node's `max_fuel` raised.

`make check-catalog-fuel TEMPLATE=send-html-email` builds the template the way
the platform does, runs it against this recording, and fails if the fuel used
is above 80% of the limit `talos.json` declares.
