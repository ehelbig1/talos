# The webhook tool described a signature its verifier refuses

2026-10-04

Found while checking how a phone app would post events into Talos.

## The defect

`create_webhook`'s response tells the caller how to sign. For the generic
format it said `X-Signature: <hex_hmac_sha256(ts+body, signing_secret)>`. The
verifier (`talos_webhooks::signature`) signs `ts + "." + body`. A sender
following the note computed a different MAC and got 401. The GitHub and
Slack descriptions were right.

Population: one description, one format of three. No webhook on this fleet
uses the generic format, so nothing live was failing.

## The fix

The description moved beside the verifier as
`talos_webhooks::HMAC_SENDER_NOTE`, and the tool formats it in. A test signs
exactly as the note says for all three formats and is accepted, and signs
the generic format without the separator and is refused. The note also now
states the 300-second timestamp window, which it did not.

No lint: one description of one verifier, now in one place.
