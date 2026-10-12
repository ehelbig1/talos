# `Send HTML Email (Gmail)` costs a quarter of what it did, and declares a measured limit (2026-10-12)

## Measured

The catalog template `send-html-email`, built through the production compile
path and run in the worker runtime against a made-up recording
(`make check-catalog-fuel`):

| `html` bytes | before | after |
|---:|---:|---:|
| 300 | 182,924 | 108,198 |
| 29,606 | 6,223,725 | 1,674,446 |
| 59,186 / 60,056 | 12,311,204 | 3,301,417 |
| 118,346 | not run | 6,415,588 |

About 206 fuel per byte of body before, about 54 after. The template had no
`recommended_fuel`, so an install got the 1,000,000 floor and could not send
a message much over 4 KB. A 30 KB message exhausted it.

## The class

A sender pays for the whole composed message, and this one paid four times:
a `serde_json::Value` tree of the entire input, a `String` copy of the body
out of it, a `format!` copy into the message, and a second JSON
serialisation that re-scanned the base64 text for characters to escape.
`CLAUDE.md` already says a module never parses an upstream payload as
`Value`; this template predates the rule.

## Decided

* **Typed input.** `Root` / `Config` / `Content` name the fields the module
  reads; the parser skips the rest without building it.
* **`Text`, a string-or-absent field.** A number or an object where a string
  belongs reads as "not given", as `Value::as_str` did, and whatever it holds
  is skipped. A derived `Option<String>` would have failed the whole payload
  on such a field, and an untagged enum buffers the value first, which is
  the cost being removed.
* **The message is built once**, into one buffer.
* **The request body is written directly**: `{"raw":"` + base64url + `"}`.
  The base64url alphabet has no character JSON escapes, so the bytes are
  the ones `serde_json` would produce.
* **A byte-wise encoder**, checked against RFC 4648's published vectors.
* **`recommended_fuel`: 60 KB at 55 fuel per byte, multiplier 1.5 =
  5,115,000.** A 60 KB message uses 64.5% of it. Sized from the table above,
  not estimated.
* **A recording of about 10 KB** (`fixtures/`, made-up data), so
  `make check-catalog-fuel` covers the template: 681,355 of 5,115,000.

## Measured and rejected

An in-place encoder (the output sized once, groups written by index):
1,694,328 at 30 KB against 1,674,446 for the simpler loop. Not kept. What is
left is the parse and the UTF-8 checks on the way in, which this module does
not control.

## Behaviour

Unchanged. The six behaviour tests written for the blank-email change pass
without modification, among them one that decodes what was sent with an
independent decoder. Two tests are added: the encoder against the published
vectors, and fields the module does not read (and a `subject` of the wrong
type) not disturbing it.

## Stated limits

* `FUEL_PER_BYTE_GUIDANCE` says "30–40 for bytes the module decodes or
  scans". This template measures 54. The guidance was not changed on one
  template's evidence.
* The limit covers a 60 KB body. A longer message needs the node's
  `max_fuel` raised; the description says so.
* An installed copy keeps its old code and limit until it is reinstalled.
* `send-gmail`, the older config-driven sender, is unchanged.

## Depends on

`2026-10-12-send-html-email-refuses-blank.md` (the same file's tests).
