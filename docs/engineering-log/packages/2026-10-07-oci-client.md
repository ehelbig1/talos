# `oci-distribution` 0.11 → `oci-client` 0.18; OpenSSL leaves the build (2026-10-07)

The follow-up `2026-10-07-reqwest-0.13.md` promised. `oci-distribution` was
the last crate on `reqwest` 0.12, and the one whose default features
compiled native-tls into every client. Its successor under the new name,
`oci-client`, uses `reqwest` 0.13.

It pulls the module catalog from a registry (`talos-registry`, the
controller's sync) and a module's WASM artifact (`module_fetcher`, the
worker). **Latent on this fleet:** `TALOS_REGISTRY_URL` is unset on both
containers and none of the 135 modules names an artifact (`oci_url`), so
neither path has run here.

## Changed

* The workspace table names `oci-client = "0.18"`, default features off;
  both users ask for `rustls-tls`. The worker runtime had asked for
  `oci-distribution`'s defaults, which is what brought native-tls in.
* The code needed the rename and nothing else: every call the two crates
  make (`fetch_manifest_digest`, `pull_manifest_raw`, `pull_blob`,
  `pull_blob_stream`, `Reference`, the auth and client config) kept its
  shape.
* The lockfile loses `reqwest` 0.12, `native-tls`, `openssl`, `openssl-sys`,
  `hyper-tls`, `tokio-native-tls` and a `base64` 0.13, and gains `oci-spec`
  and its derive helpers.
* `deny.toml` bans `native-tls` and `openssl-sys` — the hard deny its own
  note said was the ideal and could not yet be.

## Measured

Both clients against a throwaway `registry:2` from the stack's own pinned
image, one made-up artifact pushed: the manifest digest by tag, the raw
manifest by digest (bytes hash to the digest; the server's digest header
agrees), the config blob and the layer stream (each hashes to its
descriptor) — identical. A missing tag, repository or manifest digest gives
the same error from both. A missing BLOB differs: 0.11 reported the bare
HTTP 404, 0.18 reports the registry's `BLOB_UNKNOWN`.

## Found, and fixed here

**The registry sync could not recognise a missing artifact.** It decided by
matching the error's text (`manifest_unknown`, a bounded `404`, or `not
found`). What `registry:2` actually returns renders as `…OCI API error:
manifest unknown]` — none of those — from both versions. So a first deploy
with no index artifact failed instead of falling back to `/v2/_catalog`,
which the code says is the expected path. The unit tests passed because they
were written against made-up strings in the shape someone expected.

`is_registry_not_found` now reads the client's typed error first — the
registry's error code (`MANIFEST_UNKNOWN`, `NAME_UNKNOWN`, `BLOB_UNKNOWN`,
`NOT_FOUND`) or a 404 — and keeps the text matcher only as a fallback. Its
test builds the error from the registry's measured answer and asserts both
that the old matcher missed it and that the new check sees it, through
added context too; an authentication or rate-limit code is still not
"missing".

## Checked

`outbound_tls_pin` in both binaries still passes: `oci-client` brings no
native-tls. The rest: see the PR.
