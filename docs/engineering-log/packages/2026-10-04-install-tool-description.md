# The install tool's description says what an install does in both modes

2026-10-04

`install_module_from_catalog` opened its description with "Compile and
install" and listed `wasm_sha256` as always present. Since the registry
install path landed, an install on a registry deployment compiles nothing and
its copy has no bytes to hash. An agent reading the description would expect a
compile, a hash, and a copy it could hot-update.

The description now says that the reply's `source` is `compiled` or
`registry`, what each means, that `wasm_sha256` is null for a registry copy
and `content_hash` is the field to compare, and that hot update is refused on
a registry copy.

Two sentences in `list_module_catalog` said to install "when you want a
PRIVATE copy to modify with hot_update_module". The reason to install is a
copy with its own hosts, secrets and fuel limit; modifying it applies only
where the platform compiled it. Both now say so.

A unit test reads the tool's schema and holds the description to those
statements.
