# Testing a module

A module is built for the sandbox against `talos::core::*` (generated from
`wit/talos.wit`) and the `#[talos_module]` attribute. Neither exists on your
machine, so a module's tests need a stand-in. `talos-module-testkit` is that
stand-in.

## Catalog templates

Put a `#[cfg(test)] mod tests` in `module-templates/<name>/template.rs`.
Nothing else: `talos-catalog-tests` finds every template with a test module
and runs it.

```bash
make test-templates            # or: cargo test -p talos-catalog-tests
cargo test -p talos-catalog-tests google_health_daily   # one template
```

It is a workspace member, so the workspace unit tests in CI run it too.

If the template declares a crate in `talos.json` `dependencies`, add the same
crate to `talos-catalog-tests/Cargo.toml`; the build refuses a template whose
crate is missing and names it.

## Writing the tests

Two styles, and they mix.

**Take the host call as a parameter.** The logic takes the HTTP call as a
closure; `run` passes the real one and a test passes its own.

```rust
type Get<'a> = dyn FnMut(&str) -> Result<(u16, Vec<u8>), String> + 'a;
fn gather(get: &mut Get<'_>) -> Result<String, String> { … }
```

**Set up the host.** Call `run` itself and let the stand-in answer.

```rust
use talos_module_testkit::host;

host::http::respond_with(|req| Ok(host::http::response(200, r#"{"ok":true}"#)));
host::memory::put("list/mine", r#"{"items":[]}"#);
host::clock::set_unix(1_780_000_000);
let out = run(input).unwrap();
assert_eq!(host::http::requests().len(), 1);
```

| Host | Unset, it… | Set with |
|---|---|---|
| `http::fetch*` | fails with `Networkerror` (a test never reaches a network) | `host::http::respond`, `respond_with` |
| `agent_memory::*` | is an empty store | `host::memory::put`, `fail(true)` for "cannot be reached" |
| `secrets::get_secret` | resolves any path to `secrets::TEST_KEY` | `host::secrets::put`, `deny` |
| `secrets::hmac_sign` | is a real HMAC-SHA256 | — |
| `datetime::*` | reads the system clock; zones come from the IANA database | `host::clock::set_unix` |
| `llm::complete*` | fails with `NotConfigured` | `host::llm::respond`, `respond_with` |
| `logging::log` | records the line | read with `host::log::lines` |

State is per test thread: tests do not see each other's setup.

## Modules outside the catalog

Any crate can do what `talos-catalog-tests` does. In `build.rs`:

```rust
use talos_module_testkit::build::{generate, Module};
let modules = vec![Module::new("week-plan", "modules/week_plan.rs".into())];
generate(&modules, &std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap())).unwrap();
```

and in `src/lib.rs`:

```rust
pub use talos_module_testkit::talos;
include!(concat!(env!("OUT_DIR"), "/modules.rs"));
```

## What this proves

The module's logic. It does not prove the module builds for the sandbox: the
stand-in's types are a hand-written mirror of the generated ones. `make
check-catalog` compiles every template against the real bindings, and a test
in the kit holds its function names to `wit/talos.wit`. Interfaces not yet
mirrored (`model`, `database`, `messaging`, `cache`, `files`, `governance`,
`crypto`, `json`, `data_transform`) have to be added to the kit before a
module that uses them can be tested this way.
