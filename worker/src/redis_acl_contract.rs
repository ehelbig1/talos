//! The worker's Redis user grants what the worker uses (security review
//! 2026-10-15, E2-6). `deploy/redis/worker.acl-rules` is the one home of the
//! rules; a key family or a scripted command the worker uses and the rules
//! omit is refused by Redis, and with the replay guard failing closed that is
//! every dispatch. This pins the rules to the code: the key prefixes the
//! worker builds, and every command inside the Lua scripts it sends (Redis
//! checks a script's commands against the caller's ACL too).
//! `scripts/tests/redis-worker-acl-test.sh` drives the families through a
//! real Redis with the same file.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

struct Rules {
    /// `(pattern without its `*`, read_only)`.
    keys: Vec<(String, bool)>,
    commands: Vec<String>,
}

fn rules() -> Rules {
    let text = read("deploy/redis/worker.acl-rules");
    let mut keys = Vec::new();
    let mut commands = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(p) = line.strip_prefix("%R~") {
            keys.push((p.trim_end_matches('*').to_string(), true));
        } else if let Some(p) = line.strip_prefix('~') {
            keys.push((p.trim_end_matches('*').to_string(), false));
        } else if let Some(c) = line.strip_prefix('+') {
            commands.push(c.to_ascii_lowercase());
        }
    }
    Rules { keys, commands }
}

fn writable(rules: &Rules, key: &str) -> bool {
    rules
        .keys
        .iter()
        .any(|(p, ro)| !ro && key.starts_with(p.as_str()))
}

fn readable(rules: &Rules, key: &str) -> bool {
    rules.keys.iter().any(|(p, _)| key.starts_with(p.as_str()))
}

/// Every `redis.call('X'` in a script source.
fn scripted_commands(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in source.match_indices("redis.call(") {
        let rest = source[i + "redis.call(".len()..].trim_start();
        let Some(quote) = rest.chars().next().filter(|c| *c == '\'' || *c == '"') else {
            continue;
        };
        let name: String = rest[1..].chars().take_while(|c| *c != quote).collect();
        out.push(name.to_ascii_lowercase());
    }
    out
}

#[test]
fn every_scripted_command_is_granted() {
    let rules = rules();
    let mut seen = 0;
    for file in [
        "talos-local-inference/src/fleet.rs",
        "talos-worker-runtime/src/host/cache.rs",
        "talos-worker-runtime/src/host/graphql.rs",
    ] {
        for cmd in scripted_commands(&read(file)) {
            seen += 1;
            assert!(
                rules.commands.contains(&cmd),
                "{file} scripts `{cmd}`, which deploy/redis/worker.acl-rules does not grant"
            );
        }
    }
    assert!(
        seen >= 15,
        "the script scan found {seen} calls — has a script moved?"
    );
    for needed in ["eval", "evalsha", "script|load"] {
        assert!(rules.commands.contains(&needed.to_string()), "{needed}");
    }
}

#[test]
fn every_worker_key_family_is_granted() {
    let rules = rules();
    // Prefixes the code exports.
    for prefix in [
        crate::dispatch_replay::KEY_PREFIX,
        talos_worker_runtime::job_idempotency::REDIS_JOB_PREFIX,
        talos_worker_runtime::job_idempotency::REDIS_PIPELINE_PREFIX,
    ] {
        assert!(writable(&rules, &format!("{prefix}x")), "{prefix}");
    }
    // Prefixes built inline: the source still builds each, and a sample key
    // is granted as the worker uses it.
    for (file, literal, sample, write) in [
        (
            "talos-worker-runtime/src/runtime.rs",
            "wasm:result:",
            "wasm:result:h:d",
            true,
        ),
        (
            "talos-worker-runtime/src/module_fetcher.rs",
            "oci_cache:",
            "oci_cache:sha256:d",
            true,
        ),
        (
            "talos-worker-runtime/src/host/cache.rs",
            "talos_cache:",
            "talos_cache:u=x:k",
            true,
        ),
        (
            "talos-worker-runtime/src/host/secrets.rs",
            "talos:tier2_expose:",
            "talos:tier2_expose:u:d",
            true,
        ),
        (
            "talos-local-inference/src/fleet.rs",
            "talos:llm-admit:",
            "talos:llm-admit:{00}:holders",
            true,
        ),
        (
            "talos-worker-runtime/src/host/governance.rs",
            "approval:",
            "approval:w",
            true,
        ),
        (
            "talos-workflow-engine-core/src/wasm_cache.rs",
            "wasm:",
            "wasm:u:m",
            false,
        ),
    ] {
        assert!(
            read(file).contains(literal),
            "{file} no longer builds `{literal}` — update the rules and this list"
        );
        if write {
            assert!(writable(&rules, sample), "{sample} must be writable");
        } else {
            assert!(readable(&rules, sample), "{sample} must be readable");
            assert!(
                !writable(&rules, sample),
                "{sample} must NOT be writable by the worker"
            );
        }
    }
}

/// What the separation is for: keys the controller owns are not the worker's.
#[test]
fn controller_keys_are_not_the_workers() {
    let rules = rules();
    for key in [
        "talos:nonce:rpc:x",                           // the controller's replay guard
        "idempotency:k",                               // request idempotency
        "webhook:processed:k",                         // webhook dedup
        "wasm:00000000-0000-0000-0000-000000000000:m", // a module's cached bytes
        "talos:llm-keys:x",
        "session:x",
    ] {
        assert!(!writable(&rules, key), "the worker may write `{key}`");
    }
}
