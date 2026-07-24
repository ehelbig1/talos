//! CLI subcommand implementations for the controller binary — moved
//! VERBATIM out of `controller/src/main.rs` in the 2026-07 decomposition.
//! Dispatch (the `match` over `std::env::args`) stays at the very top of
//! `main()`; this module owns the subcommand bodies: the worker-identity
//! registry operations, worker provisioning-token mint/list/revoke, the
//! RFC 0010 Ed25519 keypair generator, and `publish-templates`.
use crate::*;

// ---------- worker-identity registry subcommands (RFC 0010 P2 inc.4) --------
//
// Operator-facing management of the `worker_identities` DB registry. Workers are
// credential-free (no Postgres), so THEY self-register over the HTTP endpoint;
// these subcommands are the OPERATOR path — pre-registering keys, auditing the
// registry, and retiring rotated-out keys — run from a context that already
// holds DB credentials (the controller image as a one-shot Job). Direct DB
// access is its own authorization, so no proof-of-possession is required here
// (that gate exists on the network self-registration endpoint).
pub(crate) async fn run_worker_identity_cli(sub: &str, args: &[String]) -> anyhow::Result<()> {
    use talos_worker_identity_repository::{RegisterOutcome, WorkerIdentityRepository};

    let mut worker_id: Option<String> = None;
    let mut public_key_hex: Option<String> = None;
    let mut supports_sealing = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--worker-id" => {
                worker_id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--worker-id requires a value"))?
                        .clone(),
                );
            }
            "--public-key" => {
                public_key_hex = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--public-key requires a value"))?
                        .clone(),
                );
            }
            "--supports-sealing" => supports_sealing = true,
            other => anyhow::bail!("unknown {sub} flag: {other}"),
        }
    }

    let pool = crate::db::init_pool().await?;
    let repo = WorkerIdentityRepository::new(pool);

    // Shared parse+validate for the two subcommands that take a key.
    let resolve_key =
        |worker_id: &Option<String>, hex: &Option<String>| -> anyhow::Result<(String, [u8; 32])> {
            let wid = worker_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--worker-id is required"))?;
            talos_workflow_job_protocol::validate_worker_id(&wid)
                .map_err(|e| anyhow::anyhow!("invalid --worker-id: {e}"))?;
            let hex = hex.clone().ok_or_else(|| {
                anyhow::anyhow!("--public-key is required (64-char hex Ed25519 key)")
            })?;
            // Parse through the canonical loader so a non-point is rejected here, not
            // at verify time — the stored key is guaranteed a valid Ed25519 point.
            let vk = talos_workflow_job_protocol::parse_ed25519_verifying_key_hex(&hex)
                .map_err(|e| anyhow::anyhow!("invalid --public-key: {e}"))?;
            Ok((wid, vk.to_bytes()))
        };

    match sub {
        "register-worker-identity" => {
            let (wid, pk) = resolve_key(&worker_id, &public_key_hex)?;
            match repo.register(&wid, &pk, supports_sealing).await? {
                RegisterOutcome::Registered => {
                    println!("registered worker '{wid}' (supports_sealing={supports_sealing})");
                }
                RegisterOutcome::CapReached => anyhow::bail!(
                    "worker '{wid}' already holds the maximum active keys \
                     ({}); deactivate one before adding another",
                    talos_worker_identity_repository::MAX_ACTIVE_KEYS_PER_WORKER
                ),
            }
        }
        "deactivate-worker-identity" => {
            let (wid, pk) = resolve_key(&worker_id, &public_key_hex)?;
            if repo.deactivate(&wid, &pk).await? {
                println!("deactivated one key for worker '{wid}'");
            } else {
                println!("no active key matched for worker '{wid}' (already retired or absent)");
            }
        }
        "list-worker-identities" => {
            let rows = repo.list().await?;
            if rows.is_empty() {
                println!("(worker-identity registry is empty)");
            }
            for r in rows {
                println!(
                    "{wid}\t{key}\tsealing={sealing}\tactive={active}\tlast_seen={seen}",
                    wid = r.worker_id,
                    key = hex::encode(r.public_key),
                    sealing = r.supports_sealing,
                    active = r.active,
                    seen = r.last_seen_at.to_rfc3339(),
                );
            }
        }
        _ => unreachable!("dispatch guarded by the match in main()"),
    }
    Ok(())
}

// ------- worker provisioning-token subcommands (RFC 0010 P2 inc.2/3) --------
//
// Operator mint/list/revoke for `worker_provisioning_tokens` — the single-use,
// worker_id-bound credentials the registration endpoint redeems. Same trust
// model as the worker-identity subcommands above: DB credentials ARE the
// authorization. The raw token is printed ONCE to stdout (like
// generate-worker-trust-keypair) and only its SHA-256 is stored; mints and
// revokes append to `admin_event_log` (user_id NULL — no platform user exists
// on this path) so the token lifecycle is auditable end-to-end.
pub(crate) async fn run_worker_provisioning_token_cli(
    sub: &str,
    args: &[String],
) -> anyhow::Result<()> {
    use talos_worker_identity_repository::WorkerIdentityRepository;

    let mut worker_id: Option<String> = None;
    let mut wildcard = false;
    let mut ttl_hours: i64 = 24;
    let mut note: Option<String> = None;
    let mut id: Option<uuid::Uuid> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--worker-id" => {
                worker_id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--worker-id requires a value"))?
                        .clone(),
                );
            }
            "--wildcard" => wildcard = true,
            "--ttl-hours" => {
                ttl_hours = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--ttl-hours requires a value"))?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("--ttl-hours must be an integer"))?;
            }
            "--note" => {
                note = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--note requires a value"))?
                        .clone(),
                );
            }
            "--id" => {
                id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
                        .parse()
                        .map_err(|_| anyhow::anyhow!("--id must be a UUID"))?,
                );
            }
            other => anyhow::bail!("unknown {sub} flag: {other}"),
        }
    }

    let pool = crate::db::init_pool().await?;
    let repo = WorkerIdentityRepository::new(pool);

    match sub {
        "mint-worker-provisioning-token" => {
            // Binding is an explicit choice: wildcard must be SPELLED OUT, so
            // an operator can't mint an any-worker token by forgetting a flag.
            let binding = match (&worker_id, wildcard) {
                (Some(_), true) => {
                    anyhow::bail!("--worker-id and --wildcard are mutually exclusive")
                }
                (None, false) => anyhow::bail!(
                    "specify --worker-id <id> (bound, recommended) or --wildcard (migration \
                     compat; refused when TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1)"
                ),
                (Some(wid), false) => {
                    talos_workflow_job_protocol::validate_worker_id(wid)
                        .map_err(|e| anyhow::anyhow!("invalid --worker-id: {e}"))?;
                    Some(wid.clone())
                }
                (None, true) => None,
            };
            if !(1..=24 * 30).contains(&ttl_hours) {
                anyhow::bail!("--ttl-hours must be between 1 and 720 (30 days)");
            }
            // Bound the note so the audit/list surfaces stay sane.
            if note.as_ref().is_some_and(|n| n.len() > 500) {
                anyhow::bail!("--note must be at most 500 bytes");
            }

            // 32 bytes of OS entropy, hex-encoded, prefixed for greppability.
            // Only the SHA-256 of this string is persisted.
            let raw_token = {
                use rand::RngCore;
                let mut buf = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut buf);
                format!("wpt_{}", hex::encode(buf))
            };
            let expires_at = chrono::Utc::now() + chrono::Duration::hours(ttl_hours);
            let token_id = repo
                .create_provisioning_token(
                    &provisioning_token_hash(&raw_token),
                    binding.as_deref(),
                    expires_at,
                    note.as_deref(),
                )
                .await?;
            repo.insert_provisioning_token_audit(
                "worker_provisioning_token_minted",
                token_id,
                &format!(
                    "minted worker provisioning token for {} (ttl {ttl_hours}h)",
                    binding.as_deref().unwrap_or("WILDCARD")
                ),
                Some(&serde_json::json!({
                    "worker_id": binding,
                    "expires_at": expires_at.to_rfc3339(),
                    "note": note,
                })),
            )
            .await?;

            eprintln!("# ─────────────────────────────────────────────────────────────────────");
            eprintln!("# Worker provisioning token — shown ONCE, only its SHA-256 is stored.");
            eprintln!("# Hand it to exactly ONE worker pod as its registration bearer, then");
            eprintln!("# discard it. Single-use; expires {expires_at}.");
            eprintln!("# ─────────────────────────────────────────────────────────────────────");
            match &binding {
                Some(wid) => println!("# ── on WORKER '{wid}' (bound: registers only this id) ──"),
                None => println!("# ── WILDCARD token (any worker_id, TOFU rule applies) ──"),
            }
            println!("TALOS_WORKER_REGISTRATION_TOKEN={raw_token}");
            println!("# token id: {token_id}  (revoke-worker-provisioning-token --id {token_id})");
        }
        "list-worker-provisioning-tokens" => {
            let rows = repo.list_provisioning_tokens().await?;
            if rows.is_empty() {
                println!("(no worker provisioning tokens minted)");
            }
            let now = chrono::Utc::now();
            for r in rows {
                // One derived status keeps the listing scannable; precedence
                // mirrors the redeem SQL (used beats revoked beats expired).
                let status = if let Some(used) = r.used_at {
                    format!(
                        "USED by '{}' at {}",
                        r.used_by_worker_id.as_deref().unwrap_or("?"),
                        used.to_rfc3339()
                    )
                } else if let Some(revoked) = r.revoked_at {
                    format!("REVOKED at {}", revoked.to_rfc3339())
                } else if r.expires_at <= now {
                    "EXPIRED".to_string()
                } else {
                    "live".to_string()
                };
                println!(
                    "{id}\t{binding}\texpires={expires}\t{status}\t{note}",
                    id = r.id,
                    binding = r
                        .worker_id
                        .as_deref()
                        .map(|w| format!("worker={w}"))
                        .unwrap_or_else(|| "WILDCARD".to_string()),
                    expires = r.expires_at.to_rfc3339(),
                    note = r.note.as_deref().unwrap_or(""),
                );
            }
        }
        "revoke-worker-provisioning-token" => {
            let id = id.ok_or_else(|| anyhow::anyhow!("--id <uuid> is required"))?;
            if repo.revoke_provisioning_token(id).await? {
                repo.insert_provisioning_token_audit(
                    "worker_provisioning_token_revoked",
                    id,
                    "revoked worker provisioning token",
                    None,
                )
                .await?;
                println!("revoked provisioning token {id}");
            } else {
                println!(
                    "token {id} was not live (already used, already revoked, or unknown) — \
                     nothing changed"
                );
            }
        }
        _ => unreachable!("dispatch guarded by the match in main()"),
    }
    Ok(())
}

// ---------- `controller generate-worker-trust-keypair` subcommand ----------
//
// RFC 0010 (asymmetric worker-trust boundary). Mints an Ed25519 keypair in the
// exact hex shape the env loaders accept and prints a copy-pasteable env block
// telling the operator which half goes on which process. This is the ONE
// supported way to generate keys for the boundary — hand-rolling with openssl
// produces the wrong encoding (the loaders want a raw 32-byte seed / point in
// hex, not a PKCS#8/PEM wrapper).
//
// Two roles, because the boundary has two independent keypairs:
//   --role controller            controller SIGNS dispatches, workers VERIFY.
//                                seed → TALOS_CONTROLLER_SIGNING_KEY (controller)
//                                pub  → TALOS_CONTROLLER_PUBLIC_KEY  (workers)
//   --role worker --worker-id ID this worker SIGNS results + RPC, controller VERIFIES.
//                                seed → TALOS_WORKER_SIGNING_KEY (this worker)
//                                pub  → TALOS_WORKER_PUBLIC_KEYS entry (controller)
//
// The seed is a PRIVATE key: it prints to stdout (the standard keygen pattern,
// like `wg genkey`) so the operator can capture it into a Secret, and a loud
// stderr banner reminds them never to commit it. Nothing is logged via
// `tracing` — the value never touches the structured log surface.
pub(crate) fn run_generate_worker_trust_keypair_cli(args: &[String]) -> anyhow::Result<()> {
    let mut role: Option<String> = None;
    let mut worker_id: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--role" => {
                role = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--role requires a value"))?
                        .clone(),
                );
            }
            "--worker-id" => {
                worker_id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--worker-id requires a value"))?
                        .clone(),
                );
            }
            other => anyhow::bail!("unknown generate-worker-trust-keypair flag: {other}"),
        }
    }
    let role = role.ok_or_else(|| anyhow::anyhow!("--role is required (controller|worker)"))?;

    let (seed_hex, pub_hex) = talos_workflow_job_protocol::generate_ed25519_keypair_hex();

    // Secret-handling banner on stderr so it's visible even when stdout is
    // piped into a file/secret.
    eprintln!("# ─────────────────────────────────────────────────────────────────────");
    eprintln!("# RFC 0010 worker-trust keypair ({role}). The SIGNING key below is");
    eprintln!("# SECRET — store it in a Kubernetes Secret / KMS, hand it to exactly");
    eprintln!("# one process, and NEVER commit it. The PUBLIC key is safe to share.");
    eprintln!("# ─────────────────────────────────────────────────────────────────────");

    match role.as_str() {
        "controller" => {
            println!("# ── on the CONTROLLER (signs dispatches) ──");
            println!("TALOS_DISPATCH_SCHEME=ed25519");
            println!("TALOS_CONTROLLER_SIGNING_KEY={seed_hex}");
            println!();
            println!("# ── on EVERY WORKER (verifies dispatches) ──");
            println!("TALOS_CONTROLLER_PUBLIC_KEY={pub_hex}");
            println!("# During a controller-key rotation, keep the previous public key for an");
            println!("# overlap window: TALOS_CONTROLLER_PUBLIC_KEY_PREVIOUS=<old_pub>[,<older>]");
        }
        "worker" => {
            let wid = worker_id
                .ok_or_else(|| anyhow::anyhow!("--worker-id is required for --role worker"))?;
            // The id is bound into every Ed25519 result/RPC signature and used
            // as the controller's lookup key, so it must satisfy the same
            // validator the worker applies at sign time.
            talos_workflow_job_protocol::validate_worker_id(&wid)
                .map_err(|e| anyhow::anyhow!("invalid --worker-id: {e}"))?;
            println!("# ── on WORKER '{wid}' (signs job results + RPC) ──");
            println!("TALOS_WORKER_SIGNING_KEY={seed_hex}");
            println!();
            println!("# ── on the CONTROLLER (verifies this worker) ──");
            println!("# Append to TALOS_WORKER_PUBLIC_KEYS (comma-separated worker_id=hex pairs;");
            println!("# repeat the same id with a new key for a rotation overlap window):");
            println!("TALOS_WORKER_PUBLIC_KEYS={wid}={pub_hex}");
        }
        other => anyhow::bail!("unknown --role '{other}' (expected controller|worker)"),
    }
    Ok(())
}

// ---------- `controller publish-templates` subcommand ----------
//
// Compiles every template in `--templates-dir` (default: `module-templates/`)
// using the same `CompilationService` the running controller uses, and emits
// a registry-ready bundle to `--output`:
//
//   {output}/
//     {template-name}/
//       talos.json   — manifest copied verbatim
//       module.wasm  — cargo-component build output
//     _index.json    — discovery index, format matches sync.rs::IndexConfig
//
// CI then iterates each subdirectory and runs `oras push` to publish the
// artifacts to the configured registry. See
// `.github/workflows/template-publish.yml`.
//
// This subcommand exists so CI doesn't have to replicate the cargo-component
// scaffolding (Cargo.toml + lib.rs wrapper + WIT bindings) in YAML — that
// scaffold lives in `compilation::CompilationService` and would drift the
// moment one was edited without the other. By shelling out to the controller
// binary itself, CI always uses the same compilation pipeline as production.
pub(crate) async fn run_publish_templates_cli(args: &[String]) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::path::PathBuf;

    // Tiny flag parser — clap is overkill for two options and would pull in
    // the dependency just for this subcommand.
    let mut templates_dir = PathBuf::from("module-templates");
    let mut output_dir: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--templates-dir" => {
                templates_dir = PathBuf::from(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--templates-dir requires a value"))?,
                );
            }
            "--output" => {
                output_dir =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--output requires a value")
                    })?));
            }
            other => anyhow::bail!("unknown publish-templates flag: {other}"),
        }
    }
    let output_dir = output_dir.ok_or_else(|| {
        anyhow::anyhow!("--output is required (path where artifacts will be written)")
    })?;

    if !templates_dir.exists() {
        anyhow::bail!(
            "templates dir not found: {} (set --templates-dir or run from the workspace root)",
            templates_dir.display()
        );
    }
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("create --output dir {}", output_dir.display()))?;

    // Stand up a minimal CompilationService — same constructor the server
    // uses, plus a no-op event channel so progress events are dropped.
    let workspace_root = std::env::temp_dir().join("talos-publish-workspace");
    let (event_tx, _rx) = tokio::sync::broadcast::channel::<engine::events::CompilationEvent>(64);
    let svc = CompilationService::new(workspace_root, event_tx);

    let mut index_entries: Vec<serde_json::Value> = Vec::new();
    let mut compiled = 0usize;
    let mut skipped = 0usize;

    let entries = std::fs::read_dir(&templates_dir)
        .with_context(|| format!("read --templates-dir {}", templates_dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("talos.json");
        let template_path = path.join("template.rs");
        if !manifest_path.exists() || !template_path.exists() {
            skipped += 1;
            continue;
        }

        let manifest_str = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?;
        let manifest_json: serde_json::Value = serde_json::from_str(&manifest_str)
            .with_context(|| format!("parse {}", manifest_path.display()))?;

        // `name` is the OCI repo name (kebab-case, lowercase, no spaces);
        // `version` becomes the OCI tag. Both are required for publishing.
        let name = manifest_json
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("{} missing required `name`", manifest_path.display()))?
            .to_string();
        let tag = manifest_json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("latest")
            .to_string();

        let source = std::fs::read_to_string(&template_path)
            .with_context(|| format!("read {}", template_path.display()))?;

        eprintln!("publish-templates: compiling {name} v{tag}");
        let result = svc
            .compile_to_wasm(uuid::Uuid::nil(), uuid::Uuid::new_v4(), &name, &source)
            .await
            .with_context(|| format!("compile_to_wasm({name})"))?;
        let wasm = result
            .wasm_bytes
            .ok_or_else(|| anyhow::anyhow!("compile produced no WASM bytes for {name}"))?;

        let template_out = output_dir.join(&name);
        std::fs::create_dir_all(&template_out)?;
        std::fs::write(template_out.join("talos.json"), &manifest_str)?;
        std::fs::write(template_out.join("module.wasm"), &wasm)?;

        index_entries.push(serde_json::json!({"name": name, "tag": tag}));
        compiled += 1;
    }

    // Discovery index — must match registry::sync::IndexConfig shape exactly.
    // sync_once() pulls this artifact's config blob and parses it with that
    // struct; field renames here will silently break runtime sync.
    let index = serde_json::json!({"templates": index_entries});
    std::fs::write(
        output_dir.join("_index.json"),
        serde_json::to_string_pretty(&index)?,
    )?;

    eprintln!(
        "publish-templates: done — compiled {compiled} templates, skipped {skipped} \
         (missing talos.json or template.rs), wrote bundle to {}",
        output_dir.display()
    );
    Ok(())
}
