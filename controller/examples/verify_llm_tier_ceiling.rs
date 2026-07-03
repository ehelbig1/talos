//! Smoke test for per-actor LLM tier ceiling.
//!
//! Verifies:
//! 1. Default tier for a fresh actor is `tier2` (backward compat).
//! 2. `set_actor_max_llm_tier` persists correctly.
//! 3. `get_actor_max_llm_tier` reads back the written tier.
//! 4. JobRequest signing binds `max_llm_tier` — tampering with the
//!    tier on the wire invalidates the signature.
//!
//! Worker-side enforcement (tier-1 job + anthropic call = fail-closed)
//! requires a full worker + vault stack to demonstrate, so that part
//! is covered by the worker's own unit tests against
//! `get_llm_api_key`. This verifier covers the controller-side plumbing.
//!
//! Run with:
//!   DATABASE_URL=postgres://talos:postgres@127.0.0.1:5433/talos \
//!     cargo run --example verify_llm_tier_ceiling -p controller

use anyhow::{Context, Result};
use sqlx::Row as _;
use uuid::Uuid;

use controller::actor_repository::ActorRepository;
use talos_workflow_job_protocol::{EncryptedSecrets, JobRequest, LlmTier};

#[tokio::main]
async fn main() -> Result<()> {
    let db_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let pool = sqlx::PgPool::connect(&db_url).await?;
    let repo = ActorRepository::new(pool.clone());

    // Pick any existing actor.
    let actor_id: Uuid = sqlx::query("SELECT id FROM actors LIMIT 1")
        .fetch_one(&pool)
        .await?
        .get(0);
    let user_id: Uuid = sqlx::query("SELECT user_id FROM actors WHERE id = $1")
        .bind(actor_id)
        .fetch_one(&pool)
        .await?
        .get(0);
    println!("actor: {actor_id}  user: {user_id}");

    // 1. Default is tier2.
    let t0 = repo.get_actor_max_llm_tier(actor_id).await?;
    println!("✓ initial tier: {:?}", t0);

    // 2. Flip to tier1, read back.
    let updated = repo
        .set_actor_max_llm_tier(actor_id, user_id, LlmTier::Tier1)
        .await?;
    assert!(
        updated,
        "set returned false — actor not found or wrong user"
    );
    let t1 = repo.get_actor_max_llm_tier(actor_id).await?;
    assert!(
        matches!(t1, Some(LlmTier::Tier1)),
        "expected Some(Tier1), got {:?}",
        t1
    );
    println!("✓ set/get tier1 round-trip");

    // 3. Flip back to tier2.
    repo.set_actor_max_llm_tier(actor_id, user_id, LlmTier::Tier2)
        .await?;
    let t2 = repo.get_actor_max_llm_tier(actor_id).await?;
    assert!(matches!(t2, Some(LlmTier::Tier2)));
    println!("✓ set/get tier2 round-trip");

    // 4. Wrong user denied.
    let wrong_user = Uuid::new_v4();
    let denied = repo
        .set_actor_max_llm_tier(actor_id, wrong_user, LlmTier::Tier1)
        .await?;
    assert!(!denied, "set should have returned false for wrong user");
    println!("✓ set with wrong user_id denied");

    // 5. HMAC binding — tampering with tier on the wire breaks signature.
    let mut req = JobRequest {
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        module_uri: "redis:wasm:test".to_string(),
        input_payload: serde_json::json!({}),
        encrypted_secrets: EncryptedSecrets::empty(),
        timeout_ms: 1000,
        priority: 100,
        deadline_unix_secs: 0,
        cancellation_token: None,
        allowed_hosts: vec![],
        allowed_methods: vec![],
        allowed_secrets: vec![],
        allowed_sql_operations: vec![],
        allow_tier2_exposure: false,
        signature: vec![],
        job_nonce: String::new(),
        actor_id: Some(actor_id),
        wasm_bytes: None,
        capability_world: None,
        integration_name: None,
        expected_wasm_hash: None,
        max_fuel: 0,
        user_id,
        max_llm_tier: LlmTier::Tier1,
        dry_run: false,
        reply_topic: None,
    };
    let key = [0u8; 32];
    req.sign(&key).map_err(|e| anyhow::anyhow!("sign: {e}"))?;
    req.verify(&key, 60)
        .map_err(|e| anyhow::anyhow!("verify fresh: {e}"))?;

    // Tamper: flip tier to Tier2 without re-signing.
    req.max_llm_tier = LlmTier::Tier2;
    let tampered = req.verify(&key, 60);
    assert!(
        tampered.is_err(),
        "HMAC did not catch tier downgrade tampering! This would let an on-wire attacker redirect a tier-1 actor's data to external LLMs."
    );
    println!("✓ HMAC catches tier-downgrade tampering");

    // Reset and re-sign to confirm non-tampered verify still passes.
    req.sign(&key).map_err(|e| anyhow::anyhow!("resign: {e}"))?;
    req.verify(&key, 60)
        .map_err(|e| anyhow::anyhow!("verify resigned: {e}"))?;
    println!("✓ re-signed request verifies");

    // 6. PipelineJobRequest binds tier in its signature too — closes
    //    the C1 bypass where pipeline (chain-dispatched) jobs had no
    //    tier field and silently ran at Tier2.
    use talos_workflow_job_protocol::{PipelineJobRequest, PipelineStep};
    let mut pipeline = PipelineJobRequest {
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        steps: vec![PipelineStep {
            module_id: Uuid::new_v4(),
            module_uri: "redis:wasm:test".into(),
            wasm_bytes: None,
            config: serde_json::json!({}),
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            encrypted_secrets: EncryptedSecrets::empty(),
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            max_fuel: 0,
            max_memory_mb: 128,
            timeout_ms: 1000,
            priority: 100,
            cancellation_token: None,
            integration_name: None,
            expected_wasm_hash: None,
        }],
        signature: vec![],
        job_nonce: String::new(),
        total_timeout_ms: 5000,
        share_sandbox: false,
        user_id,
        max_llm_tier: LlmTier::Tier1,
        reply_topic: None,
    };
    pipeline
        .sign(&key)
        .map_err(|e| anyhow::anyhow!("pipeline sign: {e}"))?;
    pipeline
        .verify(&key, 60)
        .map_err(|e| anyhow::anyhow!("pipeline verify: {e}"))?;
    pipeline.max_llm_tier = LlmTier::Tier2;
    assert!(
        pipeline.verify(&key, 60).is_err(),
        "PipelineJobRequest HMAC did not catch tier downgrade — chain-dispatched jobs (judge/ensemble/agent-loop) would silently bypass tier-1 ceiling"
    );
    println!("✓ PipelineJobRequest HMAC binds tier (C1 closer)");

    // 7. HTTP host deny-list locks down the C3 bypass — a tier-1 actor
    //    that uses wit_http::fetch directly cannot reach an external
    //    LLM provider's domain even with it in `allowed_hosts`.
    use talos_workflow_job_protocol::{is_external_llm_host, is_tier2_llm_vault_path};
    for host in [
        "api.anthropic.com",
        "api.openai.com",
        "generativelanguage.googleapis.com",
        "eu.api.openai.com",
    ] {
        assert!(
            is_external_llm_host(host),
            "{host} must be on the external-LLM deny-list — C3 bypass otherwise"
        );
    }
    for path in ["anthropic/api_key", "openai/api_key", "gemini/api_key"] {
        assert!(
            is_tier2_llm_vault_path(path),
            "{path} must be marked tier-2 — vault://{path} would bypass otherwise"
        );
    }
    println!("✓ external-LLM host deny-list + tier-2 vault path catalog (C3 closers)");

    println!("\n🎉 LLM tier ceiling end-to-end PASSED");
    Ok(())
}
