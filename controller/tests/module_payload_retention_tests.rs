// Module-payload retention sweep — the safety properties, end to end.
//
// The sweep NULLs `module_executions.input_data_enc` / `output_data_enc`. That
// is IRREVERSIBLE (AEAD ciphertext, no decrypt-and-restore), so what needs
// proving is not "does it free space" but "what does it refuse to touch".
//
// Three of these tests exist because a plain age-based policy would fail them:
//
//  * `never_touches_a_non_terminal_row` — a `running` row's `input_data_enc`
//    IS the live dispatch payload.
//  * `preserves_the_whole_corpus_of_a_rarely_run_module` — the one that kills
//    the age-only design. `replay_module_regression` and
//    `generate_typed_scaffold` read `status='completed'` rows ranked by
//    `completed_at DESC NULLS LAST, started_at DESC`, with the MCP handler
//    clamping `limit` to [1, 20]. For a module that ran three times a year ago
//    and then went quiet, its ENTIRE corpus is also its oldest data. An age
//    policy nulls exactly those rows and the replay tool then reports an empty
//    corpus with no error — the same silent-disable that made r303's
//    ReplayService a no-op from the day it shipped.
//  * `a_pruned_row_is_distinguishable_from_one_that_never_had_a_payload` — on
//    the live fleet 22,370 of 36,065 rows have `output_data_enc IS NULL` and
//    never had an output. Without the tombstone a pruned row is byte-identical
//    to one of those, and every future reader inherits the ambiguity.
//
// Registered in `scripts/test-integration.sh`'s TC_TESTS list — that list is
// hand-maintained, so a binary added here and not added there runs NOWHERE.

mod test_helpers;

use std::sync::Arc;
use talos_module_executions::ModuleExecutionService;
use uuid::Uuid;

/// Seeds users/organizations/modules/actors and returns the ids the execution
/// rows need. Each call is independent so tests can share one container DB.
struct Fixture {
    pool: sqlx::PgPool,
    svc: ModuleExecutionService,
    user: Uuid,
    module: Uuid,
    actor: Uuid,
}

async fn fixture() -> Fixture {
    let pool = test_helpers::get_test_db_pool().await;
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("pr-{user}@talos.test"))
    .execute(&pool)
    .await
    .unwrap();

    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("prorg-{tag}"))
    .bind(format!("prorg-{tag}"))
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();

    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, 'a', $3)")
        .bind(actor)
        .bind(user)
        .bind(org)
        .execute(&pool)
        .await
        .unwrap();

    let module = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, wasm_bytes, capability_world, kind) \
         VALUES ($1, $2, $3, '\\x00'::bytea, 'minimal-node', 'sandbox')",
    )
    .bind(module)
    .bind(user)
    .bind(format!("prmod-{tag}"))
    .execute(&pool)
    .await
    .unwrap();

    let svc = ModuleExecutionService::new(
        pool.clone(),
        Arc::new(talos_dlp_provider::DlpService::from_env()),
    );
    Fixture {
        pool,
        svc,
        user,
        module,
        actor,
    }
}

/// Inserts a `module_executions` row `age_days` old with the given status and
/// optional payload bytes. Returns the row id.
#[allow(clippy::too_many_arguments)]
async fn seed_row(
    f: &Fixture,
    status: &str,
    age_days: i32,
    input: Option<&[u8]>,
    output: Option<&[u8]>,
) -> Uuid {
    let id = Uuid::new_v4();
    let completed_at = if status == "pending" || status == "running" {
        None
    } else {
        Some(age_days)
    };
    sqlx::query(
        "INSERT INTO module_executions \
           (id, module_id, user_id, actor_id, status, trigger_type, \
            input_data_enc, output_data_enc, payload_format, \
            started_at, completed_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, 'manual', $6, $7, 4, \
                 NOW() - make_interval(days => $8::int), \
                 CASE WHEN $9::int IS NULL THEN NULL \
                      ELSE NOW() - make_interval(days => $9::int) END, \
                 NOW() - make_interval(days => $8::int))",
    )
    .bind(id)
    .bind(f.module)
    .bind(f.user)
    .bind(f.actor)
    .bind(status)
    .bind(input)
    .bind(output)
    .bind(age_days)
    .bind(completed_at)
    .execute(&f.pool)
    .await
    .unwrap();
    id
}

/// (`input_data_enc IS NOT NULL`, `output_data_enc IS NOT NULL`,
///  `payload_pruned_at IS NOT NULL`, `pruned_input_bytes`, `pruned_output_bytes`)
async fn probe(pool: &sqlx::PgPool, id: Uuid) -> (bool, bool, bool, Option<i32>, Option<i32>) {
    sqlx::query_as(
        "SELECT input_data_enc IS NOT NULL, output_data_enc IS NOT NULL, \
                payload_pruned_at IS NOT NULL, pruned_input_bytes, pruned_output_bytes \
         FROM module_executions WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn never_touches_a_non_terminal_row() {
    let f = fixture().await;
    // Deliberately far older than any plausible retention window: age must not
    // be able to override the status guard.
    let pending = seed_row(&f, "pending", 400, Some(b"live-input"), None).await;
    let running = seed_row(&f, "running", 400, Some(b"live-input"), None).await;

    f.svc.prune_terminal_payloads(30, 50, 5000).await.unwrap();

    for id in [pending, running] {
        let (has_in, _, tombstoned, _, _) = probe(&f.pool, id).await;
        assert!(
            has_in,
            "a non-terminal row's input payload is the LIVE dispatch payload and must survive"
        );
        assert!(!tombstoned, "a non-terminal row must not be tombstoned");
    }
}

#[tokio::test]
async fn preserves_the_whole_corpus_of_a_rarely_run_module() {
    let f = fixture().await;
    // Three completed runs, all a year old, and nothing since. These are
    // simultaneously the module's OLDEST rows and its ENTIRE replay corpus.
    let mut ids = Vec::new();
    for age in [360, 365, 370] {
        ids.push(seed_row(&f, "completed", age, Some(b"in"), Some(b"out")).await);
    }

    let stats = f.svc.prune_terminal_payloads(30, 50, 5000).await.unwrap();

    for id in &ids {
        let (has_in, has_out, tombstoned, _, _) = probe(&f.pool, *id).await;
        assert!(
            has_in && has_out,
            "the replay corpus of a rarely-run module must survive retention — \
             an age-only policy fails exactly here"
        );
        assert!(!tombstoned);
    }
    assert_eq!(
        stats.pruned_rows, 0,
        "nothing in this fixture is outside the corpus"
    );
}

#[tokio::test]
async fn prunes_beyond_the_corpus_and_leaves_a_tombstone() {
    let f = fixture().await;
    // corpus_keep = 20 (the floor). Seed 25 completed rows, ages 100..124 so
    // rank tracks age: ranks 1..20 protected, 21..25 prunable.
    let mut ids = Vec::new();
    for i in 0..25 {
        ids.push(seed_row(&f, "completed", 100 + i, Some(b"input-bytes"), Some(b"out")).await);
    }

    let stats = f.svc.prune_terminal_payloads(30, 20, 5000).await.unwrap();
    assert_eq!(stats.pruned_rows, 5, "ranks 21..25 only");
    assert_eq!(stats.input_bytes_freed, 5 * "input-bytes".len() as i64);
    assert_eq!(stats.output_bytes_freed, 5 * "out".len() as i64);

    for (rank, id) in ids.iter().enumerate() {
        let (has_in, _, tombstoned, in_bytes, out_bytes) = probe(&f.pool, *id).await;
        if rank < 20 {
            assert!(has_in, "rank {} is inside the replay reach", rank + 1);
            assert!(!tombstoned);
        } else {
            assert!(!has_in, "rank {} is outside the corpus", rank + 1);
            assert!(
                tombstoned,
                "a cleared payload must always leave a tombstone"
            );
            assert_eq!(in_bytes, Some("input-bytes".len() as i32));
            assert_eq!(out_bytes, Some("out".len() as i32));
        }
    }
}

#[tokio::test]
async fn a_pruned_row_is_distinguishable_from_one_that_never_had_a_payload() {
    let f = fixture().await;
    // The #638 shape: terminal, has an input, never had an output.
    let pruned = seed_row(&f, "timeout", 200, Some(b"input-only"), None).await;
    // A terminal row that never carried any payload at all.
    let never = seed_row(&f, "cancelled", 200, None, None).await;

    f.svc.prune_terminal_payloads(30, 50, 5000).await.unwrap();

    let (has_in, has_out, tombstoned, in_bytes, out_bytes) = probe(&f.pool, pruned).await;
    assert!(!has_in && !has_out);
    assert!(tombstoned, "the pruned row must carry a tombstone");
    assert_eq!(in_bytes, Some("input-only".len() as i32));
    assert_eq!(
        out_bytes, None,
        "an output that never existed must not be reported as pruned bytes"
    );

    let (has_in, has_out, tombstoned, in_bytes, out_bytes) = probe(&f.pool, never).await;
    assert!(!has_in && !has_out);
    assert!(
        !tombstoned,
        "a row that never had a payload must NOT be tombstoned — otherwise a reader \
         cannot tell 'taken by policy' from 'never recorded', which is the whole \
         reason the column exists"
    );
    assert_eq!(in_bytes, None);
    assert_eq!(out_bytes, None);
}

#[tokio::test]
async fn the_sweep_is_idempotent() {
    let f = fixture().await;
    for i in 0..25 {
        seed_row(&f, "completed", 100 + i, Some(b"payload"), None).await;
    }

    let first = f.svc.prune_terminal_payloads(30, 20, 5000).await.unwrap();
    assert_eq!(first.pruned_rows, 5);

    let second = f.svc.prune_terminal_payloads(30, 20, 5000).await.unwrap();
    assert_eq!(
        second.pruned_rows, 0,
        "a second sweep must find nothing — the tombstone excludes the row"
    );
    assert_eq!(second.input_bytes_freed, 0);
}

#[tokio::test]
async fn refuses_a_nonpositive_retention_window() {
    let f = fixture().await;
    let id = seed_row(&f, "completed", 500, Some(b"payload"), None).await;

    for days in [0, -1] {
        let stats = f.svc.prune_terminal_payloads(days, 50, 5000).await.unwrap();
        assert_eq!(
            stats.pruned_rows, 0,
            "retention_days={days} must be refused, not substituted — the predicate \
             would become `created_at < NOW()` and prune every terminal row"
        );
    }
    let (has_in, _, tombstoned, _, _) = probe(&f.pool, id).await;
    assert!(has_in && !tombstoned);
}

#[tokio::test]
async fn corpus_keep_is_clamped_up_to_the_replay_reach() {
    let f = fixture().await;
    // 25 completed rows; ask to keep only 1. The clamp must raise that to
    // REPLAY_REACH (20), because keeping fewer than the readers can reach is
    // asking for a silently-empty replay corpus by configuration.
    let mut ids = Vec::new();
    for i in 0..25 {
        ids.push(seed_row(&f, "completed", 100 + i, Some(b"payload"), None).await);
    }

    let stats = f.svc.prune_terminal_payloads(30, 1, 5000).await.unwrap();
    assert_eq!(
        stats.pruned_rows,
        5,
        "corpus_keep=1 must behave as corpus_keep={}",
        ModuleExecutionService::REPLAY_REACH
    );

    let (has_in, _, _, _, _) = probe(&f.pool, ids[19]).await;
    assert!(has_in, "rank 20 sits exactly on the reach and must survive");
}
