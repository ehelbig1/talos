//! The write-ceiling ENFORCEMENT POSTURE must survive the round trip from a
//! worker's registration to an operator-facing answer — over a real database.
//!
//! # What this binary exists to catch, and why the unit tests cannot
//!
//! `summarize_write_ceiling_enforcement` is pure and thoroughly covered in
//! `talos-worker-identity-repository`, and the worker's body shape is covered
//! in `worker::self_register`. Neither can see the parts BETWEEN them:
//!
//! * whether the registration write actually persists the two bits (a column
//!   missing from the INSERT compiles fine and reports NULL forever — the
//!   `unreported` state, which reads as an honest "unknown" and would
//!   therefore never look like a bug);
//! * whether they come back UNSWAPPED through the `list_active_builds`
//!   projection (both are `Option<bool>`, so a transposition is invisible to
//!   the type system and to any symmetric fixture);
//! * whether a RE-registration overwrites a previous claim, including back to
//!   NULL — the rule that stops a stale claim standing as if it were current;
//! * whether a fleet assembled from real rows produces the state an operator
//!   is shown.
//!
//! Every fixture here is deliberately ASYMMETRIC (`enforced != strict_egress`)
//! for the same reason: a `true`/`true` row proves nothing about ordering.
//!
//! Registered in `scripts/test-integration.sh`'s CTRL_TESTS (it uses the
//! `common` DATABASE_URL harness, not a testcontainer — sub-leg 64b).

mod common;

use talos_worker_identity_repository::{
    summarize_write_ceiling_enforcement, FleetWriteCeilingState as S, WorkerIdentityRepository,
    WriteCeilingReport,
};

fn key(n: u8) -> [u8; 32] {
    let sk = talos_workflow_job_protocol::DispatchSigningKey::from_bytes(&[n; 32]);
    sk.verifying_key().to_bytes()
}

/// Only THIS worker's rows, so the assertions do not depend on what else the
/// isolated database happens to hold.
async fn rows_for(
    repo: &WorkerIdentityRepository,
    wid: &str,
) -> Vec<talos_worker_identity_repository::WorkerBuildRow> {
    repo.list_active_builds()
        .await
        .expect("list_active_builds")
        .into_iter()
        .filter(|r| r.worker_id == wid)
        .collect()
}

/// The posture a worker reports at registration must come back byte-for-byte
/// through the projection — not merely "present", but the right bit in the
/// right field.
#[tokio::test]
async fn a_reported_posture_round_trips_unswapped() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = WorkerIdentityRepository::new(pool.clone());
    let wid = "wc-roundtrip";

    repo.register(
        wid,
        &key(11),
        false,
        Some("0.1.0+aaaaaaa"),
        // ASYMMETRIC on purpose: a swap is only detectable when the two
        // differ, and a swap is exactly what a pair of Option<bool> invites.
        WriteCeilingReport {
            enforced: Some(true),
            strict_egress: Some(false),
        },
    )
    .await
    .expect("register");

    let rows = rows_for(&repo, wid).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].write_ceiling_enforced,
        Some(true),
        "enforced must survive the write and the projection"
    );
    assert_eq!(
        rows[0].write_ceiling_strict_egress,
        Some(false),
        "strict_egress must not pick up the enforced value"
    );

    let s = summarize_write_ceiling_enforcement(&rows);
    assert_eq!(s.state, S::All);
    assert_eq!(s.enforcing, 1);
    assert_eq!(
        s.strict_egress_effective, 0,
        "strict egress is off on this worker, so it is not effective"
    );
    assert!(!s.state.ceiling_is_advisory());
}

/// The opposite assignment must produce the opposite row. Without this, a
/// projection that hard-wired one column would pass the test above.
#[tokio::test]
async fn the_inverse_posture_round_trips_too() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = WorkerIdentityRepository::new(pool.clone());
    let wid = "wc-inverse";

    repo.register(
        wid,
        &key(12),
        false,
        None,
        WriteCeilingReport {
            enforced: Some(false),
            strict_egress: Some(true),
        },
    )
    .await
    .expect("register");

    let rows = rows_for(&repo, wid).await;
    assert_eq!(rows[0].write_ceiling_enforced, Some(false));
    assert_eq!(rows[0].write_ceiling_strict_egress, Some(true));

    let s = summarize_write_ceiling_enforcement(&rows);
    assert_eq!(s.state, S::None, "every row reported, and reported off");
    assert_eq!(
        s.strict_egress_effective, 0,
        "strict egress is inert while enforcement is off — it must not be \
         counted effective just because its own bit is set"
    );
    assert!(s.state.ceiling_is_advisory());
}

/// A worker that never reports leaves NULL, and NULL must summarise as
/// UNKNOWN — never as `none`.
///
/// This is the state every row on a pre-upgrade deployment is in, and the
/// tempting wrong answer ("nobody reports enforcement, so nothing enforces")
/// is precisely the unmeasured claim this feature exists to stop.
#[tokio::test]
async fn an_unreported_row_is_unknown_not_not_enforcing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = WorkerIdentityRepository::new(pool.clone());
    let wid = "wc-silent";

    // `default()` is what the operator CLI passes — it cannot know a pod's env.
    repo.register(wid, &key(13), false, None, WriteCeilingReport::default())
        .await
        .expect("register");

    let rows = rows_for(&repo, wid).await;
    assert_eq!(rows[0].write_ceiling_enforced, None);

    let s = summarize_write_ceiling_enforcement(&rows);
    assert_eq!(s.state, S::Unknown);
    assert_eq!(s.unreported, 1);
    assert_eq!(
        s.not_enforcing, 0,
        "unreported must never be counted as off"
    );
    assert!(s.state.ceiling_is_advisory());
}

/// A RE-registration overwrites the previous claim UNCONDITIONALLY, including
/// back to NULL.
///
/// The column means "what the LATEST registration reported". Preserving a
/// previous value across a silent re-registration — the shape a naive
/// `COALESCE(EXCLUDED.x, worker_identities.x)` would produce — would leave a
/// worker that has since had enforcement turned OFF still reporting it ON,
/// which is the one direction of staleness that misleads toward safety.
#[tokio::test]
async fn re_registration_overwrites_the_claim_including_back_to_null() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = WorkerIdentityRepository::new(pool.clone());
    let wid = "wc-rereg";
    let pk = key(14);

    repo.register(
        wid,
        &pk,
        false,
        None,
        WriteCeilingReport {
            enforced: Some(true),
            strict_egress: Some(true),
        },
    )
    .await
    .expect("first register");
    assert_eq!(
        rows_for(&repo, wid).await[0].write_ceiling_enforced,
        Some(true)
    );

    // Operator turned the flag off and restarted the worker.
    repo.register(
        wid,
        &pk,
        false,
        None,
        WriteCeilingReport {
            enforced: Some(false),
            strict_egress: Some(false),
        },
    )
    .await
    .expect("second register");
    let rows = rows_for(&repo, wid).await;
    assert_eq!(rows.len(), 1, "same key must refresh, not add a row");
    assert_eq!(
        rows[0].write_ceiling_enforced,
        Some(false),
        "a stale ON claim must not survive a re-registration reporting OFF"
    );

    // And a downgrade to a worker that reports nothing must clear it rather
    // than leaving the last known answer standing as current.
    repo.register(wid, &pk, false, None, WriteCeilingReport::default())
        .await
        .expect("third register");
    assert_eq!(
        rows_for(&repo, wid).await[0].write_ceiling_enforced,
        None,
        "an unreporting registration must clear the column, not inherit it"
    );
}

/// The TOFU path — the one a self-registering worker actually takes — persists
/// the posture on both of its arms (first-use insert and idempotent refresh).
///
/// `register` and `register_tofu` are separate SQL statements, so covering one
/// says nothing about the other; the network path is the one that matters most
/// here because it is the only path a real worker uses.
#[tokio::test]
async fn the_tofu_network_path_persists_the_posture_on_both_arms() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = WorkerIdentityRepository::new(pool.clone());
    let wid = "wc-tofu";
    let pk = key(15);

    // First use — INSERT arm.
    repo.register_tofu(
        wid,
        &pk,
        false,
        Some("0.1.0+aaaaaaa"),
        WriteCeilingReport {
            enforced: Some(true),
            strict_egress: Some(false),
        },
    )
    .await
    .expect("tofu first use");
    let rows = rows_for(&repo, wid).await;
    assert_eq!(rows[0].write_ceiling_enforced, Some(true));
    assert_eq!(rows[0].write_ceiling_strict_egress, Some(false));

    // Reboot with strict egress newly enabled — UPDATE arm.
    repo.register_tofu(
        wid,
        &pk,
        false,
        Some("0.1.0+aaaaaaa"),
        WriteCeilingReport {
            enforced: Some(true),
            strict_egress: Some(true),
        },
    )
    .await
    .expect("tofu refresh");
    let rows = rows_for(&repo, wid).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].write_ceiling_strict_egress,
        Some(true),
        "the refresh arm must write the posture, not only the build"
    );
    assert_eq!(
        summarize_write_ceiling_enforcement(&rows).strict_egress_effective,
        1
    );
}

/// THE DANGEROUS FLEET. Two workers, one enforcing and one not, assembled from
/// real rows: the answer must be `some`, and it must be ADVISORY.
///
/// Nothing routes jobs by enforcement posture, so a `readonly` actor's job may
/// land on either worker. An answer of `all` here — or a non-advisory `some` —
/// would tell an operator a ceiling is load-bearing when it is a coin flip.
#[tokio::test]
async fn a_mixed_fleet_reports_some_and_stays_advisory() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = WorkerIdentityRepository::new(pool.clone());

    repo.register(
        "wc-mixed-on",
        &key(16),
        false,
        None,
        WriteCeilingReport {
            enforced: Some(true),
            strict_egress: Some(true),
        },
    )
    .await
    .expect("register on");
    repo.register(
        "wc-mixed-off",
        &key(17),
        false,
        None,
        WriteCeilingReport {
            enforced: Some(false),
            strict_egress: Some(false),
        },
    )
    .await
    .expect("register off");

    let all = repo.list_active_builds().await.expect("list");
    let mine: Vec<_> = all
        .into_iter()
        .filter(|r| r.worker_id.starts_with("wc-mixed-"))
        .collect();
    assert_eq!(mine.len(), 2);

    let s = summarize_write_ceiling_enforcement(&mine);
    assert_eq!(s.state, S::Some);
    assert_eq!((s.enforcing, s.not_enforcing, s.unreported), (1, 1, 0));
    assert!(
        s.state.ceiling_is_advisory(),
        "a mixed fleet must never read as enforced"
    );
    assert!(s.note().contains("ADVISORY IN PART"));

    // And the rendering an operator actually sees carries the composition, not
    // just the verdict.
    let j = talos_worker_identity_repository::render_write_ceiling_enforcement(Some(s));
    assert_eq!(j["enforced_by"], "some");
    assert_eq!(j["enforcing"], 1);
    assert_eq!(j["registered_rows"], 2);
}

/// A DEACTIVATED worker drops out of the fleet answer entirely.
///
/// `list_active_builds` filters on `active`, so a reaped or rotated-out worker
/// must not keep contributing an enforcement claim — otherwise a fleet could
/// read `all` on the strength of a worker that is gone.
#[tokio::test]
async fn a_deactivated_worker_stops_contributing_its_claim() {
    let (pool, _db) = common::isolated_db_pool().await;
    let repo = WorkerIdentityRepository::new(pool.clone());
    let wid = "wc-reaped";
    let pk = key(18);

    repo.register(
        wid,
        &pk,
        false,
        None,
        WriteCeilingReport {
            enforced: Some(true),
            strict_egress: Some(false),
        },
    )
    .await
    .expect("register");
    assert_eq!(rows_for(&repo, wid).await.len(), 1);

    assert!(repo.deactivate(wid, &pk).await.expect("deactivate"));
    assert!(
        rows_for(&repo, wid).await.is_empty(),
        "a deactivated identity must not keep asserting that it enforces"
    );
}
