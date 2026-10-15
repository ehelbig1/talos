//! A quota is read and written for a named organization, or the caller's own
//! personal one — never "the first org" (security review 2026-10-14, A-9).
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use controller::api::schema::{IsTwoFactorVerified, SecondFactorVerified};
use uuid::Uuid;

fn session(user: Uuid, query: &str) -> async_graphql::Request {
    async_graphql::Request::new(query.to_string())
        .data(user)
        .data(IsTwoFactorVerified(true))
        .data(SecondFactorVerified(false))
}

#[tokio::test]
async fn a_quota_is_for_the_named_org_or_the_callers_personal_one() {
    let ctx = common::setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let owner = common::create_test_user(&ctx.auth_service, "quota-owner@example.com").await;
    let viewer = common::create_test_user(&ctx.auth_service, "quota-viewer@example.com").await;
    let stranger = common::create_test_user(&ctx.auth_service, "quota-stranger@example.com").await;
    let shared = talos_organizations::OrganizationService::create_org(
        &pool,
        "Quota team",
        &format!("quota-{}", Uuid::new_v4().simple()),
        owner,
    )
    .await
    .expect("org")
    .id;
    talos_organizations::OrganizationService::add_member(
        &pool,
        shared,
        viewer,
        talos_organizations::OrgRole::Viewer,
        owner,
    )
    .await
    .expect("viewer");
    let set = |org: Uuid| {
        format!(
            r#"mutation {{ updateResourceQuotas(orgId: "{org}", input: {{cpuCores: 7}}) {{ cpuCores }} }}"#
        )
    };
    let read = |org: Uuid| format!(r#"{{ resourceQuotas(orgId: "{org}") {{ cpuCores }} }}"#);

    // The owner (an Admin) sets the shared org's quota; a Viewer reads it but
    // cannot set it; a stranger does neither.
    let resp = ctx.schema.execute(session(owner, &set(shared))).await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    let resp = ctx.schema.execute(session(viewer, &read(shared))).await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    assert_eq!(
        resp.data.into_json().unwrap()["resourceQuotas"]["cpuCores"],
        7
    );
    assert!(!ctx
        .schema
        .execute(session(viewer, &set(shared)))
        .await
        .errors
        .is_empty());
    assert!(!ctx
        .schema
        .execute(session(stranger, &read(shared)))
        .await
        .errors
        .is_empty());

    // Omitted, it is the caller's personal org — not the shared one, which
    // the viewer's first membership might be.
    let resp = ctx
        .schema
        .execute(session(viewer, "{ resourceQuotas { cpuCores } }"))
        .await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    assert_ne!(
        resp.data.into_json().unwrap()["resourceQuotas"]["cpuCores"],
        7
    );
}
