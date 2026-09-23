//! The Plaid API client.
//!
//! # Why this is controller-side and not a WASM module
//!
//! Plaid takes its `access_token` in the JSON REQUEST BODY. A Talos module
//! cannot put a secret there: `vault://` substitution resolves into HEADERS
//! only (`host::vault::resolve_vault_header`), `get_secret` hands the guest an
//! opaque handle rather than the string, and `expose_secret` is a rate-limited
//! Tier-2 opt-in that every engine dispatch path currently hardcodes to
//! `false`. That is the control working, not a gap to route around — so the
//! integration lives in the controller, like `talos-gmail`,
//! `talos-google-calendar` and `talos-google-cloud`.

use crate::config::PlaidConfig;
use std::fmt;
use std::time::Duration;

/// Plaid's documented page size for `/transactions/sync` is 500. Asking for
/// less makes more round trips; asking for more is rejected.
const SYNC_PAGE_SIZE: u32 = 500;

/// Hard ceiling on `/transactions/sync` pages in ONE call.
///
/// `has_more` is the server's word, and an unbounded `while has_more` is the
/// shape the house rules forbid: a provider bug, a pathological account, or a
/// cursor that never advances would spin forever holding a connection. At 500
/// per page this is 20 000 transactions, far past any personal account's
/// weekly delta, and the caller is TOLD when it binds rather than silently
/// receiving a truncated answer.
const MAX_SYNC_PAGES: usize = 40;

/// Per-request timeout. Plaid's transaction endpoints are slow on first sync.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// What the sync loop does after a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncStep {
    /// Plaid has more and the cursor moved: ask again.
    Continue,
    /// Plaid is done, or the cursor stopped moving.
    Done,
    /// Plaid has more but the page cap binds. The caller holds a PREFIX.
    Truncate,
}

/// The loop's termination decision, as a pure function.
///
/// Extracted because the loop body does I/O and this is the part that carries
/// the safety property: an unbounded `while has_more` is the shape the house
/// rules forbid, and "the cursor stopped advancing" is a second, independent
/// stop that a page cap alone would not provide — without it a provider
/// returning the same cursor forever would still burn all 40 pages on every
/// call.
pub(crate) const fn sync_step(
    has_more: bool,
    cursor_advanced: bool,
    pages_fetched: usize,
) -> SyncStep {
    if !has_more || !cursor_advanced {
        return SyncStep::Done;
    }
    if pages_fetched >= MAX_SYNC_PAGES {
        return SyncStep::Truncate;
    }
    SyncStep::Continue
}

/// An access token for one Plaid Item (one bank connection, one user).
///
/// Newtyped so it cannot be interchanged with a `public_token`, an `item_id`
/// or any other string, and given a redacting `Debug` for the same reason
/// `PlaidConfig` has one.
#[derive(Clone)]
pub struct AccessToken(String);

impl AccessToken {
    #[must_use]
    pub fn new(raw: String) -> Self {
        Self(raw)
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken([REDACTED])")
    }
}

/// The short-lived token the browser hands back from Plaid Link, exchanged
/// once for an [`AccessToken`]. Also redacted: it is single-use but it is
/// still a credential until it is spent.
#[derive(Clone)]
pub struct PublicToken(String);

impl PublicToken {
    #[must_use]
    pub fn new(raw: String) -> Self {
        Self(raw)
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PublicToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicToken([REDACTED])")
    }
}

/// One account on an Item. Balances are `Option` because Plaid genuinely
/// cannot always report them (a credit card's available balance, an account
/// mid-refresh) — and a missing balance must render as unknown, never as 0.00,
/// which would be a determinate negative about someone's money.
#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
pub struct Account {
    pub account_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mask: Option<String>,
    #[serde(default)]
    pub subtype: Option<String>,
    #[serde(default)]
    pub balances: Balances,
}

#[derive(Debug, Clone, Default, serde::Deserialize, PartialEq)]
pub struct Balances {
    #[serde(default)]
    pub available: Option<f64>,
    #[serde(default)]
    pub current: Option<f64>,
    #[serde(default)]
    pub iso_currency_code: Option<String>,
}

/// One transaction, narrowed to the fields a spending digest needs.
///
/// Deliberately NOT the whole Plaid payload: every field kept here is a field
/// that will be stored and possibly rendered, and the smallest set that
/// answers the question is the smallest set that can leak.
#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
pub struct Transaction {
    pub transaction_id: String,
    pub account_id: String,
    /// Plaid signs OUTflows positive and inflows negative.
    pub amount: f64,
    #[serde(default)]
    pub iso_currency_code: Option<String>,
    /// `YYYY-MM-DD`.
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub merchant_name: Option<String>,
    #[serde(default)]
    pub pending: bool,
    #[serde(default)]
    pub personal_finance_category: Option<PfCategory>,
}

#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
pub struct PfCategory {
    #[serde(default)]
    pub primary: String,
    #[serde(default)]
    pub detailed: String,
}

impl Transaction {
    /// The best human label Plaid gave us, preferring the cleaned merchant
    /// name over the raw statement descriptor.
    #[must_use]
    pub fn label(&self) -> &str {
        self.merchant_name
            .as_deref()
            .filter(|m| !m.trim().is_empty())
            .unwrap_or(&self.name)
    }

    /// True when this row moves money OUT. Plaid's sign convention is that a
    /// positive amount is a debit; getting this backwards would turn a
    /// spending report into an income report.
    #[must_use]
    pub fn is_spend(&self) -> bool {
        self.amount > 0.0
    }
}

/// The result of one `sync_transactions` call.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyncPage {
    pub added: Vec<Transaction>,
    pub modified: Vec<Transaction>,
    pub removed: Vec<String>,
    /// Store this and pass it next time. Plaid's cursor IS the durable state.
    pub next_cursor: String,
    /// True when [`MAX_SYNC_PAGES`] bound the loop before Plaid ran out of
    /// pages. The caller has a COMPLETE prefix, not a complete answer, and
    /// must say so rather than presenting a partial week as the week.
    pub truncated: bool,
    pub pages_fetched: usize,
}

#[derive(Debug, serde::Deserialize)]
struct SyncResponse {
    #[serde(default)]
    added: Vec<Transaction>,
    #[serde(default)]
    modified: Vec<Transaction>,
    #[serde(default)]
    removed: Vec<RemovedTransaction>,
    #[serde(default)]
    next_cursor: String,
    #[serde(default)]
    has_more: bool,
}

#[derive(Debug, serde::Deserialize)]
struct RemovedTransaction {
    transaction_id: String,
}

/// Plaid's `/item/public_token/exchange` reply.
///
/// Hand-written `Debug` (lint 37): `access_token` is a live credential, and a
/// derived `Debug` would put it into the first `anyhow` chain or panic message
/// that touched this struct. Caught by the structural lint, not by review.
#[derive(serde::Deserialize)]
struct ExchangeResponse {
    access_token: String,
    item_id: String,
}

impl fmt::Debug for ExchangeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeResponse")
            .field("access_token", &"[REDACTED]")
            .field("item_id", &self.item_id)
            .finish()
    }
}

#[derive(Debug, serde::Deserialize)]
struct AccountsResponse {
    #[serde(default)]
    accounts: Vec<Account>,
}

/// Plaid's error envelope. Carried so a failure names the provider's own
/// error code, which is what an operator needs, WITHOUT echoing the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaidApiError {
    pub status: u16,
    pub error_type: String,
    pub error_code: String,
}

impl fmt::Display for PlaidApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Plaid returned {} ({}/{})",
            self.status, self.error_type, self.error_code
        )
    }
}

impl PlaidApiError {
    /// True when the Item needs the user to re-authenticate in Link. This is
    /// the one failure a digest must report to a human rather than retry —
    /// no amount of retrying fixes a revoked bank login.
    #[must_use]
    pub fn needs_reauth(&self) -> bool {
        self.error_code == "ITEM_LOGIN_REQUIRED"
            || self.error_code == "ITEM_LOCKED"
            || self.error_type == "ITEM_ERROR" && self.error_code == "ACCESS_NOT_GRANTED"
    }
}

pub struct PlaidClient {
    http: reqwest::Client,
    config: PlaidConfig,
}

impl fmt::Debug for PlaidClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegates to PlaidConfig's redacting Debug rather than adding a
        // second place a secret could be printed from.
        f.debug_struct("PlaidClient")
            .field("config", &self.config)
            .finish()
    }
}

impl PlaidClient {
    /// Build against a fixed, known host, so the hardened integration client
    /// is the right tool (lint 49). No SSRF resolver is needed because no part
    /// of the URL is caller-supplied.
    #[must_use]
    pub fn new(config: PlaidConfig) -> Self {
        Self {
            http: talos_http_utils::trusted_client::build_integration_client(REQUEST_TIMEOUT),
            config,
        }
    }

    #[must_use]
    pub fn config(&self) -> &PlaidConfig {
        &self.config
    }

    /// POST a Plaid endpoint with the app credentials folded into the body,
    /// reading the response through the capped reader (lint 31).
    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        mut body: serde_json::Value,
    ) -> anyhow::Result<T> {
        // Credentials go in LAST so a caller-supplied body cannot overwrite
        // them, and they are never logged.
        if let Some(obj) = body.as_object_mut() {
            obj.insert("client_id".into(), self.config.client_id.clone().into());
            obj.insert("secret".into(), self.config.secret().to_string().into());
        }
        let url = format!("{}{path}", self.config.env.host());
        let resp = self.http.post(&url).json(&body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            // Read the error body CAPPED, and surface only Plaid's own codes.
            // The raw body can echo request fields, so it is parsed for the
            // two codes and otherwise discarded.
            let text = talos_http_body::read_error_text_capped(resp).await;
            let parsed: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            let err = PlaidApiError {
                status: status.as_u16(),
                error_type: parsed["error_type"]
                    .as_str()
                    .unwrap_or("UNKNOWN")
                    .to_string(),
                error_code: parsed["error_code"]
                    .as_str()
                    .unwrap_or("UNKNOWN")
                    .to_string(),
            };
            tracing::warn!(
                target: "talos_plaid",
                event_kind = "plaid_api_error",
                endpoint = path,
                status = err.status,
                error_type = %err.error_type,
                error_code = %err.error_code,
                needs_reauth = err.needs_reauth(),
                "Plaid request failed"
            );
            return Err(anyhow::anyhow!(err));
        }
        talos_http_body::read_json_capped(resp).await
    }

    /// Exchange the browser's short-lived `public_token` for the long-lived
    /// access token and its item id.
    pub async fn exchange_public_token(
        &self,
        public: &PublicToken,
    ) -> anyhow::Result<(AccessToken, String)> {
        let r: ExchangeResponse = self
            .post(
                "/item/public_token/exchange",
                serde_json::json!({ "public_token": public.as_str() }),
            )
            .await?;
        // Log that an exchange happened and for which ITEM — never the token.
        tracing::info!(
            target: "talos_plaid",
            event_kind = "plaid_item_linked",
            item_id = %r.item_id,
            env = self.config.env.as_str(),
            "exchanged a Plaid public token for an access token"
        );
        Ok((AccessToken::new(r.access_token), r.item_id))
    }

    pub async fn accounts(&self, token: &AccessToken) -> anyhow::Result<Vec<Account>> {
        let r: AccountsResponse = self
            .post(
                "/accounts/get",
                serde_json::json!({ "access_token": token.as_str() }),
            )
            .await?;
        Ok(r.accounts)
    }

    /// Pull every transaction change since `cursor`, bounded.
    ///
    /// Pass `None` on the first call for this Item; afterwards pass the
    /// `next_cursor` from the previous [`SyncPage`]. The cursor is the durable
    /// state — losing it means re-reading the account's whole history.
    pub async fn sync_transactions(
        &self,
        token: &AccessToken,
        cursor: Option<&str>,
    ) -> anyhow::Result<SyncPage> {
        let mut page = SyncPage {
            next_cursor: cursor.unwrap_or_default().to_string(),
            ..Default::default()
        };

        loop {
            let mut body = serde_json::json!({
                "access_token": token.as_str(),
                "count": SYNC_PAGE_SIZE,
            });
            if !page.next_cursor.is_empty() {
                body["cursor"] = page.next_cursor.clone().into();
            }
            let r: SyncResponse = self.post("/transactions/sync", body).await?;

            page.added.extend(r.added);
            page.modified.extend(r.modified);
            page.removed
                .extend(r.removed.into_iter().map(|x| x.transaction_id));
            page.pages_fetched += 1;

            // A cursor that does not advance would loop forever even under
            // the page cap's ceiling; treat it as the end rather than
            // re-requesting the same page.
            let advanced = r.next_cursor != page.next_cursor;
            page.next_cursor = r.next_cursor;

            match sync_step(r.has_more, advanced, page.pages_fetched) {
                SyncStep::Done => break,
                SyncStep::Truncate => {
                    page.truncated = true;
                    tracing::warn!(
                        target: "talos_plaid",
                        event_kind = "plaid_sync_truncated",
                        pages = page.pages_fetched,
                        added = page.added.len(),
                        "transaction sync hit its page cap; the caller has a prefix, not the whole delta"
                    );
                    break;
                }
                SyncStep::Continue => {}
            }
        }
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PlaidEnv;

    #[test]
    fn tokens_never_render_their_value() {
        let a = AccessToken::new("access-sandbox-abc123".into());
        let p = PublicToken::new("public-sandbox-xyz789".into());
        assert!(!format!("{a:?}").contains("abc123"), "{a:?}");
        assert!(!format!("{p:?}").contains("xyz789"), "{p:?}");
        assert_eq!(a.as_str(), "access-sandbox-abc123");
        assert_eq!(p.as_str(), "public-sandbox-xyz789");
    }

    #[test]
    fn the_client_debug_cannot_print_the_secret() {
        let c = PlaidClient::new(PlaidConfig::new(
            "id".into(),
            "super-secret".into(),
            PlaidEnv::Sandbox,
        ));
        let d = format!("{c:?}");
        assert!(!d.contains("super-secret"), "{d}");
        assert!(d.contains("[REDACTED]"));
    }

    #[test]
    fn a_merchant_name_beats_the_raw_descriptor_but_blank_does_not() {
        let base = Transaction {
            transaction_id: "t1".into(),
            account_id: "a1".into(),
            amount: 12.0,
            iso_currency_code: Some("USD".into()),
            date: "2026-09-20".into(),
            name: "SQ *COFFEE 1234".into(),
            merchant_name: Some("Coffee Shop".into()),
            pending: false,
            personal_finance_category: None,
        };
        assert_eq!(base.label(), "Coffee Shop");

        let blank = Transaction {
            merchant_name: Some("   ".into()),
            ..base.clone()
        };
        assert_eq!(
            blank.label(),
            "SQ *COFFEE 1234",
            "a blank merchant name must fall back, not render empty"
        );

        let none = Transaction {
            merchant_name: None,
            ..base
        };
        assert_eq!(none.label(), "SQ *COFFEE 1234");
    }

    /// Plaid signs outflows POSITIVE. Getting this backwards turns a spending
    /// report into an income report, so it is pinned rather than assumed.
    #[test]
    fn a_positive_amount_is_money_going_out() {
        let t = |amount: f64| Transaction {
            transaction_id: "t".into(),
            account_id: "a".into(),
            amount,
            iso_currency_code: None,
            date: "2026-09-20".into(),
            name: "x".into(),
            merchant_name: None,
            pending: false,
            personal_finance_category: None,
        };
        assert!(t(42.0).is_spend(), "a positive amount is a debit in Plaid");
        assert!(!t(-42.0).is_spend(), "a negative amount is money coming in");
        assert!(!t(0.0).is_spend());
    }

    /// A balance Plaid could not report must stay unknown. Rendering 0.00 for
    /// an unreadable balance is a determinate negative about someone's money.
    #[test]
    fn an_absent_balance_is_none_and_not_zero() {
        let a: Account =
            serde_json::from_value(serde_json::json!({ "account_id": "a1", "name": "Checking" }))
                .expect("minimal account parses");
        assert_eq!(a.balances.available, None);
        assert_eq!(a.balances.current, None);
        assert_ne!(a.balances.current, Some(0.0));
    }

    #[test]
    fn a_login_required_item_is_flagged_for_reauth_and_others_are_not() {
        let e = |code: &str, ty: &str| PlaidApiError {
            status: 400,
            error_type: ty.into(),
            error_code: code.into(),
        };
        assert!(e("ITEM_LOGIN_REQUIRED", "ITEM_ERROR").needs_reauth());
        assert!(e("ITEM_LOCKED", "ITEM_ERROR").needs_reauth());
        assert!(
            !e("RATE_LIMIT_EXCEEDED", "RATE_LIMIT_ERROR").needs_reauth(),
            "a rate limit is retryable; calling it re-auth sends the user to reconnect a working bank"
        );
        assert!(!e("INTERNAL_SERVER_ERROR", "API_ERROR").needs_reauth());
    }

    #[test]
    fn the_error_display_names_the_provider_code_and_no_request_detail() {
        let msg = PlaidApiError {
            status: 400,
            error_type: "ITEM_ERROR".into(),
            error_code: "ITEM_LOGIN_REQUIRED".into(),
        }
        .to_string();
        assert!(msg.contains("ITEM_LOGIN_REQUIRED"));
        assert!(msg.contains("400"));
    }

    /// Compile-time pins rather than a test (package DO's decision): these
    /// are constants, so a violated bound should fail the BUILD rather than a
    /// test run, and clippy rejects a runtime assertion over a constant.
    const _: () = assert!(SYNC_PAGE_SIZE == 500, "Plaid rejects a larger count");
    const _: () = assert!(MAX_SYNC_PAGES >= 10, "too small to complete a first sync");
    const _: () = assert!(
        MAX_SYNC_PAGES <= 100,
        "an effectively unbounded cap is the defect the cap exists to prevent"
    );

    /// `truncated` must default FALSE, so a page that never hit the cap does
    /// not claim to be partial — and must be the only way a caller learns it
    /// got a prefix.
    #[test]
    fn a_fresh_sync_page_does_not_claim_truncation() {
        let p = SyncPage::default();
        assert!(!p.truncated);
        assert_eq!(p.pages_fetched, 0);
        assert!(p.added.is_empty());
    }
}

#[cfg(test)]
mod sync_loop_tests {
    use super::{sync_step, SyncStep, MAX_SYNC_PAGES};

    /// The ordinary case: Plaid says there is more and the cursor moved.
    #[test]
    fn more_pages_with_an_advancing_cursor_continues() {
        assert_eq!(sync_step(true, true, 1), SyncStep::Continue);
        assert_eq!(
            sync_step(true, true, MAX_SYNC_PAGES - 1),
            SyncStep::Continue
        );
    }

    #[test]
    fn no_more_pages_is_done_whatever_the_cursor_did() {
        assert_eq!(sync_step(false, true, 1), SyncStep::Done);
        assert_eq!(sync_step(false, false, 1), SyncStep::Done);
    }

    /// The second, INDEPENDENT stop. A provider that keeps saying `has_more`
    /// while returning the same cursor would otherwise re-request the same
    /// page until the cap — doing 40 round trips on every single sync and
    /// reporting `truncated` on an account with nothing left to fetch.
    #[test]
    fn a_cursor_that_stops_advancing_is_done_not_truncated() {
        assert_eq!(
            sync_step(true, false, 1),
            SyncStep::Done,
            "a stalled cursor must END the loop, not burn pages against it"
        );
        assert_eq!(
            sync_step(true, false, MAX_SYNC_PAGES),
            SyncStep::Done,
            "a stalled cursor is Done even AT the cap — it is not a truncation, \
             because there was nothing more to fetch"
        );
    }

    /// The cap binds only when Plaid genuinely has more AND is still moving.
    #[test]
    fn the_cap_truncates_only_a_genuinely_unfinished_sync() {
        assert_eq!(sync_step(true, true, MAX_SYNC_PAGES), SyncStep::Truncate);
        assert_eq!(
            sync_step(true, true, MAX_SYNC_PAGES + 1),
            SyncStep::Truncate
        );
    }

    /// The property the whole extraction exists for: from any state, the loop
    /// reaches a terminal step in a bounded number of iterations. Driven as a
    /// simulation so "bounded" is demonstrated rather than asserted.
    #[test]
    fn the_loop_always_terminates_within_the_cap() {
        for stalls_after in [0usize, 1, 7, MAX_SYNC_PAGES * 2] {
            let mut pages = 0usize;
            loop {
                pages += 1;
                // A provider that always claims more, and stops advancing the
                // cursor after `stalls_after` pages.
                let advanced = pages < stalls_after;
                match sync_step(true, advanced, pages) {
                    SyncStep::Continue => {}
                    SyncStep::Done | SyncStep::Truncate => break,
                }
                assert!(
                    pages <= MAX_SYNC_PAGES,
                    "the loop ran past its cap with stalls_after={stalls_after}"
                );
            }
            assert!(
                pages <= MAX_SYNC_PAGES + 1,
                "termination took {pages} pages with stalls_after={stalls_after}"
            );
        }
    }
}
