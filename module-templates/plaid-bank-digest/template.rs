// Canonical catalog module: one connected bank (a Plaid Item) reduced to what
// a weekly money summary needs. Read-only: POSTs to Plaid's read endpoints
// (`/transactions/get`, and `/accounts/get` when transactions cannot be read);
// nothing is written anywhere and nothing is stored between runs.
//
// The module never holds a credential. The three Plaid credentials travel in
// the JSON request body as `vault://` references, which the host replaces at
// the socket: the app's `client_id` and `secret` are built here from fixed
// paths, and the bank's access token is the reference in ACCESS_TOKEN.
//
// What leaves this module is a digest, not the statement: balances, weekly
// totals, the week's five largest items and the charges that repeat monthly.
// Account numbers and their last digits are not carried.
//
// Plaid signs money OUT as a positive amount. Every sum here keeps that sign
// until the output, where spending is positive and income is positive.

use chrono::{Duration, NaiveDate, Utc};
use serde::Deserialize;
use std::collections::BTreeMap;
use talos::core::datetime;
use talos_sdk_macros::talos_module;

/// Transactions asked for per request (Plaid's maximum).
const PAGE: usize = 500;
/// The most requests one run makes for transactions.
const MAX_PAGES: usize = 10;
const DEFAULT_WEEKS: i64 = 13;
const MIN_WEEKS: i64 = 4;
const MAX_WEEKS: i64 = 26;
/// Characters of a bank-supplied name kept.
const LABEL_CHARS: usize = 40;
/// Last week's largest items listed.
const LARGEST: usize = 5;
const RECURRING_MAX: usize = 30;
const NEW_RECURRING_MAX: usize = 10;
/// Days between two charges of one monthly series.
const MONTHLY_MIN_DAYS: i64 = 26;
const MONTHLY_MAX_DAYS: i64 = 35;
/// A series whose last charge is older than this has stopped.
const ACTIVE_WITHIN_DAYS: i64 = 40;

const CLIENT_ID_REF: &str = "vault://plaid/client_id";
const SECRET_REF: &str = "vault://plaid/secret";
const TOKEN_REF_PREFIX: &str = "vault://plaid/access_token/";

// ------------------------------------------------------------ wire shapes
// Every field is optional: a missing or null field must not discard the page.

#[derive(Deserialize, Default)]
struct TxPage {
    #[serde(default)]
    accounts: Vec<Account>,
    #[serde(default)]
    transactions: Vec<Tx>,
    total_transactions: Option<usize>,
}
#[derive(Deserialize, Default)]
struct AccountsPage {
    #[serde(default)]
    accounts: Vec<Account>,
}
#[derive(Deserialize, Default)]
struct Account {
    name: Option<String>,
    official_name: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    subtype: Option<String>,
    balances: Option<Balances>,
}
#[derive(Deserialize, Default)]
struct Balances {
    available: Option<f64>,
    current: Option<f64>,
    limit: Option<f64>,
    iso_currency_code: Option<String>,
}
#[derive(Deserialize, Default)]
struct Tx {
    amount: Option<f64>,
    date: Option<String>,
    name: Option<String>,
    merchant_name: Option<String>,
    pending: Option<bool>,
    iso_currency_code: Option<String>,
    personal_finance_category: Option<Category>,
}
#[derive(Deserialize, Default)]
struct Category {
    primary: Option<String>,
    detailed: Option<String>,
}
#[derive(Deserialize, Default)]
struct PlaidError {
    error_type: Option<String>,
    error_code: Option<String>,
}

// ----------------------------------------------------------------- helpers

/// Whole cents, or `None` for a value that is not a finite number.
fn cents(amount: f64) -> Option<i64> {
    let c = (amount * 100.0).round();
    (c.is_finite() && c.abs() < 9.0e15).then_some(c as i64)
}
fn dollars(c: i64) -> f64 {
    c as f64 / 100.0
}
/// A bank-supplied label: printable, trimmed, bounded.
fn clip(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect::<String>().trim().to_string()
}
fn ident(s: Option<&str>) -> String {
    s.unwrap_or("").chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(48).collect::<String>().to_ascii_uppercase()
}

/// Where a transaction counts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    /// Money moved between accounts, or a payment to a credit card whose
    /// purchases are already counted. Left out of spending and income.
    Transfer,
    Income,
    /// Housing, utilities and loan payments.
    Fixed,
    DayToDay,
    /// Money in with no category: not known to be income or a refund.
    UnknownInflow,
}

fn classify(primary: &str, detailed: &str, amount_cents: i64) -> Class {
    match primary {
        "TRANSFER_IN" | "TRANSFER_OUT" => Class::Transfer,
        "LOAN_PAYMENTS" if detailed == "LOAN_PAYMENTS_CREDIT_CARD_PAYMENT" => Class::Transfer,
        "INCOME" => Class::Income,
        "RENT_AND_UTILITIES" | "LOAN_PAYMENTS" => Class::Fixed,
        "" if amount_cents < 0 => Class::UnknownInflow,
        _ => Class::DayToDay,
    }
}

/// The words of a merchant label that stay the same from one charge to the
/// next: lower-cased, and any word carrying a digit (a store or order number)
/// dropped. Empty when nothing is left.
fn merchant_key(label: &str) -> String {
    label
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty() && !w.chars().any(|c| c.is_ascii_digit()))
        .take(5)
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

struct Charge {
    key: String,
    label: String,
    category: String,
    cents: i64,
    date: NaiveDate,
}

/// Charges of one merchant at one price, a month apart.
struct Series {
    label: String,
    category: String,
    cents: i64,
    first: NaiveDate,
    last: NaiveDate,
    charges: usize,
}

/// Two amounts are one price when they differ by at most 5% (or 50 cents).
fn same_price(base: i64, other: i64) -> bool {
    (other - base).abs() <= (base / 20).max(50)
}

/// The monthly series among one merchant's charges, plus every charge
/// `(date, cents)` so a price change can be told from a new charge.
fn monthly_series(mut charges: Vec<&Charge>) -> Vec<Series> {
    charges.sort_by_key(|c| (c.cents, c.date));
    let mut out = Vec::new();
    let mut i = 0;
    while i < charges.len() {
        let base = charges[i].cents;
        let mut j = i + 1;
        while j < charges.len() && same_price(base, charges[j].cents) {
            j += 1;
        }
        let mut group: Vec<&Charge> = charges[i..j].to_vec();
        i = j;
        group.sort_by_key(|c| c.date);
        // Two charges on one day are one occurrence.
        group.dedup_by_key(|c| c.date);
        if group.len() < 2 {
            continue;
        }
        let monthly = group.windows(2).all(|w| {
            let gap = (w[1].date - w[0].date).num_days();
            (MONTHLY_MIN_DAYS..=MONTHLY_MAX_DAYS).contains(&gap)
        });
        if !monthly {
            continue;
        }
        let latest = group[group.len() - 1];
        out.push(Series {
            label: latest.label.clone(),
            category: latest.category.clone(),
            cents: latest.cents,
            first: group[0].date,
            last: latest.date,
            charges: group.len(),
        });
    }
    out
}

// --------------------------------------------------------------- requests

/// One POST: the path and the JSON body in, the status and the body out.
type Post<'a> = dyn FnMut(&str, &serde_json::Value) -> Result<(u16, Vec<u8>), String> + 'a;

/// Plaid's own codes for a refusal. The body is discarded: it can repeat
/// request fields.
fn refusal(status: u16, body: &[u8]) -> (String, String) {
    let e: PlaidError = serde_json::from_slice(body).unwrap_or_default();
    let code = ident(e.error_code.as_deref());
    let kind = ident(e.error_type.as_deref());
    let text = if code.is_empty() { format!("Plaid {status}") } else { format!("Plaid {status}: {kind} / {code}") };
    (code, text)
}

/// What the owner can do about a refusal, when there is something.
fn hint(code: &str) -> &'static str {
    match code {
        "ITEM_LOGIN_REQUIRED" | "PENDING_EXPIRATION" | "PENDING_DISCONNECT" | "ITEM_NOT_FOUND" | "ACCESS_NOT_GRANTED" | "INVALID_ACCESS_TOKEN" => {
            " (the bank connection has to be made again in Settings)"
        }
        "PRODUCT_NOT_READY" => " (the bank's history is still being loaded; it is usually ready within minutes of connecting)",
        "INVALID_API_KEYS" => " (the Plaid app credentials in the vault do not match PLAID_ENV)",
        _ => "",
    }
}

struct Clock {
    today: NaiveDate,
}

struct Settings {
    host: &'static str,
    environment: &'static str,
    token_ref: String,
    institution: String,
    zone: String,
    weeks: i64,
}

fn account_json(a: &Account) -> serde_json::Value {
    let b = a.balances.as_ref();
    let name = a.name.as_deref().filter(|n| !n.trim().is_empty()).or(a.official_name.as_deref()).unwrap_or("Account");
    serde_json::json!({
        "name": clip(name, LABEL_CHARS),
        "type": ident(a.kind.as_deref()).to_ascii_lowercase(),
        "subtype": a.subtype.as_deref().map(|s| clip(s, LABEL_CHARS)),
        "current": b.and_then(|b| b.current).and_then(cents).map(dollars),
        "available": b.and_then(|b| b.available).and_then(cents).map(dollars),
        "limit": b.and_then(|b| b.limit).and_then(cents).map(dollars),
        "currency": b.and_then(|b| b.iso_currency_code.as_deref()).map(|c| ident(Some(c))),
    })
}

/// The sum of one kind of balance over the accounts of one type: the total of
/// the balances that could be read, and how many could not. `None` when there
/// is no account of the type, or none could be read: an unread balance is
/// unknown, never zero.
fn total(accounts: &[Account], kind: &str, pick: fn(&Balances) -> Option<f64>) -> (Option<i64>, usize) {
    let (mut sum, mut read, mut unread) = (0i64, 0usize, 0usize);
    for a in accounts.iter().filter(|a| a.kind.as_deref().is_some_and(|k| k.eq_ignore_ascii_case(kind))) {
        match a.balances.as_ref().and_then(pick).and_then(cents) {
            Some(c) => {
                sum = sum.saturating_add(c);
                read += 1;
            }
            None => unread += 1,
        }
    }
    ((read > 0).then_some(sum), unread)
}

#[derive(Default, Clone)]
struct Week {
    day_to_day: i64,
    fixed: i64,
    income: i64,
    count: usize,
}

fn digest_transactions(txs: &[Tx], today: NaiveDate, weeks: i64, currency: &str, truncated: bool) -> serde_json::Value {
    let n = weeks as usize;
    let mut week: Vec<Week> = vec![Week::default(); n];
    let mut by_category: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    let mut charges: Vec<Charge> = Vec::new();
    let mut largest: Vec<(i64, NaiveDate, String, String, bool)> = Vec::new();
    let (mut pending, mut other_currency, mut unreadable, mut outside) = (0usize, 0usize, 0usize, 0usize);
    let (mut transfers_out, mut transfers_in, mut unknown_in) = (0i64, 0i64, 0i64);

    for t in txs {
        let (Some(c), Some(date)) =
            (t.amount.and_then(cents), t.date.as_deref().and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok()))
        else {
            unreadable += 1;
            continue;
        };
        if t.iso_currency_code.as_deref().is_some_and(|x| !x.eq_ignore_ascii_case(currency)) {
            other_currency += 1;
            continue;
        }
        let back = (today - date).num_days();
        if back < 1 || back > weeks * 7 {
            outside += 1;
            continue;
        }
        let w = ((back - 1) / 7) as usize;
        let is_pending = t.pending.unwrap_or(false);
        if is_pending {
            pending += 1;
        }
        let cat = t.personal_finance_category.as_ref();
        let primary = ident(cat.and_then(|c| c.primary.as_deref()));
        let detailed = ident(cat.and_then(|c| c.detailed.as_deref()));
        let label_src = t.merchant_name.as_deref().filter(|m| !m.trim().is_empty()).or(t.name.as_deref()).unwrap_or("");
        let label = clip(label_src, LABEL_CHARS);
        let class = classify(&primary, &detailed, c);
        week[w].count += 1;
        match class {
            Class::Transfer => {
                if w == 0 {
                    if c > 0 {
                        transfers_out += c;
                    } else {
                        transfers_in -= c;
                    }
                }
            }
            Class::UnknownInflow => {
                if w == 0 {
                    unknown_in -= c;
                }
            }
            Class::Income => week[w].income -= c,
            Class::Fixed | Class::DayToDay => {
                if class == Class::Fixed {
                    week[w].fixed += c;
                } else {
                    week[w].day_to_day += c;
                }
                let name = if primary.is_empty() { "UNCATEGORIZED".to_string() } else { primary.clone() };
                by_category.entry(name.clone()).or_insert_with(|| vec![0; n])[w] += c;
                if c > 0 {
                    if w == 0 {
                        largest.push((c, date, label.clone(), name.clone(), is_pending));
                    }
                    let key = merchant_key(label_src);
                    if !key.is_empty() {
                        charges.push(Charge { key, label: label.clone(), category: name, cents: c, date });
                    }
                }
            }
        }
    }

    // Monthly charges, merchant by merchant.
    let mut by_merchant: BTreeMap<&str, Vec<&Charge>> = BTreeMap::new();
    for c in &charges {
        by_merchant.entry(c.key.as_str()).or_default().push(c);
    }
    let mut recurring: Vec<Series> = Vec::new();
    let mut new_recurring: Vec<serde_json::Value> = Vec::new();
    for group in by_merchant.values() {
        for s in monthly_series(group.clone()) {
            if (today - s.last).num_days() > ACTIVE_WITHIN_DAYS {
                continue;
            }
            // Seen for the second time during the last week: this is the week
            // it became recognisable as a monthly charge.
            if s.charges == 2 && (1..=7).contains(&(today - s.last).num_days()) {
                // A charge from the same merchant at another price a month
                // before the first one makes it a price change.
                let previous = group
                    .iter()
                    .filter(|c| !same_price(s.cents, c.cents))
                    .filter(|c| (MONTHLY_MIN_DAYS..=MONTHLY_MAX_DAYS).contains(&(s.first - c.date).num_days()))
                    .max_by_key(|c| c.date)
                    .map(|c| c.cents);
                new_recurring.push(serde_json::json!({
                    "kind": if previous.is_some() { "price_change" } else { "new" },
                    "merchant": s.label,
                    "amount": dollars(s.cents),
                    "previous_amount": previous.map(dollars),
                    "first_date": s.first.to_string(),
                    "last_date": s.last.to_string(),
                }));
            }
            recurring.push(s);
        }
    }
    recurring.sort_by(|a, b| b.cents.cmp(&a.cents).then_with(|| a.label.cmp(&b.label)));
    let recurring_total: i64 = recurring.iter().map(|s| s.cents).sum();
    let recurring_count = recurring.len();
    let recurring_json: Vec<serde_json::Value> = recurring
        .iter()
        .take(RECURRING_MAX)
        .map(|s| {
            serde_json::json!({
                "merchant": s.label, "amount": dollars(s.cents), "category": s.category,
                "last_date": s.last.to_string(), "charges": s.charges,
            })
        })
        .collect();
    new_recurring.truncate(NEW_RECURRING_MAX);

    largest.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)).then_with(|| a.2.cmp(&b.2)));
    let largest_json: Vec<serde_json::Value> = largest
        .iter()
        .take(LARGEST)
        .map(|(c, d, label, cat, p)| {
            serde_json::json!({ "date": d.to_string(), "name": label, "amount": dollars(*c), "category": cat, "pending": p })
        })
        .collect();

    let weeks_json: Vec<serde_json::Value> = week
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let end = today - Duration::days(1 + 7 * i as i64);
            serde_json::json!({
                "start": (end - Duration::days(6)).to_string(), "end": end.to_string(),
                "day_to_day": dollars(w.day_to_day), "fixed": dollars(w.fixed), "income": dollars(w.income), "count": w.count,
            })
        })
        .collect();
    let categories: BTreeMap<String, Vec<f64>> =
        by_category.into_iter().filter(|(_, v)| v.iter().any(|c| *c != 0)).map(|(k, v)| (k, v.into_iter().map(dollars).collect())).collect();

    serde_json::json!({
        "read": txs.len(),
        "truncated": truncated,
        "pending": pending,
        "left_out": { "other_currency": other_currency, "unreadable": unreadable, "outside_window": outside },
        "weeks": weeks_json,
        "by_category": categories,
        "last_week": {
            "largest": largest_json,
            "transfers_out": dollars(transfers_out),
            "transfers_in": dollars(transfers_in),
            "uncategorized_in": dollars(unknown_in),
        },
        "recurring": recurring_json,
        "recurring_count": recurring_count,
        "recurring_monthly_total": dollars(recurring_total),
        "new_recurring": new_recurring,
    })
}

fn gather(clock: &Clock, s: &Settings, post: &mut Post<'_>) -> Result<String, String> {
    let today = clock.today;
    let (start, end) = (today - Duration::days(s.weeks * 7), today - Duration::days(1));
    let credentials = |extra: serde_json::Value| -> serde_json::Value {
        let mut body = serde_json::json!({ "client_id": CLIENT_ID_REF, "secret": SECRET_REF, "access_token": s.token_ref });
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                b.insert(k.clone(), v.clone());
            }
        }
        body
    };
    let page_body = |offset: usize| {
        credentials(serde_json::json!({
            "start_date": start.to_string(), "end_date": end.to_string(),
            "options": { "count": PAGE, "offset": offset },
        }))
    };

    let mut unavailable: Vec<serde_json::Value> = Vec::new();
    let accounts: Vec<Account>;
    let mut txs: Vec<Tx> = Vec::new();
    let mut have_transactions = false;
    let mut truncated = false;

    // The first page also carries the accounts and their balances.
    let (status, body) = post("/transactions/get", &page_body(0))?;
    if (200..300).contains(&status) {
        let first: TxPage = serde_json::from_slice(&body).map_err(|e| format!("Plaid /transactions/get answered something that could not be read: {e}"))?;
        accounts = first.accounts;
        let total = first.total_transactions.unwrap_or(first.transactions.len());
        txs = first.transactions;
        have_transactions = true;
        let mut pages = 1;
        while txs.len() < total {
            if pages >= MAX_PAGES {
                truncated = true;
                break;
            }
            // A later page that cannot be read makes the whole reading
            // unavailable: totals over the pages that did arrive would be
            // presented as the full window.
            let next = match post("/transactions/get", &page_body(txs.len())) {
                Ok((st, b)) if (200..300).contains(&st) => serde_json::from_slice::<TxPage>(&b).map_err(|e| format!("page {} could not be read: {e}", pages + 1)),
                Ok((st, b)) => Err(refusal(st, &b).1),
                Err(e) => Err(clip(&e, 200)),
            };
            match next {
                Ok(p) if p.transactions.is_empty() => break,
                Ok(p) => txs.extend(p.transactions),
                Err(reason) => {
                    unavailable.push(serde_json::json!({ "what": "transactions", "reason": reason }));
                    have_transactions = false;
                    break;
                }
            }
            pages += 1;
        }
    } else {
        // Transactions refused (not loaded yet, sign-in expired…): the
        // balances may still be readable.
        let (code, text) = refusal(status, &body);
        let (st2, body2) = post("/accounts/get", &credentials(serde_json::json!({})))?;
        if !(200..300).contains(&st2) {
            let (code2, text2) = refusal(st2, &body2);
            return Err(format!("{text2}{}", hint(&code2)));
        }
        let page: AccountsPage =
            serde_json::from_slice(&body2).map_err(|e| format!("Plaid /accounts/get answered something that could not be read: {e}"))?;
        accounts = page.accounts;
        unavailable.push(serde_json::json!({ "what": "transactions", "code": code, "reason": format!("{text}{}", hint(&code)) }));
    }

    // The currency most accounts are held in; other currencies are not added
    // to it.
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for a in &accounts {
        if let Some(c) = a.balances.as_ref().and_then(|b| b.iso_currency_code.as_deref()) {
            *seen.entry(ident(Some(c))).or_default() += 1;
        }
    }
    let currency = seen.into_iter().max_by_key(|(_, n)| *n).map(|(c, _)| c).unwrap_or_else(|| "USD".to_string());
    let in_currency: Vec<Account> = accounts
        .into_iter()
        .filter(|a| !a.balances.as_ref().and_then(|b| b.iso_currency_code.as_deref()).is_some_and(|c| !c.eq_ignore_ascii_case(&currency)))
        .collect();

    // Cash is what can be spent: the available balance, else the current one.
    let (cash, cash_unread) = total(&in_currency, "depository", |b| b.available.or(b.current));
    let (owed, owed_unread) = total(&in_currency, "credit", |b| b.current);
    let (loans, _) = total(&in_currency, "loan", |b| b.current);
    let (invested, _) = total(&in_currency, "investment", |b| b.current);

    let transactions = have_transactions.then(|| digest_transactions(&txs, today, s.weeks, &currency, truncated));
    serde_json::to_string(&serde_json::json!({
        "kind": "bank_digest",
        "institution": s.institution,
        "environment": s.environment,
        "as_of": today.to_string(),
        "time_zone": s.zone,
        "currency": currency,
        "window": { "start": start.to_string(), "end": end.to_string(), "weeks": s.weeks },
        "accounts": in_currency.iter().map(account_json).collect::<Vec<_>>(),
        "cash": cash.map(dollars),
        "cash_unread_accounts": cash_unread,
        "owed_on_cards": owed.map(dollars),
        "cards_unread_accounts": owed_unread,
        "loans": loans.map(dollars),
        "invested": invested.map(dollars),
        "transactions": transactions,
        "unavailable": unavailable,
    }))
    .map_err(|e| e.to_string())
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(rename = "PLAID_ENV")]
    plaid_env: Option<String>,
    #[serde(rename = "ACCESS_TOKEN")]
    access_token: Option<String>,
    #[serde(rename = "INSTITUTION")]
    institution: Option<String>,
    #[serde(rename = "TIME_ZONE")]
    time_zone: Option<String>,
    #[serde(rename = "WEEKS")]
    weeks: Option<i64>,
    #[serde(rename = "TODAY")]
    today: Option<String>,
}
#[derive(Deserialize, Default)]
struct Input {
    #[serde(default)]
    config: Config,
}

/// The access-token reference: exactly `vault://plaid/access_token/<item>`.
/// Anything else is refused, above all a token pasted into the config, which
/// would be stored in the workflow and sent as written.
fn token_reference(raw: Option<&str>) -> Result<String, String> {
    let r = raw.map(str::trim).unwrap_or("");
    let item = r.strip_prefix(TOKEN_REF_PREFIX).unwrap_or("");
    let shaped = !item.is_empty() && item.len() <= 128 && item.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if shaped {
        Ok(r.to_string())
    } else {
        Err("ACCESS_TOKEN must be the vault reference of one connected bank: vault://plaid/access_token/{item_id}. Never put the token itself in the config.".to_string())
    }
}

fn settings(c: &Config) -> Result<Settings, String> {
    let (host, environment) = match c.plaid_env.as_deref().map(str::trim) {
        Some("production") => ("production.plaid.com", "production"),
        Some("sandbox") => ("sandbox.plaid.com", "sandbox"),
        _ => return Err("PLAID_ENV must be 'production' or 'sandbox' (the environment the bank was connected in)".to_string()),
    };
    let zone = c.time_zone.as_deref().map(str::trim).filter(|z| !z.is_empty()).unwrap_or("UTC");
    if zone.len() > 64 || !zone.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '-' | '+')) {
        return Err("TIME_ZONE must be an IANA zone name such as America/New_York".to_string());
    }
    Ok(Settings {
        host,
        environment,
        token_ref: token_reference(c.access_token.as_deref())?,
        institution: clip(c.institution.as_deref().unwrap_or("Bank"), LABEL_CHARS),
        zone: zone.to_string(),
        weeks: c.weeks.unwrap_or(DEFAULT_WEEKS).clamp(MIN_WEEKS, MAX_WEEKS),
    })
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: Input = serde_json::from_str(&input).map_err(|e| format!("plaid-bank-digest input: {e}"))?;
    let s = settings(&data.config)?;
    let today = match data.config.today.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => NaiveDate::parse_from_str(t, "%Y-%m-%d").map_err(|_| "TODAY must be a date written YYYY-MM-DD".to_string())?,
        None => {
            let now = Utc::now();
            let at = u64::try_from(now.timestamp()).map_err(|_| "the clock reads a time before 1970".to_string())?;
            let offset = datetime::local_offset_seconds(&s.zone, at).map(i64::from).map_err(|_| {
                format!("TIME_ZONE '{}' is not a time zone the host knows; use an IANA name such as America/New_York (case-sensitive)", s.zone)
            })?;
            (now + Duration::seconds(offset)).date_naive()
        }
    };

    let host = s.host;
    let mut post = |path: &str, body: &serde_json::Value| -> Result<(u16, Vec<u8>), String> {
        let req = talos::core::http::Request {
            method: talos::core::http::Method::Post,
            url: format!("https://{host}{path}"),
            // The JSON content type is what lets the host replace the
            // vault:// references in the body; without it the request is
            // refused rather than sent as written.
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Accept".to_string(), "application/json".to_string()),
            ],
            body: serde_json::to_vec(body).map_err(|e| e.to_string())?,
            timeout_ms: Some(30000),
        };
        talos::core::http::fetch(&req).map(|r| (r.status, r.body)).map_err(|e| format!("Plaid {path} failed: {e:?}"))
    };
    gather(&Clock { today }, &s, &mut post)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }
    /// Sunday. Last week is Sep 27 – Oct 3.
    const TODAY: &str = "2026-10-04";
    fn cfg() -> Settings {
        settings(&Config {
            plaid_env: Some("production".into()),
            access_token: Some("vault://plaid/access_token/item-1".into()),
            institution: Some("Test Bank".into()),
            time_zone: Some("America/New_York".into()),
            weeks: Some(13),
            today: None,
        })
        .unwrap()
    }
    fn tx(date: &str, amount: f64, name: &str, primary: &str) -> Value {
        json!({"transaction_id": format!("{date}-{name}-{amount}"), "account_id": "a1", "amount": amount, "date": date, "name": name,
               "merchant_name": name, "pending": false, "iso_currency_code": "USD",
               "personal_finance_category": {"primary": primary, "detailed": format!("{primary}_OTHER")}})
    }
    fn accounts() -> Value {
        json!([
            {"account_id": "a1", "name": "Everyday Checking", "mask": "1234", "type": "depository", "subtype": "checking",
             "balances": {"available": 4100.25, "current": 4300.0, "iso_currency_code": "USD"}},
            {"account_id": "a2", "name": "Savings", "mask": "9876", "type": "depository", "subtype": "savings",
             "balances": {"available": null, "current": 12000.0, "iso_currency_code": "USD"}},
            {"account_id": "a3", "name": "Rewards Card", "type": "credit", "subtype": "credit card",
             "balances": {"available": 7200.0, "current": 812.4, "limit": 8000.0, "iso_currency_code": "USD"}}
        ])
    }
    /// Answers `/transactions/get` from `txs` by the offset asked for, in
    /// pages of `page`, and records every request.
    fn bank(txs: Vec<Value>, page: usize, seen: &std::cell::RefCell<Vec<(String, Value)>>) -> impl FnMut(&str, &Value) -> Result<(u16, Vec<u8>), String> + '_ {
        move |path: &str, body: &Value| {
            seen.borrow_mut().push((path.to_string(), body.clone()));
            assert_eq!(path, "/transactions/get");
            let offset = body["options"]["offset"].as_u64().unwrap() as usize;
            let slice: Vec<Value> = txs.iter().skip(offset).take(page).cloned().collect();
            Ok((200, json!({"accounts": accounts(), "transactions": slice, "total_transactions": txs.len()}).to_string().into_bytes()))
        }
    }
    fn run_with(txs: Vec<Value>) -> Value {
        let seen = std::cell::RefCell::new(Vec::new());
        let mut post = bank(txs, 500, &seen);
        serde_json::from_str(&gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap()).unwrap()
    }

    #[test]
    fn the_request_carries_references_and_never_a_credential() {
        let seen = std::cell::RefCell::new(Vec::new());
        {
            let mut post = bank(vec![], 500, &seen);
            gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap();
        }
        let (path, body) = seen.borrow()[0].clone();
        assert_eq!(path, "/transactions/get");
        assert_eq!(body["client_id"], "vault://plaid/client_id");
        assert_eq!(body["secret"], "vault://plaid/secret");
        assert_eq!(body["access_token"], "vault://plaid/access_token/item-1");
        // 13 weeks ending yesterday.
        assert_eq!((body["start_date"].as_str(), body["end_date"].as_str()), (Some("2026-07-05"), Some("2026-10-03")));
        assert_eq!(body["options"]["count"], 500);
    }

    #[test]
    fn a_token_in_the_config_is_refused() {
        for bad in [None, Some(""), Some("access-production-1b2c"), Some("vault://plaid/secret"), Some("vault://plaid/access_token/"),
                    Some("vault://plaid/access_token/a/b"), Some("Bearer vault://plaid/access_token/item-1"), Some("vault://plaid/access_token/item 1")] {
            assert!(token_reference(bad).is_err(), "{bad:?}");
        }
        assert_eq!(token_reference(Some(" vault://plaid/access_token/Ab_9-x ")).unwrap(), "vault://plaid/access_token/Ab_9-x");
        let mut c = Config { access_token: Some("vault://plaid/access_token/i".into()), ..Config::default() };
        assert!(settings(&c).is_err(), "no environment is not a default");
        c.plaid_env = Some("development".into());
        assert!(settings(&c).is_err());
        c.plaid_env = Some("sandbox".into());
        assert_eq!(settings(&c).unwrap().host, "sandbox.plaid.com");
    }

    #[test]
    fn balances_are_summed_by_kind_and_an_unread_one_is_not_zero() {
        let out = run_with(vec![]);
        // Checking's available balance and savings' current one (no available).
        assert_eq!(out["cash"], 16100.25);
        assert_eq!(out["owed_on_cards"], 812.4);
        assert_eq!(out["loans"], Value::Null, "no loan account is unknown, not 0");
        assert_eq!(out["accounts"].as_array().unwrap().len(), 3);
        assert!(out.to_string().find("1234").is_none(), "the account's last digits are not carried");

        let mut post = |_: &str, _: &Value| {
            Ok((200, json!({"accounts": [{"name": "Checking", "type": "depository", "balances": {"available": null, "current": null}}],
                             "transactions": [], "total_transactions": 0}).to_string().into_bytes()))
        };
        let out: Value = serde_json::from_str(&gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap()).unwrap();
        assert_eq!(out["cash"], Value::Null);
        assert_eq!(out["cash_unread_accounts"], 1);
    }

    #[test]
    fn weeks_count_back_from_yesterday_and_transfers_are_left_out() {
        let out = run_with(vec![
            tx("2026-10-03", 40.0, "Grocer", "FOOD_AND_DRINK"),      // last week (Sat)
            tx("2026-09-27", 60.0, "Grocer", "FOOD_AND_DRINK"),      // last week (Sun)
            tx("2026-09-26", 25.0, "Cafe", "FOOD_AND_DRINK"),        // the week before
            tx("2026-10-04", 999.0, "Today", "GENERAL_MERCHANDISE"), // today: outside
            tx("2026-10-01", 1500.0, "Landlord", "RENT_AND_UTILITIES"),
            tx("2026-10-01", -2500.0, "Employer", "INCOME"),
            tx("2026-10-02", 800.0, "To savings", "TRANSFER_OUT"),
            tx("2026-10-02", -800.0, "From checking", "TRANSFER_IN"),
            tx("2026-09-30", -10.0, "Grocer", "FOOD_AND_DRINK"),     // a refund nets against spending
            json!({"amount": 300.0, "date": "2026-10-02", "name": "Card payment",
                   "personal_finance_category": {"primary": "LOAN_PAYMENTS", "detailed": "LOAN_PAYMENTS_CREDIT_CARD_PAYMENT"}}),
            json!({"amount": 12.0, "date": "2026-10-02", "name": "Euro shop", "iso_currency_code": "EUR"}),
        ]);
        let t = &out["transactions"];
        let w0 = &t["weeks"][0];
        assert_eq!((w0["start"].as_str(), w0["end"].as_str()), (Some("2026-09-27"), Some("2026-10-03")));
        assert_eq!(w0["day_to_day"], 90.0, "40 + 60 - 10");
        assert_eq!(w0["fixed"], 1500.0);
        assert_eq!(w0["income"], 2500.0);
        assert_eq!(t["weeks"][1]["day_to_day"], 25.0);
        assert_eq!(t["weeks"].as_array().unwrap().len(), 13);
        assert_eq!(t["last_week"]["transfers_out"], 1100.0, "the transfer and the card payment");
        assert_eq!(t["last_week"]["transfers_in"], 800.0);
        assert_eq!(t["left_out"]["other_currency"], 1);
        assert_eq!(t["left_out"]["outside_window"], 1);
        assert_eq!(t["by_category"]["FOOD_AND_DRINK"][0], 90.0);
        assert_eq!(t["last_week"]["largest"][0]["name"], "Landlord");
    }

    #[test]
    fn a_row_with_no_amount_is_counted_not_fatal() {
        let out = run_with(vec![json!({"date": "2026-10-02", "name": "No amount"}), tx("2026-10-02", 5.0, "Cafe", "FOOD_AND_DRINK")]);
        assert_eq!(out["transactions"]["left_out"]["unreadable"], 1);
        assert_eq!(out["transactions"]["weeks"][0]["day_to_day"], 5.0);
    }

    #[test]
    fn every_page_is_read_and_the_cap_is_reported() {
        let many: Vec<Value> = (0..7).map(|i| tx("2026-10-01", 1.0, &format!("Shop {i}"), "GENERAL_MERCHANDISE")).collect();
        let seen = std::cell::RefCell::new(Vec::new());
        let out: Value = {
            let mut post = bank(many.clone(), 3, &seen);
            serde_json::from_str(&gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap()).unwrap()
        };
        let offsets: Vec<u64> = seen.borrow().iter().map(|(_, b)| b["options"]["offset"].as_u64().unwrap()).collect();
        assert_eq!(offsets, vec![0, 3, 6]);
        assert_eq!(out["transactions"]["weeks"][0]["day_to_day"], 7.0);
        assert_eq!(out["transactions"]["truncated"], false);

        // More pages than the cap: said, not hidden.
        let lots: Vec<Value> = (0..(MAX_PAGES + 2)).map(|i| tx("2026-10-01", 1.0, &format!("Shop {i}"), "GENERAL_MERCHANDISE")).collect();
        let seen = std::cell::RefCell::new(Vec::new());
        let mut post = bank(lots, 1, &seen);
        let out: Value = serde_json::from_str(&gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap()).unwrap();
        assert_eq!(out["transactions"]["truncated"], true);
        assert_eq!(out["transactions"]["read"], MAX_PAGES);
    }

    #[test]
    fn a_later_page_that_fails_makes_transactions_unavailable_and_keeps_balances() {
        let mut post = |_: &str, body: &Value| {
            if body["options"]["offset"] == 0 {
                Ok((200, json!({"accounts": accounts(), "transactions": [tx("2026-10-01", 9.0, "Shop", "GENERAL_MERCHANDISE")], "total_transactions": 2}).to_string().into_bytes()))
            } else {
                Ok((500, json!({"error_type": "API_ERROR", "error_code": "INTERNAL_SERVER_ERROR"}).to_string().into_bytes()))
            }
        };
        let out: Value = serde_json::from_str(&gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap()).unwrap();
        assert_eq!(out["transactions"], Value::Null, "a partial window is not presented as the window");
        assert_eq!(out["cash"], 16100.25);
        assert_eq!(out["unavailable"][0]["what"], "transactions");
    }

    #[test]
    fn refused_transactions_fall_back_to_balances_and_a_refused_bank_is_an_error() {
        let mut post = |path: &str, _: &Value| {
            Ok(if path == "/transactions/get" {
                (400, json!({"error_type": "ITEM_ERROR", "error_code": "PRODUCT_NOT_READY", "error_message": "secret echo"}).to_string().into_bytes())
            } else {
                (200, json!({"accounts": accounts()}).to_string().into_bytes())
            })
        };
        let out: Value = serde_json::from_str(&gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap()).unwrap();
        assert_eq!(out["cash"], 16100.25);
        assert_eq!(out["transactions"], Value::Null);
        assert_eq!(out["unavailable"][0]["code"], "PRODUCT_NOT_READY");
        assert!(!out.to_string().contains("secret echo"), "Plaid's message text is not carried");

        let mut post = |_: &str, _: &Value| Ok((400, json!({"error_type": "ITEM_ERROR", "error_code": "ITEM_LOGIN_REQUIRED"}).to_string().into_bytes()));
        let err = gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap_err();
        assert!(err.contains("ITEM_LOGIN_REQUIRED") && err.contains("made again in Settings"), "{err}");

        let mut post = |_: &str, _: &Value| Err("Plaid /transactions/get failed: Timeout".to_string());
        assert!(gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap_err().contains("Timeout"));
    }

    #[test]
    fn a_monthly_charge_is_found_and_is_new_only_the_week_of_its_second_charge() {
        let out = run_with(vec![
            // Three months of a subscription: recurring, not new.
            tx("2026-07-20", 15.49, "Streamflix", "ENTERTAINMENT"),
            tx("2026-08-20", 15.49, "Streamflix", "ENTERTAINMENT"),
            tx("2026-09-20", 15.49, "Streamflix", "ENTERTAINMENT"),
            // Second charge landed last week: new.
            tx("2026-08-30", 9.99, "Cloud Box", "GENERAL_SERVICES"),
            tx("2026-09-29", 9.99, "Cloud Box", "GENERAL_SERVICES"),
            // Same shop, varying amounts, weekly: not a series.
            tx("2026-09-12", 61.20, "Grocer", "FOOD_AND_DRINK"),
            tx("2026-09-19", 48.75, "Grocer", "FOOD_AND_DRINK"),
            tx("2026-09-26", 70.02, "Grocer", "FOOD_AND_DRINK"),
            // Stopped: last charge more than 40 days ago.
            tx("2026-07-10", 30.0, "Old Gym", "PERSONAL_CARE"),
            tx("2026-08-10", 30.0, "Old Gym", "PERSONAL_CARE"),
        ]);
        let t = &out["transactions"];
        let names: Vec<&str> = t["recurring"].as_array().unwrap().iter().map(|r| r["merchant"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["Streamflix", "Cloud Box"]);
        assert_eq!(t["recurring_monthly_total"], 25.48);
        assert_eq!(t["new_recurring"].as_array().unwrap().len(), 1);
        assert_eq!(t["new_recurring"][0]["merchant"], "Cloud Box");
        assert_eq!(t["new_recurring"][0]["kind"], "new");
    }

    #[test]
    fn a_new_price_at_the_same_merchant_is_a_price_change() {
        let out = run_with(vec![
            tx("2026-07-29", 15.49, "Streamflix", "ENTERTAINMENT"),
            tx("2026-08-29", 17.99, "Streamflix", "ENTERTAINMENT"),
            tx("2026-09-29", 17.99, "Streamflix", "ENTERTAINMENT"),
        ]);
        let n = &out["transactions"]["new_recurring"][0];
        assert_eq!((n["kind"].as_str(), n["amount"].as_f64(), n["previous_amount"].as_f64()), (Some("price_change"), Some(17.99), Some(15.49)));
    }

    #[test]
    fn merchant_keys_ignore_store_and_order_numbers() {
        assert_eq!(merchant_key("SQ *CAFE 1042"), "sq cafe");
        assert_eq!(merchant_key("Cafe #1042"), merchant_key("Cafe #77"));
        assert_eq!(merchant_key("AMZN Mktp US*2K4AB1"), "amzn mktp us");
        assert_eq!(merchant_key("12345"), "");
        assert!(same_price(1000, 1050) && !same_price(1000, 1051));
        assert!(same_price(100, 150) && !same_price(100, 151), "small amounts get 50 cents");
    }

    #[test]
    fn classes() {
        assert_eq!(classify("TRANSFER_OUT", "TRANSFER_OUT_SAVINGS", 100), Class::Transfer);
        assert_eq!(classify("LOAN_PAYMENTS", "LOAN_PAYMENTS_CREDIT_CARD_PAYMENT", 100), Class::Transfer);
        assert_eq!(classify("LOAN_PAYMENTS", "LOAN_PAYMENTS_MORTGAGE_PAYMENT", 100), Class::Fixed);
        assert_eq!(classify("INCOME", "INCOME_WAGES", -100), Class::Income);
        assert_eq!(classify("", "", -100), Class::UnknownInflow);
        assert_eq!(classify("", "", 100), Class::DayToDay);
        assert_eq!(classify("FOOD_AND_DRINK", "", -100), Class::DayToDay, "a refund nets against its category");
    }
}
