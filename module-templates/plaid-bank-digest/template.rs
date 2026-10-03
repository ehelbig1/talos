// Canonical catalog module: one connected bank (a Plaid Item) reduced to what
// a weekly money summary needs. Read-only: one POST to Plaid's
// `/transactions/get` (and one to `/accounts/get` when transactions cannot be
// read); nothing is written anywhere and nothing is stored between runs.
//
// The module never holds a credential. The three Plaid credentials travel in
// the JSON request body as `vault://` references, which the host replaces at
// the socket: the app's `client_id` and `secret` are built here from fixed
// paths, and the bank's access token is the reference in ACCESS_TOKEN.
//
// What leaves this module is a digest, not the statement: balances, weekly
// totals, the week's five largest day-to-day items and the charges that
// repeat monthly. Banks put account digits inside names ("CHECKING ...1234",
// "AUTO PAY XXXXXXX5678"), so any word of a name carrying four or more digits
// is dropped before the name is returned.
//
// The work is bounded: the newest MAX_ROWS transactions are read in one
// request. A bank with more than that in the window is reported `truncated`
// and only the weeks that were read whole are counted.
//
// Plaid signs money OUT as a positive amount. Every sum here keeps that sign
// until the output, where spending is positive and income is positive.

use chrono::{Duration, NaiveDate, Utc};
use serde::Deserialize;
use std::collections::BTreeMap;
use talos::core::datetime;
use talos_sdk_macros::talos_module;

/// Transactions read, newest first. Reading one costs about 130,000 fuel
/// (measured on live responses of about 2 KB each), so this many fit inside
/// the engine's 50 M ceiling with room to spare.
const MAX_ROWS: usize = 300;
/// Fourteen weeks always hold three charges of a monthly subscription.
const DEFAULT_WEEKS: i64 = 14;
const MIN_WEEKS: i64 = 4;
const MAX_WEEKS: i64 = 26;
/// Characters of a bank-supplied name kept.
const LABEL_CHARS: usize = 40;
/// Last week's largest day-to-day items listed.
const LARGEST: usize = 5;
const RECURRING_MAX: usize = 30;
const NEW_RECURRING_MAX: usize = 10;
/// Days between two charges of one monthly series.
const MONTHLY_MIN_DAYS: i64 = 26;
const MONTHLY_MAX_DAYS: i64 = 35;
/// A series whose last charge is older than this has stopped.
const ACTIVE_WITHIN_DAYS: i64 = 40;
/// Charges in a row before a series is listed as a monthly charge. Two equal
/// purchases a month apart are common by chance; three are not.
const CONFIRMED_CHARGES: usize = 3;
/// A new monthly charge smaller than this is not worth a line.
const NEW_RECURRING_MIN_CENTS: i64 = 100;

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
/// `YYYY-MM-DD`, read without a format parser.
fn parse_ymd(s: &str) -> Option<NaiveDate> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        b[r].iter().try_fold(0u32, |acc, d| d.is_ascii_digit().then(|| acc * 10 + u32::from(d - b'0')))
    };
    NaiveDate::from_ymd_opt(i32::try_from(num(0..4)?).ok()?, num(5..7)?, num(8..10)?)
}
/// Plain text, bounded: control characters and the replacement character
/// (what a bank's mis-encoded symbol arrives as) are removed.
fn clip(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control() && *c != '\u{fffd}').take(max).collect::<String>().trim().to_string()
}
/// A bank-supplied name as it may be shown: any word carrying four or more
/// digits (an account number, a masked one, a reference, a date stamp) is
/// dropped, then the name is cleaned and bounded.
fn display_name(s: &str) -> String {
    let kept: Vec<&str> = s.split_whitespace().filter(|w| w.chars().filter(char::is_ascii_digit).count() < 4).collect();
    clip(&kept.join(" "), LABEL_CHARS)
}
/// An identifier as Plaid writes them (`FOOD_AND_DRINK`, `USD`), bounded.
fn ident(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(48).collect::<String>().to_ascii_uppercase()
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
    let mut out = String::with_capacity(label.len());
    let mut words = 0;
    for w in label.split(|c: char| !c.is_alphanumeric()) {
        if w.is_empty() || w.bytes().any(|b| b.is_ascii_digit()) {
            continue;
        }
        if words > 0 {
            out.push(' ');
        }
        out.extend(w.chars().flat_map(char::to_lowercase));
        words += 1;
        if words == 5 {
            break;
        }
    }
    out
}

/// One spending transaction, as far as finding monthly charges needs it.
struct Charge<'a> {
    key: String,
    label: &'a str,
    category: &'a str,
    cents: i64,
    date: NaiveDate,
}

/// Charges of one merchant at one price, a month apart.
struct Series<'a> {
    label: &'a str,
    category: &'a str,
    cents: i64,
    first: NaiveDate,
    last: NaiveDate,
    charges: usize,
    /// Every charge of the series, as (date, cents).
    members: Vec<(NaiveDate, i64)>,
}

/// Two amounts are one price when they differ by at most 5% (or 50 cents).
fn same_price(base: i64, other: i64) -> bool {
    (other - base).abs() <= (base / 20).max(50)
}

/// The monthly series among one merchant's charges.
fn monthly_series<'a>(mut charges: Vec<&'a Charge<'a>>) -> Vec<Series<'a>> {
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
        let members: Vec<(NaiveDate, i64)> = group.iter().map(|c| (c.date, c.cents)).collect();
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
        out.push(Series { label: latest.label, category: latest.category, cents: latest.cents, first: group[0].date, last: latest.date, charges: group.len(), members });
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
    let code = ident(e.error_code.as_deref().unwrap_or(""));
    let kind = ident(e.error_type.as_deref().unwrap_or(""));
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
    let name = a.name.as_deref().filter(|n| !n.trim().is_empty()).or(a.official_name.as_deref()).unwrap_or("");
    let shown = display_name(name);
    serde_json::json!({
        "name": if shown.is_empty() { "Account".to_string() } else { shown },
        "type": ident(a.kind.as_deref().unwrap_or("")).to_ascii_lowercase(),
        "subtype": a.subtype.as_deref().map(|s| clip(s, LABEL_CHARS)),
        "current": b.and_then(|b| b.current).and_then(cents).map(dollars),
        "available": b.and_then(|b| b.available).and_then(cents).map(dollars),
        "limit": b.and_then(|b| b.limit).and_then(cents).map(dollars),
        "currency": b.and_then(|b| b.iso_currency_code.as_deref()).map(ident),
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
    /// The part of `day_to_day + fixed` that is a monthly charge. A month's
    /// spending is the monthly charges once plus the rest averaged by week;
    /// averaging the monthly ones by week would count a window that happens
    /// to hold four rent payments as more than three months of rent.
    recurring: i64,
    count: usize,
}

/// How many of the `weeks` asked for were read whole, given that the rows
/// (newest first) stop at `oldest`: a week counts only when it begins after
/// that day, since rows of that day itself may have been cut off.
fn whole_weeks(today: NaiveDate, weeks: i64, oldest: NaiveDate) -> i64 {
    (0..weeks).take_while(|w| today - Duration::days(7 * (w + 1)) > oldest).count() as i64
}

/// The digest of the rows over `weeks` whole weeks ending yesterday.
fn digest_transactions(txs: &[Tx], today: NaiveDate, weeks: i64, currency: &str, truncated: bool) -> serde_json::Value {
    let n = weeks as usize;
    let mut week: Vec<Week> = vec![Week::default(); n];
    // Day-to-day spending per category per week. Fixed costs are monthly, so
    // a week-by-week comparison of them says nothing; they are one total.
    let mut by_category: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
    let mut charges: Vec<Charge> = Vec::new();
    let mut largest: Vec<(i64, NaiveDate, &str, &str, bool)> = Vec::new();
    let (mut pending, mut other_currency, mut unreadable, mut outside) = (0usize, 0usize, 0usize, 0usize);
    let (mut transfers_out, mut transfers_in, mut unknown_in) = (0i64, 0i64, 0i64);

    for t in txs {
        let (Some(c), Some(date)) = (t.amount.and_then(cents), t.date.as_deref().and_then(parse_ymd)) else {
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
        let primary = cat.and_then(|c| c.primary.as_deref()).unwrap_or("");
        let detailed = cat.and_then(|c| c.detailed.as_deref()).unwrap_or("");
        let label = t.merchant_name.as_deref().filter(|m| !m.trim().is_empty()).or(t.name.as_deref()).unwrap_or("");
        let class = classify(primary, detailed, c);
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
                let name = if primary.is_empty() { "UNCATEGORIZED" } else { primary };
                if class == Class::Fixed {
                    week[w].fixed += c;
                } else {
                    week[w].day_to_day += c;
                    by_category.entry(name).or_insert_with(|| vec![0; n])[w] += c;
                    if c > 0 && w == 0 {
                        largest.push((c, date, label, name, is_pending));
                    }
                }
                if c > 0 {
                    let key = merchant_key(label);
                    if !key.is_empty() {
                        charges.push(Charge { key, label, category: name, cents: c, date });
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
        let series = monthly_series(group.clone());
        let active = |s: &Series| (today - s.last).num_days() <= ACTIVE_WITHIN_DAYS;
        let active_count = series.iter().filter(|s| active(s)).count();
        for s in series {
            if !active(&s) {
                continue;
            }
            // Seen for the second time during the last week: the week it
            // became recognisable. Reported once, since next week it has
            // either a third charge or a last charge older than a week.
            if s.charges == 2 && s.cents >= NEW_RECURRING_MIN_CENTS && (1..=7).contains(&(today - s.last).num_days()) {
                // A price change: this merchant's only running series, and a
                // charge at another price a month before its first one. A
                // merchant billing several things at once is not one.
                let previous = (active_count == 1)
                    .then(|| {
                        group
                            .iter()
                            .filter(|c| !same_price(s.cents, c.cents))
                            .filter(|c| (MONTHLY_MIN_DAYS..=MONTHLY_MAX_DAYS).contains(&(s.first - c.date).num_days()))
                            .max_by_key(|c| c.date)
                            .map(|c| c.cents)
                    })
                    .flatten();
                new_recurring.push(serde_json::json!({
                    "kind": if previous.is_some() { "price_change" } else { "new" },
                    "merchant": display_name(s.label),
                    "amount": dollars(s.cents),
                    "previous_amount": previous.map(dollars),
                    "first_date": s.first.to_string(),
                    "last_date": s.last.to_string(),
                }));
            }
            if s.charges >= CONFIRMED_CHARGES {
                for (date, c) in &s.members {
                    let back = (today - *date).num_days();
                    if (1..=weeks * 7).contains(&back) {
                        week[((back - 1) / 7) as usize].recurring += c;
                    }
                }
                recurring.push(s);
            }
        }
    }
    recurring.sort_by(|a, b| b.cents.cmp(&a.cents).then_with(|| a.label.cmp(b.label)));
    let recurring_total: i64 = recurring.iter().map(|s| s.cents).sum();
    let recurring_count = recurring.len();
    let recurring_json: Vec<serde_json::Value> = recurring
        .iter()
        .take(RECURRING_MAX)
        .map(|s| {
            serde_json::json!({
                "merchant": display_name(s.label), "amount": dollars(s.cents), "category": ident(s.category),
                "last_date": s.last.to_string(), "charges": s.charges,
            })
        })
        .collect();
    new_recurring.truncate(NEW_RECURRING_MAX);

    largest.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)).then_with(|| a.2.cmp(b.2)));
    let largest_json: Vec<serde_json::Value> = largest
        .iter()
        .take(LARGEST)
        .map(|(c, d, label, cat, p)| {
            serde_json::json!({ "date": d.to_string(), "name": display_name(label), "amount": dollars(*c), "category": ident(cat), "pending": p })
        })
        .collect();

    let weeks_json: Vec<serde_json::Value> = week
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let end = today - Duration::days(1 + 7 * i as i64);
            serde_json::json!({
                "start": (end - Duration::days(6)).to_string(), "end": end.to_string(),
                "day_to_day": dollars(w.day_to_day), "fixed": dollars(w.fixed), "income": dollars(w.income),
                "recurring": dollars(w.recurring), "count": w.count,
            })
        })
        .collect();
    let categories: BTreeMap<String, Vec<f64>> =
        by_category.into_iter().filter(|(_, v)| v.iter().any(|c| *c != 0)).map(|(k, v)| (ident(k), v.into_iter().map(dollars).collect())).collect();

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
    let credentials = || serde_json::json!({ "client_id": CLIENT_ID_REF, "secret": SECRET_REF, "access_token": s.token_ref });

    let mut unavailable: Vec<serde_json::Value> = Vec::new();
    let accounts: Vec<Account>;
    let mut txs: Vec<Tx> = Vec::new();
    // The weeks counted; fewer than asked for when the bank has more rows in
    // the window than are read. `None`: no transactions to digest.
    let mut weeks_read: Option<i64> = None;
    let mut truncated = false;

    // One request: the newest rows, and with them the accounts and balances.
    let mut body = credentials();
    body["start_date"] = serde_json::Value::String(start.to_string());
    body["end_date"] = serde_json::Value::String(end.to_string());
    body["options"] = serde_json::json!({ "count": MAX_ROWS, "offset": 0 });
    let (status, raw) = post("/transactions/get", &body)?;
    if (200..300).contains(&status) {
        let page: TxPage = serde_json::from_slice(&raw).map_err(|e| format!("Plaid /transactions/get answered something that could not be read: {e}"))?;
        accounts = page.accounts;
        txs = page.transactions;
        truncated = page.total_transactions.is_some_and(|t| t > txs.len());
        weeks_read = Some(s.weeks);
        if truncated {
            // Only what was read whole can be counted, and that can be told
            // only if the rows really are newest first.
            let dates: Vec<NaiveDate> = txs.iter().filter_map(|t| t.date.as_deref().and_then(parse_ymd)).collect();
            let newest_first = dates.windows(2).all(|w| w[0] >= w[1]);
            let whole = dates.last().filter(|_| newest_first).map(|oldest| whole_weeks(today, s.weeks, *oldest)).unwrap_or(0);
            if whole >= 1 {
                weeks_read = Some(whole);
            } else {
                weeks_read = None;
                unavailable.push(serde_json::json!({
                    "what": "transactions",
                    "reason": format!("the bank has more than {MAX_ROWS} transactions in the window and not one whole week of them could be read"),
                }));
            }
        }
    } else {
        // Transactions refused (not loaded yet, sign-in expired…): the
        // balances may still be readable.
        let (code, text) = refusal(status, &raw);
        let (st2, raw2) = post("/accounts/get", &credentials())?;
        if !(200..300).contains(&st2) {
            let (code2, text2) = refusal(st2, &raw2);
            return Err(format!("{text2}{}", hint(&code2)));
        }
        let page: AccountsPage =
            serde_json::from_slice(&raw2).map_err(|e| format!("Plaid /accounts/get answered something that could not be read: {e}"))?;
        accounts = page.accounts;
        unavailable.push(serde_json::json!({ "what": "transactions", "code": code, "reason": format!("{text}{}", hint(&code)) }));
    }

    // The currency most accounts are held in; other currencies are not added
    // to it.
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for a in &accounts {
        if let Some(c) = a.balances.as_ref().and_then(|b| b.iso_currency_code.as_deref()) {
            *seen.entry(ident(c)).or_default() += 1;
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

    let transactions = weeks_read.map(|w| digest_transactions(&txs, today, w, &currency, truncated));
    serde_json::to_string(&serde_json::json!({
        "kind": "bank_digest",
        "institution": s.institution,
        "environment": s.environment,
        "as_of": today.to_string(),
        "time_zone": s.zone,
        "currency": currency,
        "window": { "start": start.to_string(), "end": end.to_string(), "weeks_asked": s.weeks, "weeks": weeks_read },
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
        Some(t) => parse_ymd(t).ok_or_else(|| "TODAY must be a date written YYYY-MM-DD".to_string())?,
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
        parse_ymd(s).unwrap()
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
            {"account_id": "a1", "name": "EVERYDAY CHECKING ...1234", "mask": "1234", "type": "depository", "subtype": "checking",
             "balances": {"available": 4100.25, "current": 4300.0, "iso_currency_code": "USD"}},
            {"account_id": "a2", "name": "Savings", "mask": "9876", "type": "depository", "subtype": "savings",
             "balances": {"available": null, "current": 12000.0, "iso_currency_code": "USD"}},
            {"account_id": "a3", "name": "VISA SIGNATURE\u{fffd}\u{fffd} CARD ...4321", "type": "credit", "subtype": "credit card",
             "balances": {"available": 7200.0, "current": 812.4, "limit": 8000.0, "iso_currency_code": "USD"}}
        ])
    }
    /// Answers `/transactions/get` with the first `returned` of `txs` and the
    /// true total, and records every request.
    fn bank(txs: Vec<Value>, returned: usize, seen: &std::cell::RefCell<Vec<(String, Value)>>) -> impl FnMut(&str, &Value) -> Result<(u16, Vec<u8>), String> + '_ {
        move |path: &str, body: &Value| {
            seen.borrow_mut().push((path.to_string(), body.clone()));
            assert_eq!(path, "/transactions/get");
            let slice: Vec<Value> = txs.iter().take(returned).cloned().collect();
            Ok((200, json!({"accounts": accounts(), "transactions": slice, "total_transactions": txs.len()}).to_string().into_bytes()))
        }
    }
    fn run_cut(txs: Vec<Value>, returned: usize) -> Value {
        let seen = std::cell::RefCell::new(Vec::new());
        let mut post = bank(txs, returned, &seen);
        serde_json::from_str(&gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap()).unwrap()
    }
    fn run_with(txs: Vec<Value>) -> Value {
        run_cut(txs, usize::MAX)
    }

    #[test]
    fn one_request_carries_references_and_never_a_credential() {
        let seen = std::cell::RefCell::new(Vec::new());
        {
            let mut post = bank(vec![], usize::MAX, &seen);
            gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap();
        }
        assert_eq!(seen.borrow().len(), 1, "one request");
        let (path, body) = seen.borrow()[0].clone();
        assert_eq!(path, "/transactions/get");
        assert_eq!(body["client_id"], "vault://plaid/client_id");
        assert_eq!(body["secret"], "vault://plaid/secret");
        assert_eq!(body["access_token"], "vault://plaid/access_token/item-1");
        // 13 weeks ending yesterday.
        assert_eq!((body["start_date"].as_str(), body["end_date"].as_str()), (Some("2026-07-05"), Some("2026-10-03")));
        assert_eq!(body["options"], json!({"count": MAX_ROWS, "offset": 0}));
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

        let mut post = |_: &str, _: &Value| {
            Ok((200, json!({"accounts": [{"name": "Checking", "type": "depository", "balances": {"available": null, "current": null}}],
                             "transactions": [], "total_transactions": 0}).to_string().into_bytes()))
        };
        let out: Value = serde_json::from_str(&gather(&Clock { today: d(TODAY) }, &cfg(), &mut post).unwrap()).unwrap();
        assert_eq!(out["cash"], Value::Null);
        assert_eq!(out["cash_unread_accounts"], 1);
    }

    #[test]
    fn account_digits_inside_names_are_not_returned() {
        let out = run_with(vec![
            tx("2026-10-01", 90.0, "BANK LOAN AUTO PAY 991231 XXXXXXX5678", "GENERAL_SERVICES"),
        ]);
        assert_eq!(out["accounts"][0]["name"], "EVERYDAY CHECKING");
        assert_eq!(out["accounts"][2]["name"], "VISA SIGNATURE CARD");
        assert_eq!(out["transactions"]["last_week"]["largest"][0]["name"], "BANK LOAN AUTO PAY");
        let text = out.to_string();
        for digits in ["1234", "9876", "4321", "5678", "991231"] {
            assert!(!text.contains(digits), "{digits} is in the output");
        }
        assert_eq!(display_name("Store 1042"), "Store");
        assert_eq!(display_name("7-Eleven 123"), "7-Eleven 123", "short numbers are part of a name");
        assert_eq!(display_name("0873124248"), "");
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
        // Fixed costs are one total: not a category beside a usual week, and
        // not among the week's largest items.
        assert_eq!(t["by_category"].get("RENT_AND_UTILITIES"), None);
        assert_eq!(t["last_week"]["largest"][0]["name"], "Grocer");
        assert_eq!(t["last_week"]["largest"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn a_row_with_no_amount_is_counted_not_fatal() {
        let out = run_with(vec![json!({"date": "2026-10-02", "name": "No amount"}), tx("2026-10-02", 5.0, "Cafe", "FOOD_AND_DRINK")]);
        assert_eq!(out["transactions"]["left_out"]["unreadable"], 1);
        assert_eq!(out["transactions"]["weeks"][0]["day_to_day"], 5.0);
    }

    /// Newest first, as Plaid returns them.
    fn busy() -> Vec<Value> {
        vec![
            tx("2026-10-03", 10.0, "A", "FOOD_AND_DRINK"),
            tx("2026-10-01", 10.0, "B", "FOOD_AND_DRINK"),
            tx("2026-09-28", 10.0, "C", "FOOD_AND_DRINK"), // week 0 begins Sep 27
            tx("2026-09-25", 10.0, "D", "FOOD_AND_DRINK"),
            tx("2026-09-22", 10.0, "E", "FOOD_AND_DRINK"), // week 1 begins Sep 20
            tx("2026-09-21", 10.0, "F", "FOOD_AND_DRINK"),
            tx("2026-09-10", 10.0, "G", "FOOD_AND_DRINK"),
        ]
    }

    #[test]
    fn when_the_bank_has_more_rows_than_are_read_only_whole_weeks_are_counted() {
        // Everything arrives: thirteen weeks, nothing cut.
        let all = run_with(busy());
        assert_eq!(all["transactions"]["truncated"], false);
        assert_eq!(all["window"]["weeks"], 13);
        assert_eq!(all["transactions"]["weeks"][1]["day_to_day"], 30.0);

        // Five of seven arrive, the oldest dated Sep 22: week 1 (Sep 20–26)
        // may be missing rows, so only week 0 is counted and week 1's rows
        // are not presented as that week's total.
        let cut = run_cut(busy(), 5);
        assert_eq!(cut["transactions"]["truncated"], true);
        assert_eq!(cut["window"]["weeks"], 1);
        assert_eq!(cut["window"]["weeks_asked"], 13);
        assert_eq!(cut["transactions"]["weeks"].as_array().unwrap().len(), 1);
        assert_eq!(cut["transactions"]["weeks"][0]["day_to_day"], 30.0);
        assert_eq!(cut["transactions"]["left_out"]["outside_window"], 2);
        assert_eq!(cut["transactions"]["by_category"]["FOOD_AND_DRINK"], json!([30.0]));

        // Cut inside the first week: no whole week, so no totals at all —
        // and the balances are still given.
        let none = run_cut(busy(), 2);
        assert_eq!(none["transactions"], Value::Null);
        assert_eq!(none["unavailable"][0]["what"], "transactions");
        assert_eq!(none["cash"], 16100.25);

        // Cut, and not newest first: which weeks are whole cannot be told.
        let mut shuffled = busy();
        shuffled.swap(0, 4);
        assert_eq!(run_cut(shuffled, 5)["transactions"], Value::Null);

        assert_eq!(whole_weeks(d(TODAY), 13, d("2026-09-26")), 1, "week 0 begins the day after");
        assert_eq!(whole_weeks(d(TODAY), 13, d("2026-09-27")), 0, "rows of the cut-off day may be missing");
        assert_eq!(whole_weeks(d(TODAY), 13, d("2020-01-01")), 13);
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
    fn a_monthly_charge_needs_three_in_a_row_and_is_new_the_week_of_its_second() {
        let out = run_with(vec![
            // Three months of a subscription: a monthly charge, not new.
            tx("2026-07-20", 15.49, "Streamflix", "ENTERTAINMENT"),
            tx("2026-08-20", 15.49, "Streamflix", "ENTERTAINMENT"),
            tx("2026-09-20", 15.49, "Streamflix", "ENTERTAINMENT"),
            // Second charge landed last week: new, and not yet on the list.
            tx("2026-08-30", 9.99, "Cloud Box", "GENERAL_SERVICES"),
            tx("2026-09-29", 9.99, "Cloud Box", "GENERAL_SERVICES"),
            // The same order twice, a month apart, weeks ago: neither.
            tx("2026-08-10", 35.87, "Pizza Place", "FOOD_AND_DRINK"),
            tx("2026-09-09", 35.87, "Pizza Place", "FOOD_AND_DRINK"),
            // Same shop, varying amounts, weekly: not a series.
            tx("2026-09-12", 61.20, "Grocer", "FOOD_AND_DRINK"),
            tx("2026-09-19", 48.75, "Grocer", "FOOD_AND_DRINK"),
            tx("2026-09-26", 70.02, "Grocer", "FOOD_AND_DRINK"),
            // Stopped: last charge more than 40 days ago.
            tx("2026-06-12", 30.0, "Old Gym", "PERSONAL_CARE"),
            tx("2026-07-12", 30.0, "Old Gym", "PERSONAL_CARE"),
            tx("2026-08-12", 30.0, "Old Gym", "PERSONAL_CARE"),
            // A fixed cost is a monthly charge too.
            tx("2026-08-01", 1500.0, "Landlord", "RENT_AND_UTILITIES"),
            tx("2026-09-01", 1500.0, "Landlord", "RENT_AND_UTILITIES"),
            tx("2026-10-01", 1500.0, "Landlord", "RENT_AND_UTILITIES"),
            // Too small to mention as new.
            tx("2026-08-31", 0.05, "Penny Cloud", "GENERAL_SERVICES"),
            tx("2026-09-30", 0.05, "Penny Cloud", "GENERAL_SERVICES"),
        ]);
        let t = &out["transactions"];
        let names: Vec<&str> = t["recurring"].as_array().unwrap().iter().map(|r| r["merchant"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["Landlord", "Streamflix"]);
        assert_eq!(t["recurring_monthly_total"], 1515.49);
        assert_eq!(t["recurring_count"], 2);
        // The weeks say how much of their spending was a monthly charge.
        assert_eq!(t["weeks"][0]["recurring"], 1500.0, "the Oct 1 rent");
        assert_eq!(t["weeks"][1]["recurring"], 15.49, "the Sep 20 subscription");
        assert_eq!(t["weeks"][2]["recurring"], 0.0);
        assert_eq!(t["new_recurring"].as_array().unwrap().len(), 1, "{}", t["new_recurring"]);
        assert_eq!(t["new_recurring"][0]["merchant"], "Cloud Box");
        assert_eq!(t["new_recurring"][0]["kind"], "new");
    }

    #[test]
    fn a_new_price_is_a_price_change_only_when_it_replaced_the_old_one() {
        let out = run_with(vec![
            tx("2026-07-29", 15.49, "Streamflix", "ENTERTAINMENT"),
            tx("2026-08-29", 17.99, "Streamflix", "ENTERTAINMENT"),
            tx("2026-09-29", 17.99, "Streamflix", "ENTERTAINMENT"),
        ]);
        let n = &out["transactions"]["new_recurring"][0];
        assert_eq!((n["kind"].as_str(), n["amount"].as_f64(), n["previous_amount"].as_f64()), (Some("price_change"), Some(17.99), Some(15.49)));

        // One merchant billing two things at once: the second is new, and an
        // unrelated earlier charge is not its "old price".
        let out = run_with(vec![
            tx("2026-07-31", 7.74, "Cloud Host", "GENERAL_SERVICES"),
            tx("2026-08-31", 7.74, "Cloud Host", "GENERAL_SERVICES"),
            tx("2026-09-30", 7.74, "Cloud Host", "GENERAL_SERVICES"),
            tx("2026-07-31", 30.0, "Cloud Host", "GENERAL_SERVICES"),
            tx("2026-08-30", 20.0, "Cloud Host", "GENERAL_SERVICES"),
            tx("2026-09-29", 20.0, "Cloud Host", "GENERAL_SERVICES"),
        ]);
        let n = &out["transactions"]["new_recurring"];
        assert_eq!(n.as_array().unwrap().len(), 1);
        assert_eq!((n[0]["kind"].as_str(), n[0]["previous_amount"].clone()), (Some("new"), Value::Null));
    }

    #[test]
    fn merchant_keys_ignore_store_and_order_numbers() {
        assert_eq!(merchant_key("SQ *CAFE 1042"), "sq cafe");
        assert_eq!(merchant_key("Cafe #1042"), merchant_key("Cafe #77"));
        assert_eq!(merchant_key("AMZN Mktp US*2K4AB1"), "amzn mktp us");
        assert_eq!(merchant_key("12345"), "");
        assert_eq!(merchant_key("One Two Three Four Five Six"), "one two three four five");
        assert!(same_price(1000, 1050) && !same_price(1000, 1051));
        assert!(same_price(100, 150) && !same_price(100, 151), "small amounts get 50 cents");
    }

    #[test]
    fn dates_and_classes() {
        assert_eq!(parse_ymd("2026-02-28"), NaiveDate::from_ymd_opt(2026, 2, 28));
        for bad in ["2026-02-30", "2026-2-28", "2026/02/28", "20260228", "", "2026-02-28T00:00:00Z", "2026-0a-28"] {
            assert_eq!(parse_ymd(bad), None, "{bad}");
        }
        assert_eq!(classify("TRANSFER_OUT", "TRANSFER_OUT_SAVINGS", 100), Class::Transfer);
        assert_eq!(classify("LOAN_PAYMENTS", "LOAN_PAYMENTS_CREDIT_CARD_PAYMENT", 100), Class::Transfer);
        assert_eq!(classify("LOAN_PAYMENTS", "LOAN_PAYMENTS_MORTGAGE_PAYMENT", 100), Class::Fixed);
        assert_eq!(classify("INCOME", "INCOME_WAGES", -100), Class::Income);
        assert_eq!(classify("", "", -100), Class::UnknownInflow);
        assert_eq!(classify("", "", 100), Class::DayToDay);
        assert_eq!(classify("FOOD_AND_DRINK", "", -100), Class::DayToDay, "a refund nets against its category");
    }
}
