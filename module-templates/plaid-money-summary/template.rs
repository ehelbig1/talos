// Canonical catalog module: the digests of several connected banks (each the
// output of `plaid-bank-digest`, gathered by a Collect node) combined into
// one money summary. Pure computation: no network, no memory, no clock.
//
// The rule throughout: a figure that rests on a bank that could not be read is
// not shown as if it were whole. Cash, what is owed on cards and the months of
// cash covered are `null` unless every bank was read; spending from the banks
// that were read is still given, marked partial, with the missing banks named.

use serde::Deserialize;
use std::collections::BTreeMap;
use talos_sdk_macros::talos_module;

/// Weeks before last week needed before a "usual week" is stated.
const MIN_PRIOR_WEEKS: usize = 4;
const CATEGORIES_SHOWN: usize = 5;
const LARGEST_SHOWN: usize = 5;
const RECURRING_SHOWN: usize = 15;
const NEW_RECURRING_SHOWN: usize = 10;
const ACCOUNTS_SHOWN: usize = 40;
const LABEL_CHARS: usize = 40;
const REASON_CHARS: usize = 160;
/// Average weeks in a month.
const WEEKS_PER_MONTH: f64 = 365.25 / 12.0 / 7.0;

// ------------------------------------------------------------- input shapes

#[derive(Deserialize, Default)]
struct In {
    #[serde(default)]
    config: Config,
    #[serde(default)]
    input: Collected,
    #[serde(rename = "__degraded_inputs__")]
    degraded: Option<Degraded>,
}
#[derive(Deserialize, Default)]
struct Config {
    /// The banks expected, by the INSTITUTION each reader was given. A bank
    /// listed here with no digest is reported as missing.
    #[serde(rename = "BANKS", default)]
    banks: Vec<String>,
}
#[derive(Deserialize, Default)]
struct Collected {
    #[serde(default)]
    items: Vec<Digest>,
}
#[derive(Deserialize, Default)]
struct Degraded {
    #[serde(default)]
    entries: Vec<DegradedEntry>,
}
#[derive(Deserialize, Default)]
struct DegradedEntry {
    node: Option<String>,
    reason: Option<String>,
}
#[derive(Deserialize, Default)]
struct Digest {
    kind: Option<String>,
    institution: Option<String>,
    as_of: Option<String>,
    currency: Option<String>,
    #[serde(default)]
    accounts: Vec<Account>,
    cash: Option<f64>,
    #[serde(default)]
    cash_unread_accounts: usize,
    owed_on_cards: Option<f64>,
    #[serde(default)]
    cards_unread_accounts: usize,
    transactions: Option<Transactions>,
    #[serde(default)]
    unavailable: Vec<Unavailable>,
}
#[derive(Deserialize, Default)]
struct Account {
    name: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    subtype: Option<String>,
    current: Option<f64>,
    available: Option<f64>,
    limit: Option<f64>,
}
#[derive(Deserialize, Default)]
struct Unavailable {
    reason: Option<String>,
}
#[derive(Deserialize, Default)]
struct Transactions {
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    pending: usize,
    #[serde(default)]
    weeks: Vec<Week>,
    #[serde(default)]
    by_category: BTreeMap<String, Vec<f64>>,
    #[serde(default)]
    last_week: LastWeek,
    #[serde(default)]
    recurring: Vec<Recurring>,
    #[serde(default)]
    recurring_count: usize,
    recurring_monthly_total: Option<f64>,
    #[serde(default)]
    new_recurring: Vec<NewRecurring>,
}
#[derive(Deserialize, Default)]
struct Week {
    start: Option<String>,
    end: Option<String>,
    #[serde(default)]
    day_to_day: f64,
    #[serde(default)]
    fixed: f64,
    #[serde(default)]
    income: f64,
    /// The part of the week's spending that is a monthly charge.
    #[serde(default)]
    recurring: f64,
    #[serde(default)]
    count: usize,
}
#[derive(Deserialize, Default)]
struct LastWeek {
    #[serde(default)]
    largest: Vec<Largest>,
    #[serde(default)]
    transfers_out: f64,
    #[serde(default)]
    transfers_in: f64,
}
#[derive(Deserialize, Default)]
struct Largest {
    date: Option<String>,
    name: Option<String>,
    #[serde(default)]
    amount: f64,
    category: Option<String>,
    #[serde(default)]
    pending: bool,
}
#[derive(Deserialize, Default)]
struct Recurring {
    merchant: Option<String>,
    #[serde(default)]
    amount: f64,
    last_date: Option<String>,
}
#[derive(Deserialize, Default)]
struct NewRecurring {
    kind: Option<String>,
    merchant: Option<String>,
    #[serde(default)]
    amount: f64,
    previous_amount: Option<f64>,
    last_date: Option<String>,
}

// ----------------------------------------------------------------- helpers

fn cents(x: f64) -> i64 {
    let c = (x * 100.0).round();
    if c.is_finite() && c.abs() < 9.0e15 {
        c as i64
    } else {
        0
    }
}
fn dollars(c: i64) -> f64 {
    c as f64 / 100.0
}
fn clip(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect::<String>().trim().to_string()
}
fn label(s: &Option<String>, fallback: &str) -> String {
    let v = clip(s.as_deref().unwrap_or(""), LABEL_CHARS);
    if v.is_empty() {
        fallback.to_string()
    } else {
        v
    }
}
/// A date as written by the reader, or nothing.
fn date(s: &Option<String>) -> Option<String> {
    let d = s.as_deref()?;
    (d.len() == 10 && d.chars().all(|c| c.is_ascii_digit() || c == '-')).then(|| d.to_string())
}
/// The middle of the values (the mean of the two middle ones for an even count).
fn median(values: &[i64]) -> Option<i64> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_unstable();
    let mid = v.len() / 2;
    Some(if v.len() % 2 == 1 { v[mid] } else { (v[mid - 1] + v[mid]) / 2 })
}
fn same_name(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

fn summarize(data: In) -> Result<String, String> {
    let digests: Vec<&Digest> = data.input.items.iter().filter(|d| d.kind.as_deref() == Some("bank_digest")).collect();
    if digests.is_empty() {
        return Err("no bank could be read, so there is no money summary to give".to_string());
    }
    let mut notes: Vec<String> = Vec::new();

    // Banks that did not arrive: the ones the engine reports as failed
    // upstream, and any expected bank with no digest.
    let mut missing: Vec<serde_json::Value> = Vec::new();
    if let Some(d) = &data.degraded {
        for e in &d.entries {
            missing.push(serde_json::json!({
                "bank": label(&e.node, "a bank"),
                "reason": clip(e.reason.as_deref().unwrap_or("could not be read"), REASON_CHARS),
            }));
        }
    }
    let failed_branches = data.input.items.len() - digests.len();
    let unnamed_failures = failed_branches.saturating_sub(missing.len());
    let expected_absent: Vec<&String> = data
        .config
        .banks
        .iter()
        .filter(|b| !b.trim().is_empty() && !digests.iter().any(|d| same_name(d.institution.as_deref().unwrap_or(""), b)))
        .collect();
    if missing.is_empty() {
        for b in &expected_absent {
            missing.push(serde_json::json!({ "bank": clip(b, LABEL_CHARS), "reason": "could not be read" }));
        }
        if expected_absent.is_empty() && unnamed_failures > 0 {
            missing.push(serde_json::json!({ "bank": format!("{unnamed_failures} bank(s)"), "reason": "could not be read" }));
        }
    }
    let all_banks_arrived = missing.is_empty() && expected_absent.is_empty() && failed_branches == 0;

    // One day and one currency: totals across different ones are not totals.
    let as_of = digests.iter().filter_map(|d| date(&d.as_of)).max();
    let currency = digests.iter().find_map(|d| d.currency.clone()).map(|c| clip(&c, 8)).unwrap_or_else(|| "USD".to_string());
    let same_day = digests.iter().all(|d| date(&d.as_of) == as_of);
    let same_currency = digests.iter().all(|d| !d.currency.as_deref().is_some_and(|c| !c.eq_ignore_ascii_case(&currency)));
    if !same_currency {
        notes.push("The banks hold different currencies, so nothing is added up across them.".to_string());
    }

    // ---- balances
    let balances_whole = all_banks_arrived && same_currency && digests.iter().all(|d| d.cash_unread_accounts == 0 && d.cards_unread_accounts == 0);
    let cash_known: i64 = digests.iter().filter_map(|d| d.cash).map(cents).sum();
    let owed_known: i64 = digests.iter().filter_map(|d| d.owed_on_cards).map(cents).sum();
    let (cash, owed, after_cards) = if balances_whole {
        (Some(cash_known), Some(owed_known), Some(cash_known - owed_known))
    } else {
        (None, None, None)
    };
    let accounts_total: usize = digests.iter().map(|d| d.accounts.len()).sum();
    let cash_accounts = digests.iter().flat_map(|d| d.accounts.iter()).filter(|a| a.kind.as_deref() == Some("depository")).count();
    let accounts: Vec<serde_json::Value> = digests
        .iter()
        .flat_map(|d| d.accounts.iter().map(move |a| (*d, a)))
        .take(ACCOUNTS_SHOWN)
        .map(|(d, a)| {
            serde_json::json!({
                "bank": label(&d.institution, "Bank"),
                "name": label(&a.name, "Account"),
                "type": clip(a.kind.as_deref().unwrap_or(""), 24),
                "subtype": a.subtype.as_deref().map(|s| clip(s, LABEL_CHARS)),
                "current": a.current.map(|x| dollars(cents(x))),
                "available": a.available.map(|x| dollars(cents(x))),
                "limit": a.limit.map(|x| dollars(cents(x))),
            })
        })
        .collect();

    // ---- banks, one line each
    let banks: Vec<serde_json::Value> = digests
        .iter()
        .map(|d| {
            let reason = d.unavailable.iter().find_map(|u| u.reason.as_deref()).map(|r| clip(r, REASON_CHARS));
            serde_json::json!({
                "bank": label(&d.institution, "Bank"),
                "status": if d.transactions.is_some() { "read" } else { "balances_only" },
                "accounts": d.accounts.len(),
                "note": reason,
            })
        })
        .collect();

    // ---- spending, from the banks whose transactions were read
    let with_tx: Vec<(&Digest, &Transactions)> = digests.iter().filter_map(|d| d.transactions.as_ref().map(|t| (*d, t))).collect();
    let spending_whole = all_banks_arrived && with_tx.len() == digests.len();
    let weeks = with_tx.iter().map(|(_, t)| t.weeks.len()).min().unwrap_or(0);
    let spending = if with_tx.is_empty() || !same_day || !same_currency || weeks == 0 {
        if !same_day {
            notes.push("The banks were read on different days, so their weeks do not line up and spending is not added up.".to_string());
        }
        serde_json::Value::Null
    } else {
        let sum_week = |i: usize, f: fn(&Week) -> f64| -> i64 { with_tx.iter().map(|(_, t)| cents(f(&t.weeks[i]))).sum() };
        // Weeks at the far end with no transactions at any bank are before the
        // history begins; counting them as weeks of zero spending would lower
        // the usual week and the monthly average.
        let mut used = weeks;
        while used > 1 && with_tx.iter().all(|(_, t)| t.weeks[used - 1].count == 0) {
            used -= 1;
        }
        let day_to_day: Vec<i64> = (0..used).map(|i| sum_week(i, |w| w.day_to_day)).collect();
        let fixed: Vec<i64> = (0..used).map(|i| sum_week(i, |w| w.fixed)).collect();
        let income0 = sum_week(0, |w| w.income);
        let prior = used - 1;
        let usual = (prior >= MIN_PRIOR_WEEKS).then(|| median(&day_to_day[1..])).flatten();
        // A month of spending: the monthly charges once, plus everything
        // else averaged by week. Averaging the monthly charges by week too
        // would overstate them whenever the window holds one payment more
        // than it holds months.
        let monthly_charges: i64 = with_tx.iter().map(|(_, t)| cents(t.recurring_monthly_total.unwrap_or(0.0))).sum();
        let other: i64 = (0..used).map(|i| day_to_day[i] + fixed[i] - sum_week(i, |w| w.recurring)).sum();
        let monthly = (prior >= MIN_PRIOR_WEEKS).then(|| monthly_charges + (other as f64 / used as f64 * WEEKS_PER_MONTH).round() as i64);

        // Categories: last week beside each one's own usual week.
        let mut cats: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
        for (_, t) in &with_tx {
            for (name, per_week) in &t.by_category {
                let row = cats.entry(name.as_str()).or_insert_with(|| vec![0; used]);
                for (i, v) in per_week.iter().take(used).enumerate() {
                    row[i] += cents(*v);
                }
            }
        }
        let mut cat_rows: Vec<(&str, i64, Option<i64>)> =
            cats.iter().map(|(k, v)| (*k, v[0], (prior >= MIN_PRIOR_WEEKS).then(|| median(&v[1..])).flatten())).filter(|(_, last, _)| *last > 0).collect();
        cat_rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));

        // Ordered first, rendered after: only the few shown are built.
        let mut largest: Vec<(i64, &Digest, &Largest)> =
            with_tx.iter().flat_map(|(d, t)| t.last_week.largest.iter().map(move |l| (cents(l.amount), *d, l))).collect();
        largest.sort_by(|a, b| b.0.cmp(&a.0));
        let largest_json: Vec<serde_json::Value> = largest
            .iter()
            .take(LARGEST_SHOWN)
            .map(|(c, d, l)| {
                serde_json::json!({
                    "date": date(&l.date), "name": label(&l.name, "Unnamed"), "amount": dollars(*c),
                    "category": l.category.as_deref().map(|c| clip(c, LABEL_CHARS)), "bank": label(&d.institution, "Bank"), "pending": l.pending,
                })
            })
            .collect();

        if with_tx.iter().any(|(_, t)| t.truncated) {
            notes.push("A bank had more transactions than are read at once, so fewer weeks are compared.".to_string());
        }
        let w0 = &with_tx[0].1.weeks[0];
        // Months of cash: only when every balance and every bank's spending
        // is in, and there is spending to divide by.
        let months = match (after_cards, monthly) {
            (Some(c), Some(m)) if spending_whole && m > 0 => Some((c as f64 / m as f64 * 10.0).round() / 10.0),
            _ => None,
        };
        serde_json::json!({
            "partial": !spending_whole,
            "banks": with_tx.iter().map(|(d, _)| label(&d.institution, "Bank")).collect::<Vec<_>>(),
            "weeks_compared": prior,
            "last_week": {
                "start": date(&w0.start), "end": date(&w0.end),
                "day_to_day": dollars(day_to_day[0]), "fixed": dollars(fixed[0]),
                "total": dollars(day_to_day[0] + fixed[0]), "income": dollars(income0),
            },
            "usual_week_day_to_day": usual.map(dollars),
            "monthly_average": monthly.map(dollars),
            "months_of_cash": months,
            "categories": cat_rows.iter().take(CATEGORIES_SHOWN).map(|(k, last, usual)| serde_json::json!({
                "category": k, "last_week": dollars(*last), "usual_week": usual.map(dollars),
            })).collect::<Vec<_>>(),
            "largest": largest_json,
            "pending": with_tx.iter().map(|(_, t)| t.pending).sum::<usize>(),
            "transfers_left_out": {
                "out": dollars(with_tx.iter().map(|(_, t)| cents(t.last_week.transfers_out)).sum()),
                "in": dollars(with_tx.iter().map(|(_, t)| cents(t.last_week.transfers_in)).sum()),
            },
        })
    };

    // ---- monthly charges
    let recurring = if with_tx.is_empty() || !same_currency {
        serde_json::Value::Null
    } else {
        let mut items: Vec<(i64, &Digest, &Recurring)> =
            with_tx.iter().flat_map(|(d, t)| t.recurring.iter().map(move |r| (cents(r.amount), *d, r))).collect();
        items.sort_by(|a, b| b.0.cmp(&a.0));
        let items_json: Vec<serde_json::Value> = items
            .iter()
            .take(RECURRING_SHOWN)
            .map(|(c, d, r)| {
                serde_json::json!({ "merchant": label(&r.merchant, "Unnamed"), "amount": dollars(*c), "bank": label(&d.institution, "Bank"), "last_date": date(&r.last_date) })
            })
            .collect();
        let fresh: Vec<serde_json::Value> = with_tx
            .iter()
            .flat_map(|(d, t)| t.new_recurring.iter().map(move |n| (*d, n)))
            .take(NEW_RECURRING_SHOWN)
            .map(|(d, n)| {
                serde_json::json!({
                    "kind": if n.kind.as_deref() == Some("price_change") { "price_change" } else { "new" },
                    "merchant": label(&n.merchant, "Unnamed"), "amount": dollars(cents(n.amount)),
                    "previous_amount": n.previous_amount.map(|x| dollars(cents(x))), "bank": label(&d.institution, "Bank"), "last_date": date(&n.last_date),
                })
            })
            .collect();
        serde_json::json!({
            "partial": !spending_whole,
            "count": with_tx.iter().map(|(_, t)| t.recurring_count).sum::<usize>(),
            "monthly_total": dollars(with_tx.iter().map(|(_, t)| cents(t.recurring_monthly_total.unwrap_or(0.0))).sum()),
            "items": items_json,
            "new": fresh,
        })
    };

    serde_json::to_string(&serde_json::json!({
        "kind": "money",
        "as_of": as_of,
        "currency": currency,
        "complete": balances_whole && spending_whole && spending != serde_json::Value::Null,
        "banks": banks,
        "missing": missing,
        "cash": cash.map(dollars),
        "owed_on_cards": owed.map(dollars),
        "cash_after_cards": after_cards.map(dollars),
        "accounts": accounts,
        "accounts_total": accounts_total,
        "cash_accounts": cash_accounts,
        "spending": spending,
        "recurring": recurring,
        "notes": notes,
    }))
    .map_err(|e| e.to_string())
}

#[talos_module(world = "minimal-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: In = serde_json::from_str(&input).map_err(|e| format!("plaid-money-summary input: {e}"))?;
    summarize(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// A digest with `weeks` of day-to-day spending (index 0 = last week).
    fn digest(bank: &str, cash: Option<f64>, owed: Option<f64>, weeks: &[f64]) -> Value {
        let w: Vec<Value> = weeks
            .iter()
            .enumerate()
            .map(|(i, v)| {
                // Rent of 1000 every fourth week, which is also a monthly charge.
                let rent = if i % 4 == 0 { 1000.0 } else { 0.0 };
                json!({"start": format!("2026-09-{:02}", 27 - i.min(26)), "end": "2026-10-03", "day_to_day": v, "fixed": rent, "recurring": rent, "income": 0.0, "count": if *v > 0.0 { 5 } else { 0 }})
            })
            .collect();
        json!({
            "kind": "bank_digest", "institution": bank, "as_of": "2026-10-04", "currency": "USD",
            "accounts": [{"name": "Checking", "type": "depository", "subtype": "checking", "current": cash, "available": cash}],
            "cash": cash, "cash_unread_accounts": 0, "owed_on_cards": owed, "cards_unread_accounts": 0,
            "transactions": {
                "truncated": false, "pending": 1, "weeks": w,
                "by_category": {"FOOD_AND_DRINK": weeks},
                "last_week": {"largest": [{"date": "2026-10-01", "name": format!("{bank} shop"), "amount": weeks[0], "category": "FOOD_AND_DRINK", "pending": false}],
                              "transfers_out": 100.0, "transfers_in": 0.0},
                "recurring": [{"merchant": "Landlord", "amount": 1000.0, "last_date": "2026-10-01"}],
                "recurring_count": 1, "recurring_monthly_total": 1000.0,
                "new_recurring": []
            },
            "unavailable": []
        })
    }
    fn run_on(items: Vec<Value>, banks: &[&str], degraded: Option<Value>) -> Value {
        let mut input = json!({"config": {"BANKS": banks}, "input": {"items": items, "count": 0}});
        if let Some(d) = degraded {
            input["__degraded_inputs__"] = d;
        }
        serde_json::from_str(&run(input.to_string()).unwrap()).unwrap()
    }
    const WEEKS: [f64; 9] = [300.0, 200.0, 220.0, 180.0, 900.0, 210.0, 190.0, 0.0, 0.0];

    #[test]
    fn two_banks_are_added_up_and_the_usual_week_is_a_median() {
        let out = run_on(vec![digest("Alpha", Some(5000.0), None, &WEEKS), digest("Beta", Some(1000.0), Some(400.0), &WEEKS)], &["Alpha", "Beta"], None);
        assert_eq!(out["complete"], true);
        assert_eq!(out["cash"], 6000.0);
        assert_eq!(out["owed_on_cards"], 400.0);
        assert_eq!(out["cash_after_cards"], 5600.0);
        let s = &out["spending"];
        assert_eq!(s["last_week"]["day_to_day"], 600.0);
        // The two empty weeks at the far end are before the history began:
        // six prior weeks, median of [400, 440, 360, 1800, 420, 380] = 410.
        assert_eq!(s["weeks_compared"], 6);
        assert_eq!(s["usual_week_day_to_day"], 410.0, "one unusual week does not move the usual one");
        // A month is the rent once (2 x 1000) plus the rest by week:
        // 4400 over seven weeks = 628.57 a week = 2733.16 a month. The three
        // rent payments in the seven weeks are not averaged in again.
        assert_eq!(s["monthly_average"], 4733.16);
        assert_eq!(s["months_of_cash"], 1.2);
        assert_eq!(out["cash_accounts"], 2);
        assert_eq!(s["categories"][0], json!({"category": "FOOD_AND_DRINK", "last_week": 600.0, "usual_week": 410.0}));
        assert_eq!(s["largest"].as_array().unwrap().len(), 2);
        assert_eq!(out["recurring"]["monthly_total"], 2000.0);
        assert_eq!(out["recurring"]["count"], 2);
        assert_eq!(out["missing"], json!([]));
    }

    #[test]
    fn a_bank_that_failed_is_named_and_totals_that_need_it_are_unknown() {
        let failed = json!({"__error": true, "error_message": "Plaid 400: ITEM_ERROR / ITEM_LOGIN_REQUIRED"});
        let degraded = json!({"any_degraded": true, "count": 1, "entries": [{"node": "beta", "reason": "Plaid 400: ITEM_ERROR / ITEM_LOGIN_REQUIRED (the bank connection has to be made again in Settings)"}]});
        let out = run_on(vec![digest("Alpha", Some(5000.0), None, &WEEKS), failed], &["Alpha", "Beta"], Some(degraded));
        assert_eq!(out["complete"], false);
        assert_eq!(out["cash"], Value::Null, "cash without one bank is not the cash");
        assert_eq!(out["missing"][0]["bank"], "beta");
        assert!(out["missing"][0]["reason"].as_str().unwrap().contains("ITEM_LOGIN_REQUIRED"));
        assert_eq!(out["spending"]["partial"], true);
        assert_eq!(out["spending"]["last_week"]["day_to_day"], 300.0, "what was read is still given");
        assert_eq!(out["spending"]["months_of_cash"], Value::Null);
        assert_eq!(out["accounts"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn an_expected_bank_with_no_digest_is_missing_even_without_an_engine_report() {
        let out = run_on(vec![digest("Alpha", Some(5000.0), None, &WEEKS)], &["Alpha", "Beta"], None);
        assert_eq!(out["missing"], json!([{"bank": "Beta", "reason": "could not be read"}]));
        assert_eq!(out["cash"], Value::Null);
        // With no expected list and nothing failed, one bank is the whole picture.
        let out = run_on(vec![digest("Alpha", Some(5000.0), None, &WEEKS)], &[], None);
        assert_eq!((out["complete"].clone(), out["cash"].clone()), (json!(true), json!(5000.0)));
    }

    #[test]
    fn balances_only_and_unread_balances_withhold_the_totals_they_touch() {
        let mut b = digest("Beta", Some(1000.0), None, &WEEKS);
        b["transactions"] = Value::Null;
        b["unavailable"] = json!([{"what": "transactions", "code": "PRODUCT_NOT_READY", "reason": "Plaid 400: ITEM_ERROR / PRODUCT_NOT_READY"}]);
        let out = run_on(vec![digest("Alpha", Some(5000.0), None, &WEEKS), b], &[], None);
        assert_eq!(out["cash"], 6000.0, "both balances were read");
        assert_eq!(out["banks"][1]["status"], "balances_only");
        assert_eq!(out["spending"]["partial"], true);
        assert_eq!(out["spending"]["months_of_cash"], Value::Null);
        assert_eq!(out["complete"], false);

        let mut c = digest("Gamma", None, None, &WEEKS);
        c["cash_unread_accounts"] = json!(1);
        let out = run_on(vec![digest("Alpha", Some(5000.0), None, &WEEKS), c], &[], None);
        assert_eq!(out["cash"], Value::Null, "an unread balance is unknown, not zero");
    }

    #[test]
    fn too_little_history_gives_no_usual_week() {
        let out = run_on(vec![digest("Alpha", Some(5000.0), None, &[300.0, 200.0, 220.0, 0.0, 0.0])], &[], None);
        let s = &out["spending"];
        assert_eq!(s["weeks_compared"], 2);
        assert_eq!(s["usual_week_day_to_day"], Value::Null);
        assert_eq!(s["monthly_average"], Value::Null);
        assert_eq!(s["months_of_cash"], Value::Null);
        assert_eq!(s["last_week"]["day_to_day"], 300.0);
    }

    #[test]
    fn banks_read_on_different_days_are_not_added_up() {
        let mut b = digest("Beta", Some(1000.0), None, &WEEKS);
        b["as_of"] = json!("2026-10-05");
        let out = run_on(vec![digest("Alpha", Some(5000.0), None, &WEEKS), b], &[], None);
        assert_eq!(out["spending"], Value::Null);
        assert_eq!(out["complete"], false);
        assert!(out["notes"][0].as_str().unwrap().contains("different days"));
    }

    #[test]
    fn nothing_readable_is_an_error_and_other_inputs_are_ignored() {
        let input = json!({"config": {}, "input": {"items": [{"__error": true}, {"kind": "something_else"}]}});
        assert!(run(input.to_string()).unwrap_err().contains("no bank could be read"));
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[3, 1, 2]), Some(2));
        assert_eq!(median(&[4, 1, 2, 3]), Some(2));
    }
}
