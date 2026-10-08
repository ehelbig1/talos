// Canonical catalog module: list recent messages in one Outlook mail folder
// through Microsoft Graph. Read-only: ONE GET request, nothing is written.
//
// Uses vault:// header resolution for auth — the module never holds the token.
// The output mirrors `gmail-list-messages` per message (id, subject, from,
// date, snippet) plus `to`, `is_read` and `web_link`, so a workflow written
// against one mailbox reads the other with the same field names.

use serde::{Deserialize, Serialize};
use talos::core::datetime;
use talos_sdk_macros::talos_module;

const GRAPH: &str = "https://graph.microsoft.com/v1.0";
/// The message fields asked for; nothing else is sent back.
const SELECT: &str = "id,subject,from,toRecipients,receivedDateTime,bodyPreview,isRead,webLink";
/// Graph's well-known folder names this template documents. Any other value
/// is taken as a folder id (Graph also knows more well-known names, such as
/// `outbox`; those pass the id check unchanged).
const WELL_KNOWN_FOLDERS: [&str; 6] = ["inbox", "sentitems", "drafts", "archive", "deleteditems", "junkemail"];
/// Longest folder id accepted. Graph's ids are about 120 characters.
const MAX_FOLDER_CHARS: usize = 256;
const DEFAULT_HOURS_BACK: u64 = 24;
const MAX_HOURS_BACK: u64 = 720;
const DEFAULT_MAX_RESULTS: u64 = 10;
/// Most messages one run returns (`$top`).
const HARD_CAP: u64 = 25;
/// Recipients written into `to` before the rest are only counted.
const MAX_RECIPIENTS: usize = 20;
/// Characters of a Graph error quoted in an error.
const ERROR_BODY_CHARS: usize = 300;

// ------------------------------------------------------------ wire shapes

#[derive(Deserialize)]
struct ListResp {
    #[serde(default)]
    value: Option<Vec<GraphMessage>>,
    /// Present when the folder holds more messages in the window than `$top`.
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct GraphMessage {
    #[serde(default)]
    id: String,
    subject: Option<String>,
    from: Option<Recipient>,
    #[serde(rename = "toRecipients")]
    to_recipients: Option<Vec<Recipient>>,
    #[serde(rename = "receivedDateTime")]
    received: Option<String>,
    #[serde(rename = "bodyPreview")]
    body_preview: Option<String>,
    #[serde(rename = "isRead")]
    is_read: Option<bool>,
    #[serde(rename = "webLink")]
    web_link: Option<String>,
}

#[derive(Deserialize)]
struct Recipient {
    #[serde(rename = "emailAddress")]
    email_address: Option<EmailAddress>,
}

#[derive(Deserialize)]
struct EmailAddress {
    name: Option<String>,
    address: Option<String>,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: Option<GraphError>,
}

#[derive(Deserialize)]
struct GraphError {
    code: Option<String>,
    message: Option<String>,
}

// ----------------------------------------------------------------- config

struct Settings {
    auth: String,
    folder: String,
    hours_back: u64,
    unread_only: bool,
    max_results: u64,
}

impl Settings {
    /// Every setting checked before anything is sent. A setting that is out
    /// of range or of the wrong kind is an error, not silently replaced.
    fn from_config(config: &serde_json::Value) -> Result<Self, String> {
        let auth = config["AUTH_HEADER"]
            .as_str()
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .ok_or("Missing AUTH_HEADER config (expected 'Bearer vault://oauth/microsoft_365/{user_id}/{account_id}/access_token')")?
            .to_string();
        Ok(Settings {
            auth,
            folder: folder(&config["FOLDER"])?,
            hours_back: whole_number(&config["HOURS_BACK"], "HOURS_BACK", DEFAULT_HOURS_BACK, 1, MAX_HOURS_BACK)?,
            unread_only: flag(&config["UNREAD_ONLY"], "UNREAD_ONLY", false)?,
            max_results: whole_number(&config["MAX_RESULTS"], "MAX_RESULTS", DEFAULT_MAX_RESULTS, 1, HARD_CAP)?,
        })
    }
}

/// The folder: a well-known name (any case) or a folder id. It goes into the
/// request PATH, so only the characters a Graph id is made of are accepted —
/// no `/`, `.`, `%`, `?` or `#` can reach the URL.
fn folder(value: &serde_json::Value) -> Result<String, String> {
    let raw = match value {
        serde_json::Value::Null => return Ok("inbox".to_string()),
        serde_json::Value::String(s) => s.trim(),
        _ => return Err("FOLDER must be a string: a well-known folder name such as inbox, or a folder id".to_string()),
    };
    if raw.is_empty() {
        return Ok("inbox".to_string());
    }
    if let Some(name) = WELL_KNOWN_FOLDERS.iter().find(|w| w.eq_ignore_ascii_case(raw)) {
        return Ok((*name).to_string());
    }
    let is_id = raw.len() <= MAX_FOLDER_CHARS
        && raw.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'=' | b'+'));
    if !is_id {
        return Err(format!(
            "FOLDER '{}' is neither a well-known folder ({}) nor a folder id (letters, digits, '-', '_', '=', '+'; at most {MAX_FOLDER_CHARS} characters)",
            clip_chars(raw, 60),
            WELL_KNOWN_FOLDERS.join(", ")
        ));
    }
    Ok(raw.to_string())
}

/// A whole number in `min..=max`: a JSON integer or a string holding one.
/// Absent (or an empty string) is `default`.
fn whole_number(value: &serde_json::Value, key: &str, default: u64, min: u64, max: u64) -> Result<u64, String> {
    let n = match value {
        serde_json::Value::Null => return Ok(default),
        serde_json::Value::String(s) if s.trim().is_empty() => return Ok(default),
        serde_json::Value::String(s) => s.trim().parse::<u64>().ok(),
        v => v.as_u64(),
    };
    match n {
        Some(n) if (min..=max).contains(&n) => Ok(n),
        _ => Err(format!("{key} must be a whole number from {min} to {max}, got {}", clip_chars(&value.to_string(), 40))),
    }
}

/// A boolean, or the string "true" / "false". Absent (or empty) is `default`.
fn flag(value: &serde_json::Value, key: &str, default: bool) -> Result<bool, String> {
    match value {
        serde_json::Value::Null => Ok(default),
        serde_json::Value::Bool(b) => Ok(*b),
        serde_json::Value::String(s) if s.trim().is_empty() => Ok(default),
        serde_json::Value::String(s) if s.trim().eq_ignore_ascii_case("true") => Ok(true),
        serde_json::Value::String(s) if s.trim().eq_ignore_ascii_case("false") => Ok(false),
        v => Err(format!("{key} must be true or false, got {}", clip_chars(&v.to_string(), 40))),
    }
}

// ---------------------------------------------------------------- request

/// The start of the window, `hours_back` before `now`, as Graph's DateTimeOffset
/// literal (UTC, second precision).
fn window_start(now_unix: u64, hours_back: u64) -> Result<String, String> {
    let start = now_unix
        .checked_sub(hours_back * 3600)
        .ok_or("the clock reads a time before the start of the window")?;
    datetime::format(start, "%Y-%m-%dT%H:%M:%SZ").map_err(|e| format!("could not format the window start: {e:?}"))
}

fn list_url(s: &Settings, since: &str) -> String {
    // Graph requires a property in $orderby to appear in $filter too, and
    // first; `receivedDateTime ge …` does both.
    let mut filter = format!("receivedDateTime ge {since}");
    if s.unread_only {
        filter.push_str(" and isRead eq false");
    }
    format!(
        "{GRAPH}/me/mailFolders/{}/messages?$select={}&$orderby={}&$filter={}&$top={}",
        pct(&s.folder),
        pct(SELECT),
        pct("receivedDateTime desc"),
        pct(&filter),
        s.max_results
    )
}

// ----------------------------------------------------------------- output

/// The reply, or the error a caller can act on.
fn shape(status: u16, body: &[u8], s: &Settings, since: &str) -> Result<String, String> {
    if status == 401 {
        return Err("Microsoft 365 401: access_token invalid or expired. Call refresh_oauth_token to force a refresh and check the outcome; if Microsoft refused the refresh, reconnect the account on the integrations page.".to_string());
    }
    if !(200..300).contains(&status) {
        return Err(format!("Graph HTTP {status}: {}", error_text(body)));
    }
    let page: ListResp = serde_json::from_slice(body).map_err(|e| format!("Graph response could not be read: {e}"))?;
    let listed = page.value.unwrap_or_default();
    let cap = s.max_results as usize;
    // More messages in the window than were returned: Graph said so with a
    // next link, or (defensively) sent more than `$top`.
    let truncated = page.next_link.is_some_and(|l| !l.is_empty()) || listed.len() > cap;
    let messages: Vec<Entry> = listed.into_iter().take(cap).map(message_entry).collect();
    serde_json::to_string(&Output {
        count: messages.len(),
        messages,
        folder: &s.folder,
        hours_back: s.hours_back,
        unread_only: s.unread_only,
        since,
        truncated,
    })
    .map_err(|e| e.to_string())
}

// Typed output: serialising a struct is far cheaper in fuel than building a
// `serde_json::Value` map per message.
#[derive(Serialize)]
struct Output<'a> {
    count: usize,
    messages: Vec<Entry>,
    folder: &'a str,
    hours_back: u64,
    unread_only: bool,
    since: &'a str,
    truncated: bool,
}

/// One message, under `gmail-list-messages`' field names.
#[derive(Serialize)]
struct Entry {
    id: String,
    subject: String,
    from: String,
    to: String,
    date: String,
    snippet: String,
    is_read: bool,
    web_link: String,
}

fn message_entry(m: GraphMessage) -> Entry {
    let recipients = m.to_recipients.unwrap_or_default();
    let mut to = recipients
        .iter()
        .take(MAX_RECIPIENTS)
        .map(mailbox)
        .filter(|r| !r.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    if recipients.len() > MAX_RECIPIENTS {
        to.push_str(&format!(" (+{} more)", recipients.len() - MAX_RECIPIENTS));
    }
    Entry {
        id: m.id,
        subject: m.subject.unwrap_or_default(),
        from: m.from.as_ref().map(mailbox).unwrap_or_default(),
        to,
        date: m.received.unwrap_or_default(),
        snippet: m.body_preview.unwrap_or_default(),
        is_read: m.is_read.unwrap_or(false),
        web_link: m.web_link.unwrap_or_default(),
    }
}

/// One mailbox as an e-mail header writes it: `Name <address>`, the bare
/// address when there is no name (or the name IS the address), and a name
/// holding header punctuation quoted (`"Doe, Jane" <jane@example.com>`).
fn mailbox(r: &Recipient) -> String {
    let Some(e) = r.email_address.as_ref() else {
        return String::new();
    };
    let name = e.name.as_deref().map(str::trim).unwrap_or("");
    let address = e.address.as_deref().map(str::trim).unwrap_or("");
    match (name.is_empty(), address.is_empty()) {
        (false, false) if !name.eq_ignore_ascii_case(address) => format!("{} <{address}>", display_name(name)),
        (_, false) => address.to_string(),
        (false, true) => display_name(name),
        (true, true) => String::new(),
    }
}

fn display_name(name: &str) -> String {
    if name.chars().any(|c| matches!(c, ',' | ';' | ':' | '<' | '>' | '@' | '"' | '(' | ')' | '[' | ']' | '\\')) {
        format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        name.to_string()
    }
}

/// What a Graph error says: `code: message` when the body is Graph's error
/// shape (so `MailboxNotEnabledForRESTAPI` is never lost past the clip),
/// otherwise the body itself. Clipped on a character boundary.
fn error_text(body: &[u8]) -> String {
    if let Ok(ErrorBody { error: Some(e) }) = serde_json::from_slice::<ErrorBody>(body) {
        let code = e.code.unwrap_or_default();
        let message = e.message.unwrap_or_default();
        let text = match (code.is_empty(), message.is_empty()) {
            (false, false) => format!("{code}: {message}"),
            (false, true) => code,
            (true, false) => message,
            (true, true) => String::new(),
        };
        if !text.is_empty() {
            return clip_chars(&text, ERROR_BODY_CHARS);
        }
    }
    clip_chars(&String::from_utf8_lossy(body), ERROR_BODY_CHARS)
}

// ----------------------------------------------------------------- helpers

/// A string cut to `max` characters on a character boundary.
fn clip_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// -------------------------------------------------------------------- run

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);
    let settings = Settings::from_config(config)?;
    let since = window_start(datetime::now_unix(), settings.hours_back)?;

    let req = talos::core::http::Request {
        method: talos::core::http::Method::Get,
        url: list_url(&settings, &since),
        headers: vec![
            ("Authorization".to_string(), settings.auth.clone()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(15000),
    };
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("Graph fetch: {e:?}"))?;
    shape(resp.status, &resp.body, &settings, &since)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use talos_module_testkit::host;

    /// 2026-10-08T12:00:00Z.
    const NOW: u64 = 1_791_460_800;
    const AUTH: &str = "Bearer vault://oauth/microsoft_365/made-up-user/made-up-account/access_token";

    fn list(config: Value) -> Result<Value, String> {
        host::clock::set_unix(NOW);
        run(json!({ "config": config }).to_string()).map(|s| serde_json::from_str(&s).unwrap())
    }
    fn msg(id: &str, name: &str, address: &str) -> Value {
        json!({
            "@odata.etag": "W/\"made-up\"",
            "id": id,
            "subject": format!("Subject {id}"),
            "from": { "emailAddress": { "name": name, "address": address } },
            "toRecipients": [{ "emailAddress": { "name": "Made Up Owner", "address": "owner@example.com" } }],
            "receivedDateTime": "2026-10-08T09:15:00Z",
            "bodyPreview": format!("Preview of {id}"),
            "isRead": false,
            "webLink": format!("https://outlook.office365.com/owa/?ItemID={id}&exvsurl=1&viewmodel=ReadMessageItem"),
        })
    }
    fn page(messages: Vec<Value>, next: Option<&str>) -> String {
        let mut p = json!({
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users('made-up')/mailFolders('inbox')/messages(id,subject,from,toRecipients,receivedDateTime,bodyPreview,isRead,webLink)",
            "value": messages,
        });
        if let Some(n) = next {
            p["@odata.nextLink"] = json!(n);
        }
        p.to_string()
    }

    #[test]
    fn the_request_is_one_get_built_from_the_settings() {
        host::http::respond(200, page(vec![], None));
        list(json!({ "AUTH_HEADER": AUTH, "FOLDER": "SentItems", "HOURS_BACK": 48, "UNREAD_ONLY": true, "MAX_RESULTS": 5 })).unwrap();
        let requests = host::http::requests();
        assert_eq!(requests.len(), 1, "one request");
        let r = &requests[0];
        assert_eq!(r.method, talos::core::http::Method::Get);
        assert_eq!(
            r.url,
            "https://graph.microsoft.com/v1.0/me/mailFolders/sentitems/messages\
             ?$select=id%2Csubject%2Cfrom%2CtoRecipients%2CreceivedDateTime%2CbodyPreview%2CisRead%2CwebLink\
             &$orderby=receivedDateTime%20desc\
             &$filter=receivedDateTime%20ge%202026-10-06T12%3A00%3A00Z%20and%20isRead%20eq%20false\
             &$top=5"
        );
        assert!(r.headers.iter().any(|(k, v)| k == "Authorization" && v == AUTH));
        assert!(r.body.is_empty());
    }

    #[test]
    fn the_defaults_are_the_inbox_over_the_last_day() {
        host::http::respond(200, page(vec![], None));
        let o = list(json!({ "AUTH_HEADER": AUTH })).unwrap();
        let url = host::http::requests()[0].url.clone();
        assert!(url.starts_with("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?"), "{url}");
        assert!(url.contains("&$filter=receivedDateTime%20ge%202026-10-07T12%3A00%3A00Z&$top=10"), "{url}");
        assert!(!url.contains("isRead%20eq"), "{url}");
        assert_eq!(
            o,
            json!({ "count": 0, "messages": [], "folder": "inbox", "hours_back": 24, "unread_only": false,
                    "since": "2026-10-07T12:00:00Z", "truncated": false })
        );
        // Empty strings, as a form submits them, are the defaults too.
        host::http::respond(200, page(vec![], None));
        let o = list(json!({ "AUTH_HEADER": AUTH, "FOLDER": " ", "HOURS_BACK": "", "UNREAD_ONLY": "", "MAX_RESULTS": "" })).unwrap();
        assert_eq!((o["folder"].clone(), o["hours_back"].clone()), (json!("inbox"), json!(24)));
    }

    #[test]
    fn a_folder_id_is_percent_encoded_into_the_path() {
        host::http::respond(200, page(vec![], None));
        let o = list(json!({ "AUTH_HEADER": AUTH, "FOLDER": "AAMkAGI2-made_up+id==", "MAX_RESULTS": "3", "UNREAD_ONLY": "TRUE" })).unwrap();
        let url = host::http::requests()[0].url.clone();
        assert!(url.starts_with("https://graph.microsoft.com/v1.0/me/mailFolders/AAMkAGI2-made_up%2Bid%3D%3D/messages?"), "{url}");
        assert!(url.ends_with("isRead%20eq%20false&$top=3"), "{url}");
        assert_eq!(o["folder"], json!("AAMkAGI2-made_up+id=="));
        assert_eq!(o["unread_only"], json!(true));
    }

    #[test]
    fn messages_are_returned_under_gmails_field_names() {
        let mut quiet = msg("m2", "", "noreply@example.com");
        quiet["subject"] = Value::Null;
        quiet["isRead"] = json!(true);
        quiet["toRecipients"] = json!([
            { "emailAddress": { "name": "Doe, Jane", "address": "jane@example.com" } },
            { "emailAddress": { "name": "team@example.com", "address": "team@example.com" } },
            { "emailAddress": { "name": "Say \"Hi\"", "address": "hi@example.com" } },
            { "emailAddress": null },
        ]);
        host::http::respond(200, page(vec![msg("m1", "Made Up Sender", "sender@example.com"), quiet], None));
        let o = list(json!({ "AUTH_HEADER": AUTH })).unwrap();
        assert_eq!(o["count"], json!(2));
        assert_eq!(
            o["messages"][0],
            json!({
                "id": "m1",
                "subject": "Subject m1",
                "from": "Made Up Sender <sender@example.com>",
                "to": "Made Up Owner <owner@example.com>",
                "date": "2026-10-08T09:15:00Z",
                "snippet": "Preview of m1",
                "is_read": false,
                "web_link": "https://outlook.office365.com/owa/?ItemID=m1&exvsurl=1&viewmodel=ReadMessageItem",
            })
        );
        let m2 = &o["messages"][1];
        assert_eq!((m2["subject"].clone(), m2["from"].clone(), m2["is_read"].clone()), (json!(""), json!("noreply@example.com"), json!(true)));
        assert_eq!(m2["to"], json!(r#""Doe, Jane" <jane@example.com>, team@example.com, "Say \"Hi\"" <hi@example.com>"#));
    }

    #[test]
    fn a_long_recipient_list_is_cut_and_counted() {
        let mut m = msg("m1", "A", "a@example.com");
        m["toRecipients"] = Value::Array(
            (0..23).map(|i| json!({ "emailAddress": { "address": format!("r{i}@example.com") } })).collect(),
        );
        host::http::respond(200, page(vec![m], None));
        let o = list(json!({ "AUTH_HEADER": AUTH })).unwrap();
        let to = o["messages"][0]["to"].as_str().unwrap().to_string();
        assert!(to.starts_with("r0@example.com, r1@example.com"), "{to}");
        assert!(to.ends_with("r19@example.com (+3 more)"), "{to}");
    }

    #[test]
    fn more_in_the_window_than_returned_is_said() {
        // Graph pages with a next link: it is not followed (one request), and
        // the output says the folder holds more.
        let next = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$skip=2";
        host::http::respond(200, page(vec![msg("m1", "A", "a@example.com"), msg("m2", "B", "b@example.com")], Some(next)));
        let o = list(json!({ "AUTH_HEADER": AUTH, "MAX_RESULTS": 2 })).unwrap();
        assert_eq!((o["count"].clone(), o["truncated"].clone()), (json!(2), json!(true)));
        assert_eq!(host::http::requests().len(), 1, "the next link is not followed");
        // More than $top in one page: only $top are returned.
        let three = vec![msg("m1", "A", "a@example.com"), msg("m2", "B", "b@example.com"), msg("m3", "C", "c@example.com")];
        host::http::respond(200, page(three, None));
        let o = list(json!({ "AUTH_HEADER": AUTH, "MAX_RESULTS": 2 })).unwrap();
        assert_eq!((o["count"].clone(), o["truncated"].clone()), (json!(2), json!(true)));
        assert_eq!(o["messages"][1]["id"], json!("m2"));
        // No next link and no more than asked for: complete.
        host::http::respond(200, page(vec![msg("m1", "A", "a@example.com")], None));
        let o = list(json!({ "AUTH_HEADER": AUTH, "MAX_RESULTS": 2 })).unwrap();
        assert_eq!((o["count"].clone(), o["truncated"].clone()), (json!(1), json!(false)));
        // A page with no `value` at all is an empty folder, not an error.
        host::http::respond(200, "{}");
        assert_eq!(list(json!({ "AUTH_HEADER": AUTH })).unwrap()["count"], json!(0));
    }

    #[test]
    fn a_refused_token_says_what_to_do() {
        host::http::respond(401, r#"{"error":{"code":"InvalidAuthenticationToken","message":"Access token has expired."}}"#);
        let e = list(json!({ "AUTH_HEADER": AUTH })).unwrap_err();
        assert!(e.starts_with("Microsoft 365 401: access_token invalid or expired."), "{e}");
        assert!(e.contains("refresh_oauth_token"), "{e}");
    }

    #[test]
    fn a_graph_error_is_surfaced_and_clipped_on_a_character_boundary() {
        host::http::respond(
            404,
            r#"{"error":{"code":"MailboxNotEnabledForRESTAPI","message":"The mailbox is either inactive, soft-deleted, or is hosted on-premise.","innerError":{"date":"2026-10-08T12:00:00","request-id":"made-up"}}}"#,
        );
        let e = list(json!({ "AUTH_HEADER": AUTH })).unwrap_err();
        assert_eq!(e, "Graph HTTP 404: MailboxNotEnabledForRESTAPI: The mailbox is either inactive, soft-deleted, or is hosted on-premise.");
        // A body that is not Graph's error shape is quoted, clipped to whole characters.
        host::http::respond(503, "é".repeat(1000));
        let e = list(json!({ "AUTH_HEADER": AUTH })).unwrap_err();
        assert_eq!(e, format!("Graph HTTP 503: {}", "é".repeat(ERROR_BODY_CHARS)));
        // A long Graph message is clipped too, with its code kept.
        host::http::respond(400, json!({ "error": { "code": "BadRequest", "message": "x".repeat(2000) } }).to_string());
        let e = list(json!({ "AUTH_HEADER": AUTH })).unwrap_err();
        assert!(e.starts_with("Graph HTTP 400: BadRequest: xxx"), "{e}");
        assert_eq!(e.chars().count(), "Graph HTTP 400: ".len() + ERROR_BODY_CHARS);
    }

    #[test]
    fn an_unreadable_reply_or_a_failed_fetch_is_an_error() {
        host::http::respond(200, "<html>not json</html>");
        assert!(list(json!({ "AUTH_HEADER": AUTH })).is_err_and(|e| e.starts_with("Graph response could not be read")));
        host::http::respond_with(|_| Err(talos::core::http::Error::Timeout));
        assert!(list(json!({ "AUTH_HEADER": AUTH })).is_err_and(|e| e == "Graph fetch: Timeout"));
    }

    #[test]
    fn a_bad_setting_is_refused_before_anything_is_sent() {
        let base = |key: &str, value: Value| {
            let mut c = json!({ "AUTH_HEADER": AUTH });
            c[key] = value;
            c
        };
        let bad = [
            json!({}),
            json!({ "AUTH_HEADER": "  " }),
            json!({ "AUTH_HEADER": 7 }),
            base("FOLDER", json!("inbox/../users")),
            base("FOLDER", json!("a b")),
            base("FOLDER", json!("id%2F")),
            base("FOLDER", json!("x?$top=999")),
            base("FOLDER", json!("x".repeat(MAX_FOLDER_CHARS + 1))),
            base("FOLDER", json!(["inbox"])),
            base("HOURS_BACK", json!(0)),
            base("HOURS_BACK", json!(721)),
            base("HOURS_BACK", json!(-1)),
            base("HOURS_BACK", json!(1.5)),
            base("HOURS_BACK", json!("a day")),
            base("MAX_RESULTS", json!(0)),
            base("MAX_RESULTS", json!(26)),
            base("UNREAD_ONLY", json!("yes")),
            base("UNREAD_ONLY", json!(1)),
        ];
        for config in bad {
            assert!(list(config.clone()).is_err(), "{config}");
        }
        assert!(host::http::requests().is_empty(), "nothing is sent for a refused setting");
        assert!(list(json!({})).is_err_and(|e| e.contains("vault://oauth/microsoft_365/")));
        assert!(list(base("HOURS_BACK", json!(721))).is_err_and(|e| e.contains("HOURS_BACK must be a whole number from 1 to 720")));
        // The edges of each range are accepted, and a well-known name in any case.
        host::http::respond(200, page(vec![], None));
        for config in [
            base("HOURS_BACK", json!(720)),
            base("HOURS_BACK", json!("1")),
            base("MAX_RESULTS", json!(25)),
            base("FOLDER", json!("JunkEmail")),
            base("FOLDER", json!("x".repeat(MAX_FOLDER_CHARS))),
        ] {
            assert!(list(config.clone()).is_ok(), "{config}");
        }
        assert!(host::http::requests()[3].url.contains("/mailFolders/junkemail/"));
    }

    #[test]
    fn the_window_start_is_utc_to_the_second() {
        host::clock::set_unix(NOW);
        assert_eq!(window_start(NOW, 1).unwrap(), "2026-10-08T11:00:00Z");
        assert_eq!(window_start(NOW, 720).unwrap(), "2026-09-08T12:00:00Z");
        assert!(window_start(3600, 2).is_err());
    }
}
