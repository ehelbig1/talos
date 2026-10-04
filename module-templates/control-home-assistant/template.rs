// Home control adapter: Home Assistant.
//
// A workflow decides WHAT should happen at home in service-neutral words:
//
//   { "commands": [ { "target": "office_lights", "action": "turn_off" },
//                   { "target": "thermostat", "action": "set_temperature", "value": 20.5 } ] }
//
// This adapter is where those words meet one service. Its TARGETS config maps
// each neutral target to a Home Assistant entity and lists the actions that
// target allows. A target that is not in the map, or an action it does not
// allow, is REFUSED and nothing is sent for it: the map is the allow-list of
// what a workflow may do in the house. docs/home-control-contract.md.
//
// DRY_RUN defaults to TRUE (the house pattern for a module that changes
// something): it reports exactly what it would do and sends nothing.
//
// Best-effort batch: one command failing is recorded and the rest continue.
//
// DLP: logs counts only. A failure names the host and the status, never the
// response body, an entity id or the token.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use talos_sdk_macros::talos_module;

const PROVIDER: &str = "home-assistant";
const MAX_COMMANDS: usize = 8;
const MAX_TARGETS: usize = 64;
const MAX_NAME_BYTES: usize = 64;

#[derive(Deserialize, Default)]
struct Cfg {
    #[serde(rename = "BASE_URL", default)]
    base_url: Option<String>,
    #[serde(rename = "AUTH_HEADER", default)]
    auth_header: Option<String>,
    #[serde(rename = "TARGETS", default)]
    targets: BTreeMap<String, Target>,
    #[serde(rename = "DRY_RUN", default)]
    dry_run: Option<bool>,
    #[serde(rename = "TIMEOUT_MS", default)]
    timeout_ms: Option<u32>,
}

#[derive(Deserialize)]
struct Target {
    /// The Home Assistant entity (`light.office`).
    #[serde(default)]
    entity: String,
    /// The actions this target allows. Empty allows nothing.
    #[serde(default)]
    allow: Vec<String>,
    /// Bounds on `set_temperature`'s value. Both are required to allow it.
    #[serde(default)]
    min: Option<f64>,
    #[serde(default)]
    max: Option<f64>,
}

#[derive(Deserialize)]
struct Command {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    value: Option<f64>,
}

#[derive(Deserialize)]
struct Incoming {
    #[serde(default)]
    config: Cfg,
    #[serde(default)]
    commands: Option<Vec<Command>>,
    #[serde(default)]
    skip: Option<bool>,
}

#[derive(Serialize)]
struct CommandResult {
    target: String,
    action: String,
    /// `done`, `dry_run`, `refused` or `failed`.
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
struct Verdict {
    provider: &'static str,
    skipped: bool,
    dry_run: bool,
    done: usize,
    refused: usize,
    failed: usize,
    /// Commands past the limit, not looked at.
    not_run: usize,
    results: Vec<CommandResult>,
}

#[derive(Serialize)]
struct ServiceCall<'a> {
    entity_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
}

fn clean_name(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_BYTES)
        .collect()
}

/// A neutral name: what a compose module or a model writes for a target.
fn usable_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_BYTES
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A Home Assistant entity id: `domain.object`, each part lowercase letters,
/// digits and `_`. It goes into a request body; nothing else is let through.
fn usable_entity(s: &str) -> bool {
    match s.split_once('.') {
        Some((domain, object)) => usable_name(domain) && usable_name(object),
        None => false,
    }
}

/// An https base address with no query or fragment, without its trailing `/`.
fn usable_base(s: &str) -> Result<String, String> {
    let s = s.trim();
    let ok = s.len() > "https://".len()
        && s.len() <= 2000
        && s.starts_with("https://")
        && s.bytes().all(|b| b.is_ascii_graphic())
        && !s.contains('?')
        && !s.contains('#');
    if !ok {
        return Err("BASE_URL must be an https:// address with no query".to_string());
    }
    Ok(s.trim_end_matches('/').to_string())
}

fn host_of(base: &str) -> &str {
    base.trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
}

/// The service a neutral action is, for this adapter. `None`: not an action
/// the contract defines.
fn service_for(action: &str) -> Option<&'static str> {
    match action {
        // `homeassistant.*` acts on any entity that can be switched,
        // including a scene or a script, so one path covers them.
        "turn_on" | "run" => Some("homeassistant/turn_on"),
        "turn_off" => Some("homeassistant/turn_off"),
        "toggle" => Some("homeassistant/toggle"),
        "set_temperature" => Some("climate/set_temperature"),
        _ => None,
    }
}

/// What to call for one command, or why it is refused. Pure: the whole
/// allow-list decision is here.
fn plan<'a>(
    targets: &'a BTreeMap<String, Target>,
    command: &Command,
) -> Result<(&'static str, &'a str, Option<f64>), &'static str> {
    let name = command.target.as_deref().unwrap_or("");
    let action = command.action.as_deref().unwrap_or("");
    let service = service_for(action).ok_or("unknown_action")?;
    let target = targets.get(name).ok_or("unknown_target")?;
    if !target.allow.iter().any(|a| a == action) {
        return Err("action_not_allowed");
    }
    if !usable_entity(&target.entity) {
        return Err("target_misconfigured");
    }
    let value = if action == "set_temperature" {
        let (Some(min), Some(max)) = (target.min, target.max) else {
            return Err("target_has_no_bounds");
        };
        let v = command.value.ok_or("value_missing")?;
        if !v.is_finite() || v < min || v > max {
            return Err("value_out_of_range");
        }
        Some(v)
    } else {
        None
    };
    Ok((service, target.entity.as_str(), value))
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};

    let incoming: Incoming = serde_json::from_str(&input)
        .map_err(|e| format!("could not read the node input: {e}"))?;
    let cfg = incoming.config;
    let base = usable_base(
        cfg.base_url
            .as_deref()
            .ok_or("Missing BASE_URL config (Home Assistant's external https:// address)")?,
    )?;
    let auth = cfg
        .auth_header
        .as_deref()
        .filter(|a| !a.trim().is_empty())
        .ok_or("Missing AUTH_HEADER config (expected 'Bearer vault://homeassistant/token')")?;
    if cfg.targets.is_empty() {
        return Err("Missing TARGETS config: the targets this node may act on, each with the actions it allows".to_string());
    }
    if cfg.targets.len() > MAX_TARGETS || cfg.targets.keys().any(|k| !usable_name(k)) {
        return Err(format!(
            "TARGETS must name at most {MAX_TARGETS} targets, each lowercase letters, digits and '_'"
        ));
    }
    let dry_run = cfg.dry_run.unwrap_or(true);

    let mut verdict = Verdict {
        provider: PROVIDER,
        skipped: false,
        dry_run,
        done: 0,
        refused: 0,
        failed: 0,
        not_run: 0,
        results: Vec::new(),
    };
    if incoming.skip == Some(true) {
        verdict.skipped = true;
        return serde_json::to_string(&verdict).map_err(|e| e.to_string());
    }
    let commands = incoming.commands.ok_or(
        "No commands: the upstream node's output has no `commands` list (docs/home-control-contract.md)",
    )?;
    verdict.not_run = commands.len().saturating_sub(MAX_COMMANDS);

    for command in commands.iter().take(MAX_COMMANDS) {
        let mut result = CommandResult {
            target: clean_name(command.target.as_deref().unwrap_or("")),
            action: clean_name(command.action.as_deref().unwrap_or("")),
            status: "refused",
            reason: None,
        };
        let (service, entity, value) = match plan(&cfg.targets, command) {
            Ok(planned) => planned,
            Err(why) => {
                verdict.refused += 1;
                result.reason = Some(why.to_string());
                verdict.results.push(result);
                continue;
            }
        };
        if dry_run {
            result.status = "dry_run";
            verdict.results.push(result);
            continue;
        }
        let body = serde_json::to_vec(&ServiceCall {
            entity_id: entity,
            temperature: value,
        })
        .map_err(|e| format!("could not build the request: {e}"))?;
        let req = talos::core::http::Request {
            method: talos::core::http::Method::Post,
            url: format!("{base}/api/services/{service}"),
            headers: vec![
                ("Authorization".to_string(), auth.to_string()),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            body,
            timeout_ms: Some(cfg.timeout_ms.unwrap_or(10_000).clamp(1_000, 30_000)),
        };
        match talos::core::http::fetch(&req) {
            Ok(resp) if (200..300).contains(&resp.status) => {
                result.status = "done";
                verdict.done += 1;
            }
            Ok(resp) => {
                result.status = "failed";
                result.reason = Some(format!("{} answered {}", host_of(&base), resp.status));
                verdict.failed += 1;
            }
            Err(_) => {
                result.status = "failed";
                result.reason = Some(format!("{} could not be reached", host_of(&base)));
                verdict.failed += 1;
            }
        }
        verdict.results.push(result);
    }

    logging::log(
        Level::Info,
        &format!(
            "control-home-assistant: {} done, {} refused, {} failed, dry_run={}",
            verdict.done, verdict.refused, verdict.failed, dry_run
        ),
    );
    serde_json::to_string(&verdict).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use talos_module_testkit::host;

    fn config(dry_run: bool) -> Value {
        json!({
            "BASE_URL": "https://home.example.test/",
            "AUTH_HEADER": "Bearer vault://homeassistant/token",
            "DRY_RUN": dry_run,
            "TARGETS": {
                "office_lights": { "entity": "light.made_up_office", "allow": ["turn_on", "turn_off"] },
                "thermostat": { "entity": "climate.made_up_hall", "allow": ["set_temperature"], "min": 16, "max": 24 },
                "bedtime": { "entity": "scene.made_up_bedtime", "allow": ["run"] },
                "unbounded": { "entity": "climate.made_up_attic", "allow": ["set_temperature"] },
                "front_door": { "entity": "lock.made_up_front", "allow": [] },
            },
        })
    }
    fn act(config: Value, upstream: Value) -> Result<Value, String> {
        let mut input = upstream;
        input["config"] = config;
        run(input.to_string()).map(|s| serde_json::from_str(&s).unwrap())
    }
    fn statuses(v: &Value) -> Vec<(String, String)> {
        v["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["status"].as_str().unwrap().to_string(),
                    r["reason"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn allowed_commands_become_service_calls() {
        host::http::respond(200, "[]");
        let v = act(
            config(false),
            json!({ "commands": [
                { "target": "office_lights", "action": "turn_off" },
                { "target": "thermostat", "action": "set_temperature", "value": 20.5 },
                { "target": "bedtime", "action": "run" },
            ] }),
        )
        .unwrap();
        assert_eq!((v["done"].clone(), v["refused"].clone(), v["failed"].clone()), (json!(3), json!(0), json!(0)));
        let sent: Vec<(String, Value)> = host::http::requests()
            .into_iter()
            .map(|r| (r.url, serde_json::from_slice(&r.body).unwrap()))
            .collect();
        assert_eq!(
            sent,
            vec![
                ("https://home.example.test/api/services/homeassistant/turn_off".to_string(), json!({ "entity_id": "light.made_up_office" })),
                ("https://home.example.test/api/services/climate/set_temperature".to_string(), json!({ "entity_id": "climate.made_up_hall", "temperature": 20.5 })),
                ("https://home.example.test/api/services/homeassistant/turn_on".to_string(), json!({ "entity_id": "scene.made_up_bedtime" })),
            ]
        );
        // The neutral words come back; the entity ids do not.
        assert!(!v.to_string().contains("made_up"), "{v}");
    }

    #[test]
    fn what_the_map_does_not_allow_is_refused_and_nothing_is_sent_for_it() {
        host::http::respond(200, "[]");
        let v = act(
            config(false),
            json!({ "commands": [
                { "target": "garage", "action": "turn_on" },
                { "target": "office_lights", "action": "toggle" },
                { "target": "front_door", "action": "turn_off" },
                { "target": "office_lights", "action": "unlock" },
                { "target": "thermostat", "action": "set_temperature", "value": 31 },
                { "target": "thermostat", "action": "set_temperature" },
                { "target": "unbounded", "action": "set_temperature", "value": 20 },
                // A model that writes the entity id itself gets nowhere.
                { "target": "lock.made_up_front", "action": "turn_off" },
            ] }),
        )
        .unwrap();
        assert_eq!((v["done"].clone(), v["refused"].clone()), (json!(0), json!(8)));
        let reasons: Vec<String> = statuses(&v).into_iter().map(|(_, r)| r).collect();
        assert_eq!(
            reasons,
            [
                "unknown_target", "action_not_allowed", "action_not_allowed", "unknown_action",
                "value_out_of_range", "value_missing", "target_has_no_bounds", "unknown_target"
            ]
        );
        assert!(host::http::requests().is_empty());
    }

    #[test]
    fn nothing_is_sent_unless_dry_run_is_turned_off() {
        let mut c = config(false);
        c.as_object_mut().unwrap().remove("DRY_RUN");
        let v = act(c, json!({ "commands": [{ "target": "office_lights", "action": "turn_on" }] })).unwrap();
        assert_eq!(v["dry_run"], json!(true), "the default is to send nothing");
        assert_eq!(statuses(&v), [("dry_run".to_string(), String::new())]);
        let skipped = act(config(false), json!({ "skip": true, "commands": [{ "target": "office_lights", "action": "turn_on" }] })).unwrap();
        assert_eq!(skipped["skipped"], json!(true));
        assert!(host::http::requests().is_empty());
    }

    #[test]
    fn one_failure_is_recorded_and_the_rest_continue() {
        host::http::respond_with(|req| {
            Ok(host::http::response(
                if req.url.ends_with("/turn_off") { 500 } else { 200 },
                r#"{"message":"entity light.made_up_office unavailable"}"#,
            ))
        });
        let v = act(
            config(false),
            json!({ "commands": [
                { "target": "office_lights", "action": "turn_off" },
                { "target": "office_lights", "action": "turn_on" },
            ] }),
        )
        .unwrap();
        assert_eq!(
            statuses(&v),
            [
                ("failed".to_string(), "home.example.test answered 500".to_string()),
                ("done".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn commands_past_the_limit_are_counted_not_run() {
        host::http::respond(200, "[]");
        let commands: Vec<Value> = (0..11).map(|_| json!({ "target": "office_lights", "action": "turn_on" })).collect();
        let v = act(config(false), json!({ "commands": commands })).unwrap();
        assert_eq!((v["done"].clone(), v["not_run"].clone()), (json!(8), json!(3)));
        assert_eq!(host::http::requests().len(), 8);
    }

    #[test]
    fn config_that_cannot_work_is_refused() {
        for (patch, why) in [
            (json!({ "BASE_URL": null }), "Missing BASE_URL"),
            (json!({ "BASE_URL": "http://192.168.1.50:8123" }), "https://"),
            (json!({ "AUTH_HEADER": null }), "Missing AUTH_HEADER"),
            (json!({ "TARGETS": {} }), "Missing TARGETS"),
            (json!({ "TARGETS": { "Bad Name": { "entity": "light.x", "allow": ["turn_on"] } } }), "TARGETS must name"),
        ] {
            let mut c = config(false);
            for (k, v) in patch.as_object().unwrap() {
                c[k] = v.clone();
            }
            let e = act(c, json!({ "commands": [] })).unwrap_err();
            assert!(e.contains(why), "{patch}: {e}");
        }
        assert!(act(config(false), json!({})).unwrap_err().contains("no `commands` list"));
        // An entity id that is not one never reaches a request.
        let mut c = config(false);
        c["TARGETS"]["office_lights"]["entity"] = json!("light.x\", \"entity_id\": \"lock.front");
        let v = act(c, json!({ "commands": [{ "target": "office_lights", "action": "turn_on" }] })).unwrap();
        assert_eq!(statuses(&v), [("refused".to_string(), "target_misconfigured".to_string())]);
    }
}
