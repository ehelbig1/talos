use crate::talos::core::{agent_memory, datetime, http, llm, logging, secrets};
use crate::{host, talos::MIRRORED};
use std::collections::BTreeSet;

/// Every function of an interface in the WIT, by reading the file.
fn wit_functions(wit: &str, interface: &str) -> BTreeSet<String> {
    let start = wit
        .find(&format!("\ninterface {interface} {{"))
        .unwrap_or_else(|| panic!("interface {interface} is not in wit/talos.wit"));
    let body = &wit[start + 1..];
    // The interface ends at the first `}` in column 0.
    let end = body.find("\n}").expect("interface end");
    body[..end]
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let (name, rest) = l.split_once(':')?;
            (rest.trim_start().starts_with("func(") && !name.contains(' '))
                .then(|| name.to_string())
        })
        .collect()
}

/// The mirror has exactly the functions the WIT has, for each interface it
/// mirrors: one renamed, removed or added there fails here.
#[test]
fn every_mirrored_function_is_in_the_wit() {
    let wit = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../wit/talos.wit"))
        .expect("wit/talos.wit");
    assert!(MIRRORED.len() >= 6, "the table lost entries");
    for (interface, functions) in MIRRORED {
        let mirrored: BTreeSet<String> = functions.iter().map(|f| (*f).to_string()).collect();
        assert_eq!(
            mirrored,
            wit_functions(&wit, interface),
            "interface {interface}"
        );
    }
}

#[test]
fn http_is_answered_by_the_test_and_never_by_a_network() {
    let req = http::Request {
        method: http::Method::Post,
        url: "https://example.test/a".into(),
        headers: vec![],
        body: b"{}".to_vec(),
        timeout_ms: Some(1000),
    };
    assert_eq!(
        http::fetch(&req).unwrap_err(),
        http::Error::Networkerror,
        "no responder, no network"
    );

    host::http::respond_with(|r| {
        if r.url.ends_with("/a") {
            Ok(host::http::response(200, "first"))
        } else {
            Err(http::Error::Timeout)
        }
    });
    assert_eq!(http::fetch(&req).unwrap().body, b"first");
    let other = http::Request {
        url: "https://example.test/b".into(),
        ..req.clone()
    };
    let all = http::fetch_all(&[req.clone(), other]);
    assert_eq!(all[0].as_ref().unwrap().status, 200);
    assert_eq!(all[1].as_ref().unwrap_err(), &http::Error::Timeout);
    let seen: Vec<String> = host::http::requests().into_iter().map(|r| r.url).collect();
    assert_eq!(
        seen.len(),
        4,
        "every request is recorded, answered or not: {seen:?}"
    );
}

#[test]
fn one_tests_setup_is_not_seen_by_another_thread() {
    host::memory::put("k", "v");
    host::http::respond(200, "x");
    let elsewhere = std::thread::spawn(|| {
        let req = http::Request {
            method: http::Method::Get,
            url: "https://example.test".into(),
            headers: vec![],
            body: vec![],
            timeout_ms: None,
        };
        (agent_memory::get("k"), http::fetch(&req).map(|r| r.status))
    })
    .join()
    .unwrap();
    assert_eq!(
        elsewhere,
        (
            Err(agent_memory::Error::KeyNotFound),
            Err(http::Error::Networkerror)
        )
    );
}

#[test]
fn memory_tells_absent_from_unreachable() {
    assert!(agent_memory::get_entry("list/mine").unwrap().is_none());
    agent_memory::set("list/mine", "{}").unwrap();
    assert_eq!(
        agent_memory::get_entry("list/mine").unwrap().unwrap().value,
        "{}"
    );
    assert_eq!(
        agent_memory::list_keys(Some("list/")).unwrap(),
        vec!["list/mine"]
    );
    host::memory::fail(true);
    assert_eq!(
        agent_memory::get_entry("list/mine").unwrap_err(),
        agent_memory::Error::NotAvailable
    );
    assert_eq!(
        agent_memory::set("a", "b").unwrap_err(),
        agent_memory::Error::NotAvailable
    );
    host::memory::fail(false);
    agent_memory::delete("list/mine").unwrap();
    assert_eq!(
        agent_memory::get("list/mine").unwrap_err(),
        agent_memory::Error::KeyNotFound
    );
}

#[test]
fn a_secret_is_a_handle_and_signing_is_a_real_hmac() {
    let h = secrets::get_secret("any/path").unwrap();
    assert_eq!(
        secrets::hmac_sign(h, b"data").unwrap(),
        secrets::test_hmac(secrets::TEST_KEY, b"data")
    );
    // RFC 4231 test case 2.
    let known = secrets::test_hmac(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(known[..4], [0x5b, 0xdc, 0xc1, 0x46]);

    host::secrets::put("auth/key", b"other".to_vec());
    let other = secrets::get_secret("auth/key").unwrap();
    assert_ne!(
        secrets::hmac_sign(other, b"data").unwrap(),
        secrets::hmac_sign(h, b"data").unwrap()
    );
    assert_eq!(
        secrets::resolve_config_vault("vault://auth/key").map(|_| ()),
        Ok(())
    );
    assert_eq!(
        secrets::resolve_config_vault("auth/key"),
        Err(secrets::Error::Notfound)
    );

    secrets::release_slot(h).unwrap();
    assert_eq!(
        secrets::hmac_sign(h, b"data"),
        Err(secrets::Error::Notfound),
        "a released handle signs nothing"
    );
    assert_eq!(secrets::release_slot(h), Err(secrets::Error::Notfound));
    assert_eq!(
        secrets::hmac_sign(0, b"data"),
        Err(secrets::Error::Notfound)
    );
    assert_eq!(
        secrets::expose_secret(other, "why"),
        Err(secrets::Error::Unauthorized)
    );

    host::secrets::deny("gone");
    assert_eq!(secrets::get_secret("gone"), Err(secrets::Error::Notfound));
}

#[test]
fn the_clock_can_be_set_and_zones_follow_their_own_rules() {
    host::clock::set_unix(1_780_000_000);
    assert_eq!(datetime::now_unix(), 1_780_000_000);
    assert_eq!(datetime::now_iso(), "2026-05-28T20:26:40Z");
    assert_eq!(
        datetime::parse("2026-05-28T20:26:40Z", None),
        Ok(1_780_000_000)
    );
    assert_eq!(
        datetime::format(1_780_000_000, "%Y-%m-%d").unwrap(),
        "2026-05-28"
    );
    // New York: daylight time in July, standard time in January.
    assert_eq!(
        datetime::local_offset_seconds("America/New_York", 1_783_000_000),
        Ok(-4 * 3600)
    );
    assert_eq!(
        datetime::local_offset_seconds("America/New_York", 1_768_000_000),
        Ok(-5 * 3600)
    );
    for bad in ["", "america/new_york", "Not/AZone"] {
        assert_eq!(
            datetime::local_offset_seconds(bad, 0),
            Err(datetime::Error::Invalidformat),
            "{bad}"
        );
    }
    assert_eq!(datetime::add_seconds(10, -3), 7);
    assert_eq!(datetime::diff_seconds(10, 13), -3);
}

#[test]
fn the_model_answers_only_when_the_test_says_so() {
    let req = llm::CompletionRequest {
        provider: Some(llm::Provider::Ollama),
        model: Some("m".into()),
        messages: vec![llm::Message {
            role: llm::Role::User,
            content: "hi".into(),
        }],
        max_tokens: None,
        temperature: None,
        system_prompt: None,
    };
    assert!(matches!(
        llm::complete(&req),
        Err(llm::Error::NotConfigured(_))
    ));
    host::llm::respond("hello");
    assert_eq!(
        llm::complete_with_options(&req, Some("{}")).unwrap().text,
        "hello"
    );
    assert_eq!(host::llm::requests().len(), 2);
    logging::log(logging::Level::Info, "done");
    assert_eq!(
        host::log::lines(),
        vec![(logging::Level::Info, "done".to_string())]
    );
}
