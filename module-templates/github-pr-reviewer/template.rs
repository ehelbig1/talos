#![allow(warnings)]
use serde_json::Value;
use talos::core::http::{fetch_with_bearer, Method, Request};
use talos::core::llm::{self, CompletionRequest, Message, Provider, Role};
use talos::core::logging::{self, Level};
use talos::core::secrets::get_secret;
use talos_sdk_macros::talos_module;

// Capability world is selected by THIS macro attribute (it drives WIT bindgen via
// the scaffold's extract_wit_world), NOT by talos.json. `secrets-node` gives us
// `http` + `secrets` + `llm`. Keep in sync with talos.json `capability_world`
// (lint-structural.sh check 48 enforces the match).
//
// This module is a PR reviewer triggered by a GitHub `pull_request` webhook. The
// event payload arrives as the node INPUT (`envelope.input`), and settings arrive
// as the node CONFIG (`envelope.config`). It must therefore use `talos_module`
// (raw envelope) — NOT `talos_node`, whose typed args are all read from `config`
// and so cannot receive runtime webhook input.
//
// LLM: review generation goes through the host `llm::complete` function, which
// resolves the provider's API key host-side (vault-first) and enforces the actor's
// tier ceiling. A Tier-1 actor (or LLM_PROVIDER=ollama) runs a LOCAL model with NO
// API key — this module never reads an LLM secret. Only the GitHub token is a
// module secret, resolved to a Tier-1 host-side slot handle (never plaintext in
// WASM) and used via `fetch_with_bearer`.
#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    // Engine envelope: { "config": {...}, "input": <PR webhook event>, ... }
    let envelope: Value =
        serde_json::from_str(&input).map_err(|e| format!("Invalid envelope JSON: {}", e))?;
    let config = envelope.get("config").cloned().unwrap_or(Value::Null);

    // ── Config (keys MUST match talos.json config_schema) ──────────────
    let github_token_secret = config
        .get("GITHUB_TOKEN_SECRET")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or("Missing 'GITHUB_TOKEN_SECRET' config — a PAT secret path (e.g. 'github/token') \
                or a GitHub App installation via 'github_app:<owner>'")?;

    // LLM provider/model are OPTIONAL. The host resolves any required API key
    // vault-first and enforces the tier ceiling — no LLM secret is read here.
    //  • unset    → the host's configured default provider (+ tier enforcement)
    //  • ollama   → LOCAL model, no API key (also forced for Tier-1 actors)
    //  • external → key resolved from the platform vault (e.g. anthropic/api_key)
    let provider_str = config
        .get("LLM_PROVIDER")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let provider = match provider_str.as_str() {
        "" => None,
        "anthropic" => Some(Provider::Anthropic),
        "openai" => Some(Provider::Openai),
        "gemini" => Some(Provider::Gemini),
        "ollama" | "local" => Some(Provider::Ollama),
        other => {
            return Err(format!(
                "Unknown LLM_PROVIDER '{}' — use one of: anthropic, openai, gemini, ollama",
                other
            ))
        }
    };
    let model = config
        .get("LLM_MODEL")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let expected_repo = config
        .get("REPOSITORY")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // ── The PR webhook event arrives as the node input ─────────────────
    // It may be a JSON object, or a JSON string needing a second parse.
    let event: Value = match envelope.get("input") {
        Some(Value::String(s)) if !s.trim().is_empty() => serde_json::from_str(s)
            .map_err(|e| format!("Node input is a string but not valid JSON: {}", e))?,
        Some(v) if !v.is_null() => v.clone(),
        _ => {
            return Ok("No pull_request event in input — nothing to review. Trigger this \
                       module from a GitHub PR webhook, or pass a sample PR 'opened' / \
                       'synchronize' event as the node input."
                .to_string())
        }
    };

    // Only act on opened / synchronize PR events.
    let action = event.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if action != "opened" && action != "synchronize" {
        return Ok(format!(
            "Skipping: event action '{}' is not 'opened' or 'synchronize'.",
            action
        ));
    }

    // Scope guard: only review PRs for the configured repository.
    if !expected_repo.is_empty() {
        let event_repo = event
            .get("repository")
            .and_then(|r| r.get("full_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !event_repo.is_empty() && event_repo != expected_repo {
            return Ok(format!(
                "Skipping: PR repo '{}' does not match configured REPOSITORY '{}'.",
                event_repo, expected_repo
            ));
        }
    }

    let pr = event
        .get("pull_request")
        .ok_or("No 'pull_request' object in the event payload")?;
    let pr_number = pr
        .get("number")
        .and_then(|v| v.as_i64())
        .ok_or("No PR number in payload")?;
    // Use the API resource URL (api.github.com) + a diff Accept header rather than
    // `diff_url` (which points at github.com, outside this module's allowed_hosts).
    let pr_api_url = pr
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("No pull_request.url (api.github.com resource) in payload")?;
    let comments_url = pr
        .get("comments_url")
        .and_then(|v| v.as_str())
        .ok_or("No comments_url in payload")?;

    // Resolve the GitHub token to a host-side slot handle (Tier-1 safe — plaintext
    // never enters WASM; `fetch_with_bearer` injects the real token host-side).
    let github_slot = get_secret(github_token_secret).map_err(|e| {
        format!(
            "Failed to resolve GitHub token '{}': {:?}",
            github_token_secret, e
        )
    })?;

    logging::log(Level::Info, &format!("Reviewing PR #{}", pr_number));

    // ── 1. Fetch the diff (api.github.com, diff media type) ────────────
    let diff_req = Request {
        method: Method::Get,
        url: pr_api_url.to_string(),
        headers: vec![
            (
                "Accept".to_string(),
                "application/vnd.github.v3.diff".to_string(),
            ),
            ("User-Agent".to_string(), "Talos-Reviewer".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(15000),
    };
    let diff_resp =
        fetch_with_bearer(github_slot, &diff_req).map_err(|e| format!("Failed to fetch PR diff: {:?}", e))?;
    if diff_resp.status != 200 {
        return Err(format!(
            "GitHub returned {} fetching the diff for PR #{}",
            diff_resp.status, pr_number
        ));
    }
    let mut diff_text = String::from_utf8_lossy(&diff_resp.body).to_string();
    if diff_text.trim().is_empty() {
        return Ok(format!("PR #{} diff is empty — nothing to review.", pr_number));
    }
    // Cap the diff sent to the LLM (bounds tokens + WASM fuel). Truncate on a char
    // boundary to avoid a UTF-8 panic.
    const MAX_DIFF_BYTES: usize = 48_000;
    if diff_text.len() > MAX_DIFF_BYTES {
        let mut cut = MAX_DIFF_BYTES;
        while !diff_text.is_char_boundary(cut) {
            cut -= 1;
        }
        diff_text.truncate(cut);
        diff_text.push_str("\n…[diff truncated for review]…");
    }

    // ── 2. Generate the review via the host LLM ────────────────────────
    // Key resolution + provider egress happen host-side; a Tier-1 actor (or
    // LLM_PROVIDER=ollama) runs locally with no API key.
    let system_prompt = "You are an expert, strict senior engineer. Review the code diff for bugs, \
        security issues, performance problems, and bad practices. Respond with a concise, polite \
        Markdown comment. Include code snippets for any suggested changes.";
    let review_req = CompletionRequest {
        provider,
        model,
        messages: vec![Message {
            role: Role::User,
            content: format!("Here is the PR diff:\n```diff\n{}\n```", diff_text),
        }],
        max_tokens: Some(1500),
        temperature: Some(0.2),
        system_prompt: Some(system_prompt.to_string()),
    };
    let completion =
        llm::complete(&review_req).map_err(|e| format!("LLM completion failed: {:?}", e))?;
    let review = completion.text;
    if review.trim().is_empty() {
        return Err("LLM returned an empty review".to_string());
    }

    logging::log(Level::Info, "Generated review; posting comment to GitHub.");

    // ── 3. Post the review as a PR comment ─────────────────────────────
    // A read-only GitHub App installation can't comment (403); in that case still
    // return the generated review so the node output is useful.
    let comment_body = serde_json::json!({
        "body": format!("🤖 **Talos Auto-Review**\n\n{}", review)
    });
    let comment_req = Request {
        method: Method::Post,
        url: comments_url.to_string(),
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "Talos-Reviewer".to_string()),
        ],
        body: serde_json::to_vec(&comment_body).map_err(|e| format!("encode comment: {}", e))?,
        timeout_ms: Some(15000),
    };
    let post = fetch_with_bearer(github_slot, &comment_req)
        .map_err(|e| format!("Failed to post comment: {:?}", e))?;
    let posted = post.status == 201;
    if !posted {
        logging::log(
            Level::Warn,
            &format!(
                "Review generated but POST comment returned {} (a read-only GitHub App \
                 installation cannot comment). Returning the review in the node output.",
                post.status
            ),
        );
    }

    Ok(serde_json::json!({
        "pr_number": pr_number,
        "model": completion.model,
        "posted": posted,
        "post_status": post.status,
        "review": review,
    })
    .to_string())
}
