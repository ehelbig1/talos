#![allow(warnings)]
use serde_json::Value;
use talos::core::http::{fetch, Method, Request};
use talos::core::logging::{self, Level};
use talos::core::secrets::get_secret;
use talos_sdk_macros::talos_node;

// The capability world is selected by THIS attribute (it drives WIT bindgen via
// the scaffold's extract_wit_world), NOT by talos.json. Bare `#[talos_node]`
// defaults to `minimal-node`, which has no `http` / `secrets` interfaces — so the
// `talos::core::{http,secrets}` imports above won't resolve. This module needs
// both (GitHub + OpenAI HTTP, get_secret). Keep in sync with talos.json
// `capability_world` — lint-structural.sh check 48 enforces the match.
#[talos_node(world = "secrets-node")]
pub fn run(
    github_webhook_payload: String,
    github_token_secret: String,
    openai_api_key_secret: String,
    openai_model: String,
) -> Result<String, String> {
    // 1. Parse payload
    let payload: Value = serde_json::from_str(&github_webhook_payload)
        .map_err(|e| format!("Invalid webhook payload JSON: {}", e))?;

    // Check if it's a pull request event
    let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if action != "opened" && action != "synchronize" {
        return Ok("Skipping: Event is not a PR opened or synchronize action.".to_string());
    }

    let pr = payload
        .get("pull_request")
        .ok_or("No 'pull_request' object in payload")?;
    let pr_number = pr
        .get("number")
        .and_then(|v| v.as_i64())
        .ok_or("No PR number")?;
    let diff_url = pr
        .get("diff_url")
        .and_then(|v| v.as_str())
        .ok_or("No diff_url")?;
    let comments_url = pr
        .get("comments_url")
        .and_then(|v| v.as_str())
        .ok_or("No comments_url")?;

    let github_token = get_secret(&github_token_secret).map_err(|e| {
        format!(
            "Failed to load GitHub token from {}: {}",
            github_token_secret, e
        )
    })?;

    let openai_key = get_secret(&openai_api_key_secret).map_err(|e| {
        format!(
            "Failed to load OpenAI token from {}: {}",
            openai_api_key_secret, e
        )
    })?;

    logging::log(Level::Info, &format!("Reviewing PR #{}", pr_number));

    // 2. Fetch Diff
    let diff_req = Request {
        method: Method::Get,
        url: diff_url.to_string(),
        headers: vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", github_token),
            ),
            (
                "Accept".to_string(),
                "application/vnd.github.v3.diff".to_string(),
            ),
            ("User-Agent".to_string(), "Talos-Reviewer".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(10000),
    };

    let diff_resp = fetch(&diff_req).map_err(|e| format!("Failed to fetch PR diff: {:?}", e))?;
    if diff_resp.status != 200 {
        return Err(format!(
            "GitHub API returned {} when fetching diff",
            diff_resp.status
        ));
    }

    let diff_text = String::from_utf8_lossy(&diff_resp.body).to_string();

    if diff_text.trim().is_empty() {
        return Ok("No changes in PR diff, skipping review.".to_string());
    }

    // 3. Call LLM
    let system_prompt = "You are an expert strict Senior Engineer. Review the following code diff for bugs, performance issues, or bad practices. Output your review as a polite, concise Markdown comment. Provide code snippets if suggesting changes.";

    let llm_body = serde_json::json!({
        "model": openai_model,
        "messages": [
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": format!("Here is the PR diff:\n```diff\n{}\n```", diff_text) }
        ],
        "max_tokens": 1500
    });

    let llm_req = Request {
        method: Method::Post,
        url: "https://api.openai.com/v1/chat/completions".to_string(),
        headers: vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", openai_key),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: serde_json::to_vec(&llm_body).unwrap(),
        timeout_ms: Some(60000),
    };

    let llm_resp = fetch(&llm_req).map_err(|e| format!("Failed to call OpenAI: {:?}", e))?;
    if llm_resp.status != 200 {
        return Err(format!("OpenAI API returned status {}", llm_resp.status));
    }

    let llm_json: Value = serde_json::from_slice(&llm_resp.body)
        .map_err(|_| "Failed to parse OpenAI JSON".to_string())?;

    let review_comment = llm_json["choices"][0]["message"]["content"]
        .as_str()
        .ok_or("Failed to extract content from LLM response")?;

    logging::log(Level::Info, "Generated LLM review. Posting to GitHub.");

    // 4. Post Comment
    let comment_body = serde_json::json!({
        "body": format!("🤖 **Talos Auto-Review:**\n\n{}", review_comment)
    });

    let comment_req = Request {
        method: Method::Post,
        url: comments_url.to_string(),
        headers: vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", github_token),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "Talos-Reviewer".to_string()),
        ],
        body: serde_json::to_vec(&comment_body).unwrap(),
        timeout_ms: Some(10000),
    };

    let comment_resp =
        fetch(&comment_req).map_err(|e| format!("Failed to post comment: {:?}", e))?;
    if comment_resp.status != 201 {
        return Err(format!(
            "GitHub API returned status {} when posting comment",
            comment_resp.status
        ));
    }

    Ok(format!(
        "Successfully reviewed PR #{} and posted comment.",
        pr_number
    ))
}
