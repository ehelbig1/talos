use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};
    use talos::core::secrets;
    use talos::core::http::{self, Method, Request};

    logging::log(Level::Info, "1. Starting GitHub Repo Analyzer module");

    let payload: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON input: {}", e))?;

    logging::log(Level::Info, "2. Parsed payload");

    let config_json = payload.get("config").unwrap_or(&payload);
    let repo = config_json.get("repository")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required 'repository' parameter".to_string())?;

    let search_pattern = config_json.get("search_pattern")
        .and_then(|v| v.as_str())
        .unwrap_or("(?i)(fix|bug|issue|feat)");

    let secret_name = config_json.get("secret_name")
        .and_then(|v| v.as_str())
        .unwrap_or("github_token");

    logging::log(Level::Info, "3. Extracted config");

    let token = secrets::get_secret(secret_name)
        .map_err(|e| format!(
            "Failed to retrieve GitHub PAT from secret '{}': {}. \
             Provision the secret via the Talos secrets vault before using this module. \
             For public repos without authentication, use github-analyzer-public (http-node).",
            secret_name, e
        ))?;

    logging::log(Level::Info, "4. Got secret");

    let search_words: Vec<&str> = search_pattern
        .split('|')
        .map(|s| s.trim_matches(|c| c == '(' || c == ')' || c == '?' || c == 'i'))
        .collect();

    logging::log(Level::Info, "5. Using simple substring match instead of Regex");

    let url = format!("https://api.github.com/repos/{}/commits?per_page=5", repo);
    let headers = vec![
        ("User-Agent".to_string(), "Talos-Automation-Node/1.0".to_string()),
        ("Accept".to_string(), "application/vnd.github.v3+json".to_string()),
        ("Authorization".to_string(), format!("Bearer {}", token)),
    ];

    let request = Request {
        method: Method::Get,
        url: url.clone(),
        headers,
        body: vec![],
        timeout_ms: Some(5000),
    };

    logging::log(Level::Info, "6. Sending HTTP request");

    let response = http::fetch(&request)
        .map_err(|e| format!("HTTP request failed: {:?}", e))?;

    if response.status != 200 {
        return Err(format!("GitHub API returned error status {}. Response body size: {}", response.status, response.body.len()));
    }

    logging::log(Level::Info, &format!("7. Got HTTP response. Body size: {}", response.body.len()));

    #[derive(serde::Deserialize)]
    struct GithubCommitAuthor {
        name: Option<String>,
        date: Option<String>,
    }
    
    #[derive(serde::Deserialize)]
    struct GithubCommitInner {
        message: Option<String>,
        author: Option<GithubCommitAuthor>,
    }
    
    #[derive(serde::Deserialize)]
    struct GithubCommit {
        sha: Option<String>,
        commit: Option<GithubCommitInner>,
    }

    // Safety: cap response body to 1MB to prevent WASM memory exhaustion
    if response.body.len() > 1_048_576 {
        return Err(format!("GitHub API response too large ({} bytes). Try a smaller repository or use per_page parameter.", response.body.len()));
    }

    let commits: Vec<GithubCommit> = serde_json::from_slice(&response.body)
        .map_err(|e| format!("Failed to parse GitHub JSON response ({} bytes, err: {})", response.body.len(), e))?;

    logging::log(Level::Info, &format!("8. Parsed {} commits", commits.len()));

    let mut total_commits = 0;
    let mut matched_commits = Vec::new();
    let mut oldest_commit_date: Option<String> = None;
    let mut newest_commit_date: Option<String> = None;

    for commit_obj in commits {
        total_commits += 1;

        let message = commit_obj.commit.as_ref().and_then(|c| c.message.clone()).unwrap_or_default();
        let date_str = commit_obj.commit.as_ref().and_then(|c| c.author.as_ref()).and_then(|a| a.date.clone()).unwrap_or_default();
        let sha = commit_obj.sha.clone().unwrap_or_default().chars().take(7).collect::<String>();
        let author = commit_obj.commit.as_ref().and_then(|c| c.author.as_ref()).and_then(|a| a.name.clone()).unwrap_or_else(|| "Unknown".to_string());

        if !date_str.is_empty() {
            if oldest_commit_date.as_ref().map_or(true, |old| &date_str < old) {
                oldest_commit_date = Some(date_str.clone());
            }
            if newest_commit_date.as_ref().map_or(true, |new| &date_str > new) {
                newest_commit_date = Some(date_str.clone());
            }
        }

        let msg_lower = message.to_lowercase();
        let mut is_match = false;
        for word in &search_words {
            if msg_lower.contains(&word.to_lowercase()) {
                is_match = true;
                break;
            }
        }

        if is_match {
            let first_line = message.lines().next().unwrap_or("");
            matched_commits.push(serde_json::json!({
                "sha": sha,
                "author": author,
                "date": date_str,
                "message": first_line
            }));
        }
    }

    logging::log(Level::Info, "9. Finished loop");

    let time_span = match (oldest_commit_date, newest_commit_date) {
        (Some(oldest), Some(newest)) => {
            format!("From {} to {}", oldest, newest)
        }
        _ => "Unknown".to_string()
    };

    let output = serde_json::json!({
        "success": true,
        "repository": repo,
        "analysis_stats": {
            "total_commits_checked": total_commits,
            "regex_pattern_used": search_pattern,
            "pattern_matches": matched_commits.len(),
            "time_span_of_commits": time_span,
        },
        "matched_commits": matched_commits,
    });

    logging::log(Level::Info, "10. Serialization done");

    serde_json::to_string(&output).map_err(|e| format!("Serialization error: {}", e))
}
