use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value =
        serde_json::from_str(&input).map_err(|e| format!("Invalid JSON input: {}", e))?;
    let config = input_json
        .get("config")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    // ── Extract config ───────────────────────────────────────────────────
    let embedding_api_url = config
        .get("EMBEDDING_API_URL")
        .and_then(|v| v.as_str())
        .ok_or("Missing required config: EMBEDDING_API_URL")?;
    let embedding_model = config
        .get("EMBEDDING_MODEL")
        .and_then(|v| v.as_str())
        .unwrap_or("text-embedding-3-small");
    let embedding_key_path = config
        .get("EMBEDDING_API_KEY_SECRET")
        .and_then(|v| v.as_str())
        .ok_or("Missing required config: EMBEDDING_API_KEY_SECRET")?;

    let vector_db_url = config
        .get("VECTOR_DB_URL")
        .and_then(|v| v.as_str())
        .ok_or("Missing required config: VECTOR_DB_URL")?;
    let vector_db_key_path = config
        .get("VECTOR_DB_API_KEY_SECRET")
        .and_then(|v| v.as_str());

    let top_k = config
        .get("TOP_K")
        .and_then(|v| v.as_u64())
        .unwrap_or(5)
        .min(50)
        .max(1) as u32;

    let llm_api_url = config
        .get("LLM_API_URL")
        .and_then(|v| v.as_str())
        .unwrap_or("https://api.openai.com/v1/chat/completions");
    let llm_model = config
        .get("LLM_MODEL")
        .and_then(|v| v.as_str())
        .unwrap_or("gpt-4o");
    let llm_key_path = config
        .get("LLM_API_KEY_SECRET")
        .and_then(|v| v.as_str())
        .ok_or("Missing required config: LLM_API_KEY_SECRET")?;

    let system_prompt = config.get("SYSTEM_PROMPT").and_then(|v| v.as_str()).unwrap_or(
        "You are a helpful assistant. Answer the user's question using ONLY the provided context documents. If the context does not contain enough information, say so explicitly. Do not make up information.",
    );
    let max_tokens = config
        .get("MAX_TOKENS")
        .and_then(|v| v.as_u64())
        .unwrap_or(1024);
    let score_threshold = config
        .get("SCORE_THRESHOLD")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    // ── Extract the query from input ─────────────────────────────────────
    let data = input_json
        .get("input")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let query = data
        .get("query")
        .and_then(|v| v.as_str())
        .or_else(|| data.as_str())
        .ok_or(
            "Missing 'query' in input. Expected {\"query\": \"your question here\"}",
        )?
        .to_string();

    if query.is_empty() {
        return Err("Query must not be empty".to_string());
    }

    use talos::core::http::{Method, Request};

    // ── Step 1: Generate embedding ───────────────────────────────────────
    let embedding_slot = talos::core::secrets::get_secret(embedding_key_path)
        .map_err(|e| format!("Failed to retrieve embedding API key '{}': {:?}", embedding_key_path, e))?;

    let embedding_body = serde_json::json!({
        "model": embedding_model,
        "input": query,
    });

    let embedding_request = Request {
        method: Method::Post,
        url: embedding_api_url.to_string(),
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: serde_json::to_vec(&embedding_body).unwrap(),
        timeout_ms: Some(15000),
    };

    let embedding_resp = talos::core::http::fetch_with_bearer(embedding_slot, &embedding_request)
        .map_err(|e| format!("Embedding API request failed: {:?}", e))?;

    if embedding_resp.status >= 400 {
        let body_str = String::from_utf8(embedding_resp.body)
            .unwrap_or_else(|_| "<non-utf8>".to_string());
        return Err(format!(
            "Embedding API error (HTTP {}): {}",
            embedding_resp.status,
            body_str.chars().take(500).collect::<String>()
        ));
    }

    let embedding_response: serde_json::Value = serde_json::from_slice(&embedding_resp.body)
        .map_err(|e| format!("Invalid JSON from embedding API: {}", e))?;

    // Extract the embedding vector: data[0].embedding
    let embedding_vector = embedding_response
        .get("data")
        .and_then(|d| d.get(0))
        .and_then(|d| d.get("embedding"))
        .ok_or("Embedding API response missing data[0].embedding")?
        .clone();

    // ── Step 2: Search vector store ──────────────────────────────────────
    let vector_query_body = serde_json::json!({
        "vector": embedding_vector,
        "topK": top_k,
        "includeMetadata": true,
    });

    let vector_request = Request {
        method: Method::Post,
        url: vector_db_url.to_string(),
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: serde_json::to_vec(&vector_query_body).unwrap(),
        timeout_ms: Some(15000),
    };

    let vector_resp = if let Some(vdb_key_path) = vector_db_key_path {
        let vdb_slot = talos::core::secrets::get_secret(vdb_key_path)
            .map_err(|e| format!("Failed to retrieve vector DB API key '{}': {:?}", vdb_key_path, e))?;
        talos::core::http::fetch_with_header(vdb_slot, "Api-Key", &vector_request)
            .map_err(|e| format!("Vector DB request failed: {:?}", e))?
    } else {
        talos::core::http::fetch(&vector_request)
            .map_err(|e| format!("Vector DB request failed: {:?}", e))?
    };

    if vector_resp.status >= 400 {
        let body_str = String::from_utf8(vector_resp.body)
            .unwrap_or_else(|_| "<non-utf8>".to_string());
        return Err(format!(
            "Vector DB error (HTTP {}): {}",
            vector_resp.status,
            body_str.chars().take(500).collect::<String>()
        ));
    }

    let vector_response: serde_json::Value = serde_json::from_slice(&vector_resp.body)
        .map_err(|e| format!("Invalid JSON from vector DB: {}", e))?;

    // Extract matches — supports both Pinecone-style {matches: [...]} and
    // generic {results: [...]} response formats.
    let matches = vector_response
        .get("matches")
        .or_else(|| vector_response.get("results"))
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();

    // Filter by score threshold and build context documents
    let mut sources: Vec<serde_json::Value> = Vec::new();
    let mut context_parts: Vec<String> = Vec::new();

    for (idx, m) in matches.iter().enumerate() {
        let score = m
            .get("score")
            .and_then(|s| s.as_f64())
            .unwrap_or(0.0);

        if score < score_threshold {
            continue;
        }

        // Extract text from metadata.text, metadata.content, or metadata.page_content
        let metadata = m.get("metadata").cloned().unwrap_or(serde_json::json!({}));
        let text = metadata
            .get("text")
            .or_else(|| metadata.get("content"))
            .or_else(|| metadata.get("page_content"))
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();

        if !text.is_empty() {
            context_parts.push(format!("[Document {}] (score: {:.4})\n{}", idx + 1, score, text));
        }

        sources.push(serde_json::json!({
            "text": text,
            "score": score,
            "metadata": metadata,
        }));
    }

    let source_count = sources.len();

    if context_parts.is_empty() {
        let result = serde_json::json!({
            "answer": "No relevant documents found in the vector store for this query.",
            "query": query,
            "sources": [],
            "source_count": 0,
            "model": llm_model,
        });
        return serde_json::to_string(&result)
            .map_err(|e| format!("Failed to serialize output: {}", e));
    }

    // ── Step 3: Synthesize answer with LLM ───────────────────────────────
    let context_block = context_parts.join("\n\n");

    // Cap context to prevent exceeding token limits (roughly 100k chars)
    let truncated_context = if context_block.len() > 100_000 {
        format!(
            "{}\n[TRUNCATED: context exceeded 100,000 characters]",
            &context_block[..100_000]
        )
    } else {
        context_block
    };

    let user_message = format!(
        "Context documents:\n<context>\n{}\n</context>\n\nQuestion: {}",
        truncated_context, query
    );

    let llm_slot = talos::core::secrets::get_secret(llm_key_path)
        .map_err(|e| format!("Failed to retrieve LLM API key '{}': {:?}", llm_key_path, e))?;

    let llm_body = serde_json::json!({
        "model": llm_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
    });

    let llm_request = Request {
        method: Method::Post,
        url: llm_api_url.to_string(),
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: serde_json::to_vec(&llm_body).unwrap(),
        timeout_ms: Some(30000),
    };

    let llm_resp = talos::core::http::fetch_with_bearer(llm_slot, &llm_request)
        .map_err(|e| format!("LLM API request failed: {:?}", e))?;

    if llm_resp.status == 401 || llm_resp.status == 403 {
        let body_str = String::from_utf8(llm_resp.body)
            .unwrap_or_else(|_| "<non-utf8>".to_string());
        return Err(format!(
            "LLM API authentication error (HTTP {}): {} -- check LLM_API_KEY_SECRET.",
            llm_resp.status,
            body_str.chars().take(500).collect::<String>()
        ));
    }
    if llm_resp.status == 429 {
        let body_str = String::from_utf8(llm_resp.body)
            .unwrap_or_else(|_| "<non-utf8>".to_string());
        return Err(format!(
            "LLM API rate limit (HTTP 429): {}",
            body_str.chars().take(300).collect::<String>()
        ));
    }
    if llm_resp.status >= 400 {
        let body_str = String::from_utf8(llm_resp.body)
            .unwrap_or_else(|_| "<non-utf8>".to_string());
        return Err(format!(
            "LLM API error (HTTP {}): {}",
            llm_resp.status,
            body_str.chars().take(500).collect::<String>()
        ));
    }

    let llm_response: serde_json::Value = serde_json::from_slice(&llm_resp.body)
        .map_err(|e| format!("Invalid JSON from LLM API: {}", e))?;

    // 1MB safety cap
    let llm_body_len = llm_resp.body.len();
    if llm_body_len > 1_048_576 {
        return Err("LLM response exceeds 1MB safety limit".to_string());
    }

    let answer = llm_response
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or("Failed to extract answer from LLM response")?
        .to_string();

    // Strip markdown fences if present
    let answer_clean = {
        let trimmed = answer.trim();
        if let Some(after) = trimmed
            .strip_prefix("```json")
            .or_else(|| trimmed.strip_prefix("```"))
        {
            after
                .trim_start_matches('\n')
                .trim_end_matches("```")
                .trim()
                .to_string()
        } else {
            trimmed.to_string()
        }
    };

    let result = serde_json::json!({
        "answer": answer_clean,
        "query": query,
        "sources": sources,
        "source_count": source_count,
        "model": llm_model,
    });

    serde_json::to_string(&result).map_err(|e| format!("Failed to serialize output: {}", e))
}
