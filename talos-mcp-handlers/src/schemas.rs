pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "describe_capability_world",
            "description": "Describe the WIT host functions and interfaces available in a given capability world. \
                Accepts both short form ('minimal', 'http') and suffixed form ('minimal-node', 'http-node') — they are equivalent. \
                Note: the short names returned here correspond to the capability_world values used in \
                compile_custom_sandbox, run_sandbox, hot_update_module, and create_actor with a '-node' suffix appended — \
                e.g. 'minimal' → 'minimal-node', 'automation' → 'automation-node'. \
                'llm-node' and 'network-node' are actor capability ceilings, NOT compile worlds — calling with those names returns a clarifying error pointing at the right compile world (typically 'secrets' for LLM access).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "capability_world": { "type": "string", "description": "Capability world (compile worlds): short form 'minimal' | 'http' | 'secrets' | 'filesystem' | 'messaging' | 'cache' | 'database' | 'governance' | 'agent' | 'automation', or suffixed form ('minimal-node', 'http-node', 'agent-node', etc.). Both are accepted." }
                },
                "required": ["capability_world"]
            }
        }),
        serde_json::json!({
            "name": "test_condition",
            "description": "Test a Rhai condition expression against a JSON payload. Returns whether the condition evaluates to true or false, or any parse error.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "condition": { "type": "string", "description": "Rhai condition expression (e.g. 'score >= 50', 'status == \"ok\"')" },
                    "payload": { "type": "object", "description": "JSON object to evaluate the condition against" }
                },
                "required": ["condition", "payload"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_graph",
            "description": "Get a simplified, visual-friendly DAG representation of a workflow. Shows nodes as 'name (module) [world]' and edges as 'source -> target [condition]'.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "set_workflow_priority",
            "description": "Set the execution priority for a workflow. Priority is stored on execution records for visibility and dispatch ordering.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "priority": { "type": "string", "description": "Priority level: 'high', 'normal', or 'low'" }
                },
                "required": ["workflow_id", "priority"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_input_schema",
            "description": "Infer a JSON schema for a workflow's expected input by analyzing recent completed executions' trigger input data. Returns property types, required vs optional keys, and sample values. Set confirm_inferred_schema=true to immediately apply the inferred schema via set_workflow_input_schema in a single call.\n\nDETAILS: Looks at up to 10 most-recent completed executions WITH non-null output_data containing a `__trigger_input__` field. Scheduler-fired runs that don't carry trigger payloads, runs whose output_data was redacted, and pre-output-encryption legacy rows are excluded. The response surfaces `based_on_executions` (the actual inference sample size), `total_successful_executions` (the wider count for context), and `excluded_count` (the delta) so a small sample size is self-explanatory rather than mysterious.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "confirm_inferred_schema": { "type": "boolean", "description": "If true, immediately applies the inferred schema to the workflow (equivalent to calling set_workflow_input_schema with the inferred result). Default: false — returns the inferred schema without saving it." }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "set_workflow_intent",
            "description": "Register structured intent metadata on a workflow describing its purpose in machine-readable form.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "intent": {
                        "type": "object",
                        "description": "Structured intent object",
                        "properties": {
                            "action": { "type": "string", "description": "What the workflow does (e.g., 'fetch', 'transform', 'notify')" },
                            "subject": { "type": "string", "description": "What it operates on (e.g., 'github-issues', 'customer-data')" },
                            "output_type": { "type": "string", "description": "What it produces (e.g., 'report', 'notification', 'data-record')" },
                            "trigger_context": { "type": "string", "description": "When it should be invoked (e.g., 'on-new-issue', 'daily', 'on-demand')" }
                        },
                        "required": ["action", "subject"]
                    }
                },
                "required": ["workflow_id", "intent"]
            }
        }),
        serde_json::json!({
            "name": "get_session_context",
            "description": "Get a compact context payload of top workflows for the current session. Designed to fit under 800 tokens for LLM system prompts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_description": { "type": "string", "description": "Optional task description to match relevant workflows" },
                    "limit": { "type": "number", "description": "Max workflows to return (default: 10)" }
                }
            }
        }),
        serde_json::json!({
            "name": "get_workflow_identity",
            "description": "Author/debug view of a workflow. Returns: name, description, capabilities, intent, declared input_schema, readiness_score (raw), readiness_computed_at, node_count, plus a _see_also block pointing at the dedicated tools for inferred-input-schema (get_workflow_input_schema), readiness-score breakdown (get_readiness_breakdown), and representative output structure (get_node_output on a recent execution). For operational monitoring (execution stats, version history, module deps, schedules) use get_workflow_summary instead.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
    ]
}

pub fn capability_worlds() -> serde_json::Value {
    serde_json::json!({
        "_usage_note": "IMPORTANT: In compile_custom_sandbox and lint_sandbox, place `use` statements INSIDE your fn run() body, not at the top level. The #[talos_module] macro generates the WIT bindings at module scope — your function body is where the imports resolve.",
        "minimal": {
            "description": "Basic node with logging, JSON, datetime, crypto, and env utilities. No I/O.",
            "interfaces": {
                "logging": {
                    "functions": ["log(level: Level, message: string)"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::logging::{self, Level};\n    logging::log(Level::Info, \"Hello from WASM!\");\n    Ok(input)\n}"
                },
                "json": {
                    "functions": ["parse(json-str: string) -> result", "query(json-str: string, path: string) -> result<string, error>", "merge(json1: string, json2: string) -> result<string, error>", "prettify(json-str: string) -> result<string, error>", "minify(json-str: string) -> result<string, error>"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::json;\n    use talos::core::logging::{self, Level};\n    let val = json::query(&input, \"$.key\").map_err(|e| format!(\"{:?}\", e))?;\n    logging::log(Level::Info, &val);\n    Ok(val)\n}"
                },
                "datetime": {
                    "functions": ["now-unix() -> u64", "now-iso() -> string", "parse(date-str, format?) -> result<u64, error>", "format(timestamp, format) -> result<string, error>", "add-seconds(timestamp, seconds) -> u64", "diff-seconds(t1, t2) -> s64"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::datetime;\n\nlet now = datetime::now_unix();\nlet iso = datetime::now_iso();\nlet future = datetime::add_seconds(now, 3600);"
                },
                "crypto": {
                    "functions": ["hash(algorithm, data) -> bytes", "hmac(algorithm, key, data) -> bytes", "encode(encoding, data) -> string", "decode(encoding, data) -> result<bytes, error>", "random-bytes(length) -> bytes", "uuid() -> string"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::crypto;\n\nlet id = crypto::uuid();\nlet hash = crypto::hash(\"sha256\", b\"hello\");\nlet encoded = crypto::encode(\"base64\", &hash);"
                },
                "env": {
                    "functions": ["get-var(key) -> option<string>", "get-all-vars() -> string", "get-workflow-id() -> string", "get-execution-id() -> string", "get-module-id() -> string"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::env;\n\nlet wf_id = env::get_workflow_id();\nlet exec_id = env::get_execution_id();\nif let Some(val) = env::get_var(\"MY_VAR\") {\n    logging::log(Level::Info, &val);\n}"
                }
            },
            "crates": ["serde", "serde_json", "chrono", "uuid", "base64", "sha2", "hmac"]
        },
        "http": {
            "description": "HTTP requests, webhooks, GraphQL, email, state, data transforms, and templates.",
            "interfaces": {
                "logging": { "functions": ["log(level, message)"], "example": "(see minimal world)" },
                "json": { "functions": ["parse, query, merge, prettify, minify"], "example": "(see minimal world)" },
                "datetime": { "functions": ["now-unix, now-iso, parse, format, add-seconds, diff-seconds"], "example": "(see minimal world)" },
                "crypto": { "functions": ["hash, hmac, encode, decode, random-bytes, uuid"], "example": "(see minimal world)" },
                "env": { "functions": ["get-var, get-all-vars, get-workflow-id, get-execution-id, get-module-id"], "example": "(see minimal world)" },
                "http": {
                    "functions": ["fetch(req: request) -> result<response, error>"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::http::{self, Request, Method};\n    use talos::core::logging::{self, Level};\n    let req = Request { url: \"https://api.example.com\".to_string(), method: Method::Get, headers: vec![], body: vec![], timeout_ms: Some(10000) };\n    let resp = http::fetch(&req).map_err(|e| format!(\"{:?}\", e))?;\n    logging::log(Level::Info, &format!(\"Status: {}\", resp.status));\n    Ok(format!(\"status: {}\", resp.status))\n}"
                },
                "webhook": { "functions": ["send(req: webhook-request) -> result<webhook-response, error>"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::webhook::{self, WebhookRequest};\n\nlet req = WebhookRequest { url: \"https://hooks.example.com/notify\".to_string(), payload: \"{}\".to_string(), headers: vec![] };\nlet resp = webhook::send(&req)?;" },
                "graphql": { "functions": ["execute(req) -> result<response, error>", "execute-with-retry(req, max-retries) -> result<response, error>"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::graphql::{self, GraphqlRequest};\n\nlet req = GraphqlRequest { endpoint: \"https://api.example.com/graphql\".to_string(), query: \"{ users { id name } }\".to_string(), variables: None, headers: vec![] };\nlet resp = graphql::execute(&req)?;" },
                "email": { "functions": ["send(msg: message) -> result"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::email::{self, Message};\n\nlet msg = Message { to: \"user@example.com\".to_string(), subject: \"Hello\".to_string(), body: \"World\".to_string(), from: None };\nemail::send(&msg)?;" },
                "state": { "functions": ["get(key) -> result<string, error>", "set(key, value) -> result", "delete(key) -> result", "exists(key) -> bool", "list-keys() -> list<string>"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::state;\n\nstate::set(\"counter\", \"42\")?;\nlet val = state::get(\"counter\")?;\nlet exists = state::exists(\"counter\");" },
                "data-transform": { "functions": ["csv-to-json, json-to-csv, xml-to-json, json-to-xml"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::data_transform;\n\nlet json = data_transform::csv_to_json(\"name,age\\nAlice,30\")?;" },
                "templates": { "functions": ["render(template, variables, syntax) -> result<string, error>", "render-file(path, variables, syntax) -> result<string, error>"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::templates;\n\nlet result = templates::render(\"Hello {{name}}!\", \"{\\\"name\\\": \\\"World\\\"}\", None)?;" },
                "events": { "functions": ["emit(event-type, payload) -> result", "emit-with-metadata(event-type, payload, metadata?) -> result"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::events;\n\nevents::emit(\"order.created\", &serde_json::json!({\"order_id\": 123}).to_string())?;" },
                "http-stream": { "functions": ["connect(url, headers) -> result<string, error>", "next-event(stream-id) -> option<sse-event>", "close(stream-id)"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::http_stream;\n\nlet sid = http_stream::connect(\"https://api.example.com/events\", &[])?;\nwhile let Some(event) = http_stream::next_event(&sid) {\n    // process event.data\n}" }
            },
            "crates": ["serde", "serde_json", "chrono", "uuid", "url", "base64", "sha2", "hmac"]
        },
        "secrets": {
            "description": "Network + secrets vault + LLM API access (Anthropic, OpenAI, Gemini) with tool use and streaming + vector embedding generation.",
            "interfaces": {
                "all http interfaces": { "functions": ["(see http world)"], "example": "(see http world)" },
                "secrets": {
                    "functions": ["get-secret(key-path: string) -> result<string, error>"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::secrets;\n\nlet api_key = secrets::get_secret(\"my-api-key\")?;\n// Use api_key in HTTP requests — never log it directly"
                },
                "llm": { "functions": ["complete(req: completion-request) -> result<completion-response, error>"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::llm::{self, CompletionRequest, Message, Role};\n    use talos::core::logging::{self, Level};\n    let req = CompletionRequest {\n        provider: None,  // None = Anthropic (default); Some(Provider::Openai) for OpenAI\n        model: Some(\"claude-sonnet-4-6\".to_string()),\n        messages: vec![Message { role: Role::User, content: input }],\n        max_tokens: Some(500),\n        temperature: None,\n        system_prompt: Some(\"You are a helpful assistant.\".to_string()),\n    };\n    let resp = llm::complete(&req).map_err(|e| format!(\"{:?}\", e))?;\n    logging::log(Level::Info, &resp.text);\n    Ok(resp.text)\n}" },
                "llm-tools": { "functions": ["complete-with-tools(req) -> result<tool-completion-response, error>"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::llm_tools;\n\n// Define tools and let the LLM call them\nlet resp = llm_tools::complete_with_tools(&req)?;" },
                "llm-streaming": { "functions": ["start-stream(req) -> result<string, error>", "next-event(stream-id) -> option<stream-event>", "cancel-stream(stream-id)"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::llm_streaming;\n\nlet stream_id = llm_streaming::start_stream(&req)?;\nwhile let Some(event) = llm_streaming::next_event(&stream_id) {\n    // Process streaming tokens\n}" },
                "context-window": { "functions": ["estimate-tokens(text, model?) -> u32", "get-context-info(model?) -> context-info"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::context_window;\n\nlet tokens = context_window::estimate_tokens(\"Hello world\", None);" },
                "resource-quotas": { "functions": ["check-quota(metric) -> result<usage-info, error>", "record-usage(metric, amount) -> result<usage-info, error>", "list-quotas() -> list<usage-info>"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::resource_quotas;\n\nlet usage = resource_quotas::check_quota(\"llm_tokens\")?;" },
                "embedding": { "functions": ["generate(text, model?) -> result<list<f32>, error>"], "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::embedding;\n\nlet vec = embedding::generate(\"customer feedback about pricing\", None)?;\n// vec is a Vec<f32> embedding vector for similarity comparisons" }
            },
            "crates": ["serde", "serde_json", "chrono", "uuid"]
        },
        "filesystem": {
            "description": "Network + sandboxed file I/O for document processing and file conversion.",
            "interfaces": {
                "all http interfaces": { "functions": ["(see http world)"], "example": "(see http world)" },
                "files": {
                    "functions": ["read(path) -> result<bytes, error>", "write(path, contents) -> result", "exists(path) -> bool", "metadata(path) -> result<file-metadata, error>", "list-dir(path) -> result<list<string>, error>", "delete(path) -> result"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::files;\n\nfiles::write(\"output.txt\", b\"Hello World\")?;\nlet data = files::read(\"output.txt\")?;\nlet exists = files::exists(\"output.txt\");\nlet entries = files::list_dir(\".\")?;"
                }
            },
            "crates": ["serde", "serde_json"]
        },
        "messaging": {
            "description": "Network + NATS pub/sub messaging.",
            "interfaces": {
                "all http interfaces": { "functions": ["(see http world)"], "example": "(see http world)" },
                "messaging": {
                    "functions": ["publish(topic, payload) -> result", "publish-with-headers(msg) -> result", "request(topic, payload, timeout-ms) -> result<bytes, error>"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::messaging;\n\nmessaging::publish(\"my.topic\", b\"{\\\"event\\\": \\\"hello\\\"}\")?;\nlet reply = messaging::request(\"my.service\", b\"{\\\"action\\\": \\\"ping\\\"}\", 5000)?;"
                }
            },
            "crates": ["serde", "serde_json"]
        },
        "cache": {
            "description": "Network + Redis distributed cache.",
            "interfaces": {
                "all http interfaces": { "functions": ["(see http world)"], "example": "(see http world)" },
                "cache": {
                    "functions": ["get(key) -> result<string, error>", "set(key, value, ttl?) -> result", "delete(key) -> result", "exists(key) -> bool", "increment(key, amount) -> result<s64, error>", "decrement(key, amount) -> result<s64, error>", "mget(keys) -> result<list<option<string>>, error>", "mset(pairs) -> result", "expire(key, ttl) -> result"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::cache;\n\ncache::set(\"user:123\", \"{\\\"name\\\": \\\"Alice\\\"}\", Some(3600))?;\nlet val = cache::get(\"user:123\")?;\nlet count = cache::increment(\"visits\", 1)?;"
                }
            },
            "crates": ["serde", "serde_json"]
        },
        "database": {
            "description": "Network + secrets + PostgreSQL database + LLM + agent memory.",
            "interfaces": {
                "all http + secrets + llm interfaces": { "functions": ["(see secrets world)"], "example": "(see secrets world)" },
                "database": {
                    "functions": ["execute-query(sql, params) -> result<query-result, error>", "get-last-error() -> string"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::database;\n\nlet result = database::execute_query(\n    \"SELECT id, name FROM users WHERE status = $1 LIMIT 10\",\n    &[\"active\".to_string()]\n)?;\nlogging::log(Level::Info, &format!(\"Got {} rows\", result.rows_affected));"
                },
                "agent-memory": {
                    "functions": ["set(key, value) -> result", "get(key) -> result<string, error>", "delete(key) -> result", "list-keys(prefix?) -> result<list<string>, error>", "store-with-embedding(entry) -> result", "search(query, limit) -> result<list<search-result>, error>", "search-filtered(query, options) -> result<list<search-result>, error>"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::agent_memory;\n\nagent_memory::set(\"last_query\", \"SELECT * FROM users\")?;\nlet val = agent_memory::get(\"last_query\")?;\nlet keys = agent_memory::list_keys(Some(\"last_\"))?;"
                }
            },
            "crates": ["serde", "serde_json", "sqlx (via WIT database)"]
        },
        "governance": {
            "description": "Network + human-in-the-loop approval gates.",
            "interfaces": {
                "all http interfaces": { "functions": ["(see http world)"], "example": "(see http world)" },
                "governance": {
                    "functions": ["request-approval(reason: string) -> bool"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::governance;\n\nlet approved = governance::request_approval(\"Delete 500 records from production\");\nif !approved {\n    return Err(\"Operation requires human approval\".into());\n}"
                }
            },
            "crates": ["serde", "serde_json"]
        },
        "agent": {
            "description": "The recommended world for autonomous agents. Provides secrets + LLM suite (with tool use and streaming) + agent memory (key-value + vector search) + human-in-the-loop governance + multi-agent orchestration. Does NOT include filesystem, cache, messaging, database, or object storage.",
            "interfaces": {
                "all http + secrets + llm interfaces": { "functions": ["(see secrets world)"], "example": "(see secrets world)" },
                "agent-memory": {
                    "functions": ["set(key, value)", "get(key) -> string", "delete(key)", "list-keys(prefix?) -> list<string>", "store-with-embedding(entry)", "search(query, limit) -> list<search-result>", "search-filtered(query, options) -> list<search-result>"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::agent_memory;\n\nagent_memory::set(\"context\", &summary)?;\nlet results = agent_memory::search(\"customer feedback\", 5)?;\n// Self-recall guard — exclude this workflow's own synthesized output:\nlet recent = agent_memory::search_filtered(\"customer feedback\",\n    SearchOptions { limit: 5, exclude_kinds: vec![\"meeting_prep\".into()] })?;"
                },
                "governance": {
                    "functions": ["request-approval(reason) -> bool"],
                    "example": "let approved = governance::request_approval(\"Send email to 1000 users\");"
                },
                "agent-orchestration": {
                    "functions": ["invoke(msg, timeout-ms) -> result<agent-response, error>", "send(msg) -> result", "list-agents() -> result<list<string>, error>"],
                    "example": "let resp = agent_orchestration::invoke(AgentMessage { target: \"analyst\".into(), payload: task.into(), correlation_id: None }, 30000)?;"
                }
            },
            "crates": ["serde", "serde_json"]
        },
        "automation": {
            "description": "Full platform access: all interfaces including secrets, files, cache, messaging, database, governance, agent orchestration, and object storage.",
            "interfaces": {
                "all interfaces from all worlds": { "functions": ["(see individual worlds)"], "example": "(see individual worlds)" },
                "agent-orchestration": {
                    "functions": ["invoke(msg, timeout-ms) -> result<agent-response, error>", "send(msg) -> result", "list-agents() -> result<list<string>, error>"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::agent_orchestration;\n\nlet agents = agent_orchestration::list_agents()?;\nlet resp = agent_orchestration::invoke(\"Analyze this dataset\", 30000)?;"
                },
                "object-storage": {
                    "functions": ["put(req) -> result", "get(bucket, key) -> result<get-response, error>", "delete(bucket, key) -> result", "list-objects(bucket, prefix?, max-keys?) -> result<list<list-entry>, error>"],
                    "example": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::object_storage;\n\nobject_storage::put(&PutRequest { bucket: \"my-bucket\".into(), key: \"data.json\".into(), body: b\"{}\".to_vec(), content_type: Some(\"application/json\".into()) })?;\nlet obj = object_storage::get(\"my-bucket\", \"data.json\")?;"
                }
            },
            "crates": ["serde", "serde_json", "all platform crates via WIT"]
        }
    })
}

pub fn complex_examples() -> serde_json::Value {
    serde_json::json!({
        "http": {
            "Authenticated HTTP with secrets": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::http::{self, Request, Method};\n    use talos::core::secrets;\n    use talos::core::logging::{self, Level};\n    let api_key = secrets::get_secret(\"my-api-key\").map_err(|e| format!(\"{:?}\", e))?;\n    let req = Request {\n        url: \"https://api.example.com/data\".to_string(),\n        method: Method::Get,\n        headers: vec![(\"Authorization\".to_string(), format!(\"Bearer {}\", api_key))],\n        body: vec![],\n        timeout_ms: Some(10000),\n    };\n    let resp = http::fetch(&req).map_err(|e| format!(\"{:?}\", e))?;\n    Ok(String::from_utf8_lossy(&resp.body).to_string())\n}"
        },
        "cache": {
            "Atomic read-modify-write with cache": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::cache;\n    use talos::core::logging::{self, Level};\n    let current = cache::get(\"counter\").unwrap_or(None).unwrap_or(\"0\".to_string());\n    let count: i64 = current.parse().unwrap_or(0);\n    cache::set(\"counter\", &(count + 1).to_string(), Some(3600)).map_err(|e| format!(\"{:?}\", e))?;\n    Ok(format!(\"Counter: {} -> {}\", count, count + 1))\n}"
        },
        "database": {
            "Paginated DB query": "pub fn run(input: String) -> Result<String, String> {\n    use talos::core::database;\n    use talos::core::logging::{self, Level};\n    let page: i64 = serde_json::from_str::<serde_json::Value>(&input).ok()\n        .and_then(|v| v.get(\"page\").and_then(|p| p.as_i64())).unwrap_or(1);\n    let offset = (page - 1) * 100;\n    // Use parameterized queries to prevent SQL injection — never interpolate values into SQL\n    let result = database::execute_query(\n        \"SELECT * FROM my_table ORDER BY id LIMIT $1 OFFSET $2\",\n        &[\"100\".to_string(), offset.to_string()]\n    ).map_err(|e| { let d = database::get_last_error(); format!(\"{:?}: {}\", e, d) })?;\n    Ok(result.rows)\n}"
        }
    })
}

pub fn fuel_cost_guidance() -> serde_json::Value {
    serde_json::json!({
        "minimal": {
            "summary": "Negligible fuel — pure computation, no I/O.",
            "per_interface": {
                "logging": "~100 fuel per log call",
                "json": "~200–500 fuel per operation (scales with document size)",
                "datetime": "~50–100 fuel per call",
                "crypto": "~500–2,000 fuel per hash/hmac (scales with data size)",
                "env": "~100 fuel per get-var call"
            }
        },
        "http": {
            "summary": "Dominated by network I/O. Budget per outbound call.",
            "per_interface": {
                "http": "~5,000–20,000 fuel per fetch (scales with response size)",
                "webhook": "~5,000–15,000 fuel per send",
                "graphql": "~5,000–20,000 fuel per execute",
                "email": "~3,000–8,000 fuel per send",
                "state": "~500–1,000 fuel per get/set",
                "data-transform": "~500–2,000 fuel per conversion",
                "templates": "~200–1,000 fuel per render",
                "events": "~1,000–3,000 fuel per emit (NATS publish)",
                "http-stream": "~5,000–20,000 fuel per connect (long-lived); ~100 fuel per next-event poll"
            }
        },
        "secrets": {
            "summary": "LLM calls are the dominant cost. Each completion is 100k–300k fuel.",
            "per_interface": {
                "secrets": "~1,000 fuel per get-secret (vault decrypt round-trip)",
                "llm": "~100,000–200,000 fuel per complete() call (varies by model and output length)",
                "llm-tools": "~150,000–300,000 fuel per complete-with-tools() call (tool schema adds overhead)",
                "llm-streaming": "~100,000–250,000 fuel per stream session",
                "context-window": "~200 fuel per estimate-tokens call",
                "resource-quotas": "~500 fuel per check/record",
                "embedding": "~10,000–30,000 fuel per generate() call (varies by text length and model)"
            }
        },
        "filesystem": {
            "summary": "File operations scale with data size.",
            "per_interface": {
                "files": "~2,000–10,000 fuel per read/write (scales with file size)"
            }
        },
        "messaging": {
            "summary": "Low latency pub/sub. Per-message cost is modest.",
            "per_interface": {
                "messaging": "~2,000–5,000 fuel per publish; ~3,000–8,000 fuel per request (includes reply wait)"
            }
        },
        "cache": {
            "summary": "Very fast. Cache ops are cheap compared to network I/O.",
            "per_interface": {
                "cache": "~500–2,000 fuel per get/set/delete; mget/mset scale with batch size"
            }
        },
        "database": {
            "summary": "Query cost scales with result set and query complexity.",
            "per_interface": {
                "database": "~5,000–50,000 fuel per execute-query (complex joins or large results cost more)",
                "agent-memory": "~1,000–5,000 fuel per get/set; search with embedding ~10,000–30,000 fuel"
            }
        },
        "governance": {
            "summary": "Approval gate suspends execution until human responds — no fuel consumed while waiting.",
            "per_interface": {
                "governance": "~1,000 fuel to issue request-approval; execution is suspended (no fuel) until approved/denied"
            }
        },
        "agent": {
            "summary": "Combines secrets + LLM + agent memory + governance + orchestration. LLM and orchestration dominate fuel cost.",
            "per_interface": {
                "agent-memory": "~500–2,000 fuel per set/get; ~10,000–50,000 per search (embedding generation)",
                "governance": "~1,000 fuel to issue; suspended while waiting",
                "agent-orchestration": "~200,000–500,000 fuel per invoke (includes sub-agent execution)"
            }
        },
        "automation": {
            "summary": "Combines all worlds. Agent orchestration is the most expensive operation.",
            "per_interface": {
                "agent-orchestration": "~200,000–500,000 fuel per agent invoke (includes sub-agent budget)",
                "object-storage": "~5,000–20,000 fuel per put/get (scales with object size)"
            }
        }
    })
}
