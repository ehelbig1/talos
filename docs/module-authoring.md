# Module Authoring Guide

Talos modules are WebAssembly (WASM) components that execute within a sandboxed runtime. Each module implements a WIT (WebAssembly Interface Types) world and can access platform capabilities such as HTTP, secrets, state, logging, and messaging.

## Supported Languages

- **Rust** (primary, best tooling support)
- **JavaScript** (via ComponentizeJS)
- **TypeScript** (via ComponentizeJS)

## WIT Interface

All modules implement the `talos:core` package. The core entry point is:

```wit
world processor {
    import talos:core/logging;
    export process: func(input: string) -> string;
}
```

Modules receive a JSON string as input and return a JSON string as output.

### Available Capabilities

Each world can import one or more capability interfaces:

| World                    | Imports                                      | Use Case                           |
|--------------------------|----------------------------------------------|------------------------------------|
| `processor`              | `logging`                                    | Simple data transformation         |
| `http-processor`         | `logging`, `http`                            | External API calls                 |
| `secret-processor`       | `logging`, `secrets`                         | Access encrypted secrets           |
| `stateful-processor`     | `logging`, `state`                           | Persistent key-value storage       |
| `full-processor`         | `logging`, `http`, `secrets`, `state`        | All capabilities                   |
| `database-query`         | `logging`, `database`                        | SQL query execution                |
| `message-publisher`      | `logging`, `messaging`                       | Publish to NATS topics             |

### HTTP Interface

```wit
interface http {
    enum method { get, post, put, delete, patch }
    record request {
        method: method,
        url: string,
        headers: list<tuple<string, string>>,
        body: list<u8>,
        timeout-ms: option<u32>,
    }
    record response {
        status: u16,
        headers: list<tuple<string, string>>,
        body: list<u8>,
    }
    fetch: func(req: request) -> result<response, error>;
}
```

### Secrets Interface

```wit
interface secrets {
    get-secret: func(key-path: string) -> result<string, error>;
}
```

### State Interface

```wit
interface state {
    get: func(key: string) -> result<string, error>;
    set: func(key: string, value: string) -> result<_, error>;
    delete: func(key: string) -> result<_, error>;
    exists: func(key: string) -> bool;
    list-keys: func() -> list<string>;
}
```

### Logging Interface

```wit
interface logging {
    enum level { debug, info, warn, error }
    log: func(lvl: level, msg: string);
}
```

## Creating a Rust Module

### 1. Project Setup

```bash
cargo new --lib my-module
cd my-module
```

Add to `Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen = "0.36"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

### 2. Implement the Module

```rust
wit_bindgen::generate!({
    world: "http-processor",
    path: "../wit/talos.wit",
});

struct MyModule;

impl Guest for MyModule {
    fn process(input: String) -> String {
        // Parse input
        let data: serde_json::Value = serde_json::from_str(&input)
            .unwrap_or(serde_json::json!({}));

        // Use logging
        talos::core::logging::log(
            talos::core::logging::Level::Info,
            &format!("Processing: {}", data),
        );

        // Make HTTP request
        let response = talos::core::http::fetch(&talos::core::http::Request {
            method: talos::core::http::Method::Get,
            url: "https://api.example.com/data".to_string(),
            headers: vec![],
            body: vec![],
            timeout_ms: Some(5000),
        });

        // Return result
        match response {
            Ok(resp) => {
                let body = String::from_utf8_lossy(&resp.body);
                serde_json::json!({ "status": resp.status, "body": body }).to_string()
            }
            Err(e) => serde_json::json!({ "error": format!("{:?}", e) }).to_string(),
        }
    }
}

export!(MyModule);
```

### 3. Compile to WASM

```bash
cargo build --target wasm32-wasip2 --release
```

### 4. Upload via GraphQL

Use the `createCustomModule` mutation to upload the compiled `.wasm` file.

## Creating a JavaScript/TypeScript Module

### 1. Write the Module

The exported entry point MUST be named `run` (not `process`) and take the
single JSON string argument — every world exports `run(input: string) ->
result<string, string>` (see [Module input contract](#module-input-contract)
for exactly what `input` contains).

```javascript
// my-module.js
export function run(input) {
    // `input` is a JSON-encoded envelope string — parse it, then read your
    // node config from `.config` (NOT the top-level parse result).
    const payload = JSON.parse(input);
    const config = payload.config ?? {};

    // Use imported capabilities via global bindings
    log("info", `Processing n=${config.n}`);

    return JSON.stringify({ doubled: (config.n ?? 0) * 2 });
}
```

### 2. Compile

Compile via the `compile_custom_sandbox` MCP tool with `language:
"javascript"` (jco/componentize under the hood). `capability_world` is
authoritative and `dependencies` must be omitted (modules are
self-contained — no network at componentize time). Python is identical with
`language: "python"` and a module-level `def run(input: str) -> str:`.

## Module input contract

Regardless of language, `run(input)` receives a **JSON-encoded string of the
node payload**, not your raw value. This is the single most common
JS/Python authoring trap — parsing `input` and using it directly yields the
whole envelope, so a module silently computes on `undefined`/`None`.

The parsed envelope has this shape (built identically by `test_module` and
by the live engine in `engine_dispatch_single`):

```jsonc
{
  "config": { /* your node config — test_module's `config` arg, or add_node_to_workflow's `config` field */ },
  "input":  { /* upstream node's output (empty for the first node) */ },
  /* ...plus config's and input's own keys spread at the root for convenience */
}
```

So a doubler expecting `{ "n": 21 }` as its config reads:

| Language | Read your config value |
|----------|------------------------|
| JavaScript | `JSON.parse(input).config.n` |
| Python | `json.loads(input)["config"]["n"]` |
| Rust (SDK) | `data["config"]["n"]` — the `#[talos_module]` macro parses the envelope for you |

Rust authors rarely notice this because the SDK hands them `data`
pre-parsed; JS/Python `run(input)` sees the raw envelope string and must
parse + index `.config` themselves.

### Upload via GraphQL

The `createCustomModule` mutation also accepts pre-compiled `.wasm`; the
`compile_custom_sandbox` MCP path above is preferred for source-in,
module-out authoring.

## Module Configuration

Modules can declare a JSON Schema for their configuration:

```json
{
    "type": "object",
    "properties": {
        "api_key_secret": {
            "type": "string",
            "description": "Secret key path for the API key"
        },
        "endpoint": {
            "type": "string",
            "description": "Target API endpoint URL"
        }
    },
    "required": ["endpoint"]
}
```

Configuration values are passed as part of the input JSON when the module executes within a workflow.

## Built-in Templates

Talos ships with pre-built module templates for common tasks:

- `http-request` -- Make HTTP API calls
- `json-transform` -- Transform JSON data with expressions
- `send-slack-message` -- Post messages to Slack channels
- `send-gmail` -- Send emails via Gmail API
- `redis-cache` -- Read/write Redis cache
- `database-query` -- Execute SQL queries
- `llm-inference` -- Call LLM APIs (Anthropic, OpenAI)
- `human-approval` -- Pause workflow for human review
- `data-validator` -- Validate data against JSON Schema
- `slack-webhook-listener` -- Receive Slack webhook events
- `google-calendar-webhook` -- Receive Google Calendar push notifications

Use the `createModuleFromTemplate` mutation to instantiate any template with custom configuration.

## LLM Tool Use

The `llm-tools` interface enables function calling (tool use) with LLM providers. Available in `secrets-node`, `database-node`, and `automation-node` worlds.

### Key Types

```wit
record tool-definition {
    name: string,              // Unique tool name (e.g. "search_database")
    description: string,       // Human-readable description shown to the model
    input-schema: string,      // JSON Schema string for tool parameters
}

record tool-call {
    tool-name: string,         // Tool the model wants to invoke
    call-id: string,           // Unique ID for pairing with results
    arguments: string,         // JSON string of input arguments
}

variant content-block {
    text(string),
    tool-use(tool-call),
    tool-result(tool-result),
    image(image-content),
}
```

### Request/Response Flow

1. Build a `tool-completion-request` with your messages and an array of `tool-definition` entries.
2. Call `complete-with-tools(req)` to get a `tool-completion-response`.
3. Iterate the response `content` blocks. If any block is a `tool-use`, execute the tool locally with the provided arguments.
4. Construct `tool-result` blocks with matching `call-id` values and append them to the conversation.
5. Call `complete-with-tools` again with the updated messages to get the model's final answer.

Use `force-tool` in the request to require the model to call a specific tool. Use `response-schema` for structured JSON output validation.

## LLM Streaming

The `llm-streaming` interface provides incremental token delivery for long-running completions. Available in `secrets-node`, `database-node`, and `automation-node` worlds.

### Streaming Pattern

```
start-stream(req) -> stream-id
loop:
    next-event(stream-id) -> option<stream-event>
    match event:
        text-delta(str)    -> append to output buffer
        tool-call(tc)      -> handle tool call
        usage(u)           -> record token counts
        done(reason)       -> break loop
        error(msg)         -> handle error, break
        none               -> stream complete, break
cancel-stream(stream-id)   -> early termination
```

Use `start-stream` for plain text streaming or `start-tool-stream` to include tool definitions. The `messages-json` and `tools-json` fields accept JSON-encoded arrays matching the `llm-tools` message and tool definition formats.

## Context Window

The `context-window` interface provides token estimation and model context information. Available in `secrets-node`, `database-node`, and `automation-node` worlds.

- **`estimate-tokens(text, model)`** -- Estimate the number of tokens in a string for a given model.
- **`get-context-info(model)`** -- Returns a `context-info` record with `max-tokens`, `used-tokens`, and `available-tokens`.

Use this to check available context budget before constructing large prompts, avoiding truncation or API errors.

## Resource Quotas

The `resource-quotas` interface lets modules check and record resource usage against configured limits. Available in `secrets-node`, `database-node`, and `automation-node` worlds.

- **`check-quota(metric)`** -- Check remaining budget for a metric (e.g. `"llm_tokens"`, `"http_calls"`).
- **`record-usage(metric, amount)`** -- Record usage and get updated info. Fails with `quota-exceeded` if the limit would be exceeded.
- **`list-quotas()`** -- List all tracked metrics and their current usage.

Quotas are enforced per-user within a billing period. Modules should call `check-quota` before expensive operations and `record-usage` after completion.

## Agent Memory

The `agent-memory` interface provides persistent key-value storage with optional vector similarity search. Available in `database-node` and `automation-node` worlds. Memory is scoped to the module within its workflow, providing isolation between modules.

### Key-Value Operations

- **`set(key, value)`** / **`get(key)`** / **`delete(key)`** -- Basic CRUD for string values.
- **`list-keys(prefix)`** -- List keys matching an optional prefix filter.

### Semantic Search

- **`store-with-embedding(entry)`** -- Store a value with an automatically generated embedding vector. Accepts optional JSON metadata for filtering.
- **`search(query, limit)`** -- Find the top `limit` entries by cosine similarity to the query string. Returns results with similarity scores (0.0 to 1.0).

Memory persists across executions within the same workflow, making it suitable for building agents that accumulate knowledge over time.

## Agent Orchestration

The `agent-orchestration` interface enables multi-agent coordination via NATS messaging. Available only in the `automation-node` world.

- **`invoke(msg, timeout_ms)`** -- Send a message to another agent/workflow and wait for its response (synchronous, max 120s timeout).
- **`send(msg)`** -- Fire-and-forget message to another agent/workflow (asynchronous).
- **`list-agents()`** -- Discover available agents/workflows that can be invoked.

Messages include a `target` (agent/workflow identifier), `payload` (JSON string), and optional `correlation-id` for request-reply patterns.

## Security Tiers

Talos enforces a tiered capability model at the WASM binary level. Each module is compiled against exactly one world, and the runtime linker only exposes host functions belonging to that world. Choose the least privileged world that satisfies your module's needs.

| World | Tier | Capabilities | Use Case |
|-------|------|-------------|----------|
| `minimal-node` | 1 | logging, json, datetime, crypto, env | Pure computation, validation, formatting |
| `http-node` | 2 | + http, webhook, graphql, email, state, data-transform, templates | API integrations, stateful workflows |
| `network-node` | 3 | + raw TCP/UDP sockets (wasi:sockets) | Native DB drivers, AMQP clients |
| `secrets-node` | 3a | + secrets, llm, llm-tools, llm-streaming, context-window, resource-quotas | LLM agents, OAuth token usage |
| `filesystem-node` | 3b | + files | File format conversion, document processing |
| `messaging-node` | 3c | + messaging (NATS) | Event fan-out, notification pipelines |
| `cache-node` | 3d | + cache (Redis) | Memoization, rate counting |
| `governance-node` | 3e | + governance | Human-in-the-loop approval gates |
| `database-node` | 4 | + secrets, llm (full), database, agent-memory | Data pipelines, reporting |
| `automation-node` | 5 | All interfaces including agent-orchestration, object-storage | Full platform access (requires review) |

**Security notes:**
- `network-node` and above bypass the `allowed_hosts` domain whitelist (operates at IP level).
- `automation-node` grants the largest blast radius -- use only when no narrower world suffices.
- All worlds export a single `run(input: string) -> result<string, string>` function.
