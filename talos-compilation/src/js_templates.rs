//! JavaScript/TypeScript template stubs for each capability world.
//!
//! These templates provide starting points for users writing JS/TS WASM modules.
//! They are compiled to Component Model WASM via `jco componentize`.

/// Minimal node: pure computation, no external access.
pub const JS_TEMPLATE_MINIMAL: &str = r#"// Minimal Node Template
// Pure computation — no network, filesystem, or secrets access.

export function run(input) {
  const data = JSON.parse(input);

  // Your logic here
  const result = {
    message: `Processed: ${data.message || "no input"}`,
    timestamp: new Date().toISOString(),
  };

  return JSON.stringify(result);
}
"#;

/// HTTP node: can make outbound HTTP requests.
pub const JS_TEMPLATE_HTTP: &str = r#"// HTTP Node Template
// Can make outbound HTTP requests via fetch().

export async function run(input) {
  const data = JSON.parse(input);
  const url = data.url || "https://httpbin.org/get";
  const method = data.method || "GET";

  const response = await fetch(url, {
    method,
    headers: data.headers || {},
    body: data.body ? JSON.stringify(data.body) : undefined,
  });

  const responseData = await response.json();
  return JSON.stringify({
    status: response.status,
    data: responseData,
  });
}
"#;

/// Database node: can execute SQL queries.
pub const JS_TEMPLATE_DATABASE: &str = r#"// Database Node Template
// Can execute SQL queries via the Talos database interface.

export function run(input) {
  const data = JSON.parse(input);

  // The database interface is provided by the Talos host.
  // Use the query/execute functions from the imported interface.
  const result = {
    query: data.query || "SELECT 1",
    params: data.params || [],
    message: "Database query prepared",
  };

  return JSON.stringify(result);
}
"#;

/// Messaging node: can publish/subscribe to message queues.
pub const JS_TEMPLATE_MESSAGING: &str = r#"// Messaging Node Template
// Can publish and subscribe to message queues.

export function run(input) {
  const data = JSON.parse(input);

  const result = {
    topic: data.topic || "default",
    payload: data.payload || {},
    action: data.action || "publish",
    message: "Message operation prepared",
  };

  return JSON.stringify(result);
}
"#;

/// Secrets node: can access encrypted secrets from the Talos vault.
pub const JS_TEMPLATE_SECRETS: &str = r#"// Secrets Node Template
// Can access encrypted secrets from the Talos vault.

export function run(input) {
  const data = JSON.parse(input);

  // The secrets interface is provided by the Talos host.
  // Access secrets by key_path through the imported interface.
  const result = {
    secretKey: data.secret_key || "my-api-key",
    message: "Secret access prepared — the host will resolve the value at runtime",
  };

  return JSON.stringify(result);
}
"#;

/// TypeScript minimal template with type annotations.
pub const TS_TEMPLATE_MINIMAL: &str = r#"// Minimal Node Template (TypeScript)
// Pure computation — no external access.

interface InputData {
  message?: string;
  [key: string]: unknown;
}

interface OutputData {
  message: string;
  timestamp: string;
}

export function run(input: string): string {
  const data: InputData = JSON.parse(input);

  const result: OutputData = {
    message: `Processed: ${data.message || "no input"}`,
    timestamp: new Date().toISOString(),
  };

  return JSON.stringify(result);
}
"#;

/// TypeScript HTTP template with type annotations.
pub const TS_TEMPLATE_HTTP: &str = r#"// HTTP Node Template (TypeScript)
// Can make outbound HTTP requests.

interface HttpInput {
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
}

interface HttpOutput {
  status: number;
  data: unknown;
}

export async function run(input: string): Promise<string> {
  const data: HttpInput = JSON.parse(input);
  const url = data.url || "https://httpbin.org/get";
  const method = data.method || "GET";

  const response = await fetch(url, {
    method,
    headers: data.headers || {},
    body: data.body ? JSON.stringify(data.body) : undefined,
  });

  const responseData = await response.json();
  const result: HttpOutput = {
    status: response.status,
    data: responseData,
  };

  return JSON.stringify(result);
}
"#;

/// Returns the default JS template for a given WIT world name.
pub fn js_template_for_world(world: &str) -> &'static str {
    match world {
        "minimal-node" | "minimal" => JS_TEMPLATE_MINIMAL,
        "http-node" | "http" | "network-node" | "network" => JS_TEMPLATE_HTTP,
        "database-node" | "database" | "database-query" => JS_TEMPLATE_DATABASE,
        "messaging-node" | "messaging" => JS_TEMPLATE_MESSAGING,
        "secrets-node" | "secrets" => JS_TEMPLATE_SECRETS,
        _ => JS_TEMPLATE_MINIMAL,
    }
}

// ============================================================================
// Python Templates
// ============================================================================

/// Minimal Python node: pure computation.
pub const PY_TEMPLATE_MINIMAL: &str = r#""""Minimal Node Template - Pure computation."""
import json

def run(input_str: str) -> str:
    data = json.loads(input_str)

    result = {
        "message": f"Processed: {data.get('message', 'no input')}",
    }

    return json.dumps(result)
"#;

/// HTTP Python node: can make outbound requests.
pub const PY_TEMPLATE_HTTP: &str = r#""""HTTP Node Template - Can make outbound HTTP requests."""
import json
from talos.core import http

def run(input_str: str) -> str:
    data = json.loads(input_str)
    url = data.get("url", "https://httpbin.org/get")

    response = http.fetch(http.Request(
        method=http.Method.GET,
        url=url,
        headers=[],
        body=b"",
        timeout_ms=30000,
    ))

    body = bytes(response.body).decode("utf-8")
    result = {
        "status": response.status,
        "body": body[:10000],
    }

    return json.dumps(result)
"#;

/// LLM Python node: call language models.
pub const PY_TEMPLATE_LLM: &str = r#""""LLM Node Template - Call language model APIs."""
import json
from talos.core import llm

def run(input_str: str) -> str:
    data = json.loads(input_str)
    prompt = data.get("prompt", "Hello, how are you?")
    model = data.get("model")

    response = llm.complete(llm.CompletionRequest(
        provider=None,  # defaults to Anthropic
        model=model,
        messages=[llm.Message(role=llm.Role.USER, content=prompt)],
        max_tokens=1024,
        temperature=None,
        system_prompt=data.get("system_prompt"),
    ))

    result = {
        "text": response.text,
        "model": response.model,
        "usage": {
            "input_tokens": response.usage.input_tokens if response.usage else 0,
            "output_tokens": response.usage.output_tokens if response.usage else 0,
        } if response.usage else None,
    }

    return json.dumps(result)
"#;

/// Returns the default Python template for a given WIT world name.
pub fn py_template_for_world(world: &str) -> &'static str {
    match world {
        "minimal-node" | "minimal" => PY_TEMPLATE_MINIMAL,
        "http-node" | "http" | "network-node" | "network" => PY_TEMPLATE_HTTP,
        "secrets-node" | "secrets" => PY_TEMPLATE_LLM,
        _ => PY_TEMPLATE_MINIMAL,
    }
}

// ============================================================================
// Go Templates (TinyGo WASM Component Model)
// ============================================================================

/// Minimal Go node: pure computation.
pub const GO_TEMPLATE_MINIMAL: &str = r#"package main

import (
	"encoding/json"
)

// Run is the exported entry point called by the Talos runtime.
func Run(input string) (string, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(input), &data); err != nil {
		return "", err
	}

	result := map[string]interface{}{
		"message": "Processed from Go",
	}

	out, err := json.Marshal(result)
	return string(out), err
}

func main() {}
"#;

/// HTTP Go node: can make outbound HTTP requests.
pub const GO_TEMPLATE_HTTP: &str = r#"package main

import (
	"encoding/json"

	"github.com/aspect-build/aspect-cli/pkg/talos/core/http"
)

// Run is the exported entry point called by the Talos runtime.
func Run(input string) (string, error) {
	var data map[string]interface{}
	json.Unmarshal([]byte(input), &data)

	url := "https://httpbin.org/get"
	if u, ok := data["url"].(string); ok {
		url = u
	}

	resp, err := http.Fetch(http.Request{
		Method:  http.MethodGet,
		URL:     url,
		Headers: nil,
		Body:    nil,
	})
	if err != nil {
		return "", err
	}

	result := map[string]interface{}{
		"status": resp.Status,
		"body":   string(resp.Body),
	}

	out, _ := json.Marshal(result)
	return string(out), nil
}

func main() {}
"#;

/// Returns the default Go template for a given WIT world name.
pub fn go_template_for_world(world: &str) -> &'static str {
    match world {
        "http-node" | "http" | "network-node" | "network" => GO_TEMPLATE_HTTP,
        _ => GO_TEMPLATE_MINIMAL,
    }
}

/// Returns the default TypeScript template for a given WIT world name.
pub fn ts_template_for_world(world: &str) -> &'static str {
    match world {
        "minimal-node" | "minimal" => TS_TEMPLATE_MINIMAL,
        "http-node" | "http" | "network-node" | "network" => TS_TEMPLATE_HTTP,
        // Fall back to JS templates for worlds without TS-specific templates
        "database-node" | "database" | "database-query" => JS_TEMPLATE_DATABASE,
        "messaging-node" | "messaging" => JS_TEMPLATE_MESSAGING,
        "secrets-node" | "secrets" => JS_TEMPLATE_SECRETS,
        _ => TS_TEMPLATE_MINIMAL,
    }
}
