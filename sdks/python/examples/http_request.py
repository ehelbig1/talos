"""HTTP Request — fetch a URL and return the response.

Compile: talos compile --language python --world http-node http_request.py

This module requires the http-node capability world which grants access
to talos.core.http.fetch() for making outbound HTTP requests.
"""

from talos_sdk import talos_module


@talos_module(world="http-node")
def run(data: dict) -> dict:
    url = data.get("url", data.get("config", {}).get("url"))
    if not url:
        return {"__error": True, "error": "Missing 'url' in input or config"}

    method = data.get("method", "GET").upper()
    headers = data.get("headers", {})

    # In the WASM sandbox, this calls the host's HTTP implementation
    # which enforces SSRF protection (blocks RFC1918, metadata endpoints, etc.)
    from talos_sdk.module import http

    response = http.fetch({
        "url": url,
        "method": method,
        "headers": headers,
    })

    return {
        "status_code": response.get("status", 0),
        "body": response.get("body", ""),
        "headers": response.get("headers", {}),
    }
