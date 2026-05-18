"""Secret Access — demonstrate the three-tier secret model.

Compile: talos compile --language python --world secrets-node secret_access.py

This module demonstrates Talos's three-tier secret architecture:
- Tier 1: Host-only (secret never leaves host — used for auth headers)
- Tier 2: Explicit expose (audited, rate-limited — for modules that need the value)
- Tier 3: vault:// config injection (auto-resolved by the engine)
"""

from talos_sdk import talos_module


@talos_module(world="secrets-node")
def run(data: dict) -> dict:
    config = data.get("config", {})
    api_key_path = config.get("api_key_path", "default/api_key")

    from talos_sdk.module import secrets, http

    # Tier 1: Get an opaque slot handle (secret never enters WASM memory)
    slot = secrets.get_secret(api_key_path)

    # Use the slot for authenticated HTTP requests — the host injects the
    # secret as an Authorization header without exposing it to this code
    response = http.fetch_with_bearer(slot, {
        "url": config.get("api_url", "https://api.example.com/data"),
        "method": "GET",
    })

    # Release the slot when done (auto-released on execution end, but
    # explicit release is good practice for long-running modules)
    secrets.release_slot(slot)

    return {
        "status_code": response.get("status", 0),
        "body": response.get("body", ""),
        "secret_was_exposed": False,  # Tier 1 — secret never left the host
    }
