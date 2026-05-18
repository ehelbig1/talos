"""Core decorator for Talos Python modules.

The ``@talos_module`` decorator marks a Python function as the entry point
for a Talos WASM module. It handles JSON serialization, error wrapping, and
world metadata embedding — mirroring the Rust ``#[talos_module]`` proc macro.

At compile time, ``componentize-py`` reads the WIT world from the embedded
``__TALOS_WORLD__`` variable and links only the capabilities permitted by
that world. This means a ``minimal-node`` module physically cannot call HTTP
or database APIs, even if the Python code imports them.
"""

from __future__ import annotations

import functools
import json
import traceback
from typing import Any, Callable

from talos_sdk.types import VALID_WORLDS, TalosInput


def talos_module(
    world: str = "minimal-node",
) -> Callable[[Callable[..., Any]], Callable[[str], str]]:
    """Decorator that wraps a Python function as a Talos module entry point.

    Args:
        world: Capability world for this module. Determines which host
               functions (HTTP, secrets, database, etc.) are available.
               Must be one of the worlds defined in wit/talos.wit.

    Usage::

        @talos_module(world="http-node")
        def run(data: dict) -> dict:
            url = data.get("url", "https://example.com")
            # ... use talos.core.http.fetch() ...
            return {"status": "ok", "url": url}

    The decorated function receives parsed JSON as a ``dict`` and must
    return a ``dict`` (or raise an exception for errors). The decorator
    handles JSON serialization for the WASM boundary.
    """
    if world not in VALID_WORLDS:
        raise ValueError(
            f"Unknown capability world '{world}'. "
            f"Valid worlds: {', '.join(sorted(VALID_WORLDS))}"
        )

    def decorator(fn: Callable[..., Any]) -> Callable[[str], str]:
        # Embed world metadata for componentize-py and the Talos runtime
        # to read at compile/link time.
        fn.__talos_world__ = world  # type: ignore[attr-defined]

        @functools.wraps(fn)
        def wrapper(input_json: str) -> str:
            """WASM entry point: run(input: string) -> result<string, string>."""
            try:
                data = json.loads(input_json) if input_json else {}
                result = fn(data)

                # Allow returning TalosOutput, dict, str, or None
                if result is None:
                    return json.dumps({"__status": "ok"})
                if isinstance(result, str):
                    return result
                if hasattr(result, "to_json"):
                    return result.to_json()
                return json.dumps(result)

            except Exception as exc:
                # Surface the error to the Talos engine as an Err(String).
                # Only include the traceback in non-production builds to avoid
                # leaking internal paths and logic to execution output.
                import os

                error_payload: dict[str, object] = {
                    "__error": True,
                    "error": str(exc),
                }
                if os.environ.get("RUST_ENV") != "production":
                    error_payload["traceback"] = traceback.format_exc()
                return json.dumps(error_payload)

        # Store the world as a module-level variable that componentize-py
        # and the Talos compilation service can discover.
        wrapper.__talos_world__ = world  # type: ignore[attr-defined]

        return wrapper

    return decorator


# ── Host function stubs ─────────────────────────────────────────────────────
# These are placeholder APIs that componentize-py will bind to actual WASM
# imports at compile time. In pure Python (outside WASM), they raise errors.


class _HostStub:
    """Placeholder for WASM host function bindings.

    At runtime inside the WASM sandbox, componentize-py replaces these
    with actual host function calls. Outside WASM (e.g., unit tests),
    calling these raises a clear error.
    """

    def __getattr__(self, name: str) -> Any:
        def stub(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError(
                f"talos.core.{name}() is only available inside the Talos WASM sandbox. "
                "Use 'talos compile --language python' to build and test your module."
            )

        return stub


# These will be replaced by componentize-py bindings at compile time
http = _HostStub()
secrets = _HostStub()
logging = _HostStub()
database = _HostStub()
cache = _HostStub()
state = _HostStub()
