"""Type definitions for Talos Python modules.

These mirror the WIT interface types defined in wit/talos.wit, providing
Python-idiomatic wrappers for the WASM component model types.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TalosInput:
    """Parsed input to a Talos module.

    The engine passes a JSON string to the `run()` export. This class
    provides structured access to the standard fields:

    - ``config``: Node configuration from the workflow graph
    - ``input``: Upstream node output (inter-node data flow)
    - ``__trigger_input__``: Original trigger payload (passthrough to all nodes)
    """

    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def config(self) -> dict[str, Any]:
        return self.raw.get("config", {})

    @property
    def input(self) -> Any:
        return self.raw.get("input")

    @property
    def trigger_input(self) -> dict[str, Any]:
        return self.raw.get("__trigger_input__", {})

    def get(self, key: str, default: Any = None) -> Any:
        """Access a top-level field (config values are merged to root)."""
        return self.raw.get(key, default)

    @classmethod
    def from_json(cls, json_str: str) -> TalosInput:
        import json

        return cls(raw=json.loads(json_str))


@dataclass
class TalosOutput:
    """Structured output from a Talos module.

    Serialize with ``to_json()`` before returning from ``run()``.
    """

    data: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        import json

        return json.dumps(self.data)


# ── Capability World Constants ──────────────────────────────────────────────
# These match the worlds defined in wit/talos.wit

WORLD_MINIMAL = "minimal-node"
WORLD_HTTP = "http-node"
WORLD_LLM = "llm-node"
WORLD_NETWORK = "network-node"
WORLD_SECRETS = "secrets-node"
WORLD_FILESYSTEM = "filesystem-node"
WORLD_MESSAGING = "messaging-node"
WORLD_CACHE = "cache-node"
WORLD_GOVERNANCE = "governance-node"
WORLD_DATABASE = "database-node"
WORLD_AGENT = "agent-node"
WORLD_AUTOMATION = "automation-node"

VALID_WORLDS = {
    WORLD_MINIMAL,
    WORLD_HTTP,
    WORLD_LLM,
    WORLD_NETWORK,
    WORLD_SECRETS,
    WORLD_FILESYSTEM,
    WORLD_MESSAGING,
    WORLD_CACHE,
    WORLD_GOVERNANCE,
    WORLD_DATABASE,
    WORLD_AGENT,
    WORLD_AUTOMATION,
}
