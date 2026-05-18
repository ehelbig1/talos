"""Talos Python SDK — build WASM workflow modules in Python.

Modules are compiled to WebAssembly via componentize-py and executed inside
Talos's capability-gated WASM sandbox with the same security guarantees as
Rust modules: fuel limits, memory caps, per-module secret scoping, and
tiered capability worlds.

Usage:
    from talos_sdk import talos_module

    @talos_module(world="http-node")
    def run(data: dict) -> dict:
        return {"result": "hello from Python"}
"""

__version__ = "0.1.0"

from talos_sdk.module import talos_module
from talos_sdk.types import TalosInput, TalosOutput

__all__ = ["talos_module", "TalosInput", "TalosOutput"]
