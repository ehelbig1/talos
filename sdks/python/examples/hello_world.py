"""Hello World — minimal Talos module in Python.

Compile: talos compile --language python --world minimal-node hello_world.py
"""

from talos_sdk import talos_module


@talos_module(world="minimal-node")
def run(data: dict) -> dict:
    name = data.get("name", data.get("input", {}).get("name", "World"))
    return {
        "greeting": f"Hello, {name}!",
        "source": "python-sdk",
    }
