#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import urllib.request
import urllib.error
import hashlib
import re
from pathlib import Path

def do_request(url, method='GET', data=None, headers={}):
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response, response.read()
    except urllib.error.HTTPError as e:
        return e, e.read()

def lint_module(module_dir):
    print("🔍 Linting WebAssembly Component...")
    cargo_toml_path = module_dir / "Cargo.toml"
    if cargo_toml_path.exists():
        with open(cargo_toml_path, "r") as f:
            cargo_toml = f.read()
            
        if re.search(r'^regex\s*=', cargo_toml, re.MULTILINE):
            print("⚠️  WARNING: The `regex` crate is known to cause memory bloat and stack overflows in wasm32-wasip1.")
            print("   💡 Recommendation: Use `regex-lite` instead for WebAssembly modules.")
            print("   If you proceed, you risk Wasm traps on complex inputs.")
            
        if re.search(r'^chrono\s*=', cargo_toml, re.MULTILINE):
            print("⚠️  WARNING: The `chrono` crate relies on 128-bit math intrinsics (__multi3) which can cause missing symbol traps in wasm32-wasip1.")
            print("   💡 Recommendation: Use string-based date comparisons or delegate date math to the Host/JS if possible.")
            
    # Search for deep JSON deserialization
    src_dir = module_dir / "src"
    if not src_dir.exists():
        src_dir = module_dir  # e.g., if template.rs is at root
        
    for rust_file in list(src_dir.glob("**/*.rs")) + list(module_dir.glob("*.rs")):
        with open(rust_file, "r") as f:
            rs_code = f.read()
            if "serde_json::Value" in rs_code and "from_slice" in rs_code:
                print("⚠️  WARNING: Found `serde_json::Value` parsing from slice. Deeply nested JSON from external APIs can overflow the WebAssembly stack during recursive descent.")
                print("   💡 Recommendation: Use explicit structs for `serde::Deserialize` and ignore unknown fields instead of a generic JSON tree.")

def push_to_oci(registry, repo, tag, file_path, talos_manifest):
    with open(file_path, 'rb') as f:
        data = f.read()

    layer_digest = "sha256:" + hashlib.sha256(data).hexdigest()
    layer_size = len(data)

    # 1. Start upload for layer
    resp, body = do_request(f"http://{registry}/v2/{repo}/blobs/uploads/", method='POST')
    if resp.status not in (202, 201):
        raise Exception(f"Failed to start layer upload: {resp.status} {body}")

    loc = resp.headers.get('Location')
    if loc.startswith('/'):
        loc = f"http://{registry}" + loc

    # 2. Upload layer blob
    url = f"{loc}&digest={layer_digest}" if "?" in loc else f"{loc}?digest={layer_digest}"
    resp, body = do_request(url, method='PUT', data=data, headers={'Content-Type': 'application/octet-stream'})
    if resp.status != 201:
        raise Exception(f"Failed to upload layer: {resp.status} {body}")

    # 3. Create config blob (using talos.json manifest content!)
    config_data = json.dumps(talos_manifest).encode('utf-8')
    config_digest = "sha256:" + hashlib.sha256(config_data).hexdigest()
    config_size = len(config_data)

    resp, body = do_request(f"http://{registry}/v2/{repo}/blobs/uploads/", method='POST')
    loc = resp.headers.get('Location')
    if loc.startswith('/'):
        loc = f"http://{registry}" + loc

    url = f"{loc}&digest={config_digest}" if "?" in loc else f"{loc}?digest={config_digest}"
    resp, body = do_request(url, method='PUT', data=config_data, headers={'Content-Type': 'application/octet-stream'})

    # 4. Push manifest
    manifest = {
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.wasm.config.v1+json",
            "size": config_size,
            "digest": config_digest
        },
        "layers": [
            {
                "mediaType": "application/vnd.wasm.content.layer.v1+wasm",
                "size": layer_size,
                "digest": layer_digest
            }
        ]
    }
    manifest_json = json.dumps(manifest).encode('utf-8')
    resp, body = do_request(
        f"http://{registry}/v2/{repo}/manifests/{tag}", 
        method='PUT', 
        data=manifest_json, 
        headers={'Content-Type': 'application/vnd.oci.image.manifest.v1+json'}
    )
    if resp.status not in (200, 201):
         raise Exception(f"Failed to push manifest: {resp.status} {body}")
         
    return f"oci://{registry}/{repo}:{tag}"

def main():
    if len(sys.argv) < 2:
        print("Usage: talos-publish.py <module-directory>")
        sys.exit(1)
        
    module_dir = Path(sys.argv[1]).resolve()
    manifest_path = module_dir / "talos.json"
    
    if not manifest_path.exists():
        print(f"Error: {manifest_path} not found. Please create a talos.json manifest.")
        sys.exit(1)
        
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)
        
    # Validate talos.json schema basics
    if 'allowed_hosts' in manifest and not isinstance(manifest['allowed_hosts'], list):
        print("❌ Error: 'allowed_hosts' in talos.json must be an array of strings.")
        sys.exit(1)
        
    if 'allowed_hosts' in manifest:
        for host in manifest['allowed_hosts']:
            if "://" in host or "/" in host:
                print(f"❌ Error: Invalid 'allowed_hosts' entry '{host}'. Must be just the hostname (e.g. 'api.github.com' instead of 'https://api.github.com/').")
                sys.exit(1)
        
    name = manifest.get('name')
    if not name:
        print("Error: 'name' is required in talos.json")
        sys.exit(1)
        
    print(f"🚀 Building {name}...")
    
    # Run Developer Experience Linters
    lint_module(module_dir)

    
    # 1. Build
    try:
        subprocess.run(["cargo", "component", "build", "--release", "--target", "wasm32-wasip1"], cwd=module_dir, check=True)
    except subprocess.CalledProcessError:
        print("❌ Build failed!")
        sys.exit(1)
        
    # Find WASM
    bin_name = name.replace('-', '_')
    wasm_path = module_dir / "target" / "wasm32-wasip1" / "release" / f"{bin_name}.wasm"
    
    if not wasm_path.exists():
        print(f"❌ Failed to find compiled WASM at {wasm_path}")
        sys.exit(1)
        
    # 2. Push to OCI
    registry = os.getenv("TALOS_REGISTRY", "localhost:5001")
    repo = f"talos-tools/{name}"
    tag = manifest.get('version', 'v1.0.0')
    
    print(f"📦 Pushing to OCI Registry ({registry}/{repo}:{tag})...")
    oci_url = push_to_oci(registry, repo, tag, str(wasm_path), manifest)
    print(f"✅ Successfully pushed: {oci_url}")
    
    # 3. Register with Controller
    print("📡 Registering template with Talos Controller...")
    api_endpoint = os.getenv("TALOS_API_URL", "http://localhost:8000") + "/api/registry/publish"
    
    payload = {
        "name": manifest.get('display_name', name),
        "category": manifest.get('category', 'Custom'),
        "description": manifest.get('description', ''),
        "config_schema": manifest.get('config_schema', {"type": "object", "properties": {}}),
        "oci_url": oci_url,
    }
    
    req = urllib.request.Request(
        api_endpoint, 
        data=json.dumps(payload).encode('utf-8'), 
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            resp_data = json.loads(response.read())
            print(f"🎉 Success: {resp_data.get('message', 'Registered')}")
            print(f"🤖 This tool is now available to MCP AI Agents instantly!")
    except urllib.error.HTTPError as e:
        print(f"❌ Failed to register with controller: {e.status} {e.read().decode('utf-8')}")

if __name__ == "__main__":
    main()
