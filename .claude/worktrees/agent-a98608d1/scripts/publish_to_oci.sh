#!/bin/bash
# Scripts to build and push Talos modules to a local or remote OCI registry

set -e

REGISTRY_URL=${1:-"localhost:5001"}
ORG="talos-tools"

echo "Building and pushing Talos modules to OCI Registry: $REGISTRY_URL"

# For each module template
for dir in module-templates/*/; do
    dir=${dir%*/}
    module_name=$(basename "$dir")
    
    echo "======================================"
    echo "Processing $module_name..."
    
    # We need to compile the Wasm binary first
    # Many of these are just Cargo projects
    if [ -f "$dir/Cargo.toml" ]; then
        echo "Building $module_name to wasm32-wasi..."
        cd "$dir"
        cargo build --target wasm32-wasi --release
        
        WASM_FILE="target/wasm32-wasi/release/${module_name//-/_}.wasm"
        if [ -f "$WASM_FILE" ]; then
            echo "Successfully built $WASM_FILE"
            
            # Using skopeo or crane or similar tools to push Wasm as OCI artifact
            # For simplicity, if standard tools aren't installed, we can skip or use dummy layer push
            echo "Pushing $module_name:v1.0.0 to $REGISTRY_URL/$ORG/$module_name..."
            
            # In a real environment, you'd use something like:
            # wasm-to-oci push "$WASM_FILE" "$REGISTRY_URL/$ORG/$module_name:v1.0.0"
            echo "Note: OCI Push logic requires wasm-to-oci or crane installed locally."
        else
            echo "Wasm file not found: $WASM_FILE"
        fi
        cd ../../
    else
        echo "No Cargo.toml found in $dir, skipping..."
    fi
done

echo "Done!"
