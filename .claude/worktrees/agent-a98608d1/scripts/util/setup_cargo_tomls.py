import os
import re
import shutil

module_templates_dir = "module-templates"

for dir_name in os.listdir(module_templates_dir):
    dir_path = os.path.join(module_templates_dir, dir_name)
    if not os.path.isdir(dir_path):
        continue
    
    template_file = os.path.join(dir_path, "template.rs")
    if not os.path.isfile(template_file):
        print(f"Skipping {dir_name}: no template.rs")
        continue

    with open(template_file, "r") as f:
        source_code = f.read()

    # Extract world
    world = "automation-node"
    m = re.search(r'world\s*=\s*"([^"]+)"', source_code)
    if m:
        world = m.group(1)
    else:
        m2 = re.search(r'world:\s*"([^"]+)"', source_code)
        if m2:
            world = m2.group(1)
            
    package_name = dir_name.lower()
    
    cargo_toml = f"""[package]
name = "{package_name}"
version = "0.1.0"
edition = "2021"

[dependencies]
wit-bindgen = "0.26.0"
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
talos_sdk_macros = {{ path = "../../talos_sdk_macros" }}

[lib]
crate-type = ["cdylib"]
path = "template.rs"

[package.metadata.component]
package = "talos:{package_name}"

[package.metadata.component.target]
path = "../../wit/talos.wit"
world = "{world}"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
"""

    with open(os.path.join(dir_path, "Cargo.toml"), "w") as f:
        f.write(cargo_toml)

    print(f"Generated Cargo.toml for {dir_name} with world {world}")

