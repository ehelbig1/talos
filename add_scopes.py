import re

with open("/Users/evanhelbig/projects/talos/controller/src/api/schema.rs", "r") as f:
    schema = f.read()

def insert_scope(method_name, scope_enum):
    global schema
    
    # Match from `async fn method_name` down to the first `{`
    pattern = r'async fn ' + re.escape(method_name) + r'\b[\s\S]*?\{'
    
    match = re.search(pattern, schema)
    if not match:
        print(f"Could not find {method_name}")
        return

    replacement = match.group() + f'\n        require_scope(ctx, crate::api_keys::ApiKeyScope::{scope_enum})?;\n'
    
    # check if already patched
    if f'require_scope(ctx, crate::api_keys::ApiKeyScope::{scope_enum})?;' not in schema[match.start():match.end()+100]:
        schema = schema[:match.start()] + replacement + schema[match.end():]
        print(f"Patched {method_name}")
    else:
        print(f"Already patched {method_name}")

for f in ["test_custom_module", "create_custom_module", "update_custom_module", "create_module_from_template"]:
    insert_scope(f, "WorkflowsWrite")

with open("/Users/evanhelbig/projects/talos/controller/src/api/schema.rs", "w") as f:
    f.write(schema)

print("Done")
