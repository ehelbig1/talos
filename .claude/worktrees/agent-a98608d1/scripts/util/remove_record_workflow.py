import re

with open("controller/src/webhooks/mod.rs", "r") as f:
    content = f.read()

# Remove the call to record_workflow_execution in the tokio::spawn block
removal = re.search(r'            // 12\. Record workflow execution\n            if let Err\(e\) = router_clone\n                \.record_workflow_execution\(.*?            }\n', content, re.DOTALL)
if removal:
    content = content.replace(removal.group(0), "")

# Remove the function definition for record_workflow_execution
func_def = re.search(r'    /// Locate the workflow that contains the given module and insert a.*?\n    async fn record_workflow_execution\(.*?    }\n', content, re.DOTALL)
if func_def:
    content = content.replace(func_def.group(0), "")

with open("controller/src/webhooks/mod.rs", "w") as f:
    f.write(content)

print("Removed record_workflow_execution")
