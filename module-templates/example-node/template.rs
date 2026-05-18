#![allow(warnings)]
use talos_sdk_macros::talos_node;

#[talos_node(world = "minimal-node")]
pub fn run(repo: String, pull_number: u32) -> Result<String, String> {
    // This is a test node template demonstrating the #[talos_node(world = "minimal-node")] macro
    Ok(format!(
        "Successfully reviewed PR #{} for repo: {}",
        pull_number, repo
    ))
}
