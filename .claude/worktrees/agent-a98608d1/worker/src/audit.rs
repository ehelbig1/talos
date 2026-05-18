use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditEvent {
    pub workflow_id: String,
    pub execution_id: String,
    pub sequence_num: u64,
    pub timestamp: i64,
    pub actor: String,         // e.g., "agent:gpt-4", "human:manager@company.com"
    pub action: String,        // e.g., "mcp:request_tool", "wasi:human_approval"
    pub payload: String,       // The exact JSON sent or received
    pub previous_hash: String, // The cryptographic link
}

impl AuditEvent {
    /// Generates the immutable signature for this exact moment in time
    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();

        // Serialize the event to a canonical string (excluding its own hash)
        let event_string = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.workflow_id,
            self.execution_id,
            self.sequence_num,
            self.timestamp,
            self.actor,
            self.action,
            self.payload
        );

        // Hash the current event WITH the previous hash
        hasher.update(format!("{}|{}", self.previous_hash, event_string));

        format!("{:x}", hasher.finalize())
    }
}

use chrono::Utc;

/// A local tracker for the cryptographic ledger of a specific execution
pub struct ExecutionLedger {
    pub workflow_id: String,
    pub execution_id: String,
    pub current_sequence: u64,
    pub last_hash: String,
}

impl ExecutionLedger {
    pub fn new(workflow_id: &str, execution_id: &str) -> Self {
        Self {
            workflow_id: workflow_id.to_string(),
            execution_id: execution_id.to_string(),
            current_sequence: 0,
            // The genesis hash can be a known seed or a hash of the execution ID itself
            last_hash: format!(
                "{:x}",
                Sha256::digest(format!("genesis:{}|{}", workflow_id, execution_id).as_bytes())
            ),
        }
    }

    /// Appends a new event to the ledger, calculating the proper sequence and cryptographic link
    pub fn append(&mut self, actor: &str, action: &str, payload: &str) -> AuditEvent {
        self.current_sequence += 1;

        let event = AuditEvent {
            workflow_id: self.workflow_id.clone(),
            execution_id: self.execution_id.clone(),
            sequence_num: self.current_sequence,
            timestamp: Utc::now().timestamp(),
            actor: actor.to_string(),
            action: action.to_string(),
            payload: payload.to_string(),
            previous_hash: self.last_hash.clone(),
        };

        // Finalize the cryptographic link
        let current_hash = event.calculate_hash();

        // Update the ledger pointer
        self.last_hash = current_hash;

        event
    }
}
