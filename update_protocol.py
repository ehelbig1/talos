import re

with open("job-protocol/src/lib.rs", "r") as f:
    content = f.read()

# 1. Add thiserror definitions
content = content.replace("use uuid::Uuid;", """use uuid::Uuid;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Missing or invalid shared key: {0}")]
    InvalidKey(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    #[error("Signature error: {0}")]
    SignatureError(String),
    #[error("Invalid or expired nonce: {0}")]
    NonceError(String),
}""")

# 2. Replace type signatures
content = content.replace("Result<Self, String>", "Result<Self, ProtocolError>")
content = content.replace("Result<HashMap<String, String>, String>", "Result<HashMap<String, String>, ProtocolError>")
content = content.replace("Result<(), String>", "Result<(), ProtocolError>")
content = content.replace("Result<Vec<u8>, String>", "Result<Vec<u8>, ProtocolError>")

# 3. Replace return strings in EncryptedSecrets
content = content.replace('Err(format!(\n                "WORKER_SHARED_KEY must be 32 bytes, got {}",\n                key.len()\n            ))', 'Err(ProtocolError::InvalidKey(format!("WORKER_SHARED_KEY must be 32 bytes, got {}", key.len())))')
content = content.replace('format!("serialize secrets: {e}")', 'ProtocolError::SerializationError(e)')
# but Wait, we used `#[from]` for serde_json::Error so `map_err(|e| e.into())` or actually we can just use `map_err(|e| ProtocolError::EncryptionError(format!("serialize secrets: {e}")))`
content = content.replace('.map_err(|e| format!("serialize secrets: {e}"))', '.map_err(ProtocolError::SerializationError)')
content = content.replace('.map_err(|e| format!("deserialize secrets: {e}"))', '.map_err(ProtocolError::SerializationError)')
content = content.replace('.map_err(|e| format!("create cipher: {e}"))', '.map_err(|e| ProtocolError::EncryptionError(format!("create cipher: {e}")))')
content = content.replace('.map_err(|e| format!("encrypt secrets: {e}"))', '.map_err(|e| ProtocolError::EncryptionError(format!("encrypt secrets: {e}")))')
content = content.replace('.map_err(|_| "decryption failed — wrong key or tampered ciphertext".to_string())', '.map_err(|_| ProtocolError::DecryptionError("decryption failed — wrong key or tampered ciphertext".to_string()))')
content = content.replace('Err("invalid nonce length".to_string())', 'Err(ProtocolError::NonceError("invalid nonce length".to_string()))')

# 4. Replace .sign and .verify
content = content.replace('.map_err(|e| format!("system time error: {e}"))', '.map_err(|e| ProtocolError::NonceError(format!("system time error: {e}")))')
content = content.replace('.map_err(|e| format!("HMAC key error: {e}"))', '.map_err(|e| ProtocolError::SignatureError(format!("HMAC key error: {e}")))')

content = content.replace('Err("malformed job_nonce".to_string())', 'Err(ProtocolError::NonceError("malformed job_nonce".to_string()))')
content = content.replace('Err("malformed result_nonce".to_string())', 'Err(ProtocolError::NonceError("malformed result_nonce".to_string()))')
content = content.replace('.map_err(|_| "invalid timestamp in job_nonce".to_string())', '.map_err(|_| ProtocolError::NonceError("invalid timestamp in job_nonce".to_string()))')
content = content.replace('.map_err(|_| "invalid timestamp in result_nonce".to_string())', '.map_err(|_| ProtocolError::NonceError("invalid timestamp in result_nonce".to_string()))')
content = content.replace('Err(format!(\n                "job_nonce is too old ({} s, max {})",\n                now.saturating_sub(ts),\n                max_age_secs\n            ))', 'Err(ProtocolError::NonceError(format!("job_nonce is too old ({} s, max {})", now.saturating_sub(ts), max_age_secs)))')
content = content.replace('Err(format!(\n                "result_nonce is too old ({} s, max {})",\n                now.saturating_sub(ts),\n                max_age_secs\n            ))', 'Err(ProtocolError::NonceError(format!("result_nonce is too old ({} s, max {})", now.saturating_sub(ts), max_age_secs)))')
content = content.replace('.map_err(|_| "HMAC signature verification failed".to_string())', '.map_err(|_| ProtocolError::SignatureError("HMAC signature verification failed".to_string()))')


content = content.replace('.map_err(|_| {\n        "WORKER_SHARED_KEY environment variable is not set. \\\n         Generate with: openssl rand -hex 32"\n            .to_string()\n    })', '.map_err(|_| ProtocolError::InvalidKey("WORKER_SHARED_KEY environment variable is not set".to_string()))')
content = content.replace('.map_err(|e| format!("WORKER_SHARED_KEY is not valid hex: {e}"))', '.map_err(|e| ProtocolError::InvalidKey(format!("WORKER_SHARED_KEY is not valid hex: {e}")))')

with open("job-protocol/src/lib.rs", "w") as f:
    f.write(content)
