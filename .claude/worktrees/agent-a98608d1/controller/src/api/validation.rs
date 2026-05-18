use async_graphql::Result;

const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10MB

pub fn validate_payload_size(name: &str, payload: &str) -> Result<()> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(async_graphql::Error::new(format!(
            "{} payload exceeds maximum size of 10MB",
            name
        )));
    }
    Ok(())
}
