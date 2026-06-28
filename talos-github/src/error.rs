use thiserror::Error;

/// Errors from the GitHub App auth primitives. Messages are operator-facing
/// (key-format / config problems) and deliberately carry NO secret material —
/// never the private key bytes, never a minted token.
#[derive(Debug, Error)]
pub enum GithubAppError {
    /// The supplied App private key PEM could not be parsed or was rejected by
    /// the signing backend (wrong format, too-small modulus, corrupt PEM).
    #[error("invalid GitHub App private key: {0}")]
    InvalidKey(String),

    /// The App id was empty / malformed (it becomes the JWT `iss`).
    #[error("invalid GitHub App id: {0}")]
    InvalidAppId(String),

    /// The signing operation itself failed.
    #[error("failed to sign GitHub App JWT: {0}")]
    Signing(String),

    /// The `POST .../access_tokens` response body could not be parsed.
    #[error("failed to parse installation-token response: {0}")]
    ParseResponse(String),
}
