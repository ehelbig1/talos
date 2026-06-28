//! `talos-github` — GitHub App authentication primitives (RFC 0008, Phase B).
//!
//! Phase B replaces the long-lived PATs in the GitHub modules with a GitHub
//! App: short-lived, repo-scoped, auto-rotating **installation access tokens**.
//! This crate is step **B1** — the network-free crypto/protocol core:
//!
//! 1. [`AppSigningKey`] — parse the App private key (PKCS#1 or PKCS#8 PEM) and
//!    mint RS256 App JWTs ([`AppSigningKey::build_app_jwt`]).
//! 2. [`installation_token_request`] / [`parse_installation_token_response`] —
//!    build the `POST .../access_tokens` request and parse the response into an
//!    [`InstallationToken`].
//!
//! **Security posture (RFC 0008 D3 + open-question 3):** GitHub mandates RS256,
//! an RSA *private-key* operation — precisely the operation RUSTSEC-2023-0071
//! (the Marvin timing sidechannel in the `rsa` crate) affects, with no upstream
//! fix. Signing here is done with `ring` (constant-time, blinded, unaffected);
//! the `rsa` crate is used ONLY to normalize the key PEM to PKCS#8 (a
//! parse/encode operation), so the vulnerable signing/decryption path is never
//! invoked. See the RUSTSEC-2023-0071 entry in `deny.toml` / `audit.toml`.
//!
//! **Credential-free worker invariant:** all of this is controller-side. The
//! App private key never reaches the worker; only short-lived installation
//! tokens flow to module dispatch later (B4), through the existing encrypted
//! `vault://` secret path.
//!
//! The live HTTP call + the 1-hour token cache (wired into the proactive
//! refresh task) land in B3 — kept out here so this crate stays fully
//! unit-testable without a network or an HTTP-client dependency.

mod app_jwt;
mod error;
mod installation_token;

pub use app_jwt::{AppSigningKey, MAX_APP_JWT_TTL_SECS};
pub use error::GithubAppError;
pub use installation_token::{
    installation_token_request, parse_installation_token_response, InstallationToken,
    GITHUB_API_BASE,
};
