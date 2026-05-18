//! AWS Signature V4 signing for S3-compatible object storage.
//!
//! Reference: <https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html>
//!
//! Uses only crates already in the worker dependency tree (sha2, hmac, hex, chrono).

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Compute the SHA-256 hex digest of the given bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The conventional hash used for requests with no body (GET, DELETE, LIST).
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Generate AWS Signature V4 headers for an S3 request.
///
/// Returns a `Vec` of `(header_name, header_value)` tuples that must be added
/// to the outgoing HTTP request: `Authorization`, `x-amz-date`, and
/// `x-amz-content-sha256`.
pub fn sign_s3_request(
    method: &str,
    url: &url::Url,
    body_hash: &str, // SHA256 hex of request body, or UNSIGNED_PAYLOAD
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str, // "s3"
) -> Vec<(String, String)> {
    let now = Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let host = url.host_str().unwrap_or("");
    // Include port in the Host header when it is non-default (MinIO, etc.).
    let host_header = match url.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    };
    let path = url.path();

    // Query string parameters must be sorted by key for the canonical request.
    let canonical_query = sorted_query_string(url);

    // --- Step 1: Canonical request ---
    // Headers MUST be in sorted order by lowercase header name.
    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host_header, body_hash, amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        uri_encode_path(path),
        canonical_query,
        canonical_headers,
        signed_headers,
        body_hash
    );

    // --- Step 2: String to sign ---
    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_hash
    );

    // --- Step 3: Signing key & signature ---
    let k_date = hmac_sha256(
        format!("AWS4{}", secret_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    // --- Step 4: Authorization header ---
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key, credential_scope, signed_headers, signature
    );

    vec![
        ("Authorization".to_string(), authorization),
        ("x-amz-date".to_string(), amz_date),
        ("x-amz-content-sha256".to_string(), body_hash.to_string()),
    ]
}

/// HMAC-SHA256(key, data) returning raw bytes.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Sort query parameters by key (and by value for duplicate keys) as required
/// by the SigV4 canonical query string specification.
fn sorted_query_string(url: &url::Url) -> String {
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&")
}

/// URI-encode a string per RFC 3986. When `encode_slash` is true, forward
/// slashes are percent-encoded (used for query parameters). When false, they
/// are left as-is (used for the URI path).
fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'~' | b'.' => {
                out.push(byte as char);
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                out.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    out
}

/// URI-encode only the path portion (slashes are preserved).
fn uri_encode_path(path: &str) -> String {
    path.split('/')
        .map(|segment| uri_encode(segment, true))
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex_empty() {
        // SHA256("") is well-known
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_uri_encode_path_preserves_slashes() {
        assert_eq!(
            uri_encode_path("/bucket/my key.txt"),
            "/bucket/my%20key.txt"
        );
    }

    #[test]
    fn test_sorted_query_string() {
        let url =
            url::Url::parse("https://s3.amazonaws.com/bucket?prefix=foo&max-keys=10&list-type=2")
                .expect("S3 signing test operation should succeed");
        let qs = sorted_query_string(&url);
        assert_eq!(qs, "list-type=2&max-keys=10&prefix=foo");
    }

    #[test]
    fn test_sign_returns_required_headers() {
        let url = url::Url::parse("https://s3.us-east-1.amazonaws.com/bucket/key")
            .expect("S3 signing test operation should succeed");
        let headers = sign_s3_request(
            "GET",
            &url,
            UNSIGNED_PAYLOAD,
            "AKID",
            "SECRET",
            "us-east-1",
            "s3",
        );
        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"Authorization"));
        assert!(names.contains(&"x-amz-date"));
        assert!(names.contains(&"x-amz-content-sha256"));

        let auth = &headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .expect("S3 signing test operation should succeed")
            .1;
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKID/"));
    }
}
