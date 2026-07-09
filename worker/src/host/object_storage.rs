//! `object-storage` (S3-compatible) host interface and bucket/key
//! identifier validation.

use super::*;

// ============================================================================
// Object Storage (S3-compatible via reqwest HTTP)
// ============================================================================

// MCP-602 (2026-05-12): per-method capability gate for object-storage.
// WIT-world linkage already restricts `talos:core/object-storage` to
// the `automation-node` world (== CapabilityWorld::Trusted) at compile
// time — the only world that imports it (verified via grep
// `import object-storage` in wit/talos.wit). But the S3 credentials
// (s3_endpoint / s3_access_key / s3_secret_key) are populated from
// env on EVERY TalosContext regardless of capability_world (see
// context.rs:639-641). If a module loads with the wrong world tag
// (operator override, wit_inspector returning Unknown but bindings
// still linking, or future changes to the WIT world set), these
// methods would silently use the operator-configured S3 creds.
// Fail closed unless capability_world is exactly Trusted.
fn require_object_storage_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_object_storage::Error> {
    if matches!(world, crate::wit_inspector::CapabilityWorld::Trusted) {
        Ok(())
    } else {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_object_storage call but lacks Trusted capability"
        );
        Err(wit_object_storage::Error::NotConfigured)
    }
}

/// MCP-1098 (2026-05-16): reject bucket / key values whose syntax would
/// rewrite the S3 URL built by `format!("{}/{}/{}", endpoint, bucket, key)`.
///
/// Pre-fix: `wit_object_storage::{put,get,delete,list_objects}` accept
/// caller-supplied `bucket` and `key` strings and concatenate them
/// straight into the URL. After `url::Url::parse`, embedded `?` becomes
/// the start of the query string, embedded `#` becomes the fragment,
/// and `..` segments get normalised away — and the S3 signer then
/// signs the resulting URL **including** the canonical query string,
/// so the request goes to S3 with the injected parameters bearing a
/// valid SigV4 signature.
///
/// Concrete vectors (Trusted-tier modules only, but defense-in-depth
/// matters regardless of tier):
/// * `key = "myfile?acl=public-read"` on PUT → S3 honors the ACL
///   override, setting the new object public-read despite the operator
///   having scoped the IAM role to private objects only.
/// * `key = "myfile?versionId=<other-id>"` on GET → bypasses the
///   intended key-scoped read with a versionId query parameter.
/// * `bucket = "../private-bucket"` → `url::Url::parse` normalises
///   `/intended/../private-bucket/key` to `/private-bucket/key`,
///   bucket-jumping out of the intended bucket.
/// * `bucket = "mybucket\r\nX-Injected: 1"` → CRLF in URL/host is
///   rejected by `url::Url::parse` (defense in depth) — but explicit
///   rejection here gives a clear error path with an audit log line
///   instead of the generic OperationFailed from URL parse.
///
/// The validators reject the URL-syntax characters AND path-traversal
/// segments BEFORE the URL is built. Percent-encoding is intentionally
/// NOT used — operators who legitimately need keys with `?`/`#` should
/// either re-scope the bucket access or stick to S3's recommended key
/// charset. Same boundary-validation discipline as
/// `talos-config::sanitize_oauth_error_code` (MCP-1094).
fn validate_s3_bucket(bucket: &str) -> Result<(), wit_object_storage::Error> {
    const MAX_S3_BUCKET_LEN: usize = 63;
    if bucket.is_empty() || bucket.len() > MAX_S3_BUCKET_LEN {
        tracing::warn!(
            bucket_len = bucket.len(),
            "wit_object_storage bucket name length invalid (must be 1..=63)"
        );
        return Err(wit_object_storage::Error::OperationFailed);
    }
    // S3 bucket-name charset (RFC 4648-ish subset): lowercase alnum, dot, hyphen.
    if !bucket
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        tracing::warn!(
            "wit_object_storage bucket name contains invalid characters (allowed: a-z 0-9 . -)"
        );
        return Err(wit_object_storage::Error::OperationFailed);
    }
    // Reject leading/trailing dot/hyphen and consecutive dots, matching AWS rules.
    if bucket.starts_with('.')
        || bucket.ends_with('.')
        || bucket.starts_with('-')
        || bucket.ends_with('-')
        || bucket.contains("..")
    {
        tracing::warn!(
            "wit_object_storage bucket name violates AWS naming rules (no leading/trailing . or -, no ..)"
        );
        return Err(wit_object_storage::Error::OperationFailed);
    }
    Ok(())
}

fn validate_s3_key(key: &str) -> Result<(), wit_object_storage::Error> {
    const MAX_S3_KEY_LEN: usize = 1024;
    if key.is_empty() || key.len() > MAX_S3_KEY_LEN {
        tracing::warn!(
            key_len = key.len(),
            "wit_object_storage key length invalid (must be 1..=1024)"
        );
        return Err(wit_object_storage::Error::OperationFailed);
    }
    // Reject URL-syntax characters that would rewrite the request after
    // `url::Url::parse`. `?` and `#` are the immediate query/fragment
    // separators; control chars (0x00..=0x1F, 0x7F) cover CRLF and any
    // other byte sequences that would either be rejected by HTTP header
    // formation or change request semantics.
    if key
        .bytes()
        .any(|b| b == b'?' || b == b'#' || matches!(b, 0..=0x1F | 0x7F))
    {
        tracing::warn!(
            "wit_object_storage key contains forbidden character (?, #, or control byte)"
        );
        return Err(wit_object_storage::Error::OperationFailed);
    }
    // Reject path-traversal segments — `url::Url::parse` would normalise
    // these away, jumping out of the intended bucket prefix.
    if key.split('/').any(|seg| seg == ".." || seg == ".") {
        tracing::warn!("wit_object_storage key contains path-traversal segment (.. or .)");
        return Err(wit_object_storage::Error::OperationFailed);
    }
    Ok(())
}

impl wit_object_storage::Host for TalosContext {
    async fn put(
        &mut self,
        req: wit_object_storage::PutRequest,
    ) -> Result<(), wit_object_storage::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity (sibling of MCP-696).
        // `require_object_storage_capability` is sync/pure; inline the
        // audit at the call site before delegating. Pattern matches
        // the four wit_object_storage methods (put/get/delete/list_objects).
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            let target = format!("{}/{}", req.bucket, req.key);
            self.record_capability_denied("wit_object_storage::put", "capability-world", &target)
                .await;
        }
        require_object_storage_capability(&self.capability_world)?;
        // MCP-1098: bucket/key URL-injection guard.
        validate_s3_bucket(&req.bucket)?;
        validate_s3_key(&req.key)?;
        // Write-ceiling gate: an object put mutates storage — refuse for
        // read-only actors. Inert unless enforcement is on.
        if self
            .write_ceiling_refuses("object-storage-put", &format!("{}/{}", req.bucket, req.key))
            .await
        {
            return Err(wit_object_storage::Error::AccessDenied);
        }
        let endpoint = self
            .s3_endpoint
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let access_key = self
            .s3_access_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let secret_key = self
            .s3_secret_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let region = self.s3_region.as_deref().unwrap_or("us-east-1");

        // Size limit: 100 MB per object
        const MAX_OBJECT_SIZE: usize = 100 * 1024 * 1024;
        if req.body.len() > MAX_OBJECT_SIZE {
            tracing::warn!(
                module_id = ?self.module_id,
                size = req.body.len(),
                "Object upload exceeds 100MB limit"
            );
            return Err(wit_object_storage::Error::OperationFailed);
        }

        let url_str = format!("{}/{}/{}", endpoint, req.bucket, req.key);
        let parsed_url = url::Url::parse(&url_str).map_err(|e| {
            tracing::warn!(error = %e, "Invalid S3 URL");
            wit_object_storage::Error::OperationFailed
        })?;
        let content_type = req
            .content_type
            .unwrap_or_else(|| "application/octet-stream".to_string());

        let body_hash = crate::s3_signer::sha256_hex(&req.body);
        let auth_headers = crate::s3_signer::sign_s3_request(
            "PUT",
            &parsed_url,
            &body_hash,
            access_key,
            secret_key,
            region,
            "s3",
        );

        let client = self.http_client.clone();
        let mut builder = client.put(parsed_url).header("Content-Type", &content_type);
        for (name, value) in &auth_headers {
            builder = builder.header(name, value);
        }
        // MCP-720: per-op timeout (see OBJECT_STORAGE_TIMEOUT_MS).
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(OBJECT_STORAGE_TIMEOUT_MS),
            builder.body(req.body).send(),
        )
        .await
        .map_err(|_| {
            tracing::warn!(timeout_ms = OBJECT_STORAGE_TIMEOUT_MS, "S3 PUT timed out");
            wit_object_storage::Error::OperationFailed
        })?
        .map_err(|e| {
            tracing::warn!(error = %e, "S3 PUT failed");
            wit_object_storage::Error::OperationFailed
        })?;

        if !response.status().is_success() {
            tracing::warn!(status = response.status().as_u16(), "S3 PUT returned error");
            return Err(wit_object_storage::Error::OperationFailed);
        }

        Ok(())
    }

    async fn get(
        &mut self,
        bucket: String,
        key: String,
    ) -> Result<wit_object_storage::GetResponse, wit_object_storage::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see put above.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            let target = format!("{}/{}", bucket, key);
            self.record_capability_denied("wit_object_storage::get", "capability-world", &target)
                .await;
        }
        require_object_storage_capability(&self.capability_world)?;
        // MCP-1098: bucket/key URL-injection guard.
        validate_s3_bucket(&bucket)?;
        validate_s3_key(&key)?;
        let endpoint = self
            .s3_endpoint
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let access_key = self
            .s3_access_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let secret_key = self
            .s3_secret_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let region = self.s3_region.as_deref().unwrap_or("us-east-1");

        let url_str = format!("{}/{}/{}", endpoint, bucket, key);
        let parsed_url = url::Url::parse(&url_str).map_err(|e| {
            tracing::warn!(error = %e, "Invalid S3 URL");
            wit_object_storage::Error::OperationFailed
        })?;

        let auth_headers = crate::s3_signer::sign_s3_request(
            "GET",
            &parsed_url,
            crate::s3_signer::UNSIGNED_PAYLOAD,
            access_key,
            secret_key,
            region,
            "s3",
        );

        let client = self.http_client.clone();
        let mut builder = client.get(parsed_url);
        for (name, value) in &auth_headers {
            builder = builder.header(name, value);
        }
        // MCP-720: per-op timeout (see OBJECT_STORAGE_TIMEOUT_MS).
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(OBJECT_STORAGE_TIMEOUT_MS),
            builder.send(),
        )
        .await
        .map_err(|_| {
            tracing::warn!(timeout_ms = OBJECT_STORAGE_TIMEOUT_MS, "S3 GET timed out");
            wit_object_storage::Error::OperationFailed
        })?
        .map_err(|e| {
            tracing::warn!(error = %e, "S3 GET failed");
            wit_object_storage::Error::OperationFailed
        })?;

        if response.status().as_u16() == 404 {
            return Err(wit_object_storage::Error::NotFound);
        }
        if !response.status().is_success() {
            tracing::warn!(status = response.status().as_u16(), "S3 GET returned error");
            return Err(wit_object_storage::Error::OperationFailed);
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Check Content-Length before downloading to prevent OOM.
        if let Some(cl) = response.content_length() {
            if cl > MAX_OBJECT_READ_BYTES as u64 {
                tracing::warn!(
                    bucket = %bucket,
                    key = %key,
                    content_length = cl,
                    limit = MAX_OBJECT_READ_BYTES,
                    "object-storage::get blocked — object exceeds 64 MiB read limit"
                );
                return Err(wit_object_storage::Error::OperationFailed);
            }
        }

        // MCP-1115 (2026-05-16): stream chunk-by-chunk instead of
        // `response.bytes().await`. The pre-check above catches
        // honest servers that declare Content-Length, but a
        // malicious / compromised / MITM'd S3-compatible endpoint
        // could (a) omit Content-Length on a chunked-transfer
        // response, or (b) lie about it. `response.bytes()` then
        // buffers the entire body into host RAM BEFORE the
        // post-download `body.len() > MAX` check fires — too late
        // to stop the OOM. Sibling shape to wit_http::fetch which
        // streams + checks per chunk (line ~2021).
        use futures_util::StreamExt;
        let mut stream = response.bytes_stream();
        let mut body_bytes: Vec<u8> = Vec::new();
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| {
                tracing::warn!(error = %e, "S3 GET failed reading body chunk");
                wit_object_storage::Error::OperationFailed
            })?;
            if body_bytes.len().saturating_add(chunk.len()) > MAX_OBJECT_READ_BYTES {
                tracing::warn!(
                    bucket = %bucket,
                    key = %key,
                    accumulated = body_bytes.len(),
                    chunk_len = chunk.len(),
                    limit = MAX_OBJECT_READ_BYTES,
                    "object-storage::get blocked — streaming body exceeds 64 MiB limit"
                );
                return Err(wit_object_storage::Error::OperationFailed);
            }
            body_bytes.extend_from_slice(&chunk);
        }

        let size = body_bytes.len() as u64;

        Ok(wit_object_storage::GetResponse {
            body: body_bytes,
            content_type,
            size,
        })
    }

    async fn delete(
        &mut self,
        bucket: String,
        key: String,
    ) -> Result<(), wit_object_storage::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see put above.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            let target = format!("{}/{}", bucket, key);
            self.record_capability_denied(
                "wit_object_storage::delete",
                "capability-world",
                &target,
            )
            .await;
        }
        require_object_storage_capability(&self.capability_world)?;
        // MCP-1098: bucket/key URL-injection guard.
        validate_s3_bucket(&bucket)?;
        validate_s3_key(&key)?;
        // Write-ceiling gate: an object delete mutates storage — refuse for
        // read-only actors. Inert unless enforcement is on.
        if self
            .write_ceiling_refuses("object-storage-delete", &format!("{}/{}", bucket, key))
            .await
        {
            return Err(wit_object_storage::Error::AccessDenied);
        }
        let endpoint = self
            .s3_endpoint
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let access_key = self
            .s3_access_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let secret_key = self
            .s3_secret_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let region = self.s3_region.as_deref().unwrap_or("us-east-1");

        let url_str = format!("{}/{}/{}", endpoint, bucket, key);
        let parsed_url = url::Url::parse(&url_str).map_err(|e| {
            tracing::warn!(error = %e, "Invalid S3 URL");
            wit_object_storage::Error::OperationFailed
        })?;

        let auth_headers = crate::s3_signer::sign_s3_request(
            "DELETE",
            &parsed_url,
            crate::s3_signer::UNSIGNED_PAYLOAD,
            access_key,
            secret_key,
            region,
            "s3",
        );

        let client = self.http_client.clone();
        let mut builder = client.delete(parsed_url);
        for (name, value) in &auth_headers {
            builder = builder.header(name, value);
        }
        // MCP-720: per-op timeout (see OBJECT_STORAGE_TIMEOUT_MS).
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(OBJECT_STORAGE_TIMEOUT_MS),
            builder.send(),
        )
        .await
        .map_err(|_| {
            tracing::warn!(
                timeout_ms = OBJECT_STORAGE_TIMEOUT_MS,
                "S3 DELETE timed out"
            );
            wit_object_storage::Error::OperationFailed
        })?
        .map_err(|e| {
            tracing::warn!(error = %e, "S3 DELETE failed");
            wit_object_storage::Error::OperationFailed
        })?;

        if response.status().as_u16() == 404 {
            return Err(wit_object_storage::Error::NotFound);
        }
        if !response.status().is_success() {
            tracing::warn!(
                status = response.status().as_u16(),
                "S3 DELETE returned error"
            );
            return Err(wit_object_storage::Error::OperationFailed);
        }

        Ok(())
    }

    async fn list_objects(
        &mut self,
        bucket: String,
        prefix: Option<String>,
        max_keys: Option<u32>,
    ) -> Result<Vec<wit_object_storage::ListEntry>, wit_object_storage::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see put above.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            let target = format!("{}/{}", bucket, prefix.as_deref().unwrap_or(""));
            self.record_capability_denied(
                "wit_object_storage::list_objects",
                "capability-world",
                &target,
            )
            .await;
        }
        require_object_storage_capability(&self.capability_world)?;
        // MCP-1098: bucket name URL-injection guard. Prefix already
        // URL-encoded below, so no validator needed there.
        validate_s3_bucket(&bucket)?;
        let endpoint = self
            .s3_endpoint
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let access_key = self
            .s3_access_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let secret_key = self
            .s3_secret_key
            .as_ref()
            .ok_or(wit_object_storage::Error::NotConfigured)?;
        let region = self.s3_region.as_deref().unwrap_or("us-east-1");

        let mut url_str = format!("{}/{}?list-type=2", endpoint, bucket);
        if let Some(ref p) = prefix {
            // URL-encode the prefix to prevent query parameter injection via
            // characters like '&', '=', or '%' in the prefix value.
            let encoded: String = url::form_urlencoded::byte_serialize(p.as_bytes()).collect();
            url_str.push_str(&format!("&prefix={}", encoded));
        }
        if let Some(max) = max_keys {
            url_str.push_str(&format!("&max-keys={}", max.min(1000)));
        }

        let parsed_url = url::Url::parse(&url_str).map_err(|e| {
            tracing::warn!(error = %e, "Invalid S3 URL");
            wit_object_storage::Error::OperationFailed
        })?;

        let auth_headers = crate::s3_signer::sign_s3_request(
            "GET",
            &parsed_url,
            crate::s3_signer::UNSIGNED_PAYLOAD,
            access_key,
            secret_key,
            region,
            "s3",
        );

        let client = self.http_client.clone();
        let mut builder = client.get(parsed_url);
        for (name, value) in &auth_headers {
            builder = builder.header(name, value);
        }
        // MCP-720: per-op timeout (see OBJECT_STORAGE_TIMEOUT_MS).
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(OBJECT_STORAGE_TIMEOUT_MS),
            builder.send(),
        )
        .await
        .map_err(|_| {
            tracing::warn!(timeout_ms = OBJECT_STORAGE_TIMEOUT_MS, "S3 LIST timed out");
            wit_object_storage::Error::OperationFailed
        })?
        .map_err(|e| {
            tracing::warn!(error = %e, "S3 LIST failed");
            wit_object_storage::Error::OperationFailed
        })?;

        if !response.status().is_success() {
            tracing::warn!(
                status = response.status().as_u16(),
                "S3 LIST returned error"
            );
            return Err(wit_object_storage::Error::OperationFailed);
        }

        // MCP-1115: stream + cap LIST XML response. Sibling of the
        // wit_object_storage::get streaming fix above. `response.text()`
        // pre-fix buffered the entire XML response into host RAM with
        // NO size cap — a malicious S3-compatible endpoint that
        // ignores max-keys=1000 could OOM the worker. Stream chunks
        // up to MAX_LIST_RESPONSE_BYTES (4 MiB), then convert to
        // String once we know the size is bounded.
        use futures_util::StreamExt;
        let mut stream = response.bytes_stream();
        let mut body_bytes: Vec<u8> = Vec::new();
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| {
                tracing::warn!(error = %e, "S3 LIST failed reading body chunk");
                wit_object_storage::Error::OperationFailed
            })?;
            if body_bytes.len().saturating_add(chunk.len()) > MAX_LIST_RESPONSE_BYTES {
                tracing::warn!(
                    bucket = %bucket,
                    accumulated = body_bytes.len(),
                    chunk_len = chunk.len(),
                    limit = MAX_LIST_RESPONSE_BYTES,
                    "object-storage::list_objects blocked — streaming XML exceeds 4 MiB limit"
                );
                return Err(wit_object_storage::Error::OperationFailed);
            }
            body_bytes.extend_from_slice(&chunk);
        }
        let body = String::from_utf8_lossy(&body_bytes).into_owned();

        // Parse S3 XML list response
        let mut entries = Vec::new();
        for key_match in body.split("<Key>").skip(1) {
            if let Some(key_end) = key_match.find("</Key>") {
                let key = key_match[..key_end].to_string();
                let size = key_match
                    .split("<Size>")
                    .nth(1)
                    .and_then(|s| s.split("</Size>").next())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let last_modified = key_match
                    .split("<LastModified>")
                    .nth(1)
                    .and_then(|s| s.split("</LastModified>").next())
                    .map(String::from);

                entries.push(wit_object_storage::ListEntry {
                    key,
                    size,
                    last_modified,
                });
            }
        }

        Ok(entries)
    }
}

// ============================================================================
// MCP-1098: S3 bucket / key URL-injection validator tests
// ============================================================================
#[cfg(test)]
mod s3_identifier_validation_tests {
    use super::{validate_s3_bucket, validate_s3_key};

    #[test]
    fn bucket_canonical_names_accepted() {
        for b in [
            "my-bucket",
            "team.assets",
            "logs2024",
            "abc",
            // 63-char (AWS max).
            "a23456789012345678901234567890123456789012345678901234567890123",
        ] {
            assert!(validate_s3_bucket(b).is_ok(), "rejected: {b}");
        }
    }

    #[test]
    fn bucket_url_injection_rejected() {
        for b in [
            "",                // empty
            "Bucket",          // uppercase
            "my_bucket",       // underscore
            "my bucket",       // space
            ".bucket",         // leading dot
            "bucket.",         // trailing dot
            "-bucket",         // leading hyphen
            "bucket-",         // trailing hyphen
            "my..bucket",      // consecutive dots
            "my/other-bucket", // slash
            "../private",      // traversal
            "bucket?acl=x",    // query injection
            "bucket#frag",     // fragment
            "bucket\r\nX:1",   // CRLF
            "bucket\x00null",  // NUL
        ] {
            assert!(
                validate_s3_bucket(b).is_err(),
                "accepted disallowed bucket: {b:?}"
            );
        }
    }

    #[test]
    fn key_canonical_paths_accepted() {
        for k in [
            "file.txt",
            "year=2026/month=05/day=16/event.json",
            "user/uuid-1234/profile.png",
            "deep/path/with/many/segments/file.bin",
            // Special-but-permitted chars per S3 recommended charset.
            "report (final) v2.csv",
            "logs+extra-data.txt",
        ] {
            assert!(validate_s3_key(k).is_ok(), "rejected: {k:?}");
        }
    }

    #[test]
    fn key_url_injection_rejected() {
        // The headline attack: ?acl= would set object ACL post-signing.
        assert!(validate_s3_key("file.txt?acl=public-read").is_err());
        // Sibling variants the URL parser would honour.
        assert!(validate_s3_key("file?versionId=abc").is_err());
        assert!(validate_s3_key("path/file#fragment").is_err());
        assert!(validate_s3_key("file\r\nHeader: 1").is_err());
        assert!(validate_s3_key("file\x00name").is_err());
        assert!(validate_s3_key("file\x01control").is_err());
    }

    #[test]
    fn key_traversal_segments_rejected() {
        assert!(validate_s3_key("../other-bucket-key").is_err());
        assert!(validate_s3_key("path/../escape").is_err());
        assert!(validate_s3_key("path/./normal").is_err());
        assert!(validate_s3_key("..").is_err());
        assert!(validate_s3_key(".").is_err());
        // Sanity: a literal ".." substring inside a segment is fine.
        assert!(validate_s3_key("path/with..dots-in-name").is_ok());
    }

    #[test]
    fn key_length_bounds_enforced() {
        assert!(validate_s3_key("").is_err());
        let max = "x".repeat(1024);
        assert!(validate_s3_key(&max).is_ok());
        let over = "x".repeat(1025);
        assert!(validate_s3_key(&over).is_err());
    }
}
