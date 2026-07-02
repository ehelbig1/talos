//! `files` host interface (capability-based sandbox filesystem).

use super::*;

// ============================================================================
// Files (capability-based sandbox)
// ============================================================================

impl wit_files::Host for TalosContext {
    async fn read(&mut self, path: String) -> Result<Vec<u8>, wit_files::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        // MCP-586: defense-in-depth — match the explicit capability
        // check on `write` / `delete` / `exists`. The per-execution
        // tempdir wired into `fs_dir` (context.rs:388) means a
        // non-Filesystem module today gets NotFound from an empty
        // sandbox, but read/metadata/list_dir should fail-closed
        // with `Permissiondenied` like the sibling mutators. Without
        // an explicit gate the only barrier is the tempdir wiring;
        // if that ever changes (e.g. shared sandbox between
        // executions) the read-side would silently allow access.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("files-read", "capability-world", &path)
                .await;
            tracing::warn!("WASM module attempted file read but lacks Filesystem capability");
            return Err(wit_files::Error::Permissiondenied);
        }
        let safe_path = sanitize_path(&path)?;
        let __result = tokio::task::block_in_place(|| {
            // Check file size before reading to prevent OOM from large files.
            let meta = self
                .fs_dir
                .metadata(&safe_path)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => wit_files::Error::Notfound,
                    std::io::ErrorKind::PermissionDenied => wit_files::Error::Permissiondenied,
                    _ => wit_files::Error::Ioerror,
                })?;
            if meta.len() > MAX_FILE_READ_BYTES as u64 {
                tracing::warn!(
                    path = %path,
                    size = meta.len(),
                    limit = MAX_FILE_READ_BYTES,
                    "files::read blocked — file exceeds 64 MiB read limit"
                );
                return Err(wit_files::Error::Ioerror);
            }
            self.fs_dir.read(&safe_path).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => wit_files::Error::Notfound,
                std::io::ErrorKind::PermissionDenied => wit_files::Error::Permissiondenied,
                _ => wit_files::Error::Ioerror,
            })
        });

        if let Some(ref m) = __metrics {
            m.record_host_function_call("files::read", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn write(&mut self, path: String, contents: Vec<u8>) -> Result<(), wit_files::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<(), wit_files::Error> = async move {
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Filesystem | CapabilityWorld::Trusted
            ) {
                self.record_capability_denied("files-write", "capability-world", &path)
                    .await;
                tracing::warn!("WASM module attempted file access but lacks Filesystem capability");
                return Err(wit_files::Error::Permissiondenied);
            }

            // MCP-770 (2026-05-13): validate the path BEFORE the byte-quota
            // CAS loop. Pre-fix the CAS bumped `fs_bytes_written` first,
            // then `sanitize_path` ran — so a guest submitting a 16 MiB
            // body with a sandbox-escape path (`../foo`) reserved 16 MiB
            // against its own per-execution quota even though the write
            // failed with `Invalidpath`. A few such calls exhausted
            // `MAX_FS_BYTES_PER_EXECUTION`, blocking subsequent legitimate
            // writes for the rest of the execution despite zero bytes
            // having actually landed on disk. Extends the MCP-612 rule
            // ("counter only advances when admitted") to cover ALL
            // pre-write validation, not just the cap check itself.
            // Capability gate already ran above (line 5443), so this is
            // the only remaining pure-validation step that can fail before
            // we touch disk.
            let safe_path = sanitize_path(&path)?;

            // MCP-612 (2026-05-12): use a load-check-CAS loop instead of
            // fetch_add-then-check. The pre-fix shape bumped the counter
            // BEFORE the limit check, so a write that exceeded the cap left
            // the counter poisoned with phantom bytes. A subsequent SMALLER
            // write that would have fit under the cap would then fail
            // because the counter said it didn't. Same pattern issue
            // `check_rate_limit` (context.rs:1050) calls out explicitly in
            // its docstring: counter only advances when admitted.
            use std::sync::atomic::Ordering;
            let bytes = contents.len() as u64;
            loop {
                let current = self.fs_bytes_written.load(Ordering::Relaxed);
                let projected = current.saturating_add(bytes);
                if projected > MAX_FS_BYTES_PER_EXECUTION {
                    tracing::warn!(
                        module_id = ?self.module_id,
                        bytes_written = current,
                        attempted = bytes,
                        limit = MAX_FS_BYTES_PER_EXECUTION,
                        "File system write quota would be exceeded — not admitting"
                    );
                    if let Some(ref m) = self.metrics {
                        m.record_rate_limit_exceeded("fs");
                    }
                    return Err(wit_files::Error::Permissiondenied);
                }
                if self
                    .fs_bytes_written
                    .compare_exchange_weak(current, projected, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }

            tokio::task::block_in_place(|| {
                // Create parent directories within the sandbox if needed.
                if let Some(parent) = safe_path.parent() {
                    if parent != std::path::Path::new("") {
                        self.fs_dir
                            .create_dir_all(parent)
                            .map_err(|_| wit_files::Error::Ioerror)?;
                    }
                }
                self.fs_dir
                    .write(&safe_path, &contents)
                    .map_err(|e| match e.kind() {
                        std::io::ErrorKind::PermissionDenied => wit_files::Error::Permissiondenied,
                        _ => wit_files::Error::Ioerror,
                    })
            })
        }
        .await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("files::write", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn exists(&mut self, path: String) -> bool {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            // MCP-690 (2026-05-13): audit-ledger emission for
            // capability denial parity with the fallible siblings
            // (read/write/delete/metadata/list_dir all
            // record_capability_denied). Pre-fix `exists` silently
            // returned `false`, so a Minimal-world module probing
            // file paths could enumerate without an audit trail.
            self.record_capability_denied("files-exists", "capability-world", &path)
                .await;
            return false;
        }
        sanitize_path(&path)
            .map(|p| tokio::task::block_in_place(|| self.fs_dir.metadata(&p).is_ok()))
            .unwrap_or(false)
    }

    async fn metadata(
        &mut self,
        path: String,
    ) -> Result<wit_files::FileMetadata, wit_files::Error> {
        // MCP-586: sibling defense-in-depth gate to `read`. The
        // `exists` accessor below already returns false for
        // non-Filesystem worlds; `metadata` returning a real result
        // (size, mtime, is_directory) for a non-Filesystem actor
        // would expose more state than the matching `exists` call —
        // make both consistent.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("files-metadata", "capability-world", &path)
                .await;
            return Err(wit_files::Error::Permissiondenied);
        }
        let safe_path = sanitize_path(&path)?;
        let meta = tokio::task::block_in_place(|| {
            self.fs_dir
                .metadata(&safe_path)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => wit_files::Error::Notfound,
                    _ => wit_files::Error::Ioerror,
                })
        })?;
        let modified_unix = meta
            .modified()
            .ok()
            .and_then(|t| t.into_std().duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(wit_files::FileMetadata {
            size: meta.len(),
            modified_unix,
            is_directory: meta.is_dir(),
        })
    }

    async fn list_dir(&mut self, path: String) -> Result<Vec<String>, wit_files::Error> {
        // MCP-586: sibling defense-in-depth gate. A non-Filesystem
        // module enumerating directory entries shouldn't even reach
        // the sandbox tempdir.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("files-list-dir", "capability-world", &path)
                .await;
            return Err(wit_files::Error::Permissiondenied);
        }
        let safe_path = sanitize_path(&path)?;
        tokio::task::block_in_place(|| {
            let entries = self
                .fs_dir
                .read_dir(&safe_path)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => wit_files::Error::Notfound,
                    _ => wit_files::Error::Ioerror,
                })?;
            // Limit the number of entries to prevent OOM on directories with millions of files.
            const MAX_DIR_ENTRIES: usize = 10_000;
            let names: Vec<String> = entries
                .flatten()
                .take(MAX_DIR_ENTRIES)
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();
            Ok(names)
        })
    }

    async fn delete(&mut self, path: String) -> Result<(), wit_files::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Filesystem | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("files-delete", "capability-world", &path)
                .await;
            tracing::warn!("WASM module attempted file access but lacks Filesystem capability");
            return Err(wit_files::Error::Permissiondenied);
        }

        let safe_path = sanitize_path(&path)?;
        tokio::task::block_in_place(|| {
            let is_dir = self
                .fs_dir
                .metadata(&safe_path)
                .map(|m| m.is_dir())
                .unwrap_or(false);
            if is_dir {
                self.fs_dir.remove_dir_all(&safe_path)
            } else {
                self.fs_dir.remove_file(&safe_path)
            }
            .map_err(|_| wit_files::Error::Ioerror)
        })
    }
}

/// Strip `..` components and leading `/` to prevent path traversal attacks.
fn sanitize_path(path: &str) -> Result<std::path::PathBuf, wit_files::Error> {
    use std::path::{Component, PathBuf};
    let mut safe = PathBuf::new();
    for component in std::path::Path::new(path).components() {
        match component {
            Component::Normal(c) => safe.push(c),
            Component::CurDir => {}
            // Reject any attempt to escape the sandbox.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(wit_files::Error::Invalidpath);
            }
        }
    }
    Ok(safe)
}
