//! `talos-offhost-backup` — get the ciphertext off this host (Tier 2).
//!
//! ```text
//! upload             encrypt + PUT every local artifact the bucket lacks
//! fetch              GET + decrypt one archive (the restore drill's source)
//! plan               print what `upload` would do (no credentials needed with --offline)
//! probe-append-only  try to DELETE and to OVERWRITE; both must be REFUSED
//! ```
//!
//! # The three things this binary is careful about
//!
//! 1. **It never fails the local dump.** It is a separate process on a
//!    separate schedule; the `postgres-backup` sidecar does not call it and
//!    cannot be broken by it. That is also why a persistent failure would be
//!    invisible, which is why every path writes the textfile metric.
//! 2. **Secrets never reach argv.** The B2 secret is read by `aws` from the
//!    environment; the `age` passphrase is a value in memory. `ps` shows
//!    neither. The B2 key **id** is logged; the secret is not.
//! 3. **Every failure is CLASSIFIED into a closed set** before it becomes a
//!    metric label, so the alert on it is well-defined before it first
//!    fires and cannot be turned into a cardinality bomb by provider text.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use age::secrecy::SecretString;
use talos_offhost_backup::aws::{
    delete_object_argv, get_object_argv, head_object_argv, list_objects_argv, put_object_argv,
    S3Target,
};
use talos_offhost_backup::classify::{classify_aws_failure, FailureReason};
use talos_offhost_backup::crypto::{decrypt_file, encrypt_file};
use talos_offhost_backup::key::{ArtifactKind, KEY_ROOT};
use talos_offhost_backup::metrics::{self, MetricState, TEXTFILE_NAME};
use talos_offhost_backup::passphrase::{
    assert_contained, assert_non_empty, choose_source, path_like_tokens, PassphraseSource,
};
use talos_offhost_backup::plan::{
    age_hours, newest_for_kind, plan_uploads, LocalArtifact, UploadMode,
};

// ── Small output helpers. Nothing here ever prints a secret. ──────────
fn log(msg: &str) {
    eprintln!("▶ {msg}");
}
fn ok(msg: &str) {
    eprintln!("✓ {msg}");
}
fn warn(msg: &str) {
    eprintln!("⚠ {msg}");
}

/// A failure that already knows which metric label it belongs under.
#[derive(Debug)]
struct Failure {
    reason: FailureReason,
    detail: String,
}

impl Failure {
    fn new(reason: FailureReason, detail: impl Into<String>) -> Failure {
        Failure {
            reason,
            detail: detail.into(),
        }
    }
}

type R<T> = Result<T, Failure>;

// ═══════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════

/// Non-secret configuration. Everything in here is safe to print.
#[derive(Debug, Clone)]
struct Config {
    target: Option<S3Target>,
    backup_dir: PathBuf,
    textfile_dir: PathBuf,
    aws_bin: String,
    /// Directories a passphrase source may NOT resolve inside. Supplied by
    /// the wrapper script, which knows both the worktree root and the main
    /// clone (`git rev-parse --git-common-dir`) — the pair #639 needed after
    /// a worktree run accepted a key file sitting in the main checkout.
    checkout_roots: Vec<PathBuf>,
    passphrase_cmd: Option<String>,
    passphrase_file: Option<String>,
    escrow_timeout_secs: u64,
    max_age_hours: i64,
    /// Logged so an operator can tell WHICH credential is in play. The key
    /// id is not a secret; the key itself never appears anywhere.
    access_key_id: Option<String>,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

fn resolve_config() -> Config {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let bucket = env("TALOS_OFFHOST_B2_BUCKET");
    let endpoint = env("TALOS_OFFHOST_B2_ENDPOINT");
    let region = env("TALOS_OFFHOST_B2_REGION");
    // All three or nothing. A bucket with no endpoint would silently address
    // real AWS S3 — a different provider and a different account.
    let target = match (bucket, endpoint, region) {
        (Some(bucket), Some(endpoint_url), Some(region)) => Some(S3Target {
            endpoint_url,
            bucket,
            region,
        }),
        _ => None,
    };
    Config {
        target,
        backup_dir: PathBuf::from(
            env("TALOS_OFFHOST_BACKUP_DIR")
                .or_else(|| env("TALOS_BACKUP_DIR"))
                .unwrap_or_else(|| format!("{home}/.talos/backups")),
        ),
        textfile_dir: PathBuf::from(
            env("TALOS_OFFHOST_TEXTFILE_DIR")
                .or_else(|| env("TALOS_TEXTFILE_DIR"))
                .unwrap_or_else(|| format!("{home}/.talos/metrics/textfile_collector")),
        ),
        aws_bin: env("TALOS_OFFHOST_AWS_BIN").unwrap_or_else(|| "aws".to_string()),
        checkout_roots: env("TALOS_OFFHOST_CHECKOUT_ROOTS")
            .map(|s| {
                s.split(':')
                    .filter(|p| !p.is_empty())
                    .map(PathBuf::from)
                    .collect()
            })
            .unwrap_or_default(),
        passphrase_cmd: env("TALOS_OFFHOST_AGE_PASSPHRASE_CMD"),
        passphrase_file: env("TALOS_OFFHOST_AGE_PASSPHRASE_FILE"),
        escrow_timeout_secs: env("TALOS_OFFHOST_ESCROW_TIMEOUT_SECS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
        max_age_hours: env("TALOS_OFFHOST_MAX_AGE_HOURS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(168),
        access_key_id: env("AWS_ACCESS_KEY_ID"),
    }
}

impl Config {
    fn target(&self) -> R<&S3Target> {
        self.target.as_ref().ok_or_else(|| {
            Failure::new(
                FailureReason::Config,
                "off-host destination not configured. Set all three of \
                 TALOS_OFFHOST_B2_BUCKET, TALOS_OFFHOST_B2_ENDPOINT and \
                 TALOS_OFFHOST_B2_REGION — see docs/offhost-backup.md.",
            )
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Passphrase resolution
// ═══════════════════════════════════════════════════════════════════════

/// Resolve the `age` passphrase, applying #639's containment rules.
///
/// The value is returned in a `SecretString` and never printed, never
/// written to a file, and never placed on a command line.
fn resolve_passphrase(cfg: &Config) -> R<(SecretString, String)> {
    let source = choose_source(
        cfg.passphrase_cmd.as_deref(),
        cfg.passphrase_file.as_deref(),
    )
    .map_err(|e| Failure::new(FailureReason::Config, e.to_string()))?;

    // FAIL CLOSED on an undeterminable checkout root. The wrapper always
    // supplies it; if nothing did, the "is this key sitting in the repo?"
    // question cannot be answered, and answering it "no" by default is how a
    // containment check becomes decorative.
    if cfg.checkout_roots.is_empty() {
        return Err(Failure::new(
            FailureReason::Config,
            "TALOS_OFFHOST_CHECKOUT_ROOTS is unset, so the passphrase source cannot be \
             checked for living inside a checkout. Run this through \
             scripts/offhost-backup/upload.sh (which sets it from `git rev-parse`), or set \
             it yourself to a colon-separated list of checkout roots.",
        ));
    }

    let backup_real = std::fs::canonicalize(&cfg.backup_dir).ok();
    let roots: Vec<PathBuf> = cfg
        .checkout_roots
        .iter()
        .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
        .collect();

    let raw = match &source {
        PassphraseSource::File(p) => {
            let real = std::fs::canonicalize(p).map_err(|e| {
                Failure::new(
                    FailureReason::Config,
                    format!("TALOS_OFFHOST_AGE_PASSPHRASE_FILE='{}': {e}", p.display()),
                )
            })?;
            assert_contained(&real, "age passphrase file", &roots, backup_real.as_deref())
                .map_err(|e| Failure::new(FailureReason::Config, e.to_string()))?;
            let text = std::fs::read_to_string(&real).map_err(|e| {
                Failure::new(
                    FailureReason::Config,
                    format!("could not read the age passphrase file: {e}"),
                )
            })?;
            text.lines().next().unwrap_or_default().to_string()
        }
        PassphraseSource::Command(c) => {
            // Same token scan as #639: the guarded branch must not be the one
            // nobody is told to use. STATED LIMIT — a token scan is not a
            // shell parser (see passphrase.rs).
            for tok in path_like_tokens(c) {
                if let Ok(real) = std::fs::canonicalize(&tok) {
                    assert_contained(
                        &real,
                        &format!("age passphrase command argument '{tok}'"),
                        &roots,
                        backup_real.as_deref(),
                    )
                    .map_err(|e| Failure::new(FailureReason::Config, e.to_string()))?;
                }
            }
            run_bounded(c, cfg.escrow_timeout_secs)?
        }
    };

    // A CR from a Windows-y clipboard or a CRLF file is the single most
    // confusing possible outcome of a correct escrow: it presents as "wrong
    // passphrase" against an archive that is fine.
    let raw = raw.trim_end_matches(['\r', '\n']).to_string();
    assert_non_empty(&raw).map_err(|e| {
        Failure::new(
            FailureReason::Config,
            format!("{e}\n   source: {}", source.describe()),
        )
    })?;
    Ok((SecretString::from(raw), source.describe()))
}

/// Run a passphrase helper under a watchdog and return its first stdout line.
///
/// The watchdog kills the whole PROCESS GROUP. `sh -c 'op read …'` forks the
/// real helper as a grandchild that inherits the capture pipe, so signalling
/// only the direct child leaves the read blocked on an EOF that never
/// arrives — the drill measured exactly that in #639, with a `sleep 300`
/// surviving as a PID-1 orphan.
///
/// stderr is left ATTACHED so a password manager can prompt and a failing
/// helper can say why. Swallowing it is how an unattended run turns into
/// silence.
fn run_bounded(cmd: &str, secs: u64) -> R<String> {
    use std::os::unix::process::CommandExt;

    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        // New process group, so ONE kill reaches every descendant.
        .process_group(0)
        .spawn()
        .map_err(|e| {
            Failure::new(
                FailureReason::Config,
                format!("could not run the age passphrase command: {e}"),
            )
        })?;

    let pgid = child.id() as i32;
    let mut stdout = child.stdout.take().expect("piped");
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    let out = match rx.recv_timeout(std::time::Duration::from_secs(secs)) {
        Ok(buf) => buf,
        Err(_) => {
            // SAFETY: negative pid targets the process group we created.
            unsafe {
                libc::kill(-pgid, libc::SIGTERM);
                std::thread::sleep(std::time::Duration::from_secs(2));
                libc::kill(-pgid, libc::SIGKILL);
            }
            let _ = child.wait();
            return Err(Failure::new(
                FailureReason::Config,
                format!(
                    "the age passphrase command did not finish within {secs}s and was killed. \
                     A helper that PROMPTS (Touch ID, a passphrase) cannot work unattended — \
                     under launchd there is nobody to answer it. Use a service-account token, \
                     or raise TALOS_OFFHOST_ESCROW_TIMEOUT_SECS if it is merely slow."
                ),
            ));
        }
    };
    let _ = child.wait();
    // Exit status is deliberately NOT consulted — only what the helper
    // PRINTED. `op read` exits 0 while printing a diagnostic on a stale
    // session, and a helper that prints the key and exits 1 is still usable.
    // The empty-output case is caught by assert_non_empty with a message
    // naming the source.
    Ok(String::from_utf8_lossy(&out)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string())
}

// ═══════════════════════════════════════════════════════════════════════
// The `aws` runner
// ═══════════════════════════════════════════════════════════════════════

struct Aws {
    bin: String,
}

#[derive(Debug)]
struct AwsOut {
    stdout: String,
}

impl Aws {
    /// Run one `aws` invocation. Credentials come from the inherited
    /// environment and are never added here.
    fn run(&self, argv: &[String]) -> R<AwsOut> {
        let out = Command::new(&self.bin)
            .args(argv)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                Failure::new(
                    FailureReason::MissingTool,
                    format!("could not execute '{}': {e}", self.bin),
                )
            })?;
        if out.status.success() {
            return Ok(AwsOut {
                stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            });
        }
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        Err(Failure::new(
            classify_aws_failure(out.status.code(), &stderr),
            // The FIRST line only. AWS CLI tracebacks are long and the tail
            // of one has been known to echo a request body.
            stderr.lines().next().unwrap_or("(no stderr)").to_string(),
        ))
    }
}

/// Every key under the Talos prefix, following pagination to the end.
///
/// Stopping at the first page would make "the newest object in the bucket"
/// wrong once the bucket holds more than 1000 archives, and it would make
/// `plan_uploads` re-PUT — i.e. OVERWRITE — an archive it could not see.
fn list_all_keys(aws: &Aws, t: &S3Target) -> R<Vec<String>> {
    let mut keys = Vec::new();
    let mut token: Option<String> = None;
    // Bounded: a provider that never stops returning a continuation token
    // must not spin forever. 1000 pages × 1000 keys is ~2700 years of daily
    // archives.
    for _ in 0..1000 {
        let out = aws.run(&list_objects_argv(
            t,
            &format!("{KEY_ROOT}/"),
            token.as_deref(),
        ))?;
        let v: serde_json::Value = if out.stdout.trim().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&out.stdout).map_err(|e| {
                Failure::new(
                    FailureReason::Other,
                    format!("could not parse the bucket listing: {e}"),
                )
            })?
        };
        if let Some(items) = v.get("Contents").and_then(|c| c.as_array()) {
            for it in items {
                if let Some(k) = it.get("Key").and_then(|k| k.as_str()) {
                    keys.push(k.to_string());
                }
            }
        }
        match v.get("NextContinuationToken").and_then(|t| t.as_str()) {
            Some(next) => token = Some(next.to_string()),
            None => return Ok(keys),
        }
    }
    Err(Failure::new(
        FailureReason::Other,
        "bucket listing did not terminate after 1000 pages",
    ))
}

// ═══════════════════════════════════════════════════════════════════════
// Local artifact discovery
// ═══════════════════════════════════════════════════════════════════════

fn discover_local(backup_dir: &Path) -> Vec<LocalArtifact> {
    let mut out = Vec::new();
    for kind in ArtifactKind::ALL {
        let dir = if kind.backup_subdir().is_empty() {
            backup_dir.to_path_buf()
        } else {
            backup_dir.join(kind.backup_subdir())
        };
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(name) = e.file_name().into_string() else {
                continue;
            };
            // `from_filename` rejects `.partial`, traversal and anything not
            // shaped like this kind — a half-written dump must never be
            // encrypted and shipped as if it were a backup.
            if let Ok(a) = LocalArtifact::from_filename(kind, &name) {
                out.push(a);
            }
        }
    }
    out
}

fn local_path(backup_dir: &Path, a: &LocalArtifact) -> PathBuf {
    if a.kind.backup_subdir().is_empty() {
        backup_dir.join(&a.filename)
    } else {
        backup_dir.join(a.kind.backup_subdir()).join(&a.filename)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Metric emission
// ═══════════════════════════════════════════════════════════════════════

/// Write the textfile metric atomically.
///
/// The temp file is created INSIDE the target directory so the rename is
/// same-filesystem and therefore actually atomic — a temp file in `$TMPDIR`
/// can land on a different device, where `mv` degrades to copy+unlink and a
/// collector can read a half-written file. Same reasoning, same shape as
/// `scripts/drills/backup-restore.sh`.
fn write_metric(dir: &Path, st: &MetricState) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let final_path = dir.join(TEXTFILE_NAME);
    let tmp_prefix = format!(".{TEXTFILE_NAME}.");

    let tmp = dir.join(format!("{tmp_prefix}{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(metrics::render(st).as_bytes())?;
        f.flush()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp, &final_path)?;

    // Sweep temp files orphaned by an EARLIER aborted write. They never
    // corrupt a scrape — node_exporter's textfile collector reads only
    // `*.prom` and these end in a pid — but nothing else ever cleans this
    // directory, so they accumulate one per killed run.
    //
    // AFTER the rename, not before, and the ordering is the whole safety
    // argument. Sweeping first means a write that fails at any point after
    // it (a full disk, a permissions change) has DESTROYED the previous
    // metric and published nothing in its place — losing the carried-forward
    // counters, which is the one thing this file exists to preserve. It also
    // makes the "a careless glob eats the real metric" hazard untestable,
    // because the rename immediately recreates whatever the sweep removed:
    // the first version of this function swept first, and the unit test
    // asserting the metric survives the sweep passed even when the glob was
    // mutated to match everything. Sweeping last makes that mutation
    // observable, which is the only reason to believe the assertion.
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with(&tmp_prefix) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    Ok(final_path)
}

fn load_previous(dir: &Path) -> MetricState {
    let text = std::fs::read_to_string(dir.join(TEXTFILE_NAME)).ok();
    MetricState::carried_forward(text.as_deref())
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

// ═══════════════════════════════════════════════════════════════════════
// Subcommands
// ═══════════════════════════════════════════════════════════════════════

fn cmd_upload(cfg: &Config, mode: UploadMode) -> i32 {
    let mut st = load_previous(&cfg.textfile_dir);
    st.last_run = now_unix();
    st.enabled = cfg.target.is_some();

    let result = do_upload(cfg, mode, &mut st);
    let rc = match result {
        Ok(n) => {
            if n == 0 {
                ok("nothing to upload — the bucket already has the newest archive of each kind");
            } else {
                ok(&format!("{n} archive(s) uploaded"));
            }
            0
        }
        Err(f) => {
            st.record_run_failure(f.reason);
            // WARN, not fatal-looking: the local dump is untouched and still
            // worth having. The counter above is what makes this visible
            // anyway — that is the whole design.
            warn(&format!(
                "off-host upload FAILED (reason={}): {}",
                f.reason.as_str(),
                f.detail
            ));
            1
        }
    };

    match write_metric(&cfg.textfile_dir, &st) {
        Ok(p) => ok(&format!("metric → {}", p.display())),
        Err(e) => {
            // The metric IS the signal. Losing it silently would recreate
            // exactly the invisible-failure mode this whole change exists to
            // close, so say so loudly and fail the run.
            eprintln!(
                "✗ could not write the metric into {}: {e}\n   \
                 A silent upload failure is worse than no upload. Fix the textfile \
                 directory (TALOS_TEXTFILE_DIR) before trusting this pipeline.",
                cfg.textfile_dir.display()
            );
            return 1;
        }
    }
    rc
}

fn do_upload(cfg: &Config, mode: UploadMode, st: &mut MetricState) -> R<usize> {
    let target = cfg.target()?;
    if let Some(id) = &cfg.access_key_id {
        // The key ID is not a secret and knowing WHICH credential ran is the
        // difference between "rotated" and "broken" when this starts failing.
        log(&format!(
            "bucket {} @ {} (access key id {})",
            target.bucket, target.endpoint_url, id
        ));
    } else {
        log(&format!(
            "bucket {} @ {}",
            target.bucket, target.endpoint_url
        ));
    }

    let (passphrase, source) = resolve_passphrase(cfg)?;
    log(&format!("age passphrase from {source}"));

    let aws = Aws {
        bin: cfg.aws_bin.clone(),
    };
    let remote = list_all_keys(&aws, target)?;
    let local = discover_local(&cfg.backup_dir);
    if local.is_empty() {
        return Err(Failure::new(
            FailureReason::Config,
            format!(
                "no backup artifacts found under {} — is the postgres-backup sidecar running?",
                cfg.backup_dir.display()
            ),
        ));
    }
    let todo = plan_uploads(&local, &remote, mode);
    log(&format!(
        "{} local artifact(s), {} already off-host, {} to send",
        local.len(),
        remote.len(),
        todo.len()
    ));

    let work = std::env::temp_dir().join(format!("talos-offhost-{}", std::process::id()));
    std::fs::create_dir_all(&work).map_err(|e| {
        Failure::new(
            FailureReason::Other,
            format!("could not create a work directory: {e}"),
        )
    })?;

    let mut sent = 0usize;
    let mut first_error: Option<Failure> = None;
    for a in &todo {
        let key = match a.object_key() {
            Ok(k) => k,
            Err(e) => {
                st.record_failure(a.kind, FailureReason::Other);
                warn(&format!("skipping {}: {e}", a.filename));
                continue;
            }
        };

        // Pre-flight. A GUARD, not a control — see aws::head_object_argv for
        // the TOCTOU this cannot close and for what actually stops an
        // overwrite (the credential and the bucket rule, neither of which
        // lives here).
        match aws.run(&head_object_argv(target, &key)) {
            Ok(_) => {
                warn(&format!(
                    "{key} already exists — SKIPPING rather than overwriting it"
                ));
                continue;
            }
            Err(f) if f.reason == FailureReason::NotFound => {}
            Err(f) => {
                st.record_failure(a.kind, f.reason);
                first_error.get_or_insert(f);
                continue;
            }
        }

        let src = local_path(&cfg.backup_dir, a);
        let enc = work.join(format!("{}.age", a.filename));
        if let Err(e) = encrypt_file(&passphrase, &src, &enc) {
            st.record_failure(a.kind, FailureReason::Encrypt);
            first_error.get_or_insert(Failure::new(FailureReason::Encrypt, e.to_string()));
            continue;
        }

        let put = put_object_argv(target, &key, &enc.to_string_lossy());
        match aws.run(&put) {
            Ok(_) => {
                st.record_success(a.kind, now_unix());
                sent += 1;
                ok(&format!("{} → {key}", a.filename));
            }
            Err(f) => {
                st.record_failure(a.kind, f.reason);
                warn(&format!(
                    "upload of {} failed (reason={}): {}",
                    a.filename,
                    f.reason.as_str(),
                    f.detail
                ));
                first_error.get_or_insert(f);
            }
        }
        // The plaintext never lands here, but the CIPHERTEXT still costs
        // disk on a laptop with a 400 MB dump. Remove it as we go rather
        // than at the end, so an interrupted run does not leave a pile.
        let _ = std::fs::remove_file(&enc);
    }
    let _ = std::fs::remove_dir(&work);

    match first_error {
        Some(f) => Err(f),
        None => Ok(sent),
    }
}

fn cmd_fetch(cfg: &Config, kind: ArtifactKind, dest: &Path, assert_fresh: bool) -> i32 {
    match do_fetch(cfg, kind, dest, assert_fresh) {
        Ok(key) => {
            ok(&format!("{key} → {}", dest.display()));
            // STDOUT carries the key and nothing else, so a caller can
            // capture it in a command substitution while every diagnostic
            // above still reaches the operator on stderr. The restore drill
            // prints it in its banner: "restored from <this object>" is the
            // evidence that the run touched the OFF-HOST copy.
            println!("{key}");
            0
        }
        Err(f) => {
            eprintln!(
                "✗ off-host fetch FAILED (reason={}): {}",
                f.reason.as_str(),
                f.detail
            );
            1
        }
    }
}

fn do_fetch(cfg: &Config, kind: ArtifactKind, dest: &Path, assert_fresh: bool) -> R<String> {
    let target = cfg.target()?;
    let (passphrase, source) = resolve_passphrase(cfg)?;
    log(&format!("age passphrase from {source}"));

    let aws = Aws {
        bin: cfg.aws_bin.clone(),
    };
    let remote = list_all_keys(&aws, target)?;
    let (key, taken_at) = newest_for_kind(&remote, kind).ok_or_else(|| {
        Failure::new(
            FailureReason::NotFound,
            format!(
                "the bucket holds NO {kind} archive under {KEY_ROOT}/. There is no off-host \
                 copy to restore — that IS the drill result."
            ),
        )
    })?;

    // Age is ASSERTED, not merely printed. The drill's 2026-08-13 lesson,
    // one hop further out: if the uploader died, the bucket keeps serving
    // the last good archive and the drill keeps going green for as long as
    // retention holds it.
    let age = age_hours(taken_at, now_unix());
    if assert_fresh && cfg.max_age_hours > 0 && age > cfg.max_age_hours {
        return Err(Failure::new(
            FailureReason::NotFound,
            format!(
                "the newest off-host {kind} archive is {age}h old (limit {}h): {key}\n   \
                 The uploader has stopped. Restoring this would go green and certify a \
                 pipeline that is no longer running. Check \
                 ~/.talos/logs/offhost-backup.log and the \
                 talos_offhost_backup_failures_total counter.",
                cfg.max_age_hours
            ),
        ));
    }
    log(&format!("newest {kind}: {key} ({age}h old)"));

    let enc = dest.with_extension("age.download");
    aws.run(&get_object_argv(target, &key, &enc.to_string_lossy()))?;
    let n = decrypt_file(&passphrase, &enc, dest).map_err(|e| {
        Failure::new(
            FailureReason::Encrypt,
            format!(
                "{e}\n   The archive downloaded fine, so the BUCKET is reachable and the \
                 object exists — this is the age passphrase, not the network."
            ),
        )
    })?;
    let _ = std::fs::remove_file(&enc);
    log(&format!("decrypted {n} bytes"));
    Ok(key)
}

fn cmd_plan(cfg: &Config, mode: UploadMode, offline: bool) -> i32 {
    let local = discover_local(&cfg.backup_dir);
    let remote = if offline {
        Vec::new()
    } else {
        let Ok(t) = cfg.target() else {
            eprintln!("✗ not configured; use --offline to see keys without a bucket");
            return 1;
        };
        match list_all_keys(
            &Aws {
                bin: cfg.aws_bin.clone(),
            },
            t,
        ) {
            Ok(k) => k,
            Err(f) => {
                eprintln!(
                    "✗ listing failed (reason={}): {}",
                    f.reason.as_str(),
                    f.detail
                );
                return 1;
            }
        }
    };
    if offline {
        println!("# --offline: the bucket was NOT consulted, so nothing is shown as skipped.");
    }
    for a in plan_uploads(&local, &remote, mode) {
        println!(
            "{}\t{}\t{}",
            a.kind,
            a.filename,
            a.object_key().unwrap_or_else(|e| format!("<{e}>"))
        );
    }
    0
}

/// D4: prove the append-only property instead of asserting it.
///
/// A capability you have not tried to violate is a claim, not a control.
/// This uploads one tiny throwaway object, then attempts to OVERWRITE it and
/// to DELETE it with the same credential. **Both must be refused.**
///
/// Note what it cannot do: the probe object it creates cannot be cleaned up
/// (that would need the delete it is proving absent), so it stays in the
/// bucket forever under a `talos/v1/_probe/` prefix. That is the correct
/// trade — an un-deletable probe object is the evidence.
fn cmd_probe(cfg: &Config) -> i32 {
    let Ok(target) = cfg.target() else {
        eprintln!("✗ off-host destination not configured");
        return 1;
    };
    let aws = Aws {
        bin: cfg.aws_bin.clone(),
    };
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let key = format!("{KEY_ROOT}/_probe/{stamp}-probe.txt");

    let tmp = std::env::temp_dir().join(format!("talos-offhost-probe-{}", std::process::id()));
    if std::fs::write(
        &tmp,
        b"talos append-only probe: this object is expected to be immutable\n",
    )
    .is_err()
    {
        eprintln!("✗ could not stage the probe object");
        return 1;
    }

    let mut failures = 0;
    log(&format!("probe object: {key}"));
    if let Err(f) = aws.run(&put_object_argv(target, &key, &tmp.to_string_lossy())) {
        eprintln!(
            "✗ the credential cannot even WRITE (reason={}): {}",
            f.reason.as_str(),
            f.detail
        );
        let _ = std::fs::remove_file(&tmp);
        return 1;
    }
    ok("PutObject to a NEW key succeeded — as it must");

    // 1. Overwrite.
    match aws.run(&put_object_argv(target, &key, &tmp.to_string_lossy())) {
        Err(f) => ok(&format!(
            "OVERWRITE was refused (reason={}) — history is safe from a re-PUT",
            f.reason.as_str()
        )),
        Ok(_) => {
            eprintln!(
                "✗ OVERWRITE SUCCEEDED. This credential can replace an existing archive with \
                 new bytes under the same key, which destroys history without ever calling \
                 delete. Either the bucket needs object-lock/versioning, or accept that the \
                 unique-key derivation is the ONLY thing standing between a compromised host \
                 and unrecoverable backups."
            );
            failures += 1;
        }
    }

    // 2. Delete.
    match aws.run(&delete_object_argv(target, &key)) {
        Err(f) => ok(&format!(
            "DeleteObject was refused (reason={}) — the key lacks deleteFiles",
            f.reason.as_str()
        )),
        Ok(_) => {
            eprintln!(
                "✗ DELETE SUCCEEDED. The application key has `deleteFiles`. Re-issue it \
                 without that capability (see docs/offhost-backup.md) — a host credential \
                 that can delete makes every off-host copy only as durable as the host."
            );
            failures += 1;
        }
    }

    let _ = std::fs::remove_file(&tmp);
    if failures == 0 {
        ok("append-only holds for this credential");
        0
    } else {
        eprintln!("✗ {failures} append-only propert(y/ies) NOT enforced by the provider");
        1
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Argument parsing
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, PartialEq, Eq)]
enum Cmd {
    Upload {
        mode: UploadMode,
    },
    Fetch {
        kind: ArtifactKind,
        dest: PathBuf,
        assert_fresh: bool,
    },
    Plan {
        mode: UploadMode,
        offline: bool,
    },
    Probe,
    Help,
}

/// Pure so the CLI surface is unit-tested without running anything.
fn parse_args(args: &[String]) -> Result<Cmd, String> {
    let Some(first) = args.first() else {
        return Ok(Cmd::Help);
    };
    let rest = &args[1..];
    let has = |f: &str| rest.iter().any(|a| a == f);
    let value = |f: &str| -> Option<String> {
        rest.iter()
            .position(|a| a == f)
            .and_then(|i| rest.get(i + 1))
            .cloned()
    };
    let mode = if has("--backfill") {
        UploadMode::Backfill
    } else {
        UploadMode::NewestOnly
    };
    for a in rest {
        if a.starts_with("--")
            && ![
                "--backfill",
                "--offline",
                "--kind",
                "--dest",
                "--no-freshness-check",
            ]
            .contains(&a.as_str())
        {
            return Err(format!("unknown flag: {a}"));
        }
    }
    match first.as_str() {
        "upload" => Ok(Cmd::Upload { mode }),
        "plan" => Ok(Cmd::Plan {
            mode,
            offline: has("--offline"),
        }),
        "probe-append-only" => Ok(Cmd::Probe),
        "fetch" => {
            let kind =
                value("--kind").ok_or_else(|| "fetch needs --kind postgres|vault".to_string())?;
            let kind = ArtifactKind::parse(&kind)
                .ok_or_else(|| format!("unknown --kind '{kind}' (postgres|vault)"))?;
            let dest = value("--dest").ok_or_else(|| "fetch needs --dest <path>".to_string())?;
            Ok(Cmd::Fetch {
                kind,
                dest: PathBuf::from(dest),
                // Opt-OUT, never opt-in: a freshness gate you have to
                // remember to switch on is not a gate.
                assert_fresh: !has("--no-freshness-check"),
            })
        }
        "--help" | "-h" | "help" => Ok(Cmd::Help),
        other => Err(format!("unknown subcommand: {other}")),
    }
}

const USAGE: &str = "\
talos-offhost-backup — encrypted off-host egress for Talos backups (Tier 2)

  upload [--backfill]
      age-encrypt every local artifact the bucket lacks and PUT it under a
      unique timestamped key. Default is NEWEST-ONLY (one archive per kind);
      --backfill is the one-time opt-in that pushes the whole retained
      history. Always writes the textfile metric, including on failure.

  fetch --kind postgres|vault --dest <path> [--no-freshness-check]
      GET the newest archive of that kind and age-decrypt it. Fails if the
      bucket is unreachable, if it holds no such archive, if that archive is
      older than TALOS_OFFHOST_MAX_AGE_HOURS, or if the passphrase is wrong.

  plan [--backfill] [--offline]
      Show what upload would do. --offline needs no credentials.

  probe-append-only
      Try to OVERWRITE and to DELETE an object with the upload credential.
      Both must be refused. Leaves one un-deletable probe object behind —
      that object is the evidence.

Environment (see docs/offhost-backup.md):
  TALOS_OFFHOST_B2_BUCKET / _ENDPOINT / _REGION   destination (all three)
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY       read by `aws`, never by argv
  TALOS_OFFHOST_AGE_PASSPHRASE_CMD | _FILE        exactly one; both is refused
  TALOS_OFFHOST_CHECKOUT_ROOTS                    ':'-separated; containment
  TALOS_BACKUP_DIR, TALOS_TEXTFILE_DIR            defaults under ~/.talos
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    let cfg = resolve_config();
    let rc = match cmd {
        Cmd::Help => {
            println!("{USAGE}");
            0
        }
        Cmd::Upload { mode } => cmd_upload(&cfg, mode),
        Cmd::Plan { mode, offline } => cmd_plan(&cfg, mode, offline),
        Cmd::Fetch {
            kind,
            dest,
            assert_fresh,
        } => cmd_fetch(&cfg, kind, &dest, assert_fresh),
        Cmd::Probe => cmd_probe(&cfg),
    };
    std::process::exit(rc);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn upload_defaults_to_newest_only() {
        // The stated decision: "next dump onward", not a silent backfill of
        // twelve retained dumps on first run.
        assert_eq!(
            parse_args(&a(&["upload"])).unwrap(),
            Cmd::Upload {
                mode: UploadMode::NewestOnly
            }
        );
        assert_eq!(
            parse_args(&a(&["upload", "--backfill"])).unwrap(),
            Cmd::Upload {
                mode: UploadMode::Backfill
            }
        );
    }

    #[test]
    fn fetch_requires_both_kind_and_dest() {
        assert!(parse_args(&a(&["fetch"])).is_err());
        assert!(parse_args(&a(&["fetch", "--kind", "postgres"])).is_err());
        assert!(parse_args(&a(&["fetch", "--dest", "/tmp/x"])).is_err());
        assert!(parse_args(&a(&["fetch", "--kind", "neo4j", "--dest", "/tmp/x"])).is_err());
    }

    #[test]
    fn the_freshness_gate_is_opt_out_not_opt_in() {
        // A gate you have to remember to switch on is not a gate.
        let Cmd::Fetch { assert_fresh, .. } =
            parse_args(&a(&["fetch", "--kind", "postgres", "--dest", "/tmp/x"])).unwrap()
        else {
            panic!()
        };
        assert!(assert_fresh);
        let Cmd::Fetch { assert_fresh, .. } = parse_args(&a(&[
            "fetch",
            "--kind",
            "postgres",
            "--dest",
            "/tmp/x",
            "--no-freshness-check",
        ]))
        .unwrap() else {
            panic!()
        };
        assert!(!assert_fresh);
    }

    #[test]
    fn unknown_flags_and_subcommands_are_refused() {
        // Silently ignoring `--backfil` would make an operator believe a
        // backfill happened.
        assert!(parse_args(&a(&["upload", "--backfil"])).is_err());
        assert!(parse_args(&a(&["uplod"])).is_err());
        assert_eq!(parse_args(&[]).unwrap(), Cmd::Help);
    }

    // ── The `aws` seam, exercised with a stub. ────────────────────────
    //
    // This is how the whole egress path is testable with no bucket, no
    // credential and no network: TALOS_OFFHOST_AWS_BIN points at a script
    // that produces canned output. Only the final live run needs B2.

    struct Stub {
        dir: PathBuf,
    }

    impl Stub {
        fn new(tag: &str, body: &str) -> Stub {
            let dir = std::env::temp_dir().join(format!(
                "talos-offhost-stub-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let bin = dir.join("aws");
            std::fs::write(&bin, format!("#!/bin/sh\n{body}\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            Stub { dir }
        }
        fn bin(&self) -> String {
            self.dir.join("aws").to_string_lossy().to_string()
        }
    }

    impl Drop for Stub {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn target() -> S3Target {
        S3Target {
            endpoint_url: "https://s3.example.invalid".into(),
            bucket: "b".into(),
            region: "r".into(),
        }
    }

    #[test]
    fn a_failing_aws_is_classified_not_swallowed() {
        let s = Stub::new(
            "auth",
            "echo 'An error occurred (InvalidAccessKeyId) when calling PutObject' >&2\nexit 255",
        );
        let aws = Aws { bin: s.bin() };
        let e = aws
            .run(&put_object_argv(&target(), "k", "/dev/null"))
            .unwrap_err();
        assert_eq!(e.reason, FailureReason::Auth);
    }

    #[test]
    fn a_missing_aws_binary_is_missing_tool() {
        let aws = Aws {
            bin: "/nonexistent/aws-does-not-exist".into(),
        };
        let e = aws
            .run(&list_objects_argv(&target(), "p", None))
            .unwrap_err();
        assert_eq!(e.reason, FailureReason::MissingTool);
    }

    #[test]
    fn listing_follows_pagination_to_the_end() {
        // A listing that stops at page 1 makes plan_uploads re-PUT — i.e.
        // OVERWRITE — an archive it could not see.
        let s = Stub::new(
            "page",
            r#"
if echo "$@" | grep -q 'continuation-token'; then
  echo '{"Contents":[{"Key":"talos/v1/postgres/2026/08/20260817T101757Z-postgres.age"}]}'
else
  echo '{"Contents":[{"Key":"talos/v1/postgres/2026/08/20260810T101757Z-postgres.age"}],"NextContinuationToken":"t2"}'
fi
"#,
        );
        let keys = list_all_keys(&Aws { bin: s.bin() }, &target()).unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys
            .iter()
            .any(|k| k.contains("20260817T101757Z-postgres.age")));
    }

    #[test]
    fn an_empty_bucket_lists_as_empty_rather_than_erroring() {
        let s = Stub::new("empty", "echo '{}'");
        assert!(list_all_keys(&Aws { bin: s.bin() }, &target())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_garbage_listing_is_an_error_not_an_empty_bucket() {
        // "The bucket is empty" and "I could not read the bucket" must not
        // look the same: the first makes `fetch` report no off-host copy,
        // the second is a tooling problem.
        let s = Stub::new("junk", "echo 'not json at all'");
        let e = list_all_keys(&Aws { bin: s.bin() }, &target()).unwrap_err();
        assert_eq!(e.reason, FailureReason::Other);
    }

    #[test]
    fn discover_local_ignores_partials_and_foreign_files() {
        let d = std::env::temp_dir().join(format!("talos-offhost-disc-{}", std::process::id()));
        std::fs::create_dir_all(d.join("vault")).unwrap();
        for f in [
            "talos-20260817-101757.dump",
            "talos-20260816-101757.dump.partial",
            "README.txt",
            "talos-nope.dump",
        ] {
            std::fs::write(d.join(f), b"x").unwrap();
        }
        std::fs::write(d.join("vault/vault-20260817-221124.tar.gz"), b"x").unwrap();
        std::fs::write(d.join("vault/vault-20260817-221124.tar.gz.manifest"), b"x").unwrap();

        let mut found: Vec<String> = discover_local(&d).into_iter().map(|a| a.filename).collect();
        found.sort();
        assert_eq!(
            found,
            vec![
                "talos-20260817-101757.dump".to_string(),
                "vault-20260817-221124.tar.gz".to_string()
            ]
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_metric_is_written_atomically_and_carries_forward() {
        let d = std::env::temp_dir().join(format!("talos-offhost-metric-{}", std::process::id()));
        let mut st = MetricState::default();
        st.record_failure(ArtifactKind::Postgres, FailureReason::Auth);
        write_metric(&d, &st).unwrap();
        let back = load_previous(&d);
        assert_eq!(back.failures.get(&FailureReason::Auth), Some(&1));
        // No temp file left behind for a collector to trip over.
        let leftovers: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(
            leftovers.is_empty(),
            "orphaned temp file in the collector dir"
        );

        // BOTH directions of the sweep. An orphan left by an earlier killed
        // run must be removed — nothing else ever cleans this directory, so
        // without the sweep they accumulate one per killed run — AND the real
        // metric must survive it, because a careless glob eats the metric
        // instead and that is a worse failure than the litter.
        let orphan = d.join(format!(".{TEXTFILE_NAME}.999999"));
        std::fs::write(&orphan, b"stale").unwrap();
        write_metric(&d, &st).unwrap();
        assert!(!orphan.exists(), "an orphaned temp file was not swept");
        assert!(
            d.join(TEXTFILE_NAME).exists(),
            "the sweep removed the real metric file"
        );
        assert_eq!(
            load_previous(&d).failures.get(&FailureReason::Auth),
            Some(&1),
            "the surviving metric file is intact"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_passphrase_source_is_required_and_both_is_refused() {
        let base = Config {
            target: None,
            backup_dir: std::env::temp_dir(),
            textfile_dir: std::env::temp_dir(),
            aws_bin: "aws".into(),
            checkout_roots: vec![PathBuf::from("/nonexistent-checkout-root")],
            passphrase_cmd: None,
            passphrase_file: None,
            escrow_timeout_secs: 5,
            max_age_hours: 168,
            access_key_id: None,
        };
        assert_eq!(
            resolve_passphrase(&base).unwrap_err().reason,
            FailureReason::Config
        );
        let both = Config {
            passphrase_cmd: Some("echo x".into()),
            passphrase_file: Some("/tmp/p".into()),
            ..base.clone()
        };
        let e = resolve_passphrase(&both).unwrap_err();
        assert!(e.detail.contains("both"), "{}", e.detail);
    }

    #[test]
    fn an_undeterminable_checkout_root_fails_closed() {
        // Answering "is this key inside the repo?" with a default "no" is
        // how a containment check becomes decorative.
        let cfg = Config {
            target: None,
            backup_dir: std::env::temp_dir(),
            textfile_dir: std::env::temp_dir(),
            aws_bin: "aws".into(),
            checkout_roots: vec![],
            passphrase_cmd: Some("echo hunter2".into()),
            passphrase_file: None,
            escrow_timeout_secs: 5,
            max_age_hours: 168,
            access_key_id: None,
        };
        let e = resolve_passphrase(&cfg).unwrap_err();
        assert!(
            e.detail.contains("TALOS_OFFHOST_CHECKOUT_ROOTS"),
            "{}",
            e.detail
        );
    }

    #[test]
    fn a_hanging_passphrase_helper_is_killed_including_its_grandchildren() {
        // #639's measured failure: `sh -c 'sleep 300'` forks the sleep as a
        // GRANDCHILD holding the capture pipe, so signalling only the direct
        // child leaves the read blocked forever. This must return within a
        // few seconds, not in 300.
        let start = std::time::Instant::now();
        let e = run_bounded("sleep 300", 2).unwrap_err();
        assert!(
            start.elapsed() < std::time::Duration::from_secs(30),
            "the watchdog did not reach the grandchild"
        );
        assert_eq!(e.reason, FailureReason::Config);
        assert!(e.detail.contains("did not finish"), "{}", e.detail);
    }

    #[test]
    fn a_helper_that_prints_nothing_is_an_empty_passphrase_not_a_silent_pass() {
        assert_eq!(run_bounded("true", 5).unwrap(), "");
        assert!(assert_non_empty(&run_bounded("true", 5).unwrap()).is_err());
    }
}
