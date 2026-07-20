//! Sigstore identity-regexp policy — the single source of truth for
//! validating the `--certificate-identity-regexp` passed to `cosign
//! verify`.
//!
//! This crate exists because the check was duplicated: the worker had the
//! strong validator ([`validate_sigstore_identity_regexp`]) while the
//! controller's OCI catalog-sync (`talos-registry`) carried an ad-hoc
//! substring matcher that only rejected a handful of exact catch-alls —
//! so the controller trusted wildcard-owner regexps the worker would
//! reject (security review 2026-07-19, P4). Both processes now call this
//! one function, so the identity-pinning strength cannot drift.
//!
//! Pure, dependency-light (regex only) so it drops into both the
//! WASM-host worker and the controller without dragging in a web
//! framework.

/// Why a candidate `--certificate-identity-regexp` was rejected. Each
/// variant carries a human-readable explanation via [`Self::human_reason`]
/// so callers can log an actionable message. Pure data so it's easy to
/// match on / test.
#[derive(Debug, PartialEq, Eq)]
pub enum SigstoreRegexpRejection {
    /// The string is empty — the caller should treat this as
    /// "explicitly not configured" rather than a parse error, but in
    /// `Required` mode it's still a hard failure (see callsite).
    Empty,
    /// One of the known catch-all patterns: `.*`, `.+`, `.`, `^.*$`,
    /// etc. A regex this broad accepts any Fulcio cert identity, which
    /// is the same as having no verification at all.
    TooBroad,
    /// The pattern doesn't compile as a regex. Fail closed early so
    /// `cosign verify` doesn't error in production with an opaque
    /// upstream message.
    InvalidRegex,
    /// The pattern would match a GitHub repo or workflow URL prefix
    /// without ever anchoring the trailing `@` separator. Per the
    /// CLAUDE.md guidance: without the `@`, an attacker who creates a
    /// fork named `template-publish.yml-evil.yml` can match the same
    /// prefix.
    MissingWorkflowAnchor,
    /// The pattern starts with `https://github.com/` (the GitHub-Actions
    /// Fulcio identity prefix) but does not contain `.github/workflows/`.
    /// Sigstore identities for GitHub Actions OIDC ALWAYS include the
    /// workflow path — a pattern like `^https://github\.com/.*` would
    /// match every signed artifact from every owner/repo on github.com,
    /// defeating the per-workflow trust anchor.
    MissingGithubWorkflowPath,
    /// The pattern contains a wildcard between `github.com/` and the
    /// workflow path (`github.com/.*\.github/workflows/` or similar).
    /// This expands the trust set to any owner/repo with a matching
    /// workflow filename — including a forked repo with the same
    /// filename. Pin the owner/repo literally.
    UnpinnedGithubOwnerRepo,
    /// Pattern starts with `https://` but is missing the `^` start-of-string
    /// anchor. Cosign uses `regex::Regex::is_match` semantics — a missing
    /// `^` means the literal `https://...` could appear anywhere inside
    /// the SAN URI. While GitHub Actions OIDC SANs are well-structured,
    /// a `^` anchor is cheap defense in depth (and matches the
    /// documented operator examples in this crate's `human_reason()` text).
    MissingStartAnchor,
}

impl SigstoreRegexpRejection {
    pub fn human_reason(&self) -> &'static str {
        match self {
            Self::Empty => "TALOS_SIGSTORE_IDENTITY_REGEXP is empty",
            Self::TooBroad => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP matches anything — pin it to your \
                 workflow URL pattern (e.g. \
                 `^https://github\\.com/OWNER/talos/\\.github/workflows/template-publish\\.yml@`)"
            }
            Self::InvalidRegex => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP is not a valid regex — `cosign verify` will reject every artifact"
            }
            Self::MissingWorkflowAnchor => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP looks like a GitHub workflow pattern \
                 but is missing the trailing `@` anchor — a fork named \
                 `workflow.yml-evil.yml` could match the same prefix. \
                 End the pattern with `@` to anchor at the ref separator."
            }
            Self::MissingGithubWorkflowPath => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP targets `github.com` but does not \
                 require the `.github/workflows/` path — every Sigstore identity \
                 issued by GitHub Actions OIDC contains that path, so a pattern \
                 without it would match unrelated artifacts from any owner/repo. \
                 Use a pattern like \
                 `^https://github\\.com/OWNER/REPO/\\.github/workflows/WORKFLOW\\.yml@`."
            }
            Self::UnpinnedGithubOwnerRepo => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP has a wildcard between `github.com/` \
                 and `.github/workflows/` — owner and repo MUST be literal so a \
                 fork with the same workflow filename can't satisfy the regex. \
                 Replace `github\\.com/.*` with `github\\.com/OWNER/REPO/`."
            }
            Self::MissingStartAnchor => {
                "TALOS_SIGSTORE_IDENTITY_REGEXP starts with `https://` but is \
                 missing the `^` start-of-string anchor. Add `^` at the front \
                 (e.g. `^https://github\\.com/OWNER/REPO/...`)."
            }
        }
    }
}

/// Validate `regexp` for use as `--certificate-identity-regexp` in
/// `cosign verify`. Pure function so the security policy is easy to
/// test and cannot drift between callsites. Returns `Ok(())` if the
/// pattern is acceptable; `Err(reason)` otherwise.
///
/// Policy:
/// 1. Empty string is rejected (callers may special-case Empty for
///    `Disabled` policy mode, but the underlying check stays the
///    same).
/// 2. Known catch-all patterns are rejected. Treating `.*` /
///    `.+` / `.` / `^.*$` / `^.+$` as too broad covers the most
///    common foot-gun — an operator who sets the regexp to "any"
///    while leaving `TALOS_SIGSTORE_REQUIRED=true` would silently
///    defeat verification.
/// 3. The pattern must compile as a regex.
/// 4. Patterns targeting `github.com/.../.github/workflows/...`
///    MUST end with `@` (per the workflow-URL anchor convention
///    documented in CLAUDE.md). Missing this trailing `@` is
///    spoofable via a fork repo named `workflow.yml-evil.yml`.
/// 5. `github.com` patterns must reference `.github/workflows/` and
///    pin the owner/repo literally (no wildcard between host and the
///    workflow path).
/// 6. `https://`-prefixed patterns must carry a `^` start anchor.
pub fn validate_sigstore_identity_regexp(regexp: &str) -> Result<(), SigstoreRegexpRejection> {
    if regexp.is_empty() {
        return Err(SigstoreRegexpRejection::Empty);
    }
    // Reject known catch-all patterns. Trim whitespace first so a
    // pasted env-var with stray spaces still triggers the check.
    let trimmed = regexp.trim();
    matches!(
        trimmed,
        ".*" | ".+" | "." | "^.*$" | "^.+$" | "^.$" | "^.*" | ".*$"
    )
    .then(|| Err::<(), _>(SigstoreRegexpRejection::TooBroad))
    .transpose()?;
    // The pattern must compile or `cosign` will reject every artifact.
    if regex::Regex::new(regexp).is_err() {
        return Err(SigstoreRegexpRejection::InvalidRegex);
    }
    // Wasm-security review 2026-05-23: a `https://`-prefixed pattern
    // without a leading `^` matches the URI substring anywhere — cheap
    // defense-in-depth to require the start-anchor that all the doc
    // examples already use. We don't require `^` on non-URL patterns
    // because there are legitimate non-anchored uses (e.g. SAN-email
    // patterns).
    if regexp.starts_with("https://") {
        return Err(SigstoreRegexpRejection::MissingStartAnchor);
    }
    // Workflow-URL convention: if the pattern mentions
    // `.github/workflows/`, the file extension `.yml` (or `.yaml`)
    // must be immediately followed by `@` so the ref separator is
    // anchored. Without it, a fork repo named
    // `workflow.yml-evil.yml` would match the same prefix.
    //
    // The check looks for the `@` to appear AFTER `workflows/` in the
    // pattern source. Both the "ends with @" form (e.g.
    // `…template-publish\.yml@`) and the ref-pinned form (e.g.
    // `…template-publish\.yml@refs/heads/main$`) satisfy it.
    if let Some(workflows_idx) = regexp.find(".github/workflows/") {
        // Slice past the `workflows/` literal so any preceding `@`
        // (would be unusual but harmless) doesn't accidentally
        // satisfy the check.
        let after_workflows = &regexp[workflows_idx + ".github/workflows/".len()..];
        if !after_workflows.contains('@') {
            return Err(SigstoreRegexpRejection::MissingWorkflowAnchor);
        }
    }
    // L-14 (2026-05-22): additional anchoring checks for github.com
    // patterns. Sigstore identities issued by GitHub Actions OIDC
    // always have the form
    // `https://github.com/{owner}/{repo}/.github/workflows/{file}.yml@{ref}`.
    // A pattern that targets github.com but is missing either the
    // `.github/workflows/` path or pins the owner/repo with a
    // wildcard would expand the trust set far beyond the operator's
    // intent (any fork with the same workflow name signs as us).
    //
    // We match both `github\.com/` (regex-escaped) and `github.com/`
    // (raw) since operators write the pattern either way.
    let github_idx = regexp
        .find("github\\.com/")
        .map(|i| (i, "github\\.com/".len()))
        .or_else(|| regexp.find("github.com/").map(|i| (i, "github.com/".len())));
    if let Some((idx, prefix_len)) = github_idx {
        // 1. Pattern must reference a workflow path. Without it, every
        //    OIDC identity from any GitHub repo would satisfy the
        //    regex (e.g. `^https://github\.com/.*`).
        if !regexp.contains(".github/workflows/") {
            return Err(SigstoreRegexpRejection::MissingGithubWorkflowPath);
        }
        // 2. Owner/repo segment between `github.com/` and
        //    `.github/workflows/` must be literal — no wildcards.
        //    `.` (any-char), `.*`, `.+`, `\w+`, `[^/]+`, `\S+`
        //    between the two anchors all defeat per-repo pinning.
        let after_host = &regexp[idx + prefix_len..];
        if let Some(workflows_at) = after_host.find(".github/workflows/") {
            let owner_repo_segment = &after_host[..workflows_at];
            // Bare `.` is the canonical wildcard; `.*` / `.+` / `[]`
            // / `\w` likewise. Backslash-escaped `\.` is a literal
            // dot in the repo name (e.g. `my.repo`) and is fine, so
            // we strip those before scanning. Same for `\-`.
            let scan = owner_repo_segment
                .replace("\\.", "")
                .replace("\\-", "")
                .replace("\\_", "");
            // Any of these tokens between host and workflows path
            // indicates a wildcard.
            let suspicious_tokens = [".*", ".+", "[^", "\\w", "\\S", "\\d", "(?", ".{", "()"];
            if suspicious_tokens.iter().any(|t| scan.contains(t)) {
                return Err(SigstoreRegexpRejection::UnpinnedGithubOwnerRepo);
            }
            // A bare `.` (any-character) outside an escape is also
            // suspicious. Scan for it in the post-strip text.
            if scan.contains('.') {
                return Err(SigstoreRegexpRejection::UnpinnedGithubOwnerRepo);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rejected() {
        assert_eq!(
            validate_sigstore_identity_regexp(""),
            Err(SigstoreRegexpRejection::Empty)
        );
    }

    #[test]
    fn catch_all_rejected() {
        for p in [".*", ".+", ".", "^.*$", "^.+$", "^.$", "^.*", ".*$"] {
            assert_eq!(
                validate_sigstore_identity_regexp(p),
                Err(SigstoreRegexpRejection::TooBroad),
                "pattern {p:?} should be TooBroad"
            );
        }
    }

    #[test]
    fn invalid_regex_rejected() {
        assert_eq!(
            validate_sigstore_identity_regexp("^(unterminated"),
            Err(SigstoreRegexpRejection::InvalidRegex)
        );
    }

    #[test]
    fn github_owner_wildcarded_is_rejected() {
        // The exact P4 bypass: wildcard owner passes the controller's
        // old ad-hoc matcher but must be rejected here.
        let pattern = "^https://github\\.com/.*/talos/\\.github/workflows/template-publish\\.yml@";
        assert_eq!(
            validate_sigstore_identity_regexp(pattern),
            Err(SigstoreRegexpRejection::UnpinnedGithubOwnerRepo)
        );
    }

    #[test]
    fn github_repo_wildcarded_is_rejected() {
        let pattern = "^https://github\\.com/ehelbig1/.+/\\.github/workflows/x\\.yml@";
        assert_eq!(
            validate_sigstore_identity_regexp(pattern),
            Err(SigstoreRegexpRejection::UnpinnedGithubOwnerRepo)
        );
    }

    #[test]
    fn github_missing_workflow_anchor_is_rejected() {
        let pattern =
            "^https://github\\.com/ehelbig1/talos/\\.github/workflows/template-publish\\.yml";
        assert_eq!(
            validate_sigstore_identity_regexp(pattern),
            Err(SigstoreRegexpRejection::MissingWorkflowAnchor)
        );
    }

    #[test]
    fn github_missing_workflow_path_is_rejected() {
        let pattern = "^https://github\\.com/ehelbig1/talos/releases@";
        assert_eq!(
            validate_sigstore_identity_regexp(pattern),
            Err(SigstoreRegexpRejection::MissingGithubWorkflowPath)
        );
    }

    #[test]
    fn unanchored_https_pattern_is_rejected() {
        let pattern = "https://github\\.com/ehelbig1/talos/\\.github/workflows/x\\.yml@";
        assert_eq!(
            validate_sigstore_identity_regexp(pattern),
            Err(SigstoreRegexpRejection::MissingStartAnchor)
        );
    }

    #[test]
    fn pinned_owner_repo_is_accepted() {
        let pattern =
            "^https://github\\.com/ehelbig1/talos/\\.github/workflows/template-publish\\.yml@";
        assert!(
            validate_sigstore_identity_regexp(pattern).is_ok(),
            "{:?}",
            validate_sigstore_identity_regexp(pattern)
        );
    }

    #[test]
    fn escaped_dot_in_owner_repo_is_literal() {
        let pattern = "^https://github\\.com/my\\.org/my\\.repo/\\.github/workflows/x\\.yml@";
        assert!(
            validate_sigstore_identity_regexp(pattern).is_ok(),
            "{:?}",
            validate_sigstore_identity_regexp(pattern)
        );
    }

    #[test]
    fn non_https_pattern_does_not_require_anchor() {
        // SAN-email identities are a legitimate non-anchored use.
        let pattern = "user@example\\.com";
        assert!(
            validate_sigstore_identity_regexp(pattern).is_ok(),
            "{:?}",
            validate_sigstore_identity_regexp(pattern)
        );
    }
}
