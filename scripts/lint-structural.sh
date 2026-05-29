#!/usr/bin/env bash
# Structural lints — catch the failure classes that survive `cargo check`
# and only manifest in production.
#
# Each check is tied to a real prod incident OR a security review
# finding. Two of the more recent additions:
#
#   - check 19 (worker single-publish JobResult) catches the
#     dual-publish race that breaks every job with "result_nonce
#     already seen" — see CLAUDE.md "Verify-once rule".
#   - check 20 (wasmtime proposal lockdown) catches a silent codegen
#     surface expansion when wasmtime adds a new proposal and the
#     worker's explicit-opt-out list isn't kept current.
#
# Older checks:
#
#   1. Raw actor_memory writes + legacy `value`-column projections outside
#      the talos-memory crate. CLAUDE.md says all access goes through
#      `talos_memory::*`, but raw INSERT/SELECT keeps creeping back in.
#      When the `value` column was dropped in Phase B (2026-04-24), five
#      sites broke simultaneously and the regression wasn't caught until
#      a user opened the actor Memory tab on prod three days later.
#      Opt-out for documented exceptions: add the literal comment
#      `// allow-actor-memory-sql: <reason>` on the same line.
#
#   2. Top-level controller routes vs nginx ConfigMap proxies. Adding a
#      new top-level path on the controller is a silent prod-only
#      failure if the chart's nginx ConfigMap doesn't learn about it
#      (`/auth/csrf` and `/mcp` both bit us in 2026-04). Information-only
#      check (warns, doesn't fail the build) — nginx prefix-matches and
#      a bunch of routes are intentionally not exposed (probes, scrape).
#      Add `// no-nginx-route: <reason>` to the `.route()` line to silence
#      a single intentional-internal route.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

red()    { printf '\033[1;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

EXIT_CODE=0

# ── 1. Raw actor_memory SQL + legacy value-column projections ─────────
bold "▶ check 1: actor_memory writes + value-column projections outside talos-memory/"

# Two pattern classes, each one tied to the actor_memory table by name:
#
#  A. Writes: INSERT/UPDATE/DELETE that name actor_memory directly.
#     Allowed only via opt-out (the clone_actor bulk-copy sites are
#     documented exceptions; everything else MUST go through
#     talos_memory::persist_memory / forget / clone_in_tx).
#
#  B. Legacy `value` column projections: SQL that lists the dropped
#     `value` column alongside `value_enc`. Caught by anchoring on the
#     adjacency `value, value_enc` or `value, value_key_id` — the
#     `value_enc, value_key_id` (correct Phase-B form) does not match.
WRITE_PATTERNS=(
    'INSERT INTO actor_memory'
    'UPDATE actor_memory[[:space:]]+SET'
    'DELETE FROM actor_memory'
)
PROJECTION_PATTERNS=(
    'value, value_enc'         # SELECT key, value, value_enc, ...
    'value, value_key_id'      # SELECT key, value, value_key_id, ...
    # Note: deliberately NOT matching `(value,` or `, value,` — too many
    # false positives on Rust tuple destructuring like `(key, value, …)`.
    # The two `value, value_enc` / `value, value_key_id` adjacencies are
    # specific enough to actor_memory column projections to be reliable.
)

VIOLATIONS=0
check_pattern() {
    local pattern="$1"
    while IFS= read -r line; do
        # Opt-out marker may be on the matched line OR within the 8 lines
        # preceding it. Rust idiom is to put the comment above the binding
        # (`let row = sqlx::query("…INSERT INTO…")`), which can sit several
        # lines above the SQL string itself.
        local file lineno
        file="$(echo "$line" | cut -d: -f1)"
        lineno="$(echo "$line" | cut -d: -f2)"
        local start=$((lineno > 8 ? lineno - 8 : 1))
        if sed -n "${start},${lineno}p" "$file" 2>/dev/null \
                | grep -q 'allow-actor-memory-sql'; then
            continue
        fi
        printf '  %s\n' "$line"
        VIOLATIONS=$((VIOLATIONS + 1))
    done < <(grep -rEn "$pattern" \
                --include='*.rs' \
                --exclude-dir=target \
                controller/src talos-secrets/src talos-dlp/src worker/src 2>/dev/null \
            || true)
}
for p in "${WRITE_PATTERNS[@]}";      do check_pattern "$p"; done
for p in "${PROJECTION_PATTERNS[@]}"; do check_pattern "$p"; done

if [ "$VIOLATIONS" -gt 0 ]; then
    red "✗ found $VIOLATIONS sites"
    yellow "  → route through talos_memory::* (recall, persist, forget, clone_in_tx)"
    yellow "  → or add // allow-actor-memory-sql: <reason> if intentionally raw"
    EXIT_CODE=1
else
    green "✓ no raw actor_memory writes or legacy value-column projections"
fi
echo

# ── 2. Top-level controller routes vs nginx ConfigMap ────────────────
bold "▶ check 2: top-level controller routes vs nginx locations (info-only)"

ROUTES_FILE="$(mktemp)"
NGINX_FILE="$(mktemp)"
trap 'rm -f "$ROUTES_FILE" "$NGINX_FILE"' EXIT

# Extract the path arg from .route("/X", …) AND .nest("/X", …) calls in
# main.rs and normalise to the first path segment. Skip routes annotated
# `// no-nginx-route`. Both `route` and `nest` register a top-level path;
# nesting matters for things like `Router::new().nest("/mcp", …)`.
grep -nE '\.(route|nest)\("/' controller/src/main.rs \
    | grep -v 'no-nginx-route' \
    | grep -oE '\.(route|nest)\("/[^"]*"' \
    | grep -oE '"/[^"]*"' \
    | tr -d '"' \
    | awk -F/ '{ if ($2 != "") print "/" $2 }' \
    | sort -u > "$ROUTES_FILE"

# Extract `location /X` from the chart-rendered nginx ConfigMap.
# Use awk so we're not fighting BSD vs GNU sed escapes.
# Skip locations marked `# no-controller-route` — typically /favicon.ico
# served directly by nginx with no upstream. The marker may be on the
# location line itself or any of the 3 lines preceding it.
awk '
    {
        # Buffer the last 3 non-empty lines to check for opt-out marker.
        recent_lines[NR % 4] = $0
    }
    /^[[:space:]]*location[[:space:]]/ {
        opt_out = 0
        for (j = NR - 3; j <= NR; j++) {
            if (j < 1) continue
            if (recent_lines[j % 4] ~ /no-controller-route/) {
                opt_out = 1
            }
        }
        if (opt_out) next

        for (i = 1; i <= NF; i++) {
            if ($i ~ /^\//) {
                # First path segment only — strip nested levels.
                split($i, parts, "/")
                if (parts[2] != "") {
                    print "/" parts[2]
                } else {
                    print "/"
                }
                break
            }
        }
    }
' deploy/helm/talos/templates/frontend/configmap.yaml | sort -u > "$NGINX_FILE"

# Diff. `/` (SPA catch-all) is always fine on both sides.
MISSING="$(comm -23 "$ROUTES_FILE" "$NGINX_FILE" | grep -v '^/$' || true)"
EXTRA="$(comm -13 "$ROUTES_FILE" "$NGINX_FILE" | grep -v '^/$' || true)"

if [ -n "$MISSING" ]; then
    yellow "⚠ controller routes missing a matching top-level nginx location:"
    while IFS= read -r r; do printf '  %s\n' "$r"; done <<<"$MISSING"
    yellow "  → if intentionally internal (probes, scrape token, etc.), add"
    yellow "    // no-nginx-route on the .route() line in main.rs"
    yellow "  → otherwise add a matching location block to"
    yellow "    deploy/helm/talos/templates/frontend/configmap.yaml"
fi

if [ -n "$EXTRA" ]; then
    yellow "⚠ nginx locations with no matching top-level controller route:"
    while IFS= read -r r; do printf '  %s\n' "$r"; done <<<"$EXTRA"
    yellow "  → likely safe (handler may live in a merged sub-router) but"
    yellow "    worth a sanity-check that the proxy target actually exists"
fi

if [ -z "$MISSING" ] && [ -z "$EXTRA" ]; then
    green "✓ controller routes ↔ nginx locations are aligned"
fi
echo

# ── 3. Canonical __actor_context__ key (no __agent_context__ regressions) ─
bold "▶ check 3: __actor_context__ injection key (no __agent_context__ regressions)"

# The terminology refactor (agent → actor) renamed the LLM-input key to
# `__actor_context__`. One site in module-templates/llm-inference/template.rs
# kept reading `__agent_context__`, silently no-op'ing INJECT_CONTEXT for
# every workflow that used the canonical LLM module — for months. There
# is no compile-time check (it's a string key on a JSON map), so this
# lint is the only structural guard. If you genuinely need to read or
# write the legacy key (e.g. a backwards-compat shim), add a literal
# `// allow-agent-context-key: <reason>` comment within 4 lines above.
LEGACY_HITS=$(grep -rEn '__agent_context__' \
                --include='*.rs' \
                --exclude-dir=target \
                controller/src talos-memory/src worker/src module-templates 2>/dev/null \
            || true)

LEGACY_VIOLATIONS=0
if [ -n "$LEGACY_HITS" ]; then
    while IFS= read -r line; do
        file="$(echo "$line" | cut -d: -f1)"
        lineno="$(echo "$line" | cut -d: -f2)"
        local_start=$((lineno > 4 ? lineno - 4 : 1))
        if sed -n "${local_start},${lineno}p" "$file" 2>/dev/null \
                | grep -q 'allow-agent-context-key'; then
            continue
        fi
        printf '  %s\n' "$line"
        LEGACY_VIOLATIONS=$((LEGACY_VIOLATIONS + 1))
    done <<<"$LEGACY_HITS"
fi

if [ "$LEGACY_VIOLATIONS" -gt 0 ]; then
    red "✗ found $LEGACY_VIOLATIONS references to legacy __agent_context__"
    yellow "  → rename to __actor_context__ (the post-refactor canonical key)"
    yellow "  → or add // allow-agent-context-key: <reason> if intentionally legacy"
    EXIT_CODE=1
else
    green "✓ no __agent_context__ regressions — INJECT_CONTEXT key is canonical"
fi
echo

# ── 4. Per-call SecretsManager::new(...) outside canonical wiring ─────
bold "▶ check 4: SecretsManager::new(...) outside canonical wiring"

# A controller-wide singleton SecretsManager lives on McpState.
# Constructing a fresh one per call has bitten us in two distinct ways:
#
#   1. **KEK drift (production correctness).** A fresh manager loads its
#      KEK via `env_kek_provider_from_environment()`. In any deployment
#      using a Vault- or KMS-backed KEK provider for the global manager
#      (the production posture), the env-derived KEK and the production
#      KEK diverge. Per-row DEK unwrap then fails at WARN level inside
#      `get_secrets_by_paths` (the loop logs and continues per-row), so
#      the call returns an empty / partial map. Symptoms vary by caller
#      — for `test_subworkflow_contract` (r232) the visible failure was
#      "LLM provider 'anthropic' is not configured" because step 5 of
#      the secrets pipeline (`resolve_llm_keys`) returned an empty map.
#
#   2. **Cold caches (performance).** Each fresh manager has empty DEK
#      and LLM-keys caches; first call pays N extra DB round-trips that
#      the shared manager would have served from memory.
#
# Allowed sites:
#   - `controller/src/secrets/`       — the constructor itself + tests
#   - `controller/src/main.rs`        — canonical app initialization
#
# Anywhere else, route through the shared `state.secrets_manager` (or
# inject `Arc<SecretsManager>` via the consumer's constructor). If a
# site genuinely needs a per-call instance (test stub, documented
# defensive fallback), add a literal comment within 8 lines above:
#   // allow-secrets-manager-new: <reason>
SM_VIOLATIONS=0
while IFS= read -r line; do
    file="$(echo "$line" | cut -d: -f1)"
    lineno="$(echo "$line" | cut -d: -f2)"
    sm_start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${sm_start},${lineno}p" "$file" 2>/dev/null \
            | grep -q 'allow-secrets-manager-new'; then
        continue
    fi
    printf '  %s\n' "$line"
    SM_VIOLATIONS=$((SM_VIOLATIONS + 1))
done < <(grep -rEn 'SecretsManager::new\b' \
            --include='*.rs' \
            --exclude-dir=target \
            --exclude-dir=secrets \
            controller/src 2>/dev/null \
        | grep -v 'controller/src/main.rs' \
        || true)

if [ "$SM_VIOLATIONS" -gt 0 ]; then
    red "✗ found $SM_VIOLATIONS sites"
    yellow "  → use the shared state.secrets_manager (Arc clone) instead"
    yellow "  → or add // allow-secrets-manager-new: <reason> for documented fallbacks"
    EXIT_CODE=1
else
    green "✓ no per-call SecretsManager::new(...) outside canonical wiring"
fi
echo

# ── 5. Helm chart renders with default values AND with every toggle on ──
bold "▶ check 5: helm chart renders cleanly"

# r253 shipped with controller.audit.s3ObjectLock under the wrong parent
# block (worker:), so the chart's default render failed in prod with
# "nil pointer evaluating interface {}.s3ObjectLock". cargo-check is
# blind to this class — it survives until `helm upgrade` sees the
# template execute against the actual values tree.
#
# Two renders here:
#   (a) default values — every key the templates reference must exist.
#   (b) every `enabled: false` flipped to `true` — renders the
#       conditional blocks too. Catches misplaced keys whose `{{- if }}`
#       guard masks them when the toggle is off.
#
# Helm is required; if it's not installed we skip with a warning rather
# than fail (CI installs it; some local dev environments don't).

CHART_DIR="$ROOT/deploy/helm/talos"
if ! command -v helm >/dev/null 2>&1; then
    yellow "⚠ helm not installed — skipping chart render check"
    yellow "  install: https://helm.sh/docs/intro/install/"
elif [ ! -d "$CHART_DIR" ]; then
    yellow "⚠ chart directory not found at $CHART_DIR — skipping"
else
    HELM_LOG="$(mktemp)"
    trap 'rm -f "$ROUTES_FILE" "$NGINX_FILE" "$HELM_LOG"' EXIT

    # (a) Default render.
    if helm template "$CHART_DIR" >/dev/null 2>"$HELM_LOG"; then
        :
    else
        red "✗ helm template (default values) failed"
        sed 's/^/  /' "$HELM_LOG"
        EXIT_CODE=1
    fi

    # (b) Render with every operator-facing `enabled: false` toggled on.
    # Discover them by grepping values.yaml for the pattern. This is a
    # best-effort sweep — anything matching `<path>: enabled: false` in
    # values.yaml gets flipped to true. Misses gated-on-other-fields
    # blocks but catches the common "is the key under the right parent"
    # bug class, which is what r253 shipped broken.
    SET_ARGS=()
    # Walk the YAML keeping a path stack indexed by indent column.
    # When we see `enabled: false`, emit the dotted path to its parent.
    while IFS= read -r path; do
        SET_ARGS+=(--set "${path}.enabled=true")
    done < <(awk '
        function indent_of(line,    s) {
            s = line
            sub(/[^ ].*$/, "", s)
            return length(s)
        }
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        # A scalar key:value or a parent map.
        /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*:/ {
            ind = indent_of($0)
            line = $0
            sub(/^[[:space:]]+/, "", line)
            sub(/:.*$/, "", line)
            key = line
            # Trim stack to entries shallower than this indent.
            while (top > 0 && stack_indent[top] >= ind) { top-- }
            top++
            stack[top] = key
            stack_indent[top] = ind
            # If this line is `enabled: false`, emit the parent path.
            if ($0 ~ /^[[:space:]]*enabled:[[:space:]]*false[[:space:]]*$/) {
                parent = ""
                for (i = 1; i < top; i++) {
                    parent = parent (i == 1 ? "" : ".") stack[i]
                }
                if (parent != "") print parent
            }
        }
    ' "$CHART_DIR/values.yaml")

    if [ "${#SET_ARGS[@]}" -gt 0 ]; then
        if helm template "$CHART_DIR" "${SET_ARGS[@]}" >/dev/null 2>"$HELM_LOG"; then
            green "✓ helm chart renders cleanly (defaults + ${#SET_ARGS[@]} toggles flipped on)"
        else
            red "✗ helm template (toggles on) failed — likely a misplaced key under a parent that's only evaluated when the toggle is true"
            yellow "  toggles flipped: $(printf '%s ' "${SET_ARGS[@]}")"
            sed 's/^/  /' "$HELM_LOG"
            EXIT_CODE=1
        fi
    else
        green "✓ helm chart renders cleanly (defaults; no enabled-toggles to flip)"
    fi
    rm -f "$HELM_LOG"
fi
echo

# ── 6. Raw sqlx::query inside MCP handler functions ─────────────────
bold "▶ check 6: raw sqlx::query inside talos-mcp-handlers/"

# As of 2026-05-04 the entire MCP handler tree is raw-sqlx-free — every
# query lives in a repository (ActorRepository, ModuleRepository,
# WorkflowRepository, ExecutionRepository, AnalyticsRepository,
# AdvancedRepository, …) or a service (SecretsManager, AuthService,
# CompilationService, ParallelWorkflowEngine, …). This lint freezes that
# invariant so we don't backslide.
#
# Why repository-only: every former handler-side raw query had the same
# class of bug — caller-supplied user_id wasn't bound, owner_user_id
# filter wasn't added, malformed encrypted_value handling drifted
# between sites. Centralising in repos means the next reviewer sees
# the canonical shape and the next compile-time-clean SELECT change
# doesn't have to be hunted down in 27 files.
#
# Opt-out: add `// allow-mcp-sqlx: <reason>` within 8 lines above. Real
# justification only — the path is `make handler thin → push SQL into
# repo → call repo from handler`. If you're adding a new query, the
# repo is where it goes.
MCP_SQLX_VIOLATIONS=0
while IFS= read -r line; do
    file="$(echo "$line" | cut -d: -f1)"
    lineno="$(echo "$line" | cut -d: -f2)"
    mcp_start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${mcp_start},${lineno}p" "$file" 2>/dev/null \
            | grep -q 'allow-mcp-sqlx'; then
        continue
    fi
    printf '  %s\n' "$line"
    MCP_SQLX_VIOLATIONS=$((MCP_SQLX_VIOLATIONS + 1))
done < <(grep -rEn 'sqlx::query' \
            --include='*.rs' \
            --exclude-dir=target \
            talos-mcp-handlers/src 2>/dev/null \
        || true)

if [ "$MCP_SQLX_VIOLATIONS" -gt 0 ]; then
    red "✗ found $MCP_SQLX_VIOLATIONS raw sqlx::query calls in talos-mcp-handlers/"
    yellow "  → push the SQL into the relevant repository crate"
    yellow "    (talos-actor-repository, talos-module-repository, talos-workflow-repository,"
    yellow "     talos-execution-repository, talos-analytics-repository, talos-advanced-repository)"
    yellow "  → or add // allow-mcp-sqlx: <reason> for documented exceptions"
    EXIT_CODE=1
else
    green "✓ talos-mcp-handlers/ is raw-sqlx-free"
fi
echo

# ── 7. CI's clippy invocation must pass cleanly ─────────────────────
bold "▶ check 7: cargo clippy --workspace --no-deps -- -D warnings"

# 2026-05-04: a clippy::large_enum_variant CI break landed in 58a3c1e
# and went undetected for two days because the local dev loop used
# `cargo check`, not clippy. CI runs the invocation below; this lint
# matches it bit-for-bit so PRs see the failure at make-lint time
# rather than after push.
#
# Why `--no-deps` and not `--all-targets`: matches CI's existing
# scope (lib + bin only). Test/example clippy drift is tracked
# separately and would expand this gate. See `.github/workflows/ci.yml`
# step "cargo clippy --workspace --no-deps".
#
# This check is gated behind TALOS_LINT_CLIPPY=1 by default because
# clippy is a 60-90s build for a fresh tree. CI sets the env. Local
# `make lint` callers can opt in by exporting it.
if [ "${TALOS_LINT_CLIPPY:-0}" = "1" ]; then
    if cargo clippy --workspace --no-deps -- -D warnings >/dev/null 2>&1; then
        green "✓ clippy --workspace --no-deps clean (-D warnings)"
    else
        red "✗ clippy --workspace --no-deps failed (-D warnings)"
        yellow "  → re-run \`cargo clippy --workspace --no-deps -- -D warnings\` for diagnostics"
        EXIT_CODE=1
    fi
else
    yellow "⊘ clippy check skipped (set TALOS_LINT_CLIPPY=1 to enable)"
    yellow "  CI runs this gate; opt in locally for parity at PR time"
fi
echo

# ── 8. workflow_executions has no top-level `trigger_type` column ─────
bold "▶ check 8: trigger_type column references against workflow_executions"

# 2026-05-06: get_schedule_health silently returned zeros for every
# scheduled workflow because `get_scheduled_24h_execution_stats` and
# `list_recent_scheduled_execution_statuses` filtered on
# `WHERE trigger_type = 'scheduled'` against `workflow_executions` —
# but trigger_type only exists on `node_executions` (per migration
# 012_node_executions.sql). The handler's unwrap_or_else swallowed
# the column-not-found error and returned WorkflowHealthStats { 0, … },
# masking the bug entirely. Discovered via an MCP probe; rolled out
# in commit 357d7e4. The canonical projection on workflow_executions
# is `provenance->>'trigger_type'`.
#
# This lint freezes the invariant: any new SQL string that says
# `trigger_type` on the same line as `workflow_executions` (or in a
# string literal that also names workflow_executions) is suspect. The
# pattern is narrow on purpose — string searches naturally produce
# false positives from comments / docs that mention both terms; the
# 8-line opt-out (`// allow-trigger-type-column: <reason>`) covers
# legitimate cases. The two repository sites that DO need the right
# pattern (`provenance->>'trigger_type'`) are not flagged.
TRIGGER_TYPE_VIOLATIONS=0
# Per-file awk scan: for every line containing `trigger_type`, look at
# ±5 lines for `workflow_executions`. Catches both single-line refs
# AND the multi-line `SELECT ... trigger_type \` + `FROM workflow_executions`
# pattern (the actual shape of the analytics-repo audit-trail bug
# discovered 2026-05-06 — the original lint missed it because the
# two terms lived on different lines).
#
# Filters: skip doc comments (`///`), regular line comments (`//`),
# the canonical `provenance->>'trigger_type'` pattern, and explicit
# opt-outs (`// allow-trigger-type-column`).
while IFS= read -r match; do
    file="$(echo "$match" | cut -d: -f1)"
    lineno="$(echo "$match" | cut -d: -f2)"
    tt_start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${tt_start},${lineno}p" "$file" 2>/dev/null \
            | grep -q 'allow-trigger-type-column'; then
        continue
    fi
    printf '  %s\n' "$match"
    TRIGGER_TYPE_VIOLATIONS=$((TRIGGER_TYPE_VIOLATIONS + 1))
done < <(
    find . -name '*.rs' -not -path '*/target/*' -not -path '*/.claude/*' \
        -print0 2>/dev/null \
    | xargs -0 -I{} awk -v F='{}' '
        /trigger_type/ { interesting[NR] = $0 }
        { lines[NR] = $0 }
        END {
            for (n in interesting) {
                found_we = 0
                for (j = n-5; j <= n+5; j++) {
                    if (lines[j] ~ /workflow_executions/) found_we = 1
                }
                if (!found_we) continue
                line = interesting[n]
                if (line ~ /provenance->>'\''trigger_type'\''/) continue
                if (line ~ /node_executions/) continue
                if (line ~ /^[[:space:]]*\/\//) continue
                printf "%s:%d: %s\n", F, n, line
            }
        }
    ' {} 2>/dev/null \
    || true
)

if [ "$TRIGGER_TYPE_VIOLATIONS" -gt 0 ]; then
    red "✗ found $TRIGGER_TYPE_VIOLATIONS sites referencing trigger_type on workflow_executions"
    yellow "  → workflow_executions has NO top-level trigger_type column."
    yellow "    Use \`provenance->>'trigger_type'\` (canonical: ExecutionRepository::get_execution_base)."
    yellow "  → Or add // allow-trigger-type-column: <reason> if intentional (e.g. node_executions sub-query)."
    EXIT_CODE=1
else
    green "✓ no broken trigger_type column refs against workflow_executions"
fi
echo

# ── 9. boolean-column drift (is_active / enabled) on schedules / webhooks ─
bold "▶ check 9: boolean-column drift against workflow_schedules / webhook_triggers"

# 2026-05-06: get_workflow_summary reported `active_schedules: 0` and
# the daily-digest "upcoming schedules" surface returned empty for
# every workflow despite enabled schedules existing in list_schedules.
# Root cause: queries used the WRONG boolean-column name for these
# tables. Postgres errored at runtime, repo `unwrap_or` swallowed it,
# silent-zero hazard like the trigger_type class.
#
# Canonical column names:
#   workflow_schedules.is_enabled   (migration 20260309000200)
#   webhook_triggers.enabled        (initial schema, never renamed)
#   workflow_versions.is_active     (real column — not flagged)
#   workflows.is_enabled            (migration 20260314001600 — not flagged)
#
# Lint pattern: any line containing `is_active = ` OR `\benabled = `
# WHERE ±5 lines mention `workflow_schedules` or `webhook_triggers`.
# Then post-filter against the canonical pair so the correct usages
# (workflow_schedules.is_enabled and webhook_triggers.enabled) DON'T
# fire — only the wrong combinations do.
IS_ACTIVE_VIOLATIONS=0
while IFS= read -r match; do
    file="$(echo "$match" | cut -d: -f1)"
    lineno="$(echo "$match" | cut -d: -f2)"
    ia_start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${ia_start},${lineno}p" "$file" 2>/dev/null \
            | grep -q 'allow-is-active-column'; then
        continue
    fi
    printf '  %s\n' "$match"
    IS_ACTIVE_VIOLATIONS=$((IS_ACTIVE_VIOLATIONS + 1))
done < <(
    find . -name '*.rs' -not -path '*/target/*' -not -path '*/.claude/*' \
        -print0 2>/dev/null \
    | xargs -0 -I{} awk -v F='{}' '
        /is_active|\benabled[[:space:]]*=/ {
            interesting[NR] = $0
        }
        { lines[NR] = $0 }
        END {
            for (n in interesting) {
                found_schedules = 0
                found_webhooks = 0
                for (j = n-5; j <= n+5; j++) {
                    if (lines[j] ~ /workflow_schedules/) found_schedules = 1
                    if (lines[j] ~ /webhook_triggers/)   found_webhooks  = 1
                }
                line = interesting[n]
                if (line ~ /^[[:space:]]*\/\//) continue

                if (found_schedules) {
                    # workflow_schedules: is_enabled is correct, anything else is suspect.
                    if (line ~ /\bis_enabled\b/) continue
                    if (line ~ /\bis_active\b/ || line ~ /\benabled[[:space:]]*=/) {
                        printf "%s:%d: %s\n", F, n, line
                    }
                } else if (found_webhooks) {
                    # webhook_triggers: enabled is correct, anything else is suspect.
                    if (line ~ /\bis_active\b/) {
                        printf "%s:%d: %s\n", F, n, line
                    }
                    # is_enabled would also be wrong here, but no current code uses it
                }
            }
        }
    ' {} 2>/dev/null \
    || true
)

if [ "$IS_ACTIVE_VIOLATIONS" -gt 0 ]; then
    red "✗ found $IS_ACTIVE_VIOLATIONS sites with wrong boolean column for workflow_schedules / webhook_triggers"
    yellow "  → workflow_schedules.is_enabled (migration 20260309000200)"
    yellow "  → webhook_triggers.enabled       (initial schema, never renamed)"
    yellow "  → Or add // allow-is-active-column: <reason> if intentional"
    EXIT_CODE=1
else
    green "✓ no broken boolean column refs against schedules / webhook tables"
fi
echo

# ── 10. let _ = sqlx::query(...).execute(...) silent-swallow drift ────
bold "▶ check 10: let _ = sqlx::query(...).await silent-swallow outside tests"

# 2026-05-13/14: MCP-733 through MCP-804 closed 50+ sites of the
# fire-and-forget swallow class — `let _ = sqlx::query(...).execute(&pool).await`
# discarded DB errors that an operator needed visibility into
# (failure-marking UPDATE that left rows stuck 'running', audit-log
# writes that left gaps in WORM ledger reconstruction, lockout-state
# HSETs that degraded brute-force gating, etc.). Every fixed site
# either propagated the Err via `?`, logged via `if let Err(e) = ...`
# with `target: "talos_audit"` / "talos_rpc", or chained `.map_err`
# to log the cause before continuing.
#
# This lint freezes that invariant. A new `let _ = sqlx::query(...)`
# in production code must either:
#   1. Switch to `if let Err(e) = ...` + WARN at the canonical
#      target, OR
#   2. Add `// allow-sqlx-swallow: <reason>` within 8 lines above,
#      documenting why this site is genuinely best-effort.
#
# Test code (tests/, _test.rs, _tests.rs) is exempt — fixture
# cleanup legitimately doesn't care about errors.
SQLX_SWALLOW_VIOLATIONS=0
while IFS= read -r line; do
    file="$(echo "$line" | cut -d: -f1)"
    lineno="$(echo "$line" | cut -d: -f2)"
    ss_start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${ss_start},${lineno}p" "$file" 2>/dev/null \
            | grep -q 'allow-sqlx-swallow'; then
        continue
    fi
    printf '  %s\n' "$line"
    SQLX_SWALLOW_VIOLATIONS=$((SQLX_SWALLOW_VIOLATIONS + 1))
done < <(grep -rEn '^\s*let _\s*=\s*sqlx::query' \
            --include='*.rs' \
            --exclude-dir=target \
            --exclude-dir=tests \
            --exclude-dir=.claude \
            --exclude-dir=.git \
            . 2>/dev/null \
        | grep -v '_test\.rs:\|_tests\.rs:\|/tests/\|/test/' \
        || true)

if [ "$SQLX_SWALLOW_VIOLATIONS" -gt 0 ]; then
    red "✗ found $SQLX_SWALLOW_VIOLATIONS silent-swallow sites"
    yellow "  → use \`if let Err(e) = ...\` + WARN with \`target: \"talos_audit\"\`"
    yellow "    (or \"talos_rpc\" for outbound delivery), so operators see when"
    yellow "    the swallowed mutation fails. See MCP-733..804 for the family."
    yellow "  → or add // allow-sqlx-swallow: <reason> if genuinely best-effort"
    yellow "    (background cache hydration, etc.)"
    EXIT_CODE=1
else
    green "✓ no let _ = sqlx::query(...) silent-swallow in production code"
fi
echo

# ── 11. if let Err(...) = ...post(...).send().await — non-2xx swallow ──
bold "▶ check 11: misleading-success Err-only outbound webhook fires"

# 2026-05-14: MCP-809/810 closed the last two sites where outbound
# webhook fires used `if let Err(e) = client.post(...).send().await
# { warn(...) }` — silently swallowing `Ok(non-2xx)` responses. An
# operator-supplied notification endpoint returning 4xx (rate-limit)
# or 5xx (incident-mgmt outage) was treated as a successful
# notification: the workflow_alerts row landed locally but the
# operator alert never reached the destination, with zero log signal
# correlating the delivery failure to controller health.
#
# Canonical fix shape (3-arm match):
#   match client.post(...).send().await {
#       Ok(resp) if resp.status().is_success() => debug,
#       Ok(resp) => warn(target = "talos_rpc", status, ...),
#       Err(e)   => warn(target = "talos_rpc", error = e, ...),
#   }
#
# This lint freezes the canonical shape. A new outbound webhook fire
# using `if let Err = ...post(...).send().await` must either:
#   1. Switch to the 3-arm match (see failure_webhook.rs:83 for the
#      reference), OR
#   2. Add `// allow-err-only-webhook: <reason>` within 8 lines above,
#      documenting why this site is legitimately Err-only.
#
# Pattern matches `if let Err...send().await` on the same line; the
# multi-line form is harder to detect with grep but the single-line
# form is the dominant shape in talos (small payloads).
ERR_ONLY_WEBHOOK_VIOLATIONS=0
while IFS= read -r line; do
    file="$(echo "$line" | cut -d: -f1)"
    lineno="$(echo "$line" | cut -d: -f2)"
    eo_start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${eo_start},${lineno}p" "$file" 2>/dev/null \
            | grep -q 'allow-err-only-webhook'; then
        continue
    fi
    printf '  %s\n' "$line"
    ERR_ONLY_WEBHOOK_VIOLATIONS=$((ERR_ONLY_WEBHOOK_VIOLATIONS + 1))
done < <(grep -rEn 'if let Err.*=.*\.post\(.*\.send\(\)\.await' \
            --include='*.rs' \
            --exclude-dir=target \
            --exclude-dir=tests \
            --exclude-dir=.claude \
            --exclude-dir=.git \
            . 2>/dev/null \
        | grep -v '_test\.rs:\|_tests\.rs:\|/tests/\|/test/' \
        || true)

if [ "$ERR_ONLY_WEBHOOK_VIOLATIONS" -gt 0 ]; then
    red "✗ found $ERR_ONLY_WEBHOOK_VIOLATIONS Err-only webhook fire(s)"
    yellow "  → switch to the canonical 3-arm match — see"
    yellow "    talos-execution-orchestration::failure_webhook (line ~83)"
    yellow "    for the reference. Ok(non-2xx) MUST emit a WARN with"
    yellow "    \`target: \"talos_rpc\"\` so operators correlate delivery"
    yellow "    failures with controller health."
    yellow "  → or add // allow-err-only-webhook: <reason> if legitimately"
    yellow "    Err-only (rare — most cases benefit from the 3-arm shape)."
    EXIT_CODE=1
else
    green "✓ no Err-only outbound webhook fires"
fi
echo

# ── 12. .unwrap_or(N).min(M) caller-supplied negative bypass ──────────
bold "▶ check 12: caller-supplied limit clamp drift (.unwrap_or().min() shape)"

# 2026-05-13/14: MCP-767/811/812 closed seven sites of the caller-
# supplied-negative clamp drift class. The drifted pattern:
#
#   .unwrap_or(N).min(M) as i64
#
# …clamps ONLY the upper bound. A caller-supplied `Some(-1)` propagates
# unchanged: into Postgres LIMIT -1 → 500, into Redis EXPIRE -1 →
# instant delete, into i32-bound DB columns → `as usize` underflow
# (MCP-812 webhook rate-limit case → 18 quintillion → effectively
# unlimited rate).
#
# Canonical fix shape:
#   .unwrap_or(N).clamp(1, M) as i64
#
# This lint freezes the canonical clamp shape. A new
# `.unwrap_or(N).min(M)` in production code must either:
#   1. Switch to `.clamp(1, M)` (preserves the upper bound, adds
#      lower-bound defense against caller-supplied negatives), OR
#   2. Add `// allow-min-only-clamp: <reason>` within 8 lines above,
#      documenting why the lower bound doesn't matter (e.g. source
#      is typed u64 / usize so it can't be negative).
#
# MCP-1196 (2026-05-17): regex widened to match identifier-constant
# `.min` args in addition to numeric literals — pre-fix the pattern
# `\.unwrap_or\([0-9]+\)\s*\.min\([0-9]+\)` missed sites like
# `.unwrap_or(0).min(SYNC_WAIT_MAX_MS)` where the cap is a named
# constant. The widened pattern now covers both numeric and
# `[A-Z_][A-Z0-9_]*` (uppercase const) shapes.
MIN_CLAMP_VIOLATIONS=0
while IFS= read -r line; do
    file="$(echo "$line" | cut -d: -f1)"
    lineno="$(echo "$line" | cut -d: -f2)"
    mc_start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${mc_start},${lineno}p" "$file" 2>/dev/null \
            | grep -q 'allow-min-only-clamp'; then
        continue
    fi
    printf '  %s\n' "$line"
    MIN_CLAMP_VIOLATIONS=$((MIN_CLAMP_VIOLATIONS + 1))
done < <(grep -rEn '\.unwrap_or\(([0-9]+|[A-Z_][A-Z0-9_]*)\)\s*\.min\(([0-9]+|[A-Z_][A-Z0-9_]*)\)' \
            --include='*.rs' \
            --exclude-dir=target \
            --exclude-dir=tests \
            --exclude-dir=.claude \
            --exclude-dir=.git \
            . 2>/dev/null \
        | grep -v '_test\.rs:\|_tests\.rs:\|/tests/\|/test/' \
        || true)

if [ "$MIN_CLAMP_VIOLATIONS" -gt 0 ]; then
    red "✗ found $MIN_CLAMP_VIOLATIONS .unwrap_or().min() clamp drift site(s)"
    yellow "  → switch to .clamp(1, M) to bound the lower end too"
    yellow "    Caller \`Some(-1)\` propagates past .min() unchanged."
    yellow "    See MCP-767 (Postgres LIMIT -1 → 500), MCP-811 (six"
    yellow "    GraphQL paginated queries), MCP-812 (i32→DB→as usize"
    yellow "    underflow on webhook rate-limit) for the failure modes."
    yellow "  → or add // allow-min-only-clamp: <reason> if the source"
    yellow "    type can't be negative (typed u64/usize)."
    EXIT_CODE=1
else
    green "✓ no .unwrap_or().min() clamp drift in production code"
fi
echo

# ── 13: NetworkPolicy chart-wide-label selector drift ───────────────
bold "▶ check 13: chart-wide labels under NetworkPolicy from:/to: selectors"

# 2026-05-14: MCP-897 closed a silent worker→vault grant in the vault
# NetworkPolicy. The over-broad rule used:
#
#   - podSelector:
#       matchLabels:
#         app.kubernetes.io/part-of: talos
#         app.kubernetes.io/instance: <release>
#
# …intended to "match the vault-init Job pod" — but
# `talos.componentLabels` (helpers.tpl) renders `part-of: talos` +
# `instance: <release>` on EVERY workload in the chart, so the
# selector silently let worker / frontend / neo4j / nats / minio
# reach Vault:8200 in direct contradiction of the architecture
# comment "Worker has NO direct Vault access."
#
# This lint freezes the anti-pattern: any literal
# `app.kubernetes.io/part-of:` or `app.kubernetes.io/managed-by:`
# inside a NetworkPolicy template file is a regression candidate.
# Both labels are chart-wide via `talos.labels` (see _helpers.tpl)
# and SHOULD only appear in metadata.labels via helper invocation —
# never hand-written into a selector matchLabels block.
#
# Canonical alternative: scope selectors with
# `app.kubernetes.io/component: <name>` + `instance: <release>`
# (component is the per-workload discriminator).
#
# Opt-out marker `# allow-chart-wide-selector: <reason>` within 8
# lines above the offending line (in case some future use case
# legitimately needs to match all chart-owned workloads — though
# we can't currently imagine one).
CHART_LABEL_VIOLATIONS=0
while IFS= read -r line; do
    file="$(echo "$line" | cut -d: -f1)"
    lineno="$(echo "$line" | cut -d: -f2)"
    cl_start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${cl_start},${lineno}p" "$file" 2>/dev/null \
            | grep -q 'allow-chart-wide-selector'; then
        continue
    fi
    printf '  %s\n' "$line"
    CHART_LABEL_VIOLATIONS=$((CHART_LABEL_VIOLATIONS + 1))
done < <(grep -rEn '^[^#]*app\.kubernetes\.io/(part-of|managed-by):' \
            deploy/helm/talos/templates 2>/dev/null \
        | grep -v '_helpers\.tpl:' \
        || true)

if [ "$CHART_LABEL_VIOLATIONS" -gt 0 ]; then
    red "✗ found $CHART_LABEL_VIOLATIONS chart-wide-label selector site(s)"
    yellow "  → chart-wide labels (part-of, managed-by) are rendered on"
    yellow "    EVERY workload in the release by talos.componentLabels."
    yellow "    Using them in a NetworkPolicy from:/to: selector creates a"
    yellow "    silent allow-all-in-chart rule (see MCP-897 — worker→vault)."
    yellow "  → use app.kubernetes.io/component: <workload> + instance for"
    yellow "    real per-workload scoping."
    yellow "  → or add # allow-chart-wide-selector: <reason> if you really"
    yellow "    do want every chart-owned workload to match."
    EXIT_CODE=1
else
    green "✓ no chart-wide-label selector drift in NetworkPolicy templates"
fi
echo

# ── 14: GraphQL Err(async_graphql::Error::new(...)) missing .extend_safe() ──
bold "▶ check 14: talos-api Err(async_graphql::Error::new) missing .extend_safe()"

# 2026-05-14: MCP-916/917/918 closed 27 sites where actionable
# error messages were silently being replaced with "Internal server
# error" by the production scrubber (controller/main.rs:4990-5009).
# The scrubber checks for an explicit `.extend_safe()` marker OR
# substring overlap with a case-sensitive whitelist (Authentication
# / Access denied / Not found / Invalid / Validation / Unauthorized).
# Messages with neither survived only because the substring fallback
# accidentally matched — easy to regress.
#
# This lint freezes the post-MCP-918 discipline: every new
# `Err(async_graphql::Error::new(...))` inside talos-api/src MUST
# call `.extend_safe()` within 8 lines OR carry an opt-out marker
# `// allow-unsafe-error: <reason>` for cases where the message is
# explicitly opaque-by-design (e.g. enumeration defense where
# "Internal server error" IS the intended client output).
#
# Scoped to talos-api/src/ — other crates don't go through the
# scrubber and follow different error-discipline conventions.
EXTEND_SAFE_VIOLATIONS=0
while IFS= read -r line; do
    file="$(echo "$line" | cut -d: -f1)"
    lineno="$(echo "$line" | cut -d: -f2)"
    # MCP-1200 (2026-05-17): between-pair semantics. Pre-fix the lint
    # scanned an 8-line lookahead from each Error::new and treated ANY
    # .extend_safe() in that window as covering the match. Two
    # Error::new calls in the same if/else block (or any close-paired
    # pattern) → the first one's lookahead saw the SECOND's
    # .extend_safe() and silently passed both, even when the first
    # was bare. register_mcp_agent.rs:150 was a live instance of this
    # blind spot (duplicate-name message replaced with "Internal
    # server error" in production).
    #
    # New logic: scan forward up to 20 lines, and look for
    # .extend_safe() BEFORE the next async_graphql::Error::new(
    # appears. The first .extend_safe() encountered before a new
    # Error::new is unambiguously the current call's marker. If a
    # new Error::new appears first, the current call is missing
    # its .extend_safe().
    end_line=$((lineno + 20))
    found_extend_safe=0
    next_lineno=$((lineno + 1))
    while [ "$next_lineno" -le "$end_line" ]; do
        next_line="$(sed -n "${next_lineno}p" "$file" 2>/dev/null)"
        # Skip if blank/empty
        if [ -z "$next_line" ]; then
            next_lineno=$((next_lineno + 1))
            continue
        fi
        if echo "$next_line" | grep -q '\.extend_safe()'; then
            found_extend_safe=1
            break
        fi
        if echo "$next_line" | grep -q 'async_graphql::Error::new('; then
            # New call begins before current call closed — current is bare.
            break
        fi
        next_lineno=$((next_lineno + 1))
    done
    # Also accept .extend_safe() on the SAME line as the match
    # (single-line patterns like Error::new("foo").extend_safe()).
    same_line="$(sed -n "${lineno}p" "$file" 2>/dev/null)"
    if echo "$same_line" | grep -q '\.extend_safe()'; then
        found_extend_safe=1
    fi
    if [ "$found_extend_safe" -eq 1 ]; then
        continue
    fi
    # Skip if opt-out marker is within 8 lines above
    es_start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${es_start},${lineno}p" "$file" 2>/dev/null \
            | grep -q 'allow-unsafe-error'; then
        continue
    fi
    # Skip if any whitelist-substring is present in the FIRST 5 lines of
    # the call (the message body). Pre-MCP-1200 the check used the full
    # 8-line block — could match a whitelist substring belonging to a
    # SIBLING Error::new call. Scoping to the message-body lines stops
    # that false-cover. MCP-1051 (2026-05-15): the substring list MUST
    # match the canonical `talos_api::schema::SAFE_ERROR_SUBSTRINGS` const
    # used by the production scrubber (talos-api/src/schema/mod.rs). If
    # the const changes, update this regex too — same substrings,
    # case-sensitive.
    msg_block="$(sed -n "${lineno},$((lineno + 5))p" "$file" 2>/dev/null)"
    if echo "$msg_block" | grep -qE 'Authentication|Access denied|Not found|Invalid|Validation|Unauthorized'; then
        continue
    fi
    printf '  %s\n' "$line"
    EXTEND_SAFE_VIOLATIONS=$((EXTEND_SAFE_VIOLATIONS + 1))
# MCP-963 (2026-05-15): widen the lint pattern to also catch
# `.map_err(|_| async_graphql::Error::new(...))` and
# `.map_err(|e| async_graphql::Error::new(...))` sites — same
# scrubber discipline applies, but the original pattern only
# matched `Err(...)`. The map_err sites were missed entirely.
# Pre-fix: 1 site in talos-api echoed `e.to_string()` without
# extend_safe AND without a whitelist-substring match → operator
# saw "Internal server error" on real DB errors AND on
# permission-denied; "Template not found or access denied"
# context-message had "not found" lowercase which DOES NOT match
# the case-sensitive "Not found" whitelist. Fixed in MCP-963 by
# adding extend_safe + tracing::error log of the underlying e.
#
# MCP-1048 (2026-05-15): widen further to ALL `async_graphql::Error::new(`
# call sites. The MCP-963 pattern still missed two shapes:
#   (a) multi-line `.map_err(|e| { ... async_graphql::Error::new(...)
#       })` where the closure body spans more than one line. grep -E
#       doesn't span newlines, so the seed only matched same-line
#       constructions.
#   (b) `.ok_or_else(|| async_graphql::Error::new(...))` — the
#       MCP-963 widening covered `\.map_err\(\|[a-z_]+\|` but NOT
#       `\.ok_or_else\(\|\|`.
# Pre-fix MCP-1048 audit found 3 sites in talos-api/src/schema/
# subscriptions.rs (Failed to fetch events / Streaming not available
# / Failed to subscribe) that bypassed both the lint AND the
# substring whitelist → scrubbed to "Internal server error" in
# production.
# The seed pattern now matches every call site; the lookahead block
# below applies the same .extend_safe() / whitelist / opt-out checks
# uniformly, so a future violation in any shape is caught.
done < <(grep -rEna 'async_graphql::Error::new\(' \
            --include='*.rs' \
            talos-api/src 2>/dev/null \
        | grep -v '_test\.\|/tests/\|/validation.rs:' \
        | grep -vE ':[[:space:]]*///' \
        | grep -vE ':[[:space:]]*//[^/]' \
        || true)

if [ "$EXTEND_SAFE_VIOLATIONS" -gt 0 ]; then
    red "✗ found $EXTEND_SAFE_VIOLATIONS Err(async_graphql::Error::new) site(s) missing .extend_safe()"
    yellow "  → mark with .extend_safe() so production scrubber doesn't"
    yellow "    replace the message with 'Internal server error'."
    yellow "    See MCP-916/917/918 for the 27-site sweep that established"
    yellow "    the discipline; controller/main.rs:4990 has the scrubber."
    yellow "  → opt-out comment // allow-unsafe-error: <reason> within 8"
    yellow "    lines above is for explicit enumeration-defense paths."
    EXIT_CODE=1
else
    green "✓ talos-api GraphQL errors all marked .extend_safe() (or whitelisted)"
fi
echo

# ── 15. Graph_json write chokepoint (MCP-1226 / 1227 / 1228 / 1229) ───
#
# Every MCP handler that writes workflows.graph_json MUST route through
# `crate::utils::ensure_graph_within_caps` (or the `save_graph_json` /
# `save_graph_json_unchecked` helpers in graph.rs that wrap it) BEFORE
# the repository UPDATE. The canonical
# `talos_workflow_types::validate_graph_timeouts` caps from MCP-1216 /
# MCP-1218 / MCP-1219 / MCP-1220 / MCP-1221 only run at create /
# update / import time; any narrow-mutation handler that does
# load-modify-save bypasses those caps unless the chokepoint is
# invoked. MCP-1226 (`update_node_config(action: "update_config")`)
# was the first live-verified bypass: caller stamped `timeout_secs:
# 86400`, `retry_count: 9000`, `retry_backoff_ms: 99999999` and they
# round-tripped through the DB. MCP-1227 (executions.rs
# `analyze_execution_failure` auto-fix path) and MCP-1228
# (`add_node_to_workflow`) were the sibling holes.
#
# The lint flags:
#   * `.update_workflow_graph(`
#   * `.update_workflow_graph_unchecked(`
#   * `.update_workflow_graph_json(`
# in `talos-mcp-handlers/` UNLESS the matched line is preceded within
# 8 lines by either `ensure_graph_within_caps` (the canonical
# chokepoint call) or `validate_graph_timeouts` (the underlying
# canonical validator — same contract). The two declarations in
# `graph.rs::save_graph_json` and `save_graph_json_unchecked` ARE
# the chokepoint, so they self-opt-out via `ensure_graph_within_caps`
# inside their own bodies.
#
# Opt-out marker: `// allow-direct-graph-write: <reason>` for any
# documented exception (none today).
bold "▶ check 15: graph_json writes via canonical chokepoint (MCP-1226/1227/1228/1229)"

GRAPH_WRITE_VIOLATIONS=0
while IFS= read -r line; do
    file="$(echo "$line" | cut -d: -f1)"
    lineno="$(echo "$line" | cut -d: -f2)"

    # Look 20 lines back for chokepoint call or opt-out marker. The
    # MCP-1227 executions.rs site needed >8 lines: the validator runs
    # at the start of an if/else block, the persist call lives in the
    # else branch, and the indentation pushes the persist line 12+
    # rows below the validator. 20 lines is enough headroom for the
    # widest pattern we use without being so generous it loses
    # specificity.
    start=$((lineno > 20 ? lineno - 20 : 1))
    context="$(sed -n "${start},${lineno}p" "$file" 2>/dev/null)"

    if echo "$context" | grep -q 'ensure_graph_within_caps\|validate_graph_timeouts\|allow-direct-graph-write'; then
        continue
    fi

    printf '  %s\n' "$line"
    GRAPH_WRITE_VIOLATIONS=$((GRAPH_WRITE_VIOLATIONS + 1))
done < <(grep -rEna '\.update_workflow_graph(_unchecked|_json)?\(' \
            --include='*.rs' \
            talos-mcp-handlers/src 2>/dev/null \
        | grep -v '_test\.\|/tests/' \
        | grep -vE ':[[:space:]]*//' \
        || true)

if [ "$GRAPH_WRITE_VIOLATIONS" -gt 0 ]; then
    red "✗ found $GRAPH_WRITE_VIOLATIONS direct graph_json write(s) bypassing canonical caps"
    yellow "  → call crate::utils::ensure_graph_within_caps(&graph_json, &req_id)?"
    yellow "    before the repository write, OR route through the"
    yellow "    save_graph_json / save_graph_json_unchecked helpers"
    yellow "    in graph.rs that already wrap it."
    yellow "  → opt-out comment // allow-direct-graph-write: <reason>"
    yellow "    within 8 lines above is for documented exceptions."
    EXIT_CODE=1
else
    green "✓ talos-mcp-handlers graph_json writes all route through canonical caps"
fi
echo

# ── 16: WIT contract drift between host and templates ──────────────
bold "▶ check 16: wit/talos.wit ↔ module-templates/wit/talos.wit drift"

# L3 (2026-05-22): the worker's authoritative WIT lives in
# `wit/talos.wit`; module-templates carry a copy at
# `module-templates/wit/talos.wit` so the compilation pipeline can
# bake the right bindings into each template's workspace. If the two
# diverge — e.g. a host fn is added or signature-changed in the
# authoritative file but the templates copy is missed — every
# template compilation produces a binary that fails at the worker's
# linker because the imported world doesn't match the host's
# exposed shape.
#
# The runtime failure is loud (instantiation panics with a
# "missing import" or "type mismatch" error) but only fires at
# execution time. Catching the drift at PR time saves an entire
# build-deploy-fail cycle.
#
# This lint runs a byte-for-byte diff. Operators who legitimately
# want the two files to differ (e.g. mid-migration where the
# templates copy lags by one WIT version) can add a literal
# `# allow-wit-drift: <reason>` comment to EITHER file's header
# (within first 20 lines).
HOST_WIT="$ROOT/wit/talos.wit"
TEMPLATES_WIT="$ROOT/module-templates/wit/talos.wit"
if [ -f "$HOST_WIT" ] && [ -f "$TEMPLATES_WIT" ]; then
    # Opt-out check first
    if head -20 "$HOST_WIT" 2>/dev/null | grep -q 'allow-wit-drift' \
       || head -20 "$TEMPLATES_WIT" 2>/dev/null | grep -q 'allow-wit-drift'; then
        yellow "⊘ WIT drift check bypassed by allow-wit-drift marker"
    elif ! diff -q "$HOST_WIT" "$TEMPLATES_WIT" >/dev/null 2>&1; then
        red "✗ wit/talos.wit and module-templates/wit/talos.wit differ"
        yellow "  → these files MUST match byte-for-byte. The host file"
        yellow "    (wit/talos.wit) is authoritative; the templates copy"
        yellow "    (module-templates/wit/talos.wit) is what each template"
        yellow "    workspace gets at compile time. Divergence means every"
        yellow "    template compiled here will fail at worker instantiation"
        yellow "    with 'missing import' or 'type mismatch'."
        yellow ""
        yellow "  → fix by copying the authoritative file:"
        yellow "    cp wit/talos.wit module-templates/wit/talos.wit"
        yellow ""
        yellow "  → opt-out: add '# allow-wit-drift: <reason>' to either"
        yellow "    file's first 20 lines during a planned migration."
        yellow ""
        yellow "  diff (first 30 lines):"
        diff "$HOST_WIT" "$TEMPLATES_WIT" 2>/dev/null | head -30 | sed 's/^/    /'
        EXIT_CODE=1
    else
        green "✓ wit/talos.wit ↔ module-templates/wit/talos.wit are in sync"
    fi
else
    if [ ! -f "$HOST_WIT" ]; then
        yellow "⚠ $HOST_WIT not found — skipping WIT-drift check"
    fi
    if [ ! -f "$TEMPLATES_WIT" ]; then
        yellow "⚠ $TEMPLATES_WIT not found — skipping WIT-drift check"
    fi
fi
echo

# ── 17. encrypted_secrets: Default::default() in dispatch paths ────────
bold "▶ check 17: encrypted_secrets: Default::default() outside tests"

# CLAUDE.md (2026-04-16 loop-node dispatch regression): every engine
# dispatch path MUST call build_encrypted_secrets() (or the equivalent
# inline block) to populate JobRequest.encrypted_secrets. Shipping
# `encrypted_secrets: Default::default()` to NATS means the module
# silently loses access to ALL secrets — vault:// headers fail with
# Notfound, LLM calls fail with missing keys, and the only signal is
# the WASM module's own error message (often hours of debugging
# later). The lesson was learned in production; the lint exists so
# the next new dispatch path can't quietly repeat the regression.
#
# The lint matches the two equivalent forms:
#     encrypted_secrets: Default::default()
#     encrypted_secrets: EncryptedSecrets::default()
#
# Test fixtures legitimately want the empty/default form (they don't
# exercise the secrets pipeline). The check excludes paths under
# `tests/`, `*_tests.rs`, and the protocol crate itself (where the
# Default impl lives + is unit-tested). If a production site has a
# documented reason — like a fire-and-forget dispatch where secrets
# are never needed — add a literal comment within 4 lines above:
#   // allow-empty-encrypted-secrets: <reason>
ES_VIOLATIONS=0
while IFS= read -r line; do
    file="$(echo "$line" | cut -d: -f1)"
    lineno="$(echo "$line" | cut -d: -f2)"
    # Skip test files explicitly (defense-in-depth — the grep already
    # excludes them by directory).
    case "$file" in
        */tests/*|*_tests.rs|*/talos-workflow-job-protocol/*)
            continue
            ;;
    esac
    es_start=$((lineno > 4 ? lineno - 4 : 1))
    if sed -n "${es_start},${lineno}p" "$file" 2>/dev/null \
            | grep -q 'allow-empty-encrypted-secrets'; then
        continue
    fi
    printf '  %s\n' "$line"
    ES_VIOLATIONS=$((ES_VIOLATIONS + 1))
done < <(grep -rEn \
            'encrypted_secrets:[[:space:]]*(EncryptedSecrets::)?Default::default\(\)' \
            --include='*.rs' \
            --exclude-dir=target \
            --exclude-dir=tests \
            controller/src worker/src talos-engine talos-workflow-engine \
            talos-workflow-engine-nats talos-execution-orchestration \
            talos-continuation-trigger talos-webhooks talos-google-calendar \
            talos-gmail talos-replay-service talos-jobs talos-rpc-subscribers \
            talos-hot-update-service talos-inline-compile-service \
            2>/dev/null \
        || true)

if [ "$ES_VIOLATIONS" -gt 0 ]; then
    red "✗ found $ES_VIOLATIONS sites"
    yellow "  → use build_encrypted_secrets() / encrypt_secrets_for_job()"
    yellow "  → or add // allow-empty-encrypted-secrets: <reason> if intentional"
    EXIT_CODE=1
else
    green "✓ no encrypted_secrets: Default::default() in dispatch paths"
fi
echo

# ── 18. bare .sign() on JobResult / PipelineJobResult in worker ────────
bold "▶ check 18: JobResult/.sign() in worker (must use sign_with_worker_id)"

# L-11 (2026-05-22): production worker code MUST bind worker identity
# into every signed JobResult / PipelineJobResult via
# .sign_with_worker_id(key, worker_identity()). The back-compat
# .sign(key) wrapper is retained ONLY for test fixtures that don't
# care about per-worker attribution. Without this lint, a future
# contributor adding a new dispatch path could call the back-compat
# wrapper and quietly degrade the audit-trail forensic guarantee.
#
# This check fires only on `worker/src/**/*.rs`. The protocol crate's
# own tests + the JobRequest::sign (request, not result) flows are
# out of scope.
RESULT_SIGN_VIOLATIONS=0
while IFS= read -r line; do
    file="$(echo "$line" | cut -d: -f1)"
    case "$file" in
        */tests/*|*_tests.rs)
            continue
            ;;
    esac
    # Match `<ident>.sign(` where the receiver is a JobResult or
    # PipelineJobResult — heuristic: the variable name contains
    # "result" or "replacement" (used in truncate_oversized_*).
    if echo "$line" | grep -qiE '\b(result|replacement)\.sign\('; then
        # Skip the canonical sign_with_worker_id call (it contains
        # the literal "_with_worker_id" right after `.sign`).
        if echo "$line" | grep -q '\.sign_with_worker_id'; then
            continue
        fi
        printf '  %s\n' "$line"
        RESULT_SIGN_VIOLATIONS=$((RESULT_SIGN_VIOLATIONS + 1))
    fi
done < <(grep -rEn '\.sign\(' \
            --include='*.rs' \
            --exclude-dir=target \
            worker/src 2>/dev/null \
        || true)

if [ "$RESULT_SIGN_VIOLATIONS" -gt 0 ]; then
    red "✗ found $RESULT_SIGN_VIOLATIONS sites in worker/src using bare .sign()"
    yellow "  → use .sign_with_worker_id(key, worker_identity())"
    yellow "  → see L-11 in talos-workflow-job-protocol/src/lib.rs"
    EXIT_CODE=1
else
    green "✓ all JobResult/PipelineJobResult signs in worker use sign_with_worker_id"
fi
echo

# ── 19. Worker JobResult publish must be single-publish ────────────────
bold "▶ check 19: worker must single-publish each JobResult (no dual NATS publish)"

# wasm-security-review (2026-05-22): the verify-once rule for signed
# NATS messages (CLAUDE.md "Verify-once rule") requires that each
# JobResult / PipelineJobResult be published to EXACTLY ONE NATS
# subject — the reply inbox when the JobRequest provided one, or the
# global audit topic otherwise. Dual-publishing (sending the same
# signed result to both) primes a deterministic JOB_NONCE_CACHE race
# where the second consumer's `verify()` deterministically rejects
# with "result_nonce already seen", and every job fails.
#
# This regression class survives `cargo check` and only manifests
# under live NATS traffic with both subscribers active. We catch it
# structurally: any worker file that contains TWO OR MORE
# `nats.publish(...)` calls inside the same function whose name
# contains "publish_job_result" / "publish_result" / "send_result"
# is treated as a violation. Opt-out: add the literal comment
# `// allow-dual-publish: <reason>` on the second publish site.

DUAL_PUBLISH_VIOLATIONS=0

# Strategy: rg the worker for `publish(` callsites, group by file +
# nearest preceding `fn` boundary, and count. > 1 in the same fn that
# matches the JobResult-publish name pattern → violation.
#
# This implementation is intentionally simple — it scans worker/src
# for any function whose body contains two non-opt-out `.publish(`
# calls AND whose declaration line matches the publish-result name
# pattern. False positives can be suppressed via the per-line opt-out
# marker.

WORKER_RS_FILES=$(find worker/src -name '*.rs' \
    -not -path '*/tests/*' \
    -not -name '*_tests.rs' 2>/dev/null || true)

for file in $WORKER_RS_FILES; do
    awk '
        BEGIN { current_fn = ""; current_is_publish = 0; count = 0; first_line = 0 }
        /^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/ {
            # Emit a violation for the function we are leaving, if it
            # had > 1 publish calls.
            if (current_is_publish && count > 1) {
                printf "VIOLATION:%s:%d: function `%s` has %d publish calls (dual-publish risk)\n", FILENAME, first_line, current_fn, count
            }
            # Start tracking the new function.
            current_fn = $0
            match(current_fn, /fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)
            if (RSTART > 0) {
                fn_name = substr(current_fn, RSTART, RLENGTH)
                sub(/^fn[[:space:]]+/, "", fn_name)
                current_fn = fn_name
            }
            current_is_publish = (current_fn ~ /publish_job_result|publish_result|send_result|publish_pipeline_result/)
            count = 0
            first_line = NR
            next
        }
        /\.publish\(/ {
            # Skip opt-out lines.
            if ($0 ~ /allow-dual-publish/) next
            # Skip lines that are inside a string literal (heuristic:
            # surrounded by `"` on both sides of the `publish` call
            # within the same line). We accept the imprecision —
            # opt-out covers any legitimate false positive.
            if (current_is_publish) {
                count++
            }
        }
        END {
            if (current_is_publish && count > 1) {
                printf "VIOLATION:%s:%d: function `%s` has %d publish calls (dual-publish risk)\n", FILENAME, first_line, current_fn, count
            }
        }
    ' "$file" 2>/dev/null | while IFS= read -r line; do
        if [ -n "$line" ]; then
            printf '  %s\n' "${line#VIOLATION:}"
            DUAL_PUBLISH_VIOLATIONS=$((DUAL_PUBLISH_VIOLATIONS + 1))
        fi
    done
done

# Note: the subshell counter increments above are lost when the loop
# exits. Recompute the total in one shot for the gate below.
DUAL_PUBLISH_VIOLATIONS=$(
    for file in $WORKER_RS_FILES; do
        awk '
            BEGIN { current_fn = ""; current_is_publish = 0; count = 0 }
            /^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/ {
                if (current_is_publish && count > 1) print "x"
                current_fn = $0
                match(current_fn, /fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)
                if (RSTART > 0) {
                    fn_name = substr(current_fn, RSTART, RLENGTH)
                    sub(/^fn[[:space:]]+/, "", fn_name)
                    current_fn = fn_name
                }
                current_is_publish = (current_fn ~ /publish_job_result|publish_result|send_result|publish_pipeline_result/)
                count = 0
                next
            }
            /\.publish\(/ {
                if ($0 ~ /allow-dual-publish/) next
                if (current_is_publish) count++
            }
            END {
                if (current_is_publish && count > 1) print "x"
            }
        ' "$file" 2>/dev/null
    done | wc -l | tr -d ' '
)

if [ "${DUAL_PUBLISH_VIOLATIONS:-0}" -gt 0 ]; then
    red "✗ found $DUAL_PUBLISH_VIOLATIONS publish-result function(s) with >1 .publish() call"
    yellow "  → JobResult / PipelineJobResult MUST be single-publish (CLAUDE.md 'Verify-once rule')"
    yellow "  → branch on reply_topic and publish to ONE subject, not both"
    yellow "  → see r300/r301 incident notes in talos-workflow-job-protocol"
    yellow "  → opt-out (with documented reason): add // allow-dual-publish: <reason>"
    EXIT_CODE=1
else
    green "✓ no dual-publish patterns in worker JobResult/PipelineJobResult send paths"
fi
echo

# ── 20. wasmtime proposal lockdown ─────────────────────────────────────
bold "▶ check 20: every wasmtime WASM proposal must be explicitly opted in/out"

# wasm-security-review (2026-05-22): worker/src/runtime.rs configures
# wasmtime with an explicit deny-list of WASM proposals
# (`wasm_threads(false)`, `wasm_simd(false)`, …). Each disabled
# proposal removes Cranelift codegen attack surface; historical
# wasmtime CVEs have repeatedly landed in SIMD lowering and GC. A
# future wasmtime point release that defaults a new proposal to ON
# would silently widen our codegen attack surface unless the lockdown
# list is updated.
#
# This check ensures the explicit-opt-out list contains every
# wasmtime proposal we know about today; adding a new wasmtime
# version that introduces a new `wasm_xxx` toggle either needs an
# explicit opt-out here, or an opt-out exception via
# `// allow-wasm-proposal-default: <reason>` near the proposal block.

REQUIRED_PROPOSALS=(
    "wasm_threads(false)"
    "wasm_simd(false)"
    "wasm_relaxed_simd(false)"
    "wasm_multi_memory(false)"
    "wasm_memory64(false)"
    "wasm_gc(false)"
    "wasm_function_references(false)"
    "wasm_tail_call(false)"
)

PROPOSAL_VIOLATIONS=0
RUNTIME_FILE="worker/src/runtime.rs"
if [ -f "$RUNTIME_FILE" ]; then
    for proposal in "${REQUIRED_PROPOSALS[@]}"; do
        # Use literal string match (-F) since the pattern contains parens.
        if ! grep -qF "$proposal" "$RUNTIME_FILE"; then
            printf '  missing required call: config.%s\n' "$proposal"
            PROPOSAL_VIOLATIONS=$((PROPOSAL_VIOLATIONS + 1))
        fi
    done
else
    yellow "  (worker/src/runtime.rs not found — skipping check)"
fi

if [ "$PROPOSAL_VIOLATIONS" -gt 0 ]; then
    red "✗ $PROPOSAL_VIOLATIONS WASM proposal lockdown call(s) missing in worker/src/runtime.rs"
    yellow "  → keep the explicit deny-list current; adding a new wasmtime proposal"
    yellow "    silently widens the Cranelift codegen attack surface."
    yellow "  → see docs/wasmtime-version-tracking.md for the upgrade checklist."
    EXIT_CODE=1
else
    green "✓ wasmtime proposal lockdown calls present"
fi
echo

# ── 21. Saturating integer-cast discipline at trust boundaries ────────
bold "▶ check 21: integer-cast wraparound (.as_u64().*as u32 / map(|i| i as i32))"

# MCP-960..962 + MCP-1007/1008 + 2026-05-28 audit established the
# saturating-cast rule for caller-controlled numeric fields crossing
# a width boundary:
#
#   MCP-960: `(t - t0).num_milliseconds() as i32` wrapped for durations
#            >= 24.8 days. Saturate via `try_from + unwrap_or(i32::MAX)`.
#   MCP-961: i32 -> u32 wrap via `row.iteration_index.map(|i| i as u32)`.
#            Use `.max(0) as u32` at the read boundary.
#   MCP-962: u64 -> u32 wrap via `v.as_u64().map(|v| v as u32)`.
#            Saturate via `u32::try_from(v).unwrap_or(u32::MAX)`.
#   MCP-1008: u64 -> u32 sibling in worker LLM token-count parsing.
#   2026-05-28: caught two unchecked siblings — `talos-workflow-engine/
#               src/graph_parser.rs::read_node_retry_policy` and
#               `talos-yaml-workflows::lib.rs` both did
#               `.as_u64()...as u32` on workflow `retry_count`.
#
# The lint flags two specific dangerous shapes that survived past
# audits because `cargo check` passes them cleanly:
#
#   1. `\.as_u64\(\)`-then-`as u(8|16|32)` — direct u64→smaller wrap.
#      Defense: `u<N>::try_from(v).unwrap_or(u<N>::MAX)`.
#
#   2. `\.map\(\|[a-z_]+\| [a-z_]+ as i32\)` — u32→i32 cast applied
#      to engine-event field types via `Option::map`. Plausibly safe
#      today (engine emits non-pathological counters) but defense-in-
#      depth at the write boundary mirrors the read-boundary
#      saturate. Defense: a helper like `saturating_u32_to_i32` that
#      uses `i32::try_from(v).unwrap_or(i32::MAX)`.
#
# Opt-out: `// allow-as-u32-cast: <reason>` within 4 lines above a
# call site that's provably safe (e.g. bounded by an upstream `min()`
# clamp, or sourced from a typed `u8` literal). The presence of an
# opt-out comment skips the line.

CAST_VIOLATIONS=0

# Pattern 1: `.as_u64()` followed by `as u32` / `as u16` / `as u8`
# within ~3 lines (covering both inline and multi-line chains).
# `grep -P` for multiline lookaround — but BSD grep on macOS lacks
# -P, so fall back to a two-pass: find files containing as_u64(),
# then ripgrep with -A 3 for the cast.
TARGET_DIRS=(
    "talos-api"
    "talos-mcp-handlers"
    "talos-workflow-engine"
    "talos-yaml-workflows"
    "talos-engine"
    "worker"
    "controller"
    "talos-webhooks"
    "talos-oauth"
    "talos-atlassian"
    "talos-gmail"
    "talos-google-calendar"
    "talos-slack"
)

# rg is available on the developer workstation per Makefile; fall
# back to grep -rn if not. The compound rg expression catches:
#   .as_u64().unwrap_or(N) as u32
#   .as_u64()...).map(|v| v as u32)
#   .and_then(|x| x.as_u64()).unwrap_or(...) as u32
# but excludes:
#   u32::try_from(v).unwrap_or(u32::MAX)  ← the canonical safe shape
#   u8/u16/u32::MAX                       ← const refs
RG_BIN=""
if command -v rg >/dev/null 2>&1; then
    RG_BIN="rg"
fi

for dir in "${TARGET_DIRS[@]}"; do
    [ -d "$dir" ] || continue
    # Match the specific dangerous shape: `as u8/u16/u32` OR `as i8/i16/i32`
    # on the SAME line as a method-chain ending the cast. The earlier
    # permissive pattern over-flagged safely-clamped chains; tightening
    # to the *terminal* line catches the bug shape and lets `.min(N)
    # as u32` / `.clamp(...) as u32` pass cleanly.
    #
    # 2026-05-28 re-audit Perf#3: widened to also catch `as i32` (e.g.,
    # `elapsed().as_millis() as i32` wraps after 24.8 days).
    if [ -n "$RG_BIN" ]; then
        matches=$("$RG_BIN" -n --no-heading \
            -g '*.rs' \
            -g '!**/tests/**' \
            -g '!**/*_tests.rs' \
            'as (u|i)(8|16|32)\b' \
            "$dir" 2>/dev/null || true)
    else
        matches=$(grep -rn --include='*.rs' \
            -E 'as (u|i)(8|16|32)\b' \
            "$dir" 2>/dev/null || true)
    fi
    if [ -z "$matches" ]; then
        continue
    fi
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue

        # Pre-filters on the matched line itself:
        # 1. Skip comments / docstrings (the cast appears in prose).
        case "$body" in
            *'//'*"as u"*) [[ "$body" =~ ^[[:space:]]*// ]] && continue ;;
        esac
        if [[ "$body" =~ ^[[:space:]]*// ]] || [[ "$body" =~ ^[[:space:]]*/\*\* ]] || [[ "$body" =~ ^[[:space:]]*\* ]]; then
            continue
        fi
        # 2. Skip the canonical safe shape and known-safe siblings.
        if echo "$body" | grep -qE 'try_from|saturating_|::MAX\b|::MIN\b'; then
            continue
        fi
        # 3. Skip lines where the cast is from a u8 literal / typed
        #    constant (e.g. `255 as u32`, `MAX_X as u32`) — these are
        #    widening (smaller→larger) which is always safe.
        if echo "$body" | grep -qE '\b[0-9]+\s+as (u|i)(16|32|64)\b'; then
            continue
        fi

        # Look 3 lines above for opt-out + upper-bound clamp markers.
        # Guard against malformed match lines (e.g., multi-line rg
        # output) producing non-numeric `$lineno` — without the regex
        # check bash emits "integer expression expected" warnings.
        if [[ "$lineno" =~ ^[0-9]+$ ]] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 3 ? lineno - 3 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            # Explicit opt-out marker.
            if echo "$ctx" | grep -q "// allow-as-u32-cast:"; then
                continue
            fi
            # Upper-bound clamps in the chain make the cast safe:
            #   .min(N) — caps to N (must be < target type MAX)
            #   .clamp(L, H) — both bounds
            #   contains(&n) — range-contains guard upstream
            #   u32::from / i32::from — already-narrow source widening
            # Limit the cast-justification scan to a couple lines above
            # so distant `.min()` calls in unrelated code don't grant
            # false safety.
            if echo "$ctx" | grep -qE '\.min\(|\.clamp\(|\.contains\(&|u32::from\(|i32::from\(|u16::from\(|u8::from\('; then
                continue
            fi
        fi

        # Only flag if there's actually an upstream `.as_u64()` /
        # `.as_i64()` / `.as_f64()` / `.num_milliseconds()` / similar
        # *unbounded* numeric source within the prior few lines —
        # those are the call sites where wrap is actually possible.
        # Without this filter, every `n as u32` literal-conversion in
        # the codebase trips the lint.
        # 2026-05-28 re-audit Perf#10: widen the trigger source list.
        # Pre-fix only `.as_u64()` / `.as_i64()` / `.num_milliseconds()` /
        # `.as_secs()` were recognised. Missing siblings let real wrap
        # sites slip past (e.g., `talos-webhooks/src/lib.rs:1282,1310`
        # used `elapsed().as_millis() as i32`). Widen to cover every
        # unbounded numeric source that can produce a value > target
        # type MAX. Also widen the context window to 6 lines for
        # multi-line builder-style chains.
        unbounded_src=""
        # Pattern: any of the unbounded sources that can return a value
        # wider than the target integer cast. Includes:
        #   .as_u64() / .as_i64() / .as_f64()         — serde_json
        #   .num_milliseconds() / .num_seconds() /
        #   .num_minutes() / .num_hours() / .num_days() — chrono::Duration
        #   .as_secs() / .as_millis() / .as_micros() /
        #   .as_nanos()                                — std::time::Duration
        #   .parse::<u64>() / .parse::<i64>() / .parse() — strings
        #   u64::from_le_bytes / from_be_bytes / from_ne_bytes — buffers
        #   chrono::Duration::seconds / ::milliseconds   — int → Duration
        UNBOUNDED_SRC_RE='\.as_u64\(|\.as_i64\(|\.as_f64\(|\.num_milliseconds\(|\.num_seconds\(|\.num_minutes\(|\.num_hours\(|\.num_days\(|\.as_secs\(|\.as_millis\(|\.as_micros\(|\.as_nanos\(|\.parse::<(u|i)(16|32|64|128|size)>\(|from_(le|be|ne)_bytes\(|chrono::Duration::(seconds|milliseconds|microseconds|nanoseconds)\('
        if [[ "$lineno" =~ ^[0-9]+$ ]] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 6 ? lineno - 6 : 1))
            ctx2=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx2" | grep -qE "$UNBOUNDED_SRC_RE"; then
                unbounded_src="yes"
            fi
        fi
        # Also check the matched line itself.
        if echo "$body" | grep -qE "$UNBOUNDED_SRC_RE"; then
            unbounded_src="yes"
        fi
        if [ -z "$unbounded_src" ]; then
            continue
        fi

        printf '  %s\n' "$line"
        CAST_VIOLATIONS=$((CAST_VIOLATIONS + 1))
    done <<< "$matches"
done

# Pattern 2: `.map(|x| x as i32)` on engine-event field types.
# Specifically scoped to talos-api workflow event-persistence sites;
# this shape elsewhere is usually fine (typed-source converter).
# Recent fix landed a helper `saturating_u32_to_i32` for the canonical
# safe shape.
WRITE_BOUNDARY_FILES=(
    "talos-api/src/schema/workflows/mutations.rs"
)
for f in "${WRITE_BOUNDARY_FILES[@]}"; do
    [ -f "$f" ] || continue
    matches=$(grep -nE '\.map\(\|[a-z_]+\| [a-z_]+ as i32\)' "$f" 2>/dev/null || true)
    if [ -z "$matches" ]; then
        continue
    fi
    while IFS= read -r line; do
        lineno=$(echo "$line" | cut -d: -f1)
        body=$(echo "$line" | cut -d: -f2-)
        # Skip comments / docstrings — the cast appears in prose
        # (the regression-class test docstrings reference the bug
        # shape verbatim, which trips Pattern 2 without this guard).
        if [[ "$body" =~ ^[[:space:]]*// ]] || [[ "$body" =~ ^[[:space:]]*/\*\* ]] || [[ "$body" =~ ^[[:space:]]*\* ]]; then
            continue
        fi
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$f" 2>/dev/null || true)
            if echo "$ctx" | grep -q "// allow-as-u32-cast:"; then
                continue
            fi
        fi
        printf '  %s:%s\n' "$f" "$line"
        CAST_VIOLATIONS=$((CAST_VIOLATIONS + 1))
    done <<< "$matches"
done

if [ "$CAST_VIOLATIONS" -gt 0 ]; then
    red "✗ $CAST_VIOLATIONS integer-cast violation(s) found"
    yellow "  → use saturating conversion at trust boundaries:"
    yellow "    • u64→u32: u32::try_from(v).unwrap_or(u32::MAX)"
    yellow "    • u32→i32: i32::try_from(v).unwrap_or(i32::MAX)"
    yellow "    • i32→u32: v.max(0) as u32  (read boundary only)"
    yellow "    Opt out with: // allow-as-u32-cast: <reason>"
    yellow "    See MCP-960..962, MCP-1007/1008 for the audit class."
    EXIT_CODE=1
else
    green "✓ integer-cast discipline (MCP-960..962 / MCP-1007/1008) holds"
fi
echo

# ── 22. GraphQL per-domain query/mutation scope-parity ─────────────────
bold "▶ check 22: GraphQL queries with sibling mutations must have a scope gate"

# MCP-757 / 2026-05-28 audit established the rule: any read surface
# whose paired write surface (in the same domain dir) calls
# require_scope(...) — usually Admin — also needs a scope gate.
# Otherwise a non-Admin API key can enumerate sensitive recon data
# (linked OAuth accounts, service integrations, resource quotas,
# capability grants...). Three live gaps were found in the 2026-05-28
# sweep: linked_oauth_accounts, service_integrations, resource_quotas.
#
# The lint scans each `talos-api/src/schema/<domain>/` dir for:
#   * mutations.rs files containing `require_scope(...)` calls
#   * queries.rs files in the same dir whose top-level `async fn`
#     resolvers don't call `require_scope`.
# Flags resolvers that look like they need a gate. Heuristic — not
# perfect; opt out with `// allow-public-query: <reason>` within 4
# lines above the fn signature for legitimate pre-auth surfaces
# (e.g., oauth_login_url, health checks).

PARITY_VIOLATIONS=0

for domain_dir in talos-api/src/schema/*/; do
    [ -d "$domain_dir" ] || continue
    mutations="${domain_dir}mutations.rs"
    queries="${domain_dir}queries.rs"
    [ -f "$mutations" ] || continue
    [ -f "$queries" ] || continue

    # Does mutations.rs use require_scope at all?
    if ! grep -q "require_scope(" "$mutations" 2>/dev/null; then
        continue
    fi

    # Find each async fn resolver in queries.rs. The pattern is
    # `    async fn <name>(...)` at exactly 4-space indent (inside
    # an `#[Object] impl Foo` block). Capture the line number.
    while IFS=: read -r lineno _; do
        # Inspect the next ~60 lines after the fn signature for a
        # require_scope call OR an opt-out marker in the prior 8 lines
        # (wider window than other checks because the opt-out
        # rationale comment frequently runs 4-6 lines above the fn
        # signature when documenting why the public read is safe).
        start_above=$((lineno > 8 ? lineno - 8 : 1))
        ctx_above=$(sed -n "${start_above},${lineno}p" "$queries" 2>/dev/null || true)
        if echo "$ctx_above" | grep -q "// allow-public-query:"; then
            continue
        fi
        # Look 60 lines below for require_scope or require_2fa.
        end=$((lineno + 60))
        body=$(sed -n "${lineno},${end}p" "$queries" 2>/dev/null || true)
        if echo "$body" | grep -q "require_scope("; then
            continue
        fi
        # Pre-auth surface heuristics — exempt resolvers whose name
        # implies they're meant to be reachable without authentication
        # (login URL builders, health checks). Use the matched line
        # itself for the name.
        signature=$(sed -n "${lineno}p" "$queries" 2>/dev/null || true)
        if echo "$signature" | grep -qE 'oauth_login_url|health|liveness|readiness|version_info|server_capabilities'; then
            continue
        fi
        printf '  %s:%s — `%s` has no require_scope but a sibling mutation does\n' \
            "$queries" "$lineno" "$(echo "$signature" | sed 's/^[[:space:]]*//' | head -c 80)"
        PARITY_VIOLATIONS=$((PARITY_VIOLATIONS + 1))
    done < <(grep -nE '^    async fn ' "$queries" 2>/dev/null || true)
done

if [ "$PARITY_VIOLATIONS" -gt 0 ]; then
    red "✗ $PARITY_VIOLATIONS GraphQL query/mutation scope-parity violation(s)"
    yellow '  → add crate::schema::require_scope(ctx, ApiKeyScope::Admin)? (or appropriate scope)'
    yellow '    at the top of the resolver. Session-authenticated callers pass through unchanged.'
    yellow "  → legitimate pre-auth queries opt out with: // allow-public-query: <reason>"
    yellow "  → See MCP-757 + 2026-05-28 audit (linked_oauth_accounts / service_integrations /"
    yellow "    resource_quotas / capability_grants)."
    EXIT_CODE=1
else
    green "✓ GraphQL query/mutation scope-parity holds (MCP-757 sweep)"
fi
echo

# ── 23. AEAD AAD-binding discipline on SecretsManager::encrypt_value ──
bold "▶ check 23: encrypt_value() without AAD outside the secrets table"

# MCP-S2 (2026-05-28): every persistence boundary that stores AES-GCM
# ciphertext via SecretsManager MUST use the AAD-bound variant
# (`encrypt_value_with_aad` / `encrypt_value_aad_v1`) so an attacker
# with DB write capability can't swap ciphertexts between rows that
# share an `encryption_key_id`. The full migration landed for TOTP,
# webhook signing secret, workflow_executions.output, module_executions
# payloads, and actor_memory. Future writers must follow the same
# pattern.
#
# This check flags any call to `secrets_manager.encrypt_value(...)` /
# `sm.encrypt_value(...)` outside:
#   * The SecretsManager impl itself (talos-secrets-manager/)
#   * The `secrets` table writers (talos-api/src/schema/secrets/)
#     — they're already AAD-bound via the v0/v1 dispatcher
#   * Test files
#   * The audit_settings encrypt path (intentionally NOT migrated —
#     see MCP-S2 follow-up note in security/mutations.rs)
# Opt out elsewhere with `// allow-encrypt-value-no-aad: <reason>`
# within 4 lines above.

ENCRYPT_VIOLATIONS=0

# Use rg if available, fallback to grep.
if [ -n "$RG_BIN" ]; then
    matches=$("$RG_BIN" -n --no-heading \
        -g '*.rs' \
        -g '!talos-secrets-manager/**' \
        -g '!talos-api/src/schema/secrets/**' \
        -g '!**/tests/**' \
        -g '!**/*_tests.rs' \
        -e '\.encrypt_value\(' \
        . 2>/dev/null || true)
else
    matches=$(grep -rn --include='*.rs' \
        --exclude-dir=tests \
        --exclude='*_tests.rs' \
        -E '\.encrypt_value\(' \
        --include='*.rs' \
        talos-* worker controller 2>/dev/null \
        | grep -v 'talos-secrets-manager/' \
        | grep -v 'talos-api/src/schema/secrets/' || true)
fi

if [ -n "$matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue

        # Skip helper definitions / docstring references / commented-out lines.
        if echo "$body" | grep -qE 'pub (async )?fn encrypt_value|// |/\*|encrypt_value_with_aad|encrypt_value_aad_v1|encrypt_value_by_key'; then
            continue
        fi
        # Skip the audit-ledger / audit-settings deferral site (see
        # MCP-S2 follow-up note in security/mutations.rs).
        if echo "$file" | grep -q 'security/mutations.rs'; then
            continue
        fi

        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q '// allow-encrypt-value-no-aad:'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        ENCRYPT_VIOLATIONS=$((ENCRYPT_VIOLATIONS + 1))
    done <<< "$matches"
fi

if [ "$ENCRYPT_VIOLATIONS" -gt 0 ]; then
    red "✗ $ENCRYPT_VIOLATIONS encrypt_value() call(s) without AAD found"
    yellow "  → use SecretsManager::encrypt_value_aad_v1(value, row_id.as_bytes()) and persist"
    yellow "    the returned format_version to a per-row column. Reads dispatch via"
    yellow "    SecretsManager::decrypt_versioned."
    yellow "  → Opt out (legacy/migration-only) with: // allow-encrypt-value-no-aad: <reason>"
    yellow "  → See MCP-S2 (2026-05-28) for the full migration pattern."
    EXIT_CODE=1
else
    green "✓ AEAD AAD-binding discipline holds (MCP-S2 sweep)"
fi
echo

# ── Summary ──────────────────────────────────────────────────────────
if [ "$EXIT_CODE" -eq 0 ]; then
    green "✓ structural lints passed"
else
    red "✗ structural lints failed"
fi
exit "$EXIT_CODE"
