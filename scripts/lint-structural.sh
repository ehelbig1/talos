#!/usr/bin/env bash
# Structural lints — catch the failure classes that survive `cargo check`
# and only manifest in production.
#
# Two checks, each one tied to a real prod incident:
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

# ── Summary ──────────────────────────────────────────────────────────
if [ "$EXIT_CODE" -eq 0 ]; then
    green "✓ structural lints passed"
else
    red "✗ structural lints failed"
fi
exit "$EXIT_CODE"
