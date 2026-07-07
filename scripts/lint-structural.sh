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

# Machine-readable check count, derived from the runtime `▶ check N:`
# markers so it can't drift from the checks themselves. Used by the
# self-consistency meta-check (the last check) and by docs tooling:
#   bash scripts/lint-structural.sh --count   → prints N, exits 0
CHECK_COUNT="$(grep -cE '^bold "▶ check [0-9]+:' "${BASH_SOURCE[0]}")"
if [[ "${1:-}" == "--count" ]]; then
    echo "$CHECK_COUNT"
    exit 0
fi

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

# Default scan scope: the credential-bearing crates that must route through
# talos_memory::*. Deliberately EXCLUDES talos-memory/src, the canonical writer.
DEFAULT_DIRS="controller/src talos-secrets/src talos-dlp/src worker/src"

VIOLATIONS=0
check_pattern() {
    local pattern="$1"
    local dirs="${2:-$DEFAULT_DIRS}"
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
                $dirs 2>/dev/null \
            || true)
}
for p in "${WRITE_PATTERNS[@]}";      do check_pattern "$p"; done
for p in "${PROJECTION_PATTERNS[@]}"; do check_pattern "$p"; done
# The legacy-`value`-column projection check ALSO scans talos-memory/src —
# the canonical writer is exempt from the WRITE check but NOT from selecting a
# DROPPED column. recall_recent_by_types / recall_recent_excluding_types both
# carried `SELECT … value, value_enc …` here and broke at runtime with
# `column "value" does not exist` after Phase B dropped the column; the scan
# excluding talos-memory/ is exactly why it survived. (Found by activating the
# live-Postgres memory integration suite.)
for p in "${PROJECTION_PATTERNS[@]}"; do check_pattern "$p" "talos-memory/src"; done

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
bold "▶ check 23: encrypt_value()/decrypt_value_by_key() without AAD outside the secrets table"

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

# ── Decrypt side: the no-AAD reader must not be used on AAD-bound rows ──
# (2026-05-30) The bare `decrypt_value_by_key(kid, bytes)` is the v0/empty-AAD
# path. Calling it to read a column the writer AAD-bound via
# `encrypt_value_aad_v1` (workflow_executions.output_data_enc,
# module_executions.*_enc) AES-GCM-tag-fails on every v1 row — a SILENT
# correctness regression on encrypted deploys (replay loses history, analytics
# goes output-blind, crash-recovery drops its resume seed). Four readers drifted
# this way and were swept; the canonical readers all dispatch on the per-row
# format column via `decrypt_versioned(kid, bytes, row_id.as_bytes(), fmt)`
# (or `talos_module_payload_encryption::decrypt_payload_slot`).
#
# Allowed bare callers: the SecretsManager impl + its v0 dispatch arm
# (talos-secrets-manager/), the verification example (controller/examples/),
# and genuinely-v0 data with `// allow-decrypt-no-aad: <reason>` within 4 lines.

if [ -n "$RG_BIN" ]; then
    dec_matches=$("$RG_BIN" -n --no-heading \
        -g '*.rs' \
        -g '!talos-secrets-manager/**' \
        -g '!**/examples/**' \
        -g '!**/tests/**' \
        -g '!**/*_tests.rs' \
        -e '\.decrypt_value_by_key\(' \
        . 2>/dev/null || true)
else
    dec_matches=$(grep -rn --include='*.rs' \
        --exclude-dir=tests --exclude-dir=examples \
        --exclude='*_tests.rs' \
        -E '\.decrypt_value_by_key\(' \
        talos-* worker controller 2>/dev/null \
        | grep -v 'talos-secrets-manager/' || true)
fi

if [ -n "$dec_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue

        # Skip the _with_aad variant, helper defs, docstring/comment refs.
        if echo "$body" | grep -qE 'decrypt_value_by_key_with_aad|pub (async )?fn decrypt_value_by_key|^\s*//|//!|/\*'; then
            continue
        fi

        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q '// allow-decrypt-no-aad:'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        ENCRYPT_VIOLATIONS=$((ENCRYPT_VIOLATIONS + 1))
    done <<< "$dec_matches"
fi

if [ "$ENCRYPT_VIOLATIONS" -gt 0 ]; then
    red "✗ $ENCRYPT_VIOLATIONS encrypt_value()/decrypt_value_by_key() call(s) without AAD found"
    yellow "  → encrypt: SecretsManager::encrypt_value_aad_v1(value, row_id.as_bytes()); persist"
    yellow "    the returned format_version to a per-row column."
    yellow "  → decrypt: SecretsManager::decrypt_versioned(kid, bytes, row_id.as_bytes(), fmt)"
    yellow "    (or talos_module_payload_encryption::decrypt_payload_slot); SELECT id + format."
    yellow "  → Opt out (legacy/v0-only) with: // allow-encrypt-value-no-aad: <reason>"
    yellow "    or // allow-decrypt-no-aad: <reason>"
    yellow "  → See MCP-S2 (2026-05-28) + the 2026-05-30 reader sweep."
    EXIT_CODE=1
else
    green "✓ AEAD AAD-binding discipline holds (MCP-S2 sweep + reader sweep)"
fi
echo

# ── 24. Cross-protocol field-validation predicate must use talos-validation ──
bold "▶ check 24: inline control-char predicate in a write surface"

# 2026-05-28: the recurring GraphQL↔MCP validation-drift bug class
# (MCP-963/964/1003/1151) came from per-field validators being copied
# between the two write surfaces instead of shared. The canonical
# predicate + messages now live in `talos-validation`; both surfaces
# wrap it. This check freezes that: any inline re-derivation of the
# control-char/null-byte predicate
#   `c.is_control() && c != '\t'`  (with or without `&& c != '\n' …`)
# inside the two cross-protocol write surfaces (talos-api,
# talos-mcp-handlers) is a regression — route it through
# `talos_validation::reject_control_chars(field, value, LineMode::…)`
# (or the higher-level `validate_display_name` / `validate_resource_name`
# / `validate_multiline_description`) instead.
#
# Scope is deliberately the two protocol surfaces where the regressions
# occurred. Leaf crates (talos-memory key rules, talos-oauth token
# sanitisation, talos-auth user-name policy) keep their own narrow
# validators — they are not part of the cross-protocol-parity contract.
# Opt out with `// allow-validation-predicate: <reason>` within 4 lines
# above (e.g. a genuinely surface-specific rule the shared helper can't
# express).

VALIDATION_PREDICATE_VIOLATIONS=0

if [ -n "$RG_BIN" ]; then
    matches=$("$RG_BIN" -n --no-heading \
        -g '*.rs' \
        -g '!**/tests/**' \
        -g '!**/*_tests.rs' \
        -e "is_control\(\) && c != '\\\\t'" \
        talos-api talos-mcp-handlers 2>/dev/null || true)
else
    matches=$(grep -rn --include='*.rs' \
        --exclude-dir=tests \
        --exclude='*_tests.rs' \
        -E "is_control\(\) && c != '\\\\t'" \
        talos-api talos-mcp-handlers 2>/dev/null || true)
fi

if [ -n "$matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        [ -f "$file" ] || continue

        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q '// allow-validation-predicate:'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        VALIDATION_PREDICATE_VIOLATIONS=$((VALIDATION_PREDICATE_VIOLATIONS + 1))
    done <<< "$matches"
fi

if [ "$VALIDATION_PREDICATE_VIOLATIONS" -gt 0 ]; then
    red "✗ $VALIDATION_PREDICATE_VIOLATIONS inline control-char predicate(s) in a write surface"
    yellow "  → route through talos_validation::reject_control_chars(field, value, LineMode::SingleLine|MultiLine)"
    yellow "    or the higher-level validate_display_name / validate_resource_name / validate_multiline_description."
    yellow "  → Opt out (surface-specific rule) with: // allow-validation-predicate: <reason>"
    EXIT_CODE=1
else
    green "✓ cross-protocol field validators route through talos-validation"
fi
echo

# ── 25. No bare-pool reads/writes on RLS tables in talos-api resolvers ─
bold "▶ check 25: bare-pool queries on RLS tables in talos-api/src/schema"

# RFC 0004/0005 S2/S3: the org-isolation RLS policies only ENFORCE for a
# query that runs inside a tenant-scoped transaction (begin_tenant_read_scoped
# / begin_org_scoped / begin_user_scoped / UnitOfWork) — that is what issues
# the per-tx `SET LOCAL ROLE talos_app` + the app.current_user_id/org_ids
# GUCs. A resolver that runs a query on the bare pool (`.fetch_*(db_pool)` /
# `.execute(db_pool)`) NEVER sets the role, so even with TALOS_RLS_SET_ROLE
# on it runs as the base role and the RLS policy is a NO-OP for that read /
# write — a silent backstop gap that survives the enforcement flip.
#
# This check flags any bare-pool executor in talos-api/src/schema whose
# enclosing `sqlx::query*` block references one of the RLS-enabled tables
# (workflows, workflow_executions, actors, secrets, scratch_sessions,
# user_module_pins) — including via JOIN, the dominant ownership-gate
# shape. The ~22-PR S2/S3 conversion reduced this to ZERO; the lint freezes
# it so new code can't silently regress.
#
# Executor-match widening (2026-06-23): the original executor pattern only
# matched the by-value `(db_pool|pool|&self.db_pool)` forms and was BLIND to
# the `&`-borrowed shapes — `.execute(&db_pool)` / `.fetch_one(&pool)` /
# `.fetch_all(& self.db_pool)` — which are the dominant
# `sqlx::query(...).execute(&db_pool)` idiom and run on the bare pool just
# the same (RLS is an equal no-op). The grep pattern below makes the leading
# `&`/whitespace optional and folds `self.` into an optional prefix so
# `&db_pool`, `&pool`, and the `& self.db_pool` spacing variant are all
# caught, while `conn_pool` / `pool_handle` / `&mut *tx` stay out (the `(`
# must be immediately followed by `&?[[:space:]]*(self\.)?` then exactly
# `db_pool` or `pool`).
#
# Opt out — for a query that MUST run unscoped (a genuine cross-tenant
# platform-admin op, or an internal cross-cutting reader whose
# authorization is established upstream) — with `// allow-bare-pool-rls:
# <reason>` anywhere in the query block.

RLS_TABLE_RE='workflows|workflow_executions|actors|secrets|scratch_sessions|user_module_pins'
BARE_POOL_RLS_VIOLATIONS=0

if [ -d talos-api/src/schema ]; then
    while IFS=: read -r file lineno _; do
        [ -f "$file" ] || continue
        start=$((lineno > 40 ? lineno - 40 : 1))
        # Take the text from the LAST `sqlx::query` opening up to the
        # executor line — i.e. the actual enclosing query block.
        qblock=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null \
            | awk '/sqlx::query/{buf=""} {buf=buf"\n"$0} END{print buf}')
        echo "$qblock" | grep -q "sqlx::query" || continue
        echo "$qblock" | grep -qiE \
            "(FROM|JOIN|INTO|UPDATE)[[:space:]]+(${RLS_TABLE_RE})([^a-zA-Z0-9_]|$)" || continue
        echo "$qblock" | grep -q "// allow-bare-pool-rls:" && continue
        tbl=$(echo "$qblock" | grep -oiE \
            "(FROM|JOIN|INTO|UPDATE)[[:space:]]+(${RLS_TABLE_RE})" | head -1)
        printf '  %s:%s — bare-pool executor on an RLS-table query [%s]\n' \
            "$file" "$lineno" "$tbl"
        BARE_POOL_RLS_VIOLATIONS=$((BARE_POOL_RLS_VIOLATIONS + 1))
        # Executor-match pattern (2026-06-23): an `&`/whitespace-prefixed
        # borrow of the pool — `.execute(&db_pool)`, `.fetch_one(&pool)`,
        # `.fetch_all(& self.db_pool)` — runs on the bare pool just like the
        # by-value `db_pool` form, so RLS is an equal no-op for it. The
        # original pattern only matched `(db_pool|pool|&self.db_pool)` and was
        # blind to the `&db_pool` / `&pool` borrow shapes that dominate the
        # `sqlx::query(...).execute(&db_pool)` idiom. The leading
        # `&?[[:space:]]*` makes the borrow optional and tolerates the
        # `& self.db_pool` spacing variant. `db_pool` is matched with a
        # word-boundary-ish prefix so `&self.db_pool` collapses into the same
        # alternative (the `self\.` is optional) without also matching unrelated
        # identifiers like `conn_pool`.
    done < <(grep -rnE '\.(fetch_optional|fetch_one|fetch_all|execute)\(&?[[:space:]]*(self\.)?(db_pool|pool)\)' \
        talos-api/src/schema 2>/dev/null || true)
fi

if [ "$BARE_POOL_RLS_VIOLATIONS" -gt 0 ]; then
    red "✗ $BARE_POOL_RLS_VIOLATIONS bare-pool quer(ies) on RLS tables in talos-api resolvers"
    yellow '  → run the query on a tenant-scoped tx so RLS enforces under talos_app:'
    yellow '      let mut tx = talos_db::begin_user_scoped(db_pool, user_id).await?;     // personal'
    yellow '      let mut tx = talos_db::begin_tenant_read_scoped(db_pool, &scope).await?; // org-shared'
    yellow '      let mut uow = talos_db::UnitOfWork::begin(db_pool, &scope).await?;       // multi-call'
    yellow '    then .fetch_*/.execute(&mut *tx) (or uow.conn()) and tx.commit()/uow.commit().'
    yellow '  → genuine cross-tenant / upstream-authorized reads opt out with:'
    yellow '      // allow-bare-pool-rls: <reason>'
    yellow '  → See RFC 0005 (SET-ROLE enforcement) + the S2/S3 conversion PRs.'
    EXIT_CODE=1
else
    green "✓ no bare-pool reads/writes on RLS tables in talos-api resolvers"
fi
echo

# ── 26. In-flight execution-status set must include 'resuming' ──
bold "▶ check 26: in-flight status literal must include 'resuming'"

# (2026-05-31) The durable-execution crash-recovery feature (#51/#52) added a
# transient `resuming` status to workflow_executions — an execution claimed for
# restart-resume, semantically in-flight (it occupies an about-to-run slot).
# Every concurrency-cap count, active-execution gate (workflow delete/disable),
# cancel path, and stale-execution diagnostic that enumerates the in-flight set
# `('running', 'queued', 'pending')` MUST also include `'resuming'` — otherwise a
# resuming execution is silently uncounted: concurrency caps can be exceeded
# during recovery, and a workflow could be deleted out from under a mid-resume
# execution.
#
# There is no shared Rust constant for this set (the owning crates —
# execution-repository, workflow-repository, talos-api, analytics-repository —
# don't share a common dep), so this lint IS the single source of truth: any
# `status IN ('running', 'queued', 'pending'` literal that omits `'resuming'`
# is flagged. Opt out (a genuinely pre-resuming-semantics set) with
# `// allow-inflight-no-resuming: <reason>` within 4 lines above.

INFLIGHT_VIOLATIONS=0
if [ -n "$RG_BIN" ]; then
    inflight_matches=$("$RG_BIN" -n --no-heading \
        -g '*.rs' -g '!**/tests/**' -g '!**/*_tests.rs' \
        -e "'running', 'queued', 'pending'" \
        . 2>/dev/null || true)
else
    inflight_matches=$(grep -rn --include='*.rs' --exclude-dir=tests --exclude='*_tests.rs' \
        -F "'running', 'queued', 'pending'" \
        talos-* worker controller 2>/dev/null || true)
fi

if [ -n "$inflight_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue
        # Already includes 'resuming' on the same line → compliant.
        if echo "$body" | grep -q "'resuming'"; then
            continue
        fi
        # Opt-out marker within 4 lines above.
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q '// allow-inflight-no-resuming:'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        INFLIGHT_VIOLATIONS=$((INFLIGHT_VIOLATIONS + 1))
    done <<< "$inflight_matches"
fi

if [ "$INFLIGHT_VIOLATIONS" -gt 0 ]; then
    red "✗ $INFLIGHT_VIOLATIONS in-flight status literal(s) missing 'resuming'"
    yellow "  → add 'resuming' to the IN (...) set: status IN ('running', 'queued', 'pending', 'resuming')"
    yellow "  → a resuming execution is in-flight; omitting it under-counts concurrency caps and"
    yellow "    lets a workflow be deleted mid-resume. See crash recovery (#51/#52)."
    yellow "  → Opt out (pre-resuming-semantics set) with: // allow-inflight-no-resuming: <reason>"
    EXIT_CODE=1
else
    green "✓ in-flight status literals include 'resuming' (crash-recovery #51/#52)"
fi
echo

# ── 27. make_interval() integer args must be cast ::int ──
bold "▶ check 27: make_interval(<int arg> => \$N) must cast \$N::int"

# (2026-05-31) PostgreSQL's make_interval() types years/months/weeks/days/hours/
# mins as `int` (int4) and ONLY secs as `double precision`. sqlx sends a bound
# parameter with the OID derived from the Rust type — so binding an i64 (int8)
# or f64 (float8) to `make_interval(hours => $N)` resolves to a non-existent
# overload and FAILS AT REQUEST TIME on pg16/pg17:
#   ERROR: function make_interval(hours => bigint) does not exist
# This compiles clean and only trips when the query runs — exactly the class
# `cargo check` can't catch. Observed real bugs: retry-intelligence +
# cost-attribution bound `hours as f64`, list_secret_access_log took `hours: f64`,
# and the crash-recovery claim bound `mins: i64` (#51).
#
# Fix: cast the parameter in SQL — `make_interval(hours => $N::int)` — which
# coerces any numeric bind (i32/i64/f64) to int4. The `secs =>` arg is exempt
# (it's double precision and accepts int/float natively). Opt out (a genuine
# secs-style double arg, or a non-parameterized literal) with
# `// allow-make-interval-no-cast: <reason>` within 4 lines above.

MKINT_VIOLATIONS=0
if [ -n "$RG_BIN" ]; then
    mkint_matches=$("$RG_BIN" -n --no-heading \
        -g '*.rs' -g '!**/tests/**' -g '!**/*_tests.rs' \
        -e 'make_interval\((mins|hours|days|weeks|months|years) => \$[0-9]+\)' \
        . 2>/dev/null || true)
else
    mkint_matches=$(grep -rnE --include='*.rs' \
        'make_interval\((mins|hours|days|weeks|months|years) => \$[0-9]+\)' \
        talos-* worker controller 2>/dev/null | grep -v '/tests/' || true)
fi

if [ -n "$mkint_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue
        # Already has ::int (the regex above excludes it, but guard comments).
        if echo "$body" | grep -qE '::int\)|^\s*//|//!'; then
            continue
        fi
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q '// allow-make-interval-no-cast:'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        MKINT_VIOLATIONS=$((MKINT_VIOLATIONS + 1))
    done <<< "$mkint_matches"
fi

if [ "$MKINT_VIOLATIONS" -gt 0 ]; then
    red "✗ $MKINT_VIOLATIONS make_interval(<int arg>) without ::int cast"
    yellow "  → cast the param: make_interval(hours => \$N::int) — int8/float8 binds fail at runtime"
    yellow "    (function make_interval(hours => bigint) does not exist) on pg16/pg17."
    yellow "  → 'secs =>' is exempt (double precision). Opt out: // allow-make-interval-no-cast: <reason>"
    EXIT_CODE=1
else
    green "✓ make_interval integer args are ::int-cast (pg int4 overload safety)"
fi
echo

# ── 28. OFFSET pagination must ORDER BY a unique tiebreaker ──
bold "▶ check 28: OFFSET pagination needs a unique ORDER BY tiebreaker"

# (2026-05-31) `... ORDER BY <non-unique col> LIMIT $n OFFSET $m` silently
# SKIPS or DUPLICATES rows at page boundaries: when the sort key has ties
# (created_at / started_at / updated_at / name / timestamp all do), Postgres
# may order the tied rows differently between the page-N and page-N+1 queries,
# so a row at the boundary is seen twice or not at all. The fix is to append a
# unique tiebreaker (the PK `id`) so the sort is a TOTAL order:
#   ORDER BY created_at DESC, id DESC
# A sort whose trailing column is already unique within the query's scope
# (e.g. `version_number` under a single workflow_id) is fine.
#
# This check flags any `OFFSET $n` whose nearest preceding ORDER BY (within 4
# lines) lacks a standalone `id` / `version_number` token. Opt out (caller-owned
# ORDER BY, provably-unique sort) with `// allow-offset-no-tiebreaker: <reason>`.

OFFSET_VIOLATIONS=0
# id / .id / , id / version_number as a standalone token (not workflow_id, valid, uuid).
TIEBREAKER_RE='(^|[^a-z_])id([^a-z_]|$)|version_number'

offset_files=$(grep -rlE "OFFSET \\\$[0-9]" --include='*.rs' talos-* controller worker 2>/dev/null \
    | grep -vE '/tests/|_tests\.rs' || true)

for file in $offset_files; do
    [ -f "$file" ] || continue
    # Each line number that contains an OFFSET bind.
    for lineno in $(grep -nE "OFFSET \\\$[0-9]" "$file" | cut -d: -f1); do
        start=$((lineno > 4 ? lineno - 4 : 1))
        window=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
        # Opt-out marker anywhere in the window.
        if echo "$window" | grep -q '// allow-offset-no-tiebreaker:'; then
            continue
        fi
        # The ORDER BY → OFFSET slice. If there's no ORDER BY in the window the
        # sort is unspecified (flag); if there is, it must carry a tiebreaker.
        order_slice=$(echo "$window" | sed -n '/[Oo][Rr][Dd][Ee][Rr] [Bb][Yy]/,$p')
        if [ -z "$order_slice" ]; then
            # No ORDER BY near the OFFSET — non-deterministic pagination.
            printf '  %s:%s  (OFFSET with no ORDER BY in scope)\n' "$file" "$lineno"
            OFFSET_VIOLATIONS=$((OFFSET_VIOLATIONS + 1))
            continue
        fi
        if echo "$order_slice" | grep -qE "$TIEBREAKER_RE"; then
            continue
        fi
        printf '  %s:%s  %s\n' "$file" "$lineno" \
            "$(echo "$order_slice" | grep -iE 'order by' | head -1 | sed 's/^[[:space:]]*//')"
        OFFSET_VIOLATIONS=$((OFFSET_VIOLATIONS + 1))
    done
done

if [ "$OFFSET_VIOLATIONS" -gt 0 ]; then
    red "✗ $OFFSET_VIOLATIONS OFFSET pagination quer(ies) without a unique ORDER BY tiebreaker"
    yellow "  → append the PK to make the sort total: ORDER BY <col> DESC, id DESC"
    yellow "    (qualify when joined: we.id / e.id / l.id). Without it, paging skips/duplicates rows."
    yellow "  → provably-unique sort or caller-owned ORDER BY: // allow-offset-no-tiebreaker: <reason>"
    EXIT_CODE=1
else
    green "✓ OFFSET pagination queries carry a unique ORDER BY tiebreaker"
fi
echo

# ── 29. engine.set_actor_id() only via the canonical actor-application path ──
bold "▶ check 29: no bare engine.set_actor_id() outside the actor-application path"

# Per-actor `max_llm_tier` is the tier-1 data-egress ceiling (tier1 = local
# Ollama only, "data must not leave host").
# `talos_engine::actor_binding::apply_actor_to_engine` (moved there from
# `ActorRepository` in 2026-07 — see check 51 for the layering rule) stamps
# actor_id AND max_llm_tier together and fail-closes to Tier-1 on DB error.
# A bare `engine.set_actor_id(aid)` in a consumer crate sets the actor WITHOUT the
# tier, so the engine keeps the default Tier-2 — a tier-1 actor silently runs as
# tier-2 and its data can leave the host. CLAUDE.md documents this ("never call
# bare engine.set_actor_id; the audit team would catch it") but it was only
# grep-by-hand enforced. This freezes it.
#
# Two legitimate definitions own the setter machinery and are exempt:
#   * talos-workflow-engine/                — defines the engine + the `with_actor_id` builder.
#   * talos-engine/src/actor_binding.rs     — `apply_actor_to_engine` (the canonical stamp).
# Consumers must route through `apply_actor_to_engine`, or the builder's
# `with_actor_id(...)` followed by `for_workflow(...)` (which re-applies the tier).
# Opt out (a new path that stamps the tier itself) with
# `// allow-bare-set-actor-id: <reason>` within 4 lines above.

SET_ACTOR_VIOLATIONS=0
if [ -n "$RG_BIN" ]; then
    sa_matches=$("$RG_BIN" -n --no-heading \
        -g '*.rs' \
        -g '!talos-engine/src/actor_binding.rs' \
        -g '!talos-workflow-engine/**' \
        -g '!**/tests/**' -g '!**/*_tests.rs' \
        -e '\.set_actor_id\(' \
        . 2>/dev/null || true)
else
    sa_matches=$(grep -rnE --include='*.rs' '\.set_actor_id\(' \
        talos-* worker controller 2>/dev/null \
        | grep -vE 'talos-engine/src/actor_binding\.rs|talos-workflow-engine/|/tests/|_tests\.rs' || true)
fi

if [ -n "$sa_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue
        # Skip the definition / doc-comment references / commented lines.
        if echo "$body" | grep -qE 'fn set_actor_id|^\s*//|//!'; then
            continue
        fi
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q '// allow-bare-set-actor-id:'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        SET_ACTOR_VIOLATIONS=$((SET_ACTOR_VIOLATIONS + 1))
    done <<< "$sa_matches"
fi

if [ "$SET_ACTOR_VIOLATIONS" -gt 0 ]; then
    red "✗ $SET_ACTOR_VIOLATIONS bare engine.set_actor_id() call(s) outside the actor-application path"
    yellow "  → use talos_engine::actor_binding::apply_actor_to_engine(&repo, &mut engine, actor_id)"
    yellow "    — it stamps actor_id AND max_llm_tier (fail-closed to Tier-1), or the builder's"
    yellow "    with_actor_id(..) + for_workflow(..). Bare set_actor_id leaves a tier-1 actor at"
    yellow "    the default Tier-2 — a data-egress hole."
    yellow "  → Opt out (path stamps the tier itself): // allow-bare-set-actor-id: <reason>"
    EXIT_CODE=1
else
    green "✓ engine.set_actor_id() confined to the canonical actor-application path"
fi
echo

# ── 30. No CREATE INDEX CONCURRENTLY (or any CONCURRENTLY) in migrations ──
bold "▶ check 30: no CONCURRENTLY in migrations (sqlx runs them in a transaction)"

# sqlx wraps every migration in a single transaction. `CREATE INDEX
# CONCURRENTLY` (and `DROP INDEX CONCURRENTLY`, `REINDEX CONCURRENTLY`, …)
# CANNOT run inside a transaction — Postgres errors with
# "CREATE INDEX CONCURRENTLY cannot run inside a transaction block", which
# aborts the ENTIRE migration run on deploy, not just that statement. The
# production instinct to reach for CONCURRENTLY on a big table is exactly the
# trap. CLAUDE.md: "Use CREATE INDEX (not CONCURRENTLY) in migration files."
# Build the index non-concurrently (it briefly locks writes) or run the
# CONCURRENTLY build out-of-band, outside the migration.
#
# Comment lines (`-- … CONCURRENTLY …`) are exempt. Opt out (a migration the
# operator runs out-of-band, not via sqlx) with
# `-- allow-concurrently: <reason>` within 4 lines above.

CONCURRENTLY_VIOLATIONS=0
mig_matches=$(grep -rniE "CONCURRENTLY" migrations/*.sql 2>/dev/null || true)
if [ -n "$mig_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue
        # Skip SQL line comments (-- …) — they only document the rule.
        if echo "$body" | grep -qE '^\s*--'; then
            continue
        fi
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q -- '-- allow-concurrently:'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        CONCURRENTLY_VIOLATIONS=$((CONCURRENTLY_VIOLATIONS + 1))
    done <<< "$mig_matches"
fi

if [ "$CONCURRENTLY_VIOLATIONS" -gt 0 ]; then
    red "✗ $CONCURRENTLY_VIOLATIONS CONCURRENTLY statement(s) in migrations — these abort the whole migration run"
    yellow "  → drop CONCURRENTLY: CREATE INDEX (not CONCURRENTLY) — sqlx runs migrations in a tx."
    yellow "    Build big indexes out-of-band if the brief write lock is unacceptable."
    yellow "  → Opt out (run out-of-band, not via sqlx): -- allow-concurrently: <reason>"
    EXIT_CODE=1
else
    green "✓ no transaction-incompatible CONCURRENTLY in migrations"
fi
echo

# ── 31. No unbounded outbound HTTP response-body reads ───────────────
bold "▶ check 31: outbound HTTP response bodies must be read through talos-http-body"

# `reqwest::Response::json()` / `::text()` / `::bytes()` buffer the WHOLE
# response with no size limit. A compromised / MITM'd / buggy upstream — or,
# worse, a caller-supplied endpoint (the call_a2a_agent case) — returning a
# multi-GB body OOMs the controller, the credential-holding host. PRs #76–#88
# routed every outbound read through `talos_http_body::read_{body,json,error_text}_capped`
# (Response::chunk() stream-and-cap, 10 MiB / 64 KiB defaults). This freezes
# that: any NEW `.json()/.text()/.bytes().await` (incl. turbofish
# `.json::<T>().await`) on a response is a regression.
#
# Exempt:
#   * talos-http-body/ — the canonical capped impl (uses chunk(), not these).
#   * the worker — its read_llm_response_body_bounded uses bytes_stream() +
#     stream.next(), which does NOT match this pattern, so no exclusion needed.
#   * tests, and full-line comments.
# Opt out (a genuinely bounded internal response) with
# `// allow-unbounded-response: <reason>` within 4 lines above.

UNBOUNDED_READ_VIOLATIONS=0
if [ -n "$RG_BIN" ]; then
    # `-U` (multiline): `\s*` spans a newline, so the split-line form
    # `.json()\n.await` is caught alongside the single-line `.json().await`
    # (this is how several unbounded reads previously evaded the check). The
    # `.await` anchor is REQUIRED — so string-iterator calls like
    # `owner.bytes().all(..)` (no following `.await`) never match. The trailing
    # `grep` keeps only the anchor line (the method call), so a bare `.await`
    # continuation line isn't double-counted and line numbers point at the read.
    ur_matches=$("$RG_BIN" -Un --no-heading \
        -g '*.rs' \
        -g '!talos-http-body/**' \
        -g '!**/tests/**' -g '!**/*_tests.rs' \
        -e '\.(json|text|bytes)\(\)\s*\.await' \
        -e '\.json::<.+>\(\)\s*\.await' \
        . 2>/dev/null | grep -E '\.(json|text|bytes)(::<[^>]*>)?\(\)' || true)
else
    # grep fallback can't do multiline — single-line form only (degraded; CI uses rg).
    ur_matches=$(grep -rnE --include='*.rs' \
        -e '\.(json|text|bytes)\(\)\.await' \
        -e '\.json::<.+>\(\)\.await' \
        talos-* worker controller 2>/dev/null \
        | grep -vE 'talos-http-body/|/tests/|_tests\.rs' || true)
fi

if [ -n "$ur_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue
        # Skip full-line comments / doc comments.
        if echo "$body" | grep -qE '^\s*//|^\s*\*|//!'; then
            continue
        fi
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q '// allow-unbounded-response:'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        UNBOUNDED_READ_VIOLATIONS=$((UNBOUNDED_READ_VIOLATIONS + 1))
    done <<< "$ur_matches"
fi

if [ "$UNBOUNDED_READ_VIOLATIONS" -gt 0 ]; then
    red "✗ $UNBOUNDED_READ_VIOLATIONS unbounded outbound response read(s) — these OOM the controller on a giant body"
    yellow "  → use talos_http_body::read_json_capped(resp) / read_error_text_capped(resp) /"
    yellow "    read_body_capped(resp, max) — Response::chunk() stream-and-cap (no \`stream\` feature needed)."
    yellow "  → Opt out (response is provably bounded): // allow-unbounded-response: <reason>"
    EXIT_CODE=1
else
    green "✓ outbound response bodies read through the bounded talos-http-body path"
fi
echo

# ── 32. Outbound reqwest clients must set an explicit redirect policy ──
bold "▶ check 32: reqwest Client::builder() must set an explicit .redirect() policy"

# Credential-bearing outbound clients that follow redirects can leak the auth
# header / be turned into a secret oracle. reqwest's DEFAULT policy follows up
# to 10 redirects; the convention (paid for four times: MCP-471/496/533/534)
# is `.redirect(reqwest::redirect::Policy::none())` on every client. This
# freezes it: a NEW `Client::builder()` without an explicit `.redirect(...)`
# in its chain is a regression.
#
# Exempt: tests and full-line comments. The worker's per-execution client and
# every controller client already set Policy::none(). The ONE legitimate
# follow-redirects client (talos-registry sync — registries 3xx to blob
# storage, reqwest strips cross-origin auth) carries an explicit opt-out.
# Opt out with `// allow-default-redirect: <reason>` within 12 lines above.

REDIRECT_VIOLATIONS=0
if [ -n "$RG_BIN" ]; then
    rd_matches=$("$RG_BIN" -n --no-heading \
        -g '*.rs' \
        -g '!**/tests/**' -g '!**/*_tests.rs' \
        -e 'Client::builder\(\)' -e 'ClientBuilder::new\(\)' \
        . 2>/dev/null || true)
else
    rd_matches=$(grep -rnE --include='*.rs' \
        -e 'Client::builder\(\)|ClientBuilder::new\(\)' \
        talos-* worker controller 2>/dev/null \
        | grep -vE '/tests/|_tests\.rs' || true)
fi

if [ -n "$rd_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue
        # Skip full-line comments / doc references.
        if echo "$body" | grep -qE '^\s*//|^\s*///|^\s*\*|//!'; then
            continue
        fi
        # Look at the builder chain (this line + next 12) for an explicit redirect.
        chain=$(sed -n "${lineno},$((lineno + 12))p" "$file" 2>/dev/null || true)
        if echo "$chain" | grep -qE '\.redirect\('; then
            continue
        fi
        # Opt-out marker within 12 lines above.
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 12 ? lineno - 12 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q '// allow-default-redirect:'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        REDIRECT_VIOLATIONS=$((REDIRECT_VIOLATIONS + 1))
    done <<< "$rd_matches"
fi

if [ "$REDIRECT_VIOLATIONS" -gt 0 ]; then
    red "✗ $REDIRECT_VIOLATIONS reqwest client(s) with no explicit redirect policy — credential-leak surface"
    yellow "  → add .redirect(reqwest::redirect::Policy::none()) to the builder chain (MCP-471/496/533/534)."
    yellow "  → Opt out (must follow redirects, e.g. OCI blob storage): // allow-default-redirect: <reason>"
    EXIT_CODE=1
else
    green "✓ every outbound reqwest client sets an explicit redirect policy"
fi
echo

# ── 33. No local capability-world → integer rank re-implementations ───
bold "▶ check 33: capability-world ranking must use talos-capability-world, not a local re-impl"

# Capability worlds form a LATTICE, not a linear order — incomparable tier
# siblings (secrets vs governance, llm vs network, database vs agent) are NOT
# mutually ordered. A local `match world { "secrets" | "governance" => 3, … }`
# closure flattens them onto a line, so a `rank(a) > rank(b)` gate lets one
# sibling stand in for the other — a capability-escalation (the platform
# grant_capability_ceiling bug) or a wrong compatibility report. The canonical
# ranking (`world_rank`) and the lattice gate (`ceiling_permits` /
# `is_lattice_world`) live ONLY in talos-capability-world; everyone else must
# call them. This flags a capability-world string literal mapped to an integer
# in a match arm — the smell of a local rank re-implementation.
#
# Exempt: talos-capability-world (the canonical home), tests, comments.
# Opt out (a genuine non-ranking numeric mapping, e.g. a metrics bucket) with
# `// allow-local-world-rank: <reason>` within 4 lines above.

WORLD_RANK_VIOLATIONS=0
WORLD_RANK_RE='"(minimal|http|llm|network|secrets|governance|messaging|filesystem|cache|database|agent|automation|trusted)"( *\| *"[a-z]+")* *=> *-?[0-9]+'
if [ -n "$RG_BIN" ]; then
    wr_matches=$("$RG_BIN" -n --no-heading \
        -g '*.rs' \
        -g '!talos-capability-world/**' \
        -g '!**/tests/**' -g '!**/*_tests.rs' \
        -e "$WORLD_RANK_RE" \
        . 2>/dev/null || true)
else
    wr_matches=$(grep -rnE --include='*.rs' "$WORLD_RANK_RE" \
        talos-* worker controller 2>/dev/null \
        | grep -vE 'talos-capability-world/|/tests/|_tests\.rs' || true)
fi

if [ -n "$wr_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue
        if echo "$body" | grep -qE '^\s*//|^\s*\*|//!'; then
            continue
        fi
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q '// allow-local-world-rank:'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        WORLD_RANK_VIOLATIONS=$((WORLD_RANK_VIOLATIONS + 1))
    done <<< "$wr_matches"
fi

if [ "$WORLD_RANK_VIOLATIONS" -gt 0 ]; then
    red "✗ $WORLD_RANK_VIOLATIONS local capability-world rank re-implementation(s) — lattice-bypass / wrong-report risk"
    yellow "  → use talos_capability_world::ceiling_permits / is_lattice_world / world_rank instead of a local closure."
    yellow "  → Opt out (a real non-ranking numeric mapping): // allow-local-world-rank: <reason>"
    EXIT_CODE=1
else
    green "✓ capability-world ranking confined to talos-capability-world"
fi
echo

# ── 34. actor_memory value_format reads must fail LOUD ───────────────
bold "▶ check 34: actor_memory value_format reads must fail loud (MCP-S2 AAD dispatch)"

# `value_format` is the per-row column that drives v0-vs-v1 AAD dispatch when
# decrypting actor_memory ciphertext. It is NOT NULL in the schema, so the
# only way `try_get("value_format")` yields None/Err is a SELECT-projection
# drift — the caller forgot to project it (exactly the Phase-B `value`-column
# bug class, PR #108). Reading it with `.unwrap_or(0)` / `.ok()` silently
# defaults to format 0 (legacy no-AAD), mis-dispatching EVERY v1 ciphertext to
# empty-AAD decryption → a generic "AES-GCM tag mismatch" that buries the real
# cause. Every read MUST be `.context(...)?` so projection drift trips loudly
# at the first row (the integration suite then catches it). Freezes the MCP-S2
# loud-fail discipline applied to decrypt_row_value / rows_to_memory_hits /
# recall_exact / recall_semantic_filtered.
VF_VIOLATIONS=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    printf '  %s\n' "$line"
    VF_VIOLATIONS=$((VF_VIOLATIONS + 1))
done < <(grep -rnE 'try_get\("value_format"\)[[:space:]]*\.[[:space:]]*(unwrap_or|unwrap|ok)\b' \
            --include='*.rs' --exclude-dir=target \
            talos-memory 2>/dev/null | grep -v '/tests/' || true)

if [ "$VF_VIOLATIONS" -gt 0 ]; then
    red "✗ $VF_VIOLATIONS value_format read(s) that swallow projection drift"
    yellow "  → use .context(\"… must project \\\`value_format\\\` (MCP-S2 AAD dispatch)\")? so drift fails loud"
    EXIT_CODE=1
else
    green "✓ all actor_memory value_format reads fail loud on projection drift"
fi
echo

# ── 35. rustfmt is clean (recurrence-proof for PR #111) ──────────────
bold "▶ check 35: cargo fmt --all -- --check (rustfmt drift)"

# `make lint` runs this gate, but the pre-commit path people actually use is
# THIS script invoked directly — which never ran rustfmt, so drift accumulated
# silently to ~150 files before PR #111 swept it (2026-06-01). Running the
# fmt check HERE means the script people run pre-commit catches drift the
# moment it lands, instead of letting it pile up unseen. Unlike clippy
# (check 7, ~60-90s, env-gated), `cargo fmt --check` is ~1s — cheap enough to
# run by default. There is no rustfmt.toml; this is plain default rustfmt
# under the pinned toolchain (rust-toolchain.toml).
if ! command -v cargo >/dev/null 2>&1; then
    yellow "⊘ fmt check skipped (cargo not on PATH)"
elif cargo fmt --all -- --check >/dev/null 2>&1; then
    green "✓ rustfmt clean (cargo fmt --all -- --check)"
else
    red "✗ rustfmt drift detected"
    yellow "  → run \`cargo fmt --all\` to fix (formatting-only, AST-token-preserving)"
    EXIT_CODE=1
fi
echo

# ── 36. RustSec advisory scan (cargo audit) ──────────────────────────
bold "▶ check 36: cargo audit (RustSec dependency advisories)"

# 2026-06-01: RUSTSEC-2026-0149 (HIGH, CVSS 7.5) — a WASI sandbox-escape in
# wasmtime-wasi 43 reachable from the worker's read-only preopen — sat in the
# tree and was caught only by a manual `cargo audit` run (PR #121). The
# advisory check lives in `make audit` (cargo-deny), but the pre-commit path
# people actually use is THIS script, which never ran it. Running it here means
# a newly-introduced vulnerable dep — or a freshly-published advisory against an
# existing one — surfaces at the gate.
#
# ENV-GATED like clippy (check 7): advisory scans hit the network to refresh
# the RustSec DB and their result changes as advisories are published
# (independent of code), so an always-on default would make this script
# non-deterministic and offline-hostile. CI / pre-publish should export
# `TALOS_LINT_AUDIT=1`; locally, run `make audit` or set the env for parity.
if [ "${TALOS_LINT_AUDIT:-0}" = "1" ]; then
    if ! command -v cargo-audit >/dev/null 2>&1; then
        yellow "⊘ audit check skipped (cargo-audit not installed — \`cargo install cargo-audit\`)"
    elif cargo audit >/dev/null 2>&1; then
        green "✓ cargo audit clean (no RustSec advisories)"
    else
        red "✗ cargo audit found a vulnerable dependency"
        yellow "  → run \`cargo audit\` for the advisory + fixed-version range"
        EXIT_CODE=1
    fi
else
    yellow "⊘ audit check skipped (set TALOS_LINT_AUDIT=1 to enable)"
    yellow "  CI / pre-publish should run this; \`make audit\` covers it via cargo-deny"
fi
echo

# ── 37. structs holding plaintext secrets must not derive Debug ──────
bold "▶ check 37: secret-holding structs must redact in Debug (no derive(Debug))"

# PR #124 swept six structs that `derive(Debug)` while holding a plaintext
# secret field (api_key / client_secret / signing_secret / verification_token /
# bot_token / …). No active leak existed, but a future `tracing::debug!("{:?}",
# x)` would print the secret — the class the `talos_auth::User` custom redacting
# Debug guards against. This freezes the sweep: a NEW struct that derives Debug
# with a plaintext-secret String field is flagged; write a hand-rolled `Debug`
# that renders the secret as "[REDACTED]" instead (see PR #124 for the shape).
#
# Precise field match (`name:` exactly) so `signing_secret_enc` (ciphertext),
# `*_hash`, `*_id`, `*_expires_at` don't false-positive. Zeroizing/Secret<>
# fields are already self-redacting and exempt. Opt out a genuine non-secret
# with `// allow-debug-secret-struct: <reason>` on the struct or derive line.
DEBUG_SECRET_VIOLATIONS=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    printf '  %s\n' "$line"
    DEBUG_SECRET_VIOLATIONS=$((DEBUG_SECRET_VIOLATIONS + 1))
done < <(
    for rsf in $(grep -rlE 'derive\([^)]*\bDebug\b' --include='*.rs' \
                    --exclude-dir=target talos-* worker controller 2>/dev/null \
                 | grep -v '/tests/' | sort -u); do
        perl -0777 -ne '
            while (/#\[derive\(([^)]*)\)\][^\n]*\n\s*(?:pub\s+)?struct\s+(\w+)\s*\{(.*?)\n\}/gs) {
                my ($d, $name, $body) = ($1, $2, $3);
                next unless $d =~ /\bDebug\b/;
                next if $body =~ /allow-debug-secret-struct/;
                next if $body =~ /Zeroizing|Secret</;
                if ($body =~ /\b(api_key|client_secret|signing_secret|verification_token|bot_token|access_token|refresh_token|private_key|secret_key|password)\s*:\s*(?:Option<\s*)?String/) {
                    print "$ARGV: struct $name derives Debug with a plaintext secret field\n";
                }
            }
        ' "$rsf"
    done 2>/dev/null
)

if [ "$DEBUG_SECRET_VIOLATIONS" -gt 0 ]; then
    red "✗ $DEBUG_SECRET_VIOLATIONS struct(s) derive Debug while holding a plaintext secret"
    yellow "  → write a hand-rolled \`impl Debug\` that renders the secret as \"[REDACTED]\" (see PR #124)"
    yellow "  → or // allow-debug-secret-struct: <reason> if the field is genuinely not a secret"
    EXIT_CODE=1
else
    green "✓ no Debug-deriving structs expose a plaintext secret field"
fi
echo

# ── 38. allow_wasi_network grants must gate on the tier-1 egress ceiling ──
bold "▶ check 38: allow_wasi_network grants must gate on max_llm_tier (tier-1 egress)"

# The tier-1 data-egress ceiling (tier1 = local Ollama only, "data must not leave
# the host") is enforced on the five HTTP/GraphQL/webhook/stream host-fn paths.
# Raw `wasi:sockets` are a PARALLEL egress channel that bypasses BOTH the
# per-module `allowed_hosts` list AND those host-fn tier gates — `socket_addr_check`
# blocks only private IPs (anti-SSRF), not egress — so granting raw network to a
# tier-1 actor lets it exfiltrate to any public IP over raw TCP. PR #156 fixed the
# live execute_job / execute_pipeline paths by adding
# `&& !matches!(max_llm_tier, ...LlmTier::Tier1)` to the `allow_wasi_network` grant.
# This freezes it: every `allow_wasi_network = ...` grant must reference
# `max_llm_tier`, or carry an `allow-wasi-network-no-tier:` opt-out within 5 lines
# above (the Tier2-default sandbox / test paths that have no actor tier
# param — run_sandbox, test_module).

WASI_TIER_VIOLATIONS=0
if [ -n "$RG_BIN" ]; then
    wn_matches=$("$RG_BIN" -n --no-heading -g '*.rs' \
        -e 'allow_wasi_network[[:space:]]*=' worker/ 2>/dev/null || true)
else
    wn_matches=$(grep -rnE --include='*.rs' 'allow_wasi_network[[:space:]]*=' worker/ 2>/dev/null || true)
fi

if [ -n "$wn_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue
        # Skip comment lines and equality comparisons (not assignments).
        if echo "$body" | grep -qE '^[[:space:]]*//|=='; then
            continue
        fi
        # Read the assignment block (match line through the terminating ';').
        end=$((lineno + 8))
        block=$(sed -n "${lineno},${end}p" "$file" 2>/dev/null | awk '{print} /;/{exit}')
        if echo "$block" | grep -q 'max_llm_tier'; then
            continue
        fi
        # Opt-out marker within 5 lines above (or inside the block).
        start=$((lineno > 5 ? lineno - 5 : 1))
        ctx=$(sed -n "${start},${end}p" "$file" 2>/dev/null || true)
        if echo "$ctx" | grep -q 'allow-wasi-network-no-tier'; then
            continue
        fi
        printf '  %s\n' "$line"
        WASI_TIER_VIOLATIONS=$((WASI_TIER_VIOLATIONS + 1))
    done <<< "$wn_matches"
fi

if [ "$WASI_TIER_VIOLATIONS" -gt 0 ]; then
    red "✗ $WASI_TIER_VIOLATIONS allow_wasi_network grant(s) that ignore max_llm_tier"
    yellow "  → a tier-1 actor granted raw wasi:sockets bypasses allowed_hosts AND the host-fn"
    yellow "    tier gate and can exfiltrate to any public IP (see PR #156). Add"
    yellow "    \`&& !matches!(max_llm_tier, talos_workflow_job_protocol::LlmTier::Tier1)\`."
    yellow "  → or // allow-wasi-network-no-tier: <reason> for a Tier2-default actor-less path."
    EXIT_CODE=1
else
    green "✓ all allow_wasi_network grants gate on the tier-1 egress ceiling"
fi
echo

# ── 39. No bare status-clobber writes to workflow_executions ──────────
bold "▶ check 39: workflow_executions status writes must carry a status guard"

# An `UPDATE workflow_executions SET status='<literal>' ... WHERE id=$N` with NO
# `AND status ...` precondition can CLOBBER a row another writer owns. The
# crash-recovery sweep flips a stalled `running` row to `resuming`
# (claim_stuck_execution_for_resume); a superseded dispatcher's bare failure
# write then clobbers `resuming -> failed`, defeating recovery (PR #159), and a
# late/duplicate write can re-clobber an already-terminal row or RESURRECT a
# finished one (the resume_workflow `pending` TOCTOU, PR #158). The canonical
# repo methods (mark_execution_completed/failed/waiting, …) all guard
# `AND status …`; secondary dispatchers must too — the safe uniform guard is
# `AND status NOT IN ('completed','failed','cancelled','resuming')` (admits every
# legit non-terminal owned state, fences resuming + terminal). This freezes it:
# any single-line `UPDATE workflow_executions … SET status='<lit>' … WHERE id=$N`
# lacking `AND status` fails. (Parameterised `SET status=$N` and multi-line SQL
# are out of scope — the common regression shape is single-line literal.)
# Opt-out: `// allow-bare-status-write: <reason>` within 4 lines above.

STATUS_CLOBBER_VIOLATIONS=0
if [ -n "$RG_BIN" ]; then
    sc_matches=$("$RG_BIN" -n --no-heading -g '*.rs' -g '!**/tests/**' -g '!**/*_tests.rs' \
        -e "UPDATE workflow_executions.*SET status = '[a-z]+'.*WHERE id = [\$][0-9]" \
        . 2>/dev/null || true)
else
    sc_matches=$(grep -rnE --include='*.rs' \
        "UPDATE workflow_executions.*SET status = '[a-z]+'.*WHERE id = [\$][0-9]" \
        talos-* controller worker 2>/dev/null | grep -vE '/tests/|_tests\.rs' || true)
fi

if [ -n "$sc_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue
        # Guarded (carries a status precondition) → OK.
        if echo "$body" | grep -q 'AND status'; then
            continue
        fi
        # Opt-out marker within 4 lines above.
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q 'allow-bare-status-write'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        STATUS_CLOBBER_VIOLATIONS=$((STATUS_CLOBBER_VIOLATIONS + 1))
    done <<< "$sc_matches"
fi

if [ "$STATUS_CLOBBER_VIOLATIONS" -gt 0 ]; then
    red "✗ $STATUS_CLOBBER_VIOLATIONS bare workflow_executions status write(s) with no status guard"
    yellow "  → add a status precondition, e.g. AND status NOT IN ('completed','failed','cancelled','resuming')"
    yellow "    (PR #158/#159), or route through the guarded WorkflowRepository::mark_execution_* methods."
    yellow "  → or // allow-bare-status-write: <reason> for an intentional unconditional write."
    EXIT_CODE=1
else
    green "✓ workflow_executions status writes all carry a status guard"
fi
echo

# ── 40. SSRF-checked outbound URLs must use the shared safe HTTP client ──
bold "▶ check 40: SSRF-checked outbound URLs must use the shared safe HTTP client"

# A file that calls `check_outbound_url_no_ssrf` is BY DEFINITION firing a
# user/operator-supplied outbound URL, so it MUST build its reqwest client via
# `talos_http_utils::outbound::build_outbound_webhook_client[_with_timeout]` —
# which installs the connect-time ControllerSsrfResolver that closes the
# DNS-rebinding TOCTOU the call-time check CANNOT (PR #162: an attacker
# controlling the host's DNS returns a public IP at validation, a
# private/metadata IP at connect). A raw `reqwest::Client::builder()`/`::new()`
# in such a file is the regression shape (the gap that hit A2A / approval-gate /
# failure-webhook / policy-notify / SLA-monitor across 6 sites). Fixed-provider
# clients (LLM / Slack / OAuth / Vault — platform-fixed hosts) never call
# check_outbound_url_no_ssrf, so they are not flagged. Opt-out
# `// allow-raw-reqwest-ssrf-checked: <reason>` within 4 lines above (a
# non-webhook fixed-host client that happens to share a file with the check).

SSRF_CLIENT_VIOLATIONS=0
ssrf_files=$(grep -rlE "check_outbound_url_no_ssrf" --include='*.rs' talos-* controller 2>/dev/null \
    | grep -vE '/tests/|talos-http-utils/' || true)
for f in $ssrf_files; do
    [ -f "$f" ] || continue
    while IFS= read -r m; do
        [ -z "$m" ] && continue
        lineno=$(echo "$m" | cut -d: -f1)
        body=$(echo "$m" | cut -d: -f2-)
        # Skip comment-line references (e.g. a `// … reqwest::Client::builder() …`
        # explanatory comment is not a real client construction).
        echo "$body" | grep -qE '^[[:space:]]*//' && continue
        # Opt-out within 4 lines above.
        start=$((lineno > 4 ? lineno - 4 : 1))
        ctx=$(sed -n "${start},${lineno}p" "$f" 2>/dev/null || true)
        echo "$ctx" | grep -q 'allow-raw-reqwest-ssrf-checked' && continue
        printf '  %s:%s\n' "$f" "$lineno"
        SSRF_CLIENT_VIOLATIONS=$((SSRF_CLIENT_VIOLATIONS + 1))
    done <<< "$(grep -nE 'reqwest::Client::(builder|new)\(\)' "$f" 2>/dev/null)"
done

if [ "$SSRF_CLIENT_VIOLATIONS" -gt 0 ]; then
    red "✗ $SSRF_CLIENT_VIOLATIONS raw reqwest client(s) in a file that SSRF-checks an outbound URL"
    yellow "  → build via talos_http_utils::outbound::build_outbound_webhook_client[_with_timeout]"
    yellow "    so the client gets the connect-time ControllerSsrfResolver (DNS-rebinding gate, PR #162)."
    yellow "  → or // allow-raw-reqwest-ssrf-checked: <reason> for a fixed-host client sharing the file."
    EXIT_CODE=1
else
    green "✓ outbound clients for SSRF-checked URLs all use the shared safe builder"
fi
echo

bold "▶ check 41: approval-gate token lookups must use token_hash, not the raw token"

# PR #217: the /approvals/<token>/{approve,reject} handler + preview authenticate
# purely on the URL token. A `WHERE token = $N` lookup compares the raw secret
# with Postgres byte-comparison — NOT the workspace `subtle::ConstantTimeEq`
# discipline used for every other bearer credential. The fix added a generated
# `token_hash` column and switched lookups to `WHERE token_hash = $N` + a
# constant-time compare of the full token. A future query that reintroduces a
# bare `token = $N` equality on `workflow_approval_gates` silently regresses
# that hardening (it survives `cargo check` and every test that doesn't measure
# timing). Scope: only files that reference `workflow_approval_gates`. The
# `[^_a-zA-Z]token = \$N` pattern matches a bare `token` equality bind while
# ignoring `token_hash`, `state_token` (OAuth CSRF nonce — legitimately raw),
# and `verification_token`. Opt-out `// allow-approval-token-raw-lookup: <reason>`
# within 4 lines above.

APPROVAL_TOKEN_VIOLATIONS=0
gate_files=$(grep -rlE "workflow_approval_gates" --include='*.rs' talos-* controller 2>/dev/null \
    | grep -vE '/tests/' || true)
for f in $gate_files; do
    [ -f "$f" ] || continue
    while IFS= read -r m; do
        [ -z "$m" ] && continue
        lineno=$(echo "$m" | cut -d: -f1)
        body=$(echo "$m" | cut -d: -f2-)
        echo "$body" | grep -qE '^[[:space:]]*//' && continue
        start=$((lineno > 4 ? lineno - 4 : 1))
        ctx=$(sed -n "${start},${lineno}p" "$f" 2>/dev/null || true)
        echo "$ctx" | grep -q 'allow-approval-token-raw-lookup' && continue
        printf '  %s:%s\n' "$f" "$lineno"
        APPROVAL_TOKEN_VIOLATIONS=$((APPROVAL_TOKEN_VIOLATIONS + 1))
    done <<< "$(grep -nE '[^_a-zA-Z]token = \$[0-9]' "$f" 2>/dev/null)"
done

if [ "$APPROVAL_TOKEN_VIOLATIONS" -gt 0 ]; then
    red "✗ $APPROVAL_TOKEN_VIOLATIONS raw-token lookup(s) on workflow_approval_gates"
    yellow "  → look up WHERE token_hash = talos_text_util::sha256_hex(provided), then"
    yellow "    constant-time compare the stored token (see approval_token_matches, PR #217)."
    yellow "  → or // allow-approval-token-raw-lookup: <reason> if genuinely not a gate token."
    EXIT_CODE=1
else
    green "✓ approval-gate token lookups all key on token_hash (no raw-token equality)"
fi
echo

bold "▶ check 42: org-pinned-table creates must run on a tenant-scoped tx"

# RFC 0006 / RFC 0005 S3 (PRs #219–#222): the org-pinned tables
# (workflows / actors / secrets) carry an RLS WITH CHECK pinned to
# `app.current_org_id`. For that pin to ENFORCE once `TALOS_RLS_SET_ROLE`
# flips on, an `INSERT` (the org-setting write) MUST run on a tx opened by
# `begin_org_scoped` (or the repo `begin_personal_org_write` helpers) so the
# org GUC is set — NOT on the bare connection pool, where the pin only
# passes via its rollout-safe `unset → permit` clause (i.e. does not
# enforce). A new create path that executes `INSERT INTO {workflows,actors,
# secrets}` on `&self.db_pool` / `db_pool` silently reintroduces that gap —
# it survives `cargo check` and every test that doesn't run under the
# `talos_app` role. (UPDATE/DELETE that don't move `org_id` are out of scope:
# they stay permit-via-unset and are protected by the read-scope USING clause
# + the app-layer `user_id` filter.) Comment lines are skipped (a `//` that
# merely mentions an INSERT is not a write). Opt-out
# `// allow-unscoped-org-write: <reason>` within 4 lines above (engine /
# system / seeding paths that intentionally stay permissive).

ORG_WRITE_VIOLATIONS=0
org_write_files=$(grep -rlE "INSERT INTO (workflows|actors|secrets)\b" --include='*.rs' talos-* controller 2>/dev/null \
    | grep -vE '/tests/' || true)
for f in $org_write_files; do
    [ -f "$f" ] || continue
    while IFS= read -r m; do
        [ -z "$m" ] && continue
        lineno=$(echo "$m" | cut -d: -f1)
        body=$(echo "$m" | cut -d: -f2-)
        # Skip comment-line matches (a `//` referencing an INSERT, not a write).
        echo "$body" | grep -qE '^[[:space:]]*//' && continue
        # Inspect the statement's executor in the following lines.
        ctx=$(sed -n "${lineno},$((lineno + 16))p" "$f" 2>/dev/null || true)
        # Scoped writes use `&mut *tx` / a threaded conn — never the bare pool.
        echo "$ctx" | grep -qE '\.(execute|fetch_one|fetch_optional|fetch_all)\([[:space:]]*(&self\.db_pool|&self\.pool|db_pool|&pool|pool)[[:space:]]*\)' || continue
        # Opt-out within 4 lines above.
        start=$((lineno > 4 ? lineno - 4 : 1))
        above=$(sed -n "${start},${lineno}p" "$f" 2>/dev/null || true)
        echo "$above" | grep -q 'allow-unscoped-org-write' && continue
        printf '  %s:%s\n' "$f" "$lineno"
        ORG_WRITE_VIOLATIONS=$((ORG_WRITE_VIOLATIONS + 1))
    done <<< "$(grep -nE 'INSERT INTO (workflows|actors|secrets)\b' "$f" 2>/dev/null)"
done

if [ "$ORG_WRITE_VIOLATIONS" -gt 0 ]; then
    red "✗ $ORG_WRITE_VIOLATIONS org-pinned-table create(s) on the bare pool (unscoped)"
    yellow "  → open the write via talos_db::begin_org_scoped (or the repo"
    yellow "    begin_personal_org_write helper) so the org-pin WITH CHECK enforces (RFC 0006)."
    yellow "  → or // allow-unscoped-org-write: <reason> for an engine/system/seeding path."
    EXIT_CODE=1
else
    green "✓ org-pinned-table creates all run on a tenant-scoped tx"
fi
echo

bold "▶ check 43: controller test setup must use the isolated-DB harness, not init_pool()"

# Per-test DB isolation (docs/backlog.md): `controller/tests/common::
# setup_test_context` / `isolated_db_pool` give every test its OWN database
# (a fast `CREATE DATABASE … TEMPLATE` clone of the migrated DB, dropped on
# scope-exit), so tests never share DB state. A test setup that instead calls
# `controller::db::init_pool()` connects to the shared `DATABASE_URL` directly —
# reintroducing the global-`DELETE FROM …` shared-state pattern (and the
# cross-binary flake) the isolation removed, AND writing to the `talos_ctl`
# TEMPLATE that the other binaries clone (corrupting their snapshots). The one
# legitimate caller is `env_vars.rs`, which TESTS init_pool's missing-DATABASE_URL
# behavior. Opt-out `// allow-test-init-pool: <reason>` on the same line.

INITPOOL_VIOLATIONS=0
initpool_hits=$(grep -rnE 'init_pool[[:space:]]*\(' --include='*.rs' controller/tests 2>/dev/null \
    | grep -vE '/env_vars\.rs:' || true)
while IFS= read -r m; do
    [ -z "$m" ] && continue
    echo "$m" | grep -q 'allow-test-init-pool' && continue
    body=$(echo "$m" | cut -d: -f3-)
    echo "$body" | grep -qE '^[[:space:]]*//' && continue
    printf '  %s\n' "$m"
    INITPOOL_VIOLATIONS=$((INITPOOL_VIOLATIONS + 1))
done <<< "$initpool_hits"

if [ "$INITPOOL_VIOLATIONS" -gt 0 ]; then
    red "✗ $INITPOOL_VIOLATIONS controller test(s) call init_pool() directly (shared-DB harness)"
    yellow "  → use common::setup_test_context / common::isolated_db_pool for an isolated per-test DB."
    yellow "  → or // allow-test-init-pool: <reason> (e.g. a test OF init_pool itself)."
    EXIT_CODE=1
else
    green "✓ controller tests use the isolated-DB harness (no direct init_pool)"
fi
echo

bold "▶ check 44: production in-transit TLS gates must fail closed (not warn)"

# P1-A (compliance: HIPAA §164.312(e) / SOC2 CC6.7 / ISO A.8.24 transmission
# security): every cleartext-capable backend connection (Redis / NATS / Postgres
# / Neo4j) MUST refuse to boot in production on a non-TLS URL, not merely log a
# warning. The message bus carries decrypted memory values (potential PHI) and
# HMAC-signed payloads; Postgres carries credentials + ePHI; etc. Each gate is
# tagged `// tls-prod-gate-<name>`. This check freezes (a) the four gates'
# existence and (b) that each fails closed (return Err / panic / bail) rather
# than being softened back to a lone tracing::warn! — the pre-P1-A regression
# shape (NATS + Postgres shipped warn-only; Redis already panicked).

TLS_GATE_VIOLATIONS=0
for gate in redis nats postgres neo4j; do
    hit=$(grep -rn "tls-prod-gate-${gate}" --include='*.rs' controller/src talos-db/src 2>/dev/null | head -1 || true)
    if [ -z "$hit" ]; then
        red "✗ missing production TLS gate marker: tls-prod-gate-${gate}"
        TLS_GATE_VIOLATIONS=$((TLS_GATE_VIOLATIONS + 1))
        continue
    fi
    file=$(echo "$hit" | cut -d: -f1)
    lineno=$(echo "$hit" | cut -d: -f2)
    # The marker line + the 12 lines following it must contain a fail-closed
    # action. A gate softened back to `tracing::warn!` (no return/panic/bail)
    # is exactly the regression this check exists to catch.
    window=$(sed -n "${lineno},$((lineno + 12))p" "$file" 2>/dev/null || true)
    if ! echo "$window" | grep -qE 'return Err|panic!|bail!'; then
        red "✗ TLS gate '${gate}' at ${file}:${lineno} does not fail closed (no return Err/panic/bail within 12 lines)"
        yellow "  → a production no-TLS condition must refuse boot, not tracing::warn!"
        TLS_GATE_VIOLATIONS=$((TLS_GATE_VIOLATIONS + 1))
    fi
done

if [ "$TLS_GATE_VIOLATIONS" -gt 0 ]; then
    red "✗ $TLS_GATE_VIOLATIONS production TLS gate(s) missing or not fail-closed"
    yellow "  → Redis/NATS/Postgres/Neo4j prod connections must reject plaintext URLs at boot."
    EXIT_CODE=1
else
    green "✓ production in-transit TLS gates (redis/nats/postgres/neo4j) all fail closed"
fi
echo

bold "▶ check 45: env-KEK in production must be guarded (no plaintext master key by default)"

# P1-B (compliance: HIPAA/SOC2/ISO key management): an env-backed KEK keeps the
# root key (TALOS_MASTER_KEY) in a Secret + process memory. The controller MUST
# refuse to boot with KEK_PROVIDER=env under RUST_ENV=production unless the
# operator explicitly opts in (TALOS_ALLOW_ENV_KEK) — KMS-backed Vault is the
# compliant default. The guard is tagged `// prod-kek-guard`; this check freezes
# (a) its existence and (b) that it fails closed (return Err) within 25 lines —
# catching a future softening to a warn-only / always-accept regression.

KEK_GUARD_HITS=$(grep -rn "prod-kek-guard" --include='*.rs' controller/src 2>/dev/null | head -1 || true)
if [ -z "$KEK_GUARD_HITS" ]; then
    red "✗ missing production env-KEK guard marker: prod-kek-guard"
    yellow "  → the KEK_PROVIDER=env arm must refuse boot in production (see controller/src/main.rs)"
    EXIT_CODE=1
else
    file=$(echo "$KEK_GUARD_HITS" | cut -d: -f1)
    lineno=$(echo "$KEK_GUARD_HITS" | cut -d: -f2)
    window=$(sed -n "${lineno},$((lineno + 25))p" "$file" 2>/dev/null || true)
    if echo "$window" | grep -q 'return Err'; then
        green "✓ env-KEK-in-production guard present and fails closed"
    else
        red "✗ env-KEK guard at ${file}:${lineno} does not fail closed (no return Err within 25 lines)"
        yellow "  → a production env-KEK without TALOS_ALLOW_ENV_KEK must refuse boot, not warn."
        EXIT_CODE=1
    fi
fi
echo

bold "▶ check 46: execution finalizers must accept 'resuming', not only 'running'"

# A terminal-status writer on `workflow_executions` guarded
# `WHERE id = $N AND status = 'running'` (NOT including 'resuming') cannot
# finalize a crash-recovery-claimed row. The recovery sweep flips a stalled
# `running` row to `resuming` (claim_stuck_execution_for_resume) BEFORE re-running
# it, so a `running`-only completer / failer / waiter no-ops and the resumed
# execution sticks in `resuming` forever (force-failed only by the 30-min stale
# sweep) — PR #271. fence.rs documents these writes as
# `WHERE status = 'running' (or 'resuming')`; the safe guard is
# `status IN ('running', 'resuming')`. This freezes it: any single-line
# `WHERE id = $N AND status = 'running'` in the execution-status repos fails.
# (The `queued -> running` promotion guards on `status = 'queued'`, and the
# child-row cleanup keys on `workflow_execution_id` — both out of scope by shape.)
# Opt-out: `// allow-running-only-finalize: <reason>` within 4 lines above.

RESUME_FINALIZE_VIOLATIONS=0
rf_matches=$(grep -rnE --include='*.rs' \
    "WHERE id = [\$][0-9]+ AND status = 'running'" \
    talos-workflow-repository talos-execution-repository 2>/dev/null || true)
if [ -n "$rf_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        [ -f "$file" ] || continue
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q 'allow-running-only-finalize'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        RESUME_FINALIZE_VIOLATIONS=$((RESUME_FINALIZE_VIOLATIONS + 1))
    done <<< "$rf_matches"
fi

if [ "$RESUME_FINALIZE_VIOLATIONS" -gt 0 ]; then
    red "✗ $RESUME_FINALIZE_VIOLATIONS execution finalizer guard(s) accept only 'running', not 'resuming'"
    yellow "  → widen to status IN ('running', 'resuming') so crash-recovery resumes finalize (PR #271)."
    yellow "  → or // allow-running-only-finalize: <reason> if the write must target 'running' exclusively."
    EXIT_CODE=1
else
    green "✓ execution finalizers accept 'resuming' (crash-recovery resumes can finalize)"
fi
echo

bold "▶ check 47: append-only audit tables must not gain CASCADE/SET NULL FKs"

# A table carrying the prevent_audit_modification trigger (BEFORE DELETE OR
# UPDATE) MUST NOT have an incoming FK with ON DELETE CASCADE or SET NULL: both
# fire a DELETE/UPDATE on the immutable audit row and abort the parent's
# deletion. secret_audit_log -> secrets CASCADE made every secret undeletable
# (#264); auth_audit_log / admin_event_log -> users SET NULL made users
# undeletable (#266). Audit rows must hold the parent id as a plain (nullable)
# historical reference. This freezes it: a CREATE/ALTER of an append-only audit
# table that adds `ON DELETE CASCADE|SET NULL` fails. Pre-fix history is
# grandfathered by timestamp — those bad FKs are dropped by 20260625140000 /
# 20260625150000; only migrations newer than the last fix are scanned. Adding a
# NEW append-only audit table? Append its name to AUDIT_TABLES below.

AUDIT_FK_VIOLATIONS=0
AUDIT_TABLES='admin_event_log audit_events auth_audit_log secret_audit_log'
AUDIT_FK_CUTOFF=20260625150000
for mig in "$ROOT"/migrations/*.sql; do
    [ -f "$mig" ] || continue
    ts=$(basename "$mig" | grep -oE '^[0-9]{14}' || true)
    [ -n "$ts" ] || ts=0
    # Grandfather everything at/before the last audit-FK fix migration.
    if [ "$ts" -le "$AUDIT_FK_CUTOFF" ] 2>/dev/null; then
        continue
    fi
    for tbl in $AUDIT_TABLES; do
        hit=$(awk -v t="$tbl" '
            BEGIN { inblk = 0 }
            (/CREATE TABLE/ || /ALTER TABLE/) && index($0, t) { inblk = 1 }
            inblk && (/ON DELETE CASCADE/ || /ON DELETE SET NULL/) { print NR ": " $0 }
            inblk && /;/ { inblk = 0 }
        ' "$mig" 2>/dev/null || true)
        if [ -n "$hit" ]; then
            while IFS= read -r h; do
                printf '  %s:%s  [%s]\n' "$(basename "$mig")" "$h" "$tbl"
                AUDIT_FK_VIOLATIONS=$((AUDIT_FK_VIOLATIONS + 1))
            done <<< "$hit"
        fi
    done
done

if [ "$AUDIT_FK_VIOLATIONS" -gt 0 ]; then
    red "✗ $AUDIT_FK_VIOLATIONS append-only audit-table FK(s) with ON DELETE CASCADE/SET NULL"
    yellow "  → an append-only audit row must reference its parent WITHOUT an enforced delete action,"
    yellow "    or the parent becomes undeletable (immutability trigger blocks the cascade) — #264/#266."
    EXIT_CODE=1
else
    green "✓ no append-only audit table gains a CASCADE/SET NULL FK"
fi
echo

bold "▶ check 48: template macro world must match talos.json capability_world"

# A pre-baked template's WIT capability world is selected by the
# `#[talos_node|talos_module|talos_agent(world = "...")]` macro attribute — the
# compilation scaffold reads it via extract_wit_world to drive bindgen. The
# `capability_world` in talos.json is only catalog metadata. When the two
# disagree the MACRO wins, and the mismatch surfaces as a confusing
# `unresolved import talos::core::http` (when the macro under-grants) or a
# silent over-grant of host capabilities (when the macro over-grants).
# github-pr-reviewer shipped with talos.json=secrets-node but a BARE
# `#[talos_node]` (→ minimal-node), so it failed to install with
# `unresolved import talos::core::{http,secrets}` (#361). http-request shipped
# the inverse: talos.json=http-node, macro=network-node — a least-privilege
# over-grant. This freezes both: every module-templates/*/ entry must declare an
# EXPLICIT world in its macro that equals talos.json's capability_world.
# Opt-out: `// allow-world-mismatch: <reason>` anywhere in the template .rs.

WORLD_MATCH_VIOLATIONS=0
for tj in "$ROOT"/module-templates/*/talos.json; do
    [ -f "$tj" ] || continue
    dir="$(dirname "$tj")"
    name="$(basename "$dir")"

    cw="$(grep -oE '"capability_world"[[:space:]]*:[[:space:]]*"[^"]*"' "$tj" \
            | grep -oE '"[^"]*"$' | tr -d '"' | head -1)"
    # No declared capability_world → nothing to compare against. Skip.
    [ -n "$cw" ] || continue

    # The .rs file carrying the entry-point macro (template.rs or src/lib.rs).
    rs="$(grep -rlE '#\[(talos_sdk_macros::)?talos_(node|module|agent)' \
            "$dir" --include='*.rs' 2>/dev/null | head -1)"
    # A talos.json with no macro'd source is a data-only / non-Rust template.
    [ -n "$rs" ] || continue

    # Documented exception.
    if grep -q 'allow-world-mismatch' "$rs"; then
        continue
    fi

    # Extract the explicit `world = "..."` (or `world: "..."`) from the macro.
    mw="$(grep -oE 'talos_(node|module|agent)\([^)]*world[[:space:]]*[=:][[:space:]]*"[^"]*"' "$rs" \
            | grep -oE '"[^"]*"$' | tr -d '"' | head -1)"

    if [ -z "$mw" ]; then
        printf '  %s: bare macro (defaults to minimal-node) but talos.json says "%s"\n' \
            "$name" "$cw"
        printf '    → add an explicit world = "%s" to the macro in %s\n' \
            "$cw" "${rs#"$ROOT"/}"
        WORLD_MATCH_VIOLATIONS=$((WORLD_MATCH_VIOLATIONS + 1))
    elif [ "$mw" != "$cw" ]; then
        printf '  %s: macro world = "%s" but talos.json capability_world = "%s"\n' \
            "$name" "$mw" "$cw"
        printf '    → reconcile %s and talos.json (the macro is what actually compiles)\n' \
            "${rs#"$ROOT"/}"
        WORLD_MATCH_VIOLATIONS=$((WORLD_MATCH_VIOLATIONS + 1))
    fi
done

if [ "$WORLD_MATCH_VIOLATIONS" -gt 0 ]; then
    red "✗ $WORLD_MATCH_VIOLATIONS template(s) with macro/talos.json world drift"
    yellow "  → the #[talos_*(world=…)] attribute drives bindgen; talos.json is metadata."
    yellow "  → make them equal (least-privilege: pick the smallest world your imports need)."
    yellow "  → or add // allow-world-mismatch: <reason> in the template .rs."
    EXIT_CODE=1
else
    green "✓ template macro worlds match talos.json capability_world"
fi
echo

# ── 49. Integration crates must build HTTP clients via the shared builder ──
bold "▶ check 49: integration crates must use talos_http_utils::trusted_client (no raw reqwest client builder)"
# Every OAuth/integration crate calls FIXED, TRUSTED hosts (accounts.google.com,
# auth.atlassian.com, slack.com, googleapis.com, api.atlassian.com) carrying a
# Bearer / X-*-Token credential. A hand-rolled `reqwest::Client::builder()` is
# exactly where `redirect(Policy::none())` (credential-leak-via-3xx, MCP-533/571)
# and `connect_timeout` (black-holed-host hang, MCP-1034) get forgotten — the
# class we had to fix crate-by-crate. Route every such client through
# talos_http_utils::trusted_client::{hardened_client_builder, build_integration_client}
# so a NEW integration is hardened by construction. (User/caller-supplied URLs are
# a different concern — those use talos_http_utils::outbound::* with the SSRF
# resolver, per check 40.) Opt-out for a genuinely special client with
# `// allow-raw-integration-client: <reason>` within 4 lines above.
INTEG_CLIENT_VIOLATIONS=0
integ_client_matches=$(grep -rnE 'reqwest::Client::builder\(\)' \
    talos-gmail/src talos-google-calendar/src talos-slack/src \
    talos-atlassian/src talos-oauth/src 2>/dev/null \
    | grep -vE '/tests/|_tests\.rs' || true)
if [ -n "$integ_client_matches" ]; then
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        body=$(echo "$line" | cut -d: -f3-)
        [ -f "$file" ] || continue
        # Skip full-line comments / doc comments.
        if echo "$body" | grep -qE '^\s*//|^\s*\*|//!'; then
            continue
        fi
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$file" 2>/dev/null || true)
            if echo "$ctx" | grep -q '// allow-raw-integration-client:'; then
                continue
            fi
        fi
        printf '  %s\n' "$line"
        INTEG_CLIENT_VIOLATIONS=$((INTEG_CLIENT_VIOLATIONS + 1))
    done <<< "$integ_client_matches"
fi

if [ "$INTEG_CLIENT_VIOLATIONS" -gt 0 ]; then
    red "✗ $INTEG_CLIENT_VIOLATIONS raw reqwest::Client::builder() in integration crate(s)"
    yellow "  → use talos_http_utils::trusted_client::build_integration_client(timeout) or"
    yellow "    hardened_client_builder(timeout) (redirect-none + connect-timeout baked in)."
    yellow "  → Opt out (genuinely special client): // allow-raw-integration-client: <reason>"
    EXIT_CODE=1
else
    green "✓ integration crates build HTTP clients via the shared hardened builder"
fi
echo

# ── 50. Raw sqlx in talos-api/src/schema — HARD RULE (graduated) ──────
# talos-mcp-handlers went 371 → 0 raw-sqlx sites under check 6; the
# GraphQL schema tree sat at 117 sites (2026-07-01 review) — on the
# surface where RLS/tenancy stakes are highest. Introduced as a RATCHET
# (count may only go down); the debt was fully burned down 117 → 0
# across PRs #386/#389/#390/#391/#392 + the workflows finale, and the
# check GRADUATED to a hard rule 2026-07-06 (same arc as check 6).
# Every resolver SQL statement lives in a repository/service crate;
# scoped-tx sites use conn-taking methods (&mut PgConnection) with the
# resolver owning begin/commit so the RLS backstop is preserved
# (checks 25/42 are the guardrails). Do NOT re-add a baseline.
bold "▶ check 50: raw sqlx::query in talos-api/src/schema (must be 0)"
# 117 at introduction (2026-07-01); 108 after the trigger_workflow
# migration onto ExecutionOrchestrationService removed 9 inline sites;
# 106 after modules/queries.rs moved onto ModuleRepository (2026-07-05);
# 104 after modules/mutations.rs (gcal ownership probe → talos-google-calendar,
# module-config write → ModuleRepository); 102 after types.rs DataLoaders
# (ModuleRepository::get_modules_by_ids +
# ModuleExecutionService::get_execution_logs_batched); 98 after
# executions/mutations.rs (scoped-tx approve/deny →
# ExecutionRepository::decide_execution_approval_scoped, tx passed through),
# auth/mutations.rs (AuthService::revoke_pre_2fa_sessions), and
# security/queries.rs (talos_audit_ledger::get_user_audit_settings); 95
# after webhooks/queries.rs (WebhookRepository::list_for_user_with_stats /
# list_dlq_for_user + tx-taking
# ExecutionRepository::list_dead_letter_queue_scoped); 88 after
# subscriptions.rs + mod.rs (OrganizationService::list_user_org_ids /
# list_user_writable_org_ids, ExecutionRepository::
# list_recent_execution_events, WorkflowRepository::replace_module_refs);
# 84 after security/mutations.rs (SecretsManager::count_encryption_keys +
# talos_audit_ledger::upsert_user_audit_settings/get_user_audit_settings);
# 78 after webhooks/mutations.rs (ModuleRepository::module_owned_by_user,
# WebhookRepository::insert_trigger/get_dlq_entry_for_replay/
# mark_dlq_entry_replayed, tx-taking
# ExecutionRepository::get_dlq_replay_target_scoped +
# mark_dlq_entry_replayed); 70 after platform/queries.rs
# (ActorRepository::get_user_max_capability_world/get_user_capability_grant/
# list_capability_grants/get_user_email,
# ExecutionRepository::get_workflow_id_any_user,
# OrganizationService::list_user_org_ids/get_org_quota_limits,
# talos_integrations::store::list_user_service_integrations); 61 after
# platform/mutations.rs (tx-taking WorkflowRepository::set_max_concurrent_scoped,
# OrganizationService::first_org_id_owned_by/upsert_org_quota_limit/
# get_org_quota_limits, ActorRepository::get_user_max_capability_world/
# user_exists/upsert_capability_grant/delete_capability_grant,
# talos_integrations::store::disconnect_user_integration); 48 after
# actors/queries.rs (conn-taking ActorRepository scoped reads:
# list_actor_summaries_scoped/get_actor_details_scoped/
# actor_owned_by_user_scoped/get_actor_execution_counts_scoped/
# get_actor_workflow_counts_scoped/list_action_log_scoped, conn-taking
# WorkflowRepository::list_workflows_for_actor_scoped,
# talos_memory::list_memories_with_ciphertext_scoped (also fixes the
# actorMemories MCP-S2 projection break), SystemRepository::list_agents_for_user);
# 36 after actors/mutations.rs (conn-taking ActorRepository scoped writes:
# insert_actor_scoped (org-pinned create, resolver keeps begin_org_scoped)/
# update_actor_status_scoped/terminate_actor_scoped/update_actor_fields_scoped/
# actor_owned_active_scoped/get_actor_clone_source_scoped, conn-taking
# WorkflowRepository::archive_workflows_for_actor_scoped,
# SystemRepository::find_role_id_by_name/register_agent/delete_agent_for_user);
# 25 after workflows/queries.rs (conn-taking ExecutionRepository::
# list_latest_executions_for_workflows_scoped/list_execution_history_scoped/
# list_pending_approvals_scoped, conn-taking WorkflowRepository::
# get_workflow_for_accessor_scoped/list_workflows_for_accessor_scoped/
# get_graph_json_for_accessor_scoped/get_all_workflow_stats_scoped,
# WorkflowVersionService::get_version_for_accessor_on_conn/
# get_active_graph_json_on_conn, talos_scheduler::
# get_schedule_for_accessor_on_conn/list_schedules_for_user); 0 after
# workflows/mutations.rs (ExecutionRepository::get_execution_resume_gate/
# flip_waiting_to_pending/get_pinned_version_id/insert_execution_event/
# fail_execution_unless_terminal/insert_test_execution_row, conn-taking
# WorkflowRepository::insert_workflow_scoped (org-pinned create)/
# update_workflow_scoped/delete_workflow_guarded_scoped/
# workflow_delete_blocked_scoped + get_graph_and_actor_unchecked,
# talos_scheduler::upsert/get_for_update/update/delete_schedule_on_conn,
# talos_db::try_advisory_lock/release_advisory_lock). GRADUATED.
TALOS_API_SQLX_BASELINE=0
# `|| true`: grep exits 1 on zero matches — the expected steady state now
# that the tree is raw-sqlx-free — and pipefail would kill the script.
API_SQLX_COUNT="$({ grep -rEc 'sqlx::query' \
        --include='*.rs' \
        talos-api/src/schema 2>/dev/null || true; } \
    | awk -F: '{s+=$2} END {print s+0}')"
if [ "$API_SQLX_COUNT" -gt "$TALOS_API_SQLX_BASELINE" ]; then
    red "✗ ${API_SQLX_COUNT} raw sqlx::query site(s) in talos-api/src/schema (must be 0 — graduated hard rule)"
    yellow "  → resolver SQL goes in a repository crate (same rule as talos-mcp-handlers, check 6)."
    yellow "  → scoped-tx sites: conn-taking repo method (&mut PgConnection), resolver keeps begin/commit."
    grep -rEln 'sqlx::query' --include='*.rs' talos-api/src/schema 2>/dev/null | sed 's/^/    /'
    EXIT_CODE=1
else
    green "✓ talos-api/src/schema is raw-sqlx-free (hard rule, graduated from the 117-site ratchet)"
fi
echo

# ── 51. No workflow-engine dep in repository crates (layering) ────────
# Repository crates are the persistence layer; the workflow engine is the
# execution layer above them. `talos-actor-repository` grew a dependency
# on `talos-workflow-engine` (+ `-core`) purely to host
# `apply_actor_to_engine(&mut ParallelWorkflowEngine, …)` — a
# persistence crate reaching UP into the engine. Fixed 2026-07 by moving
# the function to `talos_engine::actor_binding` (the application layer
# that already composes repo + engine); this check freezes the fix so
# the inverted edge can't creep back via the next "convenient helper".
# Scope: the dep named exactly `talos-workflow-engine` in any
# `talos-*-repository/Cargo.toml`. (`talos-workflow-engine-core` is the
# dep-free trait-boundary crate and is deliberately NOT forbidden —
# `talos-workflow-repository` legitimately implements its traits.)
# Opt out with `# allow-repo-engine-dep: <reason>` on the dep line or
# within 4 lines above it.
bold "▶ check 51: no talos-workflow-engine dependency in talos-*-repository crates"

REPO_ENGINE_DEP_VIOLATIONS=0
for repo_toml in talos-*-repository/Cargo.toml; do
    [ -f "$repo_toml" ] || continue
    dep_matches=$(grep -nE '^[[:space:]]*talos-workflow-engine[[:space:]]*=' "$repo_toml" || true)
    [ -n "$dep_matches" ] || continue
    while IFS= read -r line; do
        lineno=$(echo "$line" | cut -d: -f1)
        body=$(echo "$line" | cut -d: -f2-)
        # Same-line or nearby opt-out marker.
        if echo "$body" | grep -q '# allow-repo-engine-dep:'; then
            continue
        fi
        if [ -n "$lineno" ] && [ "$lineno" -gt 1 ]; then
            start=$((lineno > 4 ? lineno - 4 : 1))
            ctx=$(sed -n "${start},${lineno}p" "$repo_toml" 2>/dev/null || true)
            if echo "$ctx" | grep -q '# allow-repo-engine-dep:'; then
                continue
            fi
        fi
        printf '  %s:%s\n' "$repo_toml" "$line"
        REPO_ENGINE_DEP_VIOLATIONS=$((REPO_ENGINE_DEP_VIOLATIONS + 1))
    done <<< "$dep_matches"
done

if [ "$REPO_ENGINE_DEP_VIOLATIONS" -gt 0 ]; then
    red "✗ $REPO_ENGINE_DEP_VIOLATIONS talos-workflow-engine dep(s) in repository crates (layering inversion)"
    yellow "  → repository crates are the persistence layer; they must not depend on the"
    yellow "    execution engine. Put engine-touching helpers in the application layer"
    yellow "    (talos-engine — see actor_binding::apply_actor_to_engine for the pattern)."
    yellow "  → documented exception: # allow-repo-engine-dep: <reason>"
    EXIT_CODE=1
else
    green "✓ no talos-workflow-engine dependency in repository crates"
fi
echo

# ── 52. Silent-swallow row reads in repository crates — RATCHET ───────
# `row.try_get("col").unwrap_or(<default>)` turns a schema drift (a
# renamed/retyped/dropped column) into a SILENT wrong value at runtime
# instead of an error: a renamed column reads as None / false / 0 /
# Default rather than failing, so the drift ships and surfaces as
# mysterious "empty" data far from the cause. This is the read-side twin
# of check 34 (which already forces the actor_memory value_format read to
# fail loud because a silent 0 there mis-dispatches AEAD decryption). The
# codebase-review (2026-07-03) flagged this as the single biggest
# structural code-quality gap: hundreds of these reads across the
# repository layer, invisible to `cargo check`.
#
# Introduced 2026-07-03 (codebase review) as a RATCHET at 526 sites because a
# blanket ban would have blocked every PR touching the debt. Fully burned down
# 2026-07 (524→0): every `talos-*-repository` crate now reads columns as
# `Option<T>` and propagates schema drift with `?` (NULL still yields the
# documented default; a renamed/dropped/retyped column errors instead of
# silently defaulting). Now GRADUATED to a HARD RULE (like check 6 for
# talos-mcp-handlers): the count must stay 0 — any NEW silent read is an
# outright failure. Fix by reading as
# `.try_get::<Option<_>, _>("col")?.unwrap_or(default)` (or a typed
# `FromRow`/`query_as!` mapping), NOT by re-adding a baseline.
#
# WIDENED TO WORKSPACE-WIDE 2026-07-07: the original `talos-*-repository`
# glob was a NAMING scope, not a ROLE scope — 62 more sites of the identical
# class lived in DB-reading crates that are repositories by role but not by
# name (talos-secrets-manager 24, talos-module-executions 12, talos-registry
# 11, talos-schedule-repo 7, talos-integration-state 7, talos-auth 1). All
# burned down in the same pass that widened this check, so the whole
# workspace is now at 0 and stays there.
#
# Regex catches BOTH plain `.try_get("col").unwrap_or` AND the turbofish
# `.try_get::<Option<T>, _>("col").unwrap_or` form (the `(::<[^(]*>)?` group), but
# NOT the fixed `?.unwrap_or` form — the `\)\.unwrap_or` requires `)` immediately
# followed by `.unwrap_or`, so a `)?.unwrap_or` (error propagated) never matches.
# (A silent read split across lines — `.try_get(...)` and `.unwrap_or` on separate
# lines — still slips past this line-based grep; those are rare and caught in review.)
bold "▶ check 52: silent try_get().unwrap_or reads (workspace-wide, must be 0)"
# `|| true`: now that the count is 0, `grep -c` finds no matches and exits 1,
# which under this script's `set -euo pipefail` would abort here — the very
# success case (fully burned down) must not fail the script. awk still prints 0.
# --exclude-dir: target (build artifacts), .git, .claude (session worktrees
# checked out INSIDE the repo dir would otherwise re-surface stale copies),
# node_modules (defensive; frontend has no .rs but the walk is cheaper skipped).
REPO_SILENT_READ_COUNT="$( { grep -rEc '\.try_get(::<[^(]*>)?\([^)]*\)\.unwrap_or' \
        --include='*.rs' \
        --exclude-dir=target --exclude-dir=.git --exclude-dir=.claude --exclude-dir=node_modules \
        . 2>/dev/null || true; } \
    | awk -F: '{s+=$2} END {print s+0}')"
if [ "$REPO_SILENT_READ_COUNT" -ne 0 ]; then
    red "✗ ${REPO_SILENT_READ_COUNT} silent try_get().unwrap_or read(s) workspace-wide (must be 0):"
    grep -rEn '\.try_get(::<[^(]*>)?\([^)]*\)\.unwrap_or' --include='*.rs' --exclude-dir=target --exclude-dir=.git --exclude-dir=.claude --exclude-dir=node_modules . 2>/dev/null | sed 's/^/    /'
    yellow "  → a renamed/dropped column would read as a silent default, not an error."
    yellow "    Read as Option and propagate: .try_get::<Option<_>, _>(\"col\")?.unwrap_or(default)"
    yellow "    or use a typed FromRow / query_as! mapping."
    EXIT_CODE=1
else
    green "✓ no silent try_get().unwrap_or reads workspace-wide"
fi
echo

# ── 53. Unguarded wasmtime Component::new in the worker runtime ───────
# wasmtime's Cranelift backend can PANIC (not Err) on certain guest
# instruction patterns (e.g. the aarch64 `value_is_real` lowering bug on
# jco/StarlingMonkey output). `Component::new` runs in the worker PROCESS,
# so an unguarded panic unwinds through the whole worker and kills every
# in-flight job — a guest-influenceable DoS. All component compilation
# MUST route through `TalosRuntime::compile_component_guarded` (which wraps
# it in `guard_codegen_panic`). The single legitimate site inside that
# method is tagged `// allow-unguarded-component-new`.
bold "▶ check 53: unguarded wasmtime Component::new in worker runtime (must route through the panic guard)"
UNGUARDED_CN="$(grep -rEn 'Component::new\(' --include='*.rs' worker/src 2>/dev/null \
    | grep -v 'allow-unguarded-component-new' \
    | grep -vE '//.*Component::new' || true)"
if [ -n "$UNGUARDED_CN" ]; then
    red "✗ direct wasmtime Component::new outside the panic guard:"
    echo "$UNGUARDED_CN" | sed 's/^/    /'
    yellow "  → route it through TalosRuntime::compile_component_guarded so a Cranelift"
    yellow "    codegen panic becomes a clean per-job error instead of crashing the worker."
    EXIT_CODE=1
else
    green "✓ all worker Component::new sites route through the codegen panic guard"
fi
echo

# ── 54. Lint self-consistency (meta-check) ────────────────────────────
# The system whose purpose is catching drift drifted from its own docs:
# by 2026-07-01 the script had 49 checks while CLAUDE.md said 43 and the
# pre-push hook comment said 40 — three sources, three numbers. Assert
# (a) check numbers are contiguous 1..N with no dupes/gaps (a gap means
# a renumber went wrong or a check was deleted without renumbering), and
# (b) CLAUDE.md's "N checks today" sentence matches the real count. The
# pre-push hook no longer states a number (it points at --count).
bold "▶ check 54: lint self-consistency (check numbering + documented count)"
ACTUAL_NUMS="$(grep -oE '^bold "▶ check [0-9]+:' "${BASH_SOURCE[0]}" | grep -oE '[0-9]+' | sort -n)"
EXPECTED_NUMS="$(seq 1 "$CHECK_COUNT")"
META_FAIL=0
if [ "$ACTUAL_NUMS" != "$EXPECTED_NUMS" ]; then
    red "✗ check numbers are not contiguous 1..$CHECK_COUNT (duplicate or gap)"
    yellow "  → diff of expected vs actual check numbers:"
    diff <(echo "$EXPECTED_NUMS") <(echo "$ACTUAL_NUMS") | sed 's/^/    /' || true
    META_FAIL=1
fi
if ! grep -q "${CHECK_COUNT} checks today" CLAUDE.md; then
    DOC_CLAIM="$(grep -oE '[0-9]+ checks today' CLAUDE.md | head -1 || true)"
    red "✗ CLAUDE.md check count is stale: says '${DOC_CLAIM:-<none found>}', script has ${CHECK_COUNT}"
    yellow "  → update the '<N> checks today' sentence in CLAUDE.md's pre-deploy section"
    yellow "    (and add a one-line entry for any new check to the numbered list)."
    META_FAIL=1
fi
if [ "$META_FAIL" -gt 0 ]; then
    EXIT_CODE=1
else
    green "✓ ${CHECK_COUNT} checks, contiguous numbering, CLAUDE.md count in sync"
fi
echo

# ── Summary ──────────────────────────────────────────────────────────
if [ "$EXIT_CODE" -eq 0 ]; then
    green "✓ structural lints passed"
else
    red "✗ structural lints failed"
fi
exit "$EXIT_CODE"
