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

# ── Shared whole-tree scan scope ──────────────────────────────────────
# A repo-root walk (`find .` / `grep -r … .`) can descend into a SECOND
# CHECKOUT OF THIS SAME REPOSITORY and report ANOTHER BRANCH's code as a
# finding in this tree:
#
#   * `.claude/worktrees/<session>/` — agent worktrees. Every path-anchored
#     exemption in this script ("the one legal `engine_node_uuid`
#     implementation is `talos-workflow-engine-core/src/node_identity.rs`",
#     "the one legal manifest `dependencies` reader is
#     `talos-compilation/src/catalog.rs`") stops matching under a
#     `.claude/worktrees/<name>/` prefix, so BYTE-IDENTICAL code is
#     reported as a violation. Measured 2026-09-02 against a tree with six
#     sibling worktrees (5,518 extra `.rs` files): 110 red lines, 108 of
#     them from a worktree, on a checkout whose own content is clean —
#     and the two remaining lines were the INFLATED summary count and the
#     failure verdict. Runtime went 2:10 → 4:05 for the privilege.
#   * `.git/` — git metadata; submodule checkouts live under
#     `.git/modules/`.
#
# Only two files under `.claude/` are tracked (`hooks/session-start.sh`,
# `settings.json`) and neither is `.rs`, so pruning costs no coverage.
#
# EVERY whole-tree scan MUST use these. Site-specific prunes (target,
# vendor, node_modules) stay at the site — they vary by check and are not
# about second checkouts. Check 75 enforces the rule; it exists because
# eleven scans got this right by hand and the ten added after them did
# not, the newest of them two days old.
TREE_PRUNE_FIND=( -not -path '*/.claude/*' -not -path '*/.git/*' )
TREE_PRUNE_GREP=( --exclude-dir=.claude --exclude-dir=.git )

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
DEFAULT_DIRS="controller/src talos-secrets/src talos-dlp/src worker/src talos-worker-runtime/src"

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
# main.rs AND bootstrap/router.rs (build_router moved there in the 2026-07
# main.rs decomposition — the guardrail must follow the registrations) and
# normalise to the first path segment. Skip routes annotated
# `// no-nginx-route`. Both `route` and `nest` register a top-level path;
# nesting matters for things like `Router::new().nest("/mcp", …)`.
grep -nhE '\.(route|nest)\("/' controller/src/main.rs controller/src/bootstrap/router.rs \
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
    yellow "    // no-nginx-route on the .route() line (main.rs / bootstrap/router.rs)"
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
                controller/src talos-memory/src worker/src talos-worker-runtime/src module-templates 2>/dev/null \
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
#
# The output is CAPTURED, not discarded. It used to be `>/dev/null 2>&1` with
# a "re-run for diagnostics" hint, which made every clippy failure cost the
# build TWICE — and in a cold worktree that second build is tens of minutes.
# Same reasoning as check 35. Keeping the log on disk (rather than streaming
# it) preserves the one-line-per-check output shape on the passing path.
if [ "${TALOS_LINT_CLIPPY:-0}" = "1" ]; then
    CLIPPY_LOG="$(mktemp "${TMPDIR:-/tmp}/talos-clippy.XXXXXX")"
    if cargo clippy --workspace --no-deps -- -D warnings >"$CLIPPY_LOG" 2>&1; then
        green "✓ clippy --workspace --no-deps clean (-D warnings)"
        rm -f "$CLIPPY_LOG"
    else
        red "✗ clippy --workspace --no-deps failed (-D warnings)"
        # Only the diagnostics, not the "Compiling …" progress noise.
        grep -E '^(error|warning)' -A 12 "$CLIPPY_LOG" | head -200 || cat "$CLIPPY_LOG"
        yellow "  → full log: $CLIPPY_LOG"
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
    find . -name '*.rs' -not -path '*/target/*' "${TREE_PRUNE_FIND[@]}" \
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
    find . -name '*.rs' -not -path '*/target/*' "${TREE_PRUNE_FIND[@]}" \
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
bold "▶ check 10: discarded Result on an awaited call (raw sqlx everywhere; any callee in mcp-handlers)"

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
            "${TREE_PRUNE_GREP[@]}" \
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

# Leg (b), 2026-08-19 (#660): the raw-SQL leg above covers 2 of the 109
# non-test `let _ = <expr>.await` sites in the workspace. #658 found the
# gap the hard way — `handle_add_node_to_workflow` swallowed a REPOSITORY
# call, so a failed graph save still answered "Node added", and leg (a)
# structurally cannot see a repository method.
#
# The obvious widening — grepping the `let _ =` LINE for `.await` — was
# built and MEASURED, and it does not work: the house style for the calls
# that matter is a broken method chain, so 80 of the 109 sites span
# multiple lines. That widening sees 3 of the 42 problem sites (7.1%,
# below the <8% recall bar that already rejected an earlier lint), 0 of
# the 7 sites that report success on a failed write, and — reinstated by
# line index into the fixed tree — it does NOT fire on #658's own defect.
#
# So this leg is STATEMENT-aware (gather forward to the terminating `;`
# at depth 0) and SCOPED to `talos-mcp-handlers/src/`, where 40 of 41
# sites were (a)/(b): a handler is by definition about to answer a
# caller, so a Result it drops is one nobody will ever see. Same scoping
# principle as check 6 (raw sqlx here) and check 50 (raw sqlx in
# talos-api/src/schema). Ships at ZERO — every site was either converted
# to `if let Err(e) = … { warn!(…) }` or given the marker — so this is a
# hard rule from day one, not a ratchet.
#
# STATED LIMITS, each the safe (loud) direction:
#   * brace/paren counting is TEXTUAL, so a `{` or `(` inside a string
#     literal can end the statement early or late — early means `.await`
#     is not seen (a miss), late means a neighbouring `.await` is (a
#     false positive). Cross-validated against an independent Python
#     implementation (`scripts/lint-swallow-inventory.py`): both return
#     exactly the same 30 sites on the pre-fix tree, no disagreement.
#   * the `#[cfg(test)] mod` strip ends a region at the first column-0
#     `}`, so a raw string containing one leaves test code in the
#     haystack — a false POSITIVE, never a silent miss.
#   * it says nothing about `.ok()`, `unwrap_or_default()` on a write, or
#     `let _ =` on a non-awaited Result. Those are adjacent shapes this
#     check does not claim.
SWALLOW_AWAIT_VIOLATIONS=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    printf '  %s\n' "$line"
    SWALLOW_AWAIT_VIOLATIONS=$((SWALLOW_AWAIT_VIOLATIONS + 1))
done < <(
    find talos-mcp-handlers/src -name '*.rs' \
        ! -name '*_tests.rs' ! -name 'tests.rs' ! -name 'test_support.rs' \
        -print0 2>/dev/null \
    | xargs -0 perl -0777 -n -e '
        my @L = split /\n/, $_;
        my $n = scalar @L;
        # Strip #[cfg(test)] mod regions detected at column 0 (same conservative rule as
        # check 58: a mis-detected end leaves test code in the haystack — a false
        # POSITIVE here, which is loud, never a silent miss).
        my @skip = (0) x ($n + 1);
        for (my $i = 0; $i < $n; $i++) {
            next unless $L[$i] =~ /^#\[cfg\(test\)\]/;
            my $j = $i + 1;
            $j++ while ($j < $n && $j < $i + 4 && $L[$j] !~ /^(pub\s+)?mod\s/);
            next unless ($j < $n && $L[$j] =~ /^(pub\s+)?mod\s/);
            my $k = $j + 1;
            $k++ while ($k < $n && $L[$k] !~ /^\}/);
            $skip[$_] = 1 for ($i .. ($k < $n ? $k : $n - 1));
        }
        for (my $i = 0; $i < $n; $i++) {
            next if $skip[$i];
            my $l = $L[$i];
            next if $l =~ m{^\s*(//|\*)};
            next unless $l =~ /(?:^|[^\w.])let\s+_\s*=/;
            my ($depth, $stmt, $j) = (0, "", $i);
            for (; $j < $n && $j < $i + 40; $j++) {
                my $s = $L[$j];
                $s =~ s{//.*$}{};
                $depth += ($s =~ tr/([{//);
                $depth -= ($s =~ tr/)]}//);
                $stmt .= $L[$j] . "\n";
                last if ($s =~ /;\s*$/ && $depth <= 0);
            }
            next unless $stmt =~ /\.await/;
            my $ok = 0;
            my $lo = $i - 8; $lo = 0 if $lo < 0;
            for my $k ($lo .. $i) { $ok = 1 if $L[$k] =~ /allow-swallowed-result/; }
            next if $ok;
            printf("%s:%d:%s\n", $ARGV, $i + 1, $l);
        }
' 2>/dev/null || true
)

if [ "$SWALLOW_AWAIT_VIOLATIONS" -gt 0 ]; then
    red "✗ found $SWALLOW_AWAIT_VIOLATIONS discarded Results on awaited calls in talos-mcp-handlers/src"
    yellow "  → a handler is about to answer a caller: either propagate the error"
    yellow "    into the RESPONSE, or \`if let Err(e) = ...\` + WARN and say in the"
    yellow "    response what did not happen. A log alone is not a fix when the"
    yellow "    caller is being told the operation succeeded."
    yellow "  → or add // allow-swallowed-result: <reason> within 8 lines above"
    EXIT_CODE=1
else
    green "✓ no discarded Result on an awaited call in talos-mcp-handlers/src"
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
            "${TREE_PRUNE_GREP[@]}" \
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
            "${TREE_PRUNE_GREP[@]}" \
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
# `crate::utils::ensure_graph_within_caps` (or the `save_graph_json`
# helper in graph.rs that wraps it) BEFORE
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
#   * `.update_workflow_graph_unchecked(`  (deleted in #658; the
#     alternation is kept so a reintroduction is still caught)
#   * `.update_workflow_graph_json(`
# in `talos-mcp-handlers/` UNLESS the matched line is preceded within
# 8 lines by either `ensure_graph_within_caps` (the canonical
# chokepoint call) or `validate_graph_timeouts` (the underlying
# canonical validator — same contract). The declaration in
# `graph.rs::save_graph_json` IS the chokepoint, so it self-opts-out
# via `ensure_graph_within_caps` inside its own body.
#
# NOTE (#658): this check is NOT a tenancy guard and never was — it
# only requires the CAP validator near the write. Tenancy on the
# graph_json write is now carried by the statement itself
# (`AND user_id = $3`), after `update_workflow_graph_unchecked` was
# deleted and its six handlers routed through the checked twin.
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
    yellow "    save_graph_json helper in graph.rs that already wraps it."
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
            controller/src worker/src talos-worker-runtime/src talos-engine talos-workflow-engine \
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
# This check fires only on `worker/src/**/*.rs` + the extracted
# `talos-worker-runtime/src/**/*.rs` (the worker's library half moved
# there in July 2026). The protocol crate's own tests + the
# JobRequest::sign (request, not result) flows are out of scope.
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
            worker/src talos-worker-runtime/src 2>/dev/null \
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

WORKER_RS_FILES=$(find worker/src talos-worker-runtime/src -name '*.rs' \
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
# runtime.rs moved worker/src → talos-worker-runtime/src (July 2026 lib
# extraction); the fallback path keeps the check working on older branches.
RUNTIME_FILE="talos-worker-runtime/src/runtime.rs"
[ -f "$RUNTIME_FILE" ] || RUNTIME_FILE="worker/src/runtime.rs"
if [ -f "$RUNTIME_FILE" ]; then
    for proposal in "${REQUIRED_PROPOSALS[@]}"; do
        # Use literal string match (-F) since the pattern contains parens.
        if ! grep -qF "$proposal" "$RUNTIME_FILE"; then
            printf '  missing required call: config.%s\n' "$proposal"
            PROPOSAL_VIOLATIONS=$((PROPOSAL_VIOLATIONS + 1))
        fi
    done
else
    yellow "  (runtime.rs not found in talos-worker-runtime/src or worker/src — skipping check)"
fi

if [ "$PROPOSAL_VIOLATIONS" -gt 0 ]; then
    red "✗ $PROPOSAL_VIOLATIONS WASM proposal lockdown call(s) missing in $RUNTIME_FILE"
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
#
# This is the ONLY rustfmt run in `make lint`. The Makefile used to run
# `cargo fmt --all -- --check` as well, immediately before invoking this
# script — identical coverage, twice the wall-clock. This copy is the one
# kept because it NAMES the drifted files.
#
# The output is CAPTURED rather than discarded: the previous
# `>/dev/null 2>&1` + "re-run to see it" made the operator pay for the check
# a second time to learn anything from it.
if ! command -v cargo >/dev/null 2>&1; then
    yellow "⊘ fmt check skipped (cargo not on PATH)"
else
    FMT_LOG="$(mktemp "${TMPDIR:-/tmp}/talos-fmt.XXXXXX")"
    if cargo fmt --all -- --check >"$FMT_LOG" 2>&1; then
        green "✓ rustfmt clean (cargo fmt --all -- --check)"
        rm -f "$FMT_LOG"
    else
        red "✗ rustfmt drift detected"
        # `cargo fmt --check` emits `Diff in <path> at line N:` headers; those
        # are the actionable part. Fall back to the raw log if the format ever
        # changes, so this can never print nothing.
        if grep -E '^Diff in ' "$FMT_LOG" | sort -u | head -60; then :; else
            head -60 "$FMT_LOG"
        fi
        yellow "  → run \`cargo fmt --all\` to fix (formatting-only, AST-token-preserving)"
        yellow "  → full diff: $FMT_LOG"
        EXIT_CODE=1
    fi
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
                if ($body =~ /\b(api_key|client_secret|signing_secret|verification_token|bot_token|access_token|refresh_token|private_key|secret_key|password|push_token)\s*:\s*(?:Option<\s*)?String/) {
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
        -e 'allow_wasi_network[[:space:]]*=' worker/ talos-worker-runtime/ 2>/dev/null || true)
else
    wn_matches=$(grep -rnE --include='*.rs' 'allow_wasi_network[[:space:]]*=' worker/ talos-worker-runtime/ 2>/dev/null || true)
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
# worker/src added 2026-07-19 (L5): the worker's NATS connection carries the
# same PHI/credential exposure as the controller's, so its plaintext-scheme gate
# must fail closed too. EVERY marker occurrence is validated (not just the
# first) so a second gate softened back to warn-only is still caught.
for gate in redis nats postgres neo4j; do
    # Match STANDALONE marker lines (`    // tls-prod-gate-<name>`) only — this
    # is the comment placed directly above each gate. A mid-sentence mention in
    # a `///` doc comment (e.g. "See `tls-prod-gate-postgres`.") is a reference,
    # not a gate, and must not be validated for a fail-closed action.
    hits=$(grep -rnE "^[[:space:]]*//[[:space:]]*tls-prod-gate-${gate}\b" --include='*.rs' controller/src talos-db/src worker/src talos-worker-runtime/src 2>/dev/null || true)
    if [ -z "$hits" ]; then
        red "✗ missing production TLS gate marker: tls-prod-gate-${gate}"
        TLS_GATE_VIOLATIONS=$((TLS_GATE_VIOLATIONS + 1))
        continue
    fi
    while IFS= read -r hit; do
        [ -z "$hit" ] && continue
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
    done <<< "$hits"
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
# talos-github / talos-google-cloud / talos-integration-helpers added
# 2026-07-19 (L7): they also carry Bearer/token credentials to configurable or
# fixed hosts, so a dropped redirect(none()) there is the same leak class.
integ_client_matches=$(grep -rnE 'reqwest::Client::builder\(\)' \
    talos-gmail/src talos-google-calendar/src talos-slack/src \
    talos-atlassian/src talos-oauth/src talos-github/src \
    talos-google-cloud/src talos-integration-helpers/src 2>/dev/null \
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
# THE MULTI-LINE HOLE IS NOW CLOSED (#661, 2026-08-19). This comment used to
# say a read split across lines "still slips past this line-based grep; those
# are rare and caught in review." Measured: FIVE such reads existed while the
# line-based grep reported 0 workspace-wide on a check that had been GRADUATED
# to a hard rule — and the sharpest of them (`timezone` in the workflow-schedule
# export row, `talos-workflow-repository/src/workflows.rs:1881`) silently ran
# every exported cron in UTC. "Rare and caught in review" was an assumption, not
# a measurement, and review had not caught them in the thirteen months the hole
# was documented. The perl pass below is statement-aware: it matches a
# `try_get(...)` whose `.unwrap_or` continues on the NEXT line with nothing but
# whitespace between. An intervening `?` (or `.context(...)?`) breaks the match,
# which is correct — that IS the fixed form, and it is what keeps
# `talos-registry/src/lib.rs`'s `.context(...)?.unwrap_or_else(...)` out of the
# results. Verified against the pre-fix tree: the pass reports exactly those 5
# and nothing else.
#
# STATED LIMIT, because overstating a lint is the defect one level up: this
# check covers `.unwrap_or` ONLY. `.try_get(...).ok()` has identical semantics
# — a renamed/dropped/retyped column reads as `None`, never as an error — and
# is invisible to BOTH passes, on one line or many, because neither regex
# mentions `.ok`. Measured at the same time: **84 such reads workspace-wide**,
# including the `value_enc` / `value_key_id` encryption-envelope columns in
# `talos-memory` that check 34's sibling `value_format` read is specifically
# hardened for. That is a burn-down cycle, not a lint change: gating it today
# would mean re-adding a baseline, which this check's own rule above forbids.
bold "▶ check 52: silent try_get().unwrap_or reads (workspace-wide, must be 0)"
# `|| true`: now that the count is 0, `grep -c` finds no matches and exits 1,
# which under this script's `set -euo pipefail` would abort here — the very
# success case (fully burned down) must not fail the script. awk still prints 0.
# --exclude-dir: target (build artifacts), .git, .claude (session worktrees
# checked out INSIDE the repo dir would otherwise re-surface stale copies),
# node_modules (defensive; frontend has no .rs but the walk is cheaper skipped).
REPO_SILENT_READ_COUNT="$( { grep -rEc '\.try_get(::<[^(]*>)?\([^)]*\)\.unwrap_or' \
        --include='*.rs' \
        --exclude-dir=target --exclude-dir=node_modules "${TREE_PRUNE_GREP[@]}" \
        . 2>/dev/null || true; } \
    | awk -F: '{s+=$2} END {print s+0}')"
if [ "$REPO_SILENT_READ_COUNT" -ne 0 ]; then
    red "✗ ${REPO_SILENT_READ_COUNT} silent try_get().unwrap_or read(s) workspace-wide (must be 0):"
    grep -rEn '\.try_get(::<[^(]*>)?\([^)]*\)\.unwrap_or' --include='*.rs' --exclude-dir=target --exclude-dir=node_modules "${TREE_PRUNE_GREP[@]}" . 2>/dev/null | sed 's/^/    /'
    yellow "  → a renamed/dropped column would read as a silent default, not an error."
    yellow "    Read as Option and propagate: .try_get::<Option<_>, _>(\"col\")?.unwrap_or(default)"
    yellow "    or use a typed FromRow / query_as! mapping."
    EXIT_CODE=1
else
    green "✓ no silent try_get().unwrap_or reads workspace-wide (single-line)"
fi
# 52b: the same read split across two lines. Line-based grep cannot see it;
# this per-file perl pass can. Must also be 0 — same rule, same fix.
REPO_SILENT_READ_ML="$(find . -name '*.rs' \
        -not -path './target/*' -not -path './node_modules/*' \
        "${TREE_PRUNE_FIND[@]}" -print0 2>/dev/null \
    | xargs -0 perl -ne 'BEGIN{$/=undef} my @l=split/\n/,$_; for my $i (0..$#l-1){ next if $l[$i]=~/\?/; if ($l[$i]=~/\.try_get(?:::<[^(]*>)?\([^)]*\)\s*$/ && $l[$i+1]=~/^\s*\.unwrap_or/){ print "$ARGV:".($i+1)."\n" } }' 2>/dev/null)"
REPO_SILENT_READ_ML_COUNT="$(printf '%s' "$REPO_SILENT_READ_ML" | grep -c . || true)"
if [ "$REPO_SILENT_READ_ML_COUNT" -ne 0 ]; then
    red "✗ ${REPO_SILENT_READ_ML_COUNT} MULTI-LINE silent try_get().unwrap_or read(s) (must be 0):"
    printf '%s\n' "$REPO_SILENT_READ_ML" | sed 's/^/    /'
    yellow "  → same class as check 52 above, split across lines so the grep misses it."
    yellow "    Fix: .try_get::<Option<_>, _>(\"col\")?.unwrap_or(default)"
    EXIT_CODE=1
else
    green "✓ no multi-line silent try_get().unwrap_or reads workspace-wide"
fi

# 52c/52d: the SAME read spelled `.try_get(...).ok()`. Identical in effect to
# the `.unwrap_or` form above — a renamed / dropped / retyped column produces
# Err, `.ok()` turns it into None, and the caller cannot tell that from a
# legitimate SQL NULL — and invisible to BOTH passes above, on one line or many,
# because neither regex mentions `.ok`. #661 measured it at 84 and deliberately
# did NOT gate it, because gating above zero would have meant re-adding the
# baseline this check's own header forbids. #662 burned the population down and
# the gate follows AT ZERO.
#
# The population as found was 90, not 84: the line grep #661 used misses the 7
# sites where the house style breaks the chain after `("col")` and puts `.ok()`
# on the next line, and falsely counts 1 that is prose inside a #661 comment.
# So this leg is a single statement-aware perl pass rather than a grep + a
# multi-line sibling:
#   * line comments are stripped first (only where the `//` is OUTSIDE a string
#     literal), which is what keeps talos-secrets-manager/src/manager.rs's #661
#     note — a comment that QUOTES the forbidden pattern — out of the results;
#   * the turbofish allows ONE level of nested angle brackets, because a flat
#     `[^>]*>` stops at the inner `>` of `::<Option<i64>, _>` and silently misses
#     every such site (the inventory script's own first version did exactly that
#     and under-counted by 8);
#   * `\s*` between the argument list and `.ok()` spans newlines, so 52c and 52d
#     are one pass, not two.
# VERIFIED AGAINST THE ORIGINAL TREE (the #624 rule): run over the pre-fix
# copies of the 17 touched files it reports exactly 90 sites, and that set is
# byte-for-byte the inventory in docs/swallowed-results-inventory.md Part 3.
#
# STATED LIMIT: this is still a CHAIN matcher. `let r = row.try_get("c"); …
# r.ok()` through a variable, `.map_or(…)`, and the control-flow
# `match row.try_get(…) { Err(_) => … }` shape are all invisible to it. Measured
# at the same time: 0, 0 and 14 respectively (the 14 are per-site judgements —
# several are the shape used CORRECTLY, e.g. probing an unknown column's type —
# so a blanket gate there would be wrong). Fix a hit by reading as
# `.try_get::<Option<_>, _>("col")?` (NULL still yields None, drift errors), or
# for a NOT NULL column the plain `.try_get("col")?`. Do NOT re-add a baseline.
TRYGET_OK_PERL='BEGIN{$/=undef}
my @lines = split /\n/, $_, -1;
for my $l (@lines) {
    my $q = 0; my $i = 0; my $cut = -1;
    while ($i < length($l)) {
        my $c = substr($l,$i,1);
        if ($c eq "\\\\") { $i += 2; next }
        if ($c eq "\"") { $q = 1 - $q }
        elsif ($c eq "/" && $q == 0 && substr($l,$i+1,1) eq "/") { $cut = $i; last }
        $i++;
    }
    $l = substr($l,0,$cut) if $cut >= 0;
}
my $code = join("\n", @lines);
my @nl = (0);
while ($code =~ /\n/g) { push @nl, pos($code) }
while ($code =~ /\.try_get(?:::<(?:[^<>()]|<[^<>()]*>)*>)?\s*\((?:[^()]|\([^()]*\))*\)\s*\.\s*ok\s*\(\s*\)/gs) {
    my $p = $-[0];
    my ($lo,$hi) = (0, $#nl);
    while ($lo < $hi) { my $m = int(($lo+$hi+1)/2); if ($nl[$m] <= $p) { $lo = $m } else { $hi = $m-1 } }
    print "$ARGV:" . ($lo+1) . "\n";
}'
TRYGET_OK_HITS="$(find . -name '*.rs' \
        -not -path './target/*' -not -path './node_modules/*' \
        "${TREE_PRUNE_FIND[@]}" -print0 2>/dev/null \
    | xargs -0 perl -ne "$TRYGET_OK_PERL" 2>/dev/null || true)"
TRYGET_OK_COUNT="$(printf '%s' "$TRYGET_OK_HITS" | grep -c . || true)"
if [ "$TRYGET_OK_COUNT" -ne 0 ]; then
    red "✗ ${TRYGET_OK_COUNT} silent try_get().ok() read(s) workspace-wide (must be 0):"
    printf '%s\n' "$TRYGET_OK_HITS" | sed 's/^/    /'
    yellow "  → same class as check 52: a renamed/dropped column reads as None,"
    yellow "    indistinguishable from a SQL NULL, never as an error."
    yellow "    Fix: .try_get::<Option<_>, _>(\"col\")?  (NOT NULL column: .try_get(\"col\")?)"
    EXIT_CODE=1
else
    green "✓ no silent try_get().ok() reads workspace-wide (single- and multi-line)"
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
UNGUARDED_CN="$(grep -rEn 'Component::new\(' --include='*.rs' worker/src talos-worker-runtime/src 2>/dev/null \
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

# ── 55. Bare `row.get(` / `r.get(` on sqlx rows in DB-layer crates — RATCHET ──
# `row.get("col")` PANICS (not Err) on a NULL column or a type drift —
# the unwind kills the tokio worker task mid-request and the caller sees
# a bare connection reset. Found live 2026-07-08 (#427): the first
# workflow-bound webhook (NULL module_id, legal by schema) made every
# list_webhooks call die this way. This is the PANIC-side sibling of
# check 52 (silent-default reads): the correct fail-loud idiom is
# `try_get` + `?` — same loudness, clean error instead of a task-killing
# unwind. Scope: the DB-layer crates where `r`/`row` reliably means a
# sqlx row (repository crates + the check-52 widened family); sampled
# 0 json-`.get` false positives in scope.
#
# Introduced 2026-07-08 as a RATCHET at 473 sites (#428, webhook-repository
# exemplar 8→0); FULLY BURNED DOWN same day (465→0 across all nine remaining
# crates via the check-52 playbook) and GRADUATED to a HARD RULE: the count
# must stay 0 — any new bare `.get` sqlx read in a DB-layer crate is an
# outright failure. Convert with `try_get(...)?`; do NOT re-add a baseline.
bold "▶ check 55: bare row.get() sqlx reads in DB-layer crates (must be 0)"
BARE_ROW_GET_BASELINE=0
BARE_ROW_GET_SCOPE="talos-actor-repository talos-advanced-repository talos-analytics-repository \
    talos-execution-repository talos-github-repository talos-module-repository \
    talos-webhook-repository talos-worker-identity-repository talos-workflow-repository \
    talos-schedule-repo talos-memory talos-secrets-manager talos-registry \
    talos-module-executions talos-integration-state talos-auth talos-ml"
# shellcheck disable=SC2086
BARE_ROW_GET_COUNT="$( { grep -rEc '(row|r)\.get(::<[^(]*>)?\("' \
        --include='*.rs' \
        $BARE_ROW_GET_SCOPE 2>/dev/null || true; } \
    | awk -F: '{s+=$2} END {print s+0}')"
# subtract try_get lines the broad regex also matched (try_get contains ".get" only
# when preceded by "try_" — the regex above does NOT match try_get, but keep the
# guard cheap and explicit in case of drift)
if [ "$BARE_ROW_GET_COUNT" -gt "$BARE_ROW_GET_BASELINE" ]; then
    red "✗ ${BARE_ROW_GET_COUNT} bare row.get() sqlx read(s) in DB-layer crates (must be 0):"
    # shellcheck disable=SC2086
    grep -rEn '(row|r)\.get(::<[^(]*>)?\("' --include='*.rs' $BARE_ROW_GET_SCOPE 2>/dev/null | sed 's/^/    /'
    yellow "  → a bare .get panics on NULL/type-drift and kills the request task (connection"
    yellow "    reset — the #427 list_webhooks incident). Use .try_get(\"col\")? — or, for"
    yellow "    NULLABLE columns, .try_get::<Option<_>, _>(\"col\")? with an explicit default."
    EXIT_CODE=1
else
    green "✓ no bare row.get() sqlx reads in DB-layer crates (hard rule, graduated from the 473-site ratchet)"
fi
echo

# ── 56. Unresolved effective-actor engine binding ─────────────────────
# The engine's fail-safe default for an UNBOUND actor is Tier-1
# (local-egress-only) — correct as a fail-safe, catastrophic as an
# accident: a dispatch path that builds an engine without resolving the
# effective actor makes the same workflow behave differently per trigger
# path (PR #461: unbound scheduled workflows died for 16h with generic
# `networkerror` while manual triggers worked; the review then found the
# identical defect pre-existing on the retry, replay, webhook-router and
# continuation paths). The Phase D2 contract: run the authorization gate
# (whose Phase D1 fallback resolves the user's default actor) via
# `talos_workflow_authorization::resolve_effective_actor` and bind ITS
# answer — never a literal `None`. Opt-out for deliberate fail-safe
# paths: `// allow-unresolved-effective-actor: <reason>` within 8 lines
# above the call.
bold "▶ check 56: with_effective_actor(None, …) without gate-resolved actor"
UNRESOLVED_ACTOR_HITS="$(grep -rn 'with_effective_actor(None,' \
        --include='*.rs' \
        talos-engine/src talos-scheduler/src talos-webhooks/src \
        talos-continuation-trigger/src talos-execution-orchestration/src \
        talos-mcp-handlers/src talos-api/src controller/src 2>/dev/null \
    | grep -v 'src/builder.rs' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' \
    | while IFS= read -r hit; do
        f="${hit%%:*}"; n="$(echo "$hit" | cut -d: -f2)"
        start=$(( n > 8 ? n - 8 : 1 ))
        if ! sed -n "${start},${n}p" "$f" | grep -q 'allow-unresolved-effective-actor'; then
            echo "$hit"
        fi
    done)"
if [ -n "$UNRESOLVED_ACTOR_HITS" ]; then
    red "✗ engine built with a literal-None effective actor (Tier-1 fail-safe by accident):"
    echo "$UNRESOLVED_ACTOR_HITS" | sed 's/^/    /'
    yellow "  → resolve the actor through the authorization gate"
    yellow "    (talos_workflow_authorization::resolve_effective_actor) and bind its answer,"
    yellow "    so authorization, attribution, and runtime tier use one value (PR #461)."
    yellow "  → deliberate fail-safe paths: // allow-unresolved-effective-actor: <reason>"
    yellow "    within 8 lines above the call."
    EXIT_CODE=1
else
    green "✓ no unresolved-effective-actor engine bindings"
fi
echo

# ── 57. Sub-engine builds must bind the sub-actor + narrow ceilings ────
# H2 (PR #504): a sub-engine built via `adapter_set().into_engine_with_graph(…)`
# inherits the PARENT's `actor_id` / `max_llm_tier` / `max_write_ceiling`
# verbatim. Two escalation/correctness gaps: (a) if the sub-workflow is bound to
# a MORE restrictive actor (Tier-1 / read-only), running it at the parent's
# looser ceiling is a privilege escalation across the sub-workflow boundary; and
# (b) the sub-workflow's direct `agent_memory` RPCs would resolve against the
# PARENT's actor rather than its own bound actor — silently disagreeing with the
# __actor_context__ injection path and writing memory into the wrong actor
# (identity axis added 2026-07). #504 + the identity fix close both at three
# build sites via the single chokepoint `bind_subengine_actor_and_ceilings`
# (execute_subworkflow_graph, dynamic/capability dispatch, agent-loop via
# `resolve_subworkflow_binding` hoisted before the loop) — but nothing stops a
# FOURTH build site (a new system-node kind, a new parallel executor) from
# compiling, running, and silently widening / mis-scoping. Same class as checks
# 29/56: the compiler can't see it, review might miss it, so freeze it here. Any
# file with a non-test `into_engine_with_graph(` call must also reference the
# binding chokepoint, or opt out with `// allow-unnarrowed-subengine: <reason>`
# within 8 lines above (for deliberate parent-context clones that keep the
# parent's own identity + ceilings).
bold "▶ check 57: sub-engine built without actor-bind + ceiling narrowing (H2 escalation guard)"
UNNARROWED_SUBENGINE_HITS="$(grep -rn 'into_engine_with_graph(' \
        --include='*.rs' \
        talos-* worker controller 2>/dev/null \
    | grep -vE '/tests/|_tests\.rs' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|///|//!)' \
    | grep -vE 'fn into_engine_with_graph' \
    | while IFS= read -r hit; do
        f="${hit%%:*}"; n="$(echo "$hit" | cut -d: -f2)"
        # File-level: the chokepoint (or its resolver) referenced anywhere in
        # the same file counts — the three #504 sites all qualify.
        if grep -qE 'bind_subengine_actor_and_ceilings|resolve_subworkflow_binding' "$f"; then
            continue
        fi
        start=$(( n > 8 ? n - 8 : 1 ))
        if sed -n "${start},${n}p" "$f" | grep -q 'allow-unnarrowed-subengine'; then
            continue
        fi
        echo "$hit"
    done)"
if [ -n "$UNNARROWED_SUBENGINE_HITS" ]; then
    red "✗ sub-engine build site(s) without ceiling narrowing (H2 escalation re-opened):"
    echo "$UNNARROWED_SUBENGINE_HITS" | sed 's/^/    /'
    yellow "  → after into_engine_with_graph(…), call"
    yellow "    self.bind_subengine_actor_and_ceilings(&mut sub_engine, sub_wf_id, user_id).await"
    yellow "    (or hoist resolve_subworkflow_binding once for loop bodies) so the sub-engine"
    yellow "    adopts the sub-actor's identity and runs at most_restrictive(parent, sub-actor)."
    yellow "  → deliberate parent-context clones: // allow-unnarrowed-subengine: <reason>"
    EXIT_CODE=1
else
    green "✓ every sub-engine build site narrows ceilings (or is explicitly opted out)"
fi
# ── 58. Registered-but-never-incremented Prometheus metric (dead metric) ──
# A metric field on `TalosMetrics` that is declared + registry.register()ed
# but never actually mutated is DEAD: it stays flat at 0 forever, so any
# Prometheus alert / dashboard built on it silently never fires. This is
# how the 2026-07-24 workflow failure-rate alert would have been born
# useless — `talos_workflow_executions_total` was registered but had zero
# `.inc()` sites (fixed in #570 by wiring the mark_execution_* chokepoints).
#
# Detection: for every metric collector field in the struct, require at
# least one LIVE mutation somewhere in the workspace — `.field … .inc()/
# .inc_by(nonzero)/.add()/.dec()/.observe()/.set()/.set_to_current_time()`.
# The `new()` registration (`let field = …::new`, `register(Box::new(
# field.clone()))`) and the pre-seed loops (`field.with_label_values(…)
# .inc_by(0.0)` on the BARE local) don't match — real increments go
# through `self.field`/`m.field` (leading dot); registration/seed use the
# bare local.
#
# TEST CODE IS NOT PRODUCTION CODE. A metric whose only mutation lives in
# a `#[cfg(test)] mod …` (or in a test-only source file) is still DEAD in
# production, and the alert built on it still never fires. Until 2026-07-31
# the check did NOT drop those regions — `talos_dek_cache_size` and
# `talos_module_payload_encryption_failures_total` read as LIVE solely
# because `talos-metrics`' own `crypto_invariant_metrics_render` unit test
# touches them, and that test exists specifically to prove the alerts on
# them would not silently stop firing. The lint written for this class was
# blind in this class. The haystack now drops each file's trailing
# `#[cfg(test)] mod` region and skips test-only source files (see the perl
# below for the exact, deliberately conservative rule). Opt out for a
# genuinely externally-set/scrape-only metric with
# `// allow-unincremented-metric: <reason>` on the field's
# struct-declaration line.
#
# WHAT THIS CHECK STILL CANNOT SEE (state it, do not imply otherwise —
# overstating a lint is the same defect one level up). The haystack is
# TEXTUAL, so an increment wrapped in a helper reads as live even when
# NOTHING CALLS THE HELPER: `record_outcome` (crash_recovery_total),
# `publish_dek_cache_size`, `inc_auth_attempt` / `inc_auth_failure`,
# `inc_payload_crypto_failure` and `inc_secret_decrypt_failure` are all
# one-site wrappers, so deleting every CALL SITE leaves this check green.
# Verified by mutation 2026-07-31: gutting a wrapper BODY is caught;
# deleting all its call sites is not. Closing that needs a call-graph, not
# a grep — so the guard for call sites is the per-metric production-path
# unit test (talos-auth auth_metric_tests, the dek_cache_size fill/drain
# test, payload_crypto_failures_are_counted_on_the_production_path). When
# you wire a metric through a wrapper, ship that test with it.
bold "▶ check 58: registered Prometheus metric never incremented (dead metric)"
METRICS_LIB="talos-metrics/src/lib.rs"
if [ -f "$METRICS_LIB" ]; then
    DEAD_METRICS="$(
        find talos-* worker controller -name '*.rs' -not -path '*/target/*' 2>/dev/null \
            | grep -vE '/tests/|_tests?\.rs|/tests\.rs$|/test_support\.rs$' \
            | perl -e '
                # NB: NOT perl -0777 — that would put STDIN (the piped file
                # list) into slurp mode too; each `local $/;` slurp below is
                # scoped to its own block so the line-based STDIN read works.
                #
                # Dropping #[cfg(test)] mod regions, WITHOUT brace matching.
                # Counting braces without a real tokenizer desyncs on `{`/`}`
                # inside string/char literals (manager.rs crypto code
                # triggered exactly this), producing FALSE POSITIVES that
                # block correct PRs — the cardinal sin for a structural lint.
                # And truncating to EOF at the first `#[cfg(test)] mod` is
                # WRONG too: crash_recovery.rs keeps ~90 lines of production
                # code (incl. its crash_recovery_total increment) AFTER its
                # test module, so truncation invents a dead metric.
                #
                # Instead: a COLUMN-0 `#[cfg(test)]` attached to a COLUMN-0
                # `mod` opens a region that ends at the next line beginning
                # with `}` in column 0. rustfmt guarantees a top-level items
                # closing brace sits in column 0, and nothing nested inside
                # the module can — except a line inside a multi-line raw
                # string. That single failure mode ENDS THE REGION EARLY,
                # i.e. leaves test code in the haystack (a false NEGATIVE,
                # the safe direction). It can never swallow production code.
                #
                # Deliberately conservative elsewhere too, all in the same
                # safe direction (test code may remain in the haystack, prod
                # code is never removed from it):
                #  * an INDENTED `#[cfg(test)]` (a test mod nested inside
                #    another mod) is not matched at all.
                #  * a `#[cfg(test)]` on a fn/const/use (a test-only HELPER
                #    mid-file, ~14 sites workspace-wide) opens no region —
                #    only `mod` does.
                my $lib = shift @ARGV;
                my $src;
                { open(my $fh, "<", $lib) or die "open $lib: $!"; local $/; $src = <$fh>; close $fh; }
                # Field names from the TalosMetrics struct (metric collector
                # types only; `registry: Registry` and non-metric fields are
                # excluded by the type allow-list).
                my ($struct) = $src =~ /pub struct TalosMetrics \{(.*?)\n\}/s;
                my @fields; my %optout;
                for my $line (split /\n/, ($struct // "")) {
                    if ($line =~ /pub (\w+):\s*(?:Int)?(?:Counter|Gauge|Histogram)(?:Vec)?\b/) {
                        my $f = $1;
                        push @fields, $f;
                        $optout{$f} = 1 if $line =~ m{//\s*allow-unincremented-metric};
                    }
                }
                # Haystack: every workspace .rs (test-only files already
                # excluded by the caller), with each `#[cfg(test)] mod`
                # region removed so a test-only increment cannot mask a dead
                # metric. Newlines collapsed so a multi-line
                # `.field .with_label_values(..) .inc()` matches as one stmt.
                my $hay = "";
                while (my $f = <STDIN>) {
                    chomp $f;
                    open(my $g, "<", $f) or next;
                    my $c; { local $/; $c = <$g>; } close $g;
                    $c = "" unless defined $c;
                    my @lines = split /\n/, $c, -1;
                    my @keep;
                    my $in_test = 0;
                    for (my $i = 0; $i < scalar(@lines); $i++) {
                        my $l = $lines[$i];
                        if ($in_test) {
                            # Column-0 `}` closes the top-level test module.
                            $in_test = 0 if $l =~ /^\}/;
                            next;
                        }
                        if ($l =~ /^\#\[cfg\(test\)\]/) {
                            # What does this attribute apply to? Skip any
                            # further column-0 attribute lines in between
                            # (e.g. #[path = "..._tests.rs"]).
                            my $tail = $l;
                            $tail =~ s/^\#\[cfg\(test\)\]\s*//;
                            my $j = $i;
                            while ($tail eq "" && $j + 1 < scalar(@lines)) {
                                $j++;
                                next if $lines[$j] =~ /^\#\[/;
                                $tail = $lines[$j];
                                last;
                            }
                            if ($tail =~ /^(?:pub(?:\([^)]*\))?\s+)?mod\s/) {
                                # `mod tests;` file mount: no inline body, and
                                # the mounted file is already excluded by the
                                # caller path filter. Drop just these lines.
                                $in_test = 1 unless $tail =~ /;\s*$/;
                                $i = $j;
                                next;
                            }
                        }
                        push @keep, $l;
                    }
                    $hay .= " " . join("\n", @keep);
                }
                # Tripwire on the strip itself. The blind spot this check
                # shipped with was invisible precisely because a BROKEN
                # haystack still produces a plausible-looking answer — it
                # just quietly calls dead metrics live. So assert both
                # directions against two known landmarks. Rename either and
                # this fires — which is the point; re-point it at a current
                # landmark rather than deleting the assert.
                #
                # NB: no apostrophes anywhere in this perl block — it is
                # single-quoted in the surrounding shell, so one ends the
                # program mid-comment.
                #
                # UNDER-strip landmark: a name that exists ONLY inside the
                # `#[cfg(test)] mod tests` of talos-metrics/src/lib.rs — and
                # it is the very test whose touch made talos_dek_cache_size
                # and talos_module_payload_encryption_failures_total read
                # live for months. It must be gone from the haystack.
                #
                # OVER-strip landmark: MUST be production code that sits
                # AFTER a `#[cfg(test)] mod` IN THE SAME FILE, or the assert
                # is vacuous. The first version of this tripwire used
                # `pub fn record_workflow_outcome`, which lives near the TOP
                # of talos-metrics/src/lib.rs, ABOVE the test module in that
                # file — so the exact regression the assert names (truncate
                # each file to EOF at its first `#[cfg(test)]`) left the
                # landmark untouched, the tripwire stayed silent, and the
                # check falsely reported crash_recovery_total dead.
                # `record_outcome` is the crash_recovery_total increment in
                # talos-execution-orchestration/src/crash_recovery.rs, ~50
                # lines BELOW the test module in that same file: exactly the
                # production code truncation would swallow. Verified by
                # mutation 2026-07-31 — neutering the region-close makes
                # this fire.
                my $strip_broken = ($hay =~ /crypto_invariant_metrics_render/) ? 1 : 0;
                my $overstripped = ($hay =~ /fn record_outcome\(outcome: &str, n: u64\)/) ? 0 : 1;
                print "__CFG_TEST_STRIP_BROKEN__\n" if $strip_broken;
                print "__CFG_TEST_OVERSTRIPPED__\n" if $overstripped;
                $hay =~ s/\s+/ /g;
                for my $field (@fields) {
                    next if $optout{$field};
                    # Reset the m//g scan position: scalar m//g maintains
                    # pos($hay) ACROSS these per-field while loops, so after a
                    # field matches LIVE and we `last`, the next field would
                    # resume mid-haystack and miss its own earlier increments
                    # (order-dependent false positives). Start each field at 0.
                    pos($hay) = undef;
                    my $live = 0;
                    while ($hay =~ /\.\Q$field\E\b([^;]*?)\.(inc|inc_by|add|dec|observe|set|set_to_current_time)\s*\(([^)]*)\)/g) {
                        my ($method, $args) = ($2, $3);
                        # Pre-seed / no-op: .inc_by(0), .inc_by(0.0), .inc_by(0f64)
                        next if $method eq "inc_by" && $args =~ /^\s*0(?:\.0*)?(?:f64)?\s*$/;
                        $live = 1; last;
                    }
                    print "$field\n" unless $live;
                }
            ' "$METRICS_LIB"
    )"
    DEAD58_SELFTEST=0
    if printf '%s\n' "$DEAD_METRICS" | grep -qx '__CFG_TEST_STRIP_BROKEN__'; then
        red "✗ check 58 is not stripping #[cfg(test)] mod regions — every result below is untrustworthy"
        yellow "  → a metric mutated only by a unit test would read as LIVE, which is the"
        yellow "    exact defect this check was blind to until 2026-07-31 (talos_dek_cache_size"
        yellow "    and talos_module_payload_encryption_failures_total both shipped alerts that"
        yellow "    could never fire). Fix the strip in the perl above; do not delete this assert."
        DEAD58_SELFTEST=1
    fi
    if printf '%s\n' "$DEAD_METRICS" | grep -qx '__CFG_TEST_OVERSTRIPPED__'; then
        red "✗ check 58 stripped PRODUCTION code out of its haystack (over-truncation)"
        yellow "  → every metric flagged below may be a false positive. The strip must only"
        yellow "    remove #[cfg(test)] mod regions — never truncate a file to EOF, which"
        yellow "    would swallow the ~90 lines of production code after crash_recovery.rs's"
        yellow "    test module."
        DEAD58_SELFTEST=1
    fi
    DEAD_METRICS="$(printf '%s\n' "$DEAD_METRICS" | grep -vxE '__CFG_TEST_(STRIP_BROKEN|OVERSTRIPPED)__' || true)"
    # Burn-down baseline (introduced 2026-07-24 with this check, like checks
    # 52/55): metrics that were already declared + registered but never
    # instrumented when the check landed. The check FAILS only on a NEW dead
    # metric — these are pre-existing observability debt to wire down over
    # time. To burn one down: add a real increment site AND delete it from
    # this list (a now-live baseline entry is itself a failure below, so the
    # list can't rot). Do NOT add to this list to silence the check — a new
    # dead metric means the alert/dashboard you're building is inert; wire it.
    #
    # 2026-07-31: 14 → 12. `auth_attempts_total` + `auth_failures_total` were
    # burned down because an alert (TalosControllerHighErrorRate) was already
    # shipping against them and therefore could never fire. That is the
    # priority order for the rest of this list: a dead metric with NO alert is
    # debt; a dead metric WITH an alert is a false assurance.
    #
    # 2026-08-11: 12 → 10. `circuit_breaker_opens_total` +
    # `circuit_breaker_blocks_total` were not burned down where they stood —
    # they were DELETED from talos-metrics, because they were declared in the
    # wrong process. The breaker they name is a per-process singleton in the
    # WORKER (`talos-worker-runtime/src/circuit_breaker.rs`); no controller-side
    # increment site could ever have existed. They are now produced there, under
    # the same names, via the worker's already-scraped `/metrics`.
    #
    # THE CLAIM THAT USED TO SIT HERE, AND WHY IT IS NOW A CHECK. This comment
    # asserted "Every remaining entry below has been checked against
    # deploy/helm/talos/files/alerts.yaml and deploy/observability/*.json — none
    # is referenced by an alert." That was unenforced prose, i.e. exactly the
    # class this arc keeps finding: a documented invariant nothing verifies.
    # It is now verified below, on every run, over a file set derived from the
    # tree rather than hardcoded.
    #
    # STATE ITS LIMIT RATHER THAN IMPLY MORE (overstating a lint is check 58's
    # own lesson one level up): the check matches the LITERAL exported series
    # name. It cannot see a runbook that names the underlying MECHANISM instead
    # of the metric — and that is not hypothetical, it is precisely how the two
    # circuit-breaker entries survived here. `alerts.yaml` told operators the
    # per-host circuit breaker was the "first hypothesis" for a failed dispatch
    # for months without ever writing `talos_circuit_breaker_opens_total`, so
    # the literal claim above stayed TRUE while the substance of it — "no
    # operator is being sent to a signal that cannot exist" — was false. A grep
    # cannot close that gap; only reading the runbook can. What the check does
    # close is the strictly easier direction: someone writing an alert or a
    # dashboard panel directly on a baselined metric.
    BASELINE_DEAD="$(printf '%s\n' \
        webhook_requests_total \
        webhook_request_duration_seconds \
        auth_2fa_attempts_total \
        api_key_validations_total \
        module_executions_total \
        module_execution_duration_seconds \
        workflow_execution_duration_seconds \
        rate_limit_hits_total \
        cache_hits_total \
        cache_misses_total \
        | sort)"
    DEAD_SORTED="$(printf '%s' "$DEAD_METRICS" | grep -vE '^$' | sort || true)"
    # NEW dead = flagged now but not in the baseline → hard fail.
    NEW_DEAD="$(comm -23 <(printf '%s\n' "$DEAD_SORTED" | grep -vE '^$') <(printf '%s\n' "$BASELINE_DEAD") || true)"
    # STALE baseline = listed but no longer dead (someone wired it) → remove it.
    STALE_BASELINE="$(comm -13 <(printf '%s\n' "$DEAD_SORTED" | grep -vE '^$') <(printf '%s\n' "$BASELINE_DEAD") || true)"
    DEAD58_FAIL="$DEAD58_SELFTEST"
    if [ -n "$NEW_DEAD" ]; then
        red "✗ NEW dead metric(s) — registered but never incremented (alerts on them never fire):"
        echo "$NEW_DEAD" | sed 's/^/    /'
        yellow "  → add a real mutation site: m.<field>.with_label_values(&[…]).inc()"
        yellow "    (or .observe()/.set() for histograms/gauges), at the event's"
        yellow "    chokepoint (see talos_metrics::record_workflow_outcome for the pattern)."
        yellow "  → genuinely external/scrape-only? // allow-unincremented-metric: <reason>"
        yellow "    on the field's struct-declaration line."
        DEAD58_FAIL=1
    fi
    if [ -n "$STALE_BASELINE" ]; then
        red "✗ baselined dead metric(s) are now incremented — remove them from BASELINE_DEAD (check 58):"
        echo "$STALE_BASELINE" | sed 's/^/    /'
        yellow "  → the burn-down list must shrink, never rot: delete these names from"
        yellow "    BASELINE_DEAD in scripts/lint-structural.sh."
        DEAD58_FAIL=1
    fi
    # ── 58(b): no baselined dead metric may be referenced by an alert rule or
    # a dashboard. Enforces what the comment above BASELINE_DEAD used to merely
    # assert. A dead metric with no alert is debt you can schedule; a dead
    # metric an alert or a panel selects on is a detector that can never fire
    # and a panel that reads "healthy" for a signal nobody collects. Baselining
    # is not an option for those — wire it or delete it.
    #
    # File set is DERIVED (a hardcoded list rots — check 65's own lesson): the
    # canonical chart rule file, every mounted dev rule file, and every
    # dashboard JSON under the two observability trees.
    #
    # Matched as `talos_<field>`, the exported name — TalosMetrics registers
    # every field under exactly that spelling. The bare field name is NOT used
    # as the needle: `cache_hits_total` would match the worker's unrelated
    # `wasm_cache_hits_total` and fail this check on a false positive.
    #
    # WHAT THIS ESTABLISHES, stated precisely rather than aspirationally
    # (overstating a lint is check 58's own lesson one level up). The needle is
    # `grep -l` over whole FILES, so what it proves is that the exported name
    # appears as TEXT in an alert-rule or dashboard file — NOT that an `expr:`
    # or a panel target selects on it. A bare YAML COMMENT naming a baselined
    # metric fails this check (mutation-proved 2026-08-11). That is the safe
    # direction and it is left as-is: a metric worth writing down next to the
    # alerts is a metric worth wiring or deleting, and narrowing the match to
    # `expr:` would reintroduce the "technically true, substantively false"
    # shape this check exists to kill. The failure text below says "named in"
    # rather than "referenced by" so it matches what was actually found.
    #
    # THREE FURTHER LIMITS:
    #
    #  (i) The DIRECTORIES are hardcoded even though the file enumeration
    #      inside them is globbed. Renaming `observability/rules/` — or moving
    #      `deploy/helm/talos/files/alerts.yaml` — blinds this check to
    #      everything under it, exactly the way check 65 documents about its own
    #      `$PROM_CFG`. Deriving them from the compose mounts is the real fix
    #      and is not done here.
    #
    # (ii) The vacuity guard below fires only when EVERY source vanishes
    #      (`${#B58_REF_FILES[@]}` -eq 0). If ONE of the three sources moves,
    #      the array is still non-empty, the check reports success, and that
    #      source is silently unscanned. Consequence of (i), and the reason (i)
    #      matters more than it looks.
    #
    #(iii) `deploy/observability/alerts.yaml` is a symlink to the chart file,
    #      and it is NOT scanned — not even once, let alone "twice" as this
    #      comment previously claimed. The `find` over that tree is
    #      `-type f -name '*.json'`: the name does not match, and `-type f` is
    #      false for a symlink without `-L` anyway. Harmless (the chart file is
    #      added explicitly on its own line), but the claim was wrong and a
    #      wrong claim about coverage is the defect class this check polices.
    B58_REF_FILES=()
    while IFS= read -r f; do
        [ -n "$f" ] && B58_REF_FILES+=("$f")
    done < <(
        {
            [ -f "$ROOT/deploy/helm/talos/files/alerts.yaml" ] \
                && echo "$ROOT/deploy/helm/talos/files/alerts.yaml"
            find "$ROOT/observability/rules" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null
            find "$ROOT/deploy/observability" "$ROOT/observability/grafana" \
                -type f -name '*.json' 2>/dev/null
        } | sort -u
    )
    if [ "${#B58_REF_FILES[@]}" -eq 0 ]; then
        red "✗ check 58(b): no alert-rule or dashboard files found to check the burn-down"
        yellow "  → the baseline's 'not referenced by an alert' guarantee would be vacuous."
        yellow "    Did deploy/helm/talos/files/alerts.yaml or observability/rules/ move?"
        DEAD58_FAIL=1
    else
        BASELINE_REFERENCED=""
        for name in $BASELINE_DEAD; do
            [ -n "$name" ] || continue
            hits="$(grep -l -- "talos_${name}" "${B58_REF_FILES[@]}" 2>/dev/null | tr '\n' ' ' || true)"
            [ -n "$hits" ] && BASELINE_REFERENCED="${BASELINE_REFERENCED}    talos_${name} → ${hits}
"
        done
        if [ -n "$BASELINE_REFERENCED" ]; then
            red "✗ baselined DEAD metric(s) are NAMED in an alert-rule or dashboard file (check 58):"
            printf '%s' "$BASELINE_REFERENCED"
            yellow "  → the match is file-global text, so this is 'the name appears in that file',"
            yellow "    which includes a bare comment — not proof that an expr or panel selects on"
            yellow "    it. Check the hit before acting. If a rule or panel DOES select on it, it"
            yellow "    can never fire or can only ever read 0: wire the metric (add a real"
            yellow "    increment at its chokepoint) and remove it from BASELINE_DEAD. Baselining a"
            yellow "    metric something already alerts on converts observability debt into a false"
            yellow "    assurance. If it is only a comment, say so in the comment or drop the name."
            DEAD58_FAIL=1
        fi
    fi
    if [ "$DEAD58_FAIL" -gt 0 ]; then
        EXIT_CODE=1
    else
        BASELINE_N="$(printf '%s\n' "$BASELINE_DEAD" | grep -cvE '^$' || true)"
        green "✓ no new dead metrics (${BASELINE_N} pre-existing in burn-down baseline)"
    fi
else
    yellow "⊘ check 58 skipped — $METRICS_LIB not found"
fi
echo

# ── 59. Email-sender template Subject must be RFC 2047-encoded ─────────
# An email module that builds a raw `Subject: {}` header from an un-encoded
# string mojibakes non-ASCII subjects: an LLM-authored em-dash (UTF-8 E2 80 94)
# double-encoded to `Ã¢Â€Â"` in the delivered header — the 2026-07 send-module
# bug that was un-fixable in place because the module was a source-less DB blob.
# The header MUST route through the `encode_subject` RFC 2047 helper
# (`=?UTF-8?B?..?=`, ASCII passes through byte-identical), never interpolate the
# raw field. A shared helper CRATE is impossible here (the compile service
# regenerates a fixed Cargo.toml, mounts only the single template source, and
# rejects path deps — so `send-html-email` + `send-gmail` each carry their own
# copy); this lint is the enforceable equivalent that keeps the class dead.
# Detection: a template.rs that interpolates a `Subject: {` header line MUST
# also call `encode_subject(`. Opt out (a genuinely ASCII-only pinned subject)
# with `// allow-raw-subject: <reason>` in the template.
bold "▶ check 59: email-sender template Subject must route through encode_subject (RFC 2047)"
RAW_SUBJECT_VIOLATIONS=0
for rs in "$ROOT"/module-templates/*/template.rs; do
    [ -f "$rs" ] || continue
    # Only templates that actually ASSEMBLE an RFC822 email message: a
    # `Subject: {` interpolation AND a `MIME-Version` header in the same file.
    # This excludes classifiers/parsers that merely reference "Subject:" in
    # prompt/field text (they have no MIME-Version).
    if grep -qE 'Subject: \{' "$rs" && grep -q 'MIME-Version' "$rs"; then
        if grep -q 'allow-raw-subject' "$rs"; then
            continue
        fi
        if ! grep -q 'encode_subject(' "$rs"; then
            red "  ✗ ${rs#"$ROOT"/}: builds a Subject header without encode_subject()"
            RAW_SUBJECT_VIOLATIONS=$((RAW_SUBJECT_VIOLATIONS + 1))
        fi
    fi
done
if [ "$RAW_SUBJECT_VIOLATIONS" -gt 0 ]; then
    red "✗ $RAW_SUBJECT_VIOLATIONS email template(s) build a raw Subject header (RFC 2047 mojibake risk)"
    yellow "  → route the subject through encode_subject(...) into a subject_header local"
    yellow "    before the format!(\"...Subject: {}...\") message assembly."
    yellow "  → ASCII-only pinned subject? // allow-raw-subject: <reason>"
    EXIT_CODE=1
else
    green "✓ email-sender templates route Subject through encode_subject"
fi
echo

# ── 60. Vector-similarity ORDER BY needs a unique tiebreaker ──────────
# (2026-07-26) `ORDER BY <col> <=> $n LIMIT $k` is a PARTIAL order whenever two
# rows have equal distance — and duplicate embeddings are NORMAL, not
# pathological: the same email/notification text is ingested repeatedly, so the
# vectors are byte-identical. Postgres then breaks the tie by whatever heap
# order the scan produced, which changes as rows are inserted, updated, or
# vacuumed. The query returns a DIFFERENT top-k on identical data.
#
# The motivating incident: two `ml_eval_model` runs of the same model under the
# same policy returned knn macro_f1 0.7065 vs 0.6152 and selected a DIFFERENT
# backend, while the logistic-regression arm was bit-identical across both runs
# — isolating the nondeterminism to the kNN neighbour query. `ml_examples`
# holds exact-duplicate feature text with CONFLICTING labels (a bootstrap
# `archive` and a human-corrected `to_read` for the same GitHub notification),
# so a tie flips the k-neighbour vote. That made a PROMOTION GATE a coin-flip,
# and with `auto_advance` a model can promote on a lucky draw. The same class
# silently reorders semantic memory recall and can return a different row from
# the semantic execution cache.
#
# This is structural check 28's principle (OFFSET pagination needs a unique
# ORDER BY tiebreaker) applied to the ANN path. Fix: append the PK —
#   ORDER BY embedding <=> $2, id
# Opt out with `// allow-vector-order-no-tiebreaker: <reason>` when the caller
# provably cannot have duplicate vectors.
bold "▶ check 60: vector-similarity ORDER BY needs a unique tiebreaker"

VECTOR_ORDER_VIOLATIONS=0
vec_files=$(grep -rlE "ORDER BY [A-Za-z_]+ <=>" --include='*.rs' talos-* controller worker 2>/dev/null \
    | grep -vE '/tests/|_tests\.rs' || true)

for file in $vec_files; do
    [ -f "$file" ] || continue
    for lineno in $(grep -nE "ORDER BY [A-Za-z_]+ <=>" "$file" | cut -d: -f1); do
        line=$(sed -n "${lineno}p" "$file")
        start=$((lineno > 3 ? lineno - 3 : 1))
        if sed -n "${start},${lineno}p" "$file" | grep -q '// allow-vector-order-no-tiebreaker:'; then
            continue
        fi
        # A standalone `id` token AFTER the distance operator on the same line
        # is the tiebreaker (e.g. "ORDER BY embedding <=> $2::vector, id").
        after=${line#*<=>}
        if echo "$after" | grep -qE '(^|[^a-z_])id([^a-z_]|$)'; then
            continue
        fi
        red "✗ ${file}:${lineno}: vector ORDER BY without a unique tiebreaker"
        yellow "    ${line}"
        VECTOR_ORDER_VIOLATIONS=$((VECTOR_ORDER_VIOLATIONS + 1))
    done
done

if [ "$VECTOR_ORDER_VIOLATIONS" -gt 0 ]; then
    red "✗ ${VECTOR_ORDER_VIOLATIONS} vector-similarity ORDER BY site(s) can return a different top-k on identical data"
    yellow "  → append the PK: ORDER BY <col> <=> \$N, id"
    yellow "  → or mark '// allow-vector-order-no-tiebreaker: <reason>' if duplicate vectors are impossible"
    EXIT_CODE=1
else
    green "✓ every vector-similarity ORDER BY carries a unique tiebreaker"
fi
echo

# ── 61. Signed JSON must be hashed as its exact wire bytes ────────────
# (2026-07-27) `serde_json`'s f64 round-trip is NOT idempotent: for ~10% of
# ordinary computed ratios `parse(write(x))` is a DIFFERENT f64 (one ULP off),
# so `write(parse(write(x)))` differs in content AND length. Hashing a signed
# JSON field as `Sha256(value.to_string())` therefore hashes a form that is
# RE-DERIVED independently on each side: the controller hashed write(x), the
# worker hashed write(parse(write(x))), the hashes differed, and every job
# whose payload happened to carry an unstable float failed Ed25519
# verification. `pa-autonomy-digest` (~30 computed ratios) failed 100% of runs
# while text-heavy payloads passed for weeks — a latent, fleet-wide lottery.
#
# Normalising to a "fixed point" was the FIRST fix and it was insufficient:
# some floats have NO fixed point at all (`5.455171886890906e-115` enters a
# permanent 2-cycle under repeated round trips), so no number of normalisation
# passes converges. The real fix is to stop re-deriving: bind the EXACT wire
# text and hash THAT. ONE generic type implements the pattern
# (`talos_workflow_job_protocol::RawSigned<T>`, 2026-07-29) for both surfaces:
#   • `SignedJson = RawSigned<serde_json::Value>` — dispatch/result payloads.
#   • `RawSigned<MemoryOp>` / `RawSigned<IntegrationOp>` — the memory /
#     integration-state `Set` ops, which carry an arbitrary
#     `serde_json::Value` (2026-07-27, the #598 memory-RPC twin);
#     `talos-memory` re-exports the type rather than reimplementing it. It
#     REPLACED `canonical_json_bytes` / `write_canonical`, which re-derived a
#     parsed `Value`'s text on each side (`Value::Number(n) => n.to_string()`)
#     and so hit the identical defect.
# This check guards BOTH surfaces from a regression:
#   (a) inside job-protocol, a Sha256 must not be taken over a signed field's
#       `.to_string()` (with or without an intervening accessor);
#   (b) the deleted `canonical_json_bytes` / `write_canonical` identifiers
#       must never reappear in code in EITHER crate — their return was a
#       re-derived byte form, so resurrecting either name is the same class of
#       bug wearing the old name.
#
# For (a): only `<expr>.to_string()` fed straight to a digest is flagged —
# hashing a String field (`logs.join`, `module_uri.as_bytes()`) is unaffected,
# since a String is already the exact bytes and has no re-derivation step.
# The accessor group is an ALTERNATION (`.value()` | `.get()`), not just
# `.value()`: the shared generic exposes `get()` and the `Value` alias exposes
# `value()`, so a value-only pattern would silently stop matching the moment a
# hash site used the generic spelling — the check would go quiet without
# anyone touching it. Both crate globs are `src/*.rs`, not `src/lib.rs`: the
# type now has module neighbours (`test_support.rs`, `envelope_seal.rs`,
# `subjects.rs`) and a hash site added in one of them was previously invisible.
# For (b): comment lines are skipped (the RawSigned docs and this script name
# the identifiers deliberately); only live code counts.
# Opt-out (both): `// allow-raw-json-hash: <reason>`.
bold "▶ check 61: signed JSON must be hashed as its exact wire bytes"

RAW_JSON_HASH=0
for jp_file in talos-workflow-job-protocol/src/*.rs; do
    [ -f "$jp_file" ] || continue
    while IFS=: read -r lineno _; do
        [ -n "$lineno" ] || continue
        start=$((lineno > 3 ? lineno - 3 : 1))
        if sed -n "${start},${lineno}p" "$jp_file" | grep -q '// allow-raw-json-hash:'; then
            continue
        fi
        red "✗ ${jp_file}:${lineno}: Sha256 over a re-derived .to_string() of signed JSON"
        yellow "    $(sed -n "${lineno}p" "$jp_file" | sed 's/^ *//')"
        RAW_JSON_HASH=$((RAW_JSON_HASH + 1))
    done <<EOF
$(grep -nE "Sha256::digest\((self|s)\.[A-Za-z_]+(\.(value|get)\(\))?\.to_string\(\)" "$jp_file" || true)
EOF
done

# (b) the deleted canonical machinery must not reappear as live code in
# either signed-wire crate — talos-memory (where it was deleted) or
# job-protocol (where the shared type now lives, so a "canonicalise it here
# instead" regression would land). Skip comment lines (`//`, `///`, `//!`,
# block `*`) so the RawSigned docs that explain WHY it was removed don't
# self-trip.
for mf in talos-memory/src/*.rs talos-workflow-job-protocol/src/*.rs; do
    [ -f "$mf" ] || continue
    while IFS=: read -r lineno line; do
        [ -n "$lineno" ] || continue
        trimmed="$(printf '%s' "$line" | sed 's/^[[:space:]]*//')"
        case "$trimmed" in
            //*|\**) continue ;;
        esac
        start=$((lineno > 3 ? lineno - 3 : 1))
        if sed -n "${start},${lineno}p" "$mf" | grep -q '// allow-raw-json-hash:'; then
            continue
        fi
        red "✗ ${mf}:${lineno}: canonical_json_bytes/write_canonical resurrected (re-derives signed bytes)"
        yellow "    $(printf '%s' "$trimmed")"
        RAW_JSON_HASH=$((RAW_JSON_HASH + 1))
    done <<EOF
$(grep -nE 'canonical_json_bytes|write_canonical' "$mf" || true)
EOF
done

if [ "$RAW_JSON_HASH" -gt 0 ]; then
    red "✗ ${RAW_JSON_HASH} signed-JSON hash site(s) re-derive the payload text"
    yellow "  → make the field a SignedJson / RawSigned<T> and hash its wire bytes:"
    yellow "      Sha256::digest(self.field.raw_bytes())   // or op.raw_bytes()"
    yellow "  → serde_json's f64 round-trip is not idempotent and has no fixed"
    yellow "    point for some values, so ANY re-serialised form can differ per side"
    EXIT_CODE=1
else
    green "✓ every signed-JSON hash covers the exact wire bytes"
fi
echo

# ── 62: build.rs git-stamp drift across the three copies ─────────────
bold "▶ check 62: build.rs GIT_SHA stamping must be identical across crates"

# The controller↔worker build-identity handshake (2026-07-28) compares the
# `+sha[-dirty]` suffix of two independently-composed version strings and WARNs
# when they differ. Three crates carry a copy of the same build script that
# derives that sha — talos-mcp-handlers/build.rs (the original),
# controller/build.rs, worker/build.rs. They must stay identical BELOW the
# module doc header (each header describes its own crate's use):
#   * if worker/build.rs drifts from controller/build.rs — a different
#     `--short=N`, a different override-env precedence, a different dirty rule —
#     a same-tree controller and worker compose DIFFERENT strings, and the skew
#     WARN fires on a perfectly healthy fleet. The diagnostic that exists to
#     answer "are we on one build?" would start lying, loudly and constantly.
#   * a shared build-dep crate is not worth it for ~80 lines with zero runtime
#     surface, so this lint is the enforcement the duplication needs (same shape
#     as check 16 for the duplicated WIT file).
# Comparison strips the leading `//!` doc header from each file. Opt-out:
# `# allow-build-rs-drift: <reason>` anywhere in any of the three files.
BUILD_RS_FILES=("$ROOT/talos-mcp-handlers/build.rs" "$ROOT/controller/build.rs" "$ROOT/worker/build.rs")
BUILD_RS_MISSING=0
for f in "${BUILD_RS_FILES[@]}"; do
    [ -f "$f" ] || { yellow "⚠ $f not found — skipping build.rs drift check"; BUILD_RS_MISSING=1; }
done
if [ "$BUILD_RS_MISSING" -eq 0 ]; then
    if grep -lq 'allow-build-rs-drift' "${BUILD_RS_FILES[@]}" >/dev/null 2>&1; then
        yellow "⊘ build.rs drift check bypassed by allow-build-rs-drift marker"
    else
        # Strip the `//!` header (and the blank lines inside it); compare the rest.
        strip_build_rs_header() { grep -vE '^\s*//!' "$1" | sed '/./,$!d'; }
        BUILD_RS_DRIFT=0
        AUTHORITATIVE="${BUILD_RS_FILES[0]}"
        for f in "${BUILD_RS_FILES[@]:1}"; do
            if ! diff -q <(strip_build_rs_header "$AUTHORITATIVE") \
                         <(strip_build_rs_header "$f") >/dev/null 2>&1; then
                red "✗ ${f#"$ROOT/"} has drifted from ${AUTHORITATIVE#"$ROOT/"}"
                diff <(strip_build_rs_header "$AUTHORITATIVE") \
                     <(strip_build_rs_header "$f") 2>/dev/null | head -20 | sed 's/^/    /'
                BUILD_RS_DRIFT=1
            fi
        done
        if [ "$BUILD_RS_DRIFT" -eq 1 ]; then
            yellow "  → all three build.rs copies must derive GIT_SHA/GIT_DIRTY identically."
            yellow "    talos-mcp-handlers/build.rs is authoritative; copy its body (everything"
            yellow "    below the //! header) into the others, keeping each header as-is."
            yellow "  → drift makes a same-tree controller and worker compose different build"
            yellow "    strings, so the registration build-skew WARN fires on a healthy fleet."
            yellow "  → opt-out: '# allow-build-rs-drift: <reason>' in any of the three files."
            EXIT_CODE=1
        else
            green "✓ the three build.rs copies stamp GIT_SHA identically"
        fi
    fi
fi
echo

# ── 63: ONE Rhai sandbox — discard print/debug, no raw Engine::new() ──
bold "▶ check 63: one Rhai sandbox (discard print/debug + no raw rhai::Engine::new)"

# `rhai::Engine::new()` installs `print`/`debug` handlers that `println!`
# straight to STDOUT — the same stream tracing's `fmt::layer()` writes to, so
# whatever they emit lands in the controller's container logs. Every variable
# in a workflow expression's scope is upstream-node output: post-interpolation
# secrets, email bodies, whatever that workflow carries. A stored
# `verdict_expr` / `skip_condition` / retry condition / dispatch expression of
# `print(ctx); …` therefore dumps the entire bound context past every DLP
# boundary the persistence path applies (the condition-eval WARN in
# rhai_helpers.rs scrubs its context through `redact_json` precisely because
# this data is sensitive).
#
# Confirmed exploitable 2026-07-29 while reviewing `probe_inline_judge`, which
# made it sharper still: that tool takes a CALLER-AUTHORED expression and
# CALLER-AUTHORED data per request, and its crate docs assert outright that
# nothing on the path is logged.
#
# A unit test cannot observe process stdout from inside the same process
# without fd surgery, so this lint is the enforcement. Discard (`on_print`)
# rather than `disable_symbol`: silencing keeps `print` a callable no-op, so an
# expression that already contains one keeps evaluating to the same verdict,
# where disabling turns it into a PARSE ERROR and breaks a working stored
# expression on deploy.
#
# PART B (widened 2026-07-29): fixing ONE engine is not enough. The original
# check covered only talos-engine/src/rhai_helpers.rs, and a grep that day
# found THREE more hand-rolled `rhai::Engine::new()` configs which had already
# drifted — the dispatch-expression evaluator ran a 10 000-op cap with no
# discard and no depth/size caps at all, and the `testRhaiExpression` GraphQL
# preview had no discard and no max_map_size. Every hand-rolled copy is a
# drift bomb, so the config now lives in ONE leaf crate
# (talos-rhai-sandbox::sandboxed_engine) and this check forbids constructing a
# rhai Engine anywhere else.
#
# Notes on the pattern:
#   * `Engine::default()` is included — rhai's `impl Default for Engine` is
#     literally `Self::new()`, so it is the same hole by another spelling.
#   * EMPTY parens are required, which is what keeps wasmtime's
#     `Engine::new(&config)` in talos-worker-runtime out of scope; an
#     explicitly `wasmtime::`-qualified call is excluded too.
#   * `Engine::new_raw()` is deliberately NOT flagged. It is the sanctioned
#     compile-only constructor: it registers no StandardPackage and leaves
#     both handlers as `None` (rhai dispatches via
#     `if let Some(ref print) = self.print`), so it cannot reach stdout even
#     in principle. The compile-only sites in talos-mcp-handlers use it and
#     only ever call `Engine::compile`, which never dispatches a function.
#   * `//`-comments are stripped before matching so the prose in these files
#     (which necessarily names `Engine::new()`) does not self-trip.
#   * `*/.claude/*` is excluded along with `target/` and `.git/`. Agent
#     worktrees live under `.claude/worktrees/`, so without this the check run
#     from the main checkout scans every stale sibling branch and reports its
#     files (measured: 20+ hits from pre-#614 checkouts) — a failure the
#     developer in the main tree cannot fix, which is how a check gets
#     bypassed. Same exclusion the other find-based checks above use.
#   * The walk MUST be `find .` (relative to the `cd "$ROOT"` at the top of
#     this script), never `find "$ROOT"`. When the script runs from inside an
#     agent worktree, `$ROOT` ITSELF contains `/.claude/`, so an absolute walk
#     plus the exclusion above matches every file and the check silently
#     scans nothing. The zero-scan guard below exists because that failure is
#     invisible — it reports success.
#
# Known matcher limits (this is a DRIFT check, not an adversary check — the
# shapes below need deliberate effort, and a reviewer sees them):
#   * an aliased import (`use rhai::Engine as E; E::new()`), a trait-qualified
#     `let e: rhai::Engine = Default::default();`, and a construction split
#     across two lines all evade the grep. `cargo fmt` re-joins the split form,
#     and the other two are not shapes anyone reaches for by accident.
#   * a `/* … */` BLOCK comment naming `Engine::new()` is a false positive
#     (only `//` is stripped); use the file-level opt-out if that ever happens.
#
# Opt-outs: `// allow-rhai-stdout: <reason>` (part A),
#           `// allow-raw-rhai-engine: <reason>` (part B, per file — note it is
#           file-WIDE, not line-scoped, so a file that legitimately carries one
#           is no longer covered for any FUTURE engine added to it).
RHAI_SANDBOX_REL="talos-rhai-sandbox/src/lib.rs"
RHAI_SANDBOX_FILE="$ROOT/$RHAI_SANDBOX_REL"
RHAI_FAIL=0

# Part A — the builder must silence both handlers.
if [ ! -f "$RHAI_SANDBOX_FILE" ]; then
    yellow "⚠ $RHAI_SANDBOX_FILE not found — skipping Rhai sandbox check"
    RHAI_FAIL=2
elif grep -q 'allow-rhai-stdout' "$RHAI_SANDBOX_FILE"; then
    yellow "⊘ Rhai stdout check bypassed by allow-rhai-stdout marker"
elif grep -q 'engine.on_print(' "$RHAI_SANDBOX_FILE" \
        && grep -q 'engine.on_debug(' "$RHAI_SANDBOX_FILE"; then
    green "✓ the shared Rhai sandbox builder discards print/debug output"
else
    red "✗ talos-rhai-sandbox/src/lib.rs does not install on_print + on_debug handlers"
    yellow "  → Engine::new()'s defaults println! to stdout, so a workflow expression"
    yellow "    containing print(ctx) writes the whole node input to the container log."
    yellow "  → add 'engine.on_print(|_| {});' and 'engine.on_debug(|_, _, _| {});'"
    yellow "    to sandboxed_engine() (NOT disable_symbol — that turns an existing"
    yellow "    stored expression into a parse error)."
    yellow "  → opt-out: '// allow-rhai-stdout: <reason>'."
    RHAI_FAIL=1
fi

# Part B — nobody else constructs a rhai Engine.
if [ "$RHAI_FAIL" != "2" ]; then
    RAW_RHAI_HITS=""
    RHAI_SCANNED=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        RHAI_SCANNED=$((RHAI_SCANNED + 1))
        # Skip the builder's own file, and any file with the opt-out marker.
        case "$f" in "./$RHAI_SANDBOX_REL") continue ;; esac
        grep -q 'allow-raw-rhai-engine' "$f" && continue
        # Strip //-comments so prose naming Engine::new() doesn't self-trip.
        # The `if hit=…; then` wrapper is load-bearing under `set -euo
        # pipefail`: the inner greps legitimately exit 1 on "no match", and a
        # BARE assignment from a failing pipeline aborts the whole script
        # (measured: the lint died silently after part A). Keep the wrapper.
        if hit="$(sed 's|//.*||' "$f" \
                | grep -nE '(^|[^A-Za-z0-9_:])(rhai::)?Engine::(new|default)[[:space:]]*\([[:space:]]*\)' \
                | grep -v 'wasmtime::' | head -3)"; then
            if [ -n "$hit" ]; then
                RAW_RHAI_HITS="${RAW_RHAI_HITS}${f#./}:
$(echo "$hit" | sed 's/^/    /')
"
            fi
        fi
    done <<< "$(find . -name '*.rs' -type f \
                    -not -path '*/target/*' \
                    "${TREE_PRUNE_FIND[@]}")"

    # A check that scans nothing reports success. Fail loud instead — this is
    # what an absolute-path walk from inside a `.claude/worktrees/…` checkout
    # did before it was caught in review.
    if [ "$RHAI_SCANNED" -lt 100 ]; then
        red "✗ check 63 part B scanned only $RHAI_SCANNED .rs files — the walk is broken"
        yellow "  → expected the whole workspace; a near-empty scan means the find"
        yellow "    exclusions swallowed everything (e.g. an absolute walk whose root"
        yellow "    is itself under an excluded path). Fix the find, do not lower this."
        RHAI_FAIL=1
    elif [ -n "$RAW_RHAI_HITS" ]; then
        red "✗ raw rhai Engine construction outside the sandbox builder:"
        echo "$RAW_RHAI_HITS" | sed 's/^/  /'
        yellow "  → every engine that EVALUATES an expression must come from"
        yellow "    talos_rhai_sandbox::sandboxed_engine(SandboxProfile::…), which applies"
        yellow "    the op/depth/size caps, disables eval + the module resolver, and"
        yellow "    discards print/debug. A hand-rolled config drifts — that is exactly"
        yellow "    how the dispatch evaluator ended up with no discard and no caps."
        yellow "  → a COMPILE-ONLY syntax check needs no builder: use Engine::new_raw()"
        yellow "    and call only Engine::compile (no print handler, no eval)."
        yellow "  → opt-out: '// allow-raw-rhai-engine: <reason>' in the file."
        RHAI_FAIL=1
    else
        green "✓ no raw rhai Engine construction outside talos-rhai-sandbox"
    fi
fi

if [ "$RHAI_FAIL" = "1" ]; then
    EXIT_CODE=1
fi
echo

# ── 64. Every tests/ binary must be named by a CI runner ──────────────
# docs/backlog.md claimed "100% of tests/-dir binaries now run in CI — no
# exclusions" after the June-2026 sweep. It was true on 06-08 and false
# seven weeks later: 28 binaries had accumulated that no runner named,
# because NOTHING enforced the invariant — a sweep is a snapshot, not a
# gate. Among the decayed set was `ml_registry_tenancy_tests`, the ONLY
# guard on the app-layer `AND user_id = $2` predicate that stops
# cross-tenant model resolution on the `talos.ml.predict` serving path
# (RLS does not cover it on a superuser pool), and four per-org-DEK
# encryption-at-rest binaries whose own headers ASSERTED they ran in CI.
#
# Cargo auto-discovers integration binaries at BOTH `<crate>/tests/<name>.rs`
# (target `<name>`) AND `<crate>/tests/<dir>/main.rs` (target `<dir>`) — the
# second form is easy to forget and was a hole in this check's first cut
# (verified against `cargo metadata`, not from memory). Everything else under
# `tests/<subdir>/` — `common/mod.rs`, `test_helpers/mod.rs` — is a shared
# module, not a binary, so the exclusion needs no hand-maintained list. Every
# discovered target must be named by `.github/workflows/quality.yml` or
# `scripts/test-integration.sh`, or carry a `// ci-ungated: <reason>` marker.
#
# Matching is CRATE-QUALIFIED, not by bare name: `wire_format_snapshots`
# exists in BOTH talos-workflow-job-protocol and talos-memory, and a
# name-only match would have reported the (ungated) talos-memory one as
# covered by the job-protocol entry. That collision is what hid it.
# Comments are stripped from both runner files first, so a binary
# mentioned only in prose ("its eight ml_* siblings are NOT in this
# list") does not count as gated.
#
# Three directions are checked, because "named by a runner" is only as good
# as the runner being real and being run:
#   (i)   file with no runner entry      → ungated, the original defect;
#   (ii)  runner entry with no file      → a stale entry. Cargo fails the job
#         with `no test target named X` (the #567 lesson), so this is loud
#         rather than silent — but it fails 20 minutes into the integration
#         job instead of at pre-push, and a stale entry also silently
#         "covers" nothing while looking like coverage;
#   (iii) `scripts/test-integration.sh` must actually be WIRED into CI. This
#         check reads that file directly, so if `quality.yml` stopped invoking
#         `make test-integration` (or the Makefile target stopped invoking the
#         script) every CTRL_TESTS/TC_TESTS entry would still read as "gated"
#         while running nowhere — the exact shape of the defect this check
#         exists to end, one level up.
bold "▶ check 64: every tests/*.rs binary is named by a CI runner"

CI_GATE_FAIL=0
QUALITY_YML=".github/workflows/quality.yml"
INTEGRATION_SH="scripts/test-integration.sh"

if [ ! -f "$QUALITY_YML" ] || [ ! -f "$INTEGRATION_SH" ]; then
    red "✗ check 64 cannot find its runner files ($QUALITY_YML / $INTEGRATION_SH)"
    CI_GATE_FAIL=1
else
    # Strip full-line and trailing comments, then join backslash
    # continuations so a multi-line `cargo nextest run -p X \ --test a \
    # --test b` reads as one logical command.
    strip_comments() {
        sed -e 's/[[:space:]]#.*$//' -e 's/^[[:space:]]*#.*$//' "$1"
    }

    # Emit `crate:binary` (or `crate:*` for a whole-crate run) for every
    # literal `cargo (test|nextest run)` invocation in a file. Lines whose
    # package or test name is a SHELL VARIABLE (the `for ctest in …; do
    # cargo test -p controller --test "$ctest"` loop bodies) are skipped —
    # matching them would mark EVERY controller binary as gated, which is
    # the exact false negative this check exists to prevent. Those loops'
    # real contents come from the array parsers below.
    cargo_gates() {
        strip_comments "$1" \
            | awk '{ l=$0; while (l ~ /\\$/) { sub(/\\$/,"",l); if ((getline n) > 0) l = l " " n; else break } print l }' \
            | grep -E 'cargo (nextest run|test)' \
            | while IFS= read -r line; do
                crate="$(printf '%s\n' "$line" | grep -oE '(-p|--package) [A-Za-z0-9_-]+' | head -1 | awk '{print $2}')"
                # No literal package (e.g. `--workspace`, or `-p "$crate"`).
                [ -n "$crate" ] || continue
                tests="$(printf '%s\n' "$line" | grep -oE '\--test [A-Za-z0-9_]+' | awk '{print $2}')"
                if [ -n "$tests" ]; then
                    printf '%s\n' "$tests" | sed "s#^#${crate}:#"
                elif printf '%s\n' "$line" | grep -qE '\--test([[:space:]]|$)'; then
                    # `--test "$var"` — variable-driven, contributes nothing.
                    continue
                elif ! printf '%s\n' "$line" | grep -qE '\--(lib|doc|bins?|examples?)([[:space:]]|$)'; then
                    # Whole-crate invocation (e.g. `cargo test -p
                    # talos-envelope-seal`) — covers every binary in it.
                    printf '%s:*\n' "$crate"
                fi
            done
    }

    # --- (a) quality.yml + (b) test-integration.sh cargo invocations.
    # Every parser below is `|| true`-terminated. Under `set -euo pipefail` a
    # grep that matches nothing makes the whole command-substitution
    # assignment non-zero, which aborts the ENTIRE lint script silently at
    # this line — the emptiest possible input (a runner file that stopped
    # naming any test) would kill the run instead of failing this check with a
    # message. An empty parse is a legitimate input here; let the reporting
    # below be what fails.
    GATED="$(cargo_gates "$QUALITY_YML" || true)
$(cargo_gates "$INTEGRATION_SH" || true)"
    # TESTS=( "crate:binary:store" … )
    GATED="$GATED
$(
        strip_comments "$INTEGRATION_SH" \
            | sed -n '/^TESTS=(/,/^)/p' \
            | grep -oE '"[A-Za-z0-9_-]+:[A-Za-z0-9_]+:[a-z]+"' \
            | tr -d '"' | sed -E 's#:[a-z]+$##' || true
)"
    # CTRL_TESTS / TC_TESTS =( "binary" … ) — all controller binaries.
    GATED="$GATED
$(
        strip_comments "$INTEGRATION_SH" \
            | sed -n -e '/^CTRL_TESTS=(/,/^)/p' -e '/^TC_TESTS=(/,/^)/p' \
            | grep -oE '"[A-Za-z0-9_]+"' \
            | tr -d '"' | sed 's#^#controller:#' || true
)"
    GATED="$(printf '%s\n' "$GATED" | grep -v '^$' | sort -u || true)"

    # --- (c) walk every crate's tests/ dir for cargo-discovered targets:
    #         `tests/<name>.rs` AND `tests/<dir>/main.rs`.
    UNGATED_HITS=""
    STALE_MARKERS=""
    EXISTING_TARGETS=""
    CI_GATE_SCANNED=0
    while IFS= read -r tf; do
        [ -n "$tf" ] || continue
        CI_GATE_SCANNED=$((CI_GATE_SCANNED + 1))
        if [ "$(basename "$tf")" = "main.rs" ]; then
            # tests/<dir>/main.rs → target named <dir>; crate is two levels up
            # from the tests/ dir rather than one.
            bin="$(basename "$(dirname "$tf")")"
            crate_dir="$(dirname "$(dirname "$(dirname "$tf")")")"
        else
            bin="$(basename "$tf" .rs)"
            crate_dir="$(dirname "$(dirname "$tf")")"
        fi
        crate="$(grep -m1 -E '^name[[:space:]]*=' "$crate_dir/Cargo.toml" 2>/dev/null \
                    | sed -E 's/^name[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')"
        [ -n "$crate" ] || crate="$(basename "$crate_dir")"
        EXISTING_TARGETS="${EXISTING_TARGETS}${crate}:${bin}
"
        marked=0
        grep -qE '^[[:space:]]*(//|#)[[:space:]]*ci-ungated:' "$tf" && marked=1
        if printf '%s\n' "$GATED" | grep -qxF -e "${crate}:${bin}" -e "${crate}:*"; then
            if [ "$marked" = "1" ]; then
                STALE_MARKERS="${STALE_MARKERS}  ${tf#./}  (crate ${crate})
"
            fi
        elif [ "$marked" = "0" ]; then
            UNGATED_HITS="${UNGATED_HITS}  ${tf#./}  → would need '${crate}:${bin}'
"
        fi
    done <<< "$(find . -type d -name tests \
                    -not -path './target/*' -not -path './vendor/*' \
                    -not -path './frontend/*' -not -path '*/node_modules/*' \
                    "${TREE_PRUNE_FIND[@]}" \
                    -exec sh -c 'ls -1 "$1"/*.rs "$1"/*/main.rs 2>/dev/null' _ {} \; | sort)"

    # --- (d) the reverse direction: a runner entry naming a target that does
    # not exist. `crate:*` whole-crate entries are skipped (they name no
    # specific target).
    STALE_ENTRIES=""
    while IFS= read -r g; do
        [ -n "$g" ] || continue
        case "$g" in *:\*) continue ;; esac
        printf '%s\n' "$EXISTING_TARGETS" | grep -qxF "$g" \
            || STALE_ENTRIES="${STALE_ENTRIES}  ${g}
"
    done <<< "$GATED"

    # A walk that scans nothing reports success. Fail loud instead (the
    # check-63 lesson — an absolute walk rooted under an excluded path).
    if [ "$CI_GATE_SCANNED" -lt 50 ]; then
        red "✗ check 64 found only $CI_GATE_SCANNED tests/*.rs binaries — the walk is broken"
        yellow "  → expected the whole workspace (~90). Fix the find, do not lower this."
        CI_GATE_FAIL=1
    fi
    if [ -n "$UNGATED_HITS" ]; then
        red "✗ integration-test binaries that NO CI runner names:"
        printf '%s' "$UNGATED_HITS"
        yellow "  → a tests/*.rs that no runner enumerates compiles at authoring time"
        yellow "    and then runs NOWHERE. That is how 28 binaries — including the"
        yellow "    only cross-tenant guard on the ml serving path — silently rotted"
        yellow "    for seven weeks behind a docs claim of '100%, no exclusions'."
        yellow "  → add it to CTRL_TESTS / TC_TESTS / TESTS in scripts/test-integration.sh"
        yellow "    (needs a DB or a container) or to a 'cargo nextest run -p <crate>"
        yellow "    --test <name>' step in .github/workflows/quality.yml (DB-free)."
        yellow "  → if it genuinely cannot run in CI, say why in the file itself:"
        yellow "    '// ci-ungated: <reason>'. Do NOT gate a test that early-returns"
        yellow "    without a provider — a green check over zero assertions is worse"
        yellow "    than an honest exclusion."
        CI_GATE_FAIL=1
    fi
    if [ -n "$STALE_MARKERS" ]; then
        red "✗ '// ci-ungated:' marker on a binary that IS gated (stale claim):"
        printf '%s' "$STALE_MARKERS"
        yellow "  → the marker says CI cannot run this; a runner says it does. Delete"
        yellow "    the marker, or remove the runner entry — leaving both is the same"
        yellow "    misleading-comment class this check exists to end."
        CI_GATE_FAIL=1
    fi
    if [ -n "$STALE_ENTRIES" ]; then
        red "✗ CI runner names a test target that does not exist:"
        printf '%s' "$STALE_ENTRIES"
        yellow "  → cargo fails the whole job with 'no test target named <name>'"
        yellow "    (the PR #567 lesson — a deleted test file broke the Rust check"
        yellow "    while the code was fine). Delete the runner entry too, or"
        yellow "    restore the file. Grep .github/ + Makefile before deleting a test."
        CI_GATE_FAIL=1
    fi

    # --- (e) the runner file this check trusts must actually be invoked by CI.
    # Without this, dropping the `make test-integration` step from quality.yml
    # would leave every CTRL_TESTS/TC_TESTS entry reading as "gated" while
    # running nowhere — the original defect, one level up.
    if ! grep -qE '^[[:space:]]*run:[[:space:]]*make test-integration[[:space:]]*$' "$QUALITY_YML"; then
        red "✗ $QUALITY_YML no longer runs 'make test-integration'"
        yellow "  → check 64 counts every CTRL_TESTS / TC_TESTS / TESTS entry in"
        yellow "    $INTEGRATION_SH as gated. That is only true while CI invokes"
        yellow "    the script. Restore the step, or teach this check the new path."
        CI_GATE_FAIL=1
    fi
    if ! grep -qE 'bash[[:space:]]+scripts/test-integration\.sh' Makefile 2>/dev/null; then
        red "✗ the Makefile 'test-integration' target no longer runs $INTEGRATION_SH"
        yellow "  → same reason as above: the entries in that script are only"
        yellow "    coverage while something actually executes it."
        CI_GATE_FAIL=1
    fi

    if [ "$CI_GATE_FAIL" -eq 0 ]; then
        green "✓ all $CI_GATE_SCANNED cargo test targets are gated or explicitly marked ci-ungated (runners wired, no stale entries)"
    fi
fi

if [ "$CI_GATE_FAIL" = "1" ]; then
    EXIT_CODE=1
fi
echo

# ── 65: the dev Prometheus must actually observe Talos ────────────────
bold "▶ check 65: dev Prometheus scrapes Talos and its rule files resolve"

# 2026-08-02: the local observability stack observed NOTHING of Talos and
# loaded ZERO alert rules, while looking fully configured from the outside.
# Three independent defects, none of which any existing gate could see:
#
#   * `observability/prometheus/prometheus.yml` had no controller job at
#     all — and EVERY `talos_*` series lives in the controller process. So
#     the 26 alerts in the chart's canonical rules could not be exercised
#     locally before shipping, which is how #618/#620/#623 each landed
#     detectors nobody could test.
#   * `rule_files: ['alerts.yml']` named a file docker-compose.yml never
#     mounted. Prometheus treats every rule_files entry as a GLOB, so a
#     literal path matching nothing expands to zero files and loads zero
#     groups WITHOUT an error or a warning. `/api/v1/rules` returned
#     `{"groups":[]}` on a stack whose config listed a rules file.
#   * the worker job was broken three ways at once (host `talos-worker`
#     does not resolve, port 9091 vs the real 9090 default, bearer
#     `dev-metrics-token` vs the real `dev-token`) and held `up` at 0.
#
# The fixes are a snapshot; this check is the gate — a sweep is not a gate
# (check 64's lesson). Four directions:
#
#  (a) SELECTOR AGREEMENT. Every `up{job="X"}` an alert selects on must be
#      declared as a `job_name: X` in prometheus.yml. Derived from the
#      ALERTS (the consumer) rather than a hardcoded job list, so adding an
#      alert that selects `up{job="…"}` for a job nothing scrapes fails
#      here. The controller job must also scrape `/metrics/prometheus`, NOT
#      `/metrics` — the latter is a different, authenticated dashboard
#      route behind the GraphQL proxy.
#  (b) RULE FILES RESOLVE, IN EVERY STACK. Every rule_files entry is
#      resolved through the compose bind mounts to a real file in this repo
#      (config entry → mount → file on disk), separately for EACH compose
#      file that mounts this shared prometheus.yml. Per-file, not
#      first-match: the motivating bug was a per-stack gap
#      (docker-compose.observability.yml mounted `alerts.yml`,
#      docker-compose.yml did not), so a check satisfied by any one stack
#      would have passed the tree it exists to reject.
#  (c) ALERTED-BUT-NEVER-REGISTERED. Every `talos_*` metric named in an
#      alert EXPRESSION must appear as a quoted string in some .rs file.
#      The natural extension of check 58: 58 finds registered-but-never-
#      incremented, this finds alerted-but-never-registered. Only `expr:`
#      blocks are scanned — comments and annotation prose mention names
#      like `talos_auth`/`talos_metrics` that are crate paths, not series.
#  (d) ONE DEFINITION PER ALERT NAME across the mounted rule files.
#      Prometheus does not dedup by name; two definitions fire twice on one
#      event and Alertmanager cannot merge them when the label sets differ.
#      Added during the 2026-08-02 review after mounting both files exposed
#      a long-latent duplicate `TalosWorkerDown` (1m vs 2m) firing twice.
#
# LIMITS, stated rather than implied — overstating a lint is the same
# defect one level up (check 58 learned this the expensive way):
#   * (b) knows only about compose files it is TOLD to look at — the two
#     named in PROM_COMPOSE below. A third STACK mounting this same
#     prometheus.yml would not be checked until it is added to that list.
#     (A third RULE FILE needs no such edit: the scanned rule-file set is
#     derived from rule_files + the mounts, so (a)/(c)/(d) pick it up.)
#     (Until 2026-08-02 review, (b) also stopped at the FIRST compose file
#     providing a mount, which meant it PASSED the pre-fix tree that
#     motivated it; it now requires every listed stack to provide every
#     entry, and the battery mutation "delete only docker-compose.yml's two
#     mount lines" fails the check.)
#   * (b) is a static text match on the compose bind-mount syntax
#     `- ./host:/container[:ro]`. A mount expressed in long form
#     (`type: bind` / `source:` / `target:`), through `extends`, or via an
#     env-var-interpolated path is invisible to it and reads as missing —
#     the safe direction (it fails loudly), but worth knowing before
#     rewriting a compose file.
#   * (b) rejects a GLOB rule_files entry (`- '/etc/prometheus/rules/*.yml'`)
#     even though Prometheus supports it, because a glob names no single
#     mount to resolve. Verified 2026-08-02: the glob form fails the check.
#     That is a false POSITIVE (loud), not a hole — but if the config ever
#     needs a glob, (b) has to learn to expand it against the mount set
#     rather than the entry being "worked around" with an opt-out.
#   * (a) scans the WHOLE rule file, not just `expr:` blocks (unlike (c)), so
#     a job name written out in a comment or an annotation counts as
#     "selected" and must then be declared as a scrape job. Tripped over live
#     2026-08-02 by a comment in the canonical file that spelled the selector
#     out while explaining this very check. False-POSITIVE direction (it fails
#     loudly), so it is documented rather than narrowed — but do not write the
#     selector form out in prose.
#   * (a) matches the literal single-line, double-quoted `up{…job=…}`
#     form only. A job selector on a non-`up` series, a single-quoted
#     `job='X'`, or a selector split across lines of a block-scalar `expr:`
#     is invisible to it.
#   * (a) checks that every job an ALERT NEEDS exists. It says nothing about
#     jobs no alert selects: a redundant/incorrect extra scrape job (e.g. a
#     second controller job under a different name hitting the wrong path)
#     passes, because the `metrics_path` probe is keyed to the literal
#     `talos-controller` job name. Verified 2026-08-02.
#   * NOTHING here checks the mount MODE. A rule file bind-mounted `:rw`
#     instead of `:ro` passes (verified 2026-08-02). Prometheus only reads
#     them, so this is hygiene rather than function — but it means the `:ro`
#     on the canonical chart file is convention, not an enforced invariant.
#   * (a) reads job declarations and the controller `metrics_path` out of
#     prometheus.yml textually. The metrics_path probe is scoped to the
#     controller job's OWN block (its `job_name` line up to the next
#     `job_name`); it was a fixed `grep -A12` window until the 2026-08-02
#     review, which was exploitable in the UNSAFE direction — proven by
#     mutation: controller on '/metrics' plus a NEIGHBOUR job on
#     '/metrics/prometheus' passed. It still never checks that a declared
#     target actually RESOLVES — `up == 1` is the live stack's job, not the
#     lint's.
#   * (c)'s "registered" evidence is any quoted `"talos_x"` string anywhere
#     in any .rs file — INCLUDING test files and test modules, which check
#     58 deliberately strips and this one does not. A metric named only by
#     a test therefore reads as registered. PROVEN, not inferred: on
#     2026-08-02 an alert on `talos_only_named_by_a_test_total` failed the
#     check, and adding that literal inside a `#[cfg(test)] mod` — and
#     nowhere else — made it pass. Conversely a name assembled at runtime
#     (`format!`/`concat!`) reads as unregistered; that direction is safe
#     (it fails loudly).
#   * (c) covers BOTH `talos_*` and `wasm_*` as of 2026-08-02. It previously
#     inspected only `talos_*`, which is why the dev-stack rules in
#     observability/rules/alerts.yml — built entirely on `wasm_*` series the
#     worker declares through OTEL with dots — shipped with SEVEN rules
#     naming a series no producer could emit. `wasm_*` evidence is derived
#     from the OTEL declaration (see the long note at the match site);
#     `talos_*` accepts EITHER a quoted literal or an OTEL declaration, so
#     a `talos.foo` counter declared through OTEL now correctly vouches for
#     the exported `talos_foo_total`.
#   * The OTEL-declaration evidence has the SAME test-file hole as the
#     quoted-literal evidence one bullet up, and it is not narrowed by
#     living in a particular crate: a `.u64_counter("wasm.ghost")` inside a
#     `#[cfg(test)] mod` in ANY workspace crate vouches for an alert on
#     `wasm_ghost_total`. PROVEN by mutation 2026-08-02, not inferred. So
#     "evidence must be an OTEL declaration" means the CONSTRUCTOR FORM, not
#     "declared in talos-worker-runtime" and not "in production code" — it
#     is what excludes metrics_demo.rs's raw `prometheus::Counter`s, nothing
#     more. Closing it needs the same call-graph check that check 58's
#     wrapper limit needs; a per-metric test that drives the production path
#     is the real guard.
#   * The `_bucket`/`_sum`/`_count` strip happens BEFORE the prefix split and
#     does not check the instrument KIND, so an alert on
#     `wasm_executions_total_sum` — a `_sum` a counter never exposes —
#     passes by stripping to a registered counter name. Also proven by
#     mutation; false-NEGATIVE direction, and it applies to `talos_*` too.
#
# Opt-out (c) only: `# allow-unobserved-metric: <reason naming the series>`
# anywhere in ANY scanned rule file, for a series produced outside Rust (e.g. a
# node_exporter textfile written by a shell drill). PLACEMENT IS IRRELEVANT
# and the marker is file-global — deliberately not a proximity heuristic
# (see the longer note at the match site). The reason text MUST contain the
# metric name, optionally with a trailing `*` prefix wildcard; a marker
# that names no `talos_*` series excuses nothing and the check still fails.
# There is no opt-out for (a), (b) or (d): a job an alert needs but nothing
# scrapes, a rules file that resolves to nothing, and one alert name defined
# twice are each the defect itself and have no legitimate form.
PROM_CFG="$ROOT/observability/prometheus/prometheus.yml"
# NOTE: observability/rules/alerts.yml is deliberately NOT named here. The scanned
# rule-file set is DERIVED from rule_files + the compose mounts (see below), so
# that file is picked up because it is mounted, and a third rule file added the
# same way is picked up too. Only the canonical chart file is named explicitly:
# it ships to clusters via the PrometheusRule whether or not dev mounts it.
PROM_RULES_CANON="$ROOT/deploy/helm/talos/files/alerts.yaml"
PROM_FAIL=0

if [ ! -f "$PROM_CFG" ]; then
    # SKIP-BLINDING GUARD (added 2026-08-03 after mutation testing). $PROM_CFG is
    # a hardcoded path, so ANY future move of observability/prometheus/ silently
    # turns this entire check into a ⚠ and exit 0 — mutation-proved: renaming the
    # directory to observability/prom-conf/ and updating BOTH compose files
    # consistently (a legitimate refactor) disabled every leg of check 65. That
    # is the defect this check's own header lectures about, one level up. A skip
    # is only honest when the dev stack genuinely has no Prometheus, so: if any
    # compose file still declares a prometheus service, a missing config is a
    # FAILURE, not a skip. (Deriving $PROM_CFG from the compose mount would be
    # better still and is left as the real fix; this closes the silent-pass.)
    if grep -qE '^[[:space:]]{2}prometheus:[[:space:]]*$' \
            "$ROOT/docker-compose.yml" "$ROOT/docker-compose.observability.yml" 2>/dev/null; then
        red "✗ $PROM_CFG not found, but a compose file still declares a prometheus service"
        yellow "  → the dev Prometheus config moved without updating this check, which would"
        yellow "    otherwise skip silently and take checks 65(a)-(d) with it. Point PROM_CFG"
        yellow "    at the new path."
        PROM_FAIL=1
    else
        yellow "⚠ $PROM_CFG not found and no compose prometheus service — skipping dev-Prometheus check"
    fi
else
    # ── (b) runs FIRST because it also DISCOVERS the file set ──────────
    # (a), (c) and (d) all scan "the mounted rule files". Naming those files
    # in a hardcoded list would make the scan a SNAPSHOT of today's two —
    # add a third rule file, mount it in both stacks and name it in
    # rule_files, and every one of those directions would silently skip it
    # while (b) happily reported the entry as resolved. That is check 64's
    # lesson inside check 65, so the set is DERIVED: whatever the config
    # names and the compose files mount is what gets scanned. The canonical
    # chart file is always added, mounted or not — it ships to clusters via
    # the PrometheusRule regardless of what the dev stack does with it.
    PROM_RESOLVED=""
    # Collect container→host bind mounts from every compose file that
    # mounts this prometheus.yml, so each entry is validated end to end.
    #
    # The detector must match BOTH the single-file mount
    # (`./observability/prometheus/prometheus.yml:/etc/…`) and the directory
    # mount (`./observability/prometheus:/etc/prometheus/conf`) that replaced
    # it on 2026-08-03. This is not hypothetical tidiness: the directory-mount
    # change removed the literal string `observability/prometheus/prometheus.yml`
    # from docker-compose.yml, so a detector keyed to that literal silently
    # dropped docker-compose.yml out of PROM_COMPOSE — quietly undoing the
    # per-stack coverage the 2026-08-02 review had just added, and letting a
    # deleted rule mount and a `:rw` downgrade both PASS. Caught only by
    # mutation-testing the new checks against a deliberately broken tree;
    # the fix that motivates a gate is exactly what is most likely to blind it.
    # The trailing `:` is load-bearing — it matches a MOUNT, not a prose
    # mention of the path in a comment.
    PROM_COMPOSE=()
    for c in "$ROOT/docker-compose.yml" "$ROOT/docker-compose.observability.yml"; do
        [ -f "$c" ] && grep -qE 'observability/prometheus(/prometheus\.yml)?:' "$c" \
            && PROM_COMPOSE+=("$c")
    done
    if [ "${#PROM_COMPOSE[@]}" -eq 0 ]; then
        yellow "⚠ no compose file mounts prometheus.yml — skipping rule_files resolution"
    else
        # rule_files entries: the indented list items under `rule_files:`.
        RULE_ENTRIES="$(awk '
            /^rule_files:/ { inrf=1; next }
            inrf && /^[^[:space:]#]/ { inrf=0 }
            inrf && /^[[:space:]]*-[[:space:]]*/ {
                line=$0
                sub(/^[[:space:]]*-[[:space:]]*/,"",line)
                gsub(/^['"'"'"]|['"'"'"][[:space:]]*$/,"",line)
                sub(/[[:space:]]*#.*$/,"",line)
                if (line != "") print line
            }
        ' "$PROM_CFG")"
        if [ -z "$RULE_ENTRIES" ]; then
            red "✗ prometheus.yml declares no rule_files entries — no alerts would load"
            yellow "  → the canonical rules are deploy/helm/talos/files/alerts.yaml; mount and name them."
            PROM_FAIL=1
        fi
        while IFS= read -r entry; do
            [ -n "$entry" ] || continue
            # Prometheus resolves a relative entry against the config's directory.
            case "$entry" in
                /*) cpath="$entry" ;;
                *)  cpath="/etc/prometheus/$entry" ;;
            esac
            # EVERY compose file that mounts this shared prometheus.yml must
            # provide the mount — not merely one of them. A first-match
            # `break` here would have PASSED the very tree that motivated
            # this check: docker-compose.observability.yml mounted
            # `alerts.yml` while docker-compose.yml (the only stack that can
            # reach Talos) did not, so the entry resolved "somewhere" and the
            # dev stack still loaded zero groups. The config is shared; the
            # mounts that satisfy it must be too, or the two stacks disagree
            # about what the same file means.
            missing_in=""
            for c in "${PROM_COMPOSE[@]}"; do
                # An entry may be satisfied by a mount of the FILE itself or of
                # any ANCESTOR DIRECTORY. Directory mounts became the house
                # style on 2026-08-03: once the host file is REPLACED (a new
                # inode, which every git checkout produces), a single-file bind
                # mount freezes the container's cached SIZE while still reading
                # the current bytes, so the running Prometheus served the new
                # rules TRUNCATED to the superseded file's length — silently,
                # and with /api/v1/rules looking healthy.
                # Resolving only exact file mounts here would have failed the
                # very fix for that bug, so walk the ancestors too.
                m=""; hostfile=""; mode=""
                # 1. exact file mount: `- ./host/file:/container/file[:ro]`
                m="$(grep -oE "\.[^:[:space:]]*:${cpath}(:[a-z,]+)?[[:space:]]*$" "$c" | head -1 || true)"
                if [ -n "$m" ]; then
                    hostfile="$ROOT/$(echo "${m%%:*}" | sed 's|^\./||')"
                    mode="$(echo "$m" | awk -F: 'NF>2{print $NF}')"
                else
                    # 2. ancestor-directory mount. Walk /a/b/c.yml → /a/b → /a.
                    probe="${cpath%/*}"; rest="${cpath##*/}"
                    while [ -n "$probe" ] && [ "$probe" != "/" ]; do
                        m="$(grep -oE "\.[^:[:space:]]*:${probe}(:[a-z,]+)?[[:space:]]*$" "$c" | head -1 || true)"
                        if [ -n "$m" ]; then
                            hostfile="$ROOT/$(echo "${m%%:*}" | sed 's|^\./||')/$rest"
                            mode="$(echo "$m" | awk -F: 'NF>2{print $NF}')"
                            break
                        fi
                        rest="${probe##*/}/$rest"; probe="${probe%/*}"
                    done
                fi
                if [ -z "$m" ]; then
                    missing_in="$missing_in $(basename "$c")"
                    continue
                fi
                # Validate each stack's own host path independently: two
                # compose files may name different sources for one entry.
                if [ ! -f "$hostfile" ]; then
                    red "✗ rule_files entry '$entry': $(basename "$c") mounts it from '${m%%:*}', which yields no file"
                    yellow "  → resolved to '$hostfile', which does not exist; Prometheus would load zero groups."
                    PROM_FAIL=1
                else
                    # Mode was an explicitly documented gap until 2026-08-03: a
                    # silent `:rw` downgrade would have passed. Prometheus never
                    # writes its rules, so anything but read-only is a mistake.
                    if [ "$mode" != "ro" ]; then
                        red "✗ rule_files entry '$entry': $(basename "$c") mounts it '${mode:-rw}', not ':ro'"
                        yellow "  → rule files must be mounted read-only; Prometheus never writes them."
                        PROM_FAIL=1
                    fi
                    PROM_RESOLVED="$PROM_RESOLVED
$hostfile"
                fi
            done
            if [ -n "$missing_in" ]; then
                red "✗ rule_files entry '$entry' is not mounted by:$missing_in"
                yellow "  → no bind mount there provides '$cpath'. Prometheus GLOBS rule_files,"
                yellow "    so this silently loads ZERO rule groups instead of failing — the exact"
                yellow "    defect this check exists for. Every compose file that mounts"
                yellow "    observability/prometheus/prometheus.yml shares its rule_files list and"
                yellow "    must satisfy all of it. Add the mount, or drop the entry."
                PROM_FAIL=1
            fi
        done <<< "$RULE_ENTRIES"
    fi

    # Scan set = every rule file actually reachable through a mount, plus the
    # canonical chart file (which ships whether or not dev mounts it).
    PROM_RULE_FILES=()
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        [ -f "$f" ] || continue
        case "
${PROM_RULE_FILES[*]:-}" in *"$f"*) continue ;; esac
        PROM_RULE_FILES+=("$f")
    done <<< "$PROM_RESOLVED
$PROM_RULES_CANON"
    if [ "${#PROM_RULE_FILES[@]}" -eq 0 ]; then
        yellow "⚠ no Prometheus rule files found — skipping dev-Prometheus check"
    else
        # ── (d) no alert name defined in more than one mounted file ────
        # Prometheus loads every rule_files match independently and does NOT
        # dedup by alert name, so a name defined in two mounted files becomes
        # TWO alerting rules. They fire together on one event and Alertmanager
        # cannot merge them when their label sets differ — two pages, two `for`
        # windows, two contradictory runbooks for one incident.
        # Found live 2026-08-02: `TalosWorkerDown` existed in BOTH
        # observability/rules/alerts.yml (for: 1m, component=worker) and the canonical
        # deploy/helm/talos/files/alerts.yaml (for: 2m, category=availability).
        # It was harmless only while docker-compose.yml mounted NO rules at all;
        # mounting both surfaced it immediately, with both copies observed
        # `firing` on a single worker outage. Fixing the mounts without gating
        # this would just re-arm it. Duplicates WITHIN one file are Prometheus's
        # own problem and are not checked here.
        if [ "${#PROM_RULE_FILES[@]}" -gt 1 ]; then
            DUP_ALERTS="$(for f in "${PROM_RULE_FILES[@]}"; do
                    grep -oE '^[[:space:]]*-[[:space:]]*alert:[[:space:]]*[A-Za-z0-9_]+' "$f" \
                        | sed -E 's/.*alert:[[:space:]]*//' | sort -u
                done | sort | uniq -d)"
            for a in $DUP_ALERTS; do
                red "✗ alert '$a' is defined in more than one mounted rule file"
                yellow "  → Prometheus loads each rule file independently and does not dedup by"
                yellow "    name, so both copies fire on one event; Alertmanager cannot merge them"
                yellow "    when their labels differ. Define it once — the canonical home is"
                yellow "    deploy/helm/talos/files/alerts.yaml (the file the chart's PrometheusRule"
                yellow "    embeds); observability/rules/alerts.yml is dev-only WASM/worker rules."
                PROM_FAIL=1
            done
        fi

        # ── (a) every job an alert selects on must be scraped ──────────
        DECLARED_JOBS="$(grep -oE "job_name:[[:space:]]*'[^']+'|job_name:[[:space:]]*\"[^\"]+\"" "$PROM_CFG" \
            | sed -E "s/job_name:[[:space:]]*['\"]//; s/['\"]$//" | sort -u)"
        SELECTED_JOBS="$(grep -ohE 'up\{[^}]*job="[^"]+"' "${PROM_RULE_FILES[@]}" \
            | grep -oE 'job="[^"]+"' | sed 's/job="//; s/"$//' | sort -u)"
        for j in $SELECTED_JOBS; do
            if ! echo "$DECLARED_JOBS" | grep -qx "$j"; then
                red "✗ alerts select up{job=\"$j\"} but prometheus.yml declares no such job_name"
                yellow "  → the alert can never fire: \`up\` is only produced for jobs that exist."
                yellow "    Add a scrape_config with job_name: '$j' to observability/prometheus/prometheus.yml"
                PROM_FAIL=1
            fi
        done
        # The controller job must use the scrape route, not the dashboard route.
        # Scoped to the job's OWN block (job_name line → the next job_name line),
        # NOT a fixed `grep -A12` window. The window version was exploitable in
        # the UNSAFE direction, proven by mutation 2026-08-02: point the
        # controller job at '/metrics' and give the NEXT job
        # '/metrics/prometheus', and the probe passes on the neighbour's line
        # while the controller scrapes the authenticated dashboard route.
        if echo "$DECLARED_JOBS" | grep -qx 'talos-controller'; then
            CTRL_JOB_BLOCK="$(awk "
                /^[[:space:]]*-[[:space:]]*job_name:[[:space:]]*['\\\"]talos-controller['\\\"]/ { inblk=1; next }
                inblk && /^[[:space:]]*-[[:space:]]*job_name:/ { inblk=0 }
                inblk { print }
            " "$PROM_CFG")"
            if ! echo "$CTRL_JOB_BLOCK" \
                 | grep -qE "^[[:space:]]*metrics_path:[[:space:]]*['\"]/metrics/prometheus['\"]"; then
                red "✗ the talos-controller job does not scrape metrics_path '/metrics/prometheus'"
                yellow "  → '/metrics' is a DIFFERENT, authenticated dashboard route served through"
                yellow "    the GraphQL proxy; only '/metrics/prometheus' emits the talos_* series."
                PROM_FAIL=1
            fi
        fi


        # ── (c) alerted-but-never-registered talos_* / wasm_* metrics ──
        # Scan `expr:` blocks only (block scalars included), stopping at the
        # next sibling key, so annotation prose and comments are excluded.
        #
        # `wasm_*` was added 2026-08-02. Until then (c) inspected only
        # `talos_*`, so the eleven WASM rules in observability/rules/alerts.yml had
        # ZERO coverage from any direction of this check — and SEVEN of them
        # named a series the worker cannot emit under any workload (six
        # distinct metric names; `wasm_errors_total` and
        # `wasm_executions_total` were each selected on by two rules). Most
        # had been written against worker/src/bin/metrics_demo.rs, a demo
        # binary that fabricates `wasm_*` data into its OWN private registry
        # on the port this stack's Prometheus used to scrape — though
        # `wasm_retries_total` was never in the demo either, so that one
        # named a series no producer in the tree had ever exported.
        #
        # THE DOT/UNDERSCORE PROBLEM AND HOW IT IS SOLVED. The worker declares
        # its instruments through OpenTelemetry with DOTS
        # (`meter.u64_counter("wasm.executions")`), and the Prometheus
        # exporter renders them with underscores — so the literal-string
        # evidence that works for `talos_*` finds nothing for `wasm_*`. The
        # derivation below reproduces the exporter's mapping instead:
        #
        #     .  →  _                                          (all kinds)
        #     monotonic counter: append `_total` UNCONDITIONALLY
        #
        # That last word is the whole point and is empirically verified, not
        # assumed: `opentelemetry-prometheus` 0.32 does NOT check whether the
        # name already ends in `total`, so `wasm.executions.total` exported as
        # `wasm_executions_total_TOTAL`. Encoding the rule as "append unless
        # already present" would have made the pre-fix tree PASS this check —
        # i.e. the gate would not catch the bug it exists for. The mapping is
        # pinned from the other side by
        # `exported_prometheus_names_are_stable_and_idle_seeds_at_zero` in
        # talos-worker-runtime, so a dependency bump that changes the
        # exporter's suffix rule breaks a test rather than silently unfiring
        # every WASM alert.
        #
        # LIMITS specific to the wasm_* half, stated rather than implied:
        #   * Evidence for a `wasm_*` name comes ONLY from an OTEL instrument
        #     declaration — never from a quoted literal, unlike `talos_*`.
        #     That is deliberate and is what excludes metrics_demo.rs without
        #     naming it: that file builds raw `prometheus::Counter`s into a
        #     private `Registry::new()` that no scrape endpoint serves, so its
        #     names are evidence of nothing. The cost is that a future
        #     `wasm_*` series registered directly into the default prometheus
        #     registry would read as unregistered — a false positive, which is
        #     the safe direction, and the opt-out below covers it.
        #   * The constructor and the name must be on ONE line
        #     (`.u64_counter("wasm.x")`). A declaration split across lines by
        #     rustfmt reads as no declaration — again the safe direction.
        #   * `.with_unit(...)` is NOT modelled. The exporter appends a unit
        #     suffix when a unit is set; nothing in this workspace sets one,
        #     and if that changes this derivation goes stale in the UNSAFE
        #     direction (it would keep vouching for the unsuffixed name). The
        #     pinning test is the tripwire for that, not this grep.
        ALERT_METRICS="$(awk '
            /^[[:space:]]*expr:[[:space:]]*/ {
                inexpr=1
                line=$0
                sub(/^[[:space:]]*expr:[[:space:]]*/,"",line)
                if (line != "|" && line != "|-" && line != ">" && line != ">-") print line
                next
            }
            inexpr && /^[[:space:]]*(for|labels|annotations|record|alert):[[:space:]]*/ { inexpr=0 }
            inexpr && /^[[:space:]]*-[[:space:]]*alert:/ { inexpr=0 }
            inexpr { print }
        ' "${PROM_RULE_FILES[@]}" | grep -oE '\b(talos|wasm)_[a-z0-9_]+' | sort -u || true)"
        # ONE pass over the Rust sources collecting every quoted `talos_*`
        # string literal, rather than a workspace grep per alert metric.
        # `target/` MUST be excluded: it is ~96 GB of build output on a warm
        # tree, and a name matched inside a vendored or generated source there
        # would also count as "registered" when nothing in this repo registers
        # it. (Learned the slow way while writing this check — the first draft
        # ran 18 unscoped `grep -r` passes and had not finished after 10min.)
        # Metrics explicitly excused from (c) because their producer is not
        # Rust. Parsed from `allow-unobserved-metric:` markers, which must
        # name the series (trailing `*` = prefix wildcard).
        METRIC_EXEMPTIONS="$(grep -h 'allow-unobserved-metric' "${PROM_RULE_FILES[@]}" 2>/dev/null \
            | grep -oE '(talos|wasm)_[a-z0-9_]*\*?' | sort -u || true)"
        REGISTERED_METRICS="$(grep -rhoE '"talos_[a-z0-9_]+"' \
            --include='*.rs' \
            --exclude-dir=target \
            "${TREE_PRUNE_GREP[@]}" \
            "$ROOT" 2>/dev/null | tr -d '"' | sort -u || true)"
        # OTEL instrument declarations → the names the Prometheus exporter
        # actually renders. See the long note above for the mapping and its
        # limits. Applies to every prefix, but in practice only the worker's
        # `wasm_*` instruments are declared this way.
        OTEL_REGISTERED_METRICS="$(grep -rhoE \
            '\.(u64_counter|f64_counter|u64_up_down_counter|i64_up_down_counter|f64_up_down_counter|u64_gauge|i64_gauge|f64_gauge|u64_histogram|f64_histogram|u64_observable_counter|f64_observable_counter|i64_observable_gauge|f64_observable_gauge)\("[a-z0-9_.]+"' \
            --include='*.rs' \
            --exclude-dir=target \
            "${TREE_PRUNE_GREP[@]}" \
            "$ROOT" 2>/dev/null \
            | perl -ne '
                next unless /\.(\w+)\("([a-z0-9_.]+)"/;
                my ($ctor, $name) = ($1, $2);
                $name =~ s/\./_/g;
                # Monotonic counters (NOT up/down counters, which render as
                # gauges) get `_total` appended by the exporter — always,
                # even when the name already ends in `total`.
                $name .= "_total" if $ctor =~ /counter$/ && $ctor !~ /up_down/;
                print "$name\n";
            ' | sort -u || true)"
        for m in $ALERT_METRICS; do
            # Histograms/summaries expose _bucket/_sum/_count suffixes that are
            # generated by the client library, not registered under that name.
            base="$m"
            case "$m" in
                *_bucket) base="${m%_bucket}" ;;
                *_sum)    base="${m%_sum}" ;;
                *_count)  base="${m%_count}" ;;
            esac
            # `wasm_*` is satisfied ONLY by an OTEL declaration (see above);
            # every other prefix accepts a quoted literal too.
            case "$base" in
                wasm_*)
                    if echo "$OTEL_REGISTERED_METRICS" | grep -qx "$base"; then
                        continue
                    fi
                    ;;
                *)
                    if echo "$REGISTERED_METRICS" | grep -qx "$base" \
                       || echo "$OTEL_REGISTERED_METRICS" | grep -qx "$base"; then
                        continue
                    fi
                    ;;
            esac
            # Opt-out for series produced outside Rust (textfile collectors
            # etc.). The marker must NAME the metric it excuses — a trailing
            # `*` is a prefix wildcard, e.g.
            #   # allow-unobserved-metric: talos_backup_drill_* is written by …
            # Deliberately NOT a proximity heuristic ("marker within N lines
            # of the alert"): proximity silently excuses whatever metric a
            # LATER edit happens to add nearby, which is the same
            # blast-radius-by-accident this whole check exists to prevent.
            # (The first draft of this opt-out was proximity-based and did not
            # match at all — it failed loudly, which is the correct direction.)
            if [ -n "$METRIC_EXEMPTIONS" ]; then
                exempt=0
                while IFS= read -r ex; do
                    [ -n "$ex" ] || continue
                    case "$ex" in
                        *\*) [ "${m#"${ex%\*}"}" != "$m" ] && exempt=1 ;;
                        *)   [ "$m" = "$ex" ] && exempt=1 ;;
                    esac
                    [ "$exempt" -eq 1 ] && break
                done <<< "$METRIC_EXEMPTIONS"
                [ "$exempt" -eq 1 ] && continue
            fi
            red "✗ alert expression references '$m', which no Rust source registers"
            yellow "  → an alert on an unregistered series NEVER fires — the read-side twin of"
            yellow "    check 58 (registered but never incremented). Either register the metric,"
            yellow "    fix the name, or — if it is produced outside Rust (e.g. a node_exporter"
            yellow "    textfile) — add a comment in the rule file reading"
            yellow "    '# allow-unobserved-metric: $m is …'. The marker must NAME the series"
            yellow "    (trailing '*' = prefix wildcard); placement does not matter, it is"
            yellow "    matched file-globally, and a marker naming no talos_*/wasm_* series"
            yellow "    excuses nothing."
            case "$m" in
                wasm_*)
                    yellow "    NOTE for wasm_*: evidence must be an OTEL instrument declaration"
                    yellow "    in talos-worker-runtime (e.g. .u64_counter(\"wasm.executions\")), NOT a"
                    yellow "    quoted \"wasm_...\" literal. The exporter renders '.'→'_' and appends"
                    yellow "    '_total' to every counter UNCONDITIONALLY, so an instrument named"
                    yellow "    'wasm.x.total' becomes 'wasm_x_total_total'. Do not put 'total' in an"
                    yellow "    instrument name."
                    ;;
            esac
            PROM_FAIL=1
        done
    fi
fi

if [ "$PROM_FAIL" -eq 1 ]; then
    EXIT_CODE=1
else
    green "✓ dev Prometheus scrapes every alerted job, rule files resolve, alert metrics are registered"
fi
echo

# ── 66: no single-FILE bind mount of a git-tracked config file ────────
bold "▶ check 66: compose bind mounts of tracked files must mount the DIRECTORY"
# A single-file bind mount can leave the container serving CORRUPTED content
# after the host file is replaced — silently: no error, no log line, no
# unhealthy container. Git replaces rather than rewrites in place (verified:
# every `git checkout` of a changed file yields a new inode); atomic-saving
# editors do the same.
#
# OBSERVED live 2026-08-03, after it had already cost a whole cycle. #625
# merged, deployed, its alert on disk; `/api/v1/rules` still reported the
# pre-merge 13 groups / 37 rules with `WASMMetricsPipelineDead` absent. The
# host rules file was 21953 bytes; `docker exec stat` said 6464, and the
# bytes served were a byte-exact 6464-byte PREFIX of the CURRENT host file,
# cut mid-word inside a comment. Two independent confirmations it was a
# prefix of the NEW file and not the old file intact: `cmp` against
# `head -c 6464` matched, and that prefix names WASMMetricsPipelineDead
# exactly once (the live count) where the previous committed version names it
# zero times. 6464 is exactly the previous committed version's byte length.
# It parsed only because the cut landed inside a comment block — mid-value
# the stack would have failed loudly and the bug would have been found in
# minutes rather than surviving three merges. The same shape would truncate a
# scrape config, silently dropping jobs off the tail of prometheus.yml.
#
# MECHANISM, reproduced deterministically 2026-08-03 (Docker Desktop 29.6.2,
# VirtioFS) after two earlier attempts failed. The trigger is the host file
# acquiring a NEW INODE — which every `git checkout` of a changed file does:
#   * edited IN PLACE (inode kept), a single-file mount tracks size and
#     content correctly and indefinitely (measured 100→301→701→1201 bytes);
#   * the FIRST replacement freezes the container's cached SIZE at its
#     last-known value, permanently (observed frozen for 26 h, and not
#     refreshed by later writes, replacements, re-reads, or elapsed time);
#   * the DATA path still resolves by NAME — reads return the CURRENT file's
#     bytes and `open()` gives ENOENT once the host path is gone. So do NOT
#     restate this as "a single-file mount pins the inode": the data
#     demonstrably comes from the NEW file. Only the attributes are stale;
#   * net: current bytes clamped to the frozen size (longer file → the
#     byte-exact prefix above; shorter → `stat` lies, reads are complete);
#   * `docker restart` re-binds and clears it.
# A same-length replacement cannot exhibit the bug at all and will "prove"
# the mount is fine — which is how the first two attempts came back negative.
#
# The rule is a large reduction, not a proof. A DIRECTORY mount resolves the
# name at access time and was correct in every equivalent test, including on
# a four-day-old container and across kill+start — but one directory-mounted
# container was seen frozen across two replacements and could not be made to
# do it again. The live half (scripts/verify-observability.sh) is what
# actually catches the symptom regardless of cause.
#
# SCOPE: git-TRACKED sources only. An untracked/generated file is not
# replaced by git operations and is a different (weaker) story, so flagging
# it would be noise. Long-syntax (`type: bind`) mounts are not recognised —
# the repo uses short syntax exclusively; that is the safe direction (a
# missed mount is a false negative, never a false positive). Only host paths
# written `./relative` are considered (an absolute or `${VAR}` source is not
# a repo file).
#
# LIMITS worth stating rather than implying:
#  * this is a STATIC check. It proves the mounts are shaped correctly; it
#    cannot prove the running container is reading the current bytes — a
#    container started before the fix still serves stale content through a
#    now-correct compose file. That half needs a live stack and lives in
#    scripts/verify-observability.sh (`make observability-verify`),
#    deliberately NOT here, because a CI lint with no stack could only skip,
#    and a check that skips is not a gate.
#  * only the three compose files enumerated below are scanned.
#    docker-compose.override.yml is deliberately excluded because it is
#    gitignored and per-developer — but that does mean a single-file mount
#    added there is invisible to this check (same shape as check 65's
#    PROM_COMPOSE limit).
#
# Opt-out: `# allow-single-file-mount: <reason>` on the mount line or the
# line above it.
MOUNT_FAIL=0
for cf in docker-compose.yml docker-compose.observability.yml docker-compose.prod.yml; do
    [ -f "$ROOT/$cf" ] || continue
    while IFS= read -r ln; do
        num="${ln%%:*}"
        body="${ln#*:}"
        # `- ./host/path:/container/path[:mode]` — relative host paths only
        # (an absolute or ${VAR} source is not a repo file).
        hp="$(printf '%s' "$body" | sed -nE 's|^[[:space:]]*-[[:space:]]*(\./[^:[:space:]]+):/[^:[:space:]]+(:[a-z,]+)?[[:space:]]*$|\1|p')"
        [ -n "$hp" ] || continue
        rel="${hp#./}"
        # Directory sources are the desired shape.
        [ -f "$ROOT/$rel" ] || continue
        # Untracked sources are out of scope (git does not replace them).
        git -C "$ROOT" ls-files --error-unmatch "$rel" >/dev/null 2>&1 || continue
        # Opt-out on this line or the one above it.
        if printf '%s' "$body" | grep -q 'allow-single-file-mount:'; then continue; fi
        prev="$(sed -n "$((num - 1))p" "$ROOT/$cf")"
        if printf '%s' "$prev" | grep -q 'allow-single-file-mount:'; then continue; fi
        red "✗ $cf:$num bind-mounts the tracked FILE '$rel'"
        yellow "  → a single-file bind mount pins the container to that file's"
        yellow "    cached size once the file is REPLACED; a git checkout then serves"
        yellow "    the new bytes TRUNCATED to the old length, silently. Mount its parent"
        yellow "    DIRECTORY instead — and make sure that directory contains ONLY"
        yellow "    files this container should read, since a directory mount exposes"
        yellow "    all of them. Opt out with '# allow-single-file-mount: <reason>'."
        MOUNT_FAIL=1
    done < <(grep -nE '^[[:space:]]*-[[:space:]]*\./[^:[:space:]]+:/' "$ROOT/$cf" || true)
done
if [ "$MOUNT_FAIL" -eq 1 ]; then
    EXIT_CODE=1
else
    green "✓ no compose service bind-mounts a tracked config file singly"
fi
echo

# ── 67. The fleet heartbeat must never touch the trust boundary ───────
# A NATS `WorkerHeartbeat` is HMAC-signed under `WORKER_SHARED_KEY`, which is
# FLEET-SHARED: any process holding that key can mint one naming any
# `worker_id`. A #631 liveness ping is an Ed25519 proof of possession of THAT
# worker's own registered private key. The two look alike from a distance and
# are worlds apart as evidence.
#
# So if the fleet-view code could write `worker_identities.last_liveness_at`,
# any shared-key holder could keep any worker's signing key trusted forever
# and the identity reaper would never act — the unbounded-trust gap #631 was
# built to close, reopened by an observability feature. The temptation is
# real and specific: "the heartbeat already tells us the worker is alive, why
# make it ping over HTTP too?"
#
# The in-crate unit test `heartbeat_never_touches_the_trust_boundary` asserts
# the same thing, but a test can be deleted in the same commit that
# introduces the write. This is the gate that cannot.
#
# Two directions, both scoped to `talos-worker-fleet/` (the crate that OWNS
# the fleet view):
#   (a) no source line may name the trust-boundary column or its writer;
#   (b) its `[dependencies]` may not include anything it could reach the
#       identity registry through (sqlx, the worker-identity repository, an
#       HTTP client) — (a) alone would be defeated by a helper in another
#       crate, so the dependency edge is cut too.
# Comment lines are exempt: the crate documents this rule at length, and a
# rule you may not explain is worse than no rule.
bold "▶ check 67: the fleet heartbeat must not reach the identity trust boundary"
HB_FAIL=0
HB_SRC_DIR="$ROOT/talos-worker-fleet/src"
if [ -d "$HB_SRC_DIR" ]; then
    # `#[cfg(test)]` regions are dropped from the haystack, exactly like check
    # 58 does, and for a reason that is not hypothetical: the in-crate test
    # `heartbeat_never_touches_the_trust_boundary` asserts this same rule by
    # scanning for these strings, so it necessarily CONTAINS them. Without the
    # strip this check fails on a clean tree — the rule's own guard tripping
    # the gate. A region ends at the first column-0 `}`, so code AFTER a test
    # module is still scanned (a truncate-to-EOF strip would have made the
    # mutation used to validate this check invisible). Stated limit: a write
    # performed inside a `#[cfg(test)] mod` is not seen — the safe direction,
    # since test code is not production code.
    HB_HAYSTACK="$(mktemp)"
    for f in $(find "$HB_SRC_DIR" -name '*.rs' 2>/dev/null); do
        awk -v F="$f" '
            /^#\[cfg\(test\)\]/ { intest=1 }
            intest && /^\}/        { intest=0; next }
            !intest                 { print F ":" NR ":" $0 }
        ' "$f" >> "$HB_HAYSTACK"
    done
    while IFS= read -r hit; do
        [ -z "$hit" ] && continue
        red "✗ talos-worker-fleet touches the identity trust boundary: $hit"
        yellow "  → a heartbeat is minted under the FLEET-SHARED key, so it must never"
        yellow "    write last_liveness_at, re-activate an identity, or otherwise keep a"
        yellow "    signing key trusted. That is the Ed25519 liveness ping's job (#631)."
        HB_FAIL=1
    done < <(grep -E '(last_liveness_at|touch_liveness|worker_identities)' "$HB_HAYSTACK" \
             | grep -vE ':[0-9]+:[[:space:]]*(//|\*)' || true)
    rm -f "$HB_HAYSTACK"

    HB_DEPS="$(awk '/^\[dependencies\]/{f=1;next} /^\[/{f=0} f' "$ROOT/talos-worker-fleet/Cargo.toml" 2>/dev/null || true)"
    for forbidden in sqlx talos-worker-identity-repository reqwest; do
        if echo "$HB_DEPS" | grep -q "$forbidden"; then
            red "✗ talos-worker-fleet depends on '$forbidden'"
            yellow "  → the fleet view must have no path to the identity registry at all;"
            yellow "    cutting the dependency edge is what makes the rule structural"
            yellow "    rather than a matter of which line got written today."
            HB_FAIL=1
        fi
    done
fi
if [ "$HB_FAIL" -eq 1 ]; then
    EXIT_CODE=1
else
    green "✓ the fleet heartbeat cannot reach the identity trust boundary"
fi
echo

# ── 68. Catalog templates must be compiled through CatalogTemplate ────
#
# `talos.json`'s `dependencies` field is the ONLY dependency declaration the
# runtime reads for a catalog template. Between 2026-07 and 2026-08-11 FIVE
# code paths compiled a catalog template and only ONE forwarded it:
# the disk seeder (every controller boot), the `publish-templates` OCI
# publisher, `restore_pinned_modules`, and — via a `modules.dependencies`
# column the seeder never wrote — `compile_template`. Three shipped templates
# consequently failed to compile at every single boot with
# `use of unresolved module or unlinked crate`, their `wasm_bytes` stayed
# NULL (they could not run at all), and `make check-catalog` was green the
# whole time because IT read the manifest.
#
# The fix is `talos_compilation::catalog::CatalogTemplate` — the one reader
# of a template directory, carrying source and declared dependencies as a
# unit, consumed by `CompilationService::compile_catalog_template`. The
# dependency-less `compile_to_wasm(user, job, name, source)` convenience was
# DELETED so the footgun cannot be re-acquired.
#
# It was not five paths. It was SIX — and the sixth is what makes this a
# lint rather than a patch. `talos-api`'s `createModuleFromTemplate` resolves
# a template row through the SAME `registry.get_template_for_user` as its MCP
# twin `handle_compile_template`, and passed `None` where the twin passes
# `template.dependencies.as_ref()`. While `modules.dependencies` was NULL for
# all 75 catalog rows the two were equally (invisibly) broken; the moment the
# seeder started populating that column, the same template compiled under MCP
# and failed under GraphQL. A uniform bug became a protocol-dependent one —
# inside the change whose thesis is "patching a site is not fixing a class".
# Leg (d) exists because neither (a) nor (b) could see that file: it contains
# neither `module-templates` nor a manifest read.
#
# Four directions:
#   (a) the manifest key `"dependencies"` may be read from a parsed
#       `talos.json` in exactly one place — `catalog.rs`. Scoped to receivers
#       whose NAME CONTAINS meta/manifest/tpl/talos_json (so `manifest_json`,
#       `template_manifest` and `raw_meta` are all covered), in both the
#       `.get("dependencies")` and `["dependencies"]` spellings, so
#       caller-supplied `args.get("dependencies")` — a different thing
#       entirely — is not swept up.
#   (b) any non-test source file that resolves a catalog template directory
#       (`module-templates`) AND calls into the compiler must name
#       `CatalogTemplate`. "Calls into the compiler" is matched as
#       `compile_*wasm` (so `compile_js_to_wasm` / `compile_python_to_wasm`
#       count, which the original literal `compile_to_wasm` grep missed)
#       or `compile_catalog_template`.
#   (c) the dependency-less `compile_to_wasm(user, job, name, source)`
#       convenience must stay deleted — its existence is what made `None` the
#       path of least resistance at four call sites. Scanned across ALL of
#       `talos-compilation/src/`, not just `lib.rs`, and tolerant of a
#       generic parameter list, because both were trivial evasions.
#   (d) a compile of a TEMPLATE ROW must forward its `dependencies`. Scoped
#       per-CALL (paren-balanced argument window, so it is the call and not
#       the file that must be clean) to files that resolve a row via
#       `get_template_for_user` — the one resolver returning a `NodeTemplate`
#       that carries the column. A call there whose arguments never mention
#       `dependencies` is the GraphQL regression above.
#
# STATED LIMITS, because a lint is only worth what it actually checks — and
# overstating one is the defect class this arc keeps finding (CLAUDE.md check
# 58). Every limit below was confirmed by mutation, not inferred:
#   * Every leg is TEXTUAL. (a) is defeated by a receiver whose name contains
#     none of the four stems (`let j: Value = …; j.get("dependencies")`) and
#     by any indirection (`let k = "dependencies"; m.get(k)`). (b) is defeated
#     by resolving the catalog directory through a constant defined in another
#     file. (c) is defeated by a differently-NAMED dependency-less convenience
#     (`compile_simple(…)`) — it pins one identifier, not a shape. The TYPE is
#     the real control; this is the backstop that makes bypassing it
#     deliberate.
#   * (b) fires on the FILE, not the call. A file that legitimately compiles
#     non-catalog source AND separately mentions `module-templates` satisfies
#     it merely by also using `CatalogTemplate` somewhere.
#   * (d) is scoped by an ADJACENT string (`get_template_for_user` present in
#     the same file), so a future handler that resolves a template row through
#     a NEW repository method, or in a different file from the compile call,
#     is invisible to it. It also only proves the token `dependencies` appears
#     in the argument list — `dependencies: None` would satisfy it. Neither
#     (d) nor any other leg can prove the forwarded VALUE is right, only that
#     something was forwarded. `talos-compilation`'s `catalog_template_tests`
#     cover the value; `scripts/check-catalog.sh` covers the templates.
# Opt-outs: `// allow-raw-catalog-deps: <reason>` (a),
#           `// allow-uncatalogued-compile: <reason>` (b),
#           `// allow-depless-compile: <reason>` (d) — on or within 8 lines
#           above the call, for a compile of caller-supplied source that has
#           no template row behind it.
bold "▶ check 68: catalog compiles must go through CatalogTemplate"
CT_FAIL=0
CT_HOME="talos-compilation/src/catalog.rs"

# (a) single manifest reader
while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    file="${hit%%:*}"
    [ "$file" = "$CT_HOME" ] && continue
    case "$hit" in *allow-raw-catalog-deps*) continue ;; esac
    red "✗ catalog manifest \`dependencies\` read outside $CT_HOME: $hit"
    yellow "  → use talos_compilation::CatalogTemplate::dependencies(). One reader is"
    yellow "    what stops the next compile path from quietly omitting the field."
    CT_FAIL=1
done < <(cd "$ROOT" && grep -rnE '\b[A-Za-z_][A-Za-z0-9_]*(meta|manifest|tpl|talos_json)[A-Za-z0-9_]*\s*(\.\s*get\("dependencies"\)|\["dependencies"\])|\b(meta|manifest|tpl|talos_json)\s*(\.\s*get\("dependencies"\)|\["dependencies"\])' \
         --include='*.rs' --exclude-dir=target "${TREE_PRUNE_GREP[@]}" . 2>/dev/null \
         | sed 's|^\./||' | grep -v '^target/' || true)

# (b) catalog-dir readers that compile must use the type
while IFS= read -r file; do
    [ -z "$file" ] && continue
    [ "$file" = "$CT_HOME" ] && continue
    case "$file" in */tests/*|*_tests.rs|*/test_support.rs) continue ;; esac
    grep -q 'module-templates' "$ROOT/$file" || continue
    grep -qE 'compile_[a-z_]*wasm|compile_catalog_template' "$ROOT/$file" || continue
    grep -q 'allow-uncatalogued-compile' "$ROOT/$file" && continue
    grep -q 'CatalogTemplate' "$ROOT/$file" && continue
    red "✗ $file resolves a catalog template dir and compiles, but never names CatalogTemplate"
    yellow "  → load it with talos_compilation::CatalogTemplate::load(dir) and compile via"
    yellow "    CompilationService::compile_catalog_template, so the template's declared"
    yellow "    dependencies cannot be dropped on this path."
    CT_FAIL=1
done < <(cd "$ROOT" && grep -rl 'module-templates' --include='*.rs' --exclude-dir=target "${TREE_PRUNE_GREP[@]}" . 2>/dev/null \
         | sed 's|^\./||' | grep -v '^target/' || true)

# (c) the dependency-less convenience must stay deleted. Whole crate, and a
# generic parameter list does not hide it.
if (cd "$ROOT" && grep -rqE 'fn compile_to_wasm\s*(<[^>]*>)?\s*\(' talos-compilation/src/ 2>/dev/null); then
    red "✗ CompilationService::compile_to_wasm (the dependency-less convenience) is back"
    yellow "  → it defaults dependencies to None. Catalog callers must take a CatalogTemplate;"
    yellow "    non-catalog callers should pass their deps explicitly to"
    yellow "    compile_to_wasm_with_config."
    CT_FAIL=1
fi

# (d) template-row compiles must forward the row's dependencies
while IFS= read -r file; do
    [ -z "$file" ] && continue
    case "$file" in */tests/*|*_tests.rs|*/test_support.rs) continue ;; esac
    grep -q 'get_template_for_user' "$ROOT/$file" || continue
    while IFS= read -r ln; do
        [ -z "$ln" ] && continue
        red "✗ $file:$ln compiles a template row without forwarding its \`dependencies\`"
        yellow "  → pass template.dependencies.as_ref(). Its twin does; when the two disagree,"
        yellow "    the SAME template compiles on one protocol and fails E0433 on the other."
        yellow "  → if this call builds caller-supplied source with no template row behind it,"
        yellow "    mark it \`// allow-depless-compile: <reason>\`."
        CT_FAIL=1
    done < <(cd "$ROOT" && perl -0777 -ne '
        my @lines = split /\n/, $_, -1;
        while (/compile_to_wasm_with_config\s*\(/g) {
            my $start = pos($_);
            my ($depth, $i, $len) = (1, $start, length($_));
            while ($i < $len && $depth > 0) {
                my $c = substr($_, $i, 1);
                $depth++ if $c eq "(";
                $depth-- if $c eq ")";
                $i++;
            }
            my $args = substr($_, $start, $i - $start - 1);
            next if $args =~ /dependencies/;
            my $lnum = (substr($_, 0, $start) =~ tr/\n//) + 1;
            my $lo = $lnum - 9; $lo = 0 if $lo < 0;
            my $hi = $lnum + 2; $hi = $#lines if $hi > $#lines;
            next if join("\n", @lines[$lo .. $hi]) =~ /allow-depless-compile/;
            print "$lnum\n";
        }' "$file" || true)
done < <(cd "$ROOT" && grep -rl 'compile_to_wasm_with_config' --include='*.rs' --exclude-dir=target "${TREE_PRUNE_GREP[@]}" . 2>/dev/null \
         | sed 's|^\./||' | grep -v '^target/' || true)

if [ "$CT_FAIL" -eq 1 ]; then
    EXIT_CODE=1
else
    green "✓ catalog template compiles route through CatalogTemplate"
fi
echo

# ── 69. Unconfigured tracing must mean DISABLED ───────────────────────
# `talos_trace::init_tracing(name, None)` is documented to build no exporter
# ("No endpoint configured, tracing disabled"). Both binaries made that path
# UNREACHABLE by substituting a default for the unset case:
#
#     std::env::var("JAEGER_ENDPOINT").ok().or_else(|| Some("http://localhost:4317"))
#
# Nothing sets JAEGER_ENDPOINT — not docker-compose, not the Helm chart — so
# every controller and worker built a batch span processor aimed at its own
# container's localhost, failed every export, and logged an
# ERROR `BatchSpanProcessor.ExportError` per flush while the Jaeger it could
# have reached sat empty for 36 h. An ERROR that fires forever on a healthy
# fleet trains operators to ignore ERROR, which is the harm.
#
# Two legs, because either alone is trivially evaded:
#  (a) a file that CALLS init_tracing must resolve its endpoint through the
#      shared chokepoint `endpoint_from_env` — this is the "chokepoint that
#      misses a site" guard: the defect existed identically in TWO binaries
#      and fixing one would have made it protocol-dependent;
#  (b) the three endpoint env vars may only be READ inside talos-trace, so a
#      new site cannot re-derive the endpoint (and re-add a default) in a file
#      that never mentions init_tracing.
#
# STATED LIMITS, each demonstrated rather than asserted:
#  * Both legs are TEXTUAL. A caller that receives an already-resolved
#    `Option<String>` from a third crate satisfies (a) without (b) ever seeing
#    an env read — invisible to both. So is an endpoint sourced from a config
#    struct or a CLI flag rather than the environment.
#  * (a) fires on the FILE, not the call. An opt-out therefore blinds the file
#    to a FUTURE init_tracing added to it. One opt-out exists today
#    (worker/src/bin/observability_test.rs, a developer-run demo where
#    localhost genuinely IS the Jaeger).
#  * (b) matches the literal variable names; a name assembled at runtime
#    (`env::var(format!("JAEGER_{}", x))`) evades it.
#  * Neither leg can prove the RESOLVED VALUE is right — only that resolution
#    went through the one function whose "unset ⇒ None" behaviour is unit
#    tested (`nothing_configured_resolves_to_none_not_a_default`).
bold "▶ check 69: unconfigured tracing must mean disabled (no localhost default)"
TRACE_FAIL=0
TRACE_HOME="talos-trace/src/lib.rs"

# (a) init_tracing callers must go through the chokepoint.
while IFS= read -r file; do
    [ -z "$file" ] && continue
    [ "$file" = "$TRACE_HOME" ] && continue
    case "$file" in */tests/*|*_tests.rs|*/test_support.rs) continue ;; esac
    grep -q 'allow-hardcoded-trace-endpoint' "$ROOT/$file" && continue
    grep -q 'endpoint_from_env' "$ROOT/$file" && continue
    red "✗ $file calls init_tracing() without resolving via endpoint_from_env()"
    yellow "  → use talos_trace::endpoint_from_env(); an unset variable must yield None,"
    yellow "    which is what makes init_tracing build no exporter. Substituting a"
    yellow "    default (e.g. http://localhost:4317) points the exporter at the process"
    yellow "    itself and logs BatchSpanProcessor.ExportError on every flush, forever."
    yellow "  → a demo/manual binary may mark itself \`// allow-hardcoded-trace-endpoint: <reason>\`."
    TRACE_FAIL=1
done < <(cd "$ROOT" && grep -rlE '\binit_tracing\s*\(' --include='*.rs' --exclude-dir=target "${TREE_PRUNE_GREP[@]}" . 2>/dev/null \
         | sed 's|^\./||' | grep -v '^target/' || true)

# (b) endpoint env vars are read in exactly one place.
while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    file="${hit%%:*}"
    [ "$file" = "$TRACE_HOME" ] && continue
    case "$file" in */tests/*|*_tests.rs|*/test_support.rs) continue ;; esac
    case "$hit" in *allow-hardcoded-trace-endpoint*) continue ;; esac
    red "✗ trace-endpoint env var read outside $TRACE_HOME: $hit"
    yellow "  → resolution lives in talos_trace::endpoint_from_env (JAEGER_ENDPOINT >"
    yellow "    OTEL_EXPORTER_OTLP_TRACES_ENDPOINT > OTEL_EXPORTER_OTLP_ENDPOINT, first"
    yellow "    non-empty wins, else None). A second reader is a second chance to"
    yellow "    re-introduce the default that made 'disabled' unreachable."
    TRACE_FAIL=1
done < <(cd "$ROOT" && grep -rnE 'env::var\s*\(\s*"(JAEGER_ENDPOINT|OTEL_EXPORTER_OTLP_TRACES_ENDPOINT|OTEL_EXPORTER_OTLP_ENDPOINT)"' \
         --include='*.rs' --exclude-dir=target "${TREE_PRUNE_GREP[@]}" . 2>/dev/null \
         | sed 's|^\./||' | grep -v '^target/' \
         | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true)
# ^ comment lines are dropped: the fix's own comments QUOTE the removed
#   expression verbatim so the next reader knows what not to write, and the
#   first run of this check flagged exactly those two comments. A commented
#   env read cannot resolve an endpoint, so this is a correctness fix, not a
#   weakening — but it does mean a read hidden inside a `/* */` block or on a
#   line-continuation after a comment is invisible (safe direction: it also
#   cannot execute).

if [ "$TRACE_FAIL" -eq 1 ]; then
    EXIT_CODE=1
else
    green "✓ trace endpoint resolves through talos_trace::endpoint_from_env"
fi
echo

# ── 70. tenant-scoped natural keys: a write keyed on the non-tenant half
#        of a composite UNIQUE (tenant_col, X) must also constrain tenant_col ─
# #656: `restore_pinned_modules` read under `begin_user_scoped` + `pm.user_id
# = $1`, then wrote `UPDATE modules … SET wasm_bytes = $1 WHERE name = $2`
# with NO owner predicate. The severity turned entirely on a SCHEMA fact —
# `modules.name` is unique only PER USER (`modules_user_name_uniq (user_id,
# name) WHERE user_id IS NOT NULL`) — so "3 of YOUR pins restored" wrote
# 3 × every tenant holding those names. A `WHERE <natural key> = $N` looks
# perfectly ordinary; only the index definition says it addresses more than
# one tenant's row. This check reads that index definition FOR you.
#
# The table→(tenant_col, natural_col) map is DERIVED from migrations/, never
# hardcoded (hardcoded lists rot — #624): CREATE UNIQUE INDEX, inline
# UNIQUE(...) and composite PRIMARY KEY(...) in CREATE TABLE, ADD CONSTRAINT
# … UNIQUE, with ALTER TABLE … RENAME TO / RENAME COLUMN applied.
#
# STATED LIMITS, each confirmed by running the check rather than inferred:
#  (a) TEXTUAL. The statement window is the enclosing string literal,
#      truncated heuristically; SQL assembled with format!() is invisible.
#  (b) An alias-qualified column IS handled (`WHERE m.name = $2` fires) but
#      only for a single-segment alias.
#  (c) It proves a tenant column is CONSTRAINED, never that it is constrained
#      to the RIGHT tenant — `WHERE name = $1 AND user_id = $2` passes
#      whatever $2 is. Cross-org injection is checks 25/42's business.
#  (d) Test files are excluded: `talos-advanced-repository/tests/scratch_rls.rs`
#      and `talos-db/tests/rls_org_isolation.rs` deliberately issue unscoped
#      deletes to PROVE RLS blocks them; firing there would be backwards.
#  (e) A partial-index conflict arbiter (`ON CONFLICT (name) WHERE user_id IS
#      NULL`) counts as constrained — that is the catalog idiom in
#      talos-registry and it is correct.
# Opt-out: `// allow-untenanted-natural-key: <reason>` on or within 8 lines
# above the write.
bold "▶ check 70: writes keyed on a per-tenant-unique natural key must constrain the tenant column"

NATKEY_VIOLATIONS=0
NATKEY_MAP="$(perl -0777 -e '
my %uniq; my %tbl_rename; my %col_rename;
my @files = glob("migrations/*.sql");
for my $f (@files) {
    open(my $fh, "<", $f) or next; local $/; my $s = <$fh>; close $fh;
    $s =~ s/--[^\n]*//g; $s = lc $s;
    while ($s =~ /alter\s+table\s+(?:if\s+exists\s+)?([a-z0-9_]+)\s+rename\s+to\s+([a-z0-9_]+)/g) { $tbl_rename{$1} = $2; }
    while ($s =~ /alter\s+table\s+(?:if\s+exists\s+)?([a-z0-9_]+)[^;]{0,200}?rename\s+column\s+([a-z0-9_]+)\s+to\s+([a-z0-9_]+)/g) { $col_rename{"$1.$2"} = $3; }
    while ($s =~ /create\s+unique\s+index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?[a-z0-9_]+\s+on\s+([a-z0-9_.]+)\s*(?:using\s+\w+\s*)?\(([^)]*)\)/g) {
        my ($t,$c)=($1,$2); $t =~ s/.*\.//; push @{$uniq{$t}}, [map { my $x=$_; $x =~ s/^\s+|\s+$//g; $x =~ s/\s.*//; $x } split(/,/,$c)];
    }
    while ($s =~ /alter\s+table\s+(?:if\s+exists\s+)?([a-z0-9_.]+)[^;]{0,300}?add\s+constraint\s+[a-z0-9_]+\s+unique\s*\(([^)]*)\)/gs) {
        my ($t,$c)=($1,$2); $t =~ s/.*\.//; push @{$uniq{$t}}, [map { my $x=$_; $x =~ s/^\s+|\s+$//g; $x } split(/,/,$c)];
    }
    while ($s =~ /create\s+table\s+(?:if\s+not\s+exists\s+)?([a-z0-9_.]+)\s*\(/g) {
        my $t = $1; $t =~ s/.*\.//; my $start = pos($s) - 1; my $d = 0; my $end = -1;
        for (my $i=$start; $i < length($s); $i++) {
            my $ch = substr($s,$i,1);
            if ($ch eq "(") { $d++ } elsif ($ch eq ")") { $d--; if ($d==0) { $end=$i; last } }
        }
        next if $end < 0;
        my $body = substr($s, $start+1, $end-$start-1);
        while ($body =~ /\b(?:unique|primary\s+key)\s*\(([^)]*)\)/g) {
            my @c = map { my $x=$_; $x =~ s/^\s+|\s+$//g; $x } split(/,/,$1);
            push @{$uniq{$t}}, \@c if @c > 1;
        }
    }
}
my %TEN = map { $_ => 1 } qw(user_id org_id actor_id created_by owner_user_id owner_id tenant_id);
my %seen;
for my $t (sort keys %uniq) {
    my $tn = $tbl_rename{$t} // $t;
    for my $combo (@{$uniq{$t}}) {
        my @cols = map { $col_rename{"$t.$_"} // $col_rename{"$tn.$_"} // $_ } @$combo;
        next if @cols < 2;
        my @ten = grep { $TEN{$_} } @cols;
        my @nat = grep { !$TEN{$_} } @cols;
        next unless @ten && @nat;
        my $k = "$tn|" . join(",",@ten) . "|" . join(",",@nat);
        next if $seen{$k}++;
        print "$k\n";
    }
}
')"

natkey_tables="$(echo "$NATKEY_MAP" | cut -d'|' -f1 | sort -u)"
for tbl in $natkey_tables; do
    [ -n "$tbl" ] || continue
    files=$(grep -rlE "(UPDATE[[:space:]]+${tbl}\b|DELETE[[:space:]]+FROM[[:space:]]+${tbl}\b|INTO[[:space:]]+${tbl}\b)" \
        --include='*.rs' talos-* controller worker 2>/dev/null \
        | grep -vE '/tests/|_tests\.rs|/test_support\.rs' || true)
    for file in $files; do
        [ -f "$file" ] || continue
        while IFS='|' read -r maptbl tencols natcols; do
            [ "$maptbl" = "$tbl" ] || continue
            OFFENDERS=$(TBL="$tbl" TEN="$tencols" NAT="$natcols" perl -0777 -ne '
                my $tbl = $ENV{TBL};
                $_ =~ s{//[^\n]*}{}g;   # a doc comment quoting SQL is prose, not a statement
                my @ten = split(/,/, $ENV{TEN});
                my @nat = split(/,/, $ENV{NAT});
                sub constrained {
                    my ($scope, $col) = @_;
                    return $scope =~ /(?:^|[^a-zA-Z0-9_.])(?:[a-zA-Z_][a-zA-Z0-9_]*\.)?\Q$col\E\s*(?:=|<>|!=|\bIN\b|\bLIKE\b|\bILIKE\b|\bIS\s+(?:NOT\s+)?NULL\b)/i;
                }
                while (/((?:UPDATE\s+|DELETE\s+FROM\s+|INTO\s+)\Q$tbl\E\b)/gi) {
                    my $at = $-[0];
                    my $win = substr($_, $at, 1400);
                    if ($win =~ /("\#|",|"\)|"\s*\n)/) { $win = substr($win, 0, $-[0]); }
                    my $scope = "";
                    if ($win =~ /\bWHERE\b/i) { $scope = substr($win, $-[0]); }
                    my $conflict = "";
                    if ($win =~ /ON\s+CONFLICT\s*\(([^)]*)\)([^(]{0,80}?)DO\s/is) { $conflict = "$1 $2"; }
                    for my $region ($scope, $conflict) {
                        next unless length $region;
                        my $hits_nat = 0; my $hits_ten = 0;
                        for my $c (@nat) { $hits_nat = 1 if constrained($region, $c); }
                        for my $c (@ten) { $hits_ten = 1 if constrained($region, $c); }
                        if ($hits_nat && !$hits_ten) {
                            my $ln = 1 + (substr($_, 0, $at) =~ tr/\n//);
                            print "$ln\n"; last;
                        }
                    }
                }
            ' "$file" || true)
            for lineno in $OFFENDERS; do
                start=$((lineno > 8 ? lineno - 8 : 1))
                if sed -n "${start},$((lineno + 2))p" "$file" | grep -q '// allow-untenanted-natural-key:'; then
                    continue
                fi
                red "✗ ${file}:${lineno}: write on '${tbl}' keyed on '${natcols}' without constraining '${tencols}'"
                yellow "    UNIQUE (${tencols}, ${natcols}) — this key addresses one row PER TENANT, so the write spans tenants"
                NATKEY_VIOLATIONS=$((NATKEY_VIOLATIONS + 1))
            done
        done <<< "$NATKEY_MAP"
    done
done

if [ "$NATKEY_VIOLATIONS" -gt 0 ]; then
    red "✗ ${NATKEY_VIOLATIONS} write(s) key on a per-tenant-unique natural key with no tenant predicate"
    yellow "  → add the tenant column to the WHERE (or to the ON CONFLICT arbiter)"
    yellow "  → or mark '// allow-untenanted-natural-key: <reason>' for a deliberate system-wide write"
    EXIT_CODE=1
else
    green "✓ every write on a per-tenant-unique natural key constrains its tenant column"
fi
echo

# ── 71. the graph-node-id → UUID mapping has exactly one implementation ──
# `execution_events.node_id` does NOT carry the graph's string node id — it
# carries what `talos_workflow_engine_core::engine_node_uuid` derives from it
# (the id verbatim if it parses as a UUID, else the first 16 bytes of
# SHA-256(id) as raw UUID bytes — deliberately NOT Uuid::new_v5, which would
# rewrite the version/variant nibbles and orphan every row already on disk).
#
# #693 made that function the single writer but left the READERS forking the
# arithmetic: 7 private copies across talos-mcp-handlers (executions.rs ×4,
# analytics.rs ×2) and talos-failure-analysis-service, plus a test that pinned
# the map against its OWN re-derivation instead of against observed rows.
#
# The failure mode is what makes this worth a lint rather than a style note.
# A drifted copy does not error, does not panic, and does not log: its join
# key stops matching any row, the query returns zero rows, and every surface
# built on it — the node failure breakdown, the execution trace, the failure
# analyser's label resolution — renders that as "no problems found". A
# confidently wrong answer, from a one-character difference, in code that
# still compiles. The producer end has been guarded since #693; this guards
# the reading end.
#
# DETECTION (shape, not string): a `Uuid::from_bytes|from_slice|from_bytes_le|
# from_u128` construction with a `Sha256::digest` in the 8 lines above it.
# That window is the whole idiom — digest → [0u8;16] → copy_from_slice →
# from_bytes is four lines — so it fires on a reformatted or renamed copy, not
# just on a verbatim one. The canonical home (node_identity.rs) is the only
# unconditional exemption.
#
# STATED LIMITS (each confirmed by running the check, not inferred):
#  (a) TEXTUAL and window-bounded. A copy that spreads the digest and the
#      construction more than 8 lines apart, or that hands the bytes through
#      a helper function, is invisible.
#  (b) It cannot tell a node-id derivation from any OTHER Sha256→UUID of the
#      same shape. Two exist and are deliberately independent — gcal's
#      `oauth_account_id` and talos-google-cloud's `derive_provider_key`, both
#      keyed on Google's immutable ACCOUNT id. They carry the opt-out.
#  (c) Tests are NOT exempt. A test that re-derives the expected value locally
#      passes even when the production copy and the test drift together, which
#      is exactly what talos-failure-analysis-service's pin did; the fix is to
#      pin against ids read out of a live events table.
#  (d) The three token-hash sites in mcp-handlers/auth.rs and the two WASM
#      content-hash sites (modules.rs, sandbox.rs) format their digest as hex
#      and never construct a Uuid, so they are out of range by shape and need
#      no opt-out.
# Opt-out: `// allow-adhoc-node-uuid: <reason>` within 12 lines above the
# construction (wider than the 8-line detection window on purpose — a
# permanent exemption deserves a paragraph of rationale, and the marker can
# only ever silence a site that carries it).
bold "▶ check 71: graph-node-id → UUID derivation must route through engine_node_uuid"
NODEUUID_HOME="talos-workflow-engine-core/src/node_identity.rs"
NODEUUID_VIOLATIONS=0
while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    file="${hit%%:*}"
    rest="${hit#*:}"
    lineno="${rest%%:*}"
    [ "$file" = "$NODEUUID_HOME" ] && continue
    start=$(( lineno > 8 ? lineno - 8 : 1 ))
    sed -n "${start},${lineno}p" "$ROOT/$file" 2>/dev/null \
        | grep -qE 'Sha256::digest' || continue
    mstart=$(( lineno > 12 ? lineno - 12 : 1 ))
    if sed -n "${mstart},${lineno}p" "$ROOT/$file" 2>/dev/null \
            | grep -q 'allow-adhoc-node-uuid'; then
        continue
    fi
    red "✗ ${file}:${lineno}: private SHA-256 → UUID derivation"
    NODEUUID_VIOLATIONS=$((NODEUUID_VIOLATIONS + 1))
done < <(cd "$ROOT" && grep -rnE '\bUuid::(from_bytes|from_slice|from_bytes_le|from_u128)\s*\(' \
            --include='*.rs' --exclude-dir=target --exclude-dir=vendor "${TREE_PRUNE_GREP[@]}" . 2>/dev/null \
         | sed 's|^\./||' | grep -v '^target/' || true)

if [ "$NODEUUID_VIOLATIONS" -gt 0 ]; then
    red "✗ ${NODEUUID_VIOLATIONS} private copy(ies) of a SHA-256 → UUID derivation"
    yellow "  → if this maps a GRAPH NODE ID, call talos_workflow_engine_core::engine_node_uuid()."
    yellow "    A private copy that drifts from the executor's does not fail loudly — its join"
    yellow "    matches zero rows, and zero rows reads as 'no problems found'."
    yellow "  → if it derives something else entirely (an account id, a content hash), mark it"
    yellow "    '// allow-adhoc-node-uuid: <reason>' within 12 lines above the construction."
    EXIT_CODE=1
else
    green "✓ graph-node-id → UUID derivation has one implementation"
fi
echo

# ── 72. Personal-information markers anywhere in the TRACKED TREE ─────
# The pre-commit hook (`.githooks/pre-commit` §4) scans `git diff --cached
# -U0 | grep '^+'` — STAGED ADDED LINES ONLY. That is the right shape for a
# commit-time gate ("don't let me add this"), but it has a permanent blind
# spot: anything that landed BEFORE the hook existed, or before a term was
# added to the marker list, is never staged again and so is never re-examined.
# It sits in a PUBLIC repo indefinitely, and the tool built to catch it is
# structurally incapable of seeing it.
#
# That blind spot was not theoretical. Two markers were live on main across
# three files when this check was written (#697 removed a third, found by
# accident during unrelated work — one per session, which is not a discovery
# mechanism). This check closes it by scanning the whole tracked tree instead
# of a diff.
#
# WHY THIS IS A LOCAL LINT AND NOT A CI CHECK. The marker list is
# operator-local and uncommittable BY CONSTRUCTION — it *contains* the terms
# it guards, so committing it would publish exactly what it protects. CI
# therefore cannot read it, and the question becomes whether some generic
# pattern could stand in. Measured against this tree, no:
#   - "an email address in source": 263 email-shaped tokens, 48 domains, 127
#     of them outside example.com — every one legitimate (docs, test fixtures,
#     vendored Cargo.toml authorship, and talos-dlp-provider's redaction tests,
#     which must contain email shapes to test that they get redacted). It
#     would have caught 0 of the 2 markers actually present, because neither
#     is email-shaped.
#   - "a UUID in source": 65 distinct non-zeroed UUIDs. One was a marker.
#     ~1.5% precision.
#   - "an oauth/ vault path containing @": 10 hits, none of them a marker —
#     the @-halves were already `user@example.com` / `a@b.com` placeholders.
# A CI check on those patterns would look like enforcement while catching
# nothing, so none is offered here. The honest scope is: this is enforceable
# locally, for the operator who holds the list, at `make lint` / pre-push.
#
# ABSENT-FILE BEHAVIOUR (the case CI and every fresh clone hits). Failing hard
# would make `make lint` unrunnable for every public contributor; passing
# silently would print a green tick that means "I did not look" while reading
# as "clean". So it SKIPS, LOUDLY: a distinct yellow ⊘ line, no green ✓, and
# the pattern count printed on success so an emptied list cannot masquerade as
# a clean scan either.
#
# NO OPT-OUT COMMENT, deliberately. Every other check here has one; this one
# must not, because the opt-out would have to sit next to the value it
# exempts — permanently publishing the thing the check exists to remove. The
# only two resolutions are to replace the value with a placeholder
# (`user@example.com`, a zeroed UUID) or to narrow the marker list.
#
# OUTPUT IS VALUE-FREE. A CI log, a terminal recording and a pasted lint
# failure are all as public as the repo. Findings are reported as
# `file:line (marker #N)`; the matched text is never echoed, and a PATH that
# itself contains a marker has its basename redacted too.
#
# STATED LIMITS:
#  (a) It scans the TREE, not HISTORY. `git grep` without a revision reads the
#      working tree only. A green tick here means "no marker is in the checked-
#      out files", NOT "no marker is anywhere in this repository" — every value
#      it has ever removed is still reachable in the commits that removed it,
#      including this check's own fix commit (whose `-` lines carry them).
#      Purging history needs a force-push rewrite, which is a separate and
#      deliberate act; #697 recorded the same caveat.
#  (b) TRACKED files only. An untracked file is invisible here; the pre-commit
#      hook covers it at the moment it is staged.
#  (c) Fixed-string, case-insensitive, substring. A marker that is a common
#      word will fire on unrelated text — the list is the operator's to curate,
#      and since there is no opt-out, an over-broad term must be narrowed in
#      the list rather than exempted at the call site.
#  (d) Binary files are skipped (`git grep -I`).
bold "▶ check 72: personal-information markers in the tracked tree (PUBLIC repo)"
PI_GIT_COMMON="$(git rev-parse --git-common-dir 2>/dev/null || echo '')"
case "$PI_GIT_COMMON" in
    /*) : ;;
    '') PI_GIT_COMMON="$ROOT/.git" ;;
    *)  PI_GIT_COMMON="$ROOT/$PI_GIT_COMMON" ;;
esac
PI_MARKER_FILE="$PI_GIT_COMMON/info/personal-markers"

PI_PATTERN_FILE="$(mktemp)"
if [ -f "$PI_MARKER_FILE" ]; then
    grep -v '^[[:space:]]*#' "$PI_MARKER_FILE" 2>/dev/null \
        | grep -v '^[[:space:]]*$' > "$PI_PATTERN_FILE" || true
fi
PI_PATTERN_COUNT="$(wc -l < "$PI_PATTERN_FILE" | tr -d ' ')"

if [ ! -f "$PI_MARKER_FILE" ]; then
    yellow "⊘ SKIPPED — no marker list at \$(git rev-parse --git-common-dir)/info/personal-markers"
    yellow "  This is NOT a clean result: the tree was not scanned. Expected in CI and in"
    yellow "  any fresh clone — the list is operator-local and uncommittable by design."
elif [ "$PI_PATTERN_COUNT" -eq 0 ]; then
    yellow "⊘ SKIPPED — marker list exists but contains no patterns (only comments/blanks)"
    yellow "  This is NOT a clean result: an emptied list scans nothing and would otherwise"
    yellow "  report green. Re-populate it or remove the file."
else
    PI_HIT_LOCS="$(git grep -n -i -I -F -f "$PI_PATTERN_FILE" -- . 2>/dev/null \
        | cut -d: -f1,2 || true)"
    if [ -n "$PI_HIT_LOCS" ]; then
        # Attribute each location to a marker INDEX (never its value), and
        # redact any path that is itself a marker hit.
        PI_VIOLATIONS=0
        PI_IDX=0
        PI_ATTRIBUTED="$(mktemp)"
        while IFS= read -r pat; do
            [ -z "$pat" ] && continue
            PI_IDX=$((PI_IDX + 1))
            git grep -n -i -I -F -e "$pat" -- . 2>/dev/null \
                | cut -d: -f1,2 \
                | sed "s|\$| (marker #${PI_IDX})|" >> "$PI_ATTRIBUTED" || true
        done < "$PI_PATTERN_FILE"
        while IFS= read -r loc; do
            [ -z "$loc" ] && continue
            path="${loc%%:*}"
            if printf '%s' "$(basename "$path")" | grep -qiF -f "$PI_PATTERN_FILE"; then
                loc="$(dirname "$path")/<basename redacted>${loc#"$path"}"
            fi
            red "✗ ${loc}"
            PI_VIOLATIONS=$((PI_VIOLATIONS + 1))
        done < <(sort -u "$PI_ATTRIBUTED")
        rm -f "$PI_ATTRIBUTED"
        red "✗ ${PI_VIOLATIONS} personal-information marker hit(s) in the tracked tree"
        yellow "  → this repository is PUBLIC. The pre-commit hook only sees STAGED ADDED"
        yellow "    lines, so it cannot find these and never will — they predate the hook or"
        yellow "    predate their term joining the list."
        yellow "  → resolve by replacing the value with a placeholder (user@example.com, a"
        yellow "    zeroed UUID) or, if the term is over-broad, by narrowing the marker list."
        yellow "    There is deliberately NO opt-out comment: it would have to sit next to"
        yellow "    the value, publishing the very thing this check exists to remove."
        yellow "  → marker list (local-only, never committed): \$(git rev-parse"
        yellow "    --git-common-dir)/info/personal-markers"
        EXIT_CODE=1
    else
        green "✓ tracked tree clean against all ${PI_PATTERN_COUNT} personal-information markers"
    fi
fi
rm -f "$PI_PATTERN_FILE"
echo

# ── 73. env-var PRESENCE tests must treat an empty value as unset ──────
# `std::env::var("KEY").is_ok()` returns TRUE for `Ok("")`. A Helm
# values.yaml placeholder (`talosMasterKey: ""`) or a shell `export FOO=`
# therefore reads as CONFIGURED, while every consumer in this workspace
# treats an empty value as absent — `talos_config::get_env` falls through
# to its default, `read_env_or_file` falls through to `<VAR>_FILE`.
#
# This class has been repaired ELEVEN times under distinct ticket numbers
# (MCP-590/591/592/597/598/599/611/615/620/621/625) and had no structural
# guard, which is why it kept coming back. MCP-625 is the canonical
# writeup and the sharpest illustration: four `security_audit` key checks
# reported "TALOS_MASTER_KEY is configured" and awarded +15 while
# `kek_provider` refused to load the empty key — "operators saw a green
# dashboard while critical security primitives were disabled". Its fix
# was an INLINE CLOSURE, so it did not generalise: when this check was
# written, `handle_security_audit` STILL contained an instance of the bug
# 130 lines below the comment describing it, grading the platform's CORS
# posture. The same locality trap sat in `worker/src/metrics_server.rs`,
# where MCP-932 removed the shape from one handler and left it in a
# sibling handler in the same file.
#
# TWO LEGS, and both are chosen so the value is PROVABLY never inspected —
# that is what makes the finding sound rather than a guess:
#
#  (a) A presence PREDICATE terminating an env read: `.is_ok()`,
#      `.is_some()`, `.is_err()`, `.is_none()`. The chain is joined across
#      lines first (see below), and any chain containing an emptiness or
#      value guard — `is_empty`, `.filter(`, `.trim(`, `unwrap_or`,
#      `map_or` — is exempt, because that code either handles empty or
#      reads the value (in which case empty lands in the same branch as
#      unset and there is no divergence).
#
#  (b) A WILDCARD discard of the value: `Ok(_)` / `Some(_)` in a `match`
#      or `if let` over an env read. A wildcard cannot examine the value,
#      so the branch is presence-only by construction. This leg exists
#      because leg (a) could not see `match env::var("REDIS_URL") { Ok(_)
#      => info!("Redis: configured"), … }` — two of those printed a green
#      startup line for a subsystem that was off, in the very file that
#      DEFINES the correct helper.
#
# Lines are joined into LOGICAL lines before matching (a continuation
# beginning with `.`, `Ok`, `Some`, `Err`, `None`, `=>` or `{` is appended
# to the previous line), so the split form
#     std::env::var("X")
#         .is_ok()
# is caught — a plain line-based grep misses it, and that is exactly how
# the first inventory for this check came up short. Comment-only lines are
# dropped before joining, because the fixes' own comments QUOTE the banned
# expression verbatim so the next reader knows what not to write (two such
# comments exist today and both would otherwise be reported); a commented
# env read cannot execute, so this is a correctness fix, not a weakening.
#
# MEASURED, not asserted. Against the tree this check was written on it
# reports exactly FIVE production sites and ZERO false positives:
#   talos-mcp-handlers/src/platform.rs (cors_origins, agent_api_configured)
#   worker/src/metrics_server.rs (METRICS_AUTH_TOKENS auth_status)
#   talos-config-validator/src/lib.rs (REDIS_URL, NATS_URL summary lines)
# The four correct `.ok().filter(|v| !v.is_empty()).is_some()` sites in the
# tree (talos-config-validator, talos-integrations, talos-mcp-handlers
# search.rs ×2) are all exempted by the guard-token rule, and the three
# `.is_err()` gates in talos-compilation/tests/* by the test exclusion.
#
# STATED LIMITS, each confirmed by running the check rather than inferred:
#  (a) It is TEXTUAL. A presence test performed inside a helper in another
#      crate, or on a value already resolved into an `Option<String>` by a
#      caller, is invisible to both legs.
#  (b) It deliberately does NOT flag a NAMED binding (`if let Ok(url) =
#      env::var(..)`, `match env::var(..) { Ok(url) => .. }`). That shape
#      was MEASURED on the origin/main tree this check was written against:
#      56 non-test sites (37 `let Ok(name) =` + 19 `match env::var`), of
#      which 9 were genuinely defective and all 9 are fixed in this same
#      change — talos-config-validator ×4 (validate_redis_tls REDIS_URL,
#      print_summary DATABASE_URL/BCRYPT_COST/JWT_SECRET),
#      talos-config::read_env_or_file (the `<VAR>_FILE` path),
#      talos-compilation::container_enabled, talos-db::init_pool,
#      talos-hot-update-service::invalidate_redis_cache, and
#      talos-worker-runtime::aot_key_ring. That is 16% precision / an 84%
#      false-positive rate, because the overwhelming majority of that
#      population filters or parses the value on the very next line and is
#      correct. Linting it would be enforcement-shaped noise — the failure
#      mode this repo has repaired repeatedly — so reviewers, not this
#      check, own that shape. (An earlier draft of this comment claimed
#      "~35 sites, ~3% precision, two defects". Both numbers were wrong:
#      the population was undercounted by ignoring `match`, and the defect
#      count was taken before the sweep finished. Corrected by measurement
#      against `git archive origin/main`.)
#  (c) Fail-CLOSED empty handling is not a defect and is not flagged: a
#      production TLS gate that panics on `REDIS_URL=""`, or a
#      `KEK_PROVIDER=""` that refuses an unknown backend, refuses to run
#      rather than misreporting. Those sites use named bindings and are
#      out of range by (b) anyway — but note that "treat empty as unset"
#      would WEAKEN them, so a future widening must not sweep them in.
#  (d) It proves the empty case is HANDLED, never that it is handled
#      correctly — `.filter(|v| !v.is_empty())` satisfies the check
#      whatever the surrounding logic then does.
# Opt-out: `// allow-empty-env-presence: <reason>` on the reported line or
# within 8 lines above it — for a genuine marker variable whose value is
# irrelevant and where `FOO=` deliberately means "on".
bold "▶ check 73: env-var presence tests must treat empty as unset"
EMPTY_ENV_FAIL=0
EMPTY_ENV_AWK="$(mktemp)"
cat > "$EMPTY_ENV_AWK" <<'AWKEOF'
function flush(   s) {
    if (buf == "") return
    s = buf
    if (s ~ /env::var(_os)?[[:space:]]*\(/) {
        # Leg (a): presence predicate with no emptiness/value guard.
        if (s ~ /\.is_(ok|err|some|none)[[:space:]]*\(\)/ &&
            s !~ /is_empty/ && s !~ /\.filter[[:space:]]*\(/ &&
            s !~ /\.trim[[:space:]]*\(/ && s !~ /unwrap_or/ && s !~ /map_or/)
            printf "%s:%d:%s\n", FILENAME, bufline, buf
        # Leg (b): wildcard discard — the value provably is not inspected.
        else if (s ~ /(Ok|Some)[[:space:]]*\([[:space:]]*_[[:space:]]*\)/)
            printf "%s:%d:%s\n", FILENAME, bufline, buf
    }
    buf = ""
}
{
    line = $0
    sub(/^[[:space:]]+/, "", line)
    if (line ~ /^\/\//) next
    if (buf != "" && (line ~ /^\./ || line ~ /^(Ok|Some|Err|None|=>|\{)/)) {
        buf = buf " " line
        next
    }
    flush()
    buf = line
    bufline = FNR
}
END { flush() }
AWKEOF

while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    file="${hit%%:*}"
    rest="${hit#*:}"
    lineno="${rest%%:*}"
    case "$file" in */tests/*|*_tests.rs|*/test_support.rs|*/benches/*|*/examples/*) continue ;; esac
    case "$hit" in *allow-empty-env-presence*) continue ;; esac
    # Opt-out may sit on the line or within the 8 lines above it.
    start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${start},${lineno}p" "$ROOT/$file" 2>/dev/null \
            | grep -q 'allow-empty-env-presence'; then
        continue
    fi
    red "✗ $file:$lineno env-var presence test accepts an empty value as configured"
    printf '    %s\n' "$(printf '%s' "${rest#*:}" | cut -c1-120)"
    EMPTY_ENV_FAIL=1
done < <(cd "$ROOT" && find . -name '*.rs' -not -path './target/*' -not -path '*/target/*' \
         "${TREE_PRUNE_FIND[@]}" -print0 2>/dev/null \
         | xargs -0 -n 40 awk -f "$EMPTY_ENV_AWK" 2>/dev/null \
         | sed 's|^\./||' || true)
rm -f "$EMPTY_ENV_AWK"

if [ "$EMPTY_ENV_FAIL" -eq 1 ]; then
    yellow "  → \`env::var(K).is_ok()\` is TRUE for \`Ok(\"\")\`, so a Helm placeholder"
    yellow "    (\`talosMasterKey: \"\"\`) or \`export FOO=\` reads as CONFIGURED while every"
    yellow "    consumer here treats empty as absent (get_env falls to its default,"
    yellow "    read_env_or_file falls to <VAR>_FILE). MCP-625: the security_audit"
    yellow "    reported \"TALOS_MASTER_KEY is configured\" +15 points while kek_provider"
    yellow "    refused the empty key — a green dashboard over disabled primitives."
    yellow "  → use \`talos_config::env_var_is_set_nonempty(\"KEY\")\`, or inline"
    yellow "    \`.ok().filter(|v| !v.is_empty())\` when you need the value."
    yellow "  → a genuine marker var whose value is irrelevant may carry"
    yellow "    \`// allow-empty-env-presence: <reason>\` on or above the line."
    EXIT_CODE=1
else
    green "✓ env-var presence tests all treat an empty value as unset"
fi
echo

# ── 74. health-reporting handlers must not swallow a read into a benign
#        default ────────────────────────────────────────────────────────
# `.await` followed by `.unwrap_or(0)` / `.unwrap_or_default()` /
# `.unwrap_or(None)` turns a DATABASE FAILURE into the most reassuring
# answer the surface can give: a count of 0, an empty list, a 0% error
# rate, a "not found". On a tool whose entire output is a statement about
# system state that is a lie in the one direction that matters — an
# operator opens `get_system_health` DURING an incident, and pre-fix a
# Postgres blip rendered `stale_executions: 0` and
# `unacknowledged_alerts: 0`.
#
# THIS CLASS HAS NOW BEEN REPAIRED FIVE TIMES, each time locally, each
# time in a different vocabulary:
#   MCP-366     budget_precheck              fail CLOSED, refuse the op —
#                                            the defaulted 0 was a SECURITY
#                                            fail-open. The same .unwrap_or(0)
#                                            on the same repo method is still
#                                            in handle_get_actor_budget: the
#                                            path was fixed, the population
#                                            was not.
#   2026-05-06  handle_get_schedule_health   `data_warnings: [..]` + nulls
#   #699        count_triggers_like          repo returns Result; caller
#                                            declines to say "run migrations"
#   #702        security_audit               per-check `verification:
#                                            not_verified`
#   this change get_system_health + 7 more   `talos_measurement::Readings`
# Five local repairs and no structural guard is the signature of a class,
# not of three unrelated bugs — the same shape lint 73 was written for.
#
# SCOPE is deliberately NARROW, and the narrowing is the reason this check
# is shippable at all. The bare shape (`.await` then `.unwrap_or*`) occurs
# 179 times across `talos-mcp-handlers/src` + `talos-api/src` and MOST OF
# THOSE ARE CORRECT: `repo.is_platform_admin(uid).await.unwrap_or(false)`
# fails CLOSED and is exactly right, and a decorative label lookup that
# defaults to None cannot mislead anyone about anything. Linting all 179
# would be enforcement-shaped noise. What separates the defect from the
# rest is not the DEFAULT, it is the SURFACE: inside a handler whose
# output IS a health verdict, every field is a claim about system state,
# so there is no such thing as a harmless default. The check therefore
# fires only inside functions whose name says they report system state:
#   system_health · health_dashboard · *_health · error_report ·
#   daily_digest · risk_assessment · readiness · system_status
#
# GLOB WIDENING, 2026-09-02 — and read what it is before reusing it.
# Seven more terms were added: budget · clone_actor · enqueue ·
# plan_and_execute · workflow_triggers · module_rate_limit · suggest_retry.
# Those are the
# handlers repaired that day, so this widening is a REGRESSION GUARD for
# the sites this change fixed, NOT a discovery mechanism for the next
# ones. It is a snapshot, and a snapshot is not a gate (check 64) — which
# is exactly why leg 74b exists and why the glob is NOT the answer to
# "how do we cover the surface nobody has looked at yet".
#
# It was measured before it was written, in both directions. Against
# `git archive HEAD` (the pre-fix tree) the widened terms report 15 real
# sites: three in `handle_get_actor_budget`, three in `handle_clone_actor`,
# five in `handle_list_workflow_triggers`, two in `handle_enqueue_workflow`,
# two in `handle_plan_and_execute_workflow`, two in
# `handle_suggest_retry_config`, plus `handle_get_module_rate_limit` —
# every site the change repaired. Against
# this tree they report exactly ONE, and it is the correct fail-CLOSED
# `is_platform_admin(..).unwrap_or(false)` in
# `handle_set_module_rate_limit`, now carrying the marker. So the widened
# terms ship at ZERO with 15/16 = 93.75% precision, comparable to the
# original glob's 96.7%.
#
# That one marker also widens what the OPT-OUT means, deliberately and
# once. It previously read "a genuinely decorative read"; a fail-closed
# authorization default is not decorative, it is conservative, and both
# belong under the same rule: the marker is for a default that MAKES NO
# FAVOURABLE CLAIM. Stretching the old wording to cover it silently would
# have been the drift this file exists to catch, so the wording moved.
#
# MEASURED, not asserted. Against `git archive origin/main` (b2bfa0fd)
# this check reports THIRTY sites across eight handlers, including all six
# in `handle_get_system_health`. Against this tree it reports ONE, which
# is a true FALSE POSITIVE and carries the opt-out: a graph read in
# `handle_get_error_report` used only to resolve node UUIDs to display
# labels. Measured precision 29/30 = 96.7%; false-positive rate 3.3%.
#
# STATED LIMITS:
#  (a) It is TEXTUAL and NAME-BASED. A health surface named something else
#      (`handle_get_platform_info`, `handle_whoami`) is invisible to it, as
#      is a defaulting read performed in a repository or service crate on
#      the handler's behalf. It catches the shape where the class has
#      actually recurred, not every possible instance of it.
#  (b) It does NOT judge the default's DIRECTION. Inside these handlers
#      that is the point — a fail-closed default is still a number the
#      report presents as measured — but it means the check cannot be
#      widened to the other 149 sites without the precision collapsing.
#  (c) It proves the error is not swallowed, never that the replacement is
#      good. `Readings::record` satisfies it; so would any other handling.
# THE `.ok()` SPELLING, 2026-09-02. `.await.ok()` is the same defect in a
# different word — `Result` to `Option`, error discarded, the caller then
# reading `None` as an ordinary absent value — and the regex did not
# mention it. It was found by MUTATION rather than by review: of seven
# mutations of that day's six fixes, six were caught and exactly one
# survived, `get_actor_budget`'s policy read reverted from a `match` to
# `.ok().flatten()`. That is the highest-severity site in the whole set
# (the SPEND CEILING, rendered `null`, which reads as "unlimited"), so the
# one surviving mutation was on the one field that mattered most.
#
# Scope is what makes it cheap: `.ok()` is ubiquitous in Rust and means a
# dozen things, but the intersection of "immediately after `.await`" and
# "inside a check-74 handler" contained exactly TWO sites across
# `talos-mcp-handlers/src` + `talos-api/src`. Both were genuine: the
# policy read, and `handle_get_all_readiness_scores`'s population
# aggregate, which disclosed its failure in `summary.population` prose
# while the `Readings` ledger next to it stayed clean and therefore
# rendered "complete: every field in this report was measured". Two
# disclosures in one response, contradicting each other. Both are fixed,
# so the extension ships at ZERO with no opt-out marker anywhere.
#
# `map_or` joined the same alternation in the same pass, for the opposite
# reason: it closes evasion E5 (`.await.map_or(0, |v| v)`) and its
# measured population in scope is ZERO on BOTH trees, so it costs nothing
# and needs no marker. Do NOT read the alternation as closed — see limit
# (e).
#
# THE NESTED-`fn` HOLE, closed 2026-09-02 and worth stating because the
# check could never see its own worst case. Function attribution rebound on
# ANY `fn` header, indented or not, so an inline helper stole the enclosing
# handler's name for everything below it. `handle_get_actor_budget` defines
# two `opt_or_unlimited_*` helpers mid-body, and the LLM-TOKEN-LEDGER read
# under them — `sum_llm_tokens_last_24h(..).unwrap_or(0)`, the most
# security-adjacent number in the handler — was filed under
# `opt_or_unlimited_i64` and filtered out by the glob. Widening the glob
# would not have helped; the site was invisible by construction. Rebinding
# is now gated on indentation (same level or shallower), with a column-0
# `}` resetting the tracker so a method inside an `impl` still starts a new
# function rather than inheriting the last top-level `fn` above it. Proven
# by probe in three directions: a read below an inline helper is attributed
# to the handler and FIRES; a non-reporting sibling method inside an `impl`
# does NOT inherit the health handler above it; a `*_readiness` sibling
# method IS seen under its own name. Both legs carry the same rule.
#
#  (e) The default-spelling alternation is NOT a closed set, and adding
#      to it must never be read as closing it. Three evasions were
#      measured as SURVIVORS on 2026-09-02 and are left open on purpose:
#      `match … { Err(_) => <default> }` (a block, not a chain — this is
#      the shape TWO of the three original SLA defects took, and a grep
#      cannot tell it from correct error handling), a default applied to
#      an ALREADY-RESOLVED local one statement later, and any handling
#      routed through a helper in another crate. What the check buys is
#      that the ORDINARY spelling — the one every instance of this class
#      has actually used — cannot come back silently.
#  (d) A widened glob is a SNAPSHOT of the handlers someone has already
#      looked at. It protects them from regressing; it says nothing about
#      the next report surface. Only leg 74b's scope is derived from the
#      code and therefore cannot rot.
#
# #730 WIDENING (2026-09-02), the third group. Five terms — `module_info`,
# `validate_workflow_input`, `version_diff`, `archive_policy`,
# `secret_access` — for five CONFIGURATION-claim surfaces, the same
# regression-guard footing as the second group and NOT a discovery
# mechanism. Measured in both directions before it was written: against a
# `git archive` of the pre-fix tree the five terms report **11 sites**, of
# which **9** are the real defects (`handle_get_module_info` ×2,
# `handle_test_secret_access` ×3, `handle_get_version_diff_summary` ×2,
# `handle_validate_workflow_input`, `handle_get_archive_policy`) and 2 are
# the correct fail-CLOSED `is_platform_admin(..).unwrap_or(false)` in
# `handle_set_archive_policy` / `handle_get_secret_access_log`, which now
# carry the marker; on the fixed tree they report **ZERO**. 9/11 = 81.8%,
# lower than the second group's 94.1% — and honestly so, because both
# false positives are the same known-correct shape the opt-out's second
# clause was written for, not a shape the check misjudged.
#
# What that measurement makes plain about this whole leg: the OLD glob
# reported **0** of those 9 on the pre-fix tree. The tools were
# `get_module_info` (a DB error rendering "Module not found or access
# denied" — an existence-and-authorisation verdict from a read that never
# returned), `validate_workflow_input` (a DB error, AND a workflow that
# simply does not exist, both rendering `unvalidated: true` beside the
# advice "gate on `unvalidated === true` to accept schema-less input
# intentionally" — verified live against a nil UUID, no outage required),
# `get_version_diff_summary` ("No published version — all changes are
# new"), `get_archive_policy` (`source: "environment"`), and
# `test_secret_access` (a `capability_world` of "unknown" grading a
# module's SECRET grant, instructing "Recompile with capability_world:
# secrets-node"). Not one is named "health": the surface glob's blind spot
# is not depth, it is VOCABULARY. `get_archive_policy` is the sharpest —
# MCP-552 had already fixed byte-for-byte this defect in the sibling
# `handle_get_wasm_config` ("would proclaim `source: 'env defaults only'`
# even when the DB was unreachable") in May 2026, four months and one file
# away, and nothing swept it.
# Opt-out: `// allow-benign-default: <reason>` on the reported line or
# within 8 lines above it — for a default that MAKES NO FAVOURABLE CLAIM.
# Two shapes qualify: a genuinely decorative read whose absence claims
# nothing about system state, and a fail-CLOSED default that costs the
# caller a refusal rather than granting anything. Nothing else.
bold "▶ check 74: health-reporting handlers must not swallow reads into benign defaults"
BENIGN_DEFAULT_FAIL=0
BENIGN_AWK="$(mktemp)"
cat > "$BENIGN_AWK" <<'AWKEOF'
BEGIN { fn = "?"; fnindent = 0; skipdepth = 0; intest = 0 }
FNR == 1 { fn = "?"; fnindent = 0; intest = 0; pending = ""; pendingno = 0 }
{
    line = $0
    # Drop top-level `#[cfg(test)] mod ... { .. }` regions: a test helper may
    # legitimately be named after the handler it exercises.
    if (line ~ /^#\[cfg\(test\)\]/) { intest = 1; next }
    if (intest == 1) {
        if (line ~ /^\}/) { intest = 0 }
        next
    }
    # A column-0 `}` closes a top-level item, so the next `fn` — at whatever
    # indentation — starts a fresh function. Without this reset, a method inside
    # an `impl` would inherit the name of the last top-level `fn` above it.
    if (line ~ /^\}/) { fn = "?"; fnindent = 0 }
    # A NESTED `fn` must not steal the enclosing handler's name. Measured
    # 2026-09-02: `handle_get_actor_budget` defined two `opt_or_unlimited_*`
    # helpers inline, and the `sum_llm_tokens_last_24h(..).unwrap_or(0)` BELOW
    # them — the LLM-token ledger read, the most security-adjacent number in
    # that handler — was attributed to `opt_or_unlimited_i64` and filtered out
    # by the glob. The check could never have seen it, with or without the
    # widening. Rebind only on a fn at the SAME indentation or shallower, so an
    # inline helper leaves the handler's name in place while a sibling method
    # inside an `impl` still starts a new function.
    if (match(line, /^[[:space:]]*(pub([[:space:]]*\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[A-Za-z0-9_]+/)) {
        hdr = substr(line, RSTART, RLENGTH)
        indent = match(line, /[^[:space:]]/) - 1
        sub(/.*fn[[:space:]]+/, "", hdr)
        if (fn == "?" || indent <= fnindent) { fn = hdr; fnindent = indent }
    }
    # `.ok()` joined the alternation 2026-09-02 — see "THE `.ok()` SPELLING" in
    # this check's header. It is the same defect in a different word, and it was
    # the ONLY spelling left standing when every other mutation of that day's
    # six fixes was caught.
    # Same-line form.
    if (line ~ /\.await[[:space:]]*\.(unwrap_or(_default|_else)?|ok|map_or)[[:space:]]*\(/) {
        report(FILENAME, FNR, fn, line)
    }
    # Split form: previous line ended in `.await`, this one opens the default.
    if (pending != "" && line ~ /^[[:space:]]*\.(unwrap_or(_default|_else)?|ok|map_or)[[:space:]]*\(/) {
        report(FILENAME, pendingno, fn, line)
    }
    if (line ~ /\.await[[:space:]]*$/) { pending = line; pendingno = FNR } else { pending = "" }
}
function report(file, no, f, text) {
    # The second group (budget…module_rate_limit) was added 2026-09-02 as a
    # REGRESSION GUARD for the six handlers fixed that day, NOT as a discovery
    # mechanism. The third (module_info…secret_access) was added 2026-09-02 by
    # #730 on the same footing. See "GLOB WIDENING" in this check's header for
    # the measurement in both directions and for why that distinction is the
    # whole justification.
    if (f !~ /(system_health|health_dashboard|_health|error_report|daily_digest|risk_assessment|readiness|system_status|budget|clone_actor|enqueue|plan_and_execute|workflow_triggers|module_rate_limit|suggest_retry|module_info|validate_workflow_input|version_diff|archive_policy|secret_access)/) return
    gsub(/^[[:space:]]+/, "", text)
    printf "%s:%d:%s:%s\n", file, no, f, text
}
AWKEOF

while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    file="${hit%%:*}"
    rest="${hit#*:}"
    lineno="${rest%%:*}"
    rest2="${rest#*:}"
    fname="${rest2%%:*}"
    start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${start},$((lineno + 1))p" "$ROOT/$file" 2>/dev/null \
            | grep -q 'allow-benign-default'; then
        continue
    fi
    red "✗ $file:$lineno $fname() swallows a read into a benign default"
    printf '    %s\n' "$(printf '%s' "${rest2#*:}" | cut -c1-110)"
    BENIGN_DEFAULT_FAIL=1
done < <(cd "$ROOT" && find talos-mcp-handlers/src talos-api/src -name '*.rs' \
             -not -name '*_tests.rs' -not -path '*/tests/*' -print0 2>/dev/null \
         | xargs -0 -n 40 awk -f "$BENIGN_AWK" 2>/dev/null \
         | sed 's|^\./||' || true)
rm -f "$BENIGN_AWK"

# ── 74b. Sub-leg: a `Readings` ledger must cover every awaited read ───────
# Not a new numbered check (`--count` stays 74) — same rule, second scope.
#
# WHY A SECOND SCOPE. Leg 74's function filter is a HAND-MAINTAINED NAME
# GLOB, which is the rot mode this repo has paid for repeatedly (#624: a
# hardcoded list rots; check 64: a sweep is a snapshot, not a gate). It was
# MEASURED against the pre-fix tree for the SLA compliance bug and the
# result settles the shape of the guard:
#
#   Adding `sla` to leg 74's glob makes it fire on `handle_get_workflow_
#   sla_report` at exactly ONE line — the ownership lookup's
#   `.await\n.unwrap_or(None)` — and on NONE of the three defects the bug
#   was about (`else { 100.0 }`, `p99.unwrap_or(0.0) <= target`, and a
#   `match { Err => 0 }` violations count). Two of those three have no
#   `.await` in the expression at all and the third is a match block, so
#   they were never in leg 74's range. Widening the glob would have turned
#   the check RED on the right handler for the wrong line, then GREEN once
#   that line was fixed — a green tick standing over all three real
#   defects. That is the "gate that doesn't gate" class (#624), so the
#   glob was deliberately NOT widened.
#
# THIS LEG'S SCOPE IS DERIVED FROM THE CODE, NOT LISTED: any function that
# constructs a `talos_measurement::Readings`. A handler opts itself in by
# adopting the disclosure pattern, so a new report surface is covered the
# moment it adopts it and nobody has to remember a name.
#
# ...WHICH IS WHAT IT SAID WHILE ITS `find` LISTED TWO DIRECTORIES. Widened to
# the WORKSPACE on 2026-09-02 (#726), because the sentence above was false as
# shipped and falsely in the reassuring direction. #726 moved the hygiene
# report's disclosure into `talos-analytics-repository` — a crate that now
# builds a `Readings` in the function that used to default fifteen reads — and
# this leg could not see one line of it. A scope claimed to be derived from the
# code, enforced by a hardcoded path list, is the "gate that doesn't gate"
# class (#624) sitting inside the check written to prevent it.
# MEASURED before widening: the workspace-wide population is ONE site,
# `handle_get_error_report`'s label lookup, which already carries the
# `allow-benign-default` marker for being label prettification. So the widened
# leg still ships at ZERO, not as a ratchet.
#
# WHAT IT ASSERTS, and why it is a STRONGER claim than leg 74's inside its
# scope: `Readings::note()` renders "complete: every field in this report
# was measured", and `attach` adds NOTHING when the ledger is clean. So a
# defaulted read sitting BESIDE a clean ledger does not merely omit a
# disclosure — it publishes an affirmative, false completeness claim. The
# disclosure lies about itself, which is one level worse than no
# disclosure at all.
#
# MEASURED, not asserted. Against this tree the population was TWO, both
# the same `.await\n.unwrap_or(None)` ownership/label shape: the SLA
# handler's (fixed in this change) and `handle_get_error_report`'s, which
# already carried leg 74's `allow-benign-default` marker for being label
# prettification. It therefore ships at ZERO, not as a ratchet.
#
# STATED LIMITS — all three in the loud or the honest direction:
#  (a) It only sees functions that ALREADY adopted `Readings`. A report
#      surface that never adopted it is invisible here, so this COMPLEMENTS
#      leg 74's glob, it does not replace it. (Leg 74 stays scoped to
#      `talos-mcp-handlers/src` + `talos-api/src`: its filter is a name glob
#      over HANDLER names, and running that over 100+ crates would fire on
#      every `*_health` helper in the workspace at a precision nobody measured.
#      Only THIS leg, whose scope is a code property, is safe to widen.)
#  (a2) Its function tracking is TEXTUAL: an `async` block inside a function
#      belongs to that function, which is what makes it see the hygiene sweep's
#      sixteen `join!`ed futures at all — and equally means a defaulted read in
#      a nested closure counts against the enclosing `fn`. Loud direction.
#  (b) It inherits leg 74's regex — `.await` immediately followed by
#      `.unwrap_or*` / `.ok()` / `.map_or(`, same line or split. **It did not
#      until #730**: the sentence "inherits leg 74's regex exactly" shipped on
#      2026-09-02 next to code that matched `.unwrap_or*` alone, hours after
#      leg 74 gained `ok|map_or`, and the very next line of this comment then
#      listed `.ok()` as invisible — the header contradicting itself, with the
#      first half reading as the reassuring one. `.ok()` is also the exact
#      spelling #727 found only by mutation, on the single
#      highest-severity field in its set. Widening it cost ZERO new sites,
#      measured on both trees. Still invisible: a
#      `match { Err(_) => <default> }` block and an `unwrap_or` on an
#      ALREADY-RESOLVED local. Concretely: this leg would NOT have caught any of the
#      three original SLA mechanisms. It catches the REGRESSION shape (the
#      call-site `.await.unwrap_or(0)`), which is what the unit tests
#      provably cannot see, and that division of labour is the point —
#      the renderer is guarded by `sla_absence_disclosure_tests`, the
#      wiring by this leg.
#  (c) It proves the read is not swallowed, never that the handling is
#      good — same limit as leg 74(c).
# Opt-out: the same `// allow-benign-default: <reason>` marker.
bold "▶ check 74b: a Readings ledger must cover every awaited read in its function"
READINGS_AWK="$(mktemp)"
cat > "$READINGS_AWK" <<'AWKEOF'
BEGIN { intest = 0; has_readings = 0; nhits = 0; fn = "?"; fnindent = 0 }
FNR == 1 { flush(); intest = 0; pending = ""; fn = "?"; fnindent = 0; FILE = FILENAME }
{
    line = $0
    if (line ~ /^#\[cfg\(test\)\]/) { intest = 1; next }
    if (intest == 1) { if (line ~ /^\}/) { intest = 0 } ; next }
    if (match(line, /^[[:space:]]*(pub([[:space:]]*\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[A-Za-z0-9_]+/)) {
        hdr = substr(line, RSTART, RLENGTH)
        indent = match(line, /[^[:space:]]/) - 1
        sub(/.*fn[[:space:]]+/, "", hdr)
        # Same nested-fn rule as leg 74 — see the note there.
        if (fn == "?" || indent <= fnindent) { flush(); fn = hdr; fnindent = indent }
    }
    if (line ~ /^\}/) { flush(); fn = "?"; fnindent = 0 }
    if (line ~ /Readings::(new|default)\(\)/) { has_readings = 1 }
    # #730: `ok|map_or` added so this genuinely IS leg 74's alternation. The
    # header claimed "inherits leg 74's regex exactly" from the day it landed
    # while the code omitted the two spellings leg 74 had gained hours earlier —
    # and `.ok()` is the spelling #727 found only by mutation. Measured before
    # widening: ZERO new sites, on the original tree and on the fixed one.
    if (line ~ /\.await[[:space:]]*\.(unwrap_or(_default|_else)?|ok|map_or)[[:space:]]*\(/) { record(FNR, line) }
    if (pending != "" && line ~ /^[[:space:]]*\.(unwrap_or(_default|_else)?|ok|map_or)[[:space:]]*\(/) { record(pendingno, line) }
    if (line ~ /\.await[[:space:]]*$/) { pending = line; pendingno = FNR } else { pending = "" }
}
END { flush() }
function record(no, text) { gsub(/^[[:space:]]+/, "", text); nhits++; hno[nhits] = no; htx[nhits] = text }
function flush(  i) {
    if (has_readings == 1 && nhits > 0) {
        for (i = 1; i <= nhits; i++) printf "%s:%d:%s:%s\n", FILE, hno[i], fn, htx[i]
    }
    nhits = 0; has_readings = 0; delete hno; delete htx
}
AWKEOF

READINGS_FAIL=0
while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    file="${hit%%:*}"
    rest="${hit#*:}"
    lineno="${rest%%:*}"
    rest2="${rest#*:}"
    fname="${rest2%%:*}"
    start=$((lineno > 8 ? lineno - 8 : 1))
    if sed -n "${start},$((lineno + 1))p" "$ROOT/$file" 2>/dev/null \
            | grep -q 'allow-benign-default'; then
        continue
    fi
    red "✗ $file:$lineno $fname() defaults a read beside a Readings ledger"
    printf '    %s\n' "$(printf '%s' "${rest2#*:}" | cut -c1-110)"
    READINGS_FAIL=1
done < <(cd "$ROOT" && find . -path ./target -prune -o -name '*.rs' \
             "${TREE_PRUNE_FIND[@]}" \
             -not -name '*_tests.rs' -not -path '*/tests/*' -print0 2>/dev/null \
         | xargs -0 -n 40 awk -f "$READINGS_AWK" 2>/dev/null \
         | sed 's|^\./||' || true)
rm -f "$READINGS_AWK"

if [ "$READINGS_FAIL" -eq 1 ]; then
    yellow "  → this function builds a \`talos_measurement::Readings\`, so a clean run"
    yellow "    makes it publish \"complete: every field in this report was measured\""
    yellow "    and \`attach\` adds no disclosure at all. A defaulted read beside it is"
    yellow "    therefore not a missing disclosure — it is a FALSE completeness claim."
    yellow "  → route it through the ledger: \`readings.record(\"field\", repo…await)\`."
    yellow "  → a genuinely decorative read may carry"
    yellow "    \`// allow-benign-default: <reason>\` on or above the line."
    EXIT_CODE=1
else
    green "✓ every Readings ledger covers all awaited reads in its function"
fi
echo


if [ "$BENIGN_DEFAULT_FAIL" -eq 1 ]; then
    yellow "  → inside a handler whose output IS a health verdict, every field is a"
    yellow "    claim about system state — so a defaulted read publishes a claim"
    yellow "    nobody measured. A count of 0, an empty list, a 0% error rate and a"
    yellow "    \"not found\" all read as GOOD, and a DB outage produces all four at"
    yellow "    once, at the exact moment an operator is reading the tool."
    yellow "  → use \`talos_measurement::Readings\`: \`readings.record(\"field\", repo…await)\`"
    yellow "    returns \`Option\` (JSON null, not 0), logs the error server-side, and"
    yellow "    \`readings.attach(&mut result)\` names the field under"
    yellow "    \`measurement.not_measured\`. A clean run attaches nothing, so the"
    yellow "    healthy response stays byte-identical."
    yellow "  → if the value is a PRECONDITION for the whole response, returning"
    yellow "    \`database_error\` is correct — see handle_get_schedule_health."
    yellow "  → a genuinely decorative read may carry"
    yellow "    \`// allow-benign-default: <reason>\` on or above the line."
    EXIT_CODE=1
else
    green "✓ no health-reporting handler swallows a read into a benign default"
fi
echo

# ── 75. Whole-tree scans must not walk a second checkout ──────────────
# A repo-root walk that descends into `.claude/worktrees/<session>/`
# reports ANOTHER BRANCH's source as a finding in THIS tree. It is not
# merely noise: every path-anchored exemption in this script names a
# path relative to the repo root, so under a worktree prefix the ONE
# legal implementation stops being recognised and byte-identical code is
# reported as a violation. Measured 2026-09-02 on a tree with six
# sibling worktrees (5,518 extra .rs files): 110 red lines where the
# same tree alone produces 0, 108 of them prefixed `.claude/worktrees/`,
# and the two that were not were the INFLATED summary count ("41 private
# copies", true value 0) and the failure verdict. So the number an
# operator would act on is wrong in the same direction as the noise.
#
# This is a class, not a bug: ELEVEN scans pruned `.claude` by hand and
# the TEN added after them did not — checks 58/65(c), 68, 69, 71, 73 and
# 74b, the last of them two days old. Three of those ten fired falsely;
# the other seven are latent, and 58/65(c) fails in the QUIET direction
# (a worktree copy supplies registration evidence, so an alert on a
# metric this tree never registers reads as covered).
#
# Run against the pre-fix script this check reports all 21 repo-root
# scans, not just the ten — and that is the intended reading. The rule
# is the SHARED LIST, not "some prune": the eleven correct sites spelled
# the same intent four different ways (`'*/.claude/*'`, `'./.claude/*'`,
# `--exclude-dir=.claude`, and one that pruned `.git` but not `.claude`),
# and each spelling is a place the next copy can drift.
#
# The rule: every repo-root scan uses the shared `TREE_PRUNE_FIND` /
# `TREE_PRUNE_GREP` defined at the top of this file. One definition, so
# the next scan inherits it instead of re-deciding.
#
# Three directions, because "uses the shared list" is worth only as much
# as the list being real and the detector seeing anything:
#   (a) every repo-root scan statement names one of the two arrays;
#   (b) both arrays are non-empty and both name `.claude` — an emptied
#       array would silence (a) at every site at once;
#   (c) the detector must MATCH SOMETHING. A scan-shape change that
#       makes the walk unrecognisable would otherwise turn this check
#       into a green tick over zero statements (checks 64/65's lesson).
#
# Stated limits, each confirmed by mutation rather than inferred:
#   * It is TEXTUAL and statement-scoped (a line plus its backslash
#     continuations). A scan whose root arrives in a VARIABLE
#     (`find "$dir"`, `grep -r "$SCOPE"`) is invisible — deliberately,
#     since a scoped `$dir` is the common and correct case; so is a scan
#     built with `eval` or assembled across a pipeline.
#   * It proves the array is REFERENCED, never that the reference is in
#     an effective position — `"${TREE_PRUNE_FIND[@]}"` placed after a
#     `-print0` would satisfy it. What it buys is that a NEW scan cannot
#     be added without the author meeting the rule.
#   * `rg`, `fd` and `git grep` are out of range. `git grep` needs no
#     prune (it reads tracked files, and a worktree checkout is not
#     tracked here) — that is why check 72 is not on this list.
#   * `.claude` is pruned WHOLESALE, not just `.claude/worktrees/`. Only
#     two files under it are tracked and neither is `.rs`, so the
#     coverage cost is nil; a future tracked `.rs` there would need an
#     explicit narrowing.
# Opt-out `# allow-unpruned-tree-scan: <reason>` on the statement's
# first line, for a scan that must genuinely see a second checkout.
bold "▶ check 75: whole-tree scans prune .claude worktrees and .git"
SCAN_SCOPE_FAIL=0

# (b) the shared lists must be real before (a) means anything.
if [ "${#TREE_PRUNE_FIND[@]}" -eq 0 ] || [ "${#TREE_PRUNE_GREP[@]}" -eq 0 ]; then
    red "✗ TREE_PRUNE_FIND / TREE_PRUNE_GREP is empty — every scan would pass vacuously"
    SCAN_SCOPE_FAIL=1
elif ! printf '%s\n' "${TREE_PRUNE_FIND[@]}" | grep -q '\.claude' \
     || ! printf '%s\n' "${TREE_PRUNE_GREP[@]}" | grep -q '\.claude'; then
    red "✗ the shared prune lists no longer name .claude"
    SCAN_SCOPE_FAIL=1
fi

SCAN_SCOPE_REPORT="$(perl -0777 -ne '
    my @l = split /\n/, $_;
    my $seen = 0;
    for my $i (0 .. $#l) {
        next if $l[$i] =~ /^\s*#/;
        next unless $l[$i] =~ /(?:grep\s+-\S*r\S*\s|find\s)/;
        my $stmt = $l[$i];
        my $j = $i;
        while ($stmt =~ /\\$/ && $j < $#l) {
            $j++;
            $stmt =~ s/\\$//;
            $stmt .= " " . $l[$j];
        }
        $stmt =~ s/\s+/ /g;
        # A repo-ROOT scan: `find` on the cwd, or a recursive grep whose
        # search root is the cwd or $ROOT. A scan rooted at a named
        # subdirectory is correctly scoped already and out of range.
        my $rooted = ($stmt =~ /find \x2E /)
            || ($stmt =~ /grep\s+-\S*r\S*\s/
                && $stmt =~ /(?: \x2E 2>| \x2E \)| \x2E $|"\$ROOT" 2>)/);
        next unless $rooted;
        $seen++;
        next if $stmt =~ /TREE_PRUNE_(?:FIND|GREP)/;
        next if $l[$i] =~ /allow-unpruned-tree-scan/;
        printf("BAD %d %.110s\n", $i + 1, $stmt);
    }
    printf("SEEN %d\n", $seen);
' "${BASH_SOURCE[0]}")"

while IFS= read -r bad; do
    [ -z "$bad" ] && continue
    red "✗ lint-structural.sh:${bad#BAD }"
    SCAN_SCOPE_FAIL=1
done <<< "$(printf '%s\n' "$SCAN_SCOPE_REPORT" | grep '^BAD ' || true)"

SCAN_SCOPE_SEEN="$(printf '%s\n' "$SCAN_SCOPE_REPORT" | sed -n 's/^SEEN //p')"
if [ "${SCAN_SCOPE_SEEN:-0}" -lt 5 ]; then
    red "✗ check 75 recognised only ${SCAN_SCOPE_SEEN:-0} repo-root scan(s) — the"
    yellow "    detector has stopped matching this script's own scan shape, so a"
    yellow "    green tick here would stand over nothing. Fix the detector, not the"
    yellow "    threshold."
    SCAN_SCOPE_FAIL=1
fi

if [ "$SCAN_SCOPE_FAIL" -eq 1 ]; then
    yellow "  → a repo-root walk descends into .claude/worktrees/<session>/, which"
    yellow "    holds OTHER branches' source. Path-anchored exemptions do not match"
    yellow "    under that prefix, so identical code is reported as a violation and"
    yellow "    any count this check prints is inflated by whatever is checked out"
    yellow "    beside you."
    yellow "  → append \"\${TREE_PRUNE_FIND[@]}\" (walks) or \"\${TREE_PRUNE_GREP[@]}\""
    yellow "    (recursive greps) to the statement. They are defined once at the top"
    yellow "    of this file; per-check prunes (target, vendor, node_modules) stay"
    yellow "    where they are."
    EXIT_CODE=1
else
    green "✓ all ${SCAN_SCOPE_SEEN} repo-root scans prune second checkouts"
fi
echo

# ── 76. An input-schema read must be CLASSIFIED, not defaulted ────────
# `workflows.input_schema` decides whether the input-validation gate runs
# at all, so a read of it that does not come back with a definite answer
# must REFUSE — never fall into the same branch as "this workflow
# declares no schema". A gate that silently does not run is
# indistinguishable, in every response and every log, from a gate that
# passed.
#
# Three sites had the defect and each spelled it differently, which is
# why this is a check and not a review note.
# `WorkflowValidationService::check_trigger_input` degraded a fetch `Err`
# to `None` and SAID SO in its doc comment, justifying it as availability
# ("rather than rejecting all triggers on a transient DB hiccup") —
# refuted by its own single caller, where the three repository reads and
# the authorization resolve ABOVE it all return `Err` on a DB failure, so
# a transient hiccup had already killed the trigger three reads earlier.
# `handle_call_workflow` and `handle_test_workflow` wrote
# `if let Ok(Some(schema)) = …`, which routes BOTH the read error and the
# unknown-workflow answer into the silent skip branch — under comments
# claiming the gate exists so "a sync-call doesn't bypass the gate" and so
# "a green test is [not] silently less strict than a real trigger".
#
# Two legs, because either alone is trivially evaded:
#   (a) The FLATTENING projection `get_workflow_input_schema` may be
#       called only inside `talos-workflow-repository/`. Its own doc
#       comment says it collapses "no such workflow" into "no schema", so
#       every outside caller inherits that flattening whatever it then
#       does with the value. Outside callers take the three-way
#       `_scoped` sibling.
#   (b) A `_scoped` call outside the repository crate must have a
#       classifier named within the 6 lines above it
#       (`classify_input_schema_read` / `decide_trigger_input` /
#       `enforce_declared_input_schema`). Without (b), (a) is defeated in
#       one line by `get_workflow_input_schema_scoped(..).await.ok()
#       .flatten().flatten()`, which reproduces the original defect
#       exactly — CONFIRMED by mutation, leg (b) fires on it.
#   (c) The three DECISION functions must not be called into a `let _ =`.
#       Legs (a) and (b) both live at the READ; neither can see a call
#       site that runs the gate correctly and then throws the answer
#       away. `let _ = decide_input_schema_outcome(validation, wf);` was
#       MEASURED as a survivor of every other instrument here — all 31
#       crate tests green, legs (a) and (b) green, check 10 green (it is
#       scoped to `talos-mcp-handlers/src`) — which is the #724 shape
#       exactly. The BARE-statement discard
#       (`decide_input_schema_outcome(..);`) needs no lint: the three
#       functions carry `#[must_use]`, so CI's `-D warnings` refuses it.
#       `let _ =` is the documented way to silence `#[must_use]`, so it
#       is the one spelling a lint has to cover.
#
# Measured before it was written, in both directions: **3 findings on the
# pre-fix tree — exactly the three defects, no false positives — and 0
# after.** A FILE-scoped formulation ("the file must name a classifier")
# was built first and REJECTED on measurement: all three MCP sites live in
# one file that already named `classify_input_schema_read` from the
# reporting fix, so it reported 0 on a tree containing 2 of the 3 defects
# — a gate that does not gate (#624, checks 64/65).
#
# Scope is DERIVED from the method name, not a hand-maintained list of
# handlers, so a brand-new enforcement site in a crate nobody has thought
# about is covered the day it is written (probe-confirmed against a fresh
# call added to `talos-scheduler`).
#
# Stated limits, each confirmed by mutation rather than inferred:
#   * Both legs are TEXTUAL and line-based. A read reached through a
#     wrapper in another crate, or a method renamed by a re-export alias,
#     is invisible to both.
#   * (b) is WINDOW-bounded at 6 lines. The three live sites pass the
#     read straight into the classifier call with no intervening binding
#     (measured max distance 3 lines), but a reflow or an added comment
#     that pushes the classifier further up reads as unclassified — a
#     FALSE POSITIVE, which is the loud direction.
#   * (b) proves a classifier is NEARBY, never that its answer is
#     honoured. `classify_input_schema_read(read); /* ignored */` would
#     satisfy it. The refusal behaviour itself is pinned by unit tests
#     (`trigger_input_failclosed_tests`, `trigger_input_gate_tests`,
#     `input_schema_enforcement_tests`) which drive the production
#     decision functions.
#   * Neither leg says anything about the OTHER fail-open enforcement
#     gates in this workspace (capability ceilings, rate limits, policy
#     evaluation). This check is about one read; that population is its
#     own problem and a wider regex would be enforcement-shaped noise.
#   * `<crate>/tests/` binaries are excluded; a `#[cfg(test)]` module
#     inside `src/` is NOT, so a test that calls the flattening read
#     directly must carry the opt-out.
# Opt-outs `// allow-flattened-schema-read: <reason>` (a) and
# `// allow-unclassified-schema-read: <reason>` (b), on the reported line
# or within 8 lines above.
bold "▶ check 76: input-schema reads are classified, not defaulted"
SCHEMA_READ_FAIL=0
SCHEMA_CLASSIFIERS='classify_input_schema_read|decide_trigger_input|enforce_declared_input_schema'

# Does the marker sit on the line, or within the 8 lines above it?
schema_read_exempt() {
    local file="$1" line="$2" marker="$3" lo
    lo=$(( line > 8 ? line - 8 : 1 ))
    sed -n "${lo},${line}p" "$file" | grep -q "$marker"
}

while IFS=: read -r f n _rest; do
    [ -n "${f:-}" ] || continue
    case "$f" in ./talos-workflow-repository/*) continue ;; esac
    case "$f" in */tests/*) continue ;; esac
    if schema_read_exempt "$f" "$n" 'allow-flattened-schema-read:'; then continue; fi
    red "✗ $f:$n calls the FLATTENING get_workflow_input_schema outside the repository crate"
    SCHEMA_READ_FAIL=$((SCHEMA_READ_FAIL + 1))
done < <(grep -rn --include='*.rs' --exclude-dir=target --exclude-dir=vendor \
             --exclude-dir=node_modules "${TREE_PRUNE_GREP[@]}" \
             -E '\.get_workflow_input_schema\(' . 2>/dev/null || true)

while IFS=: read -r f n _rest; do
    [ -n "${f:-}" ] || continue
    case "$f" in ./talos-workflow-repository/*) continue ;; esac
    case "$f" in */tests/*) continue ;; esac
    lo=$(( n > 6 ? n - 6 : 1 ))
    if sed -n "${lo},${n}p" "$f" | grep -qE "$SCHEMA_CLASSIFIERS"; then continue; fi
    if schema_read_exempt "$f" "$n" 'allow-unclassified-schema-read:'; then continue; fi
    red "✗ $f:$n reads the input schema without a classifier in the 6 lines above"
    SCHEMA_READ_FAIL=$((SCHEMA_READ_FAIL + 1))
done < <(grep -rn --include='*.rs' --exclude-dir=target --exclude-dir=vendor \
             --exclude-dir=node_modules "${TREE_PRUNE_GREP[@]}" \
             -E '\.get_workflow_input_schema_scoped\(' . 2>/dev/null || true)

SCHEMA_DECISION_FNS='decide_input_schema_outcome|enforce_declared_input_schema|decide_trigger_input'
while IFS=: read -r f n _rest; do
    [ -n "${f:-}" ] || continue
    case "$f" in */tests/*) continue ;; esac
    if schema_read_exempt "$f" "$n" 'allow-unclassified-schema-read:'; then continue; fi
    red "✗ $f:$n discards the input-schema gate's answer into \`let _ =\`"
    SCHEMA_READ_FAIL=$((SCHEMA_READ_FAIL + 1))
done < <(grep -rn --include='*.rs' --exclude-dir=target --exclude-dir=vendor \
             --exclude-dir=node_modules "${TREE_PRUNE_GREP[@]}" \
             -E 'let[[:space:]]+_[[:space:]]*=.*('"$SCHEMA_DECISION_FNS"')\(' . 2>/dev/null || true)

if [ "$SCHEMA_READ_FAIL" -gt 0 ]; then
    yellow "  → a read that did not come back with a definite answer must REFUSE."
    yellow "    Take the three-way get_workflow_input_schema_scoped (Err /"
    yellow "    no-such-workflow / schema-or-not) and pass it straight into a"
    yellow "    classifier: classify_input_schema_read (MCP handlers) or"
    yellow "    WorkflowValidationService::decide_trigger_input (trigger path)."
    yellow "    Only a definite Ok(Some(None)) may skip validation."
    EXIT_CODE=1
else
    green "✓ every input-schema read outside the repository crate is classified"
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
