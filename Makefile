# Talos Makefile — concise, safety-first development commands.
#
# Three sections (see `make help`):
#   Dev      — day-to-day start/stop/rebuild
#   Quality  — local gates that match GitHub Actions CI
#   Ops      — rarely-used operational commands
#
# Most dev-loop targets accept `SERVICE=<name>` (default: controller), e.g.
#   make rebuild SERVICE=worker
#   make logs    SERVICE=postgres
#   make shell   SERVICE=frontend

SHELL              := /bin/bash
.SHELLFLAGS        := -eu -o pipefail -c
MAKEFLAGS          += --warn-undefined-variables --no-print-directory
.DEFAULT_GOAL      := help

SERVICE            ?= controller

# Git state exposed to the controller build so session_start.server_version
# surfaces the deployed commit (operator never has to ask "what's running?").
# Falls back to `unknown`/`false` when invoked outside a git checkout.
export GIT_SHA_OVERRIDE   := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)
export GIT_DIRTY_OVERRIDE := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo true || echo false)

.PHONY: help setup up down rebuild restart logs ps shell doctor quickstart \
        check build lint lint-frontend hooks test test-changed test-integration test-clean coverage-html audit check-catalog ci \
        drill drill-schedule drill-unschedule drill-schedule-status \
        offhost-upload offhost-backfill offhost-plan offhost-probe \
        offhost-schedule offhost-unschedule offhost-status \
        clean nuke smoke rls-preflight sqlx-prepare sqlx-check _wait-healthy \
        observability-reload observability-verify

## ──── Dev ──────────────────────────────────────────────────────────

help: ## Print this help message
	@awk 'BEGIN {FS = ":.*##"} \
	     /^## ─/   {sub(/^## /, ""); printf "\n\033[1m%s\033[0m\n", $$0; next} \
	     /^[a-zA-Z_-]+:.*?##/ {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' \
	    $(MAKEFILE_LIST)
	@printf '\nService-parameterised targets accept SERVICE=<name> (default: controller).\n'
	@printf 'Example: make logs SERVICE=postgres\n\n'

setup: ## First-time setup — generate .env with secrets, then build + start
	@bash scripts/setup-dev.sh

quickstart: ## Zero to a running workflow — golden path, printed step by step (after `make setup`)
	@bash scripts/quickstart.sh

up: ## Build + start the full dev stack, wait for health
	@test -f .env || { \
	    printf '\033[1;31m✗ no .env found.\033[0m Run `make setup` to generate one (or see QUICKSTART.md).\n'; \
	    exit 1; \
	}
	@# Refuse to build onto a full Docker VM disk: Postgres PANICs on ENOSPC
	@# mid-checkpoint and crash-loops (2026-07-29). Advisory unless >=95% —
	@# skips silently when docker is unavailable. TALOS_UP_SKIP_DISK_CHECK=1
	@# to override.
	@bash scripts/preflight-disk.sh
	@# The node-exporter service bind-mounts the drill's textfile directory.
	@# Docker WILL create a missing bind source, but as root — after which the
	@# drill (running as you) cannot write its metric and refuses to run. Make
	@# the directory here, owned by the invoking user, so that never happens.
	@mkdir -p "$${TALOS_TEXTFILE_DIR:-$$HOME/.talos/metrics/textfile_collector}"
	@dirty="$$(git status --porcelain 2>/dev/null | head -5)"; \
	 if [ -n "$$dirty" ]; then \
	    printf '\033[1;33m⚠ working tree is DIRTY — images will be stamped `-dirty` and correspond to NO commit.\033[0m\n'; \
	    printf '\033[1;33m  Nobody (including you, later) can reason about what is in them. Modified:\033[0m\n'; \
	    git status --porcelain 2>/dev/null | head -5 | sed 's/^/    /'; \
	 fi
	@before_c="$$(docker image inspect -f '{{.Id}}' talos-controller 2>/dev/null || echo none)"; \
	 before_w="$$(docker image inspect -f '{{.Id}}' talos-worker 2>/dev/null || echo none)"; \
	 GIT_SHA_OVERRIDE="$$(git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)" \
	 GIT_DIRTY_OVERRIDE="$$([ -n "$$(git status --porcelain 2>/dev/null)" ] && echo true || echo false)" \
	 docker compose build controller worker migrate; \
	 after_c="$$(docker image inspect -f '{{.Id}}' talos-controller 2>/dev/null || echo none)"; \
	 after_w="$$(docker image inspect -f '{{.Id}}' talos-worker 2>/dev/null || echo none)"; \
	 changed=""; \
	 [ "$$before_c" != "$$after_c" ] && changed="$$changed controller"; \
	 [ "$$before_w" != "$$after_w" ] && changed="$$changed worker"; \
	 if [ -n "$$changed" ]; then \
	    printf '\033[1;32m✓ rebuilt:%s\033[0m\n' "$$changed"; \
	 else \
	    printf '\033[1;33m⚠ NOTHING REBUILT — controller and worker images are byte-identical to before.\033[0m\n'; \
	    printf '\033[1;33m  Every layer was cached, so this deploy ships the SAME code you were already running.\033[0m\n'; \
	    printf '\033[1;33m  If you expected a change: docker builder prune -f --filter type=exec.cachemount\033[0m\n'; \
	 fi
	@printf '\033[1;36m→ controller/worker must roll TOGETHER: signed wire formats are version-coupled\033[0m\n'
	@if grep -Eq '^NGROK_AUTHTOKEN=.+' .env 2>/dev/null; then \
	    printf '\033[1;36m→ NGROK_AUTHTOKEN present — starting public tunnel (compose profile: public)\033[0m\n'; \
	    COMPOSE_PROFILES=public docker compose up -d --scale worker=1; \
	else \
	    docker compose up -d --scale worker=1; \
	fi
	@$(MAKE) _wait-healthy
	@printf '\033[1;32m✓ stack healthy — http://localhost:8000/health\033[0m\n'
	@if grep -Eq '^NGROK_AUTHTOKEN=.+' .env 2>/dev/null; then \
	    sleep 2; \
	    url="$$(curl -sf http://127.0.0.1:4040/api/tunnels 2>/dev/null | grep -o '"public_url":"https:[^"]*"' | head -1 | cut -d'"' -f4)"; \
	    if [ -n "$$url" ]; then \
	        printf '\033[1;36m🌐 public tunnel: %s\033[0m (run get_public_url_status for integration setup)\n' "$$url"; \
	    else \
	        printf '\033[1;33m⚠ tunnel starting — check `docker logs talos-ngrok` / http://127.0.0.1:4040\033[0m\n'; \
	    fi; \
	fi

	@# ── observability gate: SELF-HEAL, THEN FAIL HARD ──────────────────────
	@# `docker compose up -d` does NOT recreate a container whose spec is
	@# unchanged, so Prometheus keeps the rules it read at startup forever.
	@# Measured 2026-08-18: the process had been up 31 h and was evaluating 47
	@# rules against 54 on disk — seven alerts from #641/#643/#644 inert, plus
	@# #644's rewritten `TalosWorkerFleetBuildSkew` expr still in its
	@# un-fireable pre-#644 form. Every detector merged since the container
	@# started was write-only.
	@#
	@# This was ADVISORY and got swallowed into one yellow line among many, on
	@# the argument that a stale Prometheus must not block a dev stack. That
	@# argument is kept and answered instead of overridden: on divergence we
	@# APPLY THE REPO'S OWN COMMITTED CONFIG (`observability-reload` — POST
	@# /-/reload, which also diagnoses the 403/no-lifecycle case) and re-verify.
	@# The common case self-heals with no operator discipline; only a
	@# divergence a reload CANNOT fix — a broken mount, a config Prometheus
	@# rejects, a container predating --web.enable-lifecycle — is fatal, and
	@# then the stack is already up so nothing is torn down by the non-zero
	@# exit. It runs LAST so the failure is the final thing on screen.
	@#
	@# It cannot fire on a tree you did not deploy: it runs only inside an
	@# explicit `make up`, never on a file save.
	@#
	@# STATED LIMIT: this gates `make up` ONLY. A bare `docker compose build &&
	@# docker compose up -d` bypasses it and can still leave Prometheus stale.
	@# A rules-checksum label on the service would not close that either (a
	@# bare compose run evaluates the same default and skips the recreate), so
	@# the raw path is documented, not covered.
	@if bash scripts/verify-observability.sh >/dev/null 2>&1; then \
	    printf '\033[1;32m✓ observability: Prometheus is evaluating this checkout\033[0m\n'; \
	else \
	    printf '\033[1;33m⚠ Prometheus is not evaluating this checkout — applying the repo config\033[0m\n'; \
	    $(MAKE) --no-print-directory observability-reload || { \
	        printf '\033[1;31m══════════════════════════════════════════════════════════════\033[0m\n'; \
	        printf '\033[1;31m✗ OBSERVABILITY IS STALE AND A RELOAD DID NOT FIX IT\033[0m\n'; \
	        printf '\033[1;31m  The stack is UP, but Prometheus is not evaluating the rules\033[0m\n'; \
	        printf '\033[1;31m  in this checkout, so alerts merged since it started are inert.\033[0m\n'; \
	        printf '\033[1;31m  Recreate it (prometheus_data is untouched):\033[0m\n'; \
	        printf '\033[1;31m      docker compose up -d --force-recreate prometheus\033[0m\n'; \
	        printf '\033[1;31m══════════════════════════════════════════════════════════════\033[0m\n'; \
	        exit 1; \
	    }; \
	fi

down: ## Stop the stack (preserves data volumes)
	@docker compose down

rebuild: ## Hot-rebuild one service (SERVICE=controller|worker|frontend|...)
	@GIT_SHA_OVERRIDE="$$(git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)" \
	 GIT_DIRTY_OVERRIDE="$$([ -n "$$(git status --porcelain 2>/dev/null)" ] && echo true || echo false)" \
	 docker compose up -d --build -- "$(SERVICE)"

restart: ## Restart one service without rebuilding (SERVICE=...)
	@docker compose restart -- "$(SERVICE)"

observability-reload: ## Apply edited Prometheus AND Alertmanager config to the running stack (no recreate)
	@# POST /-/reload, not a restart: it keeps the in-memory TSDB head, so the
	@# user's local metric history survives. Enabled by --web.enable-lifecycle
	@# on the dev stack only (port is bound to 127.0.0.1; prod ships no
	@# prometheus service and the chart uses a PrometheusRule CRD).
	@# The 403 case is the one that actually happens and it must not be
	@# reported as "is the stack up?": Prometheus answers /-/reload with 403
	@# when it was started WITHOUT --web.enable-lifecycle, i.e. the container
	@# predates this flag being added. Recreating it is the fix, and a wrong
	@# remedy in an error message costs more than no message at all.
	@code="$$(curl -s -o /dev/null -w '%{http_code}' -XPOST http://127.0.0.1:9090/-/reload 2>/dev/null)"; \
	case "$$code" in \
	  200) printf 'reloaded — verifying it actually took effect\n' ;; \
	  403) printf 'reload refused (403): this container was started without --web.enable-lifecycle.\n'; \
	       printf '  → it predates the flag. Recreate it (the prometheus_data volume is untouched):\n'; \
	       printf '      docker compose up -d --force-recreate prometheus\n'; exit 1 ;; \
	  000) printf 'no response from http://127.0.0.1:9090 — is the stack up? (make up)\n'; exit 1 ;; \
	  *)   printf 'reload failed with HTTP %s\n' "$$code"; exit 1 ;; \
	esac
	@# ALERTMANAGER TOO, and it is not optional. Leg E of
	@# scripts/verify-observability.sh compares Alertmanager's LOADED config
	@# against alertmanager.yml on disk, and its remedy line names this target
	@# — a target that reloaded only Prometheus would be a WRONG REMEDY in an
	@# error message, which this file's 403 comment above already argues costs
	@# more than no message at all. Alertmanager needs no --web.enable-lifecycle
	@# (that flag is Prometheus-only and Alertmanager rejects it outright, see
	@# docker-compose.yml); POST /-/reload is always served.
	@if [ "$$(docker inspect -f '{{.State.Running}}' talos-alertmanager 2>/dev/null)" = "true" ]; then \
	  amcode="$$(curl -s -o /dev/null -w '%{http_code}' -XPOST http://127.0.0.1:9093/-/reload 2>/dev/null)"; \
	  case "$$amcode" in \
	    200) printf 'alertmanager reloaded\n' ;; \
	    000) printf 'alertmanager is running but http://127.0.0.1:9093 did not answer.\n'; \
	         printf '  -> its config was NOT reloaded; delivery is still using the old one.\n'; \
	         exit 1 ;; \
	    *)   printf 'alertmanager reload failed with HTTP %s - config NOT applied\n' "$$amcode"; \
	         exit 1 ;; \
	  esac; \
	else \
	  printf 'alertmanager is not running - nothing to reload there (leg D reports it)\n'; \
	fi
	@$(MAKE) --no-print-directory observability-verify

observability-verify: ## Prove the running Prometheus AND Alertmanager read THIS repo (rules + config parity)
	@bash scripts/verify-observability.sh

logs: ## Tail logs for one service (SERVICE=..., empty for all: `make logs SERVICE=`)
	@docker compose logs -f $(SERVICE)

ps: ## Show service health and database row counts
	@docker compose ps
	@printf '\nDatabase row counts:\n'
	@docker compose exec -T postgres psql -U talos -d talos -tAF'|' -c "\
	    SELECT table_name, cnt FROM ( \
	        SELECT 'workflows'           AS table_name, COUNT(*) AS cnt FROM workflows \
	        UNION ALL SELECT 'workflow_executions',  COUNT(*) FROM workflow_executions \
	        UNION ALL SELECT 'module_executions',    COUNT(*) FROM module_executions \
	        UNION ALL SELECT 'actor_memory',         COUNT(*) FROM actor_memory \
	        UNION ALL SELECT 'secrets',              COUNT(*) FROM secrets \
	        UNION ALL SELECT 'encryption_keys',      COUNT(*) FROM encryption_keys \
	    ) t ORDER BY table_name;" 2>/dev/null \
	  | awk -F'|' '{printf "  %-22s %s\n", $$1, $$2}' \
	  || printf '  (database unreachable — run `make up` first)\n'

doctor: ## Preflight: stale images vs source, Docker disk pressure, stack health — run before live-testing
	@bash scripts/doctor.sh

shell: ## Open a shell in a running service (SERVICE=...)
	@docker compose exec -- "$(SERVICE)" /bin/bash 2>/dev/null \
	    || docker compose exec -- "$(SERVICE)" /bin/sh

## ──── Quality ──────────────────────────────────────────────────────

check: ## Fast workspace type-check (no codegen — ~5× faster than full build)
	@cargo check --workspace --all-targets

build: ## Release build of all workspace binaries on the host (Docker uses scripts/release.sh)
	@cargo build --workspace --release

lint: ## Rustfmt + WIT drift + structural + clippy (-D warnings) + offline cargo-deny — matches CI
	@printf '▶ wit sync\n'
	@diff -q wit/talos.wit module-templates/wit/talos.wit >/dev/null 2>&1 \
	    || { printf '\033[1;31m✗ wit/talos.wit and module-templates/wit/talos.wit have drifted\033[0m\n'; \
	         printf '  fix: cp wit/talos.wit module-templates/wit/talos.wit\n'; exit 1; }
# NOTE: no `cargo fmt --all -- --check` here. It ran TWICE per `make lint` —
# once from this target and again as structural check 35 — which is pure
# duplicated wall-clock for identical coverage. Check 35 is the copy that was
# kept: it names the offending files with a fix hint, where bare
# `cargo fmt --check` prints a diff and exits 1. Do NOT renumber the
# structural checks to "tidy up" — meta-check 54 pins the count, and
# CLAUDE.md's "N checks today" sentence to it.
	@printf '▶ structural lints (incl. rustfmt + clippy --workspace --no-deps -D warnings)\n'
	@bash -n scripts/lint-structural.sh || { printf '\033[1;31m✗ scripts/lint-structural.sh does not parse — no check below ran\033[0m\n'; exit 1; }
	@TALOS_LINT_CLIPPY=1 bash scripts/lint-structural.sh
	@printf '▶ cargo-deny (offline: bans + licenses + sources)\n'
	@if command -v cargo-deny >/dev/null 2>&1; then \
	    cargo deny check bans licenses sources; \
	else \
	    printf '\033[1;33m⊘ cargo-deny not installed — skipping offline supply-chain check (advisories run in `make audit`)\033[0m\n'; \
	fi

lint-frontend: ## Frontend gate — eslint + prettier + vitest (skips if frontend/node_modules absent)
	@if [ -d frontend/node_modules ]; then \
	    printf '▶ frontend: eslint + prettier + vitest\n'; \
	    cd frontend && npm run lint && npm run test; \
	else \
	    printf '\033[1;33m⊘ frontend/node_modules absent — skipping frontend gate (run: cd frontend && npm ci)\033[0m\n'; \
	fi

hooks: ## Install git hooks (.githooks) — activates pre-commit + pre-push gates
	@git config core.hooksPath .githooks
	@printf '\033[1;32m✓ git hooks installed\033[0m (core.hooksPath=.githooks)\n'
	@printf '  pre-commit: secret/migration/compile checks (every commit)\n'
	@printf '  pre-push:   make lint + make lint-frontend — Rust (fmt/structural/clippy/deny) + frontend (eslint/prettier/vitest), every push\n'
	@printf '  bypass a push gate in an emergency with: git push --no-verify\n'

test: ## Run the full test suite with cargo-nextest (fast local)
	@command -v cargo-nextest >/dev/null 2>&1 \
	    || { printf '\033[1;31m✗ cargo-nextest missing\033[0m — install: cargo install cargo-nextest --locked\n'; exit 1; }
	@cargo nextest run --workspace

test-changed: ## Run nextest for ONLY crates changed vs BASE (default origin/main); ARGS=--list to just list. Fast inner loop, NOT a CI substitute
	@bash scripts/test-changed.sh $(ARGS)

test-integration: ## Run env-gated integration tests against disposable Redis+Postgres+NATS (needs Docker)
	@command -v docker >/dev/null 2>&1 \
	    || { printf '\033[1;31m✗ docker missing\033[0m — required to provision the disposable datastores\n'; exit 1; }
	@bash scripts/test-integration.sh

test-clean: ## Remove EVERY Postgres container the controller test harness ever started (all runs, this machine)
	@command -v docker >/dev/null 2>&1 \
	    || { printf '\033[1;31m✗ docker missing\033[0m\n'; exit 1; }
	@# Filtered on the harness LABEL, never on the image: the dev stack's
	@# talos-postgres, talos-postgres-backup and talos-vault-backup all run the
	@# same pgvector/pgvector:pg17 image, so an image filter would delete a
	@# developer's live database. This is the SIGKILL backstop — the harness
	@# reaps its own container at exit, but no exit hook runs on `kill -9`.
	@ids=$$(docker ps -aq --filter label=talos.test-harness=controller); \
	if [ -z "$$ids" ]; then \
	    printf '\033[0;32m✓\033[0m no leaked test-harness containers\n'; \
	else \
	    n=$$(printf '%s\n' "$$ids" | wc -l | tr -d ' '); \
	    docker rm -f $$ids >/dev/null; \
	    printf '\033[0;32m✓\033[0m removed %s leaked test-harness container(s)\n' "$$n"; \
	fi

coverage-html: ## HTML coverage report via cargo-tarpaulin (slow; local only)
	@command -v cargo-tarpaulin >/dev/null 2>&1 \
	    || { printf '\033[1;31m✗ cargo-tarpaulin missing\033[0m — install: cargo install cargo-tarpaulin --locked\n'; exit 1; }
	@cargo tarpaulin --out Html

sqlx-prepare: ## Regenerate the compile-checked .sqlx offline cache (needs a migrated DATABASE_URL)
	@command -v sqlx >/dev/null 2>&1 \
	    || { printf '\033[1;31m✗ sqlx-cli missing\033[0m — install: cargo install sqlx-cli --locked\n'; exit 1; }
	@[ -n "$$DATABASE_URL" ] \
	    || { printf '\033[1;31m✗ DATABASE_URL unset\033[0m — point it at a MIGRATED Postgres (e.g. the compose DB or a disposable pgvector).\n'; exit 1; }
	@# --all-targets so queries in test/bin targets are collected too, else
	@# `sqlx-check` (and CI) would flag them as missing from the cache.
	@SQLX_OFFLINE=false cargo sqlx prepare --workspace -- --all-targets
	@printf '\033[1;32m✓ .sqlx cache regenerated — commit the changes\033[0m\n'

sqlx-check: ## Verify the committed .sqlx cache matches the queries (needs a migrated DATABASE_URL) — CI gate
	@command -v sqlx >/dev/null 2>&1 \
	    || { printf '\033[1;31m✗ sqlx-cli missing\033[0m — install: cargo install sqlx-cli --locked\n'; exit 1; }
	@[ -n "$$DATABASE_URL" ] \
	    || { printf '\033[1;31m✗ DATABASE_URL unset\033[0m — point it at a MIGRATED Postgres.\n'; exit 1; }
	@SQLX_OFFLINE=false cargo sqlx prepare --workspace --check -- --all-targets \
	    || { printf '\033[1;31m✗ .sqlx cache is STALE\033[0m — run `make sqlx-prepare` and commit the result.\n'; exit 1; }
	@printf '\033[1;32m✓ .sqlx cache is up to date\033[0m\n'

audit: ## Supply-chain gates — cargo-deny (advisories + licenses + bans + sources), secret scan, migration idempotency
	@command -v cargo-deny  >/dev/null 2>&1 \
	    || { printf '\033[1;31m✗ cargo-deny missing\033[0m — install: cargo install cargo-deny --locked\n';  exit 1; }
	@printf '▶ cargo deny check\n'
	@cargo deny check
	@printf '▶ secret-pattern scan\n'
	@# A line may opt out with a `// secret-scan-allow: <reason>` trailing
	@# marker — used ONLY for DLP/redaction test fixtures that legitimately
	@# embed a secret-shaped literal (e.g. `sk-AAAA…`, `ghp_aaaa…`). The
	@# `grep -v` drops marked lines; any UNmarked match is a real finding.
	@if grep -rEn "AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|glpat-[a-zA-Z0-9_-]{20,}" \
	    --include='*.rs' --include='*.ts' --include='*.tsx' --include='*.py' \
	    --exclude=dlp.rs \
	    controller/src worker/src frontend/src sdks 2>/dev/null \
	    | grep -v 'secret-scan-allow'; then \
	    printf '\033[1;31m✗ hardcoded secret pattern detected\033[0m\n'; exit 1; \
	fi
	@printf '▶ migration idempotency check\n'
	@# FAILS the build on a NEW non-idempotent migration (was warn-only —
	@# a gate that never fails trains operators to skim yellow output, the
	@# same failure mode that let the RLS suite sit red). Two escape valves:
	@#   * migrations/.idempotency-grandfathered — the 16 pre-convention
	@#     migrations that are already APPLIED and therefore can't be edited
	@#     (adding a marker would change the sqlx checksum). One filename
	@#     per line; this list is frozen and must not grow.
	@#   * `-- allow-non-idempotent: <reason>` inline marker — legal on a
	@#     NEW migration (not yet applied, so the comment is part of its
	@#     first-apply checksum) for a genuinely one-shot data migration.
	@set +e; failed=0; for f in migrations/*.sql; do \
	    base="$$(basename "$$f")"; \
	    if grep -qE '^(CREATE TABLE|CREATE INDEX|ALTER TABLE)' "$$f" \
	            && ! grep -qE 'IF NOT EXISTS|IF EXISTS|DO \$$\$$' "$$f"; then \
	        if grep -qxF "$$base" migrations/.idempotency-grandfathered 2>/dev/null; then \
	            continue; \
	        fi; \
	        if grep -qE 'allow-non-idempotent:' "$$f"; then \
	            continue; \
	        fi; \
	        printf '  \033[1;31m✗ %s\033[0m is not idempotent (no IF NOT EXISTS / IF EXISTS / DO $$$$)\n' "$$f"; \
	        failed=1; \
	    fi; \
	done; \
	if [ "$$failed" -ne 0 ]; then \
	    printf '  \033[1;31mNew migrations must be idempotent.\033[0m Add IF NOT EXISTS / IF EXISTS,\n'; \
	    printf '  or `-- allow-non-idempotent: <reason>` for a genuine one-shot data migration.\n'; \
	    exit 1; \
	fi; \
	printf '  all migrations idempotent (or grandfathered/marked)\n'

check-catalog: ## Compile every module-templates/* against current WIT (used by CI)
	@bash scripts/check-catalog.sh

ci: lint lint-frontend audit test check-catalog ## Full local gate matching GitHub Actions CI
	@printf '\033[1;32m✓ CI checks passed — safe to push\033[0m\n'

## ──── Ops ──────────────────────────────────────────────────────────

drill: ## Restore the newest backup artifacts into a scratch stack and verify them (ARGS=--source live)
	@bash scripts/drills/backup-restore.sh $(ARGS)

drill-schedule: ## Install + load the weekly drill LaunchAgent (macOS). Writes ~/Library/LaunchAgents and loads it immediately.
	@bash scripts/drills/schedule.sh install

drill-unschedule: ## Remove the weekly drill LaunchAgent (macOS)
	@bash scripts/drills/schedule.sh uninstall

drill-schedule-status: ## Show whether the weekly drill is scheduled and when it last ran
	@bash scripts/drills/schedule.sh status

# ── Off-host backup egress (Tier 2). docs/offhost-backup.md ──────────
# The local dumps live on the one disk they insure. These push an
# age-encrypted copy to object storage under unique timestamped keys, with
# a counter and two alerts so a persistent failure cannot be silent.
# `make drill ARGS="--source b2"` is what proves the result is restorable.

offhost-upload: ## Encrypt + upload the NEWEST local backup artifact of each kind to off-host storage
	@bash scripts/offhost-backup/upload.sh

offhost-backfill: ## One-time: upload every retained local artifact the bucket lacks (egress-heavy)
	@bash scripts/offhost-backup/upload.sh --backfill

offhost-plan: ## Show what would be uploaded, without touching the network
	@bash scripts/offhost-backup/upload.sh plan --offline

offhost-probe: ## PROVE append-only: attempt an overwrite and a delete; both must be refused BY THE PROVIDER (unreached = NOT PROVEN, exits 1)
	@bash scripts/offhost-backup/upload.sh probe-append-only

offhost-schedule: ## Install + load the DAILY off-host upload LaunchAgent (macOS)
	@bash scripts/offhost-backup/schedule.sh install

offhost-unschedule: ## Remove the daily off-host upload LaunchAgent (macOS)
	@bash scripts/offhost-backup/schedule.sh uninstall

offhost-status: ## Show whether the upload is scheduled and when it last succeeded
	@bash scripts/offhost-backup/schedule.sh status

deploy-prod: ## One-command production deploy: publish (gated+signed) -> pin digests -> install.sh on the VM -> external smoke. ARGS passthrough (--yes, --no-sign, ...)
	bash scripts/deploy-prod.sh $(ARGS)

smoke: ## End-to-end probe of a deployed cluster (BASE_URL=https://… SMOKE_AGENT_TOKEN=… SMOKE_ACTOR_ID=…)
	@bash scripts/smoke.sh

changelog: ## Print CHANGELOG entries missing for merged PRs (add --write via CHANGELOG_WRITE=1)
	@bash scripts/changelog-update.sh $(if $(CHANGELOG_WRITE),--write,)

schema-baseline: ## Generate the migration baseline snapshot + seed (RFC 0009; BASELINE_DATABASE_URL=… disposable PG)
	@bash scripts/generate-schema-baseline.sh

verify-schema-baseline: ## Prove baseline+seed+tail == full chain (RFC 0009; CHAIN_DATABASE_URL=… BASELINE_DATABASE_URL=…)
	@bash scripts/verify-schema-baseline.sh

rls-preflight: ## Verify Postgres is ready for RLS SET-ROLE enforcement (DATABASE_URL=… controller's role)
	@bash scripts/rls-preflight.sh

VERSION ?=
SERVICES ?=
release: ## Build + push controller/worker as linux/amd64 (VERSION=1.0.0-rNNN [SERVICES="controller worker"])
	@if [ -z "$(VERSION)" ]; then \
	    printf '\033[1;31m✗ VERSION required\033[0m — usage: make release VERSION=1.0.0-rNNN\n'; exit 1; \
	fi
	@bash scripts/release.sh "$(VERSION)" $(SERVICES)

NAMESPACE ?= talos
KUBECONFIG_FILE ?= /etc/rancher/k3s/k3s.yaml
migration-recovery: ## Re-run failed migrations job + tail logs in real time (NAMESPACE=talos)
	@bash scripts/migration-recovery.sh "$(NAMESPACE)"

clean: ## Stop containers, prune build caches (PRESERVES data volumes)
	@docker compose down --rmi local
	@docker builder prune --keep-storage 8gb -f
	@docker image prune -f

nuke: ## DESTRUCTIVE — wipe containers, volumes, images, host target/. Requires TALOS_NUKE=yes
	@if [ "$${TALOS_NUKE:-}" != "yes" ]; then \
	    printf '\033[1;31m✗ refusing to nuke\033[0m — set TALOS_NUKE=yes to confirm.\n'; \
	    printf '  This will delete: database, all data volumes, Docker images, host target/.\n'; \
	    exit 1; \
	fi
	@docker compose down -v --rmi all
	@cargo clean
	@rm -rf frontend/node_modules/.vite frontend/node_modules/.cache frontend/dist

# Internal: poll /health until controller responds or 60s elapses.
_wait-healthy:
	@for i in $$(seq 1 30); do \
	    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then exit 0; fi; \
	    sleep 2; \
	done; \
	printf '\033[1;31m✗ controller did not respond within 60s\033[0m — check: make logs\n'; exit 1
