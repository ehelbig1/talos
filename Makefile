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

.PHONY: help setup up down rebuild restart logs ps shell doctor \
        check build lint lint-frontend hooks test test-integration coverage-html audit check-catalog ci \
        drill clean nuke smoke rls-preflight _wait-healthy

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

up: ## Build + start the full dev stack, wait for health
	@test -f .env || { \
	    printf '\033[1;31m✗ no .env found.\033[0m Run `make setup` to generate one (or see QUICKSTART.md).\n'; \
	    exit 1; \
	}
	@docker compose build controller worker migrate
	@docker compose up -d --scale worker=1
	@$(MAKE) _wait-healthy
	@printf '\033[1;32m✓ stack healthy — http://localhost:8000/health\033[0m\n'

down: ## Stop the stack (preserves data volumes)
	@docker compose down

rebuild: ## Hot-rebuild one service (SERVICE=controller|worker|frontend|...)
	@docker compose up -d --build -- "$(SERVICE)"

restart: ## Restart one service without rebuilding (SERVICE=...)
	@docker compose restart -- "$(SERVICE)"

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
	@printf '▶ cargo fmt --check\n'
	@cargo fmt --all -- --check
	@printf '▶ structural lints (incl. clippy --workspace --no-deps -D warnings)\n'
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

test-integration: ## Run env-gated integration tests against disposable Redis+Postgres (needs Docker)
	@command -v docker >/dev/null 2>&1 \
	    || { printf '\033[1;31m✗ docker missing\033[0m — required to provision the disposable datastores\n'; exit 1; }
	@bash scripts/test-integration.sh

coverage-html: ## HTML coverage report via cargo-tarpaulin (slow; local only)
	@command -v cargo-tarpaulin >/dev/null 2>&1 \
	    || { printf '\033[1;31m✗ cargo-tarpaulin missing\033[0m — install: cargo install cargo-tarpaulin --locked\n'; exit 1; }
	@cargo tarpaulin --out Html

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
	@set +e; flagged=0; for f in migrations/*.sql; do \
	    if grep -qE '^(CREATE TABLE|CREATE INDEX|ALTER TABLE)' "$$f" \
	            && ! grep -qE 'IF NOT EXISTS|IF EXISTS|DO \$$\$$' "$$f"; then \
	        printf '  \033[33m⚠ %s\033[0m may not be idempotent\n' "$$f"; \
	        flagged=1; \
	    fi; \
	done; \
	[ "$$flagged" -eq 0 ] && printf '  all migrations use IF NOT EXISTS / IF EXISTS / DO $$$$\n' || true

check-catalog: ## Compile every module-templates/* against current WIT (used by CI)
	@bash scripts/check-catalog.sh

ci: lint lint-frontend audit test check-catalog ## Full local gate matching GitHub Actions CI
	@printf '\033[1;32m✓ CI checks passed — safe to push\033[0m\n'

## ──── Ops ──────────────────────────────────────────────────────────

drill: ## Run the backup→restore drill (pg_dump + vault snapshot → scratch stack → verify_phase_b)
	@bash scripts/drills/backup-restore.sh

smoke: ## End-to-end probe of a deployed cluster (BASE_URL=https://… SMOKE_AGENT_TOKEN=… SMOKE_ACTOR_ID=…)
	@bash scripts/smoke.sh

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
