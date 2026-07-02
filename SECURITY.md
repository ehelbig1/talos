# Talos Security Model

## Overview

Talos is a workflow automation platform that executes user-provided WebAssembly modules. This document is a **summary**; the authoritative, maintained security documentation lives in [`docs/security/`](docs/security/):

- [`threat-model.md`](docs/security/threat-model.md) — the full threat model (assets, adversaries, trust boundaries)
- [`architecture.md`](docs/security/architecture.md) — security architecture detail (per-org DEKs, HKDF per-context AEAD subkeys, format versioning, signed NATS-RPC, capability worlds, tier ceilings)
- [`operational-runbook.md`](docs/security/operational-runbook.md) — incident response and key-rotation procedures
- [`pentest-scope.md`](docs/security/pentest-scope.md) — authorized testing scope

If a statement here and one in `docs/security/` disagree, `docs/security/` wins — this file is refreshed less often.

## Threat Model

### Assets
1. **User Data**: Workflow definitions, secrets, execution logs
2. **WASM Modules**: User-provided code that runs in the sandbox
3. **Infrastructure**: Controller, worker, database, message queues

### Threats

#### 1. Malicious WASM Modules
**Risk**: User-provided WASM could escape sandbox or access unauthorized resources.

**Mitigations**:
- Capability-based sandboxing (WASI)
- Resource limits (fuel, memory)
- Allowed hosts whitelist
- No filesystem access except tmp
- Network access controlled by host list

#### 2. Secret Exfiltration
**Risk**: Secrets could be leaked through logs or module output.

**Mitigations**:
- Envelope encryption at rest (AES-256-GCM)
- DLP redaction on all output (PII detection)
- Audit logging of all secret access
- DEK caching with TTL

#### 3. Authentication Bypass
**Risk**: Weak authentication or token theft.

**Mitigations**:
- bcrypt password hashing (cost 12+)
- JWT with HS256, min 256-bit secret
- TOTP 2FA with rate limiting
- OAuth with state token validation
- API keys with prefix-based rate limiting

#### 4. Injection Attacks
**Risk**: SQL injection, XSS, command injection.

**Mitigations**:
- Parameterized queries (sqlx)
- Input validation on all endpoints
- Content-Type validation for webhooks
- DLP patterns for sensitive data
- Security headers (CSP, HSTS, X-Frame-Options)

#### 5. DoS Attacks
**Risk**: Resource exhaustion, query complexity attacks.

**Mitigations**:
- Rate limiting per IP and per API key
- GraphQL depth/complexity limits
- Payload size limits (1MB webhooks, 1MB GraphQL)
- Circuit breakers on webhooks
- Compilation concurrency limits

## Security Headers

All responses include:
- `Content-Security-Policy`: Strict policy in production
- `Strict-Transport-Security`: HSTS with 1-year max-age
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy`: Restricted feature access

## Data Protection

### Encryption at Rest
- **Every column carrying user data** sealed with AES-256-GCM envelope encryption: secrets, OAuth tokens, actor memory (`actor_memory.value_enc`), module-execution payloads (`module_executions.{input,output,trigger_metadata}_enc`), workflow-execution outputs (`workflow_executions.output_data_enc`).
- DEKs rotated automatically; per-row DEK wrapped by KEK.
- **Pluggable KEK** via `KekProvider` trait — production deployments set `KEK_PROVIDER=vault` so the master key lives in HashiCorp Vault transit and never enters the controller process. Dev fallback (`KEK_PROVIDER=env`) reads `TALOS_MASTER_KEY` from the environment.
- **Per-actor LLM data-egress ceiling** (`actors.max_llm_tier`): tier-1 actors physically cannot reach Anthropic / OpenAI / Gemini — enforced at five worker surfaces, HMAC-bound in JobRequest signing.

### Encryption in Transit
- TLS 1.3 for all external connections
- mTLS for controller-worker communication
- NATS with authentication

### Audit Logging
- Immutable audit ledger (WORM storage)
- All authentication events logged
- Secret access logged
- Module execution logged

## Network Security

### Firewall Rules
- Database: Only controller access
- Redis: Only controller access
- NATS: Controller and workers only

### Webhook Security
- HMAC signature verification
- IP allowlist support
- Rate limiting per trigger
- Circuit breaker pattern
- Dead letter queue for dropped messages

## Secure Development

### Dependencies
- Cargo audit on all compilations
- Dependabot for automated updates
- No `unsafe` code in controller

### Secrets Management
- No secrets in code
- Environment variables for configuration
- Git hooks to prevent accidental commits

## Incident Response

### Monitoring
- Health checks on all subsystems
- Metrics export (Prometheus format)
- Alerting on error rates

### Response Playbook
1. Isolate affected components
2. Rotate compromised credentials
3. Review audit logs
4. Apply patches
5. Post-incident review

## Vulnerability Disclosure

Please report security vulnerabilities privately using [GitHub's private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (Security tab → "Report a vulnerability").

Please do not disclose security issues publicly until they have been investigated and
addressed. We aim to acknowledge reports within 72 hours.
