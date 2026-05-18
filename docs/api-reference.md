# GraphQL API Reference

The Talos controller exposes a GraphQL API at `/graphql` (POST) with WebSocket subscriptions at `/ws`.

## Authentication

All API requests require authentication via one of:

1. **HTTP-only cookies** -- Set automatically on login/signup (`talos_access_token`, `talos_refresh_token`)
2. **Bearer token** -- `Authorization: Bearer <access_token>` header
3. **API key** -- `X-API-Key: <key>` header (scoped permissions)

CSRF protection is enforced on mutations in production via the `X-CSRF-Token` header.

## Queries

### User & Auth

| Query | Description | Auth |
|-------|-------------|------|
| `me` | Get current user info (id, email, name, 2FA status) | Required |
| `apiKeys` | List user's API keys | Required |
| `linkedOAuthAccounts` | List OAuth accounts linked to the user | Required |
| `oauthLoginUrl(provider: String)` | Get OAuth authorization URL | Required |
| `auditSettings` | Get user's audit streaming settings | Admin |

### Workflows

| Query | Description | Auth |
|-------|-------------|------|
| `workflows(limit, offset)` | List user's workflows (paginated) | Required |
| `workflow(id: UUID)` | Get a single workflow by ID | Required (owner) |
| `workflowVersions(workflowId: UUID)` | List published versions | Required |
| `activeWorkflowVersion(workflowId: UUID)` | Get the active published version | Required |
| `workflowSchedule(workflowId: UUID)` | Get the cron schedule for a workflow | Required |
| `mySchedules` | List all user's workflow schedules | Required |

### Modules

| Query | Description | Auth |
|-------|-------------|------|
| `myModules(limit, offset)` | List user's compiled WASM modules | Required |
| `wasmModules(ids: [UUID])` | Batch-fetch modules by ID | Required |
| `nodeTemplates(category: String)` | List available node templates | Required |
| `nodeTemplate(id: UUID)` | Get a single node template | Required |
| `moduleTemplates` | List module code templates | Required |
| `moduleTemplate(templateId: String)` | Get a single module template | Required |
| `analyzeCustomModule(sourceCode, language)` | Static analysis of module source | Required |
| `analyzeRhai(expression)` | Validate a Rhai expression | Public |
| `testRhaiExpression(expression, inputJson)` | Evaluate Rhai against test data | Public |

### Executions

| Query | Description | Auth |
|-------|-------------|------|
| `latestWorkflowExecutions(workflowIds: [UUID])` | Get latest execution per workflow | Required |
| `workflowExecutionHistory(workflowId, limit, offset)` | Paginated execution history | Required |
| `moduleExecutionHistory(moduleId, limit, offset)` | Module-level execution history | Required |
| `moduleExecutionLogs(executionId, limit, offset)` | Execution log entries | Required |

### Webhooks & Secrets

| Query | Description | Auth |
|-------|-------------|------|
| `webhookTriggers` | List user's webhook triggers | Required |
| `secrets` | List user's secrets (metadata only) | Required |
| `secret(keyPath: String)` | Get a single secret's metadata | Required |
| `secretAuditLog(keyPath, limit, offset)` | Access audit log for a secret | Required |

### Approval Gates

| Query | Description | Auth |
|-------|-------------|------|
| `pendingApprovals(workflowId: UUID, limit, offset)` | List executions awaiting human approval | Required |

Approval gates are created by modules using the `governance` WIT interface (`request-approval`). When a module requests approval, the workflow execution pauses until an operator resolves it via the REST endpoint (see below).

### Dead Letter Queue

| Query | Description | Auth |
|-------|-------------|------|
| `deadLetterQueue(limit, offset)` | List failed jobs that exhausted retries | Required |

Dead letter entries include the original job payload, failure reason, and timestamps. Use the `replayDeadLetterEntry` mutation to re-enqueue a failed job.

### Resource Quotas

| Query | Description | Auth |
|-------|-------------|------|
| `resourceQuotas` | Get current resource usage and limits for the authenticated user | Required |

Returns usage metrics such as `llm_tokens`, `http_calls`, `db_queries`, and `wasm_executions` with their current values, limits, and remaining budget.

## Mutations

### Auth

| Mutation | Description |
|----------|-------------|
| `signup(input: SignupInput)` | Create account, returns tokens |
| `login(input: LoginInput)` | Authenticate, returns tokens |
| `refreshToken` | Refresh access token from cookie |
| `logout` | Revoke tokens, clear cookies |
| `setupTwoFactor` | Generate TOTP secret + QR code |
| `enableTwoFactor(code: String)` | Verify and enable 2FA |
| `disableTwoFactor` | Disable 2FA |
| `verifyTwoFactor(code, trustDevice)` | Verify TOTP code |

### Workflows

| Mutation | Description |
|----------|-------------|
| `createWorkflow(name, graphJson)` | Create a new workflow |
| `updateWorkflow(id, name, graphJson)` | Update workflow definition |
| `deleteWorkflow(id: UUID)` | Delete a workflow |
| `triggerWorkflow(workflowId: UUID)` | Execute a workflow (returns execution ID) |
| `resumeWorkflow(executionId: UUID)` | Resume a paused workflow |
| `testWorkflow(workflowId, mockInputs)` | Dry-run with mock data (30s timeout) |
| `publishWorkflowVersion(workflowId)` | Publish current draft as a version |
| `rollbackWorkflowVersion(workflowId, versionId)` | Roll back to a previous version |
| `createSchedule(workflowId, cronExpr, timezone)` | Set a cron schedule |
| `updateSchedule(workflowId, cronExpr, timezone, enabled)` | Update schedule |
| `deleteSchedule(workflowId)` | Remove cron schedule |

### Modules

| Mutation | Description |
|----------|-------------|
| `createModuleFromTemplate(templateId, name, config)` | Instantiate a template |
| `createModuleFromVisualTemplate(templateId, name, config)` | Visual template instantiation |
| `createCustomModule(name, sourceCode, language, config)` | Upload custom module source |
| `updateCustomModule(id, sourceCode, language, config)` | Update module source |
| `testCustomModule(sourceCode, language, testInput, config)` | Test module without saving |

### Webhooks

| Mutation | Description |
|----------|-------------|
| `createWebhookTrigger(input)` | Create a webhook endpoint |

### Secrets

| Mutation | Description |
|----------|-------------|
| `createSecret(input: CreateSecretInput)` | Store an encrypted secret |
| `updateSecret(input: UpdateSecretInput)` | Update a secret's value |
| `deleteSecret(keyPath: String)` | Delete a secret |
| `rotateDek` | Rotate the Data Encryption Key |
| `reEncryptSecrets` | Re-encrypt all secrets with current DEK |
| `rotateEncryptionKey` | Rotate the master encryption key and re-wrap all DEKs (admin only) |

### Dead Letter Queue

| Mutation | Description |
|----------|-------------|
| `replayDeadLetterEntry(entryId: UUID)` | Re-enqueue a dead letter entry for retry |

### API Keys

| Mutation | Description |
|----------|-------------|
| `createApiKey(input)` | Create a scoped API key |
| `revokeApiKey(keyId: UUID)` | Revoke an API key |
| `deleteApiKey(keyId: UUID)` | Permanently delete an API key |
| `rotateApiKey(keyId: UUID)` | Rotate key value |

### Organizations

| Mutation | Description |
|----------|-------------|
| `createOrganization(name, slug)` | Create an org (caller becomes owner) |
| `inviteMember(orgId, userId, role)` | Add member to org |
| `removeMember(orgId, userId)` | Remove member |
| `changeMemberRole(orgId, userId, role)` | Change member role |
| `transferOwnership(orgId, newOwnerId)` | Transfer org ownership |

## Subscriptions

| Subscription | Description |
|--------------|-------------|
| `executionUpdates(executionId: UUID)` | Real-time execution events via WebSocket |

Connects via the `graphql-ws` protocol at `/ws`.

## REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Comprehensive health check (DB, Redis, NATS) |
| `/health/redis` | GET | Redis-only health check |
| `/health/nats` | GET | NATS-only health check |
| `/webhooks/{id}` | POST | Incoming webhook endpoint |
| `/api/approvals/{execution_id}` | POST | Human-in-the-loop approval resolution |
| `/auth/oauth/{provider}/login` | GET | Start OAuth flow |
| `/auth/oauth/{provider}/callback` | GET | OAuth callback |
| `/auth/logout` | POST | Logout (cookie-based) |
| `/api/slack/*` | Various | Slack integration management |
| `/api/gmail/*` | Various | Gmail integration management |
| `/api/google-calendar/*` | Various | Google Calendar integration |
| `/api/registry/*` | Various | OCI module registry |
| `/mcp/*` | Various | MCP (Model Context Protocol) endpoints |

## Rate Limiting

- **API**: Configurable via `API_RATE_LIMIT` (default: 100 req/min per IP)
- **Webhooks**: Configurable via `WEBHOOK_RATE_LIMIT` (default: 60 req/min per IP)
- **Global**: Configurable via `GLOBAL_RATE_LIMIT` (default: 1000 req/min total)
- **tower_governor**: 10 req/sec per IP (production only)

Trusted IPs can bypass rate limits via `TRUSTED_IPS` environment variable.

## Approval Gate Resolution

The `POST /api/approvals/{execution_id}` REST endpoint resolves a pending human-in-the-loop approval. Send a JSON body:

```json
{
    "approved": true,
    "reason": "Looks good to proceed"
}
```

Set `approved` to `false` to reject, which fails the workflow execution. Requires authentication (cookie or bearer token) and ownership of the workflow.

## Job Priority & Cancellation

Jobs dispatched to workers support the following scheduling fields:

- **`priority`** (u8, default `100`): Priority from 0 (lowest) to 255 (highest). Higher-priority jobs are dequeued before lower-priority ones.
- **`cancellation_token`** (optional string): An opaque token checked periodically by the worker. If the token is revoked, the worker aborts execution.
- **`deadline_unix_secs`** (u64, default `0`): Absolute Unix timestamp deadline. If set, the job must complete before this time or is treated as failed. A value of `0` means no deadline.
