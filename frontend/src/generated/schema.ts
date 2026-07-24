export type Maybe<T> = T | null;
export type InputMaybe<T> = Maybe<T>;
/** All built-in and custom scalars, mapped to their actual values */
export type Scalars = {
  ID: { input: string; output: string };
  String: { input: string; output: string };
  Boolean: { input: boolean; output: boolean };
  Int: { input: number; output: number };
  Float: { input: number; output: number };
  /**
   * Implement the DateTime<Utc> scalar
   *
   * The input/output is a string in RFC3339 format.
   */
  DateTime: { input: unknown; output: unknown };
  /** A scalar that can represent any JSON value. */
  JSON: { input: unknown; output: unknown };
  /**
   * A UUID is a unique 128-bit number, stored as 16 octets. UUIDs are parsed as
   * Strings within GraphQL. UUIDs are used to assign unique identifiers to
   * entities without requiring a central allocating authority.
   *
   * # References
   *
   * * [Wikipedia: Universally Unique Identifier](http://en.wikipedia.org/wiki/Universally_unique_identifier)
   * * [RFC4122: A Universally Unique Identifier (UUID) URN Namespace](http://tools.ietf.org/html/rfc4122)
   */
  UUID: { input: string; output: string };
};

export type ActorActionLogEntry = {
  __typename?: "ActorActionLogEntry";
  actionType: Scalars["String"]["output"];
  executionId?: Maybe<Scalars["UUID"]["output"]>;
  id: Scalars["UUID"]["output"];
  summary: Scalars["String"]["output"];
  timestamp: Scalars["String"]["output"];
  workflowId?: Maybe<Scalars["UUID"]["output"]>;
};

export type ActorDetails = {
  __typename?: "ActorDetails";
  createdAt: Scalars["String"]["output"];
  description?: Maybe<Scalars["String"]["output"]>;
  executionCount: Scalars["Int"]["output"];
  id: Scalars["UUID"]["output"];
  /** ISO-8601 timestamp of the most recent execution dispatched by this actor. */
  lastActiveAt?: Maybe<Scalars["String"]["output"]>;
  maxCapabilityWorld: Scalars["String"]["output"];
  /** MCP bearer token — intentionally always None via GraphQL (shown once at MCP creation). */
  mcpToken?: Maybe<Scalars["String"]["output"]>;
  metadata?: Maybe<Scalars["String"]["output"]>;
  name: Scalars["String"]["output"];
  /** Per-minute execution rate limit. None = unlimited. */
  rateLimit?: Maybe<Scalars["Int"]["output"]>;
  /** Lifetime budget consumed. Always 0 until budget tracking is wired. */
  spentBudgetUsd: Scalars["Float"]["output"];
  status: Scalars["String"]["output"];
  /** Lifetime budget cap in USD. None = unlimited. */
  totalBudgetUsd?: Maybe<Scalars["Float"]["output"]>;
  updatedAt: Scalars["String"]["output"];
  workflowCount: Scalars["Int"]["output"];
};

export type ActorExecutionsSummary = {
  __typename?: "ActorExecutionsSummary";
  activeExecutions: Scalars["Int"]["output"];
  failedExecutions: Scalars["Int"]["output"];
  successfulExecutions: Scalars["Int"]["output"];
  totalExecutions: Scalars["Int"]["output"];
};

/** A single memory entry stored against an actor. */
export type ActorMemoryEntry = {
  __typename?: "ActorMemoryEntry";
  /** ISO-8601 expiry, null means permanent (semantic). */
  expiresAt?: Maybe<Scalars["String"]["output"]>;
  key: Scalars["String"]["output"];
  /** "working" | "episodic" | "semantic" | "scratchpad" */
  memoryType: Scalars["String"]["output"];
  updatedAt: Scalars["String"]["output"];
  /** JSON-serialized value — parse on the client. */
  value: Scalars["String"]["output"];
};

/**
 * One actor's memory entries within a batched `actorsMemories` read.
 * Groups are returned ONLY for actors the caller owns — a requested id
 * that is unknown (or another tenant's) simply has no group, so its
 * absence is indistinguishable from non-existence.
 */
export type ActorMemoryGroup = {
  __typename?: "ActorMemoryGroup";
  actorId: Scalars["UUID"]["output"];
  memories: Array<ActorMemoryEntry>;
};

export type ActorSummary = {
  __typename?: "ActorSummary";
  createdAt: Scalars["String"]["output"];
  description?: Maybe<Scalars["String"]["output"]>;
  executionCount: Scalars["Int"]["output"];
  id: Scalars["UUID"]["output"];
  maxCapabilityWorld: Scalars["String"]["output"];
  name: Scalars["String"]["output"];
  /** Lifetime budget consumed. Always 0 until budget tracking is wired. */
  spentBudgetUsd: Scalars["Float"]["output"];
  status: Scalars["String"]["output"];
  /** Lifetime budget cap in USD. None = unlimited. */
  totalBudgetUsd?: Maybe<Scalars["Float"]["output"]>;
  updatedAt: Scalars["String"]["output"];
  workflowCount: Scalars["Int"]["output"];
};

export type ActorWorkflowItem = {
  __typename?: "ActorWorkflowItem";
  createdAt: Scalars["String"]["output"];
  /** Serialized graph JSON — used client-side to detect AI Actor (LLM + INJECT_CONTEXT). */
  graphJson?: Maybe<Scalars["String"]["output"]>;
  id: Scalars["UUID"]["output"];
  name: Scalars["String"]["output"];
  nodeCount: Scalars["Int"]["output"];
  status?: Maybe<Scalars["String"]["output"]>;
  updatedAt: Scalars["String"]["output"];
};

export type ActorWorkflowsSummary = {
  __typename?: "ActorWorkflowsSummary";
  activeWorkflows: Scalars["Int"]["output"];
  totalWorkflows: Scalars["Int"]["output"];
};

export type AnalyzeCustomModuleResult = {
  __typename?: "AnalyzeCustomModuleResult";
  errors: Array<CompilationErrorObj>;
  success: Scalars["Boolean"]["output"];
};

export type AnalyzeRhaiInput = {
  script: Scalars["String"]["input"];
};

export type ApiKeyCreated = {
  __typename?: "ApiKeyCreated";
  expiresAt?: Maybe<Scalars["String"]["output"]>;
  id: Scalars["UUID"]["output"];
  key: Scalars["String"]["output"];
  name: Scalars["String"]["output"];
  scopes: Array<Scalars["String"]["output"]>;
};

export type ApiKeyInfo = {
  __typename?: "ApiKeyInfo";
  createdAt: Scalars["String"]["output"];
  expiresAt?: Maybe<Scalars["String"]["output"]>;
  id: Scalars["UUID"]["output"];
  isActive: Scalars["Boolean"]["output"];
  keyPrefix: Scalars["String"]["output"];
  lastUsedAt?: Maybe<Scalars["String"]["output"]>;
  name: Scalars["String"]["output"];
  scopes: Array<Scalars["String"]["output"]>;
  usageCount: Scalars["Int"]["output"];
};

/**
 * One integrity failure found while verifying a persisted audit chain.
 * Flattened from `talos_audit_ledger::ChainBreak` for the GraphQL surface.
 */
export type AuditChainBreak = {
  __typename?: "AuditChainBreak";
  /** Expected value (prior/genesis hash, or expected sequence), if applicable. */
  expected?: Maybe<Scalars["String"]["output"]>;
  /** Found value, if applicable. */
  found?: Maybe<Scalars["String"]["output"]>;
  /**
   * `sequence_gap` | `duplicate_sequence` | `genesis_mismatch` |
   * `linkage_mismatch` | `bad_signature` | `unsigned`.
   */
  kind: Scalars["String"]["output"];
  /** The sequence number the break is associated with, if applicable. */
  sequence?: Maybe<Scalars["Int"]["output"]>;
};

/**
 * Result of verifying the cryptographic audit chain for one execution
 * (finding #2). `ok` is true iff there are no `breaks` and — when signing
 * keys are configured — every event's HMAC verified.
 */
export type AuditChainVerification = {
  __typename?: "AuditChainVerification";
  breaks: Array<AuditChainBreak>;
  executionId: Scalars["String"]["output"];
  ok: Scalars["Boolean"]["output"];
  /** Whether HMAC verification was attempted (signing keys configured). */
  signaturesChecked: Scalars["Boolean"]["output"];
  totalEvents: Scalars["Int"]["output"];
  workflowId: Scalars["String"]["output"];
};

export type AuthPayload = {
  __typename?: "AuthPayload";
  user: UserInfo;
};

/** Detailed capability ceiling information for the current user. */
export type CapabilityCeilingDetail = {
  __typename?: "CapabilityCeilingDetail";
  ceiling: Scalars["String"]["output"];
  grantedAt?: Maybe<Scalars["String"]["output"]>;
  grantedByEmail?: Maybe<Scalars["String"]["output"]>;
  notes?: Maybe<Scalars["String"]["output"]>;
  source: Scalars["String"]["output"];
};

/** A capability grant record (admin view). */
export type CapabilityGrant = {
  __typename?: "CapabilityGrant";
  email: Scalars["String"]["output"];
  grantedAt: Scalars["String"]["output"];
  grantedBy?: Maybe<Scalars["UUID"]["output"]>;
  maxCapabilityWorld: Scalars["String"]["output"];
  notes?: Maybe<Scalars["String"]["output"]>;
  userId: Scalars["UUID"]["output"];
};

/** A single world in the capability hierarchy. */
export type CapabilityWorldInfo = {
  __typename?: "CapabilityWorldInfo";
  description: Scalars["String"]["output"];
  name: Scalars["String"]["output"];
  rank: Scalars["Int"]["output"];
};

/** Human-readable changelog entry for a workflow version. */
export type ChangelogEntry = {
  __typename?: "ChangelogEntry";
  description?: Maybe<Scalars["String"]["output"]>;
  publishedAt: Scalars["String"]["output"];
  summary: Scalars["String"]["output"];
  versionNumber: Scalars["Int"]["output"];
};

export type CompilationErrorObj = {
  __typename?: "CompilationErrorObj";
  column?: Maybe<Scalars["Int"]["output"]>;
  endColumn?: Maybe<Scalars["Int"]["output"]>;
  endLine?: Maybe<Scalars["Int"]["output"]>;
  line?: Maybe<Scalars["Int"]["output"]>;
  message: Scalars["String"]["output"];
  severity: Scalars["String"]["output"];
};

export type CompilationEvent = {
  __typename?: "CompilationEvent";
  jobId: Scalars["UUID"]["output"];
  message?: Maybe<Scalars["String"]["output"]>;
  progress?: Maybe<Scalars["Float"]["output"]>;
  status: Scalars["String"]["output"];
  userId: Scalars["UUID"]["output"];
};

/** Input type for createActor mutation. */
export type CreateActorInput = {
  description?: InputMaybe<Scalars["String"]["input"]>;
  maxCapabilityWorld?: InputMaybe<Scalars["String"]["input"]>;
  name: Scalars["String"]["input"];
  /** Per-minute execution rate limit (informational — reserved for future enforcement). */
  rateLimit?: InputMaybe<Scalars["Int"]["input"]>;
  /** Lifetime budget cap in USD (informational — enforcement via budget policies). */
  totalBudgetUsd?: InputMaybe<Scalars["Float"]["input"]>;
};

export type CreateApiKeyInput = {
  expiresInDays?: InputMaybe<Scalars["Int"]["input"]>;
  name: Scalars["String"]["input"];
  scopes: Array<Scalars["String"]["input"]>;
};

export type CreateModuleInput = {
  config: Scalars["String"]["input"];
  jobId?: InputMaybe<Scalars["UUID"]["input"]>;
  name: Scalars["String"]["input"];
  templateId: Scalars["UUID"]["input"];
};

export type CreateSecretInput = {
  allowedModules?: InputMaybe<Array<Scalars["UUID"]["input"]>>;
  description?: InputMaybe<Scalars["String"]["input"]>;
  keyPath: Scalars["String"]["input"];
  name: Scalars["String"]["input"];
  /**
   * Optional organization to assign the secret to. When set, all org
   * members can access this secret.
   */
  orgId?: InputMaybe<Scalars["UUID"]["input"]>;
  value: Scalars["String"]["input"];
};

export type CreateWebhookTriggerInput = {
  allowedIps?: InputMaybe<Array<Scalars["String"]["input"]>>;
  enabled?: InputMaybe<Scalars["Boolean"]["input"]>;
  /**
   * RFC 0007: optional provider-agnostic event filter, evaluated AFTER
   * signature verification. A non-matching delivery is acknowledged 200 with
   * no dispatch (so it doesn't burn an execution). Omit to fire on every
   * verified delivery. Shape (validated via `talos_webhooks::validate_event_filter`):
   * `{ "header": "X-GitHub-Event", "values": ["pull_request"],
   * "payload_match": { "action": ["opened","synchronize","reopened"] } }`.
   */
  eventFilter?: InputMaybe<Scalars["JSON"]["input"]>;
  maxRequestsPerMinute?: InputMaybe<Scalars["Int"]["input"]>;
  moduleId: Scalars["UUID"]["input"];
  name: Scalars["String"]["input"];
  signingSecret?: InputMaybe<Scalars["String"]["input"]>;
  verificationToken?: InputMaybe<Scalars["String"]["input"]>;
};

/**
 * Input for `createWorkflowFromDescription`. Mirrors the MCP
 * `create_workflow_from_description` tool — natural-language
 * description plus an optional fallback list of module UUIDs to
 * chain when no LLM is configured.
 */
export type CreateWorkflowFromDescriptionInput = {
  description: Scalars["String"]["input"];
  /**
   * Optional explicit module UUIDs. Used when no LLM is
   * available, or when the caller wants to force a specific set
   * of modules instead of relying on AI scaffolding.
   */
  modules?: InputMaybe<Array<Scalars["String"]["input"]>>;
};

/**
 * Result envelope for `createWorkflowFromDescription`. Maps the
 * service's typed `CreateFromDescriptionOutcome` enum into a
 * flattened struct with stable shape — GraphQL doesn't have great
 * ergonomics for multi-variant union responses, and this shape
 * matches what callers actually need to branch on (`success`,
 * `scaffolded_by`, optional error class).
 */
export type CreateWorkflowFromDescriptionResult = {
  __typename?: "CreateWorkflowFromDescriptionResult";
  /**
   * Per-soft-failure-mode tag: `"llm_incomplete"`,
   * `"llm_invalid_json"`, `"llm_failed"`, `"no_llm_and_no_explicit"`,
   * `"no_matched_modules"`, or null on success. Stable strings —
   * agents and the UI branch on these.
   */
  errorClass?: Maybe<Scalars["String"]["output"]>;
  /** Human-readable message paired with `error_class`. */
  errorMessage?: Maybe<Scalars["String"]["output"]>;
  /**
   * Sub-class for `error_class = "llm_failed"`: `"rate_limited"`,
   * `"timeout"`, `"auth"`, `"upstream_unavailable"`, `"network"`,
   * `"unknown"`. Null otherwise.
   */
  llmErrorClass?: Maybe<Scalars["String"]["output"]>;
  /**
   * Module names that exist in the catalog but have no compiled
   * WASM. Caller should run `compile_template` before triggering.
   */
  modulesNotCompiled?: Maybe<Array<Scalars["String"]["output"]>>;
  name?: Maybe<Scalars["String"]["output"]>;
  /**
   * LLM-only — the natural-language reasoning the LLM provided
   * for its scaffold choice.
   */
  reasoning?: Maybe<Scalars["String"]["output"]>;
  /**
   * "llm" | "explicit_modules" | "none". Mirrors the MCP
   * response's `scaffolded_by` field so a UI built off the MCP
   * surface can switch onto the same value.
   */
  scaffoldedBy: Scalars["String"]["output"];
  success: Scalars["Boolean"]["output"];
  /** LLM-only — suggested cron expression for automatic triggering. */
  suggestedSchedule?: Maybe<Scalars["String"]["output"]>;
  /**
   * Module names the LLM suggested but couldn't be resolved
   * against the catalog.
   */
  unresolvedModules?: Maybe<Array<Scalars["String"]["output"]>>;
  /**
   * Set on the two success cases (`LlmScaffold`,
   * `ExplicitModuleScaffold`).
   */
  workflowId?: Maybe<Scalars["UUID"]["output"]>;
};

export type CreateWorkflowInput = {
  graphJson: Scalars["String"]["input"];
  intent?: InputMaybe<Scalars["JSON"]["input"]>;
  maxConcurrentExecutions?: InputMaybe<Scalars["Int"]["input"]>;
  name: Scalars["String"]["input"];
  /**
   * Organization that owns this workflow (RFC 0004 tenant = org).
   * Omit to create it in your **personal org** (the default). When set
   * to a shared org, the caller must have Member+ role there
   * (validated against `user_writable_org_ids`); teammates then see
   * the workflow via the org-union read path.
   */
  organizationId?: InputMaybe<Scalars["UUID"]["input"]>;
};

/** A node execution that failed and was moved to the Dead Letter Queue. */
export type DeadLetterEntry = {
  __typename?: "DeadLetterEntry";
  createdAt: Scalars["String"]["output"];
  errorMessage: Scalars["String"]["output"];
  executionId: Scalars["UUID"]["output"];
  id: Scalars["UUID"]["output"];
  nodeId: Scalars["UUID"]["output"];
  payload?: Maybe<Scalars["String"]["output"]>;
  replayedAt?: Maybe<Scalars["String"]["output"]>;
  replayedBy?: Maybe<Scalars["UUID"]["output"]>;
  workflowId: Scalars["UUID"]["output"];
};

/** Per-table per-org DEK migration status (one entry per encrypted table). */
export type DekMigrationStatusEntry = {
  __typename?: "DekMigrationStatusEntry";
  /**
   * True when a `reEncrypt…ToOrg` sweep drives `pending` to 0; false for the
   * personal tables that migrate lazily on next write.
   */
  hasSweep: Scalars["Boolean"]["output"];
  /**
   * Rows still on the global DEK that have a resolvable org (remaining sweep
   * work). 0 = migration complete for this table.
   */
  pending: Scalars["Int"]["output"];
  /** Logical table/column label. */
  table: Scalars["String"]["output"];
};

/** Result of a DEK rotation operation. */
export type DekRotationResult = {
  __typename?: "DekRotationResult";
  /** Human-readable status message. */
  message: Scalars["String"]["output"];
  /** The UUID of the newly created DEK. */
  newDekId: Scalars["UUID"]["output"];
};

export type DlqEvent = {
  __typename?: "DlqEvent";
  createdAt: Scalars["String"]["output"];
  errorMessage?: Maybe<Scalars["String"]["output"]>;
  executionId?: Maybe<Scalars["UUID"]["output"]>;
  id: Scalars["UUID"]["output"];
  nodeId?: Maybe<Scalars["UUID"]["output"]>;
  /**
   * M T6-1: workflow's organisation. Same emit-time stamp.
   * Subscribers gated to org membership view events with
   * matching `org_id`.
   */
  orgId?: Maybe<Scalars["UUID"]["output"]>;
  payload?: Maybe<Scalars["String"]["output"]>;
  replayedAt?: Maybe<Scalars["String"]["output"]>;
  /**
   * M T6-1: workflow owner. Stamped at emit time so the
   * subscription filter doesn't need a per-event DB lookup. None
   * when the trigger has been deleted (`webhook_triggers.workflow_id`
   * is `ON DELETE SET NULL`) — the subscription treats None as
   * platform-admin-only-visible.
   */
  userId?: Maybe<Scalars["UUID"]["output"]>;
  workflowId?: Maybe<Scalars["UUID"]["output"]>;
};

export type Enable2FaInput = {
  code: Scalars["String"]["input"];
  secret: Scalars["String"]["input"];
};

/** A pending authorization request for a module execution. */
export type ExecutionApproval = {
  __typename?: "ExecutionApproval";
  decidedAt?: Maybe<Scalars["String"]["output"]>;
  decidedBy?: Maybe<Scalars["UUID"]["output"]>;
  executionId: Scalars["UUID"]["output"];
  id: Scalars["UUID"]["output"];
  nodeId: Scalars["UUID"]["output"];
  reason?: Maybe<Scalars["String"]["output"]>;
  requestedAt: Scalars["String"]["output"];
  requiredFor: Array<Scalars["String"]["output"]>;
  status: Scalars["String"]["output"];
  workflowId: Scalars["UUID"]["output"];
  /**
   * Display name of the workflow awaiting approval (null when owned by
   * another user). Batched via [`WorkflowNameLoader`].
   */
  workflowName?: Maybe<Scalars["String"]["output"]>;
};

export type ExecutionEvent = {
  __typename?: "ExecutionEvent";
  /** Wall-clock duration in ms from node_started to this event. Present on completion events. */
  durationMs?: Maybe<Scalars["Int"]["output"]>;
  executionId: Scalars["UUID"]["output"];
  iterationIndex?: Maybe<Scalars["Int"]["output"]>;
  iterationTotal?: Maybe<Scalars["Int"]["output"]>;
  logMessage?: Maybe<Scalars["String"]["output"]>;
  nodeId?: Maybe<Scalars["UUID"]["output"]>;
  /** Final output JSON. Only populated on `OutputReady` events for streaming consumers. */
  output?: Maybe<Scalars["JSON"]["output"]>;
  spanId?: Maybe<Scalars["String"]["output"]>;
  status: ExecutionStatus;
  traceId?: Maybe<Scalars["String"]["output"]>;
};

export enum ExecutionStatus {
  Completed = "COMPLETED",
  Failed = "FAILED",
  /**
   * Workflow has finished and the final output is available.
   * Used by streaming consumers to receive the final result.
   */
  OutputReady = "OUTPUT_READY",
  Pending = "PENDING",
  Running = "RUNNING",
  Skipped = "SKIPPED",
  Waiting = "WAITING",
}

export type GenerateCodeInput = {
  capabilityWorld: Scalars["String"]["input"];
  currentCode: Scalars["String"]["input"];
  prompt: Scalars["String"]["input"];
};

export type GenerateCodeResult = {
  __typename?: "GenerateCodeResult";
  code: Scalars["String"]["output"];
};

/** Input for granting a capability ceiling to a user. */
export type GrantCapabilityCeilingInput = {
  maxCapabilityWorld: Scalars["String"]["input"];
  notes?: InputMaybe<Scalars["String"]["input"]>;
  userId: Scalars["UUID"]["input"];
};

export enum IntegrationService {
  Gmail = "GMAIL",
  GoogleCalendar = "GOOGLE_CALENDAR",
  GoogleCloud = "GOOGLE_CLOUD",
  Jira = "JIRA",
  Slack = "SLACK",
}

/**
 * One (provider, model) LLM usage aggregate within a trailing window —
 * the per-model/provider spend breakdown row for the token-spend panel.
 */
export type LlmUsageModelRow = {
  __typename?: "LlmUsageModelRow";
  calls: Scalars["Int"]["output"];
  completionTokens: Scalars["Int"]["output"];
  model: Scalars["String"]["output"];
  promptTokens: Scalars["Int"]["output"];
  provider: Scalars["String"]["output"];
};

/**
 * Read-only per-actor LLM token spend summary (R2 token ledger). Mirrors
 * the `current_usage`/`policy` numbers the MCP `get_actor_budget` tool
 * already exposes — budget POLICY *writes* stay MCP-only (see
 * `BudgetPanel`'s "configured via MCP tools" note), this is visibility
 * only.
 */
export type LlmUsageSummary = {
  __typename?: "LlmUsageSummary";
  actorId: Scalars["UUID"]["output"];
  /**
   * Per-(provider, model) breakdown over the trailing window (`days`
   * arg on the query, default 7, clamped 1..=90).
   */
  byModel: Array<LlmUsageModelRow>;
  /**
   * Daily token ceiling from the actor's budget policy. `None` =
   * unlimited (no policy row, or an explicit NULL ceiling).
   */
  maxLlmTokensPerDay?: Maybe<Scalars["Int"]["output"]>;
  /**
   * Trailing-24h SUM(prompt_tokens + completion_tokens) — the same
   * figure `max_llm_tokens_per_day` is enforced against.
   */
  tokensLast24H: Scalars["Int"]["output"];
};

export type LoginInput = {
  email: Scalars["String"]["input"];
  password: Scalars["String"]["input"];
};

/** Result of a master key rotation operation. */
export type MasterKeyRotationResult = {
  __typename?: "MasterKeyRotationResult";
  /** Human-readable status message. */
  message: Scalars["String"]["output"];
  /** Number of DEKs that were re-encrypted with the new master key. */
  reEncryptedDekCount: Scalars["Int"]["output"];
};

export type McpAgent = {
  __typename?: "McpAgent";
  createdAt: Scalars["String"]["output"];
  id: Scalars["UUID"]["output"];
  lastUsedAt?: Maybe<Scalars["String"]["output"]>;
  name: Scalars["String"]["output"];
};

export type McpAgentCreated = {
  __typename?: "McpAgentCreated";
  agentId: Scalars["UUID"]["output"];
  name: Scalars["String"]["output"];
  role: Scalars["String"]["output"];
  token: Scalars["String"]["output"];
};

/**
 * A single pending fast-vs-LLM divergence awaiting the user's verdict.
 * `features_text` is decrypted email-derived content — same egress
 * surface as the MCP `ml_disagreements` tool, owner-only.
 */
export type MlDisagreement = {
  __typename?: "MlDisagreement";
  /** RFC-3339 timestamp. */
  createdAt: Scalars["String"]["output"];
  exampleKey?: Maybe<Scalars["String"]["output"]>;
  fastConfidence?: Maybe<Scalars["Float"]["output"]>;
  fastLabel?: Maybe<Scalars["String"]["output"]>;
  featuresText: Scalars["String"]["output"];
  id: Scalars["UUID"]["output"];
  /**
   * `divergence` (model disagreed with the LLM) or `low_confidence`
   * (model abstained; the LLM answered).
   */
  kind: Scalars["String"]["output"];
  llmLabel: Scalars["String"]["output"];
};

/**
 * The disagreement feed for one model, plus the lifecycle context the
 * review page shows above the queue.
 */
export type MlDisagreementFeed = {
  __typename?: "MlDisagreementFeed";
  lifecycleState: Scalars["String"]["output"];
  modelId: Scalars["UUID"]["output"];
  pending: Array<MlDisagreement>;
  /**
   * Rolling shadow agreement (fast-vs-LLM, all bands), 0–1, scoped to
   * the CURRENT shadow era — the window rotates on every lifecycle
   * transition, version promotion, or manual reset, so this reads only
   * evidence about the current model/teacher combination. `None` when
   * the era has no observations yet.
   */
  shadowAgreement?: Maybe<Scalars["Float"]["output"]>;
  /**
   * Current shadow era number (increments on each window rotation) —
   * display context for the agreement figure.
   */
  shadowEpoch: Scalars["Int"]["output"];
  shadowObservations: Scalars["Int"]["output"];
  /**
   * The latest teacher-vs-gold audit report (RFC 0011 R3), `ml_models
   * .teacher_audit` passed through verbatim — `null` until
   * `ml_teacher_audit` has run at least once for this model. Polymorphic
   * on `status`: `running` ({done, gold_rows}), `failed` ({error,
   * failed_at}), or `complete` (accuracy/per_class/parse_failed/
   * audited_at/mismatches — see `talos_ml::teacher_audit` for the exact
   * shape). Raw JSON passthrough (like `outputData` elsewhere in this
   * schema) rather than a fully-typed union, since the shape varies by
   * status and this field is read-only / display-only.
   */
  teacherAudit?: Maybe<Scalars["JSON"]["output"]>;
};

/**
 * One model's review summary — enough to render a list with a
 * "needs review" badge and lifecycle status.
 */
export type MlModelSummary = {
  __typename?: "MlModelSummary";
  id: Scalars["UUID"]["output"];
  /** `llm_only` | `shadow` | `hybrid` | `fast_primary`. */
  lifecycleState: Scalars["String"]["output"];
  name: Scalars["String"]["output"];
  /** Count of `pending` disagreements awaiting human review. */
  pendingDisagreements: Scalars["Int"]["output"];
  /** Holdout accuracy of the promoted version (0–1), if promoted. */
  promotedAccuracy?: Maybe<Scalars["Float"]["output"]>;
  promotedVersion?: Maybe<Scalars["Int"]["output"]>;
  taskType: Scalars["String"]["output"];
};

/** Outcome of provisioning a classifier. */
export type MlProvisionResult = {
  __typename?: "MlProvisionResult";
  /** True when a model of this name already existed and was reused. */
  alreadyExisted: Scalars["Boolean"]["output"];
  datasetId: Scalars["UUID"]["output"];
  /**
   * Always `llm_only` for a fresh classifier (it serves via the LLM and
   * distills into a fast model over time).
   */
  lifecycleState: Scalars["String"]["output"];
  /**
   * Set when `allowExternalLlm: false` is not backed by the runtime gate
   * that actually enforces egress — the bound actor's `max_llm_tier`.
   * Show it to the user: the local-only intent is advisory until the
   * actor's tier ceiling is tier1.
   */
  localityWarning?: Maybe<Scalars["String"]["output"]>;
  modelId: Scalars["UUID"]["output"];
  modelName: Scalars["String"]["output"];
};

/** Outcome of resolving one disagreement. */
export type MlResolveResult = {
  __typename?: "MlResolveResult";
  correctionAppended: Scalars["Boolean"]["output"];
  disagreementId: Scalars["UUID"]["output"];
  /** `"resolved"` (a gold correction was appended) or `"dismissed"`. */
  status: Scalars["String"]["output"];
};

export type ModuleExecution = {
  __typename?: "ModuleExecution";
  completedAt?: Maybe<Scalars["String"]["output"]>;
  createdAt: Scalars["String"]["output"];
  durationMs?: Maybe<Scalars["Int"]["output"]>;
  errorMessage?: Maybe<Scalars["String"]["output"]>;
  errorType?: Maybe<Scalars["String"]["output"]>;
  fuelConsumed?: Maybe<Scalars["Int"]["output"]>;
  id: Scalars["UUID"]["output"];
  inputData?: Maybe<Scalars["String"]["output"]>;
  logs: Array<ModuleExecutionLog>;
  memoryUsedMb?: Maybe<Scalars["Int"]["output"]>;
  module?: Maybe<WasmModule>;
  moduleId: Scalars["UUID"]["output"];
  outputData?: Maybe<Scalars["String"]["output"]>;
  startedAt: Scalars["String"]["output"];
  status: Scalars["String"]["output"];
  triggerMetadata?: Maybe<Scalars["String"]["output"]>;
  triggerType: Scalars["String"]["output"];
};

export type ModuleExecutionLog = {
  __typename?: "ModuleExecutionLog";
  createdAt: Scalars["String"]["output"];
  executionId: Scalars["UUID"]["output"];
  id: Scalars["UUID"]["output"];
  level: Scalars["String"]["output"];
  message: Scalars["String"]["output"];
  metadata?: Maybe<Scalars["String"]["output"]>;
};

export type MutationRoot = {
  __typename?: "MutationRoot";
  /**
   * Acknowledge a `new` alert. Returns false when the row doesn't exist,
   * isn't owned, or isn't `new` (guarded transition).
   */
  ackOpsAlert: Scalars["Boolean"]["output"];
  approveExecution: Scalars["Boolean"]["output"];
  /** Clone an actor, copying its semantic and episodic memories into the new actor. */
  cloneActor: ActorSummary;
  /**
   * Record a HUMAN severity correction — the distillation gold signal.
   * Overwrites any classifier label and marks the row corrected. Returns
   * true when a row transitioned (false = not found / not owned). The
   * severity is validated against the assignable vocabulary in the resolver
   * so the caller gets a specific, static message before any DB round-trip.
   */
  correctOpsAlertSeverity: Scalars["Boolean"]["output"];
  createActor: ActorSummary;
  createApiKey: ApiKeyCreated;
  createModuleFromTemplate: WasmModule;
  createOrganization: OrganizationObj;
  createSchedule: WorkflowScheduleObj;
  createSecret: Secret;
  createWebhookTrigger: WebhookTrigger;
  createWorkflow: Workflow;
  /**
   * AI-scaffolded workflow creation from a natural-language
   * description. Backed by the same `WorkflowCreationService`
   * that powers the MCP `create_workflow_from_description` tool —
   * a single source of truth for scaffold semantics across both
   * surfaces.
   *
   * Both success cases (LLM-scaffolded, explicit-modules) and all
   * soft-failure cases (LLM unavailable, LLM rate-limited, etc.)
   * return a populated `CreateWorkflowFromDescriptionResult` —
   * hard failures (DB unavailable, etc.) flow as a GraphQL Error.
   */
  createWorkflowFromDescription: CreateWorkflowFromDescriptionResult;
  /** Delete a memory entry by key for an actor the current user owns. */
  deleteActorMemory: Scalars["Boolean"]["output"];
  deleteApiKey: Scalars["Boolean"]["output"];
  deleteSchedule: Scalars["Boolean"]["output"];
  deleteSecret: Scalars["Boolean"]["output"];
  deleteWorkflow: Scalars["Boolean"]["output"];
  denyExecution: Scalars["Boolean"]["output"];
  disableTwoFactor: Scalars["Boolean"]["output"];
  disconnectServiceIntegration: Scalars["Boolean"]["output"];
  enableTwoFactor: TwoFactorEnrollment;
  generateCode: GenerateCodeResult;
  /**
   * Grant a capability ceiling to a user. Cross-user grants require
   * the designated `users.is_platform_admin` flag (M T6-1) — NOT
   * "admin of any organisation." Self-grants stay open (no-op since
   * you can't exceed your own ceiling). Granter's own ceiling must
   * be >= the world being granted (enforced separately below).
   */
  grantCapabilityCeiling: Scalars["Boolean"]["output"];
  inviteMember: OrgMemberObj;
  login: AuthPayload;
  logout: Scalars["Boolean"]["output"];
  /**
   * Revoke ALL active sessions for the authenticated user across all devices.
   * Use this after a suspected account compromise or when a user wants to
   * sign out everywhere. Clears the current device's cookies as well.
   */
  logoutAllSessions: Scalars["Boolean"]["output"];
  /**
   * Provision (or idempotently reuse) a classifier for a workflow node:
   * creates the dataset + model (born `llm_only`) + a safe default
   * promotion policy under the actor's tenancy in one owner-scoped tx, and
   * returns the model name to stamp into the node. Backed by the SAME
   * `talos_ml::provision_classifier` the MCP tool calls.
   */
  provisionMlClassifier: MlProvisionResult;
  publishWorkflowVersion: WorkflowVersion;
  /**
   * Per-org DEK arc: migrate existing `actor_memory` rows to their actor's
   * org root DEK (format v4). Memory sibling of `reEncryptSecretsToOrg`;
   * rows whose actor has no org stay on the global DEK.
   */
  reEncryptMemoriesToOrg: ReEncryptionResult;
  /**
   * Per-org DEK arc: migrate existing module-execution payloads to their
   * workflow's org root DEK (format v4). Last of the per-org sweeps; org-less
   * / standalone payloads stay on the global DEK.
   */
  reEncryptModulePayloadsToOrg: ReEncryptionResult;
  /**
   * Per-org DEK arc: migrate existing encrypted execution outputs to their
   * workflow's org root DEK (format v4). Execution-output sibling of
   * `reEncryptSecretsToOrg` / `reEncryptMemoriesToOrg`; outputs whose workflow
   * has no org stay on the global DEK.
   */
  reEncryptOutputsToOrg: ReEncryptionResult;
  reEncryptSecrets: ReEncryptionResult;
  /**
   * Per-org DEK arc: migrate existing org-scoped secrets to their org's root
   * DEK (format v4). The complement of `reEncryptSecrets` (which keeps the
   * global-DEK rows current); together they let the global DEK retire for the
   * secrets table. Personal/org-less secrets are intentionally left global.
   */
  reEncryptSecretsToOrg: ReEncryptionResult;
  refreshToken: AuthPayload;
  registerMcpAgent: McpAgentCreated;
  removeMember: Scalars["Boolean"]["output"];
  replayDeadLetterEntry: Scalars["Boolean"]["output"];
  replayWebhookDeadLetterEntry: Scalars["Boolean"]["output"];
  /**
   * Resolve one pending disagreement. `correctLabel` present → append a
   * `source=correction` gold example (built from the disagreement's own
   * stored features; the caller supplies only the label) and mark it
   * resolved. Omitted/blank → dismiss. Counts toward the model's
   * promotion policy.
   */
  resolveMlDisagreement: MlResolveResult;
  /**
   * Resolve a `new`/`acked` alert (operator-sourced). Returns false when
   * nothing matched. A later re-fire still reopens the row via ingest.
   */
  resolveOpsAlert: Scalars["Boolean"]["output"];
  resumeWorkflow: Scalars["Boolean"]["output"];
  retryExecution: Scalars["UUID"]["output"];
  revokeApiKey: Scalars["Boolean"]["output"];
  /**
   * Revoke a user's capability ceiling grant, reverting to the default (http-node).
   * Admins can revoke any grant; users can revoke their own.
   */
  revokeCapabilityCeiling: Scalars["Boolean"]["output"];
  revokeMcpAgent: Scalars["Boolean"]["output"];
  rollbackWorkflowVersion: WorkflowVersion;
  rotateApiKey: ApiKeyCreated;
  rotateDek: DekRotationResult;
  rotateEncryptionKey: Scalars["Int"]["output"];
  rotateMasterKey: MasterKeyRotationResult;
  setConcurrencyLimit: Scalars["Boolean"]["output"];
  /**
   * Bind (or unbind, with a null `actorId`) a workflow's default actor —
   * the tenancy principal its executions run under. Required for a Smart
   * Classifier node: model serving + distillation resolve the model owner
   * from this actor. Mirrors the MCP `set_workflow_actor_id` tool.
   */
  setWorkflowActorId: Scalars["Boolean"]["output"];
  setupTwoFactor: TwoFactorSetup;
  signup: AuthPayload;
  terminateActor: Scalars["Boolean"]["output"];
  testModule: TestModuleResult;
  testWorkflow: TestWorkflowResult;
  transferOwnership: OrganizationObj;
  triggerWorkflow: WorkflowExecution;
  unlinkOauthAccount: Scalars["Boolean"]["output"];
  /**
   * Write (upsert) a memory entry for an actor. Returns the saved entry.
   * Update an actor's name and/or description.
   */
  updateActor: ActorSummary;
  updateActorStatus: ActorSummary;
  updateAuditSettings: UserAuditSettings;
  updateMemberRole: OrgMemberObj;
  updateResourceQuotas: ResourceQuota;
  updateSchedule: WorkflowScheduleObj;
  updateSecret: Secret;
  updateWorkflow: Workflow;
  verifyTwoFactor: AuthPayload;
  writeActorMemory: ActorMemoryEntry;
};

export type MutationRootAckOpsAlertArgs = {
  alertId: Scalars["UUID"]["input"];
};

export type MutationRootApproveExecutionArgs = {
  id: Scalars["UUID"]["input"];
  reason?: InputMaybe<Scalars["String"]["input"]>;
};

export type MutationRootCloneActorArgs = {
  id: Scalars["UUID"]["input"];
  name?: InputMaybe<Scalars["String"]["input"]>;
};

export type MutationRootCorrectOpsAlertSeverityArgs = {
  alertId: Scalars["UUID"]["input"];
  severity: Scalars["String"]["input"];
};

export type MutationRootCreateActorArgs = {
  input: CreateActorInput;
};

export type MutationRootCreateApiKeyArgs = {
  input: CreateApiKeyInput;
};

export type MutationRootCreateModuleFromTemplateArgs = {
  input: CreateModuleInput;
};

export type MutationRootCreateOrganizationArgs = {
  name: Scalars["String"]["input"];
  slug: Scalars["String"]["input"];
};

export type MutationRootCreateScheduleArgs = {
  cronExpression: Scalars["String"]["input"];
  timezone?: InputMaybe<Scalars["String"]["input"]>;
  workflowId: Scalars["UUID"]["input"];
};

export type MutationRootCreateSecretArgs = {
  input: CreateSecretInput;
};

export type MutationRootCreateWebhookTriggerArgs = {
  input: CreateWebhookTriggerInput;
};

export type MutationRootCreateWorkflowArgs = {
  input: CreateWorkflowInput;
};

export type MutationRootCreateWorkflowFromDescriptionArgs = {
  input: CreateWorkflowFromDescriptionInput;
};

export type MutationRootDeleteActorMemoryArgs = {
  actorId: Scalars["UUID"]["input"];
  key: Scalars["String"]["input"];
};

export type MutationRootDeleteApiKeyArgs = {
  keyId: Scalars["UUID"]["input"];
};

export type MutationRootDeleteScheduleArgs = {
  workflowId: Scalars["UUID"]["input"];
};

export type MutationRootDeleteSecretArgs = {
  keyPath: Scalars["String"]["input"];
};

export type MutationRootDeleteWorkflowArgs = {
  id: Scalars["UUID"]["input"];
};

export type MutationRootDenyExecutionArgs = {
  id: Scalars["UUID"]["input"];
  reason?: InputMaybe<Scalars["String"]["input"]>;
};

export type MutationRootDisconnectServiceIntegrationArgs = {
  id: Scalars["UUID"]["input"];
  service: IntegrationService;
};

export type MutationRootEnableTwoFactorArgs = {
  input: Enable2FaInput;
};

export type MutationRootGenerateCodeArgs = {
  input: GenerateCodeInput;
};

export type MutationRootGrantCapabilityCeilingArgs = {
  input: GrantCapabilityCeilingInput;
};

export type MutationRootInviteMemberArgs = {
  orgId: Scalars["UUID"]["input"];
  role: Scalars["String"]["input"];
  targetUserId: Scalars["UUID"]["input"];
};

export type MutationRootLoginArgs = {
  input: LoginInput;
};

export type MutationRootProvisionMlClassifierArgs = {
  actorId: Scalars["UUID"]["input"];
  allowExternalLlm?: InputMaybe<Scalars["Boolean"]["input"]>;
  confidenceThreshold?: InputMaybe<Scalars["Float"]["input"]>;
  fallbackModel?: InputMaybe<Scalars["String"]["input"]>;
  fallbackProvider?: InputMaybe<Scalars["String"]["input"]>;
  k?: InputMaybe<Scalars["Int"]["input"]>;
  labels: Array<Scalars["String"]["input"]>;
  maxExamples?: InputMaybe<Scalars["Int"]["input"]>;
  name: Scalars["String"]["input"];
};

export type MutationRootPublishWorkflowVersionArgs = {
  description?: InputMaybe<Scalars["String"]["input"]>;
  workflowId: Scalars["UUID"]["input"];
};

export type MutationRootRegisterMcpAgentArgs = {
  name: Scalars["String"]["input"];
  roleName: Scalars["String"]["input"];
};

export type MutationRootRemoveMemberArgs = {
  orgId: Scalars["UUID"]["input"];
  targetUserId: Scalars["UUID"]["input"];
};

export type MutationRootReplayDeadLetterEntryArgs = {
  id: Scalars["UUID"]["input"];
};

export type MutationRootReplayWebhookDeadLetterEntryArgs = {
  id: Scalars["UUID"]["input"];
};

export type MutationRootResolveMlDisagreementArgs = {
  correctLabel?: InputMaybe<Scalars["String"]["input"]>;
  disagreementId: Scalars["UUID"]["input"];
};

export type MutationRootResolveOpsAlertArgs = {
  alertId: Scalars["UUID"]["input"];
};

export type MutationRootResumeWorkflowArgs = {
  executionId: Scalars["UUID"]["input"];
};

export type MutationRootRetryExecutionArgs = {
  executionId: Scalars["UUID"]["input"];
};

export type MutationRootRevokeApiKeyArgs = {
  keyId: Scalars["UUID"]["input"];
};

export type MutationRootRevokeCapabilityCeilingArgs = {
  userId: Scalars["UUID"]["input"];
};

export type MutationRootRevokeMcpAgentArgs = {
  id: Scalars["UUID"]["input"];
};

export type MutationRootRollbackWorkflowVersionArgs = {
  versionId: Scalars["UUID"]["input"];
  workflowId: Scalars["UUID"]["input"];
};

export type MutationRootRotateApiKeyArgs = {
  keyId: Scalars["UUID"]["input"];
};

export type MutationRootRotateMasterKeyArgs = {
  newMasterKey: Scalars["String"]["input"];
};

export type MutationRootSetConcurrencyLimitArgs = {
  maxConcurrent?: InputMaybe<Scalars["Int"]["input"]>;
  workflowId: Scalars["UUID"]["input"];
};

export type MutationRootSetWorkflowActorIdArgs = {
  actorId?: InputMaybe<Scalars["UUID"]["input"]>;
  workflowId: Scalars["UUID"]["input"];
};

export type MutationRootSignupArgs = {
  input: SignupInput;
};

export type MutationRootTerminateActorArgs = {
  cleanupWorkflows?: InputMaybe<Scalars["Boolean"]["input"]>;
  id: Scalars["UUID"]["input"];
};

export type MutationRootTestModuleArgs = {
  input?: InputMaybe<Scalars["String"]["input"]>;
  moduleId: Scalars["UUID"]["input"];
  timeoutSecs?: InputMaybe<Scalars["Int"]["input"]>;
};

export type MutationRootTestWorkflowArgs = {
  mockInputs?: InputMaybe<Scalars["String"]["input"]>;
  workflowId: Scalars["UUID"]["input"];
};

export type MutationRootTransferOwnershipArgs = {
  newOwnerId: Scalars["UUID"]["input"];
  orgId: Scalars["UUID"]["input"];
};

export type MutationRootTriggerWorkflowArgs = {
  actorId?: InputMaybe<Scalars["UUID"]["input"]>;
  workflowId: Scalars["UUID"]["input"];
};

export type MutationRootUnlinkOauthAccountArgs = {
  provider: Scalars["String"]["input"];
};

export type MutationRootUpdateActorArgs = {
  description?: InputMaybe<Scalars["String"]["input"]>;
  id: Scalars["UUID"]["input"];
  maxCapabilityWorld?: InputMaybe<Scalars["String"]["input"]>;
  name?: InputMaybe<Scalars["String"]["input"]>;
};

export type MutationRootUpdateActorStatusArgs = {
  id: Scalars["UUID"]["input"];
  status: Scalars["String"]["input"];
};

export type MutationRootUpdateAuditSettingsArgs = {
  authHeaders?: InputMaybe<Scalars["String"]["input"]>;
  otlpEndpoint?: InputMaybe<Scalars["String"]["input"]>;
  otlpProtocol?: InputMaybe<Scalars["String"]["input"]>;
  streamingEnabled: Scalars["Boolean"]["input"];
};

export type MutationRootUpdateMemberRoleArgs = {
  orgId: Scalars["UUID"]["input"];
  role: Scalars["String"]["input"];
  targetUserId: Scalars["UUID"]["input"];
};

export type MutationRootUpdateResourceQuotasArgs = {
  input: UpdateResourceQuotasInput;
};

export type MutationRootUpdateScheduleArgs = {
  cronExpression?: InputMaybe<Scalars["String"]["input"]>;
  isEnabled?: InputMaybe<Scalars["Boolean"]["input"]>;
  timezone?: InputMaybe<Scalars["String"]["input"]>;
  workflowId: Scalars["UUID"]["input"];
};

export type MutationRootUpdateSecretArgs = {
  input: UpdateSecretInput;
};

export type MutationRootUpdateWorkflowArgs = {
  id: Scalars["UUID"]["input"];
  input: CreateWorkflowInput;
};

export type MutationRootVerifyTwoFactorArgs = {
  input: Verify2FaInput;
};

export type MutationRootWriteActorMemoryArgs = {
  input: WriteActorMemoryInput;
};

export type NodeTemplate = {
  __typename?: "NodeTemplate";
  allowedHosts: Array<Scalars["String"]["output"]>;
  /**
   * The WIT capability world this template compiles to (e.g.
   * `"secrets-node"`, `"http-node"`, `"minimal-node"`). Surfaced so a
   * caller can see, BEFORE installing, the minimum actor capability
   * ceiling required to run a module built from this template — instead
   * of discovering it via a ceiling-denial at trigger time. Pair with
   * the `capabilityWorldHierarchy` query for the rank + description.
   */
  capabilityWorld: Scalars["String"]["output"];
  category: Scalars["String"]["output"];
  configSchema: Scalars["String"]["output"];
  description?: Maybe<Scalars["String"]["output"]>;
  icon?: Maybe<Scalars["String"]["output"]>;
  id: Scalars["UUID"]["output"];
  name: Scalars["String"]["output"];
  /**
   * Operation categories that make a module built from this template
   * pause for human approval at run time (e.g. `["network_scan"]`).
   * Empty for templates that never suspend. Surfaced so a suspension
   * isn't a surprise.
   */
  requiresApprovalFor: Array<Scalars["String"]["output"]>;
  /**
   * Vault secret paths (or prefix globs) this template needs granted,
   * e.g. `["oauth/gmail/*"]`. Surfaced so a caller knows what to set up
   * before running rather than hitting a resolution failure.
   */
  requiresSecrets: Array<Scalars["String"]["output"]>;
};

export type OauthAccount = {
  __typename?: "OauthAccount";
  email: Scalars["String"]["output"];
  id: Scalars["UUID"]["output"];
  lastLoginAt?: Maybe<Scalars["String"]["output"]>;
  linkedAt: Scalars["String"]["output"];
  name?: Maybe<Scalars["String"]["output"]>;
  pictureUrl?: Maybe<Scalars["String"]["output"]>;
  provider: Scalars["String"]["output"];
};

export type OauthAuthUrl = {
  __typename?: "OauthAuthUrl";
  authUrl: Scalars["String"]["output"];
  provider: Scalars["String"]["output"];
};

/**
 * One normalized operational alert as surfaced to the triage UI. Field set
 * mirrors [`OpsAlertRow`]; `severity` is the effective label (a human
 * correction overrides the classifier), `correctedSeverity` is set only when
 * a human corrected it (the distillation gold signal).
 */
export type OpsAlert = {
  __typename?: "OpsAlert";
  correctedSeverity?: Maybe<Scalars["String"]["output"]>;
  dedupKey: Scalars["String"]["output"];
  externalId?: Maybe<Scalars["String"]["output"]>;
  firstSeen: Scalars["DateTime"]["output"];
  id: Scalars["UUID"]["output"];
  lastSeen: Scalars["DateTime"]["output"];
  occurrenceCount: Scalars["Int"]["output"];
  /** Set when the alert re-fired AFTER being resolved (regression). */
  reopenedAt?: Maybe<Scalars["DateTime"]["output"]>;
  /** `operator` | `signal`, when resolved. */
  resolvedSource?: Maybe<Scalars["String"]["output"]>;
  resource?: Maybe<Scalars["String"]["output"]>;
  severity: Scalars["String"]["output"];
  severityRaw?: Maybe<Scalars["String"]["output"]>;
  source: Scalars["String"]["output"];
  /** `new` | `acked` | `resolved`. */
  status: Scalars["String"]["output"];
  title: Scalars["String"]["output"];
  triageConfidence?: Maybe<Scalars["Float"]["output"]>;
  /** `heuristic` | `classifier` | `correction`, when triaged. */
  triageSource?: Maybe<Scalars["String"]["output"]>;
};

/** Digest rollup over the active (non-resolved) alert set. */
export type OpsAlertsDigest = {
  __typename?: "OpsAlertsDigest";
  activeBySeverity: Array<SeverityCount>;
  activeBySource: Array<SourceCount>;
  newLast24H: Scalars["Int"]["output"];
  reopenedActive: Scalars["Int"]["output"];
};

/** GraphQL representation of an organization member. */
export type OrgMemberObj = {
  __typename?: "OrgMemberObj";
  id: Scalars["UUID"]["output"];
  invitedBy?: Maybe<Scalars["UUID"]["output"]>;
  joinedAt: Scalars["String"]["output"];
  orgId: Scalars["UUID"]["output"];
  role: Scalars["String"]["output"];
  userId: Scalars["UUID"]["output"];
};

/** GraphQL representation of an organization. */
export type OrganizationObj = {
  __typename?: "OrganizationObj";
  createdAt: Scalars["String"]["output"];
  id: Scalars["UUID"]["output"];
  name: Scalars["String"]["output"];
  ownerId: Scalars["UUID"]["output"];
  slug: Scalars["String"]["output"];
  updatedAt: Scalars["String"]["output"];
};

/** Pagination input for list queries */
export type PaginationInput = {
  /** Maximum number of items to return (default: 100, max: 1000) */
  limit?: InputMaybe<Scalars["Int"]["input"]>;
  /** Number of items to skip (default: 0) */
  offset?: InputMaybe<Scalars["Int"]["input"]>;
};

export type QueryRoot = {
  __typename?: "QueryRoot";
  activeWorkflowVersion?: Maybe<WorkflowVersion>;
  actor?: Maybe<ActorDetails>;
  actorActionLog: Array<ActorActionLogEntry>;
  actorExecutionsSummary: ActorExecutionsSummary;
  /**
   * List non-expired memory entries for an actor the current user owns.
   *
   * MCP-1188 (2026-05-17): `limit` arg added with default 1000 and a
   * hard cap of 1000. Pre-fix the query did `fetch_all` with no
   * LIMIT — a user's actor can hold up to MAX_MEMORIES_PER_ACTOR =
   * 10_000 rows (talos-memory:48), each carrying a decrypted value
   * up to MAX_VALUE_BYTES = 64 KiB → worst-case ~640 MB allocation
   * per request, AND a per-row AES-GCM decrypt. A user with a
   * memory-heavy actor could trash the controller on repeated calls
   * via the dashboard. The MCP sibling `handle_list_actor_memories`
   * has always had a 200-row cap; this query was the holdout.
   */
  actorMemories: Array<ActorMemoryEntry>;
  /**
   * MCP-1189 (2026-05-17): `limit` arg added with default 1000 and
   * hard cap of 1000. Pre-fix the query did `fetch_all` on workflows
   * with NO LIMIT, AND each row carried the full `graph_json` blob
   * (capped at MAX_PAYLOAD_SIZE = 10 MiB per row, talos-api/src/
   * validation.rs:31). Theoretical worst case for a malicious /
   * pathological user who created thousands of workflows linked to
   * one actor: rows × 10 MiB per `graph_json` = tens of GiB
   * allocated on the controller per request. Frontend
   * `getActorWorkflows` (graphqlClient.ts:922) explicitly requests
   * `graphJson` so the full blob comes back per row — caller can't
   * opt out via projection. Sibling fix to MCP-1188 (actor_memories
   * 1000-row cap).
   */
  actorWorkflows: Array<ActorWorkflowItem>;
  actorWorkflowsSummary: ActorWorkflowsSummary;
  actors: Array<ActorSummary>;
  /**
   * Batched sibling of `actorMemories`: one request returns the
   * memories of MANY owned actors, grouped per actor.
   *
   * N+1 this closes: the Briefings page fanned out one
   * `actorMemories(actorId)` GraphQL round-trip PER actor after
   * `actors` (1 + N requests, each opening its own tenant-scoped tx
   * and ownership check). This resolver serves the same data in ONE
   * request: one per-user unit of work, ONE batched ownership read
   * (`actor_ids_owned_by_user_scoped`), then the per-actor listings
   * on the same connection/snapshot. (Collapsing the listings into a
   * single `actor_id = ANY($1)` query needs a batched read in
   * `talos-memory` — actor_memory access MUST go through
   * `talos_memory::*` — tracked as a follow-up; the request-level
   * fan-out and per-request auth/tx overhead are already collapsed
   * here.)
   *
   * Tenancy: ids that are unknown or another tenant's are silently
   * skipped (no group), so absence is indistinguishable from
   * non-existence. Duplicated ids collapse to one group.
   */
  actorsMemories: Array<ActorMemoryGroup>;
  analyzeRhai: AnalyzeCustomModuleResult;
  apiKeys: Array<ApiKeyInfo>;
  auditSettings?: Maybe<UserAuditSettings>;
  /** Get detailed capability ceiling info for the current user. */
  capabilityCeilingDetail: CapabilityCeilingDetail;
  /**
   * List all capability grants. Requires platform admin role.
   *
   * MCP-998 (2026-05-15): closes the QUERY sibling of the M T6-1
   * drift fix that `grant_capability_ceiling` /
   * `revoke_capability_ceiling` already received. Pre-fix this used
   * the same inline `organization_members ... role IN
   * ('owner','admin')` conflation that the mutations were
   * audit-fixed away from — `require_scope(Admin)` session-bypasses,
   * and the inline EXISTS check granted access to ANY user who was
   * owner/admin of ANY organisation (their own tiny tenant counted).
   * Information-disclosure class: the query returns ALL capability
   * grants platform-wide (user_id, email, max_capability_world,
   * granted_by, granted_at, notes — LIMIT 200), so a curious org
   * admin on tenant A could enumerate every elevated user on
   * tenants B/C/D, useful for targeted social engineering or
   * reconnaissance ahead of an attempted privilege escalation.
   * Fix delegates to the canonical `ActorRepository::
   * is_platform_admin` helper that queries the dedicated
   * `users.is_platform_admin` column. Same drift class as
   * r277/r289/r291/r292 that `graphql_must_mirror_mcp_rbac_checks.md`
   * flags — every NEW endpoint that touches cross-tenant data MUST
   * either go through `require_platform_admin` or call
   * `actor_repo.is_platform_admin` after a session check.
   */
  capabilityGrants: Array<CapabilityGrant>;
  /** Return the full capability world hierarchy with ranks and descriptions. */
  capabilityWorldHierarchy: Array<CapabilityWorldInfo>;
  deadLetterQueue: Array<DeadLetterEntry>;
  /**
   * Per-org DEK migration status — per encrypted table, how many rows still
   * reference the global DEK but could be migrated to a per-org DEK (the
   * remaining work for the `reEncrypt…ToOrg` sweeps). When every `pending` is
   * 0, the global DEK is no longer load-bearing for migratable data.
   * Platform-admin only (reveals system-wide counts across all orgs).
   */
  dekMigrationStatus: Array<DekMigrationStatusEntry>;
  getAllWorkflowStats: Array<WorkflowStats>;
  getVersionDiffSummary: VersionDiffSummary;
  getWorkflowChangelog: Array<ChangelogEntry>;
  latestWorkflowExecutions: Array<WorkflowExecution>;
  linkedOauthAccounts: Array<OauthAccount>;
  /**
   * Per-actor LLM token spend (R2 token ledger) — the daily-ceiling
   * usage bar plus a trailing-window per-model/provider breakdown.
   * Read-only visibility surface; mirrors the MCP `get_actor_budget`
   * tool's `current_usage`/`policy` numbers so the two protocol
   * surfaces agree. `days` defaults to 7, clamped 1..=90 by the
   * repository method (mirrors `llm_usage_by_user_window`).
   */
  llmUsageSummary: LlmUsageSummary;
  /**
   * MCP-1190 (2026-05-17): `limit` arg added with default 100 and
   * hard cap of 1000. Pre-fix the query did `fetch_all` on
   * mcp_agents with NO LIMIT — no formal per-user MCP-agent cap
   * exists at registration time, so an admin who accidentally /
   * maliciously creates thousands of agents trashes controller
   * heap on every dashboard `mcpAgents` call. Same unbounded-
   * fetch-all audit class as MCP-1188 / MCP-1189; here per-row
   * size is small (Uuid + name + two timestamps) so the worst-
   * case is dominated by row count rather than per-row weight.
   */
  mcpAgents: Array<McpAgent>;
  me: UserInfo;
  /**
   * Pending disagreements for one model (owner-scoped, decrypted),
   * plus lifecycle + shadow context for the review header.
   */
  mlModelDisagreements: MlDisagreementFeed;
  /**
   * The caller's models, owner-scoped, ordered so the ones with the
   * most pending review float to the top.
   */
  mlModels: Array<MlModelSummary>;
  moduleExecutionHistory: Array<ModuleExecution>;
  moduleExecutionLogs: Array<ModuleExecutionLog>;
  myCapabilityCeiling: Scalars["String"]["output"];
  myModules: Array<WasmModule>;
  myOrganizations: Array<OrganizationObj>;
  mySchedules: Array<WorkflowScheduleObj>;
  nodeTemplate: NodeTemplate;
  nodeTemplates: Array<NodeTemplate>;
  oauthLoginUrl: OauthAuthUrl;
  /**
   * The caller's alerts, owner-scoped, newest activity first. With no
   * explicit `status` the triage default excludes resolved rows; an
   * explicit `status` filter overrides that.
   */
  opsAlerts: Array<OpsAlert>;
  /** Digest rollup over the caller's active alert set. */
  opsAlertsDigest: OpsAlertsDigest;
  organization: OrganizationObj;
  organizationMembers: Array<OrgMemberObj>;
  /**
   * MCP-1190 (2026-05-17): `limit` arg added with default 20 and
   * hard cap of 100, matching the canonical MCP sibling at
   * `handle_list_pending_approvals` (executions.rs:6063) which has
   * enforced 1..=100 since MCP-179. Pre-fix this GraphQL query did
   * `fetch_all` with NO LIMIT — a user with a misconfigured
   * approval workflow accumulating thousands of pending gates would
   * get a huge response on every dashboard `pendingApprovals` call;
   * repeated polls trash controller heap. Same cross-protocol
   * GraphQL-must-mirror-MCP class as MCP-1188/1189.
   */
  pendingApprovals: Array<ExecutionApproval>;
  resourceQuotas: ResourceQuota;
  secret: Secret;
  secretAuditLog: Array<SecretAuditLog>;
  secrets: Array<Secret>;
  serviceIntegrations: Array<ServiceIntegration>;
  testRhaiExpression: TestRhaiExpressionResult;
  /**
   * Verify the cryptographic audit chain for one execution (finding #2,
   * on-demand forensic check). Platform admin only — it reads the WORM
   * audit store across tenants, so it goes through the canonical
   * `is_platform_admin` gate (NOT the org-admin conflation the MCP-998
   * sweep removed). Returns the structured break list (sequence gaps,
   * linkage/genesis mismatch, bad/missing HMAC); the inline ingest check
   * and the continuous sweep cover the always-on side.
   */
  verifyAuditChain: AuditChainVerification;
  wasmModules: Array<WasmModule>;
  webhookDeadLetterQueue: Array<WebhookDlqEntry>;
  webhookTriggers: Array<WebhookTrigger>;
  workflow: Workflow;
  workflowExecutionHistory: Array<WorkflowExecution>;
  workflowSchedule?: Maybe<WorkflowScheduleObj>;
  workflowVersion?: Maybe<WorkflowVersion>;
  workflowVersions: Array<WorkflowVersion>;
  workflows: Array<Workflow>;
};

export type QueryRootActiveWorkflowVersionArgs = {
  workflowId: Scalars["UUID"]["input"];
};

export type QueryRootActorArgs = {
  id: Scalars["UUID"]["input"];
};

export type QueryRootActorActionLogArgs = {
  actorId: Scalars["UUID"]["input"];
  limit?: InputMaybe<Scalars["Int"]["input"]>;
};

export type QueryRootActorExecutionsSummaryArgs = {
  actorId: Scalars["UUID"]["input"];
};

export type QueryRootActorMemoriesArgs = {
  actorId: Scalars["UUID"]["input"];
  limit?: InputMaybe<Scalars["Int"]["input"]>;
  memoryType?: InputMaybe<Scalars["String"]["input"]>;
};

export type QueryRootActorWorkflowsArgs = {
  actorId: Scalars["UUID"]["input"];
  limit?: InputMaybe<Scalars["Int"]["input"]>;
};

export type QueryRootActorWorkflowsSummaryArgs = {
  actorId: Scalars["UUID"]["input"];
};

export type QueryRootActorsMemoriesArgs = {
  actorIds: Array<Scalars["UUID"]["input"]>;
  limitPerActor?: InputMaybe<Scalars["Int"]["input"]>;
  memoryType?: InputMaybe<Scalars["String"]["input"]>;
};

export type QueryRootAnalyzeRhaiArgs = {
  input: AnalyzeRhaiInput;
};

export type QueryRootApiKeysArgs = {
  pagination?: InputMaybe<PaginationInput>;
};

export type QueryRootGetAllWorkflowStatsArgs = {
  days?: InputMaybe<Scalars["Int"]["input"]>;
};

export type QueryRootGetVersionDiffSummaryArgs = {
  workflowId: Scalars["UUID"]["input"];
};

export type QueryRootGetWorkflowChangelogArgs = {
  limit?: InputMaybe<Scalars["Int"]["input"]>;
  workflowId: Scalars["UUID"]["input"];
};

export type QueryRootLatestWorkflowExecutionsArgs = {
  workflowIds: Array<Scalars["UUID"]["input"]>;
};

export type QueryRootLlmUsageSummaryArgs = {
  actorId: Scalars["UUID"]["input"];
  days?: InputMaybe<Scalars["Int"]["input"]>;
};

export type QueryRootMcpAgentsArgs = {
  limit?: InputMaybe<Scalars["Int"]["input"]>;
};

export type QueryRootMlModelDisagreementsArgs = {
  limit?: InputMaybe<Scalars["Int"]["input"]>;
  modelName: Scalars["String"]["input"];
};

export type QueryRootModuleExecutionHistoryArgs = {
  moduleId: Scalars["UUID"]["input"];
  pagination?: InputMaybe<PaginationInput>;
};

export type QueryRootModuleExecutionLogsArgs = {
  executionId: Scalars["UUID"]["input"];
};

export type QueryRootMyModulesArgs = {
  pagination?: InputMaybe<PaginationInput>;
};

export type QueryRootMySchedulesArgs = {
  limit?: InputMaybe<Scalars["Int"]["input"]>;
  offset?: InputMaybe<Scalars["Int"]["input"]>;
};

export type QueryRootNodeTemplateArgs = {
  id: Scalars["UUID"]["input"];
};

export type QueryRootNodeTemplatesArgs = {
  category?: InputMaybe<Scalars["String"]["input"]>;
  pagination?: InputMaybe<PaginationInput>;
};

export type QueryRootOauthLoginUrlArgs = {
  provider: Scalars["String"]["input"];
};

export type QueryRootOpsAlertsArgs = {
  limit?: InputMaybe<Scalars["Int"]["input"]>;
  severity?: InputMaybe<Scalars["String"]["input"]>;
  source?: InputMaybe<Scalars["String"]["input"]>;
  status?: InputMaybe<Scalars["String"]["input"]>;
};

export type QueryRootOrganizationArgs = {
  orgId: Scalars["UUID"]["input"];
};

export type QueryRootOrganizationMembersArgs = {
  orgId: Scalars["UUID"]["input"];
};

export type QueryRootPendingApprovalsArgs = {
  limit?: InputMaybe<Scalars["Int"]["input"]>;
};

export type QueryRootSecretArgs = {
  keyPath: Scalars["String"]["input"];
};

export type QueryRootSecretAuditLogArgs = {
  pagination?: InputMaybe<PaginationInput>;
  secretId: Scalars["UUID"]["input"];
};

export type QueryRootSecretsArgs = {
  pagination?: InputMaybe<PaginationInput>;
};

export type QueryRootTestRhaiExpressionArgs = {
  input: TestRhaiExpressionInput;
};

export type QueryRootVerifyAuditChainArgs = {
  executionId: Scalars["UUID"]["input"];
};

export type QueryRootWasmModulesArgs = {
  ids: Array<Scalars["UUID"]["input"]>;
};

export type QueryRootWebhookTriggersArgs = {
  pagination?: InputMaybe<PaginationInput>;
};

export type QueryRootWorkflowArgs = {
  id: Scalars["UUID"]["input"];
};

export type QueryRootWorkflowExecutionHistoryArgs = {
  pagination?: InputMaybe<PaginationInput>;
  workflowId: Scalars["UUID"]["input"];
};

export type QueryRootWorkflowScheduleArgs = {
  workflowId: Scalars["UUID"]["input"];
};

export type QueryRootWorkflowVersionArgs = {
  id: Scalars["UUID"]["input"];
};

export type QueryRootWorkflowVersionsArgs = {
  limit?: InputMaybe<Scalars["Int"]["input"]>;
  offset?: InputMaybe<Scalars["Int"]["input"]>;
  workflowId: Scalars["UUID"]["input"];
};

export type QueryRootWorkflowsArgs = {
  pagination?: InputMaybe<PaginationInput>;
};

/** Result of a re-encryption operation. */
export type ReEncryptionResult = {
  __typename?: "ReEncryptionResult";
  /**
   * L T2-6: number of secrets that failed to re-encrypt (decrypt
   * error, cipher init failure, UPDATE failure). Operators MUST
   * inspect this field — a non-zero value means some secrets are
   * still wrapped with a non-active DEK and may become un-decryptable
   * if the source DEK is purged. Re-run after fixing the root cause.
   */
  failedCount: Scalars["Int"]["output"];
  /**
   * L T2-6: secret IDs that failed (capped at 100). Empty when
   * `failed_count == 0`. The full list appears in server-side logs.
   */
  failedIds: Array<Scalars["UUID"]["output"]>;
  /** Human-readable status message. */
  message: Scalars["String"]["output"];
  /** Number of secrets that were re-encrypted with the new active DEK. */
  reEncryptedCount: Scalars["Int"]["output"];
};

/** Resource quotas for an organization. */
export type ResourceQuota = {
  __typename?: "ResourceQuota";
  activeExecutions: Scalars["Int"]["output"];
  concurrentExecutions: Scalars["Int"]["output"];
  cpuCores: Scalars["Int"]["output"];
  memoryGb: Scalars["Int"]["output"];
  storageGb: Scalars["Int"]["output"];
  usedCpu: Scalars["Int"]["output"];
  usedMemory: Scalars["Int"]["output"];
  usedStorage: Scalars["Int"]["output"];
};

export type Secret = {
  __typename?: "Secret";
  accessCount: Scalars["Int"]["output"];
  createdAt: Scalars["String"]["output"];
  description?: Maybe<Scalars["String"]["output"]>;
  expiresAt?: Maybe<Scalars["String"]["output"]>;
  id: Scalars["UUID"]["output"];
  keyPath: Scalars["String"]["output"];
  lastAccessedAt?: Maybe<Scalars["String"]["output"]>;
  name: Scalars["String"]["output"];
};

export type SecretAuditLog = {
  __typename?: "SecretAuditLog";
  action: Scalars["String"]["output"];
  actorType: Scalars["String"]["output"];
  errorMessage?: Maybe<Scalars["String"]["output"]>;
  id: Scalars["UUID"]["output"];
  success: Scalars["Boolean"]["output"];
  timestamp: Scalars["String"]["output"];
};

export type ServiceIntegration = {
  __typename?: "ServiceIntegration";
  accountIdentifier: Scalars["String"]["output"];
  connectedAt: Scalars["String"]["output"];
  id: Scalars["UUID"]["output"];
  service: IntegrationService;
  status: Scalars["String"]["output"];
};

/** `(severity, count)` over the active set. */
export type SeverityCount = {
  __typename?: "SeverityCount";
  count: Scalars["Int"]["output"];
  severity: Scalars["String"]["output"];
};

export type SignupInput = {
  email: Scalars["String"]["input"];
  name?: InputMaybe<Scalars["String"]["input"]>;
  password: Scalars["String"]["input"];
};

/** `(source, count)` over the active set. */
export type SourceCount = {
  __typename?: "SourceCount";
  count: Scalars["Int"]["output"];
  source: Scalars["String"]["output"];
};

export type SubscriptionRoot = {
  __typename?: "SubscriptionRoot";
  /**
   * Real-time stream of compilation progress events.
   *
   * Subscribes to the global compilation event broadcast and filters by user ID.
   */
  compilationUpdates: CompilationEvent;
  /**
   * Real-time stream of dead-letter queue entries.
   *
   * M T6-1 visibility model:
   * * Platform admins (`users.is_platform_admin = TRUE`) see every
   * event regardless of ownership.
   * * Regular users see events for workflows they own
   * (`event.user_id == subscriber`) AND events for workflows in
   * any organisation they're a member of (`event.org_id IN
   * subscriber's orgs`).
   * * Events with both `user_id` and `org_id` NULL (orphan trigger
   * whose workflow was deleted) are platform-admin-only — the
   * ownership chain is gone, so no non-admin user can prove
   * they owned the underlying workflow.
   *
   * `DlqEvent.payload` is the raw trigger body (DLP-scrubbed at
   * persistence time but still tenant-scoped); the per-tenant
   * filter is what allows non-admin users to subscribe at all.
   */
  dlqUpdates: DlqEvent;
  /**
   * Real‑time updates for a specific execution ID.
   *
   * SECURITY: Authorization is enforced - users can only subscribe to their own executions.
   * Events are replayed from the database before streaming new events, ensuring no events are lost.
   */
  executionUpdates: ExecutionEvent;
  /**
   * Stream LLM completion tokens as they are generated.
   *
   * Subscribes to a NATS topic for the given execution and streams
   * partial text chunks as they arrive from the worker. The worker
   * publishes chunks to `talos.llm.stream.{execution_id}`.
   */
  llmStream: Scalars["String"]["output"];
  /**
   * Real-time notifications when any workflow execution status changes (started, completed, failed).
   *
   * Powers the global dashboard "recent executions" list without polling.
   */
  workflowExecutionUpdates: WorkflowExecutionEvent;
};

export type SubscriptionRootExecutionUpdatesArgs = {
  executionId: Scalars["UUID"]["input"];
};

export type SubscriptionRootLlmStreamArgs = {
  executionId: Scalars["UUID"]["input"];
};

/** Result of testing a module in isolation. */
export type TestModuleResult = {
  __typename?: "TestModuleResult";
  durationMs: Scalars["Int"]["output"];
  error?: Maybe<Scalars["String"]["output"]>;
  output?: Maybe<Scalars["String"]["output"]>;
  success: Scalars["Boolean"]["output"];
};

export type TestNodeTrace = {
  __typename?: "TestNodeTrace";
  /** Error message if the node failed. */
  error?: Maybe<Scalars["String"]["output"]>;
  /** The input JSON that was fed to this node. */
  input: Scalars["String"]["output"];
  /** The node UUID. */
  nodeId: Scalars["UUID"]["output"];
  /** The output JSON produced by this node (null if skipped/failed). */
  output?: Maybe<Scalars["String"]["output"]>;
  /** "completed", "failed", or "skipped". */
  status: Scalars["String"]["output"];
};

export type TestRhaiExpressionInput = {
  mockContext: Scalars["String"]["input"];
  script: Scalars["String"]["input"];
};

export type TestRhaiExpressionResult = {
  __typename?: "TestRhaiExpressionResult";
  error?: Maybe<Scalars["String"]["output"]>;
  output?: Maybe<Scalars["String"]["output"]>;
  success: Scalars["Boolean"]["output"];
};

/** Result of a testWorkflow dry-run execution. */
export type TestWorkflowResult = {
  __typename?: "TestWorkflowResult";
  /** Total duration in milliseconds. */
  durationMs: Scalars["Int"]["output"];
  /** Error message if the workflow failed overall. */
  error?: Maybe<Scalars["String"]["output"]>;
  /** The temporary execution ID (not persisted long-term). */
  executionId: Scalars["UUID"]["output"];
  /** Per-node execution trace. */
  nodeTraces: Array<TestNodeTrace>;
  /** Edge schema validation warnings (if any). */
  schemaWarnings: Array<Scalars["String"]["output"]>;
  /** Overall status: "completed" or "failed". */
  status: Scalars["String"]["output"];
};

export type TwoFactorEnrollment = {
  __typename?: "TwoFactorEnrollment";
  backupCodes: Array<Scalars["String"]["output"]>;
};

export type TwoFactorSetup = {
  __typename?: "TwoFactorSetup";
  qrCodePng: Scalars["String"]["output"];
  qrCodeUrl: Scalars["String"]["output"];
  secret: Scalars["String"]["output"];
};

/** Input for updating organization resource quotas. */
export type UpdateResourceQuotasInput = {
  concurrentExecutions?: InputMaybe<Scalars["Int"]["input"]>;
  cpuCores?: InputMaybe<Scalars["Int"]["input"]>;
  memoryGb?: InputMaybe<Scalars["Int"]["input"]>;
  storageGb?: InputMaybe<Scalars["Int"]["input"]>;
};

export type UpdateSecretInput = {
  keyPath: Scalars["String"]["input"];
  value: Scalars["String"]["input"];
};

export type UserAuditSettings = {
  __typename?: "UserAuditSettings";
  createdAt: Scalars["String"]["output"];
  otlpEndpoint?: Maybe<Scalars["String"]["output"]>;
  otlpProtocol?: Maybe<Scalars["String"]["output"]>;
  streamingEnabled: Scalars["Boolean"]["output"];
  updatedAt: Scalars["String"]["output"];
};

export type UserInfo = {
  __typename?: "UserInfo";
  createdAt: Scalars["String"]["output"];
  email: Scalars["String"]["output"];
  id: Scalars["UUID"]["output"];
  isTwoFactorVerified: Scalars["Boolean"]["output"];
  name?: Maybe<Scalars["String"]["output"]>;
  twoFactorEnabled: Scalars["Boolean"]["output"];
};

export type Verify2FaInput = {
  code: Scalars["String"]["input"];
};

/** Summary of differences between the current draft and the last published version. */
export type VersionDiffSummary = {
  __typename?: "VersionDiffSummary";
  edgesAdded: Scalars["Int"]["output"];
  edgesRemoved: Scalars["Int"]["output"];
  hasPublishedVersion: Scalars["Boolean"]["output"];
  nodesAdded: Scalars["Int"]["output"];
  nodesChanged: Scalars["Int"]["output"];
  nodesRemoved: Scalars["Int"]["output"];
  summary: Scalars["String"]["output"];
};

export type WasmModule = {
  __typename?: "WasmModule";
  capabilityDescription?: Maybe<Scalars["String"]["output"]>;
  capabilityWorld?: Maybe<Scalars["String"]["output"]>;
  /**
   * Origin catalog template slug (e.g. "smart-classifier"); stable under
   * display-name renames. None for sandbox/extracted modules.
   */
  catalogSlug?: Maybe<Scalars["String"]["output"]>;
  compiledAt: Scalars["String"]["output"];
  config: Scalars["String"]["output"];
  /**
   * JSON string of the module's declared config schema (talos.json
   * `config_schema`), when the module declares one. The editor uses the
   * schema's REQUIRED KEYS as a rename-stable module identity.
   */
  configSchema?: Maybe<Scalars["String"]["output"]>;
  contentHash: Scalars["String"]["output"];
  id: Scalars["UUID"]["output"];
  importedInterfaces?: Maybe<Array<Scalars["String"]["output"]>>;
  /** Source language: "rust", "javascript", or "typescript". Defaults to "rust". */
  language?: Maybe<Scalars["String"]["output"]>;
  name: Scalars["String"]["output"];
  sizeBytes: Scalars["Int"]["output"];
  sourceCode?: Maybe<Scalars["String"]["output"]>;
};

/** A webhook payload that was dropped (e.g. circuit breaker) and persisted for replay. */
export type WebhookDlqEntry = {
  __typename?: "WebhookDlqEntry";
  createdAt: Scalars["String"]["output"];
  /** Reason the original request was dropped: 'circuit_breaker' | 'rate_limit' | 'sig_invalid' | 'disabled' */
  dropReason: Scalars["String"]["output"];
  /** DLP-scrubbed request headers (auth headers stripped). */
  headers?: Maybe<Scalars["String"]["output"]>;
  id: Scalars["UUID"]["output"];
  /** DLP-scrubbed request payload. */
  payload?: Maybe<Scalars["String"]["output"]>;
  replayedAt?: Maybe<Scalars["String"]["output"]>;
  replayedBy?: Maybe<Scalars["UUID"]["output"]>;
  sourceIp?: Maybe<Scalars["String"]["output"]>;
  triggerId?: Maybe<Scalars["UUID"]["output"]>;
};

export type WebhookTrigger = {
  __typename?: "WebhookTrigger";
  enabled: Scalars["Boolean"]["output"];
  errorCount: Scalars["Int"]["output"];
  /**
   * RFC 0007: the trigger's event filter, if any (null = fire on every
   * verified delivery). Read-only; set via `createWebhookTrigger`.
   */
  eventFilter?: Maybe<Scalars["JSON"]["output"]>;
  id: Scalars["UUID"]["output"];
  lastTriggeredAt?: Maybe<Scalars["String"]["output"]>;
  maxRequestsPerMinute: Scalars["Int"]["output"];
  module?: Maybe<WasmModule>;
  name: Scalars["String"]["output"];
  successCount: Scalars["Int"]["output"];
  triggerCount: Scalars["Int"]["output"];
  verificationToken?: Maybe<Scalars["String"]["output"]>;
  webhookUrl: Scalars["String"]["output"];
};

export type Workflow = {
  __typename?: "Workflow";
  /** Actor that owns this workflow, if any. */
  actorId?: Maybe<Scalars["UUID"]["output"]>;
  /**
   * Display name of the owning actor (null when unbound, or when the
   * actor belongs to another user). Batched via [`ActorNameLoader`].
   */
  actorName?: Maybe<Scalars["String"]["output"]>;
  /** Serialized representation of the graph (flexible JSON). */
  graphJson: Scalars["String"]["output"];
  id: Scalars["UUID"]["output"];
  /** Optional structured intent metadata. */
  intent?: Maybe<Scalars["JSON"]["output"]>;
  /**
   * Most recent execution of this workflow (null when never run or
   * not visible to the caller). Batched via [`LatestExecutionLoader`]
   * with the same user/org predicate as `latestWorkflowExecutions`.
   */
  latestExecution?: Maybe<WorkflowExecution>;
  /** Maximum number of concurrent executions allowed (null = unlimited). */
  maxConcurrentExecutions?: Maybe<Scalars["Int"]["output"]>;
  name: Scalars["String"]["output"];
};

export type WorkflowExecution = {
  __typename?: "WorkflowExecution";
  /** Actor that dispatched this execution, if any. */
  actorId?: Maybe<Scalars["UUID"]["output"]>;
  /**
   * Display name of the actor that dispatched this execution (null for
   * non-actor executions). Batched via [`ActorNameLoader`].
   */
  actorName?: Maybe<Scalars["String"]["output"]>;
  completedAt?: Maybe<Scalars["String"]["output"]>;
  createdAt: Scalars["String"]["output"];
  durationMs?: Maybe<Scalars["Int"]["output"]>;
  errorMessage?: Maybe<Scalars["String"]["output"]>;
  id: Scalars["UUID"]["output"];
  outputData?: Maybe<Scalars["JSON"]["output"]>;
  startedAt: Scalars["String"]["output"];
  status: Scalars["String"]["output"];
  /** How the execution was triggered: "manual", "scheduled", "webhook", "actor_dispatch", etc. */
  triggerType?: Maybe<Scalars["String"]["output"]>;
  workflowId: Scalars["UUID"]["output"];
  /**
   * Display name of the executed workflow (null when owned by another
   * user). Batched via [`WorkflowNameLoader`].
   */
  workflowName?: Maybe<Scalars["String"]["output"]>;
};

export type WorkflowExecutionEvent = {
  __typename?: "WorkflowExecutionEvent";
  errorMessage?: Maybe<Scalars["String"]["output"]>;
  executionId: Scalars["UUID"]["output"];
  startedAt: Scalars["String"]["output"];
  status: Scalars["String"]["output"];
  userId: Scalars["UUID"]["output"];
  workflowId: Scalars["UUID"]["output"];
};

export type WorkflowScheduleObj = {
  __typename?: "WorkflowScheduleObj";
  createdAt: Scalars["String"]["output"];
  cronExpression: Scalars["String"]["output"];
  id: Scalars["UUID"]["output"];
  isEnabled: Scalars["Boolean"]["output"];
  lastTriggeredAt?: Maybe<Scalars["String"]["output"]>;
  nextTriggerAt?: Maybe<Scalars["String"]["output"]>;
  timezone: Scalars["String"]["output"];
  updatedAt: Scalars["String"]["output"];
  workflowId: Scalars["UUID"]["output"];
  /**
   * Display name of the scheduled workflow (null when the workflow is
   * owned by another user). Batched via [`WorkflowNameLoader`] — the
   * per-row alternative is a point query per schedule row.
   */
  workflowName?: Maybe<Scalars["String"]["output"]>;
};

/**
 * A single node's trace during a test workflow execution.
 * Aggregated per-workflow stats for the dashboard.
 */
export type WorkflowStats = {
  __typename?: "WorkflowStats";
  avgDurationSecs?: Maybe<Scalars["Float"]["output"]>;
  failed: Scalars["Int"]["output"];
  id: Scalars["UUID"]["output"];
  name: Scalars["String"]["output"];
  succeeded: Scalars["Int"]["output"];
  total: Scalars["Int"]["output"];
};

/** A published, immutable snapshot of a workflow graph. */
export type WorkflowVersion = {
  __typename?: "WorkflowVersion";
  createdAt: Scalars["String"]["output"];
  description?: Maybe<Scalars["String"]["output"]>;
  graphJson: Scalars["String"]["output"];
  id: Scalars["UUID"]["output"];
  isActive: Scalars["Boolean"]["output"];
  publishedAt: Scalars["String"]["output"];
  publishedBy: Scalars["UUID"]["output"];
  versionNumber: Scalars["Int"]["output"];
  workflowId: Scalars["UUID"]["output"];
};

export type WriteActorMemoryInput = {
  actorId: Scalars["UUID"]["input"];
  key: Scalars["String"]["input"];
  /** "working" | "episodic" | "semantic" | "scratchpad". Default: "working". */
  memoryType?: InputMaybe<Scalars["String"]["input"]>;
  /** Custom TTL in hours. Overrides memory_type default. Null = use type default. */
  ttlHours?: InputMaybe<Scalars["Float"]["input"]>;
  /** JSON value to store. */
  value: Scalars["String"]["input"];
};
