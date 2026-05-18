import {
  useQuery,
  useMutation,
  UseQueryOptions,
  UseMutationOptions,
} from "@tanstack/react-query";
import { graphqlFetcher } from "@/lib/graphqlClient";
export type Maybe<T> = T | null;
export type InputMaybe<T> = Maybe<T>;
export type Exact<T extends { [key: string]: unknown }> = {
  [K in keyof T]: T[K];
};
export type MakeOptional<T, K extends keyof T> = Omit<T, K> & {
  [SubKey in K]?: Maybe<T[SubKey]>;
};
export type MakeMaybe<T, K extends keyof T> = Omit<T, K> & {
  [SubKey in K]: Maybe<T[SubKey]>;
};
export type MakeEmpty<
  T extends { [key: string]: unknown },
  K extends keyof T,
> = { [_ in K]?: never };
export type Incremental<T> =
  | T
  | {
      [P in keyof T]?: P extends " $fragmentName" | "__typename" ? T[P] : never;
    };
/** All built-in and custom scalars, mapped to their actual values */
export type Scalars = {
  ID: { input: string; output: string };
  String: { input: string; output: string };
  Boolean: { input: boolean; output: boolean };
  Int: { input: number; output: number };
  Float: { input: number; output: number };
  JSON: { input: unknown; output: unknown };
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

export type AuthPayload = {
  __typename?: "AuthPayload";
  user: UserInfo;
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
  maxRequestsPerMinute?: InputMaybe<Scalars["Int"]["input"]>;
  moduleId: Scalars["UUID"]["input"];
  name: Scalars["String"]["input"];
  signingSecret?: InputMaybe<Scalars["String"]["input"]>;
  verificationToken?: InputMaybe<Scalars["String"]["input"]>;
};

export type CreateWorkflowInput = {
  graphJson: Scalars["String"]["input"];
  name: Scalars["String"]["input"];
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

/** Result of a DEK rotation operation. */
export type DekRotationResult = {
  __typename?: "DekRotationResult";
  /** Human-readable status message. */
  message: Scalars["String"]["output"];
  /** The UUID of the newly created DEK. */
  newDekId: Scalars["UUID"]["output"];
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
};

export type ExecutionEvent = {
  __typename?: "ExecutionEvent";
  executionId: Scalars["UUID"]["output"];
  iterationIndex?: Maybe<Scalars["Int"]["output"]>;
  iterationTotal?: Maybe<Scalars["Int"]["output"]>;
  logMessage?: Maybe<Scalars["String"]["output"]>;
  nodeId?: Maybe<Scalars["UUID"]["output"]>;
  spanId?: Maybe<Scalars["String"]["output"]>;
  status: ExecutionStatus;
  traceId?: Maybe<Scalars["String"]["output"]>;
};

export enum ExecutionStatus {
  Completed = "COMPLETED",
  Failed = "FAILED",
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

export type McpAgentCreated = {
  __typename?: "McpAgentCreated";
  agentId: Scalars["UUID"]["output"];
  name: Scalars["String"]["output"];
  role: Scalars["String"]["output"];
  /** Bearer token — shown only once! Store in Claude Desktop config. */
  token: Scalars["String"]["output"];
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
  /** Approves a pending module execution. */
  approveExecution: Scalars["Boolean"]["output"];
  /** Create a new runtime actor */
  createActor: ActorSummary;
  /** Create a new API key */
  createApiKey: ApiKeyCreated;
  /** Create node from template */
  createModuleFromTemplate: WasmModule;
  /** Create a new organization. The caller becomes the owner. */
  createOrganization: OrganizationObj;
  /** Create or replace a cron schedule for a workflow. */
  createSchedule: WorkflowScheduleObj;
  /** Create a secret */
  createSecret: Secret;
  /** Create a webhook listener */
  createWebhookTrigger: WebhookTrigger;
  /** Create or update a workflow */
  createWorkflow: Workflow;
  /** Delete an API key permanently */
  deleteApiKey: Scalars["Boolean"]["output"];
  /** Delete a workflow schedule. */
  deleteSchedule: Scalars["Boolean"]["output"];
  /** Delete a secret - requires ownership or org membership */
  deleteSecret: Scalars["Boolean"]["output"];
  /** Delete a workflow */
  deleteWorkflow: Scalars["Boolean"]["output"];
  /** Denies a pending module execution. */
  denyExecution: Scalars["Boolean"]["output"];
  /** Disable 2FA */
  disableTwoFactor: Scalars["Boolean"]["output"];
  /** Enable 2FA - verify code and get backup codes */
  enableTwoFactor: TwoFactorEnrollment;
  /** Generate or modify code using AI */
  generateCode: GenerateCodeResult;
  /** Invite a member to an organization. Requires Admin+ role. */
  inviteMember: OrgMemberObj;
  /** Login with email and password */
  login: AuthPayload;
  /** Logout (revoke refresh token from httpOnly cookie) */
  logout: Scalars["Boolean"]["output"];
  /** Publish the current draft workflow as a new immutable version. */
  publishWorkflowVersion: WorkflowVersion;
  /**
   * Re-encrypt all secrets that are still using an inactive DEK.
   *
   * After rotating the DEK, some secrets may still be encrypted with the
   * old key. This mutation decrypts them with the old key and re-encrypts
   * them with the current active DEK.
   */
  reEncryptSecrets: ReEncryptionResult;
  /** Refresh access token using refresh token from httpOnly cookie */
  refreshToken: AuthPayload;
  registerMcpAgent: McpAgentCreated;
  /**
   * Remove a member from an organization. Requires Admin+ role.
   * Cannot remove the last owner.
   */
  removeMember: Scalars["Boolean"]["output"];
  /** Replays a node execution from the Dead Letter Queue. */
  replayDeadLetterEntry: Scalars["Boolean"]["output"];
  /**
   * Replay a dropped webhook payload from the dead-letter queue.
   * Re-dispatches the original payload to the webhook handler and marks the entry replayed.
   */
  replayWebhookDeadLetterEntry: Scalars["Boolean"]["output"];
  /** Resume execution of a workflow that is paused at a 'Wait' node. */
  resumeWorkflow: Scalars["Boolean"]["output"];
  /**
   * Retry a failed or cancelled execution by resetting its status and re-running it.
   * Unlike replay, this updates the SAME execution record.
   */
  retryExecution: Scalars["UUID"]["output"];
  /** Revoke an API key */
  revokeApiKey: Scalars["Boolean"]["output"];
  /**
   * Rollback a workflow to a previously published version.
   * Creates a new version with the same graph_json as the target version.
   */
  rollbackWorkflowVersion: WorkflowVersion;
  /** Rotate an API key (creates new key, deactivates old one) */
  rotateApiKey: ApiKeyCreated;
  /**
   * Rotate the Data Encryption Key (DEK) used for envelope encryption.
   *
   * Creates a new DEK and marks all previous DEKs as inactive. Existing
   * secrets can still be decrypted (old DEKs stay in the database), but
   * new secrets will use the new DEK. Call `reEncryptSecrets` afterwards
   * to migrate old secrets to the new key.
   */
  rotateDek: DekRotationResult;
  /**
   * Rotate the data-encryption key (DEK) version.
   *
   * Creates a new DEK version, marks existing keys for expiry in 30 days,
   * and logs a rotation event. Requires the `Admin` API key scope.
   *
   * Returns the new key version number.
   */
  rotateEncryptionKey: Scalars["Int"]["output"];
  /**
   * Rotate the master key used for envelope encryption.
   *
   * Re-encrypts all DEKs in the `encryption_keys` table with the new master
   * key. The new key must be provided as a 64-character hex string (32 bytes).
   * After rotation, update the `TALOS_MASTER_KEY` environment variable to the
   * new value before restarting the controller.
   */
  rotateMasterKey: MasterKeyRotationResult;
  /**
   * Set or clear the concurrency limit for a workflow.
   * Pass `max_concurrent` between 1 and 100 to set, or null to clear.
   */
  setConcurrencyLimit: Scalars["Boolean"]["output"];
  /** Initiate 2FA setup - generates secret and QR code */
  setupTwoFactor: TwoFactorSetup;
  /** Sign up a new user */
  signup: AuthPayload;
  /** Terminate an actor */
  terminateActor: Scalars["Boolean"]["output"];
  /** Test a module in isolation by executing it directly with optional input. */
  testModule: TestModuleResult;
  /**
   * Dry-run a workflow with mock inputs. The execution is not persisted to
   * the main workflow_executions table (it is marked `is_test_execution=true`
   * and cleaned up aggressively). Returns the full execution trace.
   */
  testWorkflow: TestWorkflowResult;
  /** Transfer organization ownership to another member. Requires Owner role. */
  transferOwnership: OrganizationObj;
  /** Trigger execution of a workflow. Returns an execution object. */
  triggerWorkflow: WorkflowExecution;
  /** Unlink OAuth account */
  unlinkOauthAccount: Scalars["Boolean"]["output"];
  /** Update an actor's status */
  updateActorStatus: ActorSummary;
  /**
   * Register a new MCP agent and return its bearer token.
   *
   * The token is shown only once — store it in Claude Desktop's config.
   * Requires admin scope.
   */
  updateAuditSettings: UserAuditSettings;
  /** Update a member's role. Requires Admin+ role. */
  updateMemberRole: OrgMemberObj;
  /** Updates resource quotas for the user's organization. */
  updateResourceQuotas: ResourceQuota;
  /** Update an existing workflow schedule. */
  updateSchedule: WorkflowScheduleObj;
  /** Update a secret (rotation) - requires ownership or org membership */
  updateSecret: Secret;
  /** Update an existing workflow */
  updateWorkflow: Workflow;
  /** Verify 2FA code (used during login after password verification) */
  verifyTwoFactor: AuthPayload;
};

export type MutationRootApproveExecutionArgs = {
  id: Scalars["UUID"]["input"];
  reason?: InputMaybe<Scalars["String"]["input"]>;
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

export type MutationRootEnableTwoFactorArgs = {
  input: Enable2FaInput;
};

export type MutationRootGenerateCodeArgs = {
  input: GenerateCodeInput;
};

export type MutationRootInviteMemberArgs = {
  orgId: Scalars["UUID"]["input"];
  role: Scalars["String"]["input"];
  targetUserId: Scalars["UUID"]["input"];
};

export type MutationRootLoginArgs = {
  input: LoginInput;
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

export type MutationRootResumeWorkflowArgs = {
  executionId: Scalars["UUID"]["input"];
};

export type MutationRootRetryExecutionArgs = {
  executionId: Scalars["UUID"]["input"];
};

export type MutationRootRevokeApiKeyArgs = {
  keyId: Scalars["UUID"]["input"];
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
  workflowId: Scalars["UUID"]["input"];
};

export type MutationRootUnlinkOauthAccountArgs = {
  provider: Scalars["String"]["input"];
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

export type NodeTemplate = {
  __typename?: "NodeTemplate";
  allowedHosts: Array<Scalars["String"]["output"]>;
  category: Scalars["String"]["output"];
  configSchema: Scalars["String"]["output"];
  description?: Maybe<Scalars["String"]["output"]>;
  icon?: Maybe<Scalars["String"]["output"]>;
  id: Scalars["UUID"]["output"];
  name: Scalars["String"]["output"];
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
  /** Get the currently active published version of a workflow. */
  activeWorkflowVersion?: Maybe<WorkflowVersion>;
  actor?: Maybe<ActorDetails>;
  actorActionLog: Array<ActorActionLogEntry>;
  actorExecutionsSummary: ActorExecutionsSummary;
  actorWorkflows: Array<ActorWorkflowItem>;
  actorWorkflowsSummary: ActorWorkflowsSummary;
  actors: Array<ActorSummary>;
  /** Analyze Rhai script syntax */
  analyzeRhai: AnalyzeCustomModuleResult;
  /** List API keys for current user with pagination */
  apiKeys: Array<ApiKeyInfo>;
  auditSettings?: Maybe<UserAuditSettings>;
  /** Returns node DLQ entries for workflows owned by the current user. */
  deadLetterQueue: Array<DeadLetterEntry>;
  /**
   * Aggregate dashboard stats across all workflows for the current user.
   * Returns the top 50 most active workflows sorted by failure count, then total.
   */
  getAllWorkflowStats: Array<WorkflowStats>;
  /**
   * Quick diff between the current draft and the last published version.
   * Returns a human-readable summary without requiring version numbers.
   */
  getVersionDiffSummary: VersionDiffSummary;
  /**
   * Human-readable changelog from version history.
   * Shows diffs between consecutive versions.
   */
  getWorkflowChangelog: Array<ChangelogEntry>;
  /** Get the latest execution for a list of workflows */
  latestWorkflowExecutions: Array<WorkflowExecution>;
  /** List linked OAuth accounts for current user */
  linkedOauthAccounts: Array<OauthAccount>;
  /** Get current authenticated user */
  me: UserInfo;
  /** Get execution history for a module */
  moduleExecutionHistory: Array<ModuleExecution>;
  /** Get logs for a specific module execution */
  moduleExecutionLogs: Array<ModuleExecutionLog>;
  /**
   * Returns the capability world ceiling for the current user.
   * Defaults to 'http-node' if no explicit grant exists.
   */
  myCapabilityCeiling: Scalars["String"]["output"];
  /** List all compiled WASM modules for current user */
  myModules: Array<WasmModule>;
  /** List all organizations the current user belongs to. */
  myOrganizations: Array<OrganizationObj>;
  /** List all schedules for the current user. */
  mySchedules: Array<WorkflowScheduleObj>;
  /** Get single template by ID */
  nodeTemplate: NodeTemplate;
  /** List available node templates with pagination */
  nodeTemplates: Array<NodeTemplate>;
  /** Get OAuth login URL for a provider */
  oauthLoginUrl: OauthAuthUrl;
  /** Get a single organization by ID. The caller must be a member. */
  organization: OrganizationObj;
  /** List all members of an organization. The caller must be a member. */
  organizationMembers: Array<OrgMemberObj>;
  /** Returns pending authorization requests for workflows owned by the current user. */
  pendingApprovals: Array<ExecutionApproval>;
  /** Returns current resource quotas for the user's primary organization. */
  resourceQuotas: ResourceQuota;
  /** Get secret metadata by key path */
  secret: Secret;
  /** Get audit log for a secret */
  secretAuditLog: Array<SecretAuditLog>;
  /** List all secrets (without values) - scoped to current user and their orgs */
  secrets: Array<Secret>;
  /** Test Rhai expression with mock context */
  testRhaiExpression: TestRhaiExpressionResult;
  /** Fetch WASM modules by IDs (for loading workflow nodes) */
  wasmModules: Array<WasmModule>;
  /** Returns DLQ entries for webhook triggers owned by the current user. */
  webhookDeadLetterQueue: Array<WebhookDlqEntry>;
  /** List webhook listeners - scoped to current user with pagination */
  webhookTriggers: Array<WebhookTrigger>;
  /** Fetch a workflow definition by ID. */
  workflow: Workflow;
  /** Get execution history for an entire workflow */
  workflowExecutionHistory: Array<WorkflowExecution>;
  /** Get the schedule for a specific workflow. */
  workflowSchedule?: Maybe<WorkflowScheduleObj>;
  /** List published versions of a workflow, ordered by version number descending. */
  workflowVersions: Array<WorkflowVersion>;
  /** List workflows for current user */
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

export type QueryRootActorWorkflowsArgs = {
  actorId: Scalars["UUID"]["input"];
};

export type QueryRootActorWorkflowsSummaryArgs = {
  actorId: Scalars["UUID"]["input"];
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

export type QueryRootOrganizationArgs = {
  orgId: Scalars["UUID"]["input"];
};

export type QueryRootOrganizationMembersArgs = {
  orgId: Scalars["UUID"]["input"];
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

export type SignupInput = {
  email: Scalars["String"]["input"];
  name?: InputMaybe<Scalars["String"]["input"]>;
  password: Scalars["String"]["input"];
};

export type SubscriptionRoot = {
  __typename?: "SubscriptionRoot";
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
  compiledAt: Scalars["String"]["output"];
  config: Scalars["String"]["output"];
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
  /** Serialized representation of the graph (flexible JSON). */
  graphJson: Scalars["String"]["output"];
  id: Scalars["UUID"]["output"];
  maxConcurrentExecutions?: Maybe<Scalars["Int"]["output"]>;
  name: Scalars["String"]["output"];
  intent?: Maybe<Scalars["JSON"]["output"]>;
};

export type WorkflowExecution = {
  __typename?: "WorkflowExecution";
  /** Actor that dispatched this execution, if any. */
  actorId?: Maybe<Scalars["UUID"]["output"]>;
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

export type GetModuleExecutionHistoryQueryVariables = Exact<{
  moduleId: Scalars["UUID"]["input"];
  pagination?: InputMaybe<PaginationInput>;
}>;

export type GetModuleExecutionHistoryQuery = {
  __typename?: "QueryRoot";
  moduleExecutionHistory: Array<{
    __typename?: "ModuleExecution";
    id: any;
    status: string;
    durationMs?: number | null;
    startedAt: string;
    errorMessage?: string | null;
    outputData?: string | null;
  }>;
};

export type GetModuleExecutionLogsQueryVariables = Exact<{
  executionId: Scalars["UUID"]["input"];
}>;

export type GetModuleExecutionLogsQuery = {
  __typename?: "QueryRoot";
  moduleExecutionLogs: Array<{
    __typename?: "ModuleExecutionLog";
    id: any;
    level: string;
    message: string;
    createdAt: string;
    metadata?: string | null;
  }>;
};

export type GetSecretAuditLogQueryVariables = Exact<{
  secretId: Scalars["UUID"]["input"];
  limit?: InputMaybe<Scalars["Int"]["input"]>;
}>;

export type GetSecretAuditLogQuery = {
  __typename?: "QueryRoot";
  secretAuditLog: Array<{
    __typename?: "SecretAuditLog";
    id: any;
    action: string;
    actorType: string;
    success: boolean;
    timestamp: string;
    errorMessage?: string | null;
  }>;
};

export type CreateSecretMutationVariables = Exact<{
  input: CreateSecretInput;
}>;

export type CreateSecretMutation = {
  __typename?: "MutationRoot";
  createSecret: {
    __typename?: "Secret";
    id: any;
    name: string;
    keyPath: string;
  };
};

export type GetSecretsQueryVariables = Exact<{
  pagination?: InputMaybe<PaginationInput>;
}>;

export type GetSecretsQuery = {
  __typename?: "QueryRoot";
  secrets: Array<{
    __typename?: "Secret";
    id: any;
    name: string;
    keyPath: string;
    description?: string | null;
    createdAt: string;
    lastAccessedAt?: string | null;
    accessCount: number;
    expiresAt?: string | null;
  }>;
};

export type DeleteSecretMutationVariables = Exact<{
  keyPath: Scalars["String"]["input"];
}>;

export type DeleteSecretMutation = {
  __typename?: "MutationRoot";
  deleteSecret: boolean;
};

export type RotateEncryptionKeyMutationVariables = Exact<{
  [key: string]: never;
}>;

export type RotateEncryptionKeyMutation = {
  __typename?: "MutationRoot";
  rotateEncryptionKey: number;
};

export type ListApiKeysQueryVariables = Exact<{
  pagination?: InputMaybe<PaginationInput>;
}>;

export type ListApiKeysQuery = {
  __typename?: "QueryRoot";
  apiKeys: Array<{
    __typename?: "ApiKeyInfo";
    id: any;
    name: string;
    keyPrefix: string;
    scopes: Array<string>;
    createdAt: string;
    expiresAt?: string | null;
    lastUsedAt?: string | null;
    isActive: boolean;
    usageCount: number;
  }>;
};

export type CreateApiKeyMutationVariables = Exact<{
  input: CreateApiKeyInput;
}>;

export type CreateApiKeyMutation = {
  __typename?: "MutationRoot";
  createApiKey: {
    __typename?: "ApiKeyCreated";
    id: any;
    name: string;
    key: string;
    scopes: Array<string>;
    expiresAt?: string | null;
  };
};

export type RevokeApiKeyMutationVariables = Exact<{
  keyId: Scalars["UUID"]["input"];
}>;

export type RevokeApiKeyMutation = {
  __typename?: "MutationRoot";
  revokeApiKey: boolean;
};

export type GetApprovalsQueryVariables = Exact<{ [key: string]: never }>;

export type GetApprovalsQuery = {
  __typename?: "QueryRoot";
  pendingApprovals: Array<{
    __typename?: "ExecutionApproval";
    id: any;
    workflowId: any;
    executionId: any;
    nodeId: any;
    requiredFor: Array<string>;
    status: string;
    requestedAt: string;
    decidedAt?: string | null;
    decidedBy?: any | null;
    reason?: string | null;
  }>;
};

export type ApproveExecutionMutationVariables = Exact<{
  id: Scalars["UUID"]["input"];
  reason?: InputMaybe<Scalars["String"]["input"]>;
}>;

export type ApproveExecutionMutation = {
  __typename?: "MutationRoot";
  approveExecution: boolean;
};

export type DenyExecutionMutationVariables = Exact<{
  id: Scalars["UUID"]["input"];
  reason?: InputMaybe<Scalars["String"]["input"]>;
}>;

export type DenyExecutionMutation = {
  __typename?: "MutationRoot";
  denyExecution: boolean;
};

export type GetAuditSettingsQueryVariables = Exact<{ [key: string]: never }>;

export type GetAuditSettingsQuery = {
  __typename?: "QueryRoot";
  auditSettings?: {
    __typename?: "UserAuditSettings";
    streamingEnabled: boolean;
    otlpEndpoint?: string | null;
    otlpProtocol?: string | null;
    updatedAt: string;
    createdAt: string;
  } | null;
};

export type UpdateAuditSettingsMutationVariables = Exact<{
  enabled: Scalars["Boolean"]["input"];
  endpoint?: InputMaybe<Scalars["String"]["input"]>;
  protocol: Scalars["String"]["input"];
  headers?: InputMaybe<Scalars["String"]["input"]>;
}>;

export type UpdateAuditSettingsMutation = {
  __typename?: "MutationRoot";
  updateAuditSettings: {
    __typename?: "UserAuditSettings";
    streamingEnabled: boolean;
    otlpEndpoint?: string | null;
    otlpProtocol?: string | null;
    updatedAt: string;
  };
};

export type GetDeadLetterQueueQueryVariables = Exact<{ [key: string]: never }>;

export type GetDeadLetterQueueQuery = {
  __typename?: "QueryRoot";
  deadLetterQueue: Array<{
    __typename?: "DeadLetterEntry";
    id: any;
    workflowId: any;
    executionId: any;
    nodeId: any;
    errorMessage: string;
    payload?: string | null;
    createdAt: string;
    replayedAt?: string | null;
    replayedBy?: any | null;
  }>;
};

export type GetWebhookDeadLetterQueueQueryVariables = Exact<{
  [key: string]: never;
}>;

export type GetWebhookDeadLetterQueueQuery = {
  __typename?: "QueryRoot";
  webhookDeadLetterQueue: Array<{
    __typename?: "WebhookDlqEntry";
    id: any;
    triggerId?: any | null;
    dropReason: string;
    headers?: string | null;
    payload?: string | null;
    sourceIp?: string | null;
    createdAt: string;
    replayedAt?: string | null;
    replayedBy?: any | null;
  }>;
};

export type ReplayDeadLetterEntryMutationVariables = Exact<{
  id: Scalars["UUID"]["input"];
}>;

export type ReplayDeadLetterEntryMutation = {
  __typename?: "MutationRoot";
  replayDeadLetterEntry: boolean;
};

export type ReplayWebhookDeadLetterEntryMutationVariables = Exact<{
  id: Scalars["UUID"]["input"];
}>;

export type ReplayWebhookDeadLetterEntryMutation = {
  __typename?: "MutationRoot";
  replayWebhookDeadLetterEntry: boolean;
};

export type RegisterMcpAgentMutationVariables = Exact<{
  name: Scalars["String"]["input"];
  role: Scalars["String"]["input"];
}>;

export type RegisterMcpAgentMutation = {
  __typename?: "MutationRoot";
  registerMcpAgent: {
    __typename?: "McpAgentCreated";
    agentId: any;
    name: string;
    token: string;
    role: string;
  };
};

export type ListLinkedAccountsQueryVariables = Exact<{ [key: string]: never }>;

export type ListLinkedAccountsQuery = {
  __typename?: "QueryRoot";
  linkedOauthAccounts: Array<{
    __typename?: "OauthAccount";
    id: any;
    provider: string;
    email: string;
    name?: string | null;
    pictureUrl?: string | null;
    linkedAt: string;
    lastLoginAt?: string | null;
  }>;
};

export type GetOAuthUrlQueryVariables = Exact<{
  provider: Scalars["String"]["input"];
}>;

export type GetOAuthUrlQuery = {
  __typename?: "QueryRoot";
  oauthLoginUrl: { __typename?: "OauthAuthUrl"; authUrl: string };
};

export type UnlinkOAuthMutationVariables = Exact<{
  provider: Scalars["String"]["input"];
}>;

export type UnlinkOAuthMutation = {
  __typename?: "MutationRoot";
  unlinkOauthAccount: boolean;
};

export type ListOrgsQueryVariables = Exact<{ [key: string]: never }>;

export type ListOrgsQuery = {
  __typename?: "QueryRoot";
  myOrganizations: Array<{
    __typename?: "OrganizationObj";
    id: any;
    name: string;
    slug: string;
    ownerId: any;
    createdAt: string;
    updatedAt: string;
  }>;
};

export type ListOrgMembersQueryVariables = Exact<{
  orgId: Scalars["UUID"]["input"];
}>;

export type ListOrgMembersQuery = {
  __typename?: "QueryRoot";
  organizationMembers: Array<{
    __typename?: "OrgMemberObj";
    id: any;
    orgId: any;
    userId: any;
    role: string;
    invitedBy?: any | null;
    joinedAt: string;
  }>;
};

export type CreateOrgMutationVariables = Exact<{
  name: Scalars["String"]["input"];
  slug: Scalars["String"]["input"];
}>;

export type CreateOrgMutation = {
  __typename?: "MutationRoot";
  createOrganization: { __typename?: "OrganizationObj"; id: any; name: string };
};

export type RemoveMemberMutationVariables = Exact<{
  orgId: Scalars["UUID"]["input"];
  userId: Scalars["UUID"]["input"];
}>;

export type RemoveMemberMutation = {
  __typename?: "MutationRoot";
  removeMember: boolean;
};

export type GetResourceQuotasQueryVariables = Exact<{ [key: string]: never }>;

export type GetResourceQuotasQuery = {
  __typename?: "QueryRoot";
  resourceQuotas: {
    __typename?: "ResourceQuota";
    cpuCores: number;
    usedCpu: number;
    memoryGb: number;
    usedMemory: number;
    storageGb: number;
    usedStorage: number;
    concurrentExecutions: number;
    activeExecutions: number;
  };
};

export type UpdateResourceQuotasMutationVariables = Exact<{
  input: UpdateResourceQuotasInput;
}>;

export type UpdateResourceQuotasMutation = {
  __typename?: "MutationRoot";
  updateResourceQuotas: {
    __typename?: "ResourceQuota";
    cpuCores: number;
    usedCpu: number;
    memoryGb: number;
    usedMemory: number;
    storageGb: number;
    usedStorage: number;
    concurrentExecutions: number;
    activeExecutions: number;
  };
};

export type Setup2FaMutationVariables = Exact<{ [key: string]: never }>;

export type Setup2FaMutation = {
  __typename?: "MutationRoot";
  setupTwoFactor: {
    __typename?: "TwoFactorSetup";
    secret: string;
    qrCodeUrl: string;
    qrCodePng: string;
  };
};

export type Enable2FaMutationVariables = Exact<{
  input: Enable2FaInput;
}>;

export type Enable2FaMutation = {
  __typename?: "MutationRoot";
  enableTwoFactor: {
    __typename?: "TwoFactorEnrollment";
    backupCodes: Array<string>;
  };
};

export type Disable2FaMutationVariables = Exact<{ [key: string]: never }>;

export type Disable2FaMutation = {
  __typename?: "MutationRoot";
  disableTwoFactor: boolean;
};

export type LegacyListActorsQueryVariables = Exact<{ [key: string]: never }>;

export type LegacyListActorsQuery = {
  __typename?: "QueryRoot";
  actors: Array<{
    __typename?: "ActorSummary";
    id: any;
    name: string;
    description?: string | null;
    status: string;
    maxCapabilityWorld: string;
    totalBudgetUsd?: number | null;
    spentBudgetUsd: number;
    workflowCount: number;
    executionCount: number;
    createdAt: string;
    updatedAt: string;
  }>;
};

export type GetWorkflowLoaderQueryVariables = Exact<{
  id: Scalars["UUID"]["input"];
}>;

export type GetWorkflowLoaderQuery = {
  __typename?: "QueryRoot";
  workflow?: {
    __typename?: "Workflow";
    id: any;
    name: string;
    graphJson: string;
    actorId?: any | null;
    maxConcurrentExecutions?: number | null;
    intent?: any | null;
  } | null;
};

export type GetModulesLoaderQueryVariables = Exact<{
  ids: Array<Scalars["UUID"]["input"]> | Scalars["UUID"]["input"];
}>;

export type GetModulesLoaderQuery = {
  __typename?: "QueryRoot";
  wasmModules: Array<{
    __typename?: "WasmModule";
    id: any;
    name: string;
    config: string;
    sourceCode?: string | null;
    capabilityWorld?: string | null;
    importedInterfaces?: Array<string> | null;
  }>;
};

export type ListActorsQueryVariables = Exact<{ [key: string]: never }>;

export type ListActorsQuery = {
  __typename?: "QueryRoot";
  actors: Array<{
    __typename?: "ActorSummary";
    id: any;
    name: string;
    status: string;
    executionCount: number;
  }>;
};

export type WorkflowsQueryVariables = Exact<{ [key: string]: never }>;

export type WorkflowsQuery = {
  __typename?: "QueryRoot";
  workflows: Array<{
    __typename?: "Workflow";
    id: any;
    name: string;
    graphJson: string;
    actorId?: any | null;
    maxConcurrentExecutions?: number | null;
    intent?: any | null;
  }>;
};

export type TriggerWorkflowMutationVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
}>;

export type TriggerWorkflowMutation = {
  __typename?: "MutationRoot";
  triggerWorkflow: {
    __typename?: "WorkflowExecution";
    id: any;
    status: string;
  };
};

export type LatestWorkflowExecutionsQueryVariables = Exact<{
  workflowIds: Array<Scalars["UUID"]["input"]> | Scalars["UUID"]["input"];
}>;

export type LatestWorkflowExecutionsQuery = {
  __typename?: "QueryRoot";
  latestWorkflowExecutions: Array<{
    __typename?: "WorkflowExecution";
    workflowId: any;
    status: string;
    startedAt: string;
    errorMessage?: string | null;
  }>;
};

export const GetModuleExecutionHistoryDocument = `
    query GetModuleExecutionHistory($moduleId: UUID!, $pagination: PaginationInput) {
  moduleExecutionHistory(moduleId: $moduleId, pagination: $pagination) {
    id
    status
    durationMs
    startedAt
    errorMessage
    outputData
  }
}
    `;

export const useGetModuleExecutionHistoryQuery = <
  TData = GetModuleExecutionHistoryQuery,
  TError = unknown,
>(
  variables: GetModuleExecutionHistoryQueryVariables,
  options?: Omit<
    UseQueryOptions<GetModuleExecutionHistoryQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetModuleExecutionHistoryQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetModuleExecutionHistoryQuery, TError, TData>({
    queryKey: ["GetModuleExecutionHistory", variables],
    queryFn: graphqlFetcher<
      GetModuleExecutionHistoryQuery,
      GetModuleExecutionHistoryQueryVariables
    >(GetModuleExecutionHistoryDocument, variables),
    ...options,
  });
};

export const GetModuleExecutionLogsDocument = `
    query GetModuleExecutionLogs($executionId: UUID!) {
  moduleExecutionLogs(executionId: $executionId) {
    id
    level
    message
    createdAt
    metadata
  }
}
    `;

export const useGetModuleExecutionLogsQuery = <
  TData = GetModuleExecutionLogsQuery,
  TError = unknown,
>(
  variables: GetModuleExecutionLogsQueryVariables,
  options?: Omit<
    UseQueryOptions<GetModuleExecutionLogsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetModuleExecutionLogsQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetModuleExecutionLogsQuery, TError, TData>({
    queryKey: ["GetModuleExecutionLogs", variables],
    queryFn: graphqlFetcher<
      GetModuleExecutionLogsQuery,
      GetModuleExecutionLogsQueryVariables
    >(GetModuleExecutionLogsDocument, variables),
    ...options,
  });
};

export const GetSecretAuditLogDocument = `
    query GetSecretAuditLog($secretId: UUID!, $limit: Int) {
  secretAuditLog(secretId: $secretId, pagination: {limit: $limit}) {
    id
    action
    actorType
    success
    timestamp
    errorMessage
  }
}
    `;

export const useGetSecretAuditLogQuery = <
  TData = GetSecretAuditLogQuery,
  TError = unknown,
>(
  variables: GetSecretAuditLogQueryVariables,
  options?: Omit<
    UseQueryOptions<GetSecretAuditLogQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetSecretAuditLogQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetSecretAuditLogQuery, TError, TData>({
    queryKey: ["GetSecretAuditLog", variables],
    queryFn: graphqlFetcher<
      GetSecretAuditLogQuery,
      GetSecretAuditLogQueryVariables
    >(GetSecretAuditLogDocument, variables),
    ...options,
  });
};

export const CreateSecretDocument = `
    mutation CreateSecret($input: CreateSecretInput!) {
  createSecret(input: $input) {
    id
    name
    keyPath
  }
}
    `;

export const useCreateSecretMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    CreateSecretMutation,
    TError,
    CreateSecretMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    CreateSecretMutation,
    TError,
    CreateSecretMutationVariables,
    TContext
  >({
    mutationKey: ["CreateSecret"],
    mutationFn: (variables?: CreateSecretMutationVariables) =>
      graphqlFetcher<CreateSecretMutation, CreateSecretMutationVariables>(
        CreateSecretDocument,
        variables,
      )(),
    ...options,
  });
};

export const GetSecretsDocument = `
    query GetSecrets($pagination: PaginationInput) {
  secrets(pagination: $pagination) {
    id
    name
    keyPath
    description
    createdAt
    lastAccessedAt
    accessCount
    expiresAt
  }
}
    `;

export const useGetSecretsQuery = <TData = GetSecretsQuery, TError = unknown>(
  variables?: GetSecretsQueryVariables,
  options?: Omit<
    UseQueryOptions<GetSecretsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<GetSecretsQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<GetSecretsQuery, TError, TData>({
    queryKey:
      variables === undefined ? ["GetSecrets"] : ["GetSecrets", variables],
    queryFn: graphqlFetcher<GetSecretsQuery, GetSecretsQueryVariables>(
      GetSecretsDocument,
      variables,
    ),
    ...options,
  });
};

export const DeleteSecretDocument = `
    mutation DeleteSecret($keyPath: String!) {
  deleteSecret(keyPath: $keyPath)
}
    `;

export const useDeleteSecretMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    DeleteSecretMutation,
    TError,
    DeleteSecretMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    DeleteSecretMutation,
    TError,
    DeleteSecretMutationVariables,
    TContext
  >({
    mutationKey: ["DeleteSecret"],
    mutationFn: (variables?: DeleteSecretMutationVariables) =>
      graphqlFetcher<DeleteSecretMutation, DeleteSecretMutationVariables>(
        DeleteSecretDocument,
        variables,
      )(),
    ...options,
  });
};

export const RotateEncryptionKeyDocument = `
    mutation RotateEncryptionKey {
  rotateEncryptionKey
}
    `;

export const useRotateEncryptionKeyMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    RotateEncryptionKeyMutation,
    TError,
    RotateEncryptionKeyMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    RotateEncryptionKeyMutation,
    TError,
    RotateEncryptionKeyMutationVariables,
    TContext
  >({
    mutationKey: ["RotateEncryptionKey"],
    mutationFn: (variables?: RotateEncryptionKeyMutationVariables) =>
      graphqlFetcher<
        RotateEncryptionKeyMutation,
        RotateEncryptionKeyMutationVariables
      >(RotateEncryptionKeyDocument, variables)(),
    ...options,
  });
};

export const ListApiKeysDocument = `
    query ListApiKeys($pagination: PaginationInput) {
  apiKeys(pagination: $pagination) {
    id
    name
    keyPrefix
    scopes
    createdAt
    expiresAt
    lastUsedAt
    isActive
    usageCount
  }
}
    `;

export const useListApiKeysQuery = <TData = ListApiKeysQuery, TError = unknown>(
  variables?: ListApiKeysQueryVariables,
  options?: Omit<
    UseQueryOptions<ListApiKeysQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<ListApiKeysQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<ListApiKeysQuery, TError, TData>({
    queryKey:
      variables === undefined ? ["ListApiKeys"] : ["ListApiKeys", variables],
    queryFn: graphqlFetcher<ListApiKeysQuery, ListApiKeysQueryVariables>(
      ListApiKeysDocument,
      variables,
    ),
    ...options,
  });
};

export const CreateApiKeyDocument = `
    mutation CreateApiKey($input: CreateApiKeyInput!) {
  createApiKey(input: $input) {
    id
    name
    key
    scopes
    expiresAt
  }
}
    `;

export const useCreateApiKeyMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    CreateApiKeyMutation,
    TError,
    CreateApiKeyMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    CreateApiKeyMutation,
    TError,
    CreateApiKeyMutationVariables,
    TContext
  >({
    mutationKey: ["CreateApiKey"],
    mutationFn: (variables?: CreateApiKeyMutationVariables) =>
      graphqlFetcher<CreateApiKeyMutation, CreateApiKeyMutationVariables>(
        CreateApiKeyDocument,
        variables,
      )(),
    ...options,
  });
};

export const RevokeApiKeyDocument = `
    mutation RevokeApiKey($keyId: UUID!) {
  revokeApiKey(keyId: $keyId)
}
    `;

export const useRevokeApiKeyMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    RevokeApiKeyMutation,
    TError,
    RevokeApiKeyMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    RevokeApiKeyMutation,
    TError,
    RevokeApiKeyMutationVariables,
    TContext
  >({
    mutationKey: ["RevokeApiKey"],
    mutationFn: (variables?: RevokeApiKeyMutationVariables) =>
      graphqlFetcher<RevokeApiKeyMutation, RevokeApiKeyMutationVariables>(
        RevokeApiKeyDocument,
        variables,
      )(),
    ...options,
  });
};

export const GetApprovalsDocument = `
    query GetApprovals {
  pendingApprovals {
    id
    workflowId
    executionId
    nodeId
    requiredFor
    status
    requestedAt
    decidedAt
    decidedBy
    reason
  }
}
    `;

export const useGetApprovalsQuery = <
  TData = GetApprovalsQuery,
  TError = unknown,
>(
  variables?: GetApprovalsQueryVariables,
  options?: Omit<
    UseQueryOptions<GetApprovalsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<GetApprovalsQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<GetApprovalsQuery, TError, TData>({
    queryKey:
      variables === undefined ? ["GetApprovals"] : ["GetApprovals", variables],
    queryFn: graphqlFetcher<GetApprovalsQuery, GetApprovalsQueryVariables>(
      GetApprovalsDocument,
      variables,
    ),
    ...options,
  });
};

export const ApproveExecutionDocument = `
    mutation ApproveExecution($id: UUID!, $reason: String) {
  approveExecution(id: $id, reason: $reason)
}
    `;

export const useApproveExecutionMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    ApproveExecutionMutation,
    TError,
    ApproveExecutionMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    ApproveExecutionMutation,
    TError,
    ApproveExecutionMutationVariables,
    TContext
  >({
    mutationKey: ["ApproveExecution"],
    mutationFn: (variables?: ApproveExecutionMutationVariables) =>
      graphqlFetcher<
        ApproveExecutionMutation,
        ApproveExecutionMutationVariables
      >(ApproveExecutionDocument, variables)(),
    ...options,
  });
};

export const DenyExecutionDocument = `
    mutation DenyExecution($id: UUID!, $reason: String) {
  denyExecution(id: $id, reason: $reason)
}
    `;

export const useDenyExecutionMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    DenyExecutionMutation,
    TError,
    DenyExecutionMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    DenyExecutionMutation,
    TError,
    DenyExecutionMutationVariables,
    TContext
  >({
    mutationKey: ["DenyExecution"],
    mutationFn: (variables?: DenyExecutionMutationVariables) =>
      graphqlFetcher<DenyExecutionMutation, DenyExecutionMutationVariables>(
        DenyExecutionDocument,
        variables,
      )(),
    ...options,
  });
};

export const GetAuditSettingsDocument = `
    query GetAuditSettings {
  auditSettings {
    streamingEnabled
    otlpEndpoint
    otlpProtocol
    updatedAt
    createdAt
  }
}
    `;

export const useGetAuditSettingsQuery = <
  TData = GetAuditSettingsQuery,
  TError = unknown,
>(
  variables?: GetAuditSettingsQueryVariables,
  options?: Omit<
    UseQueryOptions<GetAuditSettingsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetAuditSettingsQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetAuditSettingsQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["GetAuditSettings"]
        : ["GetAuditSettings", variables],
    queryFn: graphqlFetcher<
      GetAuditSettingsQuery,
      GetAuditSettingsQueryVariables
    >(GetAuditSettingsDocument, variables),
    ...options,
  });
};

export const UpdateAuditSettingsDocument = `
    mutation UpdateAuditSettings($enabled: Boolean!, $endpoint: String, $protocol: String!, $headers: String) {
  updateAuditSettings(
    streamingEnabled: $enabled
    otlpEndpoint: $endpoint
    otlpProtocol: $protocol
    authHeaders: $headers
  ) {
    streamingEnabled
    otlpEndpoint
    otlpProtocol
    updatedAt
  }
}
    `;

export const useUpdateAuditSettingsMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    UpdateAuditSettingsMutation,
    TError,
    UpdateAuditSettingsMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    UpdateAuditSettingsMutation,
    TError,
    UpdateAuditSettingsMutationVariables,
    TContext
  >({
    mutationKey: ["UpdateAuditSettings"],
    mutationFn: (variables?: UpdateAuditSettingsMutationVariables) =>
      graphqlFetcher<
        UpdateAuditSettingsMutation,
        UpdateAuditSettingsMutationVariables
      >(UpdateAuditSettingsDocument, variables)(),
    ...options,
  });
};

export const GetDeadLetterQueueDocument = `
    query GetDeadLetterQueue {
  deadLetterQueue {
    id
    workflowId
    executionId
    nodeId
    errorMessage
    payload
    createdAt
    replayedAt
    replayedBy
  }
}
    `;

export const useGetDeadLetterQueueQuery = <
  TData = GetDeadLetterQueueQuery,
  TError = unknown,
>(
  variables?: GetDeadLetterQueueQueryVariables,
  options?: Omit<
    UseQueryOptions<GetDeadLetterQueueQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetDeadLetterQueueQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetDeadLetterQueueQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["GetDeadLetterQueue"]
        : ["GetDeadLetterQueue", variables],
    queryFn: graphqlFetcher<
      GetDeadLetterQueueQuery,
      GetDeadLetterQueueQueryVariables
    >(GetDeadLetterQueueDocument, variables),
    ...options,
  });
};

export const GetWebhookDeadLetterQueueDocument = `
    query GetWebhookDeadLetterQueue {
  webhookDeadLetterQueue {
    id
    triggerId
    dropReason
    headers
    payload
    sourceIp
    createdAt
    replayedAt
    replayedBy
  }
}
    `;

export const useGetWebhookDeadLetterQueueQuery = <
  TData = GetWebhookDeadLetterQueueQuery,
  TError = unknown,
>(
  variables?: GetWebhookDeadLetterQueueQueryVariables,
  options?: Omit<
    UseQueryOptions<GetWebhookDeadLetterQueueQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetWebhookDeadLetterQueueQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetWebhookDeadLetterQueueQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["GetWebhookDeadLetterQueue"]
        : ["GetWebhookDeadLetterQueue", variables],
    queryFn: graphqlFetcher<
      GetWebhookDeadLetterQueueQuery,
      GetWebhookDeadLetterQueueQueryVariables
    >(GetWebhookDeadLetterQueueDocument, variables),
    ...options,
  });
};

export const ReplayDeadLetterEntryDocument = `
    mutation ReplayDeadLetterEntry($id: UUID!) {
  replayDeadLetterEntry(id: $id)
}
    `;

export const useReplayDeadLetterEntryMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    ReplayDeadLetterEntryMutation,
    TError,
    ReplayDeadLetterEntryMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    ReplayDeadLetterEntryMutation,
    TError,
    ReplayDeadLetterEntryMutationVariables,
    TContext
  >({
    mutationKey: ["ReplayDeadLetterEntry"],
    mutationFn: (variables?: ReplayDeadLetterEntryMutationVariables) =>
      graphqlFetcher<
        ReplayDeadLetterEntryMutation,
        ReplayDeadLetterEntryMutationVariables
      >(ReplayDeadLetterEntryDocument, variables)(),
    ...options,
  });
};

export const ReplayWebhookDeadLetterEntryDocument = `
    mutation ReplayWebhookDeadLetterEntry($id: UUID!) {
  replayWebhookDeadLetterEntry(id: $id)
}
    `;

export const useReplayWebhookDeadLetterEntryMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    ReplayWebhookDeadLetterEntryMutation,
    TError,
    ReplayWebhookDeadLetterEntryMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    ReplayWebhookDeadLetterEntryMutation,
    TError,
    ReplayWebhookDeadLetterEntryMutationVariables,
    TContext
  >({
    mutationKey: ["ReplayWebhookDeadLetterEntry"],
    mutationFn: (variables?: ReplayWebhookDeadLetterEntryMutationVariables) =>
      graphqlFetcher<
        ReplayWebhookDeadLetterEntryMutation,
        ReplayWebhookDeadLetterEntryMutationVariables
      >(ReplayWebhookDeadLetterEntryDocument, variables)(),
    ...options,
  });
};

export const RegisterMcpAgentDocument = `
    mutation RegisterMcpAgent($name: String!, $role: String!) {
  registerMcpAgent(name: $name, roleName: $role) {
    agentId
    name
    token
    role
  }
}
    `;

export const useRegisterMcpAgentMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    RegisterMcpAgentMutation,
    TError,
    RegisterMcpAgentMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    RegisterMcpAgentMutation,
    TError,
    RegisterMcpAgentMutationVariables,
    TContext
  >({
    mutationKey: ["RegisterMcpAgent"],
    mutationFn: (variables?: RegisterMcpAgentMutationVariables) =>
      graphqlFetcher<
        RegisterMcpAgentMutation,
        RegisterMcpAgentMutationVariables
      >(RegisterMcpAgentDocument, variables)(),
    ...options,
  });
};

export const ListLinkedAccountsDocument = `
    query ListLinkedAccounts {
  linkedOauthAccounts {
    id
    provider
    email
    name
    pictureUrl
    linkedAt
    lastLoginAt
  }
}
    `;

export const useListLinkedAccountsQuery = <
  TData = ListLinkedAccountsQuery,
  TError = unknown,
>(
  variables?: ListLinkedAccountsQueryVariables,
  options?: Omit<
    UseQueryOptions<ListLinkedAccountsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      ListLinkedAccountsQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<ListLinkedAccountsQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["ListLinkedAccounts"]
        : ["ListLinkedAccounts", variables],
    queryFn: graphqlFetcher<
      ListLinkedAccountsQuery,
      ListLinkedAccountsQueryVariables
    >(ListLinkedAccountsDocument, variables),
    ...options,
  });
};

export const GetOAuthUrlDocument = `
    query GetOAuthUrl($provider: String!) {
  oauthLoginUrl(provider: $provider) {
    authUrl
  }
}
    `;

export const useGetOAuthUrlQuery = <TData = GetOAuthUrlQuery, TError = unknown>(
  variables: GetOAuthUrlQueryVariables,
  options?: Omit<
    UseQueryOptions<GetOAuthUrlQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<GetOAuthUrlQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<GetOAuthUrlQuery, TError, TData>({
    queryKey: ["GetOAuthUrl", variables],
    queryFn: graphqlFetcher<GetOAuthUrlQuery, GetOAuthUrlQueryVariables>(
      GetOAuthUrlDocument,
      variables,
    ),
    ...options,
  });
};

export const UnlinkOAuthDocument = `
    mutation UnlinkOAuth($provider: String!) {
  unlinkOauthAccount(provider: $provider)
}
    `;

export const useUnlinkOAuthMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    UnlinkOAuthMutation,
    TError,
    UnlinkOAuthMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    UnlinkOAuthMutation,
    TError,
    UnlinkOAuthMutationVariables,
    TContext
  >({
    mutationKey: ["UnlinkOAuth"],
    mutationFn: (variables?: UnlinkOAuthMutationVariables) =>
      graphqlFetcher<UnlinkOAuthMutation, UnlinkOAuthMutationVariables>(
        UnlinkOAuthDocument,
        variables,
      )(),
    ...options,
  });
};

export const ListOrgsDocument = `
    query ListOrgs {
  myOrganizations {
    id
    name
    slug
    ownerId
    createdAt
    updatedAt
  }
}
    `;

export const useListOrgsQuery = <TData = ListOrgsQuery, TError = unknown>(
  variables?: ListOrgsQueryVariables,
  options?: Omit<UseQueryOptions<ListOrgsQuery, TError, TData>, "queryKey"> & {
    queryKey?: UseQueryOptions<ListOrgsQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<ListOrgsQuery, TError, TData>({
    queryKey: variables === undefined ? ["ListOrgs"] : ["ListOrgs", variables],
    queryFn: graphqlFetcher<ListOrgsQuery, ListOrgsQueryVariables>(
      ListOrgsDocument,
      variables,
    ),
    ...options,
  });
};

export const ListOrgMembersDocument = `
    query ListOrgMembers($orgId: UUID!) {
  organizationMembers(orgId: $orgId) {
    id
    orgId
    userId
    role
    invitedBy
    joinedAt
  }
}
    `;

export const useListOrgMembersQuery = <
  TData = ListOrgMembersQuery,
  TError = unknown,
>(
  variables: ListOrgMembersQueryVariables,
  options?: Omit<
    UseQueryOptions<ListOrgMembersQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<ListOrgMembersQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<ListOrgMembersQuery, TError, TData>({
    queryKey: ["ListOrgMembers", variables],
    queryFn: graphqlFetcher<ListOrgMembersQuery, ListOrgMembersQueryVariables>(
      ListOrgMembersDocument,
      variables,
    ),
    ...options,
  });
};

export const CreateOrgDocument = `
    mutation CreateOrg($name: String!, $slug: String!) {
  createOrganization(name: $name, slug: $slug) {
    id
    name
  }
}
    `;

export const useCreateOrgMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    CreateOrgMutation,
    TError,
    CreateOrgMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    CreateOrgMutation,
    TError,
    CreateOrgMutationVariables,
    TContext
  >({
    mutationKey: ["CreateOrg"],
    mutationFn: (variables?: CreateOrgMutationVariables) =>
      graphqlFetcher<CreateOrgMutation, CreateOrgMutationVariables>(
        CreateOrgDocument,
        variables,
      )(),
    ...options,
  });
};

export const RemoveMemberDocument = `
    mutation RemoveMember($orgId: UUID!, $userId: UUID!) {
  removeMember(orgId: $orgId, targetUserId: $userId)
}
    `;

export const useRemoveMemberMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    RemoveMemberMutation,
    TError,
    RemoveMemberMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    RemoveMemberMutation,
    TError,
    RemoveMemberMutationVariables,
    TContext
  >({
    mutationKey: ["RemoveMember"],
    mutationFn: (variables?: RemoveMemberMutationVariables) =>
      graphqlFetcher<RemoveMemberMutation, RemoveMemberMutationVariables>(
        RemoveMemberDocument,
        variables,
      )(),
    ...options,
  });
};

export const GetResourceQuotasDocument = `
    query GetResourceQuotas {
  resourceQuotas {
    cpuCores
    usedCpu
    memoryGb
    usedMemory
    storageGb
    usedStorage
    concurrentExecutions
    activeExecutions
  }
}
    `;

export const useGetResourceQuotasQuery = <
  TData = GetResourceQuotasQuery,
  TError = unknown,
>(
  variables?: GetResourceQuotasQueryVariables,
  options?: Omit<
    UseQueryOptions<GetResourceQuotasQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetResourceQuotasQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetResourceQuotasQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["GetResourceQuotas"]
        : ["GetResourceQuotas", variables],
    queryFn: graphqlFetcher<
      GetResourceQuotasQuery,
      GetResourceQuotasQueryVariables
    >(GetResourceQuotasDocument, variables),
    ...options,
  });
};

export const UpdateResourceQuotasDocument = `
    mutation UpdateResourceQuotas($input: UpdateResourceQuotasInput!) {
  updateResourceQuotas(input: $input) {
    cpuCores
    usedCpu
    memoryGb
    usedMemory
    storageGb
    usedStorage
    concurrentExecutions
    activeExecutions
  }
}
    `;

export const useUpdateResourceQuotasMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    UpdateResourceQuotasMutation,
    TError,
    UpdateResourceQuotasMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    UpdateResourceQuotasMutation,
    TError,
    UpdateResourceQuotasMutationVariables,
    TContext
  >({
    mutationKey: ["UpdateResourceQuotas"],
    mutationFn: (variables?: UpdateResourceQuotasMutationVariables) =>
      graphqlFetcher<
        UpdateResourceQuotasMutation,
        UpdateResourceQuotasMutationVariables
      >(UpdateResourceQuotasDocument, variables)(),
    ...options,
  });
};

export const Setup2FaDocument = `
    mutation Setup2FA {
  setupTwoFactor {
    secret
    qrCodeUrl
    qrCodePng
  }
}
    `;

export const useSetup2FaMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    Setup2FaMutation,
    TError,
    Setup2FaMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    Setup2FaMutation,
    TError,
    Setup2FaMutationVariables,
    TContext
  >({
    mutationKey: ["Setup2FA"],
    mutationFn: (variables?: Setup2FaMutationVariables) =>
      graphqlFetcher<Setup2FaMutation, Setup2FaMutationVariables>(
        Setup2FaDocument,
        variables,
      )(),
    ...options,
  });
};

export const Enable2FaDocument = `
    mutation Enable2FA($input: Enable2FAInput!) {
  enableTwoFactor(input: $input) {
    backupCodes
  }
}
    `;

export const useEnable2FaMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    Enable2FaMutation,
    TError,
    Enable2FaMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    Enable2FaMutation,
    TError,
    Enable2FaMutationVariables,
    TContext
  >({
    mutationKey: ["Enable2FA"],
    mutationFn: (variables?: Enable2FaMutationVariables) =>
      graphqlFetcher<Enable2FaMutation, Enable2FaMutationVariables>(
        Enable2FaDocument,
        variables,
      )(),
    ...options,
  });
};

export const Disable2FaDocument = `
    mutation Disable2FA {
  disableTwoFactor
}
    `;

export const useDisable2FaMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    Disable2FaMutation,
    TError,
    Disable2FaMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    Disable2FaMutation,
    TError,
    Disable2FaMutationVariables,
    TContext
  >({
    mutationKey: ["Disable2FA"],
    mutationFn: (variables?: Disable2FaMutationVariables) =>
      graphqlFetcher<Disable2FaMutation, Disable2FaMutationVariables>(
        Disable2FaDocument,
        variables,
      )(),
    ...options,
  });
};

export const LegacyListActorsDocument = `
    query LegacyListActors {
  actors {
    id
    name
    description
    status
    maxCapabilityWorld
    totalBudgetUsd
    spentBudgetUsd
    workflowCount
    executionCount
    createdAt
    updatedAt
  }
}
    `;

export const useLegacyListActorsQuery = <
  TData = LegacyListActorsQuery,
  TError = unknown,
>(
  variables?: LegacyListActorsQueryVariables,
  options?: Omit<
    UseQueryOptions<LegacyListActorsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      LegacyListActorsQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<LegacyListActorsQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["LegacyListActors"]
        : ["LegacyListActors", variables],
    queryFn: graphqlFetcher<
      LegacyListActorsQuery,
      LegacyListActorsQueryVariables
    >(LegacyListActorsDocument, variables),
    ...options,
  });
};

export const GetWorkflowLoaderDocument = `
    query GetWorkflowLoader($id: UUID!) {
  workflow(id: $id) {
    id
    name
    graphJson
  }
}
    `;

export const useGetWorkflowLoaderQuery = <
  TData = GetWorkflowLoaderQuery,
  TError = unknown,
>(
  variables: GetWorkflowLoaderQueryVariables,
  options?: Omit<
    UseQueryOptions<GetWorkflowLoaderQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetWorkflowLoaderQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetWorkflowLoaderQuery, TError, TData>({
    queryKey: ["GetWorkflowLoader", variables],
    queryFn: graphqlFetcher<
      GetWorkflowLoaderQuery,
      GetWorkflowLoaderQueryVariables
    >(GetWorkflowLoaderDocument, variables),
    ...options,
  });
};

export const GetModulesLoaderDocument = `
    query GetModulesLoader($ids: [UUID!]!) {
  wasmModules(ids: $ids) {
    id
    name
    config
    sourceCode
    capabilityWorld
    importedInterfaces
  }
}
    `;

export const useGetModulesLoaderQuery = <
  TData = GetModulesLoaderQuery,
  TError = unknown,
>(
  variables: GetModulesLoaderQueryVariables,
  options?: Omit<
    UseQueryOptions<GetModulesLoaderQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetModulesLoaderQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetModulesLoaderQuery, TError, TData>({
    queryKey: ["GetModulesLoader", variables],
    queryFn: graphqlFetcher<
      GetModulesLoaderQuery,
      GetModulesLoaderQueryVariables
    >(GetModulesLoaderDocument, variables),
    ...options,
  });
};

export const ListActorsDocument = `
    query ListActors {
  actors {
    id
    name
    status
    executionCount
  }
}
    `;

export const useListActorsQuery = <TData = ListActorsQuery, TError = unknown>(
  variables?: ListActorsQueryVariables,
  options?: Omit<
    UseQueryOptions<ListActorsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<ListActorsQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<ListActorsQuery, TError, TData>({
    queryKey:
      variables === undefined ? ["ListActors"] : ["ListActors", variables],
    queryFn: graphqlFetcher<ListActorsQuery, ListActorsQueryVariables>(
      ListActorsDocument,
      variables,
    ),
    ...options,
  });
};

export const WorkflowsDocument = `
    query Workflows {
  workflows {
    id
    name
    graphJson
    actorId
  }
}
    `;

export const useWorkflowsQuery = <TData = WorkflowsQuery, TError = unknown>(
  variables?: WorkflowsQueryVariables,
  options?: Omit<UseQueryOptions<WorkflowsQuery, TError, TData>, "queryKey"> & {
    queryKey?: UseQueryOptions<WorkflowsQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<WorkflowsQuery, TError, TData>({
    queryKey:
      variables === undefined ? ["Workflows"] : ["Workflows", variables],
    queryFn: graphqlFetcher<WorkflowsQuery, WorkflowsQueryVariables>(
      WorkflowsDocument,
      variables,
    ),
    ...options,
  });
};

export const TriggerWorkflowDocument = `
    mutation TriggerWorkflow($workflowId: UUID!) {
  triggerWorkflow(workflowId: $workflowId) {
    id
    status
  }
}
    `;

export const useTriggerWorkflowMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    TriggerWorkflowMutation,
    TError,
    TriggerWorkflowMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    TriggerWorkflowMutation,
    TError,
    TriggerWorkflowMutationVariables,
    TContext
  >({
    mutationKey: ["TriggerWorkflow"],
    mutationFn: (variables?: TriggerWorkflowMutationVariables) =>
      graphqlFetcher<TriggerWorkflowMutation, TriggerWorkflowMutationVariables>(
        TriggerWorkflowDocument,
        variables,
      )(),
    ...options,
  });
};

export const LatestWorkflowExecutionsDocument = `
    query LatestWorkflowExecutions($workflowIds: [UUID!]!) {
  latestWorkflowExecutions(workflowIds: $workflowIds) {
    workflowId
    status
    startedAt
    errorMessage
  }
}
    `;

export const useLatestWorkflowExecutionsQuery = <
  TData = LatestWorkflowExecutionsQuery,
  TError = unknown,
>(
  variables: LatestWorkflowExecutionsQueryVariables,
  options?: Omit<
    UseQueryOptions<LatestWorkflowExecutionsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      LatestWorkflowExecutionsQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<LatestWorkflowExecutionsQuery, TError, TData>({
    queryKey: ["LatestWorkflowExecutions", variables],
    queryFn: graphqlFetcher<
      LatestWorkflowExecutionsQuery,
      LatestWorkflowExecutionsQueryVariables
    >(LatestWorkflowExecutionsDocument, variables),
    ...options,
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// Types for operations added below (not yet in codegen output)
// ─────────────────────────────────────────────────────────────────────────────

export type WorkflowVersionItem = {
  __typename?: "WorkflowVersion";
  id: any;
  workflowId: any;
  versionNumber: number;
  graphJson: string;
  description?: string | null;
  publishedAt: string;
  publishedBy: any;
  isActive: boolean;
  createdAt: string;
};

export type WorkflowExecutionItem = {
  __typename?: "WorkflowExecution";
  id: any;
  workflowId: any;
  status: string;
  startedAt: string;
  completedAt?: string | null;
  triggerType?: string | null;
  actorId?: any | null;
  errorMessage?: string | null;
  createdAt: string;
  durationMs?: number | null;
};

export type WorkflowScheduleItem = {
  __typename?: "WorkflowScheduleObj";
  id: any;
  workflowId: any;
  cronExpression: string;
  timezone: string;
  isEnabled: boolean;
  lastTriggeredAt?: string | null;
  nextTriggerAt?: string | null;
  createdAt: string;
  updatedAt: string;
};

export type DekRotationResultType = {
  __typename?: "DekRotationResult";
  newDekId: any;
  message: string;
};

export type ReEncryptionResultType = {
  __typename?: "ReEncryptionResult";
  reEncryptedCount: number;
  message: string;
};

export type MasterKeyRotationResultType = {
  __typename?: "MasterKeyRotationResult";
  reEncryptedDekCount: number;
  message: string;
};

// ─────────────────────────────────────────────────────────────────────────────
// Workflow Versions
// ─────────────────────────────────────────────────────────────────────────────

export type WorkflowVersionsQueryVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
  limit?: InputMaybe<Scalars["Int"]["input"]>;
}>;

export type WorkflowVersionsQuery = {
  __typename?: "QueryRoot";
  workflowVersions: Array<WorkflowVersionItem>;
};

export const WorkflowVersionsDocument = `
    query WorkflowVersions($workflowId: UUID!, $limit: Int) {
  workflowVersions(workflowId: $workflowId, limit: $limit) {
    id
    workflowId
    versionNumber
    description
    publishedAt
    publishedBy
    isActive
    createdAt
  }
}
    `;

export const useWorkflowVersionsQuery = <
  TData = WorkflowVersionsQuery,
  TError = unknown,
>(
  variables: WorkflowVersionsQueryVariables,
  options?: Omit<
    UseQueryOptions<WorkflowVersionsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<WorkflowVersionsQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<WorkflowVersionsQuery, TError, TData>({
    queryKey: ["WorkflowVersions", variables],
    queryFn: graphqlFetcher<WorkflowVersionsQuery, WorkflowVersionsQueryVariables>(
      WorkflowVersionsDocument,
      variables,
    ),
    ...options,
  });
};

export type PublishWorkflowVersionMutationVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
  description?: InputMaybe<Scalars["String"]["input"]>;
}>;

export type PublishWorkflowVersionMutation = {
  __typename?: "MutationRoot";
  publishWorkflowVersion: WorkflowVersionItem;
};

export const PublishWorkflowVersionDocument = `
    mutation PublishWorkflowVersion($workflowId: UUID!, $description: String) {
  publishWorkflowVersion(workflowId: $workflowId, description: $description) {
    id
    workflowId
    versionNumber
    description
    publishedAt
    publishedBy
    isActive
    createdAt
  }
}
    `;

export const usePublishWorkflowVersionMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    PublishWorkflowVersionMutation,
    TError,
    PublishWorkflowVersionMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    PublishWorkflowVersionMutation,
    TError,
    PublishWorkflowVersionMutationVariables,
    TContext
  >({
    mutationKey: ["PublishWorkflowVersion"],
    mutationFn: (variables?: PublishWorkflowVersionMutationVariables) =>
      graphqlFetcher<
        PublishWorkflowVersionMutation,
        PublishWorkflowVersionMutationVariables
      >(PublishWorkflowVersionDocument, variables)(),
    ...options,
  });
};

export type RollbackWorkflowVersionMutationVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
  versionId: Scalars["UUID"]["input"];
}>;

export type RollbackWorkflowVersionMutation = {
  __typename?: "MutationRoot";
  rollbackWorkflowVersion: WorkflowVersionItem;
};

export const RollbackWorkflowVersionDocument = `
    mutation RollbackWorkflowVersion($workflowId: UUID!, $versionId: UUID!) {
  rollbackWorkflowVersion(workflowId: $workflowId, versionId: $versionId) {
    id
    workflowId
    versionNumber
    description
    publishedAt
    isActive
    createdAt
  }
}
    `;

export const useRollbackWorkflowVersionMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    RollbackWorkflowVersionMutation,
    TError,
    RollbackWorkflowVersionMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    RollbackWorkflowVersionMutation,
    TError,
    RollbackWorkflowVersionMutationVariables,
    TContext
  >({
    mutationKey: ["RollbackWorkflowVersion"],
    mutationFn: (variables?: RollbackWorkflowVersionMutationVariables) =>
      graphqlFetcher<
        RollbackWorkflowVersionMutation,
        RollbackWorkflowVersionMutationVariables
      >(RollbackWorkflowVersionDocument, variables)(),
    ...options,
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// Execution History & Retry
// ─────────────────────────────────────────────────────────────────────────────

export type WorkflowExecutionHistoryQueryVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
  limit?: InputMaybe<Scalars["Int"]["input"]>;
  offset?: InputMaybe<Scalars["Int"]["input"]>;
}>;

export type WorkflowExecutionHistoryQuery = {
  __typename?: "QueryRoot";
  workflowExecutionHistory: Array<WorkflowExecutionItem>;
};

export const WorkflowExecutionHistoryDocument = `
    query WorkflowExecutionHistory($workflowId: UUID!, $limit: Int, $offset: Int) {
  workflowExecutionHistory(workflowId: $workflowId, pagination: {limit: $limit, offset: $offset}) {
    id
    workflowId
    status
    startedAt
    completedAt
    triggerType
    actorId
    errorMessage
    createdAt
    durationMs
  }
}
    `;

export const useWorkflowExecutionHistoryQuery = <
  TData = WorkflowExecutionHistoryQuery,
  TError = unknown,
>(
  variables: WorkflowExecutionHistoryQueryVariables,
  options?: Omit<
    UseQueryOptions<WorkflowExecutionHistoryQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      WorkflowExecutionHistoryQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<WorkflowExecutionHistoryQuery, TError, TData>({
    queryKey: ["WorkflowExecutionHistory", variables],
    queryFn: graphqlFetcher<
      WorkflowExecutionHistoryQuery,
      WorkflowExecutionHistoryQueryVariables
    >(WorkflowExecutionHistoryDocument, variables),
    ...options,
  });
};

export type RetryExecutionMutationVariables = Exact<{
  executionId: Scalars["UUID"]["input"];
}>;

export type RetryExecutionMutation = {
  __typename?: "MutationRoot";
  retryExecution: any;
};

export const RetryExecutionDocument = `
    mutation RetryExecution($executionId: UUID!) {
  retryExecution(executionId: $executionId)
}
    `;

export const useRetryExecutionMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    RetryExecutionMutation,
    TError,
    RetryExecutionMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    RetryExecutionMutation,
    TError,
    RetryExecutionMutationVariables,
    TContext
  >({
    mutationKey: ["RetryExecution"],
    mutationFn: (variables?: RetryExecutionMutationVariables) =>
      graphqlFetcher<RetryExecutionMutation, RetryExecutionMutationVariables>(
        RetryExecutionDocument,
        variables,
      )(),
    ...options,
  });
};

export type ResumeWorkflowMutationVariables = Exact<{
  executionId: Scalars["UUID"]["input"];
}>;

export type ResumeWorkflowMutation = {
  __typename?: "MutationRoot";
  resumeWorkflow: boolean;
};

export const ResumeWorkflowDocument = `
    mutation ResumeWorkflow($executionId: UUID!) {
  resumeWorkflow(executionId: $executionId)
}
    `;

export const useResumeWorkflowMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    ResumeWorkflowMutation,
    TError,
    ResumeWorkflowMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    ResumeWorkflowMutation,
    TError,
    ResumeWorkflowMutationVariables,
    TContext
  >({
    mutationKey: ["ResumeWorkflow"],
    mutationFn: (variables?: ResumeWorkflowMutationVariables) =>
      graphqlFetcher<ResumeWorkflowMutation, ResumeWorkflowMutationVariables>(
        ResumeWorkflowDocument,
        variables,
      )(),
    ...options,
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// Schedules
// ─────────────────────────────────────────────────────────────────────────────

export type MySchedulesQueryVariables = Exact<{ [key: string]: never }>;

export type MySchedulesQuery = {
  __typename?: "QueryRoot";
  mySchedules: Array<WorkflowScheduleItem>;
};

export const MySchedulesDocument = `
    query MySchedules {
  mySchedules {
    id
    workflowId
    cronExpression
    timezone
    isEnabled
    lastTriggeredAt
    nextTriggerAt
    createdAt
    updatedAt
  }
}
    `;

export const useMySchedulesQuery = <TData = MySchedulesQuery, TError = unknown>(
  variables?: MySchedulesQueryVariables,
  options?: Omit<
    UseQueryOptions<MySchedulesQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<MySchedulesQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<MySchedulesQuery, TError, TData>({
    queryKey:
      variables === undefined ? ["MySchedules"] : ["MySchedules", variables],
    queryFn: graphqlFetcher<MySchedulesQuery, MySchedulesQueryVariables>(
      MySchedulesDocument,
      variables,
    ),
    ...options,
  });
};

export type CreateScheduleMutationVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
  cronExpression: Scalars["String"]["input"];
  timezone?: InputMaybe<Scalars["String"]["input"]>;
}>;

export type CreateScheduleMutation = {
  __typename?: "MutationRoot";
  createSchedule: WorkflowScheduleItem;
};

export const CreateScheduleDocument = `
    mutation CreateSchedule($workflowId: UUID!, $cronExpression: String!, $timezone: String) {
  createSchedule(workflowId: $workflowId, cronExpression: $cronExpression, timezone: $timezone) {
    id
    workflowId
    cronExpression
    timezone
    isEnabled
    nextTriggerAt
    createdAt
    updatedAt
  }
}
    `;

export const useCreateScheduleMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    CreateScheduleMutation,
    TError,
    CreateScheduleMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    CreateScheduleMutation,
    TError,
    CreateScheduleMutationVariables,
    TContext
  >({
    mutationKey: ["CreateSchedule"],
    mutationFn: (variables?: CreateScheduleMutationVariables) =>
      graphqlFetcher<CreateScheduleMutation, CreateScheduleMutationVariables>(
        CreateScheduleDocument,
        variables,
      )(),
    ...options,
  });
};

export type UpdateScheduleMutationVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
  cronExpression?: InputMaybe<Scalars["String"]["input"]>;
  timezone?: InputMaybe<Scalars["String"]["input"]>;
  isEnabled?: InputMaybe<Scalars["Boolean"]["input"]>;
}>;

export type UpdateScheduleMutation = {
  __typename?: "MutationRoot";
  updateSchedule: WorkflowScheduleItem;
};

export const UpdateScheduleDocument = `
    mutation UpdateSchedule($workflowId: UUID!, $cronExpression: String, $timezone: String, $isEnabled: Boolean) {
  updateSchedule(workflowId: $workflowId, cronExpression: $cronExpression, timezone: $timezone, isEnabled: $isEnabled) {
    id
    workflowId
    cronExpression
    timezone
    isEnabled
    nextTriggerAt
    updatedAt
  }
}
    `;

export const useUpdateScheduleMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    UpdateScheduleMutation,
    TError,
    UpdateScheduleMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    UpdateScheduleMutation,
    TError,
    UpdateScheduleMutationVariables,
    TContext
  >({
    mutationKey: ["UpdateSchedule"],
    mutationFn: (variables?: UpdateScheduleMutationVariables) =>
      graphqlFetcher<UpdateScheduleMutation, UpdateScheduleMutationVariables>(
        UpdateScheduleDocument,
        variables,
      )(),
    ...options,
  });
};

export type DeleteScheduleMutationVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
}>;

export type DeleteScheduleMutation = {
  __typename?: "MutationRoot";
  deleteSchedule: boolean;
};

export const DeleteScheduleDocument = `
    mutation DeleteSchedule($workflowId: UUID!) {
  deleteSchedule(workflowId: $workflowId)
}
    `;

export const useDeleteScheduleMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    DeleteScheduleMutation,
    TError,
    DeleteScheduleMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    DeleteScheduleMutation,
    TError,
    DeleteScheduleMutationVariables,
    TContext
  >({
    mutationKey: ["DeleteSchedule"],
    mutationFn: (variables?: DeleteScheduleMutationVariables) =>
      graphqlFetcher<DeleteScheduleMutation, DeleteScheduleMutationVariables>(
        DeleteScheduleDocument,
        variables,
      )(),
    ...options,
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// API Key Rotation & Deletion
// ─────────────────────────────────────────────────────────────────────────────

export type RotateApiKeyMutationVariables = Exact<{
  keyId: Scalars["UUID"]["input"];
}>;

export type RotateApiKeyMutation = {
  __typename?: "MutationRoot";
  rotateApiKey: {
    __typename?: "ApiKeyCreated";
    id: any;
    name: string;
    key: string;
    scopes: Array<string>;
    expiresAt?: string | null;
  };
};

export const RotateApiKeyDocument = `
    mutation RotateApiKey($keyId: UUID!) {
  rotateApiKey(keyId: $keyId) {
    id
    name
    key
    scopes
    expiresAt
  }
}
    `;

export const useRotateApiKeyMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    RotateApiKeyMutation,
    TError,
    RotateApiKeyMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    RotateApiKeyMutation,
    TError,
    RotateApiKeyMutationVariables,
    TContext
  >({
    mutationKey: ["RotateApiKey"],
    mutationFn: (variables?: RotateApiKeyMutationVariables) =>
      graphqlFetcher<RotateApiKeyMutation, RotateApiKeyMutationVariables>(
        RotateApiKeyDocument,
        variables,
      )(),
    ...options,
  });
};

export type DeleteApiKeyMutationVariables = Exact<{
  keyId: Scalars["UUID"]["input"];
}>;

export type DeleteApiKeyMutation = {
  __typename?: "MutationRoot";
  deleteApiKey: boolean;
};

export const DeleteApiKeyDocument = `
    mutation DeleteApiKey($keyId: UUID!) {
  deleteApiKey(keyId: $keyId)
}
    `;

export const useDeleteApiKeyMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    DeleteApiKeyMutation,
    TError,
    DeleteApiKeyMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    DeleteApiKeyMutation,
    TError,
    DeleteApiKeyMutationVariables,
    TContext
  >({
    mutationKey: ["DeleteApiKey"],
    mutationFn: (variables?: DeleteApiKeyMutationVariables) =>
      graphqlFetcher<DeleteApiKeyMutation, DeleteApiKeyMutationVariables>(
        DeleteApiKeyDocument,
        variables,
      )(),
    ...options,
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// Organization Member Management
// ─────────────────────────────────────────────────────────────────────────────

export type InviteMemberMutationVariables = Exact<{
  orgId: Scalars["UUID"]["input"];
  targetUserId: Scalars["UUID"]["input"];
  role: Scalars["String"]["input"];
}>;

export type InviteMemberMutation = {
  __typename?: "MutationRoot";
  inviteMember: {
    __typename?: "OrgMemberObj";
    id: any;
    orgId: any;
    userId: any;
    role: string;
    invitedBy?: any | null;
    joinedAt: string;
  };
};

export const InviteMemberDocument = `
    mutation InviteMember($orgId: UUID!, $targetUserId: UUID!, $role: String!) {
  inviteMember(orgId: $orgId, targetUserId: $targetUserId, role: $role) {
    id
    orgId
    userId
    role
    invitedBy
    joinedAt
  }
}
    `;

export const useInviteMemberMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    InviteMemberMutation,
    TError,
    InviteMemberMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    InviteMemberMutation,
    TError,
    InviteMemberMutationVariables,
    TContext
  >({
    mutationKey: ["InviteMember"],
    mutationFn: (variables?: InviteMemberMutationVariables) =>
      graphqlFetcher<InviteMemberMutation, InviteMemberMutationVariables>(
        InviteMemberDocument,
        variables,
      )(),
    ...options,
  });
};

export type UpdateMemberRoleMutationVariables = Exact<{
  orgId: Scalars["UUID"]["input"];
  targetUserId: Scalars["UUID"]["input"];
  role: Scalars["String"]["input"];
}>;

export type UpdateMemberRoleMutation = {
  __typename?: "MutationRoot";
  updateMemberRole: {
    __typename?: "OrgMemberObj";
    id: any;
    orgId: any;
    userId: any;
    role: string;
    joinedAt: string;
  };
};

export const UpdateMemberRoleDocument = `
    mutation UpdateMemberRole($orgId: UUID!, $targetUserId: UUID!, $role: String!) {
  updateMemberRole(orgId: $orgId, targetUserId: $targetUserId, role: $role) {
    id
    orgId
    userId
    role
    joinedAt
  }
}
    `;

export const useUpdateMemberRoleMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    UpdateMemberRoleMutation,
    TError,
    UpdateMemberRoleMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    UpdateMemberRoleMutation,
    TError,
    UpdateMemberRoleMutationVariables,
    TContext
  >({
    mutationKey: ["UpdateMemberRole"],
    mutationFn: (variables?: UpdateMemberRoleMutationVariables) =>
      graphqlFetcher<
        UpdateMemberRoleMutation,
        UpdateMemberRoleMutationVariables
      >(UpdateMemberRoleDocument, variables)(),
    ...options,
  });
};

export type TransferOwnershipMutationVariables = Exact<{
  orgId: Scalars["UUID"]["input"];
  newOwnerId: Scalars["UUID"]["input"];
}>;

export type TransferOwnershipMutation = {
  __typename?: "MutationRoot";
  transferOwnership: {
    __typename?: "OrganizationObj";
    id: any;
    name: string;
    slug: string;
    ownerId: any;
    updatedAt: string;
  };
};

export const TransferOwnershipDocument = `
    mutation TransferOwnership($orgId: UUID!, $newOwnerId: UUID!) {
  transferOwnership(orgId: $orgId, newOwnerId: $newOwnerId) {
    id
    name
    slug
    ownerId
    updatedAt
  }
}
    `;

export const useTransferOwnershipMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    TransferOwnershipMutation,
    TError,
    TransferOwnershipMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    TransferOwnershipMutation,
    TError,
    TransferOwnershipMutationVariables,
    TContext
  >({
    mutationKey: ["TransferOwnership"],
    mutationFn: (variables?: TransferOwnershipMutationVariables) =>
      graphqlFetcher<
        TransferOwnershipMutation,
        TransferOwnershipMutationVariables
      >(TransferOwnershipDocument, variables)(),
    ...options,
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// Encryption Key Management
// ─────────────────────────────────────────────────────────────────────────────

export type RotateDekMutationVariables = Exact<{ [key: string]: never }>;

export type RotateDekMutation = {
  __typename?: "MutationRoot";
  rotateDek: DekRotationResultType;
};

export const RotateDekDocument = `
    mutation RotateDek {
  rotateDek {
    newDekId
    message
  }
}
    `;

export const useRotateDekMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    RotateDekMutation,
    TError,
    RotateDekMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    RotateDekMutation,
    TError,
    RotateDekMutationVariables,
    TContext
  >({
    mutationKey: ["RotateDek"],
    mutationFn: (variables?: RotateDekMutationVariables) =>
      graphqlFetcher<RotateDekMutation, RotateDekMutationVariables>(
        RotateDekDocument,
        variables,
      )(),
    ...options,
  });
};

export type ReEncryptSecretsMutationVariables = Exact<{ [key: string]: never }>;

export type ReEncryptSecretsMutation = {
  __typename?: "MutationRoot";
  reEncryptSecrets: ReEncryptionResultType;
};

export const ReEncryptSecretsDocument = `
    mutation ReEncryptSecrets {
  reEncryptSecrets {
    reEncryptedCount
    message
  }
}
    `;

export const useReEncryptSecretsMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    ReEncryptSecretsMutation,
    TError,
    ReEncryptSecretsMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    ReEncryptSecretsMutation,
    TError,
    ReEncryptSecretsMutationVariables,
    TContext
  >({
    mutationKey: ["ReEncryptSecrets"],
    mutationFn: (variables?: ReEncryptSecretsMutationVariables) =>
      graphqlFetcher<ReEncryptSecretsMutation, ReEncryptSecretsMutationVariables>(
        ReEncryptSecretsDocument,
        variables,
      )(),
    ...options,
  });
};

export type RotateMasterKeyMutationVariables = Exact<{
  newMasterKey: Scalars["String"]["input"];
}>;

export type RotateMasterKeyMutation = {
  __typename?: "MutationRoot";
  rotateMasterKey: MasterKeyRotationResultType;
};

export const RotateMasterKeyDocument = `
    mutation RotateMasterKey($newMasterKey: String!) {
  rotateMasterKey(newMasterKey: $newMasterKey) {
    reEncryptedDekCount
    message
  }
}
    `;

export const useRotateMasterKeyMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    RotateMasterKeyMutation,
    TError,
    RotateMasterKeyMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    RotateMasterKeyMutation,
    TError,
    RotateMasterKeyMutationVariables,
    TContext
  >({
    mutationKey: ["RotateMasterKey"],
    mutationFn: (variables?: RotateMasterKeyMutationVariables) =>
      graphqlFetcher<RotateMasterKeyMutation, RotateMasterKeyMutationVariables>(
        RotateMasterKeyDocument,
        variables,
      )(),
    ...options,
  });
};

// ---------------------------------------------------------------------------
// setConcurrencyLimit mutation
// ---------------------------------------------------------------------------
export type SetConcurrencyLimitMutationVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
  maxConcurrent?: InputMaybe<Scalars["Int"]["input"]>;
}>;
export type SetConcurrencyLimitMutation = { __typename?: "MutationRoot"; setConcurrencyLimit: boolean };
const SetConcurrencyLimitDocument = `
  mutation SetConcurrencyLimit($workflowId: UUID!, $maxConcurrent: Int) {
    setConcurrencyLimit(workflowId: $workflowId, maxConcurrent: $maxConcurrent)
  }
`;
export const useSetConcurrencyLimitMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<SetConcurrencyLimitMutation, TError, SetConcurrencyLimitMutationVariables, TContext>,
) =>
  useMutation<SetConcurrencyLimitMutation, TError, SetConcurrencyLimitMutationVariables, TContext>({
    mutationKey: ["SetConcurrencyLimit"],
    mutationFn: (variables: SetConcurrencyLimitMutationVariables) =>
      graphqlFetcher<SetConcurrencyLimitMutation, SetConcurrencyLimitMutationVariables>(SetConcurrencyLimitDocument, variables)(),
    ...options,
  });

// ---------------------------------------------------------------------------
// deleteWorkflow mutation
// ---------------------------------------------------------------------------
export type DeleteWorkflowMutationVariables = Exact<{ id: Scalars["UUID"]["input"] }>;
export type DeleteWorkflowMutation = { __typename?: "MutationRoot"; deleteWorkflow: boolean };
const DeleteWorkflowDocument = `
  mutation DeleteWorkflow($id: UUID!) {
    deleteWorkflow(id: $id)
  }
`;
export const useDeleteWorkflowMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<DeleteWorkflowMutation, TError, DeleteWorkflowMutationVariables, TContext>,
) =>
  useMutation<DeleteWorkflowMutation, TError, DeleteWorkflowMutationVariables, TContext>({
    mutationKey: ["DeleteWorkflow"],
    mutationFn: (variables: DeleteWorkflowMutationVariables) =>
      graphqlFetcher<DeleteWorkflowMutation, DeleteWorkflowMutationVariables>(DeleteWorkflowDocument, variables)(),
    ...options,
  });

// ---------------------------------------------------------------------------
// testWorkflow mutation
// ---------------------------------------------------------------------------
export type TestWorkflowMutationVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
  mockInputs?: InputMaybe<Scalars["String"]["input"]>;
}>;
export type TestWorkflowMutation = {
  __typename?: "MutationRoot";
  testWorkflow: {
    __typename?: "TestWorkflowResult";
    executionId: string;
    status: string;
    durationMs: number;
    error?: string | null;
    schemaWarnings: Array<string>;
    nodeTraces: Array<{
      __typename?: "TestNodeTrace";
      nodeId: string;
      status: string;
      input: string;
      output?: string | null;
      error?: string | null;
    }>;
  };
};
const TestWorkflowDocument = `
  mutation TestWorkflow($workflowId: UUID!, $mockInputs: String) {
    testWorkflow(workflowId: $workflowId, mockInputs: $mockInputs) {
      executionId
      status
      durationMs
      error
      schemaWarnings
      nodeTraces {
        nodeId
        status
        input
        output
        error
      }
    }
  }
`;
export const useTestWorkflowMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<TestWorkflowMutation, TError, TestWorkflowMutationVariables, TContext>,
) =>
  useMutation<TestWorkflowMutation, TError, TestWorkflowMutationVariables, TContext>({
    mutationKey: ["TestWorkflow"],
    mutationFn: (variables: TestWorkflowMutationVariables) =>
      graphqlFetcher<TestWorkflowMutation, TestWorkflowMutationVariables>(TestWorkflowDocument, variables)(),
    ...options,
  });

// ---------------------------------------------------------------------------
// updateSecret
// ---------------------------------------------------------------------------
export type UpdateSecretMutationVariables = Exact<{
  input: UpdateSecretInput;
}>;
export type UpdateSecretMutation = { __typename?: "MutationRoot"; updateSecret: { __typename?: "Secret"; id: string; name: string; keyPath: string } };
const UpdateSecretDocument = `
  mutation UpdateSecret($input: UpdateSecretInput!) {
    updateSecret(input: $input) {
      id
      name
      keyPath
    }
  }
`;
export const useUpdateSecretMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<UpdateSecretMutation, TError, UpdateSecretMutationVariables, TContext>,
) =>
  useMutation<UpdateSecretMutation, TError, UpdateSecretMutationVariables, TContext>({
    mutationKey: ["UpdateSecret"],
    mutationFn: (variables: UpdateSecretMutationVariables) =>
      graphqlFetcher<UpdateSecretMutation, UpdateSecretMutationVariables>(UpdateSecretDocument, variables)(),
    ...options,
  });

// ---------------------------------------------------------------------------
// webhookTriggers query
// ---------------------------------------------------------------------------
export type WebhookTriggersQueryVariables = Exact<{ [key: string]: never }>;
export type WebhookTriggersQuery = {
  __typename?: "QueryRoot";
  webhookTriggers: Array<{
    __typename?: "WebhookTrigger";
    id: string;
    name: string;
    webhookUrl: string;
    enabled: boolean;
    triggerCount: number;
    successCount: number;
    errorCount: number;
    maxRequestsPerMinute: number;
    lastTriggeredAt?: string | null;
    verificationToken?: string | null;
  }>;
};
const WebhookTriggersDocument = `
  query WebhookTriggers {
    webhookTriggers {
      id
      name
      webhookUrl
      enabled
      triggerCount
      successCount
      errorCount
      maxRequestsPerMinute
      lastTriggeredAt
      verificationToken
    }
  }
`;
export const useWebhookTriggersQuery = <TData = WebhookTriggersQuery, TError = unknown>(
  variables?: WebhookTriggersQueryVariables,
  options?: Omit<UseQueryOptions<WebhookTriggersQuery, TError, TData>, "queryKey"> & { queryKey?: UseQueryOptions<WebhookTriggersQuery, TError, TData>["queryKey"] },
) =>
  useQuery<WebhookTriggersQuery, TError, TData>({
    queryKey: variables === undefined ? ["WebhookTriggers"] : ["WebhookTriggers", variables],
    queryFn: graphqlFetcher<WebhookTriggersQuery, WebhookTriggersQueryVariables>(WebhookTriggersDocument, variables),
    ...options,
  });

// ---------------------------------------------------------------------------
// createWebhookTrigger mutation
// ---------------------------------------------------------------------------
export type CreateWebhookTriggerMutationVariables = Exact<{
  input: CreateWebhookTriggerInput;
}>;
export type CreateWebhookTriggerMutation = {
  __typename?: "MutationRoot";
  createWebhookTrigger: {
    __typename?: "WebhookTrigger";
    id: string;
    name: string;
    webhookUrl: string;
    verificationToken?: string | null;
  };
};
const CreateWebhookTriggerDocument = `
  mutation CreateWebhookTrigger($input: CreateWebhookTriggerInput!) {
    createWebhookTrigger(input: $input) {
      id
      name
      webhookUrl
      verificationToken
    }
  }
`;
export const useCreateWebhookTriggerMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<CreateWebhookTriggerMutation, TError, CreateWebhookTriggerMutationVariables, TContext>,
) =>
  useMutation<CreateWebhookTriggerMutation, TError, CreateWebhookTriggerMutationVariables, TContext>({
    mutationKey: ["CreateWebhookTrigger"],
    mutationFn: (variables: CreateWebhookTriggerMutationVariables) =>
      graphqlFetcher<CreateWebhookTriggerMutation, CreateWebhookTriggerMutationVariables>(CreateWebhookTriggerDocument, variables)(),
    ...options,
  });

// ---------------------------------------------------------------------------
// nodeTemplates query
// ---------------------------------------------------------------------------
export type NodeTemplatesQueryVariables = Exact<{
  category?: InputMaybe<Scalars["String"]["input"]>;
}>;
export type NodeTemplatesQuery = {
  __typename?: "QueryRoot";
  nodeTemplates: Array<{
    __typename?: "NodeTemplate";
    id: string;
    name: string;
    category: string;
    description?: string | null;
    icon?: string | null;
    allowedHosts: Array<string>;
  }>;
};
const NodeTemplatesDocument = `
  query NodeTemplates($category: String) {
    nodeTemplates(category: $category) {
      id
      name
      category
      description
      icon
      allowedHosts
    }
  }
`;
export const useNodeTemplatesQuery = <TData = NodeTemplatesQuery, TError = unknown>(
  variables?: NodeTemplatesQueryVariables,
  options?: Omit<UseQueryOptions<NodeTemplatesQuery, TError, TData>, "queryKey"> & { queryKey?: UseQueryOptions<NodeTemplatesQuery, TError, TData>["queryKey"] },
) =>
  useQuery<NodeTemplatesQuery, TError, TData>({
    queryKey: variables === undefined ? ["NodeTemplates"] : ["NodeTemplates", variables],
    queryFn: graphqlFetcher<NodeTemplatesQuery, NodeTemplatesQueryVariables>(NodeTemplatesDocument, variables),
    ...options,
  });

// ---------------------------------------------------------------------------
// createModuleFromTemplate mutation
// ---------------------------------------------------------------------------
export type CreateModuleFromTemplateMutationVariables = Exact<{
  input: CreateModuleInput;
}>;
export type CreateModuleFromTemplateMutation = {
  __typename?: "MutationRoot";
  createModuleFromTemplate: {
    __typename?: "WasmModule";
    id: string;
    config: string;
  };
};
const CreateModuleFromTemplateDocument = `
  mutation CreateModuleFromTemplate($input: CreateModuleInput!) {
    createModuleFromTemplate(input: $input) {
      id
      config
    }
  }
`;
export const useCreateModuleFromTemplateMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<CreateModuleFromTemplateMutation, TError, CreateModuleFromTemplateMutationVariables, TContext>,
) =>
  useMutation<CreateModuleFromTemplateMutation, TError, CreateModuleFromTemplateMutationVariables, TContext>({
    mutationKey: ["CreateModuleFromTemplate"],
    mutationFn: (variables: CreateModuleFromTemplateMutationVariables) =>
      graphqlFetcher<CreateModuleFromTemplateMutation, CreateModuleFromTemplateMutationVariables>(CreateModuleFromTemplateDocument, variables)(),
    ...options,
  });

// ---------------------------------------------------------------------------
// getAllWorkflowStats query
// ---------------------------------------------------------------------------
export type GetAllWorkflowStatsQueryVariables = Exact<{
  days?: InputMaybe<Scalars["Int"]["input"]>;
}>;
export type GetAllWorkflowStatsQuery = {
  __typename?: "QueryRoot";
  getAllWorkflowStats: Array<{
    __typename?: "WorkflowStats";
    id: string;
    name: string;
    total: number;
    succeeded: number;
    failed: number;
    avgDurationSecs?: number | null;
  }>;
};
const GetAllWorkflowStatsDocument = `
  query GetAllWorkflowStats($days: Int) {
    getAllWorkflowStats(days: $days) {
      id
      name
      total
      succeeded
      failed
      avgDurationSecs
    }
  }
`;
export const useGetAllWorkflowStatsQuery = <TData = GetAllWorkflowStatsQuery, TError = unknown>(
  variables?: GetAllWorkflowStatsQueryVariables,
  options?: Omit<UseQueryOptions<GetAllWorkflowStatsQuery, TError, TData>, "queryKey"> & { queryKey?: UseQueryOptions<GetAllWorkflowStatsQuery, TError, TData>["queryKey"] },
) =>
  useQuery<GetAllWorkflowStatsQuery, TError, TData>({
    queryKey: variables === undefined ? ["GetAllWorkflowStats"] : ["GetAllWorkflowStats", variables],
    queryFn: graphqlFetcher<GetAllWorkflowStatsQuery, GetAllWorkflowStatsQueryVariables>(GetAllWorkflowStatsDocument, variables),
    ...options,
  });

// ---------------------------------------------------------------------------
// getVersionDiffSummary query
// ---------------------------------------------------------------------------
export type GetVersionDiffSummaryQueryVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
}>;
export type GetVersionDiffSummaryQuery = {
  __typename?: "QueryRoot";
  getVersionDiffSummary: {
    __typename?: "VersionDiffSummary";
    hasPublishedVersion: boolean;
    nodesAdded: number;
    nodesChanged: number;
    nodesRemoved: number;
    edgesAdded: number;
    edgesRemoved: number;
    summary: string;
  };
};
const GetVersionDiffSummaryDocument = `
  query GetVersionDiffSummary($workflowId: UUID!) {
    getVersionDiffSummary(workflowId: $workflowId) {
      hasPublishedVersion
      nodesAdded
      nodesChanged
      nodesRemoved
      edgesAdded
      edgesRemoved
      summary
    }
  }
`;
export const useGetVersionDiffSummaryQuery = <TData = GetVersionDiffSummaryQuery, TError = unknown>(
  variables: GetVersionDiffSummaryQueryVariables,
  options?: Omit<UseQueryOptions<GetVersionDiffSummaryQuery, TError, TData>, "queryKey"> & { queryKey?: UseQueryOptions<GetVersionDiffSummaryQuery, TError, TData>["queryKey"] },
) =>
  useQuery<GetVersionDiffSummaryQuery, TError, TData>({
    queryKey: ["GetVersionDiffSummary", variables],
    queryFn: graphqlFetcher<GetVersionDiffSummaryQuery, GetVersionDiffSummaryQueryVariables>(GetVersionDiffSummaryDocument, variables),
    ...options,
  });

// ---------------------------------------------------------------------------
// getWorkflowChangelog query
// ---------------------------------------------------------------------------
export type GetWorkflowChangelogQueryVariables = Exact<{
  workflowId: Scalars["UUID"]["input"];
}>;
export type GetWorkflowChangelogQuery = {
  __typename?: "QueryRoot";
  getWorkflowChangelog: Array<{
    __typename?: "ChangelogEntry";
    versionNumber: number;
    summary: string;
    description?: string | null;
    publishedAt: string;
  }>;
};
const GetWorkflowChangelogDocument = `
  query GetWorkflowChangelog($workflowId: UUID!) {
    getWorkflowChangelog(workflowId: $workflowId) {
      versionNumber
      summary
      description
      publishedAt
    }
  }
`;
export const useGetWorkflowChangelogQuery = <TData = GetWorkflowChangelogQuery, TError = unknown>(
  variables: GetWorkflowChangelogQueryVariables,
  options?: Omit<UseQueryOptions<GetWorkflowChangelogQuery, TError, TData>, "queryKey"> & { queryKey?: UseQueryOptions<GetWorkflowChangelogQuery, TError, TData>["queryKey"] },
) =>
  useQuery<GetWorkflowChangelogQuery, TError, TData>({
    queryKey: ["GetWorkflowChangelog", variables],
    queryFn: graphqlFetcher<GetWorkflowChangelogQuery, GetWorkflowChangelogQueryVariables>(GetWorkflowChangelogDocument, variables),
    ...options,
  });

// ---------------------------------------------------------------------------
// myModules query — list the current user's installed WASM modules
// ---------------------------------------------------------------------------

export type MyModulesQueryVariables = Exact<{
  limit?: InputMaybe<Scalars["Int"]["input"]>;
  offset?: InputMaybe<Scalars["Int"]["input"]>;
}>;

export type MyModulesQuery = {
  __typename?: "QueryRoot";
  myModules: Array<{
    __typename?: "WasmModule";
    id: any;
    name: string;
    capabilityWorld?: string | null;
    language?: string | null;
    sizeBytes: number;
    compiledAt: string;
    contentHash: string;
    capabilityDescription?: string | null;
    importedInterfaces?: Array<string> | null;
    config: string;
  }>;
};

export const MyModulesDocument = `
    query MyModules($limit: Int, $offset: Int) {
  myModules(pagination: {limit: $limit, offset: $offset}) {
    id
    name
    capabilityWorld
    language
    sizeBytes
    compiledAt
    contentHash
    capabilityDescription
    importedInterfaces
    config
  }
}
    `;

export const useMyModulesQuery = <TData = MyModulesQuery, TError = unknown>(
  variables?: MyModulesQueryVariables,
  options?: Omit<UseQueryOptions<MyModulesQuery, TError, TData>, "queryKey"> & {
    queryKey?: UseQueryOptions<MyModulesQuery, TError, TData>["queryKey"];
  },
) =>
  useQuery<MyModulesQuery, TError, TData>({
    queryKey: variables === undefined ? ["MyModules"] : ["MyModules", variables],
    queryFn: graphqlFetcher<MyModulesQuery, MyModulesQueryVariables>(MyModulesDocument, variables),
    ...options,
  });
