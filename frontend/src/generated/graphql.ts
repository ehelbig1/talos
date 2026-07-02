/** Internal type. DO NOT USE DIRECTLY. */
type Exact<T extends { [key: string]: unknown }> = { [K in keyof T]: T[K] };
/** Internal type. DO NOT USE DIRECTLY. */
export type Incremental<T> =
  | T
  | {
      [P in keyof T]?: P extends " $fragmentName" | "__typename" ? T[P] : never;
    };
import { DocumentTypeDecoration } from "@graphql-typed-document-node/core";
import {
  useQuery,
  useMutation,
  UseQueryOptions,
  UseMutationOptions,
} from "@tanstack/react-query";
import { graphqlFetcher } from "@/lib/graphqlClient";
export * from "./schema";
export type AnalyzeRhaiInput = {
  script: string;
};

/** Input type for createActor mutation. */
export type CreateActorInput = {
  description?: string | null | undefined;
  maxCapabilityWorld?: string | null | undefined;
  name: string;
  /** Per-minute execution rate limit (informational — reserved for future enforcement). */
  rateLimit?: number | null | undefined;
  /** Lifetime budget cap in USD (informational — enforcement via budget policies). */
  totalBudgetUsd?: number | null | undefined;
};

export type CreateApiKeyInput = {
  expiresInDays?: number | null | undefined;
  name: string;
  scopes: Array<string>;
};

export type CreateModuleInput = {
  config: string;
  jobId?: string | null | undefined;
  name: string;
  templateId: string;
};

export type CreateSecretInput = {
  allowedModules?: Array<string> | null | undefined;
  description?: string | null | undefined;
  keyPath: string;
  name: string;
  /**
   * Optional organization to assign the secret to. When set, all org
   * members can access this secret.
   */
  orgId?: string | null | undefined;
  value: string;
};

export type CreateWebhookTriggerInput = {
  allowedIps?: Array<string> | null | undefined;
  enabled?: boolean | null | undefined;
  /**
   * RFC 0007: optional provider-agnostic event filter, evaluated AFTER
   * signature verification. A non-matching delivery is acknowledged 200 with
   * no dispatch (so it doesn't burn an execution). Omit to fire on every
   * verified delivery. Shape (validated via `talos_webhooks::validate_event_filter`):
   * `{ "header": "X-GitHub-Event", "values": ["pull_request"],
   * "payload_match": { "action": ["opened","synchronize","reopened"] } }`.
   */
  eventFilter?: unknown;
  maxRequestsPerMinute?: number | null | undefined;
  moduleId: string;
  name: string;
  signingSecret?: string | null | undefined;
  verificationToken?: string | null | undefined;
};

export type Enable2FaInput = {
  code: string;
  secret: string;
};

export type IntegrationService = "GMAIL" | "GOOGLE_CALENDAR" | "JIRA" | "SLACK";

/** Pagination input for list queries */
export type PaginationInput = {
  /** Maximum number of items to return (default: 100, max: 1000) */
  limit?: number | null | undefined;
  /** Number of items to skip (default: 0) */
  offset?: number | null | undefined;
};

export type TestRhaiExpressionInput = {
  mockContext: string;
  script: string;
};

/** Input for updating organization resource quotas. */
export type UpdateResourceQuotasInput = {
  concurrentExecutions?: number | null | undefined;
  cpuCores?: number | null | undefined;
  memoryGb?: number | null | undefined;
  storageGb?: number | null | undefined;
};

export type UpdateSecretInput = {
  keyPath: string;
  value: string;
};

export type WriteActorMemoryInput = {
  actorId: string;
  key: string;
  /** "working" | "episodic" | "semantic" | "scratchpad". Default: "working". */
  memoryType?: string | null | undefined;
  /** Custom TTL in hours. Overrides memory_type default. Null = use type default. */
  ttlHours?: number | null | undefined;
  /** JSON value to store. */
  value: string;
};

export type GetModuleExecutionHistoryQueryVariables = Exact<{
  moduleId: string;
  pagination?: PaginationInput | null | undefined;
}>;

export type GetModuleExecutionHistoryQuery = {
  moduleExecutionHistory: Array<{
    id: string;
    status: string;
    durationMs: number | null;
    startedAt: string;
    errorMessage: string | null;
    outputData: string | null;
  }>;
};

export type GetModuleExecutionLogsQueryVariables = Exact<{
  executionId: string;
}>;

export type GetModuleExecutionLogsQuery = {
  moduleExecutionLogs: Array<{
    id: string;
    level: string;
    message: string;
    createdAt: string;
    metadata: string | null;
  }>;
};

export type GetSecretAuditLogQueryVariables = Exact<{
  secretId: string;
  limit?: number | null | undefined;
}>;

export type GetSecretAuditLogQuery = {
  secretAuditLog: Array<{
    id: string;
    action: string;
    actorType: string;
    success: boolean;
    timestamp: string;
    errorMessage: string | null;
  }>;
};

export type CreateSecretMutationVariables = Exact<{
  input: CreateSecretInput;
}>;

export type CreateSecretMutation = {
  createSecret: { id: string; name: string; keyPath: string };
};

export type GetSecretsQueryVariables = Exact<{
  pagination?: PaginationInput | null | undefined;
}>;

export type GetSecretsQuery = {
  secrets: Array<{
    id: string;
    name: string;
    keyPath: string;
    description: string | null;
    createdAt: string;
    lastAccessedAt: string | null;
    accessCount: number;
    expiresAt: string | null;
  }>;
};

export type DeleteSecretMutationVariables = Exact<{
  keyPath: string;
}>;

export type DeleteSecretMutation = { deleteSecret: boolean };

export type RotateEncryptionKeyMutationVariables = Exact<{
  [key: string]: never;
}>;

export type RotateEncryptionKeyMutation = { rotateEncryptionKey: number };

export type ListApiKeysQueryVariables = Exact<{
  pagination?: PaginationInput | null | undefined;
}>;

export type ListApiKeysQuery = {
  apiKeys: Array<{
    id: string;
    name: string;
    keyPrefix: string;
    scopes: Array<string>;
    createdAt: string;
    expiresAt: string | null;
    lastUsedAt: string | null;
    isActive: boolean;
    usageCount: number;
  }>;
};

export type CreateApiKeyMutationVariables = Exact<{
  input: CreateApiKeyInput;
}>;

export type CreateApiKeyMutation = {
  createApiKey: {
    id: string;
    name: string;
    key: string;
    scopes: Array<string>;
    expiresAt: string | null;
  };
};

export type RevokeApiKeyMutationVariables = Exact<{
  keyId: string;
}>;

export type RevokeApiKeyMutation = { revokeApiKey: boolean };

export type RotateApiKeyMutationVariables = Exact<{
  keyId: string;
}>;

export type RotateApiKeyMutation = {
  rotateApiKey: {
    id: string;
    name: string;
    key: string;
    scopes: Array<string>;
    expiresAt: string | null;
  };
};

export type DeleteApiKeyMutationVariables = Exact<{
  keyId: string;
}>;

export type DeleteApiKeyMutation = { deleteApiKey: boolean };

export type GetDeadLetterQueueQueryVariables = Exact<{ [key: string]: never }>;

export type GetDeadLetterQueueQuery = {
  deadLetterQueue: Array<{
    id: string;
    workflowId: string;
    executionId: string;
    nodeId: string;
    errorMessage: string;
    payload: string | null;
    createdAt: string;
    replayedAt: string | null;
    replayedBy: string | null;
  }>;
};

export type GetWebhookDeadLetterQueueQueryVariables = Exact<{
  [key: string]: never;
}>;

export type GetWebhookDeadLetterQueueQuery = {
  webhookDeadLetterQueue: Array<{
    id: string;
    triggerId: string | null;
    dropReason: string;
    headers: string | null;
    payload: string | null;
    sourceIp: string | null;
    createdAt: string;
    replayedAt: string | null;
    replayedBy: string | null;
  }>;
};

export type ReplayDeadLetterEntryMutationVariables = Exact<{
  id: string;
}>;

export type ReplayDeadLetterEntryMutation = { replayDeadLetterEntry: boolean };

export type ReplayWebhookDeadLetterEntryMutationVariables = Exact<{
  id: string;
}>;

export type ReplayWebhookDeadLetterEntryMutation = {
  replayWebhookDeadLetterEntry: boolean;
};

export type RegisterMcpAgentMutationVariables = Exact<{
  name: string;
  role: string;
}>;

export type RegisterMcpAgentMutation = {
  registerMcpAgent: {
    agentId: string;
    name: string;
    token: string;
    role: string;
  };
};

export type ListLinkedAccountsQueryVariables = Exact<{ [key: string]: never }>;

export type ListLinkedAccountsQuery = {
  linkedOauthAccounts: Array<{
    id: string;
    provider: string;
    email: string;
    name: string | null;
    pictureUrl: string | null;
    linkedAt: string;
    lastLoginAt: string | null;
  }>;
};

export type GetOAuthUrlQueryVariables = Exact<{
  provider: string;
}>;

export type GetOAuthUrlQuery = { oauthLoginUrl: { authUrl: string } };

export type UnlinkOAuthMutationVariables = Exact<{
  provider: string;
}>;

export type UnlinkOAuthMutation = { unlinkOauthAccount: boolean };

export type ListOrgsQueryVariables = Exact<{ [key: string]: never }>;

export type ListOrgsQuery = {
  myOrganizations: Array<{
    id: string;
    name: string;
    slug: string;
    ownerId: string;
    createdAt: string;
    updatedAt: string;
  }>;
};

export type ListOrgMembersQueryVariables = Exact<{
  orgId: string;
}>;

export type ListOrgMembersQuery = {
  organizationMembers: Array<{
    id: string;
    orgId: string;
    userId: string;
    role: string;
    invitedBy: string | null;
    joinedAt: string;
  }>;
};

export type CreateOrgMutationVariables = Exact<{
  name: string;
  slug: string;
}>;

export type CreateOrgMutation = {
  createOrganization: { id: string; name: string };
};

export type RemoveMemberMutationVariables = Exact<{
  orgId: string;
  userId: string;
}>;

export type RemoveMemberMutation = { removeMember: boolean };

export type InviteMemberMutationVariables = Exact<{
  orgId: string;
  targetUserId: string;
  role: string;
}>;

export type InviteMemberMutation = {
  inviteMember: {
    id: string;
    orgId: string;
    userId: string;
    role: string;
    invitedBy: string | null;
    joinedAt: string;
  };
};

export type UpdateMemberRoleMutationVariables = Exact<{
  orgId: string;
  targetUserId: string;
  role: string;
}>;

export type UpdateMemberRoleMutation = {
  updateMemberRole: {
    id: string;
    orgId: string;
    userId: string;
    role: string;
    joinedAt: string;
  };
};

export type TransferOwnershipMutationVariables = Exact<{
  orgId: string;
  newOwnerId: string;
}>;

export type TransferOwnershipMutation = {
  transferOwnership: { id: string; name: string; ownerId: string };
};

export type Setup2FaMutationVariables = Exact<{ [key: string]: never }>;

export type Setup2FaMutation = {
  setupTwoFactor: { secret: string; qrCodeUrl: string; qrCodePng: string };
};

export type Enable2FaMutationVariables = Exact<{
  input: Enable2FaInput;
}>;

export type Enable2FaMutation = {
  enableTwoFactor: { backupCodes: Array<string> };
};

export type Disable2FaMutationVariables = Exact<{ [key: string]: never }>;

export type Disable2FaMutation = { disableTwoFactor: boolean };

export type ListActorSummariesQueryVariables = Exact<{ [key: string]: never }>;

export type ListActorSummariesQuery = {
  actors: Array<{
    id: string;
    name: string;
    description: string | null;
    status: string;
    maxCapabilityWorld: string;
    totalBudgetUsd: number | null;
    spentBudgetUsd: number;
    workflowCount: number;
    executionCount: number;
    createdAt: string;
    updatedAt: string;
  }>;
};

export type GetActorQueryVariables = Exact<{
  id: string;
}>;

export type GetActorQuery = {
  actor: {
    id: string;
    name: string;
    description: string | null;
    status: string;
    maxCapabilityWorld: string;
    totalBudgetUsd: number | null;
    spentBudgetUsd: number;
    workflowCount: number;
    executionCount: number;
    createdAt: string;
    updatedAt: string;
    mcpToken: string | null;
    rateLimit: number | null;
    metadata: string | null;
    lastActiveAt: string | null;
  } | null;
};

export type CreateActorMutationVariables = Exact<{
  input: CreateActorInput;
}>;

export type CreateActorMutation = {
  createActor: {
    id: string;
    name: string;
    description: string | null;
    status: string;
    maxCapabilityWorld: string;
    totalBudgetUsd: number | null;
    spentBudgetUsd: number;
    workflowCount: number;
    executionCount: number;
    createdAt: string;
    updatedAt: string;
  };
};

export type UpdateActorStatusMutationVariables = Exact<{
  id: string;
  status: string;
}>;

export type UpdateActorStatusMutation = {
  updateActorStatus: {
    id: string;
    name: string;
    description: string | null;
    status: string;
    maxCapabilityWorld: string;
    totalBudgetUsd: number | null;
    spentBudgetUsd: number;
    workflowCount: number;
    executionCount: number;
    createdAt: string;
    updatedAt: string;
  };
};

export type TerminateActorMutationVariables = Exact<{
  id: string;
  cleanupWorkflows?: boolean | null | undefined;
}>;

export type TerminateActorMutation = { terminateActor: boolean };

export type GetActorActionLogQueryVariables = Exact<{
  actorId: string;
  limit?: number | null | undefined;
}>;

export type GetActorActionLogQuery = {
  actorActionLog: Array<{
    id: string;
    actionType: string;
    summary: string;
    timestamp: string;
    workflowId: string | null;
    executionId: string | null;
  }>;
};

export type GetActorWorkflowsQueryVariables = Exact<{
  actorId: string;
}>;

export type GetActorWorkflowsQuery = {
  actorWorkflows: Array<{
    id: string;
    name: string;
    status: string | null;
    nodeCount: number;
    graphJson: string | null;
    createdAt: string;
    updatedAt: string;
  }>;
};

export type GetActorExecutionsSummaryQueryVariables = Exact<{
  actorId: string;
}>;

export type GetActorExecutionsSummaryQuery = {
  actorExecutionsSummary: {
    totalExecutions: number;
    successfulExecutions: number;
    failedExecutions: number;
    activeExecutions: number;
  };
};

export type UpdateActorMutationVariables = Exact<{
  id: string;
  name?: string | null | undefined;
  description?: string | null | undefined;
  maxCapabilityWorld?: string | null | undefined;
}>;

export type UpdateActorMutation = {
  updateActor: {
    id: string;
    name: string;
    description: string | null;
    status: string;
    maxCapabilityWorld: string;
    workflowCount: number;
    executionCount: number;
    createdAt: string;
    updatedAt: string;
  };
};

export type CloneActorMutationVariables = Exact<{
  id: string;
  name?: string | null | undefined;
}>;

export type CloneActorMutation = {
  cloneActor: {
    id: string;
    name: string;
    description: string | null;
    status: string;
    maxCapabilityWorld: string;
    workflowCount: number;
    executionCount: number;
    createdAt: string;
    updatedAt: string;
  };
};

export type GetActorMemoriesQueryVariables = Exact<{
  actorId: string;
  memoryType?: string | null | undefined;
}>;

export type GetActorMemoriesQuery = {
  actorMemories: Array<{
    key: string;
    value: string;
    memoryType: string;
    expiresAt: string | null;
    updatedAt: string;
  }>;
};

export type WriteActorMemoryMutationVariables = Exact<{
  input: WriteActorMemoryInput;
}>;

export type WriteActorMemoryMutation = {
  writeActorMemory: {
    key: string;
    value: string;
    memoryType: string;
    expiresAt: string | null;
    updatedAt: string;
  };
};

export type DeleteActorMemoryMutationVariables = Exact<{
  actorId: string;
  key: string;
}>;

export type DeleteActorMemoryMutation = { deleteActorMemory: boolean };

export type GetMyCapabilityCeilingQueryVariables = Exact<{
  [key: string]: never;
}>;

export type GetMyCapabilityCeilingQuery = { myCapabilityCeiling: string };

export type GetAllWorkflowStatsQueryVariables = Exact<{
  days?: number | null | undefined;
}>;

export type GetAllWorkflowStatsQuery = {
  getAllWorkflowStats: Array<{
    id: string;
    name: string;
    total: number;
    succeeded: number;
    failed: number;
    avgDurationSecs: number | null;
  }>;
};

export type GetApprovalsQueryVariables = Exact<{ [key: string]: never }>;

export type GetApprovalsQuery = {
  pendingApprovals: Array<{
    id: string;
    workflowId: string;
    executionId: string;
    nodeId: string;
    requiredFor: Array<string>;
    status: string;
    requestedAt: string;
    decidedAt: string | null;
    decidedBy: string | null;
    reason: string | null;
  }>;
};

export type ApproveExecutionMutationVariables = Exact<{
  id: string;
  reason?: string | null | undefined;
}>;

export type ApproveExecutionMutation = { approveExecution: boolean };

export type DenyExecutionMutationVariables = Exact<{
  id: string;
  reason?: string | null | undefined;
}>;

export type DenyExecutionMutation = { denyExecution: boolean };

export type GetAuditSettingsQueryVariables = Exact<{ [key: string]: never }>;

export type GetAuditSettingsQuery = {
  auditSettings: {
    streamingEnabled: boolean;
    otlpEndpoint: string | null;
    otlpProtocol: string | null;
    updatedAt: string;
    createdAt: string;
  } | null;
};

export type UpdateAuditSettingsMutationVariables = Exact<{
  enabled: boolean;
  endpoint?: string | null | undefined;
  protocol: string;
  headers?: string | null | undefined;
}>;

export type UpdateAuditSettingsMutation = {
  updateAuditSettings: {
    streamingEnabled: boolean;
    otlpEndpoint: string | null;
    otlpProtocol: string | null;
    updatedAt: string;
  };
};

export type GetResourceQuotasQueryVariables = Exact<{ [key: string]: never }>;

export type GetResourceQuotasQuery = {
  resourceQuotas: {
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
  updateResourceQuotas: {
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

export type RotateDekMutationVariables = Exact<{ [key: string]: never }>;

export type RotateDekMutation = {
  rotateDek: { newDekId: string; message: string };
};

export type ReEncryptSecretsMutationVariables = Exact<{ [key: string]: never }>;

export type ReEncryptSecretsMutation = {
  reEncryptSecrets: { reEncryptedCount: number; message: string };
};

export type RotateMasterKeyMutationVariables = Exact<{
  newMasterKey: string;
}>;

export type RotateMasterKeyMutation = {
  rotateMasterKey: { reEncryptedDekCount: number; message: string };
};

export type UpdateSecretMutationVariables = Exact<{
  input: UpdateSecretInput;
}>;

export type UpdateSecretMutation = {
  updateSecret: { id: string; name: string; keyPath: string };
};

export type GetCapabilityCeilingDetailQueryVariables = Exact<{
  [key: string]: never;
}>;

export type GetCapabilityCeilingDetailQuery = {
  capabilityCeilingDetail: {
    ceiling: string;
    source: string;
    grantedByEmail: string | null;
    grantedAt: string | null;
    notes: string | null;
  };
};

export type GetCapabilityWorldHierarchyQueryVariables = Exact<{
  [key: string]: never;
}>;

export type GetCapabilityWorldHierarchyQuery = {
  capabilityWorldHierarchy: Array<{
    name: string;
    rank: number;
    description: string;
  }>;
};

export type RevokeCapabilityCeilingMutationVariables = Exact<{
  userId: string;
}>;

export type RevokeCapabilityCeilingMutation = {
  revokeCapabilityCeiling: boolean;
};

export type GetCurrentUserIdQueryVariables = Exact<{ [key: string]: never }>;

export type GetCurrentUserIdQuery = { me: { id: string } };

export type ListServiceIntegrationsQueryVariables = Exact<{
  [key: string]: never;
}>;

export type ListServiceIntegrationsQuery = {
  serviceIntegrations: Array<{
    id: string;
    service: IntegrationService;
    accountIdentifier: string;
    connectedAt: string;
    status: string;
  }>;
};

export type DisconnectServiceIntegrationMutationVariables = Exact<{
  id: string;
  service: IntegrationService;
}>;

export type DisconnectServiceIntegrationMutation = {
  disconnectServiceIntegration: boolean;
};

export type ListMcpAgentsQueryVariables = Exact<{ [key: string]: never }>;

export type ListMcpAgentsQuery = {
  mcpAgents: Array<{
    id: string;
    name: string;
    createdAt: string;
    lastUsedAt: string | null;
  }>;
};

export type RevokeMcpAgentMutationVariables = Exact<{
  id: string;
}>;

export type RevokeMcpAgentMutation = { revokeMcpAgent: boolean };

export type MyModulesQueryVariables = Exact<{
  limit?: number | null | undefined;
  offset?: number | null | undefined;
}>;

export type MyModulesQuery = {
  myModules: Array<{
    id: string;
    name: string;
    capabilityWorld: string | null;
    language: string | null;
    sizeBytes: number;
    compiledAt: string;
    contentHash: string;
    capabilityDescription: string | null;
    importedInterfaces: Array<string> | null;
    config: string;
  }>;
};

export type CreateModuleFromTemplateMutationVariables = Exact<{
  input: CreateModuleInput;
}>;

export type CreateModuleFromTemplateMutation = {
  createModuleFromTemplate: { id: string; name: string; config: string };
};

export type NodeTemplatesQueryVariables = Exact<{
  category?: string | null | undefined;
}>;

export type NodeTemplatesQuery = {
  nodeTemplates: Array<{
    id: string;
    name: string;
    category: string;
    description: string | null;
    icon: string | null;
    allowedHosts: Array<string>;
  }>;
};

export type GetNodeTemplatesQueryVariables = Exact<{
  category?: string | null | undefined;
}>;

export type GetNodeTemplatesQuery = {
  nodeTemplates: Array<{
    id: string;
    name: string;
    category: string;
    description: string | null;
    configSchema: string;
    icon: string | null;
    allowedHosts: Array<string>;
  }>;
};

export type GetNodeTemplateQueryVariables = Exact<{
  id: string;
}>;

export type GetNodeTemplateQuery = {
  nodeTemplate: {
    id: string;
    name: string;
    category: string;
    description: string | null;
    configSchema: string;
    icon: string | null;
  };
};

export type AnalyzeRhaiQueryVariables = Exact<{
  input: AnalyzeRhaiInput;
}>;

export type AnalyzeRhaiQuery = {
  analyzeRhai: {
    success: boolean;
    errors: Array<{
      line: number | null;
      column: number | null;
      endLine: number | null;
      endColumn: number | null;
      message: string;
      severity: string;
    }>;
  };
};

export type TestRhaiExpressionQueryVariables = Exact<{
  input: TestRhaiExpressionInput;
}>;

export type TestRhaiExpressionQuery = {
  testRhaiExpression: {
    success: boolean;
    output: string | null;
    error: string | null;
  };
};

export type MySchedulesQueryVariables = Exact<{ [key: string]: never }>;

export type MySchedulesQuery = {
  mySchedules: Array<{
    id: string;
    workflowId: string;
    cronExpression: string;
    timezone: string;
    isEnabled: boolean;
    lastTriggeredAt: string | null;
    nextTriggerAt: string | null;
    createdAt: string;
    updatedAt: string;
  }>;
};

export type CreateScheduleMutationVariables = Exact<{
  workflowId: string;
  cronExpression: string;
  timezone?: string | null | undefined;
}>;

export type CreateScheduleMutation = {
  createSchedule: {
    id: string;
    workflowId: string;
    cronExpression: string;
    timezone: string;
    isEnabled: boolean;
    nextTriggerAt: string | null;
    createdAt: string;
    updatedAt: string;
  };
};

export type UpdateScheduleMutationVariables = Exact<{
  workflowId: string;
  cronExpression?: string | null | undefined;
  timezone?: string | null | undefined;
  isEnabled?: boolean | null | undefined;
}>;

export type UpdateScheduleMutation = {
  updateSchedule: {
    id: string;
    workflowId: string;
    cronExpression: string;
    timezone: string;
    isEnabled: boolean;
    nextTriggerAt: string | null;
    updatedAt: string;
  };
};

export type DeleteScheduleMutationVariables = Exact<{
  workflowId: string;
}>;

export type DeleteScheduleMutation = { deleteSchedule: boolean };

export type SetConcurrencyLimitMutationVariables = Exact<{
  workflowId: string;
  maxConcurrent?: number | null | undefined;
}>;

export type SetConcurrencyLimitMutation = { setConcurrencyLimit: boolean };

export type DeleteWorkflowMutationVariables = Exact<{
  id: string;
}>;

export type DeleteWorkflowMutation = { deleteWorkflow: boolean };

export type TestWorkflowMutationVariables = Exact<{
  workflowId: string;
  mockInputs?: string | null | undefined;
}>;

export type TestWorkflowMutation = {
  testWorkflow: {
    executionId: string;
    status: string;
    durationMs: number;
    error: string | null;
    schemaWarnings: Array<string>;
    nodeTraces: Array<{
      nodeId: string;
      status: string;
      input: string;
      output: string | null;
      error: string | null;
    }>;
  };
};

export type ResumeWorkflowMutationVariables = Exact<{
  executionId: string;
}>;

export type ResumeWorkflowMutation = { resumeWorkflow: boolean };

export type RetryExecutionMutationVariables = Exact<{
  executionId: string;
}>;

export type RetryExecutionMutation = { retryExecution: string };

export type WorkflowVersionsQueryVariables = Exact<{
  workflowId: string;
  limit?: number | null | undefined;
}>;

export type WorkflowVersionsQuery = {
  workflowVersions: Array<{
    id: string;
    workflowId: string;
    versionNumber: number;
    description: string | null;
    publishedAt: string;
    publishedBy: string;
    isActive: boolean;
    createdAt: string;
  }>;
};

export type PublishWorkflowVersionMutationVariables = Exact<{
  workflowId: string;
  description?: string | null | undefined;
}>;

export type PublishWorkflowVersionMutation = {
  publishWorkflowVersion: {
    id: string;
    workflowId: string;
    versionNumber: number;
    description: string | null;
    publishedAt: string;
    publishedBy: string;
    isActive: boolean;
    createdAt: string;
  };
};

export type RollbackWorkflowVersionMutationVariables = Exact<{
  workflowId: string;
  versionId: string;
}>;

export type RollbackWorkflowVersionMutation = {
  rollbackWorkflowVersion: {
    id: string;
    workflowId: string;
    versionNumber: number;
    description: string | null;
    publishedAt: string;
    isActive: boolean;
    createdAt: string;
  };
};

export type GetVersionDiffSummaryQueryVariables = Exact<{
  workflowId: string;
}>;

export type GetVersionDiffSummaryQuery = {
  getVersionDiffSummary: {
    hasPublishedVersion: boolean;
    nodesAdded: number;
    nodesChanged: number;
    nodesRemoved: number;
    edgesAdded: number;
    edgesRemoved: number;
    summary: string;
  };
};

export type GetWorkflowChangelogQueryVariables = Exact<{
  workflowId: string;
}>;

export type GetWorkflowChangelogQuery = {
  getWorkflowChangelog: Array<{
    versionNumber: number;
    summary: string;
    description: string | null;
    publishedAt: string;
  }>;
};

export type WebhookTriggersQueryVariables = Exact<{ [key: string]: never }>;

export type WebhookTriggersQuery = {
  webhookTriggers: Array<{
    id: string;
    name: string;
    webhookUrl: string;
    enabled: boolean;
    triggerCount: number;
    successCount: number;
    errorCount: number;
    maxRequestsPerMinute: number;
    lastTriggeredAt: string | null;
    verificationToken: string | null;
  }>;
};

export type CreateWebhookTriggerMutationVariables = Exact<{
  input: CreateWebhookTriggerInput;
}>;

export type CreateWebhookTriggerMutation = {
  createWebhookTrigger: {
    id: string;
    name: string;
    webhookUrl: string;
    verificationToken: string | null;
  };
};

export type WorkflowExecutionHistoryQueryVariables = Exact<{
  workflowId: string;
  limit?: number | null | undefined;
  offset?: number | null | undefined;
}>;

export type WorkflowExecutionHistoryQuery = {
  workflowExecutionHistory: Array<{
    id: string;
    workflowId: string;
    status: string;
    startedAt: string;
    completedAt: string | null;
    triggerType: string | null;
    actorId: string | null;
    errorMessage: string | null;
    createdAt: string;
    durationMs: number | null;
  }>;
};

export type GetWorkflowExecutionHistoryQueryVariables = Exact<{
  workflowId: string;
  pagination?: PaginationInput | null | undefined;
}>;

export type GetWorkflowExecutionHistoryQuery = {
  workflowExecutionHistory: Array<{
    id: string;
    status: string;
    startedAt: string;
    completedAt: string | null;
    durationMs: number | null;
    errorMessage: string | null;
    outputData: unknown;
    triggerType: string | null;
    actorId: string | null;
  }>;
};

export type ListWorkflowNamesQueryVariables = Exact<{ [key: string]: never }>;

export type ListWorkflowNamesQuery = {
  workflows: Array<{ id: string; name: string }>;
};

export type TriggerWorkflowAsActorMutationVariables = Exact<{
  workflowId: string;
  actorId?: string | null | undefined;
}>;

export type TriggerWorkflowAsActorMutation = {
  triggerWorkflow: { id: string };
};

export type GetWorkflowLoaderQueryVariables = Exact<{
  id: string;
}>;

export type GetWorkflowLoaderQuery = {
  workflow: {
    id: string;
    name: string;
    graphJson: string;
    actorId: string | null;
    maxConcurrentExecutions: number | null;
    intent: unknown;
  };
};

export type GetModulesLoaderQueryVariables = Exact<{
  ids: Array<string> | string;
}>;

export type GetModulesLoaderQuery = {
  wasmModules: Array<{
    id: string;
    name: string;
    config: string;
    sourceCode: string | null;
    capabilityWorld: string | null;
    importedInterfaces: Array<string> | null;
  }>;
};

export type ListActorsQueryVariables = Exact<{ [key: string]: never }>;

export type ListActorsQuery = {
  actors: Array<{
    id: string;
    name: string;
    status: string;
    executionCount: number;
  }>;
};

export type WorkflowsQueryVariables = Exact<{ [key: string]: never }>;

export type WorkflowsQuery = {
  workflows: Array<{
    id: string;
    name: string;
    graphJson: string;
    actorId: string | null;
    maxConcurrentExecutions: number | null;
    intent: unknown;
  }>;
};

export type TriggerWorkflowMutationVariables = Exact<{
  workflowId: string;
}>;

export type TriggerWorkflowMutation = {
  triggerWorkflow: { id: string; status: string };
};

export type LatestWorkflowExecutionsQueryVariables = Exact<{
  workflowIds: Array<string> | string;
}>;

export type LatestWorkflowExecutionsQuery = {
  latestWorkflowExecutions: Array<{
    workflowId: string;
    status: string;
    startedAt: string;
    errorMessage: string | null;
  }>;
};

export class TypedDocumentString<TResult, TVariables>
  extends String
  implements DocumentTypeDecoration<TResult, TVariables>
{
  __apiType?: NonNullable<
    DocumentTypeDecoration<TResult, TVariables>["__apiType"]
  >;
  private value: string;
  public __meta__?: Record<string, any> | undefined;

  constructor(value: string, __meta__?: Record<string, any> | undefined) {
    super(value);
    this.value = value;
    this.__meta__ = __meta__;
  }

  override toString(): string & DocumentTypeDecoration<TResult, TVariables> {
    return this.value;
  }
}

export const GetModuleExecutionHistoryDocument = new TypedDocumentString(`
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
    `);

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

export const GetModuleExecutionLogsDocument = new TypedDocumentString(`
    query GetModuleExecutionLogs($executionId: UUID!) {
  moduleExecutionLogs(executionId: $executionId) {
    id
    level
    message
    createdAt
    metadata
  }
}
    `);

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

export const GetSecretAuditLogDocument = new TypedDocumentString(`
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
    `);

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

export const CreateSecretDocument = new TypedDocumentString(`
    mutation CreateSecret($input: CreateSecretInput!) {
  createSecret(input: $input) {
    id
    name
    keyPath
  }
}
    `);

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

export const GetSecretsDocument = new TypedDocumentString(`
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
    `);

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

export const DeleteSecretDocument = new TypedDocumentString(`
    mutation DeleteSecret($keyPath: String!) {
  deleteSecret(keyPath: $keyPath)
}
    `);

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

export const RotateEncryptionKeyDocument = new TypedDocumentString(`
    mutation RotateEncryptionKey {
  rotateEncryptionKey
}
    `);

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

export const ListApiKeysDocument = new TypedDocumentString(`
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
    `);

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

export const CreateApiKeyDocument = new TypedDocumentString(`
    mutation CreateApiKey($input: CreateApiKeyInput!) {
  createApiKey(input: $input) {
    id
    name
    key
    scopes
    expiresAt
  }
}
    `);

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

export const RevokeApiKeyDocument = new TypedDocumentString(`
    mutation RevokeApiKey($keyId: UUID!) {
  revokeApiKey(keyId: $keyId)
}
    `);

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

export const RotateApiKeyDocument = new TypedDocumentString(`
    mutation RotateApiKey($keyId: UUID!) {
  rotateApiKey(keyId: $keyId) {
    id
    name
    key
    scopes
    expiresAt
  }
}
    `);

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

export const DeleteApiKeyDocument = new TypedDocumentString(`
    mutation DeleteApiKey($keyId: UUID!) {
  deleteApiKey(keyId: $keyId)
}
    `);

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

export const GetDeadLetterQueueDocument = new TypedDocumentString(`
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
    `);

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

export const GetWebhookDeadLetterQueueDocument = new TypedDocumentString(`
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
    `);

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

export const ReplayDeadLetterEntryDocument = new TypedDocumentString(`
    mutation ReplayDeadLetterEntry($id: UUID!) {
  replayDeadLetterEntry(id: $id)
}
    `);

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

export const ReplayWebhookDeadLetterEntryDocument = new TypedDocumentString(`
    mutation ReplayWebhookDeadLetterEntry($id: UUID!) {
  replayWebhookDeadLetterEntry(id: $id)
}
    `);

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

export const RegisterMcpAgentDocument = new TypedDocumentString(`
    mutation RegisterMcpAgent($name: String!, $role: String!) {
  registerMcpAgent(name: $name, roleName: $role) {
    agentId
    name
    token
    role
  }
}
    `);

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

export const ListLinkedAccountsDocument = new TypedDocumentString(`
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
    `);

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

export const GetOAuthUrlDocument = new TypedDocumentString(`
    query GetOAuthUrl($provider: String!) {
  oauthLoginUrl(provider: $provider) {
    authUrl
  }
}
    `);

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

export const UnlinkOAuthDocument = new TypedDocumentString(`
    mutation UnlinkOAuth($provider: String!) {
  unlinkOauthAccount(provider: $provider)
}
    `);

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

export const ListOrgsDocument = new TypedDocumentString(`
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
    `);

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

export const ListOrgMembersDocument = new TypedDocumentString(`
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
    `);

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

export const CreateOrgDocument = new TypedDocumentString(`
    mutation CreateOrg($name: String!, $slug: String!) {
  createOrganization(name: $name, slug: $slug) {
    id
    name
  }
}
    `);

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

export const RemoveMemberDocument = new TypedDocumentString(`
    mutation RemoveMember($orgId: UUID!, $userId: UUID!) {
  removeMember(orgId: $orgId, targetUserId: $userId)
}
    `);

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

export const InviteMemberDocument = new TypedDocumentString(`
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
    `);

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

export const UpdateMemberRoleDocument = new TypedDocumentString(`
    mutation UpdateMemberRole($orgId: UUID!, $targetUserId: UUID!, $role: String!) {
  updateMemberRole(orgId: $orgId, targetUserId: $targetUserId, role: $role) {
    id
    orgId
    userId
    role
    joinedAt
  }
}
    `);

export const useUpdateMemberRoleMutation = <
  TError = unknown,
  TContext = unknown,
>(
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

export const TransferOwnershipDocument = new TypedDocumentString(`
    mutation TransferOwnership($orgId: UUID!, $newOwnerId: UUID!) {
  transferOwnership(orgId: $orgId, newOwnerId: $newOwnerId) {
    id
    name
    ownerId
  }
}
    `);

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

export const Setup2FaDocument = new TypedDocumentString(`
    mutation Setup2FA {
  setupTwoFactor {
    secret
    qrCodeUrl
    qrCodePng
  }
}
    `);

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

export const Enable2FaDocument = new TypedDocumentString(`
    mutation Enable2FA($input: Enable2FAInput!) {
  enableTwoFactor(input: $input) {
    backupCodes
  }
}
    `);

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

export const Disable2FaDocument = new TypedDocumentString(`
    mutation Disable2FA {
  disableTwoFactor
}
    `);

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

export const ListActorSummariesDocument = new TypedDocumentString(`
    query ListActorSummaries {
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
    `);

export const useListActorSummariesQuery = <
  TData = ListActorSummariesQuery,
  TError = unknown,
>(
  variables?: ListActorSummariesQueryVariables,
  options?: Omit<
    UseQueryOptions<ListActorSummariesQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      ListActorSummariesQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<ListActorSummariesQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["ListActorSummaries"]
        : ["ListActorSummaries", variables],
    queryFn: graphqlFetcher<
      ListActorSummariesQuery,
      ListActorSummariesQueryVariables
    >(ListActorSummariesDocument, variables),
    ...options,
  });
};

export const GetActorDocument = new TypedDocumentString(`
    query GetActor($id: UUID!) {
  actor(id: $id) {
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
    mcpToken
    rateLimit
    metadata
    lastActiveAt
  }
}
    `);

export const useGetActorQuery = <TData = GetActorQuery, TError = unknown>(
  variables: GetActorQueryVariables,
  options?: Omit<UseQueryOptions<GetActorQuery, TError, TData>, "queryKey"> & {
    queryKey?: UseQueryOptions<GetActorQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<GetActorQuery, TError, TData>({
    queryKey: ["GetActor", variables],
    queryFn: graphqlFetcher<GetActorQuery, GetActorQueryVariables>(
      GetActorDocument,
      variables,
    ),
    ...options,
  });
};

export const CreateActorDocument = new TypedDocumentString(`
    mutation CreateActor($input: CreateActorInput!) {
  createActor(input: $input) {
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
    `);

export const useCreateActorMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    CreateActorMutation,
    TError,
    CreateActorMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    CreateActorMutation,
    TError,
    CreateActorMutationVariables,
    TContext
  >({
    mutationKey: ["CreateActor"],
    mutationFn: (variables?: CreateActorMutationVariables) =>
      graphqlFetcher<CreateActorMutation, CreateActorMutationVariables>(
        CreateActorDocument,
        variables,
      )(),
    ...options,
  });
};

export const UpdateActorStatusDocument = new TypedDocumentString(`
    mutation UpdateActorStatus($id: UUID!, $status: String!) {
  updateActorStatus(id: $id, status: $status) {
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
    `);

export const useUpdateActorStatusMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    UpdateActorStatusMutation,
    TError,
    UpdateActorStatusMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    UpdateActorStatusMutation,
    TError,
    UpdateActorStatusMutationVariables,
    TContext
  >({
    mutationKey: ["UpdateActorStatus"],
    mutationFn: (variables?: UpdateActorStatusMutationVariables) =>
      graphqlFetcher<
        UpdateActorStatusMutation,
        UpdateActorStatusMutationVariables
      >(UpdateActorStatusDocument, variables)(),
    ...options,
  });
};

export const TerminateActorDocument = new TypedDocumentString(`
    mutation TerminateActor($id: UUID!, $cleanupWorkflows: Boolean) {
  terminateActor(id: $id, cleanupWorkflows: $cleanupWorkflows)
}
    `);

export const useTerminateActorMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    TerminateActorMutation,
    TError,
    TerminateActorMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    TerminateActorMutation,
    TError,
    TerminateActorMutationVariables,
    TContext
  >({
    mutationKey: ["TerminateActor"],
    mutationFn: (variables?: TerminateActorMutationVariables) =>
      graphqlFetcher<TerminateActorMutation, TerminateActorMutationVariables>(
        TerminateActorDocument,
        variables,
      )(),
    ...options,
  });
};

export const GetActorActionLogDocument = new TypedDocumentString(`
    query GetActorActionLog($actorId: UUID!, $limit: Int) {
  actorActionLog(actorId: $actorId, limit: $limit) {
    id
    actionType
    summary
    timestamp
    workflowId
    executionId
  }
}
    `);

export const useGetActorActionLogQuery = <
  TData = GetActorActionLogQuery,
  TError = unknown,
>(
  variables: GetActorActionLogQueryVariables,
  options?: Omit<
    UseQueryOptions<GetActorActionLogQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetActorActionLogQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetActorActionLogQuery, TError, TData>({
    queryKey: ["GetActorActionLog", variables],
    queryFn: graphqlFetcher<
      GetActorActionLogQuery,
      GetActorActionLogQueryVariables
    >(GetActorActionLogDocument, variables),
    ...options,
  });
};

export const GetActorWorkflowsDocument = new TypedDocumentString(`
    query GetActorWorkflows($actorId: UUID!) {
  actorWorkflows(actorId: $actorId) {
    id
    name
    status
    nodeCount
    graphJson
    createdAt
    updatedAt
  }
}
    `);

export const useGetActorWorkflowsQuery = <
  TData = GetActorWorkflowsQuery,
  TError = unknown,
>(
  variables: GetActorWorkflowsQueryVariables,
  options?: Omit<
    UseQueryOptions<GetActorWorkflowsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetActorWorkflowsQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetActorWorkflowsQuery, TError, TData>({
    queryKey: ["GetActorWorkflows", variables],
    queryFn: graphqlFetcher<
      GetActorWorkflowsQuery,
      GetActorWorkflowsQueryVariables
    >(GetActorWorkflowsDocument, variables),
    ...options,
  });
};

export const GetActorExecutionsSummaryDocument = new TypedDocumentString(`
    query GetActorExecutionsSummary($actorId: UUID!) {
  actorExecutionsSummary(actorId: $actorId) {
    totalExecutions
    successfulExecutions
    failedExecutions
    activeExecutions
  }
}
    `);

export const useGetActorExecutionsSummaryQuery = <
  TData = GetActorExecutionsSummaryQuery,
  TError = unknown,
>(
  variables: GetActorExecutionsSummaryQueryVariables,
  options?: Omit<
    UseQueryOptions<GetActorExecutionsSummaryQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetActorExecutionsSummaryQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetActorExecutionsSummaryQuery, TError, TData>({
    queryKey: ["GetActorExecutionsSummary", variables],
    queryFn: graphqlFetcher<
      GetActorExecutionsSummaryQuery,
      GetActorExecutionsSummaryQueryVariables
    >(GetActorExecutionsSummaryDocument, variables),
    ...options,
  });
};

export const UpdateActorDocument = new TypedDocumentString(`
    mutation UpdateActor($id: UUID!, $name: String, $description: String, $maxCapabilityWorld: String) {
  updateActor(
    id: $id
    name: $name
    description: $description
    maxCapabilityWorld: $maxCapabilityWorld
  ) {
    id
    name
    description
    status
    maxCapabilityWorld
    workflowCount
    executionCount
    createdAt
    updatedAt
  }
}
    `);

export const useUpdateActorMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    UpdateActorMutation,
    TError,
    UpdateActorMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    UpdateActorMutation,
    TError,
    UpdateActorMutationVariables,
    TContext
  >({
    mutationKey: ["UpdateActor"],
    mutationFn: (variables?: UpdateActorMutationVariables) =>
      graphqlFetcher<UpdateActorMutation, UpdateActorMutationVariables>(
        UpdateActorDocument,
        variables,
      )(),
    ...options,
  });
};

export const CloneActorDocument = new TypedDocumentString(`
    mutation CloneActor($id: UUID!, $name: String) {
  cloneActor(id: $id, name: $name) {
    id
    name
    description
    status
    maxCapabilityWorld
    workflowCount
    executionCount
    createdAt
    updatedAt
  }
}
    `);

export const useCloneActorMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    CloneActorMutation,
    TError,
    CloneActorMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    CloneActorMutation,
    TError,
    CloneActorMutationVariables,
    TContext
  >({
    mutationKey: ["CloneActor"],
    mutationFn: (variables?: CloneActorMutationVariables) =>
      graphqlFetcher<CloneActorMutation, CloneActorMutationVariables>(
        CloneActorDocument,
        variables,
      )(),
    ...options,
  });
};

export const GetActorMemoriesDocument = new TypedDocumentString(`
    query GetActorMemories($actorId: UUID!, $memoryType: String) {
  actorMemories(actorId: $actorId, memoryType: $memoryType) {
    key
    value
    memoryType
    expiresAt
    updatedAt
  }
}
    `);

export const useGetActorMemoriesQuery = <
  TData = GetActorMemoriesQuery,
  TError = unknown,
>(
  variables: GetActorMemoriesQueryVariables,
  options?: Omit<
    UseQueryOptions<GetActorMemoriesQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetActorMemoriesQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetActorMemoriesQuery, TError, TData>({
    queryKey: ["GetActorMemories", variables],
    queryFn: graphqlFetcher<
      GetActorMemoriesQuery,
      GetActorMemoriesQueryVariables
    >(GetActorMemoriesDocument, variables),
    ...options,
  });
};

export const WriteActorMemoryDocument = new TypedDocumentString(`
    mutation WriteActorMemory($input: WriteActorMemoryInput!) {
  writeActorMemory(input: $input) {
    key
    value
    memoryType
    expiresAt
    updatedAt
  }
}
    `);

export const useWriteActorMemoryMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    WriteActorMemoryMutation,
    TError,
    WriteActorMemoryMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    WriteActorMemoryMutation,
    TError,
    WriteActorMemoryMutationVariables,
    TContext
  >({
    mutationKey: ["WriteActorMemory"],
    mutationFn: (variables?: WriteActorMemoryMutationVariables) =>
      graphqlFetcher<
        WriteActorMemoryMutation,
        WriteActorMemoryMutationVariables
      >(WriteActorMemoryDocument, variables)(),
    ...options,
  });
};

export const DeleteActorMemoryDocument = new TypedDocumentString(`
    mutation DeleteActorMemory($actorId: UUID!, $key: String!) {
  deleteActorMemory(actorId: $actorId, key: $key)
}
    `);

export const useDeleteActorMemoryMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    DeleteActorMemoryMutation,
    TError,
    DeleteActorMemoryMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    DeleteActorMemoryMutation,
    TError,
    DeleteActorMemoryMutationVariables,
    TContext
  >({
    mutationKey: ["DeleteActorMemory"],
    mutationFn: (variables?: DeleteActorMemoryMutationVariables) =>
      graphqlFetcher<
        DeleteActorMemoryMutation,
        DeleteActorMemoryMutationVariables
      >(DeleteActorMemoryDocument, variables)(),
    ...options,
  });
};

export const GetMyCapabilityCeilingDocument = new TypedDocumentString(`
    query GetMyCapabilityCeiling {
  myCapabilityCeiling
}
    `);

export const useGetMyCapabilityCeilingQuery = <
  TData = GetMyCapabilityCeilingQuery,
  TError = unknown,
>(
  variables?: GetMyCapabilityCeilingQueryVariables,
  options?: Omit<
    UseQueryOptions<GetMyCapabilityCeilingQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetMyCapabilityCeilingQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetMyCapabilityCeilingQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["GetMyCapabilityCeiling"]
        : ["GetMyCapabilityCeiling", variables],
    queryFn: graphqlFetcher<
      GetMyCapabilityCeilingQuery,
      GetMyCapabilityCeilingQueryVariables
    >(GetMyCapabilityCeilingDocument, variables),
    ...options,
  });
};

export const GetAllWorkflowStatsDocument = new TypedDocumentString(`
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
    `);

export const useGetAllWorkflowStatsQuery = <
  TData = GetAllWorkflowStatsQuery,
  TError = unknown,
>(
  variables?: GetAllWorkflowStatsQueryVariables,
  options?: Omit<
    UseQueryOptions<GetAllWorkflowStatsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetAllWorkflowStatsQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetAllWorkflowStatsQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["GetAllWorkflowStats"]
        : ["GetAllWorkflowStats", variables],
    queryFn: graphqlFetcher<
      GetAllWorkflowStatsQuery,
      GetAllWorkflowStatsQueryVariables
    >(GetAllWorkflowStatsDocument, variables),
    ...options,
  });
};

export const GetApprovalsDocument = new TypedDocumentString(`
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
    `);

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

export const ApproveExecutionDocument = new TypedDocumentString(`
    mutation ApproveExecution($id: UUID!, $reason: String) {
  approveExecution(id: $id, reason: $reason)
}
    `);

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

export const DenyExecutionDocument = new TypedDocumentString(`
    mutation DenyExecution($id: UUID!, $reason: String) {
  denyExecution(id: $id, reason: $reason)
}
    `);

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

export const GetAuditSettingsDocument = new TypedDocumentString(`
    query GetAuditSettings {
  auditSettings {
    streamingEnabled
    otlpEndpoint
    otlpProtocol
    updatedAt
    createdAt
  }
}
    `);

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

export const UpdateAuditSettingsDocument = new TypedDocumentString(`
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
    `);

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

export const GetResourceQuotasDocument = new TypedDocumentString(`
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
    `);

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

export const UpdateResourceQuotasDocument = new TypedDocumentString(`
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
    `);

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

export const RotateDekDocument = new TypedDocumentString(`
    mutation RotateDek {
  rotateDek {
    newDekId
    message
  }
}
    `);

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

export const ReEncryptSecretsDocument = new TypedDocumentString(`
    mutation ReEncryptSecrets {
  reEncryptSecrets {
    reEncryptedCount
    message
  }
}
    `);

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
      graphqlFetcher<
        ReEncryptSecretsMutation,
        ReEncryptSecretsMutationVariables
      >(ReEncryptSecretsDocument, variables)(),
    ...options,
  });
};

export const RotateMasterKeyDocument = new TypedDocumentString(`
    mutation RotateMasterKey($newMasterKey: String!) {
  rotateMasterKey(newMasterKey: $newMasterKey) {
    reEncryptedDekCount
    message
  }
}
    `);

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

export const UpdateSecretDocument = new TypedDocumentString(`
    mutation UpdateSecret($input: UpdateSecretInput!) {
  updateSecret(input: $input) {
    id
    name
    keyPath
  }
}
    `);

export const useUpdateSecretMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    UpdateSecretMutation,
    TError,
    UpdateSecretMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    UpdateSecretMutation,
    TError,
    UpdateSecretMutationVariables,
    TContext
  >({
    mutationKey: ["UpdateSecret"],
    mutationFn: (variables?: UpdateSecretMutationVariables) =>
      graphqlFetcher<UpdateSecretMutation, UpdateSecretMutationVariables>(
        UpdateSecretDocument,
        variables,
      )(),
    ...options,
  });
};

export const GetCapabilityCeilingDetailDocument = new TypedDocumentString(`
    query GetCapabilityCeilingDetail {
  capabilityCeilingDetail {
    ceiling
    source
    grantedByEmail
    grantedAt
    notes
  }
}
    `);

export const useGetCapabilityCeilingDetailQuery = <
  TData = GetCapabilityCeilingDetailQuery,
  TError = unknown,
>(
  variables?: GetCapabilityCeilingDetailQueryVariables,
  options?: Omit<
    UseQueryOptions<GetCapabilityCeilingDetailQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetCapabilityCeilingDetailQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetCapabilityCeilingDetailQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["GetCapabilityCeilingDetail"]
        : ["GetCapabilityCeilingDetail", variables],
    queryFn: graphqlFetcher<
      GetCapabilityCeilingDetailQuery,
      GetCapabilityCeilingDetailQueryVariables
    >(GetCapabilityCeilingDetailDocument, variables),
    ...options,
  });
};

export const GetCapabilityWorldHierarchyDocument = new TypedDocumentString(`
    query GetCapabilityWorldHierarchy {
  capabilityWorldHierarchy {
    name
    rank
    description
  }
}
    `);

export const useGetCapabilityWorldHierarchyQuery = <
  TData = GetCapabilityWorldHierarchyQuery,
  TError = unknown,
>(
  variables?: GetCapabilityWorldHierarchyQueryVariables,
  options?: Omit<
    UseQueryOptions<GetCapabilityWorldHierarchyQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetCapabilityWorldHierarchyQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetCapabilityWorldHierarchyQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["GetCapabilityWorldHierarchy"]
        : ["GetCapabilityWorldHierarchy", variables],
    queryFn: graphqlFetcher<
      GetCapabilityWorldHierarchyQuery,
      GetCapabilityWorldHierarchyQueryVariables
    >(GetCapabilityWorldHierarchyDocument, variables),
    ...options,
  });
};

export const RevokeCapabilityCeilingDocument = new TypedDocumentString(`
    mutation RevokeCapabilityCeiling($userId: UUID!) {
  revokeCapabilityCeiling(userId: $userId)
}
    `);

export const useRevokeCapabilityCeilingMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    RevokeCapabilityCeilingMutation,
    TError,
    RevokeCapabilityCeilingMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    RevokeCapabilityCeilingMutation,
    TError,
    RevokeCapabilityCeilingMutationVariables,
    TContext
  >({
    mutationKey: ["RevokeCapabilityCeiling"],
    mutationFn: (variables?: RevokeCapabilityCeilingMutationVariables) =>
      graphqlFetcher<
        RevokeCapabilityCeilingMutation,
        RevokeCapabilityCeilingMutationVariables
      >(RevokeCapabilityCeilingDocument, variables)(),
    ...options,
  });
};

export const GetCurrentUserIdDocument = new TypedDocumentString(`
    query GetCurrentUserId {
  me {
    id
  }
}
    `);

export const useGetCurrentUserIdQuery = <
  TData = GetCurrentUserIdQuery,
  TError = unknown,
>(
  variables?: GetCurrentUserIdQueryVariables,
  options?: Omit<
    UseQueryOptions<GetCurrentUserIdQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetCurrentUserIdQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetCurrentUserIdQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["GetCurrentUserId"]
        : ["GetCurrentUserId", variables],
    queryFn: graphqlFetcher<
      GetCurrentUserIdQuery,
      GetCurrentUserIdQueryVariables
    >(GetCurrentUserIdDocument, variables),
    ...options,
  });
};

export const ListServiceIntegrationsDocument = new TypedDocumentString(`
    query ListServiceIntegrations {
  serviceIntegrations {
    id
    service
    accountIdentifier
    connectedAt
    status
  }
}
    `);

export const useListServiceIntegrationsQuery = <
  TData = ListServiceIntegrationsQuery,
  TError = unknown,
>(
  variables?: ListServiceIntegrationsQueryVariables,
  options?: Omit<
    UseQueryOptions<ListServiceIntegrationsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      ListServiceIntegrationsQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<ListServiceIntegrationsQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["ListServiceIntegrations"]
        : ["ListServiceIntegrations", variables],
    queryFn: graphqlFetcher<
      ListServiceIntegrationsQuery,
      ListServiceIntegrationsQueryVariables
    >(ListServiceIntegrationsDocument, variables),
    ...options,
  });
};

export const DisconnectServiceIntegrationDocument = new TypedDocumentString(`
    mutation DisconnectServiceIntegration($id: UUID!, $service: IntegrationService!) {
  disconnectServiceIntegration(id: $id, service: $service)
}
    `);

export const useDisconnectServiceIntegrationMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    DisconnectServiceIntegrationMutation,
    TError,
    DisconnectServiceIntegrationMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    DisconnectServiceIntegrationMutation,
    TError,
    DisconnectServiceIntegrationMutationVariables,
    TContext
  >({
    mutationKey: ["DisconnectServiceIntegration"],
    mutationFn: (variables?: DisconnectServiceIntegrationMutationVariables) =>
      graphqlFetcher<
        DisconnectServiceIntegrationMutation,
        DisconnectServiceIntegrationMutationVariables
      >(DisconnectServiceIntegrationDocument, variables)(),
    ...options,
  });
};

export const ListMcpAgentsDocument = new TypedDocumentString(`
    query ListMcpAgents {
  mcpAgents {
    id
    name
    createdAt
    lastUsedAt
  }
}
    `);

export const useListMcpAgentsQuery = <
  TData = ListMcpAgentsQuery,
  TError = unknown,
>(
  variables?: ListMcpAgentsQueryVariables,
  options?: Omit<
    UseQueryOptions<ListMcpAgentsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<ListMcpAgentsQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<ListMcpAgentsQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["ListMcpAgents"]
        : ["ListMcpAgents", variables],
    queryFn: graphqlFetcher<ListMcpAgentsQuery, ListMcpAgentsQueryVariables>(
      ListMcpAgentsDocument,
      variables,
    ),
    ...options,
  });
};

export const RevokeMcpAgentDocument = new TypedDocumentString(`
    mutation RevokeMcpAgent($id: UUID!) {
  revokeMcpAgent(id: $id)
}
    `);

export const useRevokeMcpAgentMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    RevokeMcpAgentMutation,
    TError,
    RevokeMcpAgentMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    RevokeMcpAgentMutation,
    TError,
    RevokeMcpAgentMutationVariables,
    TContext
  >({
    mutationKey: ["RevokeMcpAgent"],
    mutationFn: (variables?: RevokeMcpAgentMutationVariables) =>
      graphqlFetcher<RevokeMcpAgentMutation, RevokeMcpAgentMutationVariables>(
        RevokeMcpAgentDocument,
        variables,
      )(),
    ...options,
  });
};

export const MyModulesDocument = new TypedDocumentString(`
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
    `);

export const useMyModulesQuery = <TData = MyModulesQuery, TError = unknown>(
  variables?: MyModulesQueryVariables,
  options?: Omit<UseQueryOptions<MyModulesQuery, TError, TData>, "queryKey"> & {
    queryKey?: UseQueryOptions<MyModulesQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<MyModulesQuery, TError, TData>({
    queryKey:
      variables === undefined ? ["MyModules"] : ["MyModules", variables],
    queryFn: graphqlFetcher<MyModulesQuery, MyModulesQueryVariables>(
      MyModulesDocument,
      variables,
    ),
    ...options,
  });
};

export const CreateModuleFromTemplateDocument = new TypedDocumentString(`
    mutation CreateModuleFromTemplate($input: CreateModuleInput!) {
  createModuleFromTemplate(input: $input) {
    id
    name
    config
  }
}
    `);

export const useCreateModuleFromTemplateMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    CreateModuleFromTemplateMutation,
    TError,
    CreateModuleFromTemplateMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    CreateModuleFromTemplateMutation,
    TError,
    CreateModuleFromTemplateMutationVariables,
    TContext
  >({
    mutationKey: ["CreateModuleFromTemplate"],
    mutationFn: (variables?: CreateModuleFromTemplateMutationVariables) =>
      graphqlFetcher<
        CreateModuleFromTemplateMutation,
        CreateModuleFromTemplateMutationVariables
      >(CreateModuleFromTemplateDocument, variables)(),
    ...options,
  });
};

export const NodeTemplatesDocument = new TypedDocumentString(`
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
    `);

export const useNodeTemplatesQuery = <
  TData = NodeTemplatesQuery,
  TError = unknown,
>(
  variables?: NodeTemplatesQueryVariables,
  options?: Omit<
    UseQueryOptions<NodeTemplatesQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<NodeTemplatesQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<NodeTemplatesQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["NodeTemplates"]
        : ["NodeTemplates", variables],
    queryFn: graphqlFetcher<NodeTemplatesQuery, NodeTemplatesQueryVariables>(
      NodeTemplatesDocument,
      variables,
    ),
    ...options,
  });
};

export const GetNodeTemplatesDocument = new TypedDocumentString(`
    query GetNodeTemplates($category: String) {
  nodeTemplates(category: $category) {
    id
    name
    category
    description
    configSchema
    icon
    allowedHosts
  }
}
    `);

export const useGetNodeTemplatesQuery = <
  TData = GetNodeTemplatesQuery,
  TError = unknown,
>(
  variables?: GetNodeTemplatesQueryVariables,
  options?: Omit<
    UseQueryOptions<GetNodeTemplatesQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetNodeTemplatesQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetNodeTemplatesQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["GetNodeTemplates"]
        : ["GetNodeTemplates", variables],
    queryFn: graphqlFetcher<
      GetNodeTemplatesQuery,
      GetNodeTemplatesQueryVariables
    >(GetNodeTemplatesDocument, variables),
    ...options,
  });
};

export const GetNodeTemplateDocument = new TypedDocumentString(`
    query GetNodeTemplate($id: UUID!) {
  nodeTemplate(id: $id) {
    id
    name
    category
    description
    configSchema
    icon
  }
}
    `);

export const useGetNodeTemplateQuery = <
  TData = GetNodeTemplateQuery,
  TError = unknown,
>(
  variables: GetNodeTemplateQueryVariables,
  options?: Omit<
    UseQueryOptions<GetNodeTemplateQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<GetNodeTemplateQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<GetNodeTemplateQuery, TError, TData>({
    queryKey: ["GetNodeTemplate", variables],
    queryFn: graphqlFetcher<
      GetNodeTemplateQuery,
      GetNodeTemplateQueryVariables
    >(GetNodeTemplateDocument, variables),
    ...options,
  });
};

export const AnalyzeRhaiDocument = new TypedDocumentString(`
    query AnalyzeRhai($input: AnalyzeRhaiInput!) {
  analyzeRhai(input: $input) {
    success
    errors {
      line
      column
      endLine
      endColumn
      message
      severity
    }
  }
}
    `);

export const useAnalyzeRhaiQuery = <TData = AnalyzeRhaiQuery, TError = unknown>(
  variables: AnalyzeRhaiQueryVariables,
  options?: Omit<
    UseQueryOptions<AnalyzeRhaiQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<AnalyzeRhaiQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<AnalyzeRhaiQuery, TError, TData>({
    queryKey: ["AnalyzeRhai", variables],
    queryFn: graphqlFetcher<AnalyzeRhaiQuery, AnalyzeRhaiQueryVariables>(
      AnalyzeRhaiDocument,
      variables,
    ),
    ...options,
  });
};

export const TestRhaiExpressionDocument = new TypedDocumentString(`
    query TestRhaiExpression($input: TestRhaiExpressionInput!) {
  testRhaiExpression(input: $input) {
    success
    output
    error
  }
}
    `);

export const useTestRhaiExpressionQuery = <
  TData = TestRhaiExpressionQuery,
  TError = unknown,
>(
  variables: TestRhaiExpressionQueryVariables,
  options?: Omit<
    UseQueryOptions<TestRhaiExpressionQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      TestRhaiExpressionQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<TestRhaiExpressionQuery, TError, TData>({
    queryKey: ["TestRhaiExpression", variables],
    queryFn: graphqlFetcher<
      TestRhaiExpressionQuery,
      TestRhaiExpressionQueryVariables
    >(TestRhaiExpressionDocument, variables),
    ...options,
  });
};

export const MySchedulesDocument = new TypedDocumentString(`
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
    `);

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

export const CreateScheduleDocument = new TypedDocumentString(`
    mutation CreateSchedule($workflowId: UUID!, $cronExpression: String!, $timezone: String) {
  createSchedule(
    workflowId: $workflowId
    cronExpression: $cronExpression
    timezone: $timezone
  ) {
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
    `);

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

export const UpdateScheduleDocument = new TypedDocumentString(`
    mutation UpdateSchedule($workflowId: UUID!, $cronExpression: String, $timezone: String, $isEnabled: Boolean) {
  updateSchedule(
    workflowId: $workflowId
    cronExpression: $cronExpression
    timezone: $timezone
    isEnabled: $isEnabled
  ) {
    id
    workflowId
    cronExpression
    timezone
    isEnabled
    nextTriggerAt
    updatedAt
  }
}
    `);

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

export const DeleteScheduleDocument = new TypedDocumentString(`
    mutation DeleteSchedule($workflowId: UUID!) {
  deleteSchedule(workflowId: $workflowId)
}
    `);

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

export const SetConcurrencyLimitDocument = new TypedDocumentString(`
    mutation SetConcurrencyLimit($workflowId: UUID!, $maxConcurrent: Int) {
  setConcurrencyLimit(workflowId: $workflowId, maxConcurrent: $maxConcurrent)
}
    `);

export const useSetConcurrencyLimitMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    SetConcurrencyLimitMutation,
    TError,
    SetConcurrencyLimitMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    SetConcurrencyLimitMutation,
    TError,
    SetConcurrencyLimitMutationVariables,
    TContext
  >({
    mutationKey: ["SetConcurrencyLimit"],
    mutationFn: (variables?: SetConcurrencyLimitMutationVariables) =>
      graphqlFetcher<
        SetConcurrencyLimitMutation,
        SetConcurrencyLimitMutationVariables
      >(SetConcurrencyLimitDocument, variables)(),
    ...options,
  });
};

export const DeleteWorkflowDocument = new TypedDocumentString(`
    mutation DeleteWorkflow($id: UUID!) {
  deleteWorkflow(id: $id)
}
    `);

export const useDeleteWorkflowMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    DeleteWorkflowMutation,
    TError,
    DeleteWorkflowMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    DeleteWorkflowMutation,
    TError,
    DeleteWorkflowMutationVariables,
    TContext
  >({
    mutationKey: ["DeleteWorkflow"],
    mutationFn: (variables?: DeleteWorkflowMutationVariables) =>
      graphqlFetcher<DeleteWorkflowMutation, DeleteWorkflowMutationVariables>(
        DeleteWorkflowDocument,
        variables,
      )(),
    ...options,
  });
};

export const TestWorkflowDocument = new TypedDocumentString(`
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
    `);

export const useTestWorkflowMutation = <TError = unknown, TContext = unknown>(
  options?: UseMutationOptions<
    TestWorkflowMutation,
    TError,
    TestWorkflowMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    TestWorkflowMutation,
    TError,
    TestWorkflowMutationVariables,
    TContext
  >({
    mutationKey: ["TestWorkflow"],
    mutationFn: (variables?: TestWorkflowMutationVariables) =>
      graphqlFetcher<TestWorkflowMutation, TestWorkflowMutationVariables>(
        TestWorkflowDocument,
        variables,
      )(),
    ...options,
  });
};

export const ResumeWorkflowDocument = new TypedDocumentString(`
    mutation ResumeWorkflow($executionId: UUID!) {
  resumeWorkflow(executionId: $executionId)
}
    `);

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

export const RetryExecutionDocument = new TypedDocumentString(`
    mutation RetryExecution($executionId: UUID!) {
  retryExecution(executionId: $executionId)
}
    `);

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

export const WorkflowVersionsDocument = new TypedDocumentString(`
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
    `);

export const useWorkflowVersionsQuery = <
  TData = WorkflowVersionsQuery,
  TError = unknown,
>(
  variables: WorkflowVersionsQueryVariables,
  options?: Omit<
    UseQueryOptions<WorkflowVersionsQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      WorkflowVersionsQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<WorkflowVersionsQuery, TError, TData>({
    queryKey: ["WorkflowVersions", variables],
    queryFn: graphqlFetcher<
      WorkflowVersionsQuery,
      WorkflowVersionsQueryVariables
    >(WorkflowVersionsDocument, variables),
    ...options,
  });
};

export const PublishWorkflowVersionDocument = new TypedDocumentString(`
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
    `);

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

export const RollbackWorkflowVersionDocument = new TypedDocumentString(`
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
    `);

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

export const GetVersionDiffSummaryDocument = new TypedDocumentString(`
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
    `);

export const useGetVersionDiffSummaryQuery = <
  TData = GetVersionDiffSummaryQuery,
  TError = unknown,
>(
  variables: GetVersionDiffSummaryQueryVariables,
  options?: Omit<
    UseQueryOptions<GetVersionDiffSummaryQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetVersionDiffSummaryQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetVersionDiffSummaryQuery, TError, TData>({
    queryKey: ["GetVersionDiffSummary", variables],
    queryFn: graphqlFetcher<
      GetVersionDiffSummaryQuery,
      GetVersionDiffSummaryQueryVariables
    >(GetVersionDiffSummaryDocument, variables),
    ...options,
  });
};

export const GetWorkflowChangelogDocument = new TypedDocumentString(`
    query GetWorkflowChangelog($workflowId: UUID!) {
  getWorkflowChangelog(workflowId: $workflowId) {
    versionNumber
    summary
    description
    publishedAt
  }
}
    `);

export const useGetWorkflowChangelogQuery = <
  TData = GetWorkflowChangelogQuery,
  TError = unknown,
>(
  variables: GetWorkflowChangelogQueryVariables,
  options?: Omit<
    UseQueryOptions<GetWorkflowChangelogQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetWorkflowChangelogQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetWorkflowChangelogQuery, TError, TData>({
    queryKey: ["GetWorkflowChangelog", variables],
    queryFn: graphqlFetcher<
      GetWorkflowChangelogQuery,
      GetWorkflowChangelogQueryVariables
    >(GetWorkflowChangelogDocument, variables),
    ...options,
  });
};

export const WebhookTriggersDocument = new TypedDocumentString(`
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
    `);

export const useWebhookTriggersQuery = <
  TData = WebhookTriggersQuery,
  TError = unknown,
>(
  variables?: WebhookTriggersQueryVariables,
  options?: Omit<
    UseQueryOptions<WebhookTriggersQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<WebhookTriggersQuery, TError, TData>["queryKey"];
  },
) => {
  return useQuery<WebhookTriggersQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["WebhookTriggers"]
        : ["WebhookTriggers", variables],
    queryFn: graphqlFetcher<
      WebhookTriggersQuery,
      WebhookTriggersQueryVariables
    >(WebhookTriggersDocument, variables),
    ...options,
  });
};

export const CreateWebhookTriggerDocument = new TypedDocumentString(`
    mutation CreateWebhookTrigger($input: CreateWebhookTriggerInput!) {
  createWebhookTrigger(input: $input) {
    id
    name
    webhookUrl
    verificationToken
  }
}
    `);

export const useCreateWebhookTriggerMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    CreateWebhookTriggerMutation,
    TError,
    CreateWebhookTriggerMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    CreateWebhookTriggerMutation,
    TError,
    CreateWebhookTriggerMutationVariables,
    TContext
  >({
    mutationKey: ["CreateWebhookTrigger"],
    mutationFn: (variables?: CreateWebhookTriggerMutationVariables) =>
      graphqlFetcher<
        CreateWebhookTriggerMutation,
        CreateWebhookTriggerMutationVariables
      >(CreateWebhookTriggerDocument, variables)(),
    ...options,
  });
};

export const WorkflowExecutionHistoryDocument = new TypedDocumentString(`
    query WorkflowExecutionHistory($workflowId: UUID!, $limit: Int, $offset: Int) {
  workflowExecutionHistory(
    workflowId: $workflowId
    pagination: {limit: $limit, offset: $offset}
  ) {
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
    `);

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

export const GetWorkflowExecutionHistoryDocument = new TypedDocumentString(`
    query GetWorkflowExecutionHistory($workflowId: UUID!, $pagination: PaginationInput) {
  workflowExecutionHistory(workflowId: $workflowId, pagination: $pagination) {
    id
    status
    startedAt
    completedAt
    durationMs
    errorMessage
    outputData
    triggerType
    actorId
  }
}
    `);

export const useGetWorkflowExecutionHistoryQuery = <
  TData = GetWorkflowExecutionHistoryQuery,
  TError = unknown,
>(
  variables: GetWorkflowExecutionHistoryQueryVariables,
  options?: Omit<
    UseQueryOptions<GetWorkflowExecutionHistoryQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      GetWorkflowExecutionHistoryQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<GetWorkflowExecutionHistoryQuery, TError, TData>({
    queryKey: ["GetWorkflowExecutionHistory", variables],
    queryFn: graphqlFetcher<
      GetWorkflowExecutionHistoryQuery,
      GetWorkflowExecutionHistoryQueryVariables
    >(GetWorkflowExecutionHistoryDocument, variables),
    ...options,
  });
};

export const ListWorkflowNamesDocument = new TypedDocumentString(`
    query ListWorkflowNames {
  workflows {
    id
    name
  }
}
    `);

export const useListWorkflowNamesQuery = <
  TData = ListWorkflowNamesQuery,
  TError = unknown,
>(
  variables?: ListWorkflowNamesQueryVariables,
  options?: Omit<
    UseQueryOptions<ListWorkflowNamesQuery, TError, TData>,
    "queryKey"
  > & {
    queryKey?: UseQueryOptions<
      ListWorkflowNamesQuery,
      TError,
      TData
    >["queryKey"];
  },
) => {
  return useQuery<ListWorkflowNamesQuery, TError, TData>({
    queryKey:
      variables === undefined
        ? ["ListWorkflowNames"]
        : ["ListWorkflowNames", variables],
    queryFn: graphqlFetcher<
      ListWorkflowNamesQuery,
      ListWorkflowNamesQueryVariables
    >(ListWorkflowNamesDocument, variables),
    ...options,
  });
};

export const TriggerWorkflowAsActorDocument = new TypedDocumentString(`
    mutation TriggerWorkflowAsActor($workflowId: UUID!, $actorId: UUID) {
  triggerWorkflow(workflowId: $workflowId, actorId: $actorId) {
    id
  }
}
    `);

export const useTriggerWorkflowAsActorMutation = <
  TError = unknown,
  TContext = unknown,
>(
  options?: UseMutationOptions<
    TriggerWorkflowAsActorMutation,
    TError,
    TriggerWorkflowAsActorMutationVariables,
    TContext
  >,
) => {
  return useMutation<
    TriggerWorkflowAsActorMutation,
    TError,
    TriggerWorkflowAsActorMutationVariables,
    TContext
  >({
    mutationKey: ["TriggerWorkflowAsActor"],
    mutationFn: (variables?: TriggerWorkflowAsActorMutationVariables) =>
      graphqlFetcher<
        TriggerWorkflowAsActorMutation,
        TriggerWorkflowAsActorMutationVariables
      >(TriggerWorkflowAsActorDocument, variables)(),
    ...options,
  });
};

export const GetWorkflowLoaderDocument = new TypedDocumentString(`
    query GetWorkflowLoader($id: UUID!) {
  workflow(id: $id) {
    id
    name
    graphJson
    actorId
    maxConcurrentExecutions
    intent
  }
}
    `);

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

export const GetModulesLoaderDocument = new TypedDocumentString(`
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
    `);

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

export const ListActorsDocument = new TypedDocumentString(`
    query ListActors {
  actors {
    id
    name
    status
    executionCount
  }
}
    `);

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

export const WorkflowsDocument = new TypedDocumentString(`
    query Workflows {
  workflows {
    id
    name
    graphJson
    actorId
    maxConcurrentExecutions
    intent
  }
}
    `);

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

export const TriggerWorkflowDocument = new TypedDocumentString(`
    mutation TriggerWorkflow($workflowId: UUID!) {
  triggerWorkflow(workflowId: $workflowId) {
    id
    status
  }
}
    `);

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

export const LatestWorkflowExecutionsDocument = new TypedDocumentString(`
    query LatestWorkflowExecutions($workflowIds: [UUID!]!) {
  latestWorkflowExecutions(workflowIds: $workflowIds) {
    workflowId
    status
    startedAt
    errorMessage
  }
}
    `);

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
