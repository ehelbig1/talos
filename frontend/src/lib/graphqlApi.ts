/**
 * Thin, typed imperative wrappers around GraphQL operations.
 *
 * The operation documents live in `src/graphql/*.graphql`; graphql-codegen
 * turns them into typed react-query hooks + `*Document` constants in
 * `src/generated/graphql.ts` (`npm run codegen`).
 *
 * Prefer the generated hooks (`useGetActorQuery`, …) in components. Use these
 * wrappers only for genuinely non-hook call sites: event handlers, zustand
 * store actions, fire-and-forget fetches. Every wrapper reuses the generated
 * document constant so the operation text is single-sourced.
 */
import { graphqlRequest } from "@/lib/graphqlClient";
import {
  AnalyzeRhaiDocument,
  CloneActorDocument,
  CreateActorDocument,
  DeleteActorMemoryDocument,
  DisconnectServiceIntegrationDocument,
  GetActorActionLogDocument,
  GetActorDocument,
  GetActorExecutionsSummaryDocument,
  GetActorMemoriesDocument,
  GetActorWorkflowsDocument,
  GetMyCapabilityCeilingDocument,
  GetNodeTemplatesDocument,
  GetOAuthUrlDocument,
  GetWorkflowExecutionHistoryDocument,
  ListActorSummariesDocument,
  ListMcpAgentsDocument,
  ListServiceIntegrationsDocument,
  RevokeMcpAgentDocument,
  TerminateActorDocument,
  TestRhaiExpressionDocument,
  TriggerWorkflowAsActorDocument,
  UpdateActorDocument,
  UpdateActorStatusDocument,
  WriteActorMemoryDocument,
  type IntegrationService,
} from "@/generated/graphql";

export type { IntegrationService } from "@/generated/graphql";

// --- Rhai analysis ---

export interface AnalysisDiagnostic {
  line: number;
  column: number;
  endLine: number | null;
  endColumn: number | null;
  message: string;
  severity: string;
}

export interface RhaiAnalysisResult {
  success: boolean;
  errors: AnalysisDiagnostic[];
  warnings?: AnalysisDiagnostic[];
}

export interface RhaiTestResult {
  success: boolean;
  output?: string;
  error?: string;
}

export const analyzeRhai = async (input: {
  script: string;
}): Promise<RhaiAnalysisResult> => {
  const data = await graphqlRequest<{ analyzeRhai: RhaiAnalysisResult }>(
    AnalyzeRhaiDocument,
    { input },
  );
  return data.analyzeRhai;
};

export const testRhaiExpression = async (input: {
  script: string;
  mockContext: string;
}): Promise<RhaiTestResult> => {
  const data = await graphqlRequest<{ testRhaiExpression: RhaiTestResult }>(
    TestRhaiExpressionDocument,
    { input },
  );
  return data.testRhaiExpression;
};

// --- Workflow executions ---

export interface WorkflowExecution {
  id: string;
  status: string;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  errorMessage: string | null;
  outputData: string | null;
  /** "manual" | "scheduled" | "webhook" | "actor_dispatch" | null */
  triggerType: string | null;
  /** UUID of the Actor that dispatched this execution, if any. */
  actorId: string | null;
}

export const getWorkflowExecutionHistory = async (
  workflowId: string,
  limit?: number,
): Promise<WorkflowExecution[]> => {
  const response = await graphqlRequest<{
    workflowExecutionHistory: WorkflowExecution[];
  }>(GetWorkflowExecutionHistoryDocument, {
    workflowId,
    pagination: limit ? { limit } : undefined,
  });
  return response.workflowExecutionHistory;
};

/**
 * Trigger a workflow, optionally impersonating an Actor. `actorId: undefined`
 * triggers as the calling user (the nullable GraphQL argument is omitted).
 */
export const triggerWorkflowAsActor = async (
  workflowId: string,
  actorId?: string,
): Promise<{ id: string }> => {
  const response = await graphqlRequest<{ triggerWorkflow: { id: string } }>(
    TriggerWorkflowAsActorDocument,
    { workflowId, actorId: actorId ?? null },
  );
  return response.triggerWorkflow;
};

// --- Actor types and helpers ---
// An Actor is an identity with a capability ceiling, budget, memory, and audit trail.
// An "AI Agent" is an Actor whose workflows use LLM nodes with INJECT_CONTEXT / MEMORY_WRITE_KEY.

export interface ActorSummary {
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
}

export interface ActorDetails extends ActorSummary {
  mcpToken: string | null;
  rateLimit: number | null;
  metadata: string | null;
  lastActiveAt: string | null;
}

export const listActors = async (): Promise<ActorSummary[]> => {
  const response = await graphqlRequest<{ actors: ActorSummary[] }>(
    ListActorSummariesDocument,
  );
  return response.actors;
};

export const getActor = async (id: string): Promise<ActorDetails> => {
  const response = await graphqlRequest<{ actor: ActorDetails }>(
    GetActorDocument,
    { id },
  );
  return response.actor;
};

export const createActor = async (input: {
  name: string;
  description?: string;
  maxCapabilityWorld?: string;
  totalBudgetUsd?: number;
  rateLimit?: number;
}): Promise<ActorSummary> => {
  const response = await graphqlRequest<{ createActor: ActorSummary }>(
    CreateActorDocument,
    { input },
  );
  return response.createActor;
};

export const updateActorStatus = async (
  id: string,
  status: "active" | "suspended",
): Promise<ActorSummary> => {
  const response = await graphqlRequest<{ updateActorStatus: ActorSummary }>(
    UpdateActorStatusDocument,
    { id, status },
  );
  return response.updateActorStatus;
};

export const terminateActor = async (
  id: string,
  cleanupWorkflows?: boolean,
): Promise<boolean> => {
  const response = await graphqlRequest<{ terminateActor: boolean }>(
    TerminateActorDocument,
    { id, cleanupWorkflows },
  );
  return response.terminateActor;
};

export interface ActorActionLogEntry {
  id: string;
  actionType: string;
  summary: string;
  timestamp: string;
  workflowId: string | null;
  executionId: string | null;
}

export interface ActorWorkflowItem {
  id: string;
  name: string;
  status: string | null;
  nodeCount: number;
  /** Serialized graph JSON — used to detect AI Actor (LLM + INJECT_CONTEXT). */
  graphJson: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ActorExecutionsSummary {
  totalExecutions: number;
  successfulExecutions: number;
  failedExecutions: number;
  activeExecutions: number;
}

export const getActorActionLog = async (
  actorId: string,
  limit = 50,
): Promise<ActorActionLogEntry[]> => {
  const response = await graphqlRequest<{
    actorActionLog: ActorActionLogEntry[];
  }>(GetActorActionLogDocument, { actorId, limit });
  return response.actorActionLog;
};

export const getActorWorkflows = async (
  actorId: string,
): Promise<ActorWorkflowItem[]> => {
  const response = await graphqlRequest<{
    actorWorkflows: ActorWorkflowItem[];
  }>(GetActorWorkflowsDocument, { actorId });
  return response.actorWorkflows;
};

export const getActorExecutionsSummary = async (
  actorId: string,
): Promise<ActorExecutionsSummary> => {
  const response = await graphqlRequest<{
    actorExecutionsSummary: ActorExecutionsSummary;
  }>(GetActorExecutionsSummaryDocument, { actorId });
  return response.actorExecutionsSummary;
};

export const updateActor = async (
  id: string,
  fields: { name?: string; description?: string; maxCapabilityWorld?: string },
): Promise<ActorSummary> => {
  const response = await graphqlRequest<{ updateActor: ActorSummary }>(
    UpdateActorDocument,
    { id, ...fields },
  );
  return response.updateActor;
};

export const cloneActor = async (
  id: string,
  name?: string,
): Promise<ActorSummary> => {
  const response = await graphqlRequest<{ cloneActor: ActorSummary }>(
    CloneActorDocument,
    { id, name },
  );
  return response.cloneActor;
};

// --- Actor memory ---

export interface ActorMemoryEntry {
  key: string;
  /** JSON-serialized value string — parse before use. */
  value: string;
  memoryType: string;
  expiresAt: string | null;
  updatedAt: string;
}

export const listActorMemories = async (
  actorId: string,
  memoryType?: string,
): Promise<ActorMemoryEntry[]> => {
  const response = await graphqlRequest<{ actorMemories: ActorMemoryEntry[] }>(
    GetActorMemoriesDocument,
    { actorId, memoryType: memoryType ?? null },
  );
  return response.actorMemories ?? [];
};

export const writeActorMemory = async (input: {
  actorId: string;
  key: string;
  value: string;
  memoryType?: string;
  ttlHours?: number | null;
}): Promise<ActorMemoryEntry> => {
  const response = await graphqlRequest<{
    writeActorMemory: ActorMemoryEntry;
  }>(WriteActorMemoryDocument, { input });
  return response.writeActorMemory;
};

export const deleteActorMemory = async (
  actorId: string,
  key: string,
): Promise<boolean> => {
  const response = await graphqlRequest<{ deleteActorMemory: boolean }>(
    DeleteActorMemoryDocument,
    { actorId, key },
  );
  return response.deleteActorMemory;
};

// --- Capability ceiling ---

export const getMyCapabilityCeiling = async (): Promise<string> => {
  const response = await graphqlRequest<{ myCapabilityCeiling: string }>(
    GetMyCapabilityCeilingDocument,
  );
  return response.myCapabilityCeiling ?? "http-node";
};

// --- Node template catalog ---

export interface NodeTemplate {
  id: string;
  name: string;
  category: string;
  description: string | null;
  configSchema: string;
  icon: string | null;
  allowedHosts: string[];
}

export const getNodeTemplates = async (
  category?: string,
): Promise<NodeTemplate[]> => {
  const response = await graphqlRequest<{ nodeTemplates: NodeTemplate[] }>(
    GetNodeTemplatesDocument,
    { category: category ?? null },
  );
  return response.nodeTemplates;
};

// --- OAuth ---

// Imperative on purpose: the OAuth-link handler needs the freshly-clicked
// provider id, not a value captured in a hook's render-time closure
// (MCP-863). Kept as a wrapper so components never touch the transport.
export const getOAuthLoginUrl = async (
  provider: string,
): Promise<string | null> => {
  const response = await graphqlRequest<{
    oauthLoginUrl: { authUrl: string } | null;
  }>(GetOAuthUrlDocument, { provider });
  return response.oauthLoginUrl?.authUrl ?? null;
};

// --- Integrations & MCP Agents ---

export interface ServiceIntegration {
  id: string;
  service: IntegrationService;
  accountIdentifier: string;
  connectedAt: string;
  status: string;
}

export const listServiceIntegrations = async (): Promise<
  ServiceIntegration[]
> => {
  const response = await graphqlRequest<{
    serviceIntegrations: ServiceIntegration[];
  }>(ListServiceIntegrationsDocument);
  return response.serviceIntegrations;
};

export const disconnectServiceIntegration = async (
  id: string,
  service: IntegrationService,
): Promise<boolean> => {
  const response = await graphqlRequest<{
    disconnectServiceIntegration: boolean;
  }>(DisconnectServiceIntegrationDocument, { id, service });
  return response.disconnectServiceIntegration;
};

export interface McpAgent {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export const listMcpAgents = async (): Promise<McpAgent[]> => {
  const response = await graphqlRequest<{ mcpAgents: McpAgent[] }>(
    ListMcpAgentsDocument,
  );
  return response.mcpAgents;
};

export const revokeMcpAgent = async (id: string): Promise<boolean> => {
  const response = await graphqlRequest<{ revokeMcpAgent: boolean }>(
    RevokeMcpAgentDocument,
    { id },
  );
  return response.revokeMcpAgent;
};
