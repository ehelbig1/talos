import { sanitizeErrorMessage } from "@/lib/sanitize";
import { getCsrfToken } from "@/lib/csrf";
import { config } from "@/config";
/**
 * Minimal GraphQL client used by the Talos frontend.
 * It provides a simple `graphqlRequest` for queries/mutations via HTTP
 * and a lightweight WebSocket helper for subscriptions.
 */

// Empty string = use relative URLs (proxied by Vite), or explicit URL for production
const API_URL = config.apiUrl || "";

/**
 * Dummy gql tag for graphql-codegen to pluck GraphQL strings.
 * It just returns the string as-is.
 */
export const gql = (strings: TemplateStringsArray, ...values: unknown[]) => {
  return strings.reduce((acc, str, i) => acc + str + (values[i] || ""), "");
};

// Singleton in-flight refresh promise.
// Concurrent callers (e.g. multiple queries returning 401 simultaneously) share
// the same promise instead of firing N parallel refresh requests ("thundering herd").
let activeRefreshPromise: Promise<boolean> | null = null;

// Singleton in-flight CSRF seed promise.
// Prevents the same thundering-herd problem on fresh sessions where many
// simultaneous queries all find the CSRF cookie absent and all fire a
// redundant preflight GET.
let activeSeedPromise: Promise<void> | null = null;

async function doTokenRefresh(): Promise<boolean> {
  try {
    // Note: We don't pass the refresh token explicitly anymore.
    // The backend reads it from the httpOnly cookie automatically.
    const mutation = `
      mutation RefreshToken {
        refreshToken {
          user {
            id
          }
        }
      }
    `;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    const csrfToken = getCsrfToken();
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }

    const resp = await fetch(`${API_URL}/graphql`, {
      method: "POST",
      headers,
      credentials: "include",
      cache: "no-store", // Send cookies
      body: JSON.stringify({
        query: mutation,
      }),
    });

    const text = await resp.text();
    let json: Record<string, unknown>;
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      if (import.meta.env.DEV) console.error("Failed to parse response:", text);
      return false;
    }
    if (
      (json.errors as unknown[])?.length ||
      !(json.data as Record<string, unknown>)?.refreshToken
    ) {
      return false;
    }

    // Token is now stored in httpOnly cookie by the backend
    return true;
  } catch {
    return false;
  }
}

async function attemptTokenRefresh(): Promise<boolean> {
  // Deduplicate concurrent refresh attempts: reuse any in-flight promise.
  if (activeRefreshPromise) {
    return activeRefreshPromise;
  }
  activeRefreshPromise = doTokenRefresh().finally(() => {
    activeRefreshPromise = null;
  });
  return activeRefreshPromise;
}

// Seed the CSRF cookie by GET-ing /auth/csrf — a dedicated endpoint that
// builds the Set-Cookie header by hand. We previously hit /graphql (405 in
// prod, no Set-Cookie) and then /health (no CSRF middleware in its router
// branch, no Set-Cookie). /auth/csrf is mounted under the chart's existing
// /auth/* nginx proxy and bypasses tower_cookies / CookieManagerLayer
// indirection entirely, so it reliably carries Set-Cookie.
async function seedCsrfCookie(): Promise<void> {
  if (activeSeedPromise) return activeSeedPromise;
  activeSeedPromise = (async () => {
    try {
      await fetch(`${API_URL}/auth/csrf`, {
        method: "GET",
        credentials: "include",
      });
    } catch {
      // Best-effort — if this fails the subsequent POST will surface a clear error.
    }
  })().finally(() => {
    activeSeedPromise = null;
  });
  return activeSeedPromise;
}

export async function graphqlRequest<T>(
  query: string,
  variables?: Record<string, unknown>,
  isRetry = false,
): Promise<T> {
  // Ensure CSRF cookie exists before making any POST.
  // Browsers silently discard Set-Cookie with Secure flag over HTTP (dev), so on a
  // fresh session the cookie may be absent.  A single preflight GET seeds it.
  if (!getCsrfToken()) {
    await seedCsrfCookie();
  }

  // Build headers - authentication is handled via httpOnly cookies
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Add distributed trace ID for request correlation
  const traceId =
    crypto.randomUUID?.() || Math.random().toString(36).substring(2);
  headers["X-Trace-ID"] = traceId;

  // Add CSRF token for mutations
  const csrfToken = getCsrfToken();
  if (csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  // Add a timeout to avoid hanging requests.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000); // 15s timeout

  let resp: Response;
  try {
    resp = await fetch(`${API_URL}/graphql`, {
      method: "POST",
      headers,
      body: JSON.stringify({ query, variables }),
      // "include" is required so the browser both stores Set-Cookie headers
      // from login/signup responses and sends the httpOnly auth cookies on every
      // subsequent request.  Using "omit" silently discards cookies in both
      // directions, breaking the entire auth model.
      credentials: "include",
      signal: controller.signal,
    });
  } catch (e) {
    // Network errors, timeouts, or aborts are surfaced as a generic error.
    // This helps UI components display a consistent message.
    clearTimeout(timeout);
    if (e instanceof Error && e.name === "AbortError") {
      throw new Error("Request timed out – please try again.", { cause: e });
    }
    throw new Error(e instanceof Error ? e.message : "Network error", {
      cause: e,
    });
  }

  clearTimeout(timeout);

  // Read body as text first so we can give a meaningful error if the server
  // returns a non-JSON response (e.g. a plain-text CSRF or gateway error).
  const text = await resp.text();
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    if (import.meta.env.DEV) console.error("Failed to parse response:", text);
    throw new Error(text || `Server error (HTTP ${resp.status})`);
  }

  interface GraphQLError {
    message: string;
    extensions?: { code?: string; [key: string]: unknown };
  }

  // Check for authentication errors
  if (json.errors) {
    const errors = json.errors as GraphQLError[];
    const hasAuthError = errors.some(
      (e) =>
        e.message.includes("Authentication required") ||
        e.message.includes("Not authenticated") ||
        e.message.includes("expired"),
    );

    if (hasAuthError && !isRetry) {
      const refreshed = await attemptTokenRefresh();
      if (refreshed) {
        return graphqlRequest<T>(query, variables, true);
      }
    }

    const rawMsg = errors.map((e) => e.message).join(", ");

    // If we're hitting rate limits, explicitly bubble that up instead of generic sanitization
    if (
      errors.some(
        (e) =>
          e.extensions?.code === "RATE_LIMITED" ||
          e.message.includes("Too Many Requests"),
      )
    ) {
      throw new Error(rawMsg);
    }

    // Sanitize and cap error message length to prevent overly verbose backend errors from
    // flooding the UI or leaking sensitive internal details.
    throw new Error(sanitizeErrorMessage(rawMsg));
  }

  return json.data as T;
}

/**
 * Fetcher wrapper for graphql-codegen-typescript-react-query.
 * It returns a function that calls graphqlRequest, which is what useQuery expects for queryFn.
 */
export function graphqlFetcher<TData, TVariables>(
  query: string,
  variables?: TVariables,
) {
  return () =>
    graphqlRequest<TData>(query, variables as Record<string, unknown>);
}

/**
 * Subscribe to a GraphQL subscription using a raw WebSocket.
 * The function returns an unsubscribe callback.
 */
export interface ExecutionUpdate {
  traceId?: string;
  spanId?: string;

  executionId: string;
  nodeId?: string;
  status: string;
  logMessage?: string;
  // Enhanced tracking fields
  retryAttempt?: number;
  maxRetries?: number;
  errorRecovery?: boolean;
  approvalRequired?: string[];
  checkpointSaved?: boolean;
  iterationIndex?: number;
  iterationTotal?: number;
  /** Server-side wall-clock duration in ms (node_started → node_completed). */
  durationMs?: number;
  /** Event timestamp from server. */
  timestamp?: string;
}

export interface DlqUpdate {
  id: string;
  workflowId?: string;
  executionId?: string;
  nodeId?: string;
  errorMessage?: string;
  payload?: string;
  createdAt: string;
  replayedAt?: string;
}

export interface WorkflowExecutionUpdate {
  workflowId: string;
  executionId: string;
  userId: string;
  status: string;
  startedAt: string;
  errorMessage?: string;
}

export interface CompilationUpdate {
  jobId: string;
  userId: string;
  status: string;
  message?: string;
  progress?: number;
}

function createSubscription<T>(
  query: string,
  variables: Record<string, unknown>,
  onEvent: (event: T) => void,
  dataKey: string,
): () => void {
  // MCP-900 (2026-05-14): respect explicit VITE_WS_URL when set. Pre-fix
  // `config.wsUrl` was defined in config.ts but never imported, so
  // operators setting VITE_WS_URL at build time got a value silently
  // dropped (Vite baked it into the bundle, nothing read it). Real-
  // world use case: a deploy with split API + WS endpoints (e.g.
  // `wss://ws.example.com` on a separate gateway from
  // `https://api.example.com`) cannot be expressed via the protocol-
  // replace derivation below. Order: explicit VITE_WS_URL > derive
  // from VITE_API_URL > window.location fallback.
  const wsUrl = config.wsUrl
    ? config.wsUrl
    : API_URL
      ? API_URL.replace("http://", "ws://").replace("https://", "wss://")
      : `${window.location.protocol === "https:" ? "wss" : "ws"}://${
          window.location.host
        }`;

  let ws: WebSocket | null = null;
  let subscriptionStarted = false;
  let isClosed = false;
  let reconnectAttempts = 0;
  let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  let connectionStartTime = 0;

  const connect = () => {
    if (isClosed) return;
    if (reconnectTimeout) {
      clearTimeout(reconnectTimeout);
      reconnectTimeout = null;
    }

    ws = new WebSocket(`${wsUrl}/ws`, "graphql-ws");
    subscriptionStarted = false;
    connectionStartTime = Date.now();

    ws.onopen = () => {
      reconnectAttempts = 0;
      ws?.send(JSON.stringify({ type: "connection_init", payload: {} }));
    };

    ws.onmessage = (msg) => {
      if (Date.now() - connectionStartTime > 24 * 60 * 60 * 1000) {
        ws?.close(1000, "Max connection lifetime exceeded");
        return;
      }

      try {
        const data = JSON.parse(msg.data);

        if (data.type === "connection_ack" && !subscriptionStarted) {
          subscriptionStarted = true;
          ws?.send(
            JSON.stringify({
              id: "1",
              type: "start",
              payload: { query, variables },
            }),
          );
        }

        if (data.type === "data" && data.id === "1") {
          onEvent(data.payload.data[dataKey]);
        }

        if (data.type === "connection_error") {
          // MCP-864 (2026-05-14): try refreshing the access token on
          // handshake auth failure before giving up. Without this, a
          // WS subscription open for longer than the 15-minute access
          // token TTL would silently stop receiving updates with no
          // reconnect (the 4403 close bypasses the backoff path), so
          // users staring at an execution timeline lose live events
          // mid-session. authedFetch already handles the equivalent
          // 401 path; this brings WS parity.
          ws?.close(4403, "Forbidden");
          attemptTokenRefresh().then((refreshed) => {
            if (refreshed && !isClosed) {
              reconnectAttempts = 0;
              connect();
            } else {
              isClosed = true;
            }
          });
          return;
        }

        if (data.type === "error" && Array.isArray(data.payload)) {
          const isAuthError = data.payload.some(
            (e: Record<string, unknown>) =>
              String(e.message)?.includes("Authentication required") ||
              String(e.message)?.includes("Not authenticated") ||
              String(e.message)?.includes("expired"),
          );

          if (isAuthError) {
            ws?.close(4403, "Forbidden");
            attemptTokenRefresh().then((refreshed) => {
              if (refreshed && !isClosed) {
                reconnectAttempts = 0;
                connect();
              } else {
                isClosed = true;
              }
            });
            return;
          }
        }
      } catch {
        // ignore
      }
    };

    ws.onclose = (event) => {
      if (isClosed) return;

      // Auth-fail close codes: never reconnect (the connection_error /
      // auth-error message handlers in onmessage already kicked off a
      // refresh-then-connect attempt). 4403 from policy violation,
      // 4401 from missing creds, 1008 from policy violation as well.
      if (event.code === 4403 || event.code === 4401 || event.code === 1008) {
        return;
      }

      // MCP-865 (2026-05-14): cap reconnect attempts so a permanently
      // broken WS server (wrong URL, removed Service, tab left open
      // for days against a decommissioned environment) doesn't loop
      // every 30s forever. Pre-subscribe failures (1006 before the
      // handshake completed) suggest auth or proxy misconfiguration
      // — give up faster. Post-subscribe (live → disconnected) is
      // typically a transient network blip, so retry more generously.
      const maxAttempts = subscriptionStarted ? 30 : 5;
      if (reconnectAttempts >= maxAttempts) {
        isClosed = true;
        return;
      }

      const timeout = Math.min(1000 * 2 ** reconnectAttempts, 30000);
      reconnectAttempts++;
      reconnectTimeout = setTimeout(() => connect(), timeout);
    };
  };

  connect();

  return () => {
    isClosed = true;
    if (reconnectTimeout) clearTimeout(reconnectTimeout);
    if (ws) ws.close();
  };
}

export function subscribeExecution(
  executionId: string,
  onEvent: (event: ExecutionUpdate) => void,
): () => void {
  return createSubscription<ExecutionUpdate>(
    `subscription ($execId: UUID!) { executionUpdates(executionId: $execId) { executionId nodeId status traceId spanId logMessage retryAttempt maxRetries errorRecovery approvalRequired checkpointSaved iterationIndex iterationTotal durationMs } }`,
    { execId: executionId },
    onEvent,
    "executionUpdates",
  );
}

export function subscribeDlqUpdates(
  onEvent: (event: DlqUpdate) => void,
): () => void {
  return createSubscription<DlqUpdate>(
    `subscription { dlqUpdates { id workflowId executionId nodeId errorMessage payload createdAt replayedAt } }`,
    {},
    onEvent,
    "dlqUpdates",
  );
}

export function subscribeWorkflowExecutions(
  onEvent: (event: WorkflowExecutionUpdate) => void,
): () => void {
  return createSubscription<WorkflowExecutionUpdate>(
    `subscription { workflowExecutionUpdates { workflowId executionId userId status startedAt errorMessage } }`,
    {},
    onEvent,
    "workflowExecutionUpdates",
  );
}

export function subscribeLlmStream(
  executionId: string,
  onToken: (token: string) => void,
): () => void {
  return createSubscription<string>(
    `subscription ($execId: UUID!) { llmStream(executionId: $execId) }`,
    { execId: executionId },
    onToken,
    "llmStream",
  );
}

export function subscribeCompilation(
  onEvent: (event: CompilationUpdate) => void,
): () => void {
  return createSubscription<CompilationUpdate>(
    `subscription { compilationUpdates { jobId userId status message progress } }`,
    {},
    onEvent,
    "compilationUpdates",
  );
}

// --- Typed interfaces for GraphQL responses ---

export interface AnalysisDiagnostic {
  line: number;
  column: number;
  endLine: number | null;
  endColumn: number | null;
  message: string;
  severity: string;
}

export interface ModuleExecution {
  id: string;
  status: string;
  durationMs: number | null;
  startedAt: string;
  errorMessage: string | null;
  outputData: string | null;
}

export interface ModuleExecutionLog {
  id: string;
  level: string;
  message: string;
  createdAt: string;
  metadata: string | null;
}

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

export const getModuleExecutionHistory = async (
  moduleId: string,
  limit?: number,
): Promise<ModuleExecution[]> => {
  const query = `
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
  const response = await graphqlRequest<{
    moduleExecutionHistory: ModuleExecution[];
  }>(query, {
    moduleId,
    pagination: limit ? { limit } : undefined,
  });
  return response.moduleExecutionHistory;
};

export const getModuleExecutionLogs = async (
  executionId: string,
): Promise<ModuleExecutionLog[]> => {
  const query = `
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
  const response = await graphqlRequest<{
    moduleExecutionLogs: ModuleExecutionLog[];
  }>(query, { executionId });
  return response.moduleExecutionLogs;
};

export const generateCode = async (input: {
  prompt: string;
  currentCode: string;
  capabilityWorld: string;
}): Promise<{ code: string }> => {
  const query = `
    mutation GenerateCode($input: GenerateCodeInput!) {
      generateCode(input: $input) {
        code
      }
    }
  `;
  const data = await graphqlRequest<{ generateCode: { code: string } }>(query, {
    input,
  });
  return data.generateCode;
};

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
  const query = `
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
  `;
  const data = await graphqlRequest<{ analyzeRhai: RhaiAnalysisResult }>(
    query,
    { input },
  );
  return data.analyzeRhai;
};

export const testRhaiExpression = async (input: {
  script: string;
  mockContext: string;
}): Promise<RhaiTestResult> => {
  const query = `
    query TestRhaiExpression($input: TestRhaiExpressionInput!) {
      testRhaiExpression(input: $input) {
        success
        output
        error
      }
    }
  `;
  const data = await graphqlRequest<{ testRhaiExpression: RhaiTestResult }>(
    query,
    { input },
  );
  return data.testRhaiExpression;
};

export const getWorkflowExecutionHistory = async (
  workflowId: string,
  limit?: number,
): Promise<WorkflowExecution[]> => {
  const query = `
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
  `;
  const response = await graphqlRequest<{
    workflowExecutionHistory: WorkflowExecution[];
  }>(query, {
    workflowId,
    pagination: limit ? { limit } : undefined,
  });
  return response.workflowExecutionHistory;
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

/** @deprecated Use ActorSummary */
export type ActorSummary_Legacy = ActorSummary;
/** @deprecated Use ActorDetails */
export type ActorDetails_Legacy = ActorDetails;

const ACTOR_SUMMARY_FIELDS = `
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
`;

export const listActors = async (): Promise<ActorSummary[]> => {
  const response = await graphqlRequest<{ actors: ActorSummary[] }>(
    /* GraphQL */ `
      query ListActors {
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
    `,
  );
  return response.actors;
};

/** @deprecated Use listActors */
export const listAgents = listActors;

export const getActor = async (id: string): Promise<ActorDetails> => {
  const response = await graphqlRequest<{ actor: ActorDetails }>(
    `
    query GetActor($id: UUID!) {
      actor(id: $id) {
        ${ACTOR_SUMMARY_FIELDS}
        mcpToken
        rateLimit
        metadata
        lastActiveAt
      }
    }
  `,
    { id },
  );
  return response.actor;
};

/** @deprecated Use getActor */
export const getAgent = getActor;

export const createActor = async (input: {
  name: string;
  description?: string;
  maxCapabilityWorld?: string;
  totalBudgetUsd?: number;
  rateLimit?: number;
}): Promise<ActorSummary> => {
  const response = await graphqlRequest<{ createActor: ActorSummary }>(
    `
    mutation CreateActor($input: CreateActorInput!) {
      createActor(input: $input) {
        ${ACTOR_SUMMARY_FIELDS}
      }
    }
  `,
    { input },
  );
  return response.createActor;
};

/** @deprecated Use createActor */
export const createAgent = createActor;

export const updateActorStatus = async (
  id: string,
  status: "active" | "suspended",
): Promise<ActorSummary> => {
  const response = await graphqlRequest<{ updateActorStatus: ActorSummary }>(
    `
    mutation UpdateActorStatus($id: UUID!, $status: String!) {
      updateActorStatus(id: $id, status: $status) {
        ${ACTOR_SUMMARY_FIELDS}
      }
    }
  `,
    { id, status },
  );
  return response.updateActorStatus;
};

/** @deprecated Use updateActorStatus */
export const updateAgentStatus = updateActorStatus;

export const terminateActor = async (
  id: string,
  cleanupWorkflows?: boolean,
): Promise<boolean> => {
  const response = await graphqlRequest<{ terminateActor: boolean }>(
    `
    mutation TerminateActor($id: UUID!, $cleanupWorkflows: Boolean) {
      terminateActor(id: $id, cleanupWorkflows: $cleanupWorkflows)
    }
  `,
    { id, cleanupWorkflows },
  );
  return response.terminateActor;
};

/** @deprecated Use terminateActor */
export const terminateAgent = terminateActor;

export interface ActorActionLogEntry {
  id: string;
  actionType: string;
  summary: string;
  timestamp: string;
  workflowId: string | null;
  executionId: string | null;
}

/** @deprecated Use ActorActionLogEntry */
export type AgentActionLogEntry = ActorActionLogEntry;

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

/** @deprecated Use ActorWorkflowItem */
export type AgentWorkflowItem = ActorWorkflowItem;

export interface ActorExecutionsSummary {
  totalExecutions: number;
  successfulExecutions: number;
  failedExecutions: number;
  activeExecutions: number;
}

/** @deprecated Use ActorExecutionsSummary */
export type AgentExecutionsSummary = ActorExecutionsSummary;

export const getActorActionLog = async (
  actorId: string,
  limit = 50,
): Promise<ActorActionLogEntry[]> => {
  const response = await graphqlRequest<{
    actorActionLog: ActorActionLogEntry[];
  }>(
    `
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
  `,
    { actorId, limit },
  );
  return response.actorActionLog;
};

/** @deprecated Use getActorActionLog */
export const getAgentActionLog = (actorId: string, limit?: number) =>
  getActorActionLog(actorId, limit);

export const getActorWorkflows = async (
  actorId: string,
): Promise<ActorWorkflowItem[]> => {
  const response = await graphqlRequest<{
    actorWorkflows: ActorWorkflowItem[];
  }>(
    `
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
  `,
    { actorId },
  );
  return response.actorWorkflows;
};

/** @deprecated Use getActorWorkflows */
export const getAgentWorkflows = (actorId: string) =>
  getActorWorkflows(actorId);

export const getActorExecutionsSummary = async (
  actorId: string,
): Promise<ActorExecutionsSummary> => {
  const response = await graphqlRequest<{
    actorExecutionsSummary: ActorExecutionsSummary;
  }>(
    `
    query GetActorExecutionsSummary($actorId: UUID!) {
      actorExecutionsSummary(actorId: $actorId) {
        totalExecutions
        successfulExecutions
        failedExecutions
        activeExecutions
      }
    }
  `,
    { actorId },
  );
  return response.actorExecutionsSummary;
};

/** @deprecated Use getActorExecutionsSummary */
export const getAgentExecutionsSummary = (actorId: string) =>
  getActorExecutionsSummary(actorId);

export const updateActor = async (
  id: string,
  fields: { name?: string; description?: string; maxCapabilityWorld?: string },
): Promise<ActorSummary> => {
  const response = await graphqlRequest<{ updateActor: ActorSummary }>(
    `mutation UpdateActor($id: UUID!, $name: String, $description: String, $maxCapabilityWorld: String) {
      updateActor(id: $id, name: $name, description: $description, maxCapabilityWorld: $maxCapabilityWorld) {
        id name description status maxCapabilityWorld
        workflowCount executionCount createdAt updatedAt
      }
    }`,
    { id, ...fields },
  );
  return response.updateActor;
};

export const cloneActor = async (
  id: string,
  name?: string,
): Promise<ActorSummary> => {
  const response = await graphqlRequest<{ cloneActor: ActorSummary }>(
    `mutation CloneActor($id: UUID!, $name: String) {
      cloneActor(id: $id, name: $name) {
        id name description status maxCapabilityWorld
        workflowCount executionCount createdAt updatedAt
      }
    }`,
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
    `query GetActorMemories($actorId: UUID!, $memoryType: String) {
      actorMemories(actorId: $actorId, memoryType: $memoryType) {
        key value memoryType expiresAt updatedAt
      }
    }`,
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
  }>(
    `mutation WriteActorMemory($input: WriteActorMemoryInput!) {
      writeActorMemory(input: $input) {
        key value memoryType expiresAt updatedAt
      }
    }`,
    { input },
  );
  return response.writeActorMemory;
};

export const deleteActorMemory = async (
  actorId: string,
  key: string,
): Promise<boolean> => {
  const response = await graphqlRequest<{ deleteActorMemory: boolean }>(
    `mutation DeleteActorMemory($actorId: UUID!, $key: String!) {
      deleteActorMemory(actorId: $actorId, key: $key)
    }`,
    { actorId, key },
  );
  return response.deleteActorMemory;
};

// --- Schedule types ---

export interface WorkflowSchedule {
  id: string;
  workflowId: string;
  cronExpression: string;
  timezone: string;
  isEnabled: boolean;
  lastTriggeredAt: string | null;
  nextTriggerAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export const getMySchedules = async (): Promise<WorkflowSchedule[]> => {
  const response = await graphqlRequest<{ mySchedules: WorkflowSchedule[] }>(`
    query GetMySchedules {
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
  return response.mySchedules;
};

// --- Platform health stats ---

export interface WorkflowStats {
  id: string;
  name: string;
  total: number;
  succeeded: number;
  failed: number;
  avgDurationSecs: number | null;
}

export const getWorkflowStats = async (
  days?: number,
): Promise<WorkflowStats[]> => {
  const response = await graphqlRequest<{
    getAllWorkflowStats: WorkflowStats[];
  }>(
    `
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
  `,
    { days },
  );
  return response.getAllWorkflowStats;
};

// --- Secrets list (for vault health) ---

export interface SecretSummary {
  id: string;
  name: string;
  keyPath: string;
  description: string | null;
  createdAt: string;
  lastAccessedAt: string | null;
  accessCount: number;
  expiresAt: string | null;
}

export const getSecrets = async (): Promise<SecretSummary[]> => {
  const response = await graphqlRequest<{ secrets: SecretSummary[] }>(`
    query GetSecrets {
      secrets {
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
  return response.secrets;
};

// --- Capability ceiling ---

export const getMyCapabilityCeiling = async (): Promise<string> => {
  const response = await graphqlRequest<{ myCapabilityCeiling: string }>(
    `query { myCapabilityCeiling }`,
  );
  return response.myCapabilityCeiling ?? "http-node";
};

// --- Webhook DLQ ---

export interface WebhookDlqEntry {
  id: string;
  triggerId: string | null;
  sourceIp: string | null;
  dropReason: string;
  headers: string | null;
  payload: string | null;
  createdAt: string;
  replayedAt: string | null;
  replayedBy: string | null;
}

export const getWebhookDeadLetterQueue = async (): Promise<
  WebhookDlqEntry[]
> => {
  const response = await graphqlRequest<{
    webhookDeadLetterQueue: WebhookDlqEntry[];
  }>(`
    query {
      webhookDeadLetterQueue {
        id triggerId sourceIp dropReason headers payload createdAt replayedAt replayedBy
      }
    }
  `);
  return response.webhookDeadLetterQueue ?? [];
};

export const replayWebhookDlqEntry = async (id: string): Promise<boolean> => {
  const response = await graphqlRequest<{
    replayWebhookDeadLetterEntry: boolean;
  }>(
    `mutation ReplayWebhookDLQ($id: UUID!) {
      replayWebhookDeadLetterEntry(id: $id)
    }`,
    { id },
  );
  return response.replayWebhookDeadLetterEntry ?? false;
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
    `query GetNodeTemplates($category: String) {
      nodeTemplates(category: $category) {
        id
        name
        category
        description
        configSchema
        icon
        allowedHosts
      }
    }`,
    { category: category ?? null },
  );
  return response.nodeTemplates;
};

// --- Integrations & MCP Agents ---

export enum IntegrationService {
  GoogleCalendar = "GOOGLE_CALENDAR",
  Gmail = "GMAIL",
  Slack = "SLACK",
  Jira = "JIRA",
}

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
  const query = `
    query ListServiceIntegrations {
      serviceIntegrations {
        id
        service
        accountIdentifier
        connectedAt
        status
      }
    }
  `;
  const response = await graphqlRequest<{
    serviceIntegrations: ServiceIntegration[];
  }>(query);
  return response.serviceIntegrations;
};

export const disconnectServiceIntegration = async (
  id: string,
  service: IntegrationService,
): Promise<boolean> => {
  const mutation = `
    mutation DisconnectServiceIntegration($id: UUID!, $service: IntegrationService!) {
      disconnectServiceIntegration(id: $id, service: $service)
    }
  `;
  const response = await graphqlRequest<{
    disconnectServiceIntegration: boolean;
  }>(mutation, { id, service });
  return response.disconnectServiceIntegration;
};

export interface McpAgent {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export const listMcpAgents = async (): Promise<McpAgent[]> => {
  const query = `
    query ListMcpAgents {
      mcpAgents {
        id
        name
        createdAt
        lastUsedAt
      }
    }
  `;
  const response = await graphqlRequest<{ mcpAgents: McpAgent[] }>(query);
  return response.mcpAgents;
};

export const revokeMcpAgent = async (id: string): Promise<boolean> => {
  const mutation = `
    mutation RevokeMcpAgent($id: UUID!) {
      revokeMcpAgent(id: $id)
    }
  `;
  const response = await graphqlRequest<{ revokeMcpAgent: boolean }>(mutation, {
    id,
  });
  return response.revokeMcpAgent;
};
