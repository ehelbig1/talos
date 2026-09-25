import { sanitizeErrorMessage } from "@/lib/sanitize";
import { getCsrfToken } from "@/lib/csrf";
import {
  currentRefreshEpoch,
  isAuthErrorMessage,
  recoverSession,
  seedCsrfCookie,
} from "@/lib/session";
import { subscribeOverSharedSocket } from "@/lib/wsHub";
import { config } from "@/config";
/**
 * Minimal GraphQL client used by the Talos frontend — TRANSPORT ONLY.
 *
 * This module owns:
 *   - `graphqlRequest` / `graphqlFetcher`: HTTP transport with CSRF seeding,
 *     the singleton auth-refresh, timeouts, and error sanitization.
 *   - `createSubscription`-based WebSocket subscription helpers.
 *
 * Operation documents do NOT live here. They live in `src/graphql/*.graphql`
 * (plus component-local gql`...` tags) and are compiled by graphql-codegen
 * into typed react-query hooks in `src/generated/graphql.ts`. Imperative
 * typed wrappers over those documents live in `src/lib/graphqlApi.ts`.
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

// The CSRF seed, the token refresh and the auth-error match live in ONE home
// (`session.ts`, 2026-09-22): this file used to carry its own copies with its
// own in-flight promise, so it and `authedFetch.ts` could refresh concurrently
// and race the rotating refresh token against each other.
/**
 * Accepted operation document forms: a plain string, or a generated
 * `TypedDocumentString` constant from `@/generated/graphql` (a `String`
 * subclass — normalized via `.toString()` before hitting the wire).
 */
export type GraphQLDocument = string | String;

/**
 * `extensions.code` the server attaches when `updateWorkflow`'s
 * `expectedGraphVersion` no longer matches the stored graph (someone else
 * changed it since it was loaded). Mirrors
 * `talos_api::schema::workflows::mutations::GRAPH_VERSION_CONFLICT_CODE`.
 */
export const GRAPH_VERSION_CONFLICT_CODE = "GRAPH_VERSION_CONFLICT";

/**
 * A GraphQL error the caller must be able to recognise by CODE — the
 * production sanitizer canonicalises message text, so a message match would
 * not survive it. Only codes a caller acts on are raised this way.
 */
export class GraphQLCodedError extends Error {
  readonly code: string;
  constructor(message: string, code: string) {
    super(message);
    this.name = "GraphQLCodedError";
    this.code = code;
  }
}

export async function graphqlRequest<T>(
  query: GraphQLDocument,
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

  // Captured BEFORE the request leaves: if a refresh succeeds while this
  // request is on the wire with the stale cookie, its auth failure is
  // recovered by retrying, not by a second refresh (package DS).
  const epochAtSend = currentRefreshEpoch();

  let resp: Response;
  try {
    resp = await fetch(`${API_URL}/graphql`, {
      method: "POST",
      headers,
      body: JSON.stringify({ query: query.toString(), variables }),
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
    const hasAuthError = errors.some((e) => isAuthErrorMessage(e.message));

    if (hasAuthError && !isRetry) {
      const recovered = await recoverSession(epochAtSend);
      if (recovered) {
        return graphqlRequest<T>(query, variables, true);
      }
    }

    const rawMsg = errors.map((e) => e.message).join(", ");

    const conflict = errors.find(
      (e) => e.extensions?.code === GRAPH_VERSION_CONFLICT_CODE,
    );
    if (conflict) {
      throw new GraphQLCodedError(
        sanitizeErrorMessage(conflict.message),
        GRAPH_VERSION_CONFLICT_CODE,
      );
    }

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
  query: GraphQLDocument,
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
  /**
   * Final aggregated output, keyed by node id, populated on the terminal event
   * of a test run (see test_workflow). Absent for normal executions.
   */
  output?: Record<string, unknown> | null;
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

/**
 * Since package DV every subscription rides the page's ONE shared socket
 * (`wsHub.ts`). This kept its signature so the five helpers below and their
 * callers are unchanged; the connection, replay, `stop`, idle close, backoff
 * and auth recovery all live in the hub.
 */
function createSubscription<T>(
  query: string,
  variables: Record<string, unknown>,
  onEvent: (event: T) => void,
  dataKey: string,
): () => void {
  return subscribeOverSharedSocket(query, variables, onEvent, dataKey);
}

export function subscribeExecution(
  executionId: string,
  onEvent: (event: ExecutionUpdate) => void,
): () => void {
  return createSubscription<ExecutionUpdate>(
    // NOTE: only fields that actually exist on the GraphQL `ExecutionEvent`
    // type. A prior version of this query also requested
    // `retryAttempt maxRetries errorRecovery approvalRequired checkpointSaved`,
    // none of which exist on the schema type — that made the whole subscription
    // fail validation (`{data: null, errors: [...]}`), so `data.payload.data`
    // was null and every event was silently dropped (see the try/catch in
    // createSubscription). The subscription delivered ZERO events to any
    // consumer (execution monitor + test modal). Keep this selection in sync
    // with the `ExecutionEvent` SimpleObject in talos-engine-events.
    `subscription ($execId: UUID!) { executionUpdates(executionId: $execId) { executionId nodeId status traceId spanId logMessage iterationIndex iterationTotal durationMs output } }`,
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
