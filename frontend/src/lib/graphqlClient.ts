import { sanitizeErrorMessage } from "@/lib/sanitize";
import { getCsrfToken } from "@/lib/csrf";
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

/**
 * Accepted operation document forms: a plain string, or a generated
 * `TypedDocumentString` constant from `@/generated/graphql` (a `String`
 * subclass — normalized via `.toString()` before hitting the wire).
 */
export type GraphQLDocument = string | String;

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
          // Surface GraphQL errors instead of swallowing them. A query that
          // references a non-existent field returns `{data: null, errors}`,
          // and blindly indexing `data.payload.data[dataKey]` would throw into
          // the catch below — silently dropping every event with no signal.
          const payloadData = data.payload?.data;
          if (payloadData && payloadData[dataKey] != null) {
            onEvent(payloadData[dataKey]);
          } else if (data.payload?.errors?.length) {
            console.error(
              `[subscription:${dataKey}] server returned errors:`,
              data.payload.errors,
            );
          }
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
