/**
 * Dashboard data reads, kept out of the page so the paging and chunking
 * rules are testable without rendering it.
 *
 * - `workflows` is paged (the server's default page is 100, so the dashboard
 *   silently showed the first 100) up to `DASHBOARD_WORKFLOW_CAP`, with the
 *   truncation reported rather than implied away.
 * - The graph is parsed ONCE per fetch into node/edge counts and dropped, so
 *   a card never parses it on render. (The server has no count fields yet, so
 *   the full `graphJson` is still downloaded.)
 * - `latestWorkflowExecutions` refuses more than 200 ids, so it is chunked.
 */
import { useQuery } from "@tanstack/react-query";
import { graphqlRequest } from "@/lib/graphqlClient";
import {
  LatestWorkflowExecutionsDocument,
  type LatestWorkflowExecutionsQuery,
} from "@/generated/graphql";

export const WORKFLOW_PAGE_SIZE = 500;
export const DASHBOARD_WORKFLOW_CAP = 2000;
export const LATEST_EXECUTIONS_ID_CAP = 200;

const DASHBOARD_WORKFLOWS_QUERY = `query DashboardWorkflows($pagination: PaginationInput) {
  workflows(pagination: $pagination) {
    id
    name
    graphJson
    actorId
  }
}`;

export interface DashboardWorkflow {
  id: string;
  name: string;
  actorId?: string | null;
  nodeCount: number;
  edgeCount: number;
}

export interface DashboardWorkflows {
  workflows: DashboardWorkflow[];
  /** More workflows exist than the dashboard loaded. */
  truncated: boolean;
}

type Request = <T>(
  query: string,
  variables?: Record<string, unknown>,
) => Promise<T>;

export function graphCounts(graphJson: string): {
  nodeCount: number;
  edgeCount: number;
} {
  try {
    const g = JSON.parse(graphJson) as { nodes?: unknown; edges?: unknown };
    return {
      nodeCount: Array.isArray(g.nodes) ? g.nodes.length : 0,
      edgeCount: Array.isArray(g.edges) ? g.edges.length : 0,
    };
  } catch {
    return { nodeCount: 0, edgeCount: 0 };
  }
}

export async function fetchDashboardWorkflows(
  request: Request = graphqlRequest,
): Promise<DashboardWorkflows> {
  const workflows: DashboardWorkflow[] = [];
  for (let offset = 0; offset < DASHBOARD_WORKFLOW_CAP; ) {
    const limit = Math.min(WORKFLOW_PAGE_SIZE, DASHBOARD_WORKFLOW_CAP - offset);
    const page = await request<{
      workflows: Array<{
        id: string;
        name: string;
        graphJson: string;
        actorId?: string | null;
      }>;
    }>(DASHBOARD_WORKFLOWS_QUERY, { pagination: { limit, offset } });
    for (const w of page.workflows) {
      workflows.push({
        id: w.id,
        name: w.name,
        actorId: w.actorId,
        ...graphCounts(w.graphJson),
      });
    }
    if (page.workflows.length < limit) {
      return { workflows, truncated: false };
    }
    offset += limit;
  }
  // The cap was reached with full pages: one probe says whether more exist.
  const probe = await request<{ workflows: Array<{ id: string }> }>(
    `query DashboardWorkflowsProbe($pagination: PaginationInput) {
  workflows(pagination: $pagination) { id }
}`,
    { pagination: { limit: 1, offset: DASHBOARD_WORKFLOW_CAP } },
  );
  return { workflows, truncated: probe.workflows.length > 0 };
}

export async function fetchLatestExecutions(
  workflowIds: string[],
  request: Request = graphqlRequest,
): Promise<LatestWorkflowExecutionsQuery> {
  const chunks: string[][] = [];
  for (let i = 0; i < workflowIds.length; i += LATEST_EXECUTIONS_ID_CAP) {
    chunks.push(workflowIds.slice(i, i + LATEST_EXECUTIONS_ID_CAP));
  }
  const pages = await Promise.all(
    chunks.map((ids) =>
      request<LatestWorkflowExecutionsQuery>(
        LatestWorkflowExecutionsDocument.toString(),
        { workflowIds: ids },
      ),
    ),
  );
  return {
    latestWorkflowExecutions: pages.flatMap((p) => p.latestWorkflowExecutions),
  };
}

export function useDashboardWorkflows() {
  // The ["Workflows", …] prefix keeps every existing invalidation working.
  return useQuery({
    queryKey: ["Workflows", "dashboard"],
    queryFn: () => fetchDashboardWorkflows(),
    staleTime: 60_000,
  });
}

export function useLatestExecutions(workflowIds: string[]) {
  return useQuery({
    queryKey: ["LatestWorkflowExecutions", { workflowIds }],
    queryFn: () => fetchLatestExecutions(workflowIds),
    enabled: workflowIds.length > 0,
    // WebSocket handles immediate start-up telemetry; this heartbeat is the
    // fallback for terminal state transitions.
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  });
}
