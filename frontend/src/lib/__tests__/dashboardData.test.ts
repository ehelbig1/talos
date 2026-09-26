/**
 * The dashboard's reads: `workflows` is paged (the server's default page of
 * 100 silently hid the rest), truncation past the cap is reported, and
 * `latestWorkflowExecutions` is chunked under its 200-id limit.
 */
import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/graphqlClient", () => ({ graphqlRequest: vi.fn() }));

import {
  DASHBOARD_WORKFLOW_CAP,
  LATEST_EXECUTIONS_ID_CAP,
  WORKFLOW_PAGE_SIZE,
  fetchDashboardWorkflows,
  fetchLatestExecutions,
} from "../dashboardData";

function serverWith(total: number) {
  const calls: Array<{ limit: number; offset: number }> = [];
  const queries: string[] = [];
  const request = vi.fn(
    async (q: string, vars?: Record<string, unknown>): Promise<never> => {
      queries.push(q);
      const { limit, offset } = (
        vars as { pagination: { limit: number; offset: number } }
      ).pagination;
      calls.push({ limit, offset });
      const n = Math.max(0, Math.min(limit, total - offset));
      return {
        workflows: Array.from({ length: n }, (_, i) => ({
          id: `w${offset + i}`,
          name: `W${offset + i}`,
          nodeCount: offset + i === 0 ? 2 : null,
          edgeCount: offset + i === 0 ? 1 : null,
        })),
      } as never;
    },
  );
  return { request, calls, queries };
}

describe("fetchDashboardWorkflows", () => {
  it("pages past the server's default page and takes the server's counts", async () => {
    const { request, calls, queries } = serverWith(WORKFLOW_PAGE_SIZE + 3);
    const out = await fetchDashboardWorkflows(request as never);
    expect(out.workflows).toHaveLength(WORKFLOW_PAGE_SIZE + 3);
    expect(out.truncated).toBe(false);
    expect(out.workflows[0]).toMatchObject({ nodeCount: 2, edgeCount: 1 });
    // An uncountable graph stays unknown rather than reading as empty.
    expect(out.workflows[1]).toMatchObject({
      nodeCount: null,
      edgeCount: null,
    });
    expect(out.workflows[0]).not.toHaveProperty("graphJson");
    // The whole graph is never downloaded just to count it.
    for (const q of queries) {
      expect(q).not.toMatch(/graphJson/);
    }
    expect(queries[0]).toMatch(/nodeCount[\s\S]*edgeCount/);
    expect(calls).toEqual([
      { limit: WORKFLOW_PAGE_SIZE, offset: 0 },
      { limit: WORKFLOW_PAGE_SIZE, offset: WORKFLOW_PAGE_SIZE },
    ]);
  });

  it("reports truncation when more workflows exist than the cap", async () => {
    const { request } = serverWith(DASHBOARD_WORKFLOW_CAP + 1);
    const out = await fetchDashboardWorkflows(request as never);
    expect(out.workflows).toHaveLength(DASHBOARD_WORKFLOW_CAP);
    expect(out.truncated).toBe(true);
  });

  it("an exact-cap population is not truncated", async () => {
    const { request } = serverWith(DASHBOARD_WORKFLOW_CAP);
    const out = await fetchDashboardWorkflows(request as never);
    expect(out.truncated).toBe(false);
  });
});

describe("fetchLatestExecutions", () => {
  it("never sends more ids than the server accepts", async () => {
    const request = vi.fn(
      async (_q: string, vars?: Record<string, unknown>) => {
        const ids = (vars as { workflowIds: string[] }).workflowIds;
        expect(ids.length).toBeLessThanOrEqual(LATEST_EXECUTIONS_ID_CAP);
        return {
          latestWorkflowExecutions: ids.map((workflowId) => ({ workflowId })),
        };
      },
    );
    const ids = Array.from({ length: 450 }, (_, i) => `w${i}`);
    const out = await fetchLatestExecutions(ids, request as never);
    expect(request).toHaveBeenCalledTimes(3);
    expect(out.latestWorkflowExecutions).toHaveLength(450);
  });
});
