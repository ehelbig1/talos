import { describe, it, expect, vi, beforeEach } from "vitest";
import { loadWorkflowById } from "../workflowLoader";
import { useWorkflowStore } from "@/store/workflowStore";
import { graphql, HttpResponse } from "msw";
import { server } from "../../../vitest.setup";

describe("workflowLoader", () => {
  beforeEach(() => {
    useWorkflowStore.getState().clearWorkflow();
    vi.stubGlobal("console", {
      log: vi.fn(),
      error: vi.fn(),
      warn: vi.fn(),
    });
  });

  it("successfully loads a workflow and its module metadata", async () => {
    const workflowId = "wf-123";
    const moduleId = "00000000-0000-0000-0000-000000000001";

    server.use(
      graphql.query("GetWorkflowLoader", () => {
        return HttpResponse.json({
          data: {
            workflow: {
              id: workflowId,
              name: "Test Workflow",
              graphJson: JSON.stringify({
                nodes: [
                  {
                    id: "node-1",
                    type: moduleId,
                    position: { x: 10, y: 20 },
                    data: { foo: "bar" },
                  },
                ],
                edges: [
                  { source: "node-1", target: "node-2", condition: "true" },
                ],
              }),
            },
          },
        });
      }),
      graphql.query("GetModulesLoader", () => {
        return HttpResponse.json({
          data: {
            wasmModules: [
              {
                id: moduleId,
                name: "Mock Module",
                config: JSON.stringify({ default: "config" }),
                capabilityWorld: "world",
                importedInterfaces: ["iface"],
              },
            ],
          },
        });
      }),
    );

    await loadWorkflowById(workflowId);

    const state = useWorkflowStore.getState();
    expect(state.workflowId).toBe(workflowId);
    expect(state.workflowName).toBe("Test Workflow");
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0].data.moduleName).toBe("Mock Module");
    expect(state.nodes[0].data.config).toEqual({ foo: "bar" }); // Node data takes precedence
    expect(state.edges).toHaveLength(1);
    expect(state.edges[0].data?.condition).toBe("true");
  });

  it("throws error on invalid graph JSON", async () => {
    server.use(
      graphql.query("GetWorkflowLoader", () => {
        return HttpResponse.json({
          data: {
            workflow: {
              id: "wf-1",
              name: "Bad Workflow",
              graphJson: "not-json",
            },
          },
        });
      }),
    );

    await expect(loadWorkflowById("wf-1")).rejects.toThrow(
      /invalid graph data/,
    );
  });

  it("throws error on non-UUID module IDs", async () => {
    server.use(
      graphql.query("GetWorkflowLoader", () => {
        return HttpResponse.json({
          data: {
            workflow: {
              id: "wf-1",
              name: "Malicious Workflow",
              graphJson: JSON.stringify({
                nodes: [{ id: "n1", type: "not-a-uuid" }],
                edges: [],
              }),
            },
          },
        });
      }),
    );

    await expect(loadWorkflowById("wf-1")).rejects.toThrow(
      /invalid module IDs/,
    );
  });

  it("handles excessively large payloads", async () => {
    server.use(
      graphql.query("GetWorkflowLoader", () => {
        return HttpResponse.json({
          data: {
            workflow: {
              id: "wf-1",
              name: "Huge Workflow",
              graphJson: "a".repeat(3 * 1024 * 1024), // 3 MiB
            },
          },
        });
      }),
    );

    await expect(loadWorkflowById("wf-1")).rejects.toThrow(
      /exceeds the 2 MiB size limit/,
    );
  });
});
