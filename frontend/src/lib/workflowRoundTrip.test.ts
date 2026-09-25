/**
 * Load → save round trip of an MCP-authored graph through the REAL editor
 * loader (`loadWorkflowById`) and the REAL saver (`buildGraphDocument`,
 * `useWorkflowSave`).
 *
 * Until 2026-09-25 opening a workflow in the editor and pressing Save deleted
 * every execution control the MCP tools had written: `skip_condition` /
 * `continue_on_error` / `timeout_secs` in `data` (overwritten by the editor's
 * EMPTY typed fields and then dropped by JSON.stringify), `retry_*` at the
 * node's top level (never loaded), and every other top-level node / edge /
 * graph key (`execution_timeout_secs`, `kind`, `description`, edge `logic`).
 * These tests read what the ENGINE would read before and after.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement, type ReactNode } from "react";
import type * as GraphqlClientModule from "@/lib/graphqlClient";

vi.mock("@/lib/graphqlClient", async (importOriginal) => {
  const actual = await importOriginal<typeof GraphqlClientModule>();
  return { ...actual, graphqlRequest: vi.fn() };
});
vi.mock("sonner", () => ({
  toast: { error: vi.fn(), success: vi.fn(), info: vi.fn() },
}));

import {
  GRAPH_VERSION_CONFLICT_CODE,
  GraphQLCodedError,
  graphqlRequest,
} from "@/lib/graphqlClient";
import { loadWorkflowById } from "@/lib/workflowLoader";
import { buildGraphDocument, useWorkflowSave } from "@/hooks/useWorkflowSave";
import { useWorkflowStore } from "@/store/workflowStore";
import { toast } from "sonner";

const WF_ID = "11111111-1111-4111-8111-111111111111";
const MOD_FETCH = "22222222-2222-4222-8222-222222222222";
const MOD_SEND = "33333333-3333-4333-8333-333333333333";

type Json = Record<string, unknown>;

/** A graph exactly as the MCP writers shape it: `skip_condition` /
 *  `continue_on_error` inside `data` (add_skip_condition,
 *  set_continue_on_error), `retry_*` + `timeout_secs` at the node's top level
 *  (update_node_config action=update_retry, build_add_node_payload), `kind`
 *  on system nodes, `execution_timeout_secs` at the graph's top level
 *  (set_workflow_execution_timeout). */
const MCP_GRAPH: Json = {
  execution_timeout_secs: 420,
  priority: "high",
  future_graph_key: { keep: ["me"] },
  nodes: [
    {
      id: "fetch",
      type: MOD_FETCH,
      position: { x: 0, y: 0 },
      description: "Fetches the inbox",
      retry_count: 3,
      retry_backoff_ms: 2000,
      retry_condition: "status != 429",
      retry_delay_expression: "retry_after * 1000",
      timeout_secs: 45,
      data: {
        MAX_RESULTS: 10,
        skip_condition: "dry_run == true",
        continue_on_error: true,
      },
    },
    {
      id: "send",
      type: MOD_SEND,
      position: { x: 200, y: 0 },
      data: { TO: "ops@example.com" },
    },
    {
      id: "gather",
      type: "system:collect",
      kind: "collect",
      position: { x: 400, y: 0 },
      data: { continue_on_error: true },
    },
    {
      // An ill-typed control: the engine ignores a string timeout, so the
      // editor must not "own" it either — it round-trips byte-for-byte rather
      // than being overwritten by the editor's empty field.
      id: "legacy",
      type: MOD_SEND,
      position: { x: 200, y: 200 },
      data: { timeout_secs: "30", NOTE: "hand-edited" },
    },
    {
      // A backoff with NO count: the engine's method-aware default decides how
      // many retries; the editor must not invent a count.
      id: "backoff_only",
      type: MOD_FETCH,
      position: { x: 0, y: 200 },
      retry_backoff_ms: 500,
      data: {},
    },
  ],
  edges: [
    {
      id: "e-fetch-send",
      source: "fetch",
      target: "send",
      edge_type: "default",
      logic: { condition: "ok == true" },
    },
    {
      source: "fetch",
      target: "gather",
      edge_type: "conditional",
      condition: "count > 0",
    },
  ],
};

/** What the engine reads from a node (engine_graph_load.rs + graph_parser.rs
 *  precedence), so "preserved" means preserved AS THE ENGINE SEES IT. */
function engineView(graph: Json) {
  const out: Record<string, Json> = {};
  for (const n of graph.nodes as Json[]) {
    const d = (n.data ?? {}) as Json;
    const pick = (a: unknown, b: unknown) => (a !== undefined ? a : b);
    out[n.id as string] = {
      skip_condition: pick(d.skip_condition, n.skip_condition),
      continue_on_error:
        d.continue_on_error === true || n.continue_on_error === true,
      timeout_secs: pick(d.timeout_secs, n.timeout_secs),
      retry_count: pick(n.retry_count, d.retry_count),
      retry_backoff_ms: pick(n.retry_backoff_ms, d.retry_backoff_ms),
      retry_condition: pick(n.retry_condition, d.retry_condition),
      retry_delay_expression: pick(
        n.retry_delay_expression,
        d.retry_delay_expression,
      ),
    };
  }
  return out;
}

function mockBackend(graph: Json, graphVersion: number) {
  vi.mocked(graphqlRequest).mockImplementation(async (doc: unknown) => {
    const text = String(doc);
    if (text.includes("GetWorkflowLoader")) {
      return {
        workflow: {
          id: WF_ID,
          name: "inbox-triage",
          graphJson: JSON.stringify(graph),
          graphVersion,
          actorId: null,
          maxConcurrentExecutions: 2,
          intent: null,
        },
      };
    }
    if (text.includes("GetModulesLoader")) {
      return {
        wasmModules: [MOD_FETCH, MOD_SEND].map((id) => ({
          id,
          name: `module-${id.slice(0, 4)}`,
          config: "{}",
          configSchema: null,
          catalogSlug: null,
          sourceCode: null,
          capabilityWorld: "http-node",
          importedInterfaces: [],
        })),
      };
    }
    throw new Error(`unexpected document: ${text.slice(0, 60)}`);
  });
}

/** Load through the real loader, save through the real serializer. */
async function loadThenSave(graph: Json, graphVersion = 7): Promise<Json> {
  mockBackend(graph, graphVersion);
  await loadWorkflowById(WF_ID);
  return JSON.parse(
    JSON.stringify(buildGraphDocument(useWorkflowStore.getState())),
  ) as Json;
}

function node(graph: Json, id: string): Json {
  const n = (graph.nodes as Json[]).find((x) => x.id === id);
  if (!n) throw new Error(`node ${id} missing from saved graph`);
  return n;
}

beforeEach(() => {
  vi.mocked(graphqlRequest).mockReset();
  vi.mocked(toast.error).mockReset();
  useWorkflowStore.getState().clearWorkflow();
});

describe("editor load → save of an MCP-authored graph", () => {
  it("keeps every execution control exactly as the engine reads it", async () => {
    const saved = await loadThenSave(MCP_GRAPH);
    expect(engineView(saved)).toEqual(engineView(MCP_GRAPH));
  });

  it("keeps skip_condition / continue_on_error that MCP stored in data", async () => {
    const saved = await loadThenSave(MCP_GRAPH);
    const fetchData = node(saved, "fetch").data as Json;
    // The exact pre-fix loss: these were overwritten by `undefined`.
    expect(fetchData.skip_condition).toBe("dry_run == true");
    expect(fetchData.continue_on_error).toBe(true);
    expect(fetchData.MAX_RESULTS).toBe(10);
    expect((node(saved, "gather").data as Json).continue_on_error).toBe(true);
  });

  it("keeps the top-level retry_* family and timeout_secs", async () => {
    const saved = await loadThenSave(MCP_GRAPH);
    const fetch = node(saved, "fetch");
    expect(fetch.retry_count).toBe(3);
    expect(fetch.retry_backoff_ms).toBe(2000);
    expect(fetch.retry_condition).toBe("status != 429");
    expect(fetch.retry_delay_expression).toBe("retry_after * 1000");
    expect(fetch.timeout_secs).toBe(45);
  });

  it("carries an ill-typed control through unchanged instead of deleting it", async () => {
    const saved = await loadThenSave(MCP_GRAPH);
    expect(node(saved, "legacy").data).toEqual({
      timeout_secs: "30",
      NOTE: "hand-edited",
    });
  });

  it("does not invent a retry count for a node that declared only a backoff", async () => {
    const saved = await loadThenSave(MCP_GRAPH);
    const n = node(saved, "backoff_only");
    expect(n.retry_backoff_ms).toBe(500);
    expect(n).not.toHaveProperty("retry_count");
    expect(n.data).not.toHaveProperty("retry_count");
  });

  it("does not add controls to a node that had none", async () => {
    const saved = await loadThenSave(MCP_GRAPH);
    const send = node(saved, "send");
    for (const key of [
      "skip_condition",
      "continue_on_error",
      "timeout_secs",
      "retry_count",
      "retry_backoff_ms",
      "retry_condition",
      "retry_delay_expression",
    ]) {
      expect(send).not.toHaveProperty(key);
      expect(send.data).not.toHaveProperty(key);
    }
    expect(send.data).toEqual({ TO: "ops@example.com" });
  });

  it("carries unknown node, edge and graph keys through", async () => {
    const saved = await loadThenSave(MCP_GRAPH);
    expect(saved.execution_timeout_secs).toBe(420);
    expect(saved.future_graph_key).toEqual({ keep: ["me"] });
    expect(saved.priority).toBe("high");
    expect(node(saved, "fetch").description).toBe("Fetches the inbox");
    expect(node(saved, "gather").kind).toBe("collect");

    const edges = saved.edges as Json[];
    const first = edges.find((e) => e.target === "send")!;
    expect(first.id).toBe("e-fetch-send");
    expect(first.logic).toEqual({ condition: "ok == true" });
    // Editor bookkeeping never leaks into the stored edge's data.
    expect(first.data).not.toHaveProperty("storedEdgeExtras");
    const second = edges.find((e) => e.target === "gather")!;
    expect(second.condition).toBe("count > 0");
    expect(second.edge_type).toBe("conditional");
    // …nor into a stored node.
    for (const n of saved.nodes as Json[]) {
      expect(n).not.toHaveProperty("storedNodeExtras");
      expect(n.data).not.toHaveProperty("storedNodeExtras");
    }
  });

  it("is a fixed point: a second load → save changes nothing", async () => {
    const once = await loadThenSave(MCP_GRAPH);
    useWorkflowStore.getState().clearWorkflow();
    const twice = await loadThenSave(once);
    expect(twice).toEqual(once);
  });

  it("clearing a control in the editor removes it everywhere", async () => {
    await loadThenSave(MCP_GRAPH);
    useWorkflowStore.getState().updateNodeData("fetch", {
      skipCondition: undefined,
      retryPolicy: undefined,
    });
    const saved = JSON.parse(
      JSON.stringify(buildGraphDocument(useWorkflowStore.getState())),
    ) as Json;
    const fetch = node(saved, "fetch");
    // No stale copy left behind in the config or at the top level.
    expect(fetch).not.toHaveProperty("skip_condition");
    expect(fetch.data).not.toHaveProperty("skip_condition");
    expect(fetch).not.toHaveProperty("retry_count");
    expect(fetch.data).not.toHaveProperty("retry_count");
    // The untouched control survives.
    expect((fetch.data as Json).continue_on_error).toBe(true);
  });
});

describe("save sends the loaded graph version", () => {
  function renderSave() {
    const client = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    });
    const wrapper = ({ children }: { children: ReactNode }) =>
      createElement(QueryClientProvider, { client }, children);
    return renderHook(
      () =>
        useWorkflowSave({ workflowId: WF_ID, workflowName: "inbox-triage" }),
      { wrapper },
    );
  }

  it("passes expectedGraphVersion and adopts the version the server returns", async () => {
    mockBackend(MCP_GRAPH, 7);
    await loadWorkflowById(WF_ID);
    expect(useWorkflowStore.getState().graphVersion).toBe(7);

    vi.mocked(graphqlRequest).mockResolvedValueOnce({
      updateWorkflow: {
        id: WF_ID,
        name: "inbox-triage",
        intent: null,
        graphVersion: 8,
      },
    });
    const { result } = renderSave();
    await act(async () => {
      await result.current.handleSave();
    });

    const [, variables] = vi.mocked(graphqlRequest).mock.calls.at(-1)!;
    expect((variables as Json).expectedGraphVersion).toBe(7);
    expect(useWorkflowStore.getState().graphVersion).toBe(8);
  });

  it("a version conflict writes nothing, keeps the canvas dirty and says why", async () => {
    mockBackend(MCP_GRAPH, 7);
    await loadWorkflowById(WF_ID);
    useWorkflowStore.getState().updateNodeData("send", { timeoutSecs: 5 });
    expect(useWorkflowStore.getState().isDirty).toBe(true);

    vi.mocked(graphqlRequest).mockRejectedValueOnce(
      new GraphQLCodedError("changed elsewhere", GRAPH_VERSION_CONFLICT_CODE),
    );
    const { result } = renderSave();
    await act(async () => {
      await result.current.handleSave().catch(() => undefined);
    });

    expect(useWorkflowStore.getState().isDirty).toBe(true);
    expect(useWorkflowStore.getState().graphVersion).toBe(7);
    expect(vi.mocked(toast.error)).toHaveBeenCalledWith(
      expect.stringContaining("changed elsewhere"),
    );
  });
});
