import { describe, it, expect } from "vitest";
import { serializeNode } from "./useWorkflowSave";
import type { WorkflowNode } from "@/store/workflowStore";

// The engine treats a MODULE node's stored `data` as its config, FLAT —
// exactly as the MCP writers store it. The editor's old serializer persisted
// the whole WorkflowNodeData (config nested one level down + UI metadata),
// so every editor-saved module node failed at runtime with
// "Missing <KEY> config". These tests lock the corrected contract.

function moduleNode(over: Partial<WorkflowNode["data"]> = {}): WorkflowNode {
  return {
    id: "n1",
    type: "talosNode",
    position: { x: 1, y: 2 },
    data: {
      label: "Smart Classifier",
      moduleId: "3436782b-857c-4e82-a454-771b72ec7b9c",
      moduleName: "Smart Classifier",
      capabilityWorld: "agent-node",
      configSchema: { required: ["MODEL_NAME"] },
      catalogSlug: "smart-classifier",
      sourceCode: "fn run() {} // must never be persisted into the graph",
      config: {
        MODEL_NAME: "essay-topic-classifier",
        SYSTEM_PROMPT: "Classify this essay.",
        LABELS: ["Software", "Woodworking"],
      },
      ...over,
    },
  } as WorkflowNode;
}

describe("serializeNode — module nodes", () => {
  it("stores config keys FLAT in data (the engine/MCP contract)", () => {
    const out = serializeNode(moduleNode());
    expect(out.data).toMatchObject({
      MODEL_NAME: "essay-topic-classifier",
      SYSTEM_PROMPT: "Classify this essay.",
      LABELS: ["Software", "Woodworking"],
    });
    // The exact 2026-07-14 dogfood failure: config buried one level down.
    expect(out.data).not.toHaveProperty("config");
  });

  it("drops UI metadata — especially sourceCode — from the stored graph", () => {
    const out = serializeNode(moduleNode());
    for (const leak of [
      "label",
      "moduleId",
      "moduleName",
      "capabilityWorld",
      "configSchema",
      "catalogSlug",
      "sourceCode",
    ]) {
      expect(out.data).not.toHaveProperty(leak);
    }
    // moduleId still travels as the node's `type` (the engine's lookup key).
    expect(out.type).toBe("3436782b-857c-4e82-a454-771b72ec7b9c");
  });

  it("keeps the engine extras alongside the flat config", () => {
    const out = serializeNode(
      moduleNode({
        skipCondition: "is_error == false",
        continueOnError: true,
        timeoutSecs: 30,
        retryPolicy: { maxRetries: 2, backoffMs: 500 },
      }),
    );
    expect(out.data).toMatchObject({
      skip_condition: "is_error == false",
      continue_on_error: true,
      timeout_secs: 30,
      retry_count: 2,
      retry_backoff_ms: 500,
    });
    expect(out.skip_condition).toBe("is_error == false");
  });
});

describe("serializeNode — system nodes keep the legacy shape", () => {
  it("preserves full data + kind mapping for system nodes", () => {
    const n = {
      id: "s1",
      type: "talosNode",
      position: { x: 0, y: 0 },
      data: {
        label: "While Loop",
        moduleId: "system:WhileLoop",
        moduleName: "WhileLoop",
        systemNodeKind: "WhileLoop",
        config: { loopCondition: "count < 3" },
      },
    } as WorkflowNode;
    const out = serializeNode(n);
    expect(out.kind).toBe("loop");
    // System nodes intentionally keep the full-data shape (their engine
    // params live top-level in data; narrowing them is a separate change).
    expect(out.data).toMatchObject({
      systemNodeKind: "WhileLoop",
      config: { loopCondition: "count < 3" },
    });
  });
});
