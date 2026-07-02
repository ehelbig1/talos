import { describe, it, expect, beforeEach, vi } from "vitest";
import { useWorkflowStore } from "./workflowStore";
import { Connection } from "@xyflow/react";

describe("workflowStore", () => {
  beforeEach(() => {
    useWorkflowStore.getState().clearWorkflow();
    // Mock crypto.randomUUID for consistent IDs in tests
    vi.stubGlobal("crypto", {
      randomUUID: vi.fn(
        () => "test-uuid-" + Math.random().toString(36).slice(2, 9),
      ),
    });
  });

  it("should initialize with default state", () => {
    const state = useWorkflowStore.getState();
    expect(state.nodes).toEqual([]);
    expect(state.edges).toEqual([]);
    expect(state.workflowId).toBeNull();
    expect(state.workflowName).toBe("Untitled Workflow");
    expect(state.isDirty).toBe(false);
  });

  it("should add a node", () => {
    const { addNode } = useWorkflowStore.getState();

    addNode(
      "module-1",
      "Test Module",
      { x: 100, y: 100 },
      { param1: "val1" },
      "world-1",
      "desc",
      "category-1",
    );

    const state = useWorkflowStore.getState();
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0].data.moduleId).toBe("module-1");
    expect(state.nodes[0].data.label).toBe("Test Module");
    expect(state.nodes[0].position).toEqual({ x: 100, y: 100 });
    expect(state.isDirty).toBe(true);
  });

  it("should connect nodes", () => {
    const { addNode, connectNodes } = useWorkflowStore.getState();

    addNode("m1", "N1", { x: 0, y: 0 });
    addNode("m2", "N2", { x: 100, y: 100 });

    const nodes = useWorkflowStore.getState().nodes;
    const connection: Connection = {
      source: nodes[0].id,
      target: nodes[1].id,
      sourceHandle: "out",
      targetHandle: "in",
    };

    connectNodes(connection);

    const state = useWorkflowStore.getState();
    expect(state.edges).toHaveLength(1);
    expect(state.edges[0].source).toBe(nodes[0].id);
    expect(state.edges[0].target).toBe(nodes[1].id);
  });

  it("should reject a self-loop edge (source === target)", () => {
    // A node connecting to itself is a 1-node cycle; the engine rejects the
    // whole graph with "workflow graph contains a cycle". React Flow allows
    // dragging an output handle back onto the same node, so the store must
    // drop it. Regression: a single-node workflow saved with a self-edge.
    const { addNode, connectNodes } = useWorkflowStore.getState();

    addNode("m1", "N1", { x: 0, y: 0 });
    const nodeId = useWorkflowStore.getState().nodes[0].id;

    connectNodes({
      source: nodeId,
      target: nodeId,
      sourceHandle: "out",
      targetHandle: "in",
    });

    expect(useWorkflowStore.getState().edges).toHaveLength(0);
  });

  it("should update node data", () => {
    const { addNode, updateNodeData } = useWorkflowStore.getState();
    addNode("m1", "N1", { x: 0, y: 0 });
    const nodeId = useWorkflowStore.getState().nodes[0].id;

    updateNodeData(nodeId, { label: "Updated Name", config: { new: "val" } });

    const node = useWorkflowStore.getState().nodes[0];
    expect(node.data.label).toBe("Updated Name");
    expect(node.data.config).toEqual({ new: "val" });
  });

  it("should delete a node and its connected edges", () => {
    const { addNode, connectNodes, deleteNode } = useWorkflowStore.getState();
    addNode("m1", "N1", { x: 0, y: 0 });
    addNode("m2", "N2", { x: 100, y: 100 });

    const nodes = useWorkflowStore.getState().nodes;
    connectNodes({
      source: nodes[0].id,
      target: nodes[1].id,
      sourceHandle: null,
      targetHandle: null,
    });

    expect(useWorkflowStore.getState().edges).toHaveLength(1);

    deleteNode(nodes[0].id);

    const state = useWorkflowStore.getState();
    expect(state.nodes).toHaveLength(1);
    expect(state.edges).toHaveLength(0);
  });

  it("should duplicate a node", () => {
    const { addNode, duplicateNode } = useWorkflowStore.getState();
    addNode("m1", "N1", { x: 10, y: 10 });
    const nodeId = useWorkflowStore.getState().nodes[0].id;

    duplicateNode(nodeId);

    const state = useWorkflowStore.getState();
    expect(state.nodes).toHaveLength(2);
    expect(state.nodes[1].position).toEqual({ x: 50, y: 50 });
    expect(state.nodes[1].data.moduleId).toBe("m1");
  });

  it("should clear workflow", () => {
    const { addNode, setWorkflowMeta, clearWorkflow } =
      useWorkflowStore.getState();
    addNode("m1", "N1", { x: 0, y: 0 });
    setWorkflowMeta("uuid", "My Workflow");

    clearWorkflow();

    const state = useWorkflowStore.getState();
    expect(state.nodes).toHaveLength(0);
    expect(state.workflowId).toBeNull();
    expect(state.workflowName).toBe("Untitled Workflow");
    expect(state.isDirty).toBe(false);
  });

  it("should handle circular dependencies during linting simulation", () => {
    // Note: workflowStore itself doesn't implement the cycle detection logic,
    // it resides in WorkflowToolbar.tsx useMemo.
    // However, we test that the store allows creating the state that triggers it.
    const { addNode, connectNodes } = useWorkflowStore.getState();

    addNode("m1", "N1", { x: 0, y: 0 });
    addNode("m2", "N2", { x: 100, y: 100 });
    const nodes = useWorkflowStore.getState().nodes;

    connectNodes({
      source: nodes[0].id,
      target: nodes[1].id,
      sourceHandle: null,
      targetHandle: null,
    });
    connectNodes({
      source: nodes[1].id,
      target: nodes[0].id,
      sourceHandle: null,
      targetHandle: null,
    });

    const state = useWorkflowStore.getState();
    expect(state.edges).toHaveLength(2);
    expect(state.edges[0].source).toBe(nodes[0].id);
    expect(state.edges[0].target).toBe(nodes[1].id);
    expect(state.edges[1].source).toBe(nodes[1].id);
    expect(state.edges[1].target).toBe(nodes[0].id);
  });

  it("should load a workflow and set its metadata", () => {
    const { clearWorkflow, loadWorkflow, setWorkflowMeta } =
      useWorkflowStore.getState();
    clearWorkflow();
    const dummyNode = {
      id: "n1",
      type: "talosNode",
      position: { x: 0, y: 0 },
      data: { label: "", moduleId: "m", moduleName: "M" },
    } as any;
    const dummyEdge = { id: "e1", source: "n1", target: "n2" } as any;

    loadWorkflow({ nodes: [dummyNode], edges: [dummyEdge] });
    setWorkflowMeta("id123", "Demo");

    const state = useWorkflowStore.getState();
    expect(state.nodes).toEqual([dummyNode]);
    expect(state.edges).toEqual([dummyEdge]);
    expect(state.workflowId).toBe("id123");
    expect(state.workflowName).toBe("Demo");
  });

  it("should mark state as dirty on position changes", () => {
    const { addNode, onNodesChange } = useWorkflowStore.getState();
    addNode("m1", "N1", { x: 0, y: 0 });
    useWorkflowStore.getState().markClean();
    expect(useWorkflowStore.getState().isDirty).toBe(false);

    const nodes = useWorkflowStore.getState().nodes;
    onNodesChange([
      { id: nodes[0].id, type: "position", position: { x: 50, y: 50 } },
    ]);

    expect(useWorkflowStore.getState().isDirty).toBe(true);
    expect(useWorkflowStore.getState().nodes[0].position).toEqual({
      x: 50,
      y: 50,
    });
  });
});
