import { useWorkflowStore } from "../workflowStore";

describe("workflowStore", () => {
  it("adds a node with correct data", () => {
    // Reset store state
    const store = useWorkflowStore.getState();
    store.clearWorkflow();

    store.addNode("mod-1", "TestModule", { x: 0, y: 0 }, { foo: "bar" });

    const { nodes } = useWorkflowStore.getState();
    expect(nodes).toHaveLength(1);
    const node = nodes[0];
    expect(node.data.moduleId).toBe("mod-1");
    expect(node.data.moduleName).toBe("TestModule");
    expect(node.data.config).toEqual({ foo: "bar" });
  });

  it("updates node data correctly", () => {
    const store = useWorkflowStore.getState();
    store.clearWorkflow();
    // add node first
    store.addNode("mod-2", "UpdateMod", { x: 10, y: 20 }, { a: 1 });
    const nodeId = useWorkflowStore.getState().nodes[0].id;
    // update data
    store.updateNodeData(nodeId, { config: { b: 2 }, label: "NewLabel" });
    const updatedNode = useWorkflowStore.getState().nodes[0];
    expect(updatedNode.data.config).toEqual({ b: 2 });
    expect(updatedNode.data.label).toBe("NewLabel");
  });

  it("deletes node and related edges", () => {
    const store = useWorkflowStore.getState();
    store.clearWorkflow();
    store.addNode("mod-3", "DelMod", { x: 0, y: 0 });
    const node = useWorkflowStore.getState().nodes[0];
    // add a dummy edge referencing the node
    useWorkflowStore
      .getState()
      .edges.push({ id: "e1", source: node.id, target: "other" } as any);
    store.deleteNode(node.id);
    expect(useWorkflowStore.getState().nodes).toHaveLength(0);
    // edge referencing node should be removed
    expect(useWorkflowStore.getState().edges).toHaveLength(0);
  });

  it("clears workflow state", () => {
    const store = useWorkflowStore.getState();
    store.addNode("mod-4", "ClearMod", { x: 0, y: 0 });
    store.setWorkflowMeta("wf-id", "MyWorkflow");
    store.clearWorkflow();
    const state = useWorkflowStore.getState();
    expect(state.nodes).toHaveLength(0);
    expect(state.edges).toHaveLength(0);
    expect(state.workflowId).toBeNull();
    expect(state.workflowName).toBe("Untitled Workflow");
  });

  it("loads workflow and sets metadata", () => {
    const store = useWorkflowStore.getState();
    store.clearWorkflow();
    const dummyNode = {
      id: "n1",
      type: "talosNode",
      position: { x: 0, y: 0 },
      data: { label: "", moduleId: "m", moduleName: "M" },
    } as any;
    const dummyEdge = { id: "e1", source: "n1", target: "n2" } as any;
    store.loadWorkflow({ nodes: [dummyNode], edges: [dummyEdge] });
    store.setWorkflowMeta("id123", "Demo");
    const state = useWorkflowStore.getState();
    expect(state.nodes).toEqual([dummyNode]);
    expect(state.edges).toEqual([dummyEdge]);
    expect(state.workflowId).toBe("id123");
    expect(state.workflowName).toBe("Demo");
  });
});
