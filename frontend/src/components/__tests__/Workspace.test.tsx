import { addEdge } from "@xyflow/react";
import { useWorkflowStore } from "../../store/workflowStore";

/**
 * Verify that connecting two nodes via `addEdge` produces the expected edge
 * structure and that the workflow store correctly records it.
 */
test("onConnect adds an edge to the store", () => {
  // reset store state
  const { clearWorkflow } = useWorkflowStore.getState();
  clearWorkflow();

  // add two dummy nodes
  const store = useWorkflowStore.getState();
  store.addNode("mod1", "Node 1", { x: 0, y: 0 });
  store.addNode("mod2", "Node 2", { x: 100, y: 0 });

  const [sourceNode, targetNode] = useWorkflowStore.getState().nodes;
  const connection = { source: sourceNode.id, target: targetNode.id } as any;

  // mimic the onConnect logic used in Workspace
  const newEdges = addEdge(connection, []);
  // directly update store edges as Workspace would
  useWorkflowStore.setState({ edges: newEdges });

  expect(useWorkflowStore.getState().edges).toHaveLength(1);
  const edge = useWorkflowStore.getState().edges[0];
  expect(edge.source).toBe(sourceNode.id);
  expect(edge.target).toBe(targetNode.id);
});
