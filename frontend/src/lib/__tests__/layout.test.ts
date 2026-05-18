import { describe, it, expect } from "vitest";
import { getLayoutedElements } from "../layout";
import type { WorkflowNode, WorkflowEdge } from "@/store/workflowStore";

describe("layout utility", () => {
  it("should apply dagre layout to nodes", () => {
    const nodes: WorkflowNode[] = [
      {
        id: "1",
        type: "task",
        data: { label: "Node 1", moduleId: "mod-1", moduleName: "Test" },
        position: { x: 0, y: 0 },
      },
      {
        id: "2",
        type: "task",
        data: { label: "Node 2", moduleId: "mod-2", moduleName: "Test" },
        position: { x: 0, y: 0 },
      },
    ];
    const edges: WorkflowEdge[] = [{ id: "e1-2", source: "1", target: "2" }];

    const { nodes: layoutedNodes } = getLayoutedElements(nodes, edges);

    expect(layoutedNodes.length).toBe(2);
    // Dagre should have assigned positions. In a single column vertical layout,
    // X might still be 0 if the graph is centered on 0 or starts at 0.
    // Let's verify they have some position assigned.
    expect(layoutedNodes[0].position).toBeDefined();
    expect(layoutedNodes[1].position).toBeDefined();

    // Vertical layout (default 'TB') should have different Y positions
    expect(layoutedNodes[0].position.y).not.toEqual(
      layoutedNodes[1].position.y,
    );
  });

  it("should support horizontal layout", () => {
    const nodes: WorkflowNode[] = [
      {
        id: "1",
        type: "task",
        data: { label: "Node 1", moduleId: "mod-1", moduleName: "Test" },
        position: { x: 0, y: 0 },
      },
      {
        id: "2",
        type: "task",
        data: { label: "Node 2", moduleId: "mod-2", moduleName: "Test" },
        position: { x: 0, y: 0 },
      },
    ];
    const edges: WorkflowEdge[] = [{ id: "e1-2", source: "1", target: "2" }];

    const { nodes: layoutedNodes } = getLayoutedElements(nodes, edges, "LR");

    // Horizontal layout ('LR') should have different X positions
    expect(layoutedNodes[0].position.x).not.toEqual(
      layoutedNodes[1].position.x,
    );
    expect(layoutedNodes[0].targetPosition).toBe("left");
    expect(layoutedNodes[0].sourcePosition).toBe("right");
  });
});
