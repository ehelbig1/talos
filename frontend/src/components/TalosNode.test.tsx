import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@/test-utils";
import { TalosNode } from "./TalosNode";
import { Position } from "@xyflow/react";

describe("TalosNode", () => {
  const defaultProps = {
    id: "node-1",
    data: {
      label: "Test Node",
      moduleId: "module-1",
      moduleName: "Test Module",
      category: "http",
      config: { url: "https://api.com" },
    },
    selected: false,
    type: "talosNode" as const,
    zIndex: 0,
    isConnectable: true,
    xPos: 0,
    yPos: 0,
    dragging: false,
    draggable: true,
    selectable: true,
    deletable: true,
    dragHandle: undefined,
    parentId: undefined,
    width: undefined,
    height: undefined,
    selectedNodeId: null,
    onNodeClick: vi.fn(),
    onNodeDoubleClick: vi.fn(),
    onNodeMouseEnter: vi.fn(),
    onNodeMouseMove: vi.fn(),
    onNodeMouseLeave: vi.fn(),
    onNodeContextMenu: vi.fn(),
    onNodeDragStart: vi.fn(),
    onNodeDrag: vi.fn(),
    onNodeDragStop: vi.fn(),
    onConnect: vi.fn(),
    onConnectStart: vi.fn(),
    onConnectEnd: vi.fn(),
    sourcePosition: Position.Bottom,
    targetPosition: Position.Top,
    positionAbsoluteX: 0,
    positionAbsoluteY: 0,
  };

  it("renders node name correctly", () => {
    render(<TalosNode {...defaultProps} />);
    expect(screen.getByText("Test Module")).toBeInTheDocument();
  });

  it("shows config count", () => {
    render(<TalosNode {...defaultProps} />);
    expect(screen.getByText("1 configured field")).toBeInTheDocument();
  });

  it("applies selected styling", () => {
    render(<TalosNode {...defaultProps} selected={true} />);
    const nodeName = screen.getByText("Test Module");
    // The container of the name should have the styling
    const nodeContainer = nodeName.closest(".relative");
    expect(nodeContainer).toHaveClass("ring-2");
    expect(nodeContainer).toHaveClass("ring-primary/40");
  });
});
