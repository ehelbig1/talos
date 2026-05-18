import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@/test-utils";
import { NodeContextMenu } from "./NodeContextMenu";

describe("NodeContextMenu", () => {
  const defaultProps = {
    pos: { x: 100, y: 100 },
    nodeId: "test-node-123",
    onClose: vi.fn(),
    onDuplicate: vi.fn(),
    onDelete: vi.fn(),
  };

  it("renders context menu items", () => {
    render(<NodeContextMenu {...defaultProps} />);
    expect(screen.getByText("Duplicate")).toBeInTheDocument();
    expect(screen.getByText(/Remove Node/i)).toBeInTheDocument();
  });

  it("calls onDuplicate when clicked", () => {
    render(<NodeContextMenu {...defaultProps} />);
    fireEvent.click(screen.getByText("Duplicate"));
    expect(defaultProps.onDuplicate).toHaveBeenCalled();
  });

  it("calls onDelete when clicked", () => {
    render(<NodeContextMenu {...defaultProps} />);
    fireEvent.click(screen.getByText(/Remove Node/i));
    expect(defaultProps.onDelete).toHaveBeenCalled();
  });

  it("calls onClose when clicking escape", () => {
    render(<NodeContextMenu {...defaultProps} />);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(defaultProps.onClose).toHaveBeenCalled();
  });

  it("has correct ARIA roles", () => {
    render(<NodeContextMenu {...defaultProps} />);
    expect(screen.getByRole("menu")).toBeInTheDocument();
    // 3 items with nodeId: Duplicate, Copy Node ID, Remove Node
    expect(screen.getAllByRole("menuitem")).toHaveLength(3);
  });
});
