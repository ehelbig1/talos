import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { NodeHandles } from "./NodeHandles";
import { ReactFlowProvider } from "@xyflow/react";

describe("NodeHandles", () => {
  it("renders both handles with correct aria-labels", () => {
    render(
      <ReactFlowProvider>
        <NodeHandles />
      </ReactFlowProvider>,
    );

    expect(screen.getByLabelText("Input handle")).toBeInTheDocument();
    expect(screen.getByLabelText("Output handle")).toBeInTheDocument();
  });
});
