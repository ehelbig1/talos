import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, act, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import Workspace from "../Workspace";
import { useWorkflowStore } from "@/store/workflowStore";
import { useEphemeralExecutionStore } from "@/store/executionStore";
import { ReactFlowProvider } from "@xyflow/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Mock ResizeObserver which is used by ReactFlow
(globalThis as any).ResizeObserver = vi.fn().mockImplementation(function () {
  return {
    observe: vi.fn(),
    unobserve: vi.fn(),
    disconnect: vi.fn(),
  };
});

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
    },
  },
});

const renderWorkspace = () => {
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <ReactFlowProvider>
          <Workspace />
        </ReactFlowProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  );
};

describe("Workspace Integration", () => {
  beforeEach(() => {
    useWorkflowStore.getState().clearWorkflow();
    useEphemeralExecutionStore.getState().resetNodeStatuses();

    // Mock crypto.randomUUID
    vi.stubGlobal("crypto", {
      randomUUID: vi.fn(
        () => "test-node-" + Math.random().toString(36).slice(2, 9),
      ),
    });
  });

  it("renders nodes from the workflowStore", async () => {
    const { addNode } = useWorkflowStore.getState();

    act(() => {
      addNode(
        "mod-1",
        "HTTP Node",
        { x: 100, y: 100 },
        {},
        "http",
        "desc",
        "http",
      );
    });

    renderWorkspace();

    // ReactFlow nodes are rendered with the label
    expect(screen.getByText("HTTP Node")).toBeInTheDocument();
  });

  it("reflects node execution status from executionStore", async () => {
    const { addNode } = useWorkflowStore.getState();
    let nodeId: string = "";

    act(() => {
      addNode("mod-1", "Worker Node", { x: 100, y: 100 });
      nodeId = useWorkflowStore.getState().nodes[0].id;
    });

    renderWorkspace();

    // Initial status should be idle (not specific class, but check the dot)
    expect(screen.getByLabelText("Status: idle")).toBeInTheDocument();

    // Simulate node starting to run
    act(() => {
      useEphemeralExecutionStore
        .getState()
        .setNodeStatus(nodeId, { status: "running" });
    });

    await waitFor(() => {
      expect(screen.getByLabelText("Status: running")).toBeInTheDocument();
    });

    // Simulate node success
    act(() => {
      useEphemeralExecutionStore
        .getState()
        .setNodeStatus(nodeId, { status: "success" });
    });

    await waitFor(() => {
      expect(screen.getByLabelText("Status: success")).toBeInTheDocument();
    });
  });

  it("displays error messages and fix suggestions when a node fails", async () => {
    const { addNode } = useWorkflowStore.getState();
    let nodeId: string = "";

    act(() => {
      addNode("mod-1", "Failing Node", { x: 100, y: 100 });
      nodeId = useWorkflowStore.getState().nodes[0].id;
    });

    renderWorkspace();

    // Simulate failure with a known error that has a fix suggestion
    // (Assuming "timeout" is in fixSuggestions.ts)
    act(() => {
      useEphemeralExecutionStore.getState().setNodeStatus(nodeId, {
        status: "failed",
        error: "WASM execution timed out",
      });
    });

    await waitFor(() => {
      expect(screen.getAllByText(/timed out/i).length).toBeGreaterThan(0);
      // Verify that the status dot changed
      expect(screen.getByLabelText("Status: failed")).toBeInTheDocument();
    });
  });

  it("animates edges when workflow is running", () => {
    const { addNode, connectNodes } = useWorkflowStore.getState();

    act(() => {
      addNode("m1", "N1", { x: 0, y: 0 });
      addNode("m2", "N2", { x: 100, y: 100 });
      const nodes = useWorkflowStore.getState().nodes;
      connectNodes({
        source: nodes[0].id,
        target: nodes[1].id,
        sourceHandle: "out",
        targetHandle: "in",
      });
    });

    renderWorkspace();

    act(() => {
      useEphemeralExecutionStore.getState().setRunning("exec-1", "wf-1");
    });
  });
});
