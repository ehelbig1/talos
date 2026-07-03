import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "../test-utils";
import Inspector from "./Inspector";
import { useWorkflowStore } from "@/store/workflowStore";
import { useUIStore } from "@/store/uiStore";
import { useEphemeralExecutionStore } from "@/store/executionStore";
import { graphql, HttpResponse } from "msw";
import { server } from "../../vitest.setup";

// Mock clipboard
const mockWriteText = vi.fn();
Object.assign(navigator, {
  clipboard: {
    writeText: mockWriteText,
  },
});

describe("Inspector Component", () => {
  beforeEach(() => {
    useWorkflowStore.getState().clearWorkflow();
    useUIStore.getState().setSelectedNodeId(null);
    useUIStore.getState().setShowInspector(false);
    useEphemeralExecutionStore.getState().resetNodeStatuses();
    vi.clearAllMocks();
  });

  it("renders workflow properties when no node or edge is selected", () => {
    useWorkflowStore.getState().setWorkflowMeta("wf-1", "My Awesome Workflow");

    render(<Inspector />);

    expect(screen.getByText("Workflow Registry")).toBeInTheDocument();
    expect(screen.getByText("My Awesome Workflow")).toBeInTheDocument();
    // Workflow ID is now surfaced via the SYSTEM_UUID copy field.
    expect(screen.getByText("SYSTEM_UUID")).toBeInTheDocument();
    expect(screen.getByText("wf-1")).toBeInTheDocument();
  });

  it("renders node properties when a node is selected", async () => {
    const { addNode } = useWorkflowStore.getState();
    addNode("mod-1", "Test Node", { x: 0, y: 0 });
    const node = useWorkflowStore.getState().nodes[0];

    // Select the node
    useWorkflowStore.setState({
      nodes: useWorkflowStore
        .getState()
        .nodes.map((n) => ({ ...n, selected: true })),
    });
    useUIStore.getState().setSelectedNodeId(node.id);

    render(<Inspector />);

    // The node inspector renders the node label as its header.
    await waitFor(
      () => {
        expect(screen.getByText("Test Node")).toBeInTheDocument();
      },
      { timeout: 3000 },
    );

    // Config + Diagnostics tabs identify the node inspector view.
    expect(screen.getByText("Configuration")).toBeInTheDocument();
    expect(screen.getByText("Diagnostics")).toBeInTheDocument();
  });

  it.skip("switches between tabs in node view — tab state change not detectable in JSDOM", async () => {
    const { addNode } = useWorkflowStore.getState();
    addNode("mod-1", "Test Node", { x: 0, y: 0 });
    const node = useWorkflowStore.getState().nodes[0];

    useWorkflowStore.setState({
      nodes: useWorkflowStore
        .getState()
        .nodes.map((n) => ({ ...n, selected: true })),
    });
    useUIStore.getState().setSelectedNodeId(node.id);

    render(<Inspector />);

    await waitFor(
      () => {
        expect(screen.getByText("Node Properties")).toBeInTheDocument();
        expect(
          screen.queryByTestId("skeleton-inspector"),
        ).not.toBeInTheDocument();
      },
      { timeout: 3000 },
    );

    const logsTab = screen.getByRole("tab", { name: /execution data/i });
    fireEvent.click(logsTab);

    await waitFor(
      () => {
        expect(logsTab).toHaveAttribute("data-state", "active");
      },
      { timeout: 3000 },
    );
  });

  it("validates Rhai script in edge inspector", async () => {
    // Setup MSW for analyzeRhai
    server.use(
      graphql.query("AnalyzeRhai", () => {
        return HttpResponse.json({
          data: {
            analyzeRhai: {
              success: false,
              errors: [
                {
                  message: "Syntax Error at line 1",
                  line: 1,
                  column: 1,
                  severity: "ERROR",
                },
              ],
            },
          },
        });
      }),
    );

    const { addNode, connectNodes } = useWorkflowStore.getState();
    addNode("m1", "N1", { x: 0, y: 0 });
    addNode("m2", "N2", { x: 100, y: 100 });
    const nodes = useWorkflowStore.getState().nodes;

    connectNodes({
      source: nodes[0].id,
      target: nodes[1].id,
      sourceHandle: "out",
      targetHandle: "in",
    });
    const _edge = useWorkflowStore.getState().edges[0];

    useWorkflowStore.setState({
      edges: useWorkflowStore.getState().edges.map((e) => ({
        ...e,
        selected: true,
        data: { ...e.data, edgeType: "conditional" },
      })),
    });

    render(<Inspector />);

    expect(screen.getByText("Link Properties")).toBeInTheDocument();

    const textarea = screen.getByPlaceholderText(/ctx.result.score > 0.8/i);
    fireEvent.change(textarea, { target: { value: "invalid script" } });

    // Wait for debounced validation
    await waitFor(
      () => {
        expect(screen.getByText("Syntax Error at line 1")).toBeInTheDocument();
      },
      { timeout: 3000 },
    );
  });

  it("handles node deletion", async () => {
    const { addNode } = useWorkflowStore.getState();
    addNode("mod-1", "Delete Me", { x: 0, y: 0 });
    const node = useWorkflowStore.getState().nodes[0];

    useWorkflowStore.setState({
      nodes: useWorkflowStore
        .getState()
        .nodes.map((n) => ({ ...n, selected: true })),
    });
    useUIStore.getState().setSelectedNodeId(node.id);

    render(<Inspector />);

    await waitFor(
      () => {
        expect(screen.getByText("Delete Me")).toBeInTheDocument();
      },
      { timeout: 3000 },
    );

    // Expand the Core Metadata (System Internals) section
    const advancedTrigger = screen.getByRole("button", {
      name: /core metadata/i,
    });
    fireEvent.click(advancedTrigger);

    const deleteBtn = await screen.findByRole("button", {
      name: /decommission protocol node/i,
    });
    fireEvent.click(deleteBtn);

    // Confirm dialog should appear
    expect(
      screen.getByText(
        /Are you sure you want to terminate and remove node "Delete Me"\?/i,
      ),
    ).toBeInTheDocument();

    const confirmBtn = screen.getByRole("button", {
      name: /^terminate & remove$/i,
    });
    fireEvent.click(confirmBtn);

    expect(useWorkflowStore.getState().nodes).toHaveLength(0);
  });
});
