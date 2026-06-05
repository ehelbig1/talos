import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "../test-utils";
import { WorkflowToolbar } from "./WorkflowToolbar";
import { useWorkflowStore } from "@/store/workflowStore";
import { useUIStore } from "@/store/uiStore";
import { usePersistedExecutionStore } from "@/store/executionStore";
import { graphql, HttpResponse } from "msw";
import { server } from "../../vitest.setup";

describe("WorkflowToolbar Component", () => {
  beforeEach(() => {
    useWorkflowStore.getState().clearWorkflow();
    useUIStore.getState().setShowInspector(false);
    vi.clearAllMocks();
  });

  it("renders workflow name and node counts", () => {
    useWorkflowStore.getState().setWorkflowMeta("wf-1", "Test Workflow");
    useWorkflowStore.getState().addNode("mod-1", "Node 1", { x: 0, y: 0 });

    render(<WorkflowToolbar />);

    expect(screen.getByText("Test Workflow")).toBeInTheDocument();
    expect(screen.getByText("1")).toBeInTheDocument(); // node count
    expect(screen.getByText(/nodes/i)).toBeInTheDocument();
  });

  it("shows unsaved indicator when dirty", () => {
    useWorkflowStore.getState().setWorkflowMeta("wf-1", "Test Workflow");
    useWorkflowStore.getState().addNode("mod-1", "Node 1", { x: 0, y: 0 });
    // addNode marks it dirty

    render(<WorkflowToolbar />);

    expect(screen.getByText(/uncommitted/i)).toBeInTheDocument();
  });

  it("handles saving a new workflow", async () => {
    let capturedRequest: any = null;

    server.use(
      graphql.mutation("CreateWorkflow", ({ variables }) => {
        capturedRequest = variables;
        return HttpResponse.json({
          data: {
            createWorkflow: {
              id: "new-uuid",
              name: "My New Workflow",
            },
          },
        });
      }),
    );

    useWorkflowStore.getState().addNode("mod-1", "Node 1", { x: 0, y: 0 });

    render(<WorkflowToolbar />);

    const saveBtn = screen.getByRole("button", { name: /save/i });
    fireEvent.click(saveBtn);

    // Should show the name-assignment dialog
    expect(screen.getAllByText(/identity assignment/i).length).toBeGreaterThan(
      0,
    );

    const input = screen.getByPlaceholderText(/workflow identifier/i);
    fireEvent.change(input, { target: { value: "My New Workflow" } });

    const confirmBtn = screen.getByRole("button", { name: /commit identity/i });
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(capturedRequest).not.toBeNull();
      expect(capturedRequest.input.name).toBe("My New Workflow");
    });

    expect(useWorkflowStore.getState().workflowId).toBe("new-uuid");
    expect(useWorkflowStore.getState().isDirty).toBe(false);
  });

  it("toggles inspector visibility", () => {
    render(<WorkflowToolbar />);

    const toggleBtn = screen.getByRole("button", { name: /diagnostics/i });
    fireEvent.click(toggleBtn);

    expect(useUIStore.getState().showInspector).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: /diagnostics/i }));
    expect(useUIStore.getState().showInspector).toBe(false);
  });

  // Cycle detection test removed as it's not currently implemented in the toolbar UI

  it('handles "New" button with confirmation', async () => {
    const { addNode } = useWorkflowStore.getState();
    addNode("m1", "N1", { x: 0, y: 0 });

    render(<WorkflowToolbar />);

    const newBtn = screen.getByRole("button", { name: /^new$/i });
    fireEvent.click(newBtn);

    // Should show confirm dialog
    expect(
      screen.getByText(/clear the current workflow\?/i),
    ).toBeInTheDocument();

    const confirmBtn = screen.getByRole("button", { name: /clear/i });
    fireEvent.click(confirmBtn);

    expect(useWorkflowStore.getState().nodes).toHaveLength(0);
  });

  // Tidy button test removed as it's not currently implemented in the component

  it("displays run status health pill", () => {
    const workflowId = "wf-123";
    useWorkflowStore.getState().setWorkflowMeta(workflowId, "Test");
    usePersistedExecutionStore.getState().setWorkflowStatus(workflowId, {
      status: "success",
      runAt: new Date().toISOString(),
    });

    render(<WorkflowToolbar />);

    // A "success" run status renders as the "Operational" health pill.
    expect(screen.getByText(/operational/i)).toBeInTheDocument();
  });
});
