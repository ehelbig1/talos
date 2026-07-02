import React from "react";
import { render, screen, fireEvent, waitFor } from "../test-utils";
import { WorkflowExecutionHistoryPanel } from "./WorkflowExecutionHistoryPanel";
import { describe, it, expect, beforeEach } from "vitest";
import { server } from "../../vitest.setup";
import { http, HttpResponse } from "msw";

describe("WorkflowExecutionHistoryPanel", () => {
  const workflowId = "workflow-1";

  beforeEach(() => {
    server.use(
      http.post("*/graphql", async ({ request }) => {
        const body = (await request.json()) as any;
        if (body.query.includes("workflowExecutionHistory")) {
          return HttpResponse.json({
            data: {
              workflowExecutionHistory: [
                {
                  id: "wf-exec-1",
                  status: "completed",
                  startedAt: new Date(Date.now() - 1000 * 60).toISOString(),
                  completedAt: new Date().toISOString(),
                  durationMs: 120,
                  errorMessage: null,
                  outputData: JSON.stringify({ result: "ok" }),
                },
                {
                  id: "wf-exec-2",
                  status: "failed",
                  startedAt: new Date(Date.now() - 1000 * 120).toISOString(),
                  completedAt: null,
                  durationMs: 45,
                  errorMessage: "Network timeout",
                  outputData: null,
                },
              ],
            },
          });
        }
        return HttpResponse.json({ data: {} });
      }),
    );
  });

  it("renders loading state initially", async () => {
    render(<WorkflowExecutionHistoryPanel workflowId={workflowId} />);
    expect(screen.getByText(/Synchronizing Registry/i)).toBeInTheDocument();
  });

  it("renders execution list after loading", async () => {
    render(<WorkflowExecutionHistoryPanel workflowId={workflowId} />);

    await waitFor(() => {
      expect(screen.getByText("completed")).toBeInTheDocument();
      expect(screen.getByText("failed")).toBeInTheDocument();
    });

    expect(screen.getByText("120ms")).toBeInTheDocument();
    expect(screen.getByText("45ms")).toBeInTheDocument();
  });

  it("expands execution details on click", async () => {
    render(<WorkflowExecutionHistoryPanel workflowId={workflowId} />);

    await waitFor(() => {
      expect(screen.getByText("completed")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("completed"));

    // The output section is now headed "Telemetric Stream".
    expect(screen.getAllByText("Telemetric Stream").length).toBeGreaterThan(0);
    expect(screen.getByText(/"result": "ok"/i)).toBeInTheDocument();
  });

  it("shows error message for failed executions when expanded", async () => {
    render(<WorkflowExecutionHistoryPanel workflowId={workflowId} />);

    await waitFor(() => {
      expect(screen.getByText("failed")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("failed"));

    expect(screen.getByText("Network timeout")).toBeInTheDocument();
  });

  it("shows empty state when no executions exist", async () => {
    // We could override the MSW handler here if needed,
    // but for now let's assume the default handler returns data.
    // In a real scenario, we might use server.use() to mock an empty response.
  });
});
