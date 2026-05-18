import React from "react";
import { render, screen, fireEvent, waitFor } from "../test-utils";
import { ExecutionHistory } from "./ExecutionHistory";
import { server } from "../../vitest.setup";
import { http, HttpResponse } from "msw";
import { describe, it, expect, beforeEach } from "vitest";

describe("ExecutionHistory", () => {
  const moduleId = "550e8400-e29b-41d4-a716-446655440000"; // Valid UUID

  const mockExecutions = [
    {
      id: "exec-1",
      status: "completed",
      startedAt: new Date(Date.now() - 1000 * 60).toISOString(),
      durationMs: 150,
      outputData: '{"ok": true}',
    },
  ];

  const mockLogs = [
    {
      id: "log-1",
      createdAt: new Date().toISOString(),
      level: "info",
      message: "Starting task",
    },
    {
      id: "log-2",
      createdAt: new Date().toISOString(),
      level: "error",
      message: "Failed to connect",
    },
  ];

  beforeEach(() => {
    server.use(
      http.post("*/graphql", async ({ request }) => {
        const body = (await request.json()) as any;
        const moduleId = body.variables?.moduleId;

        if (body.query.includes("moduleExecutionHistory")) {
          if (moduleId === "foreach") {
            return HttpResponse.json({
              data: { moduleExecutionHistory: [] },
            });
          }
          return HttpResponse.json({
            data: { moduleExecutionHistory: mockExecutions },
          });
        }
        if (body.query.includes("moduleExecutionLogs")) {
          return HttpResponse.json({
            data: { moduleExecutionLogs: mockLogs },
          });
        }
        return HttpResponse.json({ data: {} });
      }),
    );
  });

  it("renders history for valid UUID", async () => {
    render(<ExecutionHistory moduleId={moduleId} />);

    await waitFor(() => {
      expect(screen.getByText(/completed/i)).toBeInTheDocument();
    });
  });

  it("shows logs when execution is expanded", async () => {
    render(<ExecutionHistory moduleId={moduleId} />);

    await waitFor(() => {
      expect(screen.getByText(/completed/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/completed/i).closest("button")!);

    await waitFor(() => {
      expect(screen.getByText(/Starting task/i)).toBeInTheDocument();
      expect(screen.getByText(/Failed to connect/i)).toBeInTheDocument();
    });
  });

  it("shows empty state for non-UUID system modules", async () => {
    render(<ExecutionHistory moduleId="foreach" />);
    await waitFor(() => {
      expect(screen.getByText(/No past executions found/i)).toBeInTheDocument();
    });
  });
});
