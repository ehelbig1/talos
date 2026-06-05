import React from "react";
import { render, screen, fireEvent, waitFor } from "../../test-utils";
import { SlackAppSelector } from "./SlackAppSelector";
import { server } from "../../../vitest.setup";
import { http, HttpResponse } from "msw";
import { vi, describe, it, expect, beforeEach } from "vitest";

describe("SlackAppSelector", () => {
  const mockOnSelect = vi.fn();

  const mockIntegrations = [
    {
      id: "int-1",
      team_id: "T123",
      team_name: "Test Team",
      is_active: true,
      last_used_at: new Date().toISOString(),
    },
  ];

  beforeEach(() => {
    mockOnSelect.mockClear();
    // Default handlers
    server.use(
      http.get("/api/slack/integrations", () => {
        return HttpResponse.json({
          success: true,
          data: mockIntegrations,
        });
      }),
    );
  });

  it("renders loading state initially", async () => {
    render(<SlackAppSelector onSelect={mockOnSelect} />);
    expect(screen.getByText(/Syncing Slack Grid Vectors/i)).toBeInTheDocument();
  });

  it("renders integrations after loading", async () => {
    render(<SlackAppSelector onSelect={mockOnSelect} />);

    await waitFor(() => {
      expect(
        screen.queryByText(/Syncing Slack Grid Vectors/i),
      ).not.toBeInTheDocument();
    });

    expect(screen.getByText("Test Team")).toBeInTheDocument();
    expect(screen.getByText(/ID: T123/i)).toBeInTheDocument();
  });

  it("calls onSelect when an integration is clicked", async () => {
    render(<SlackAppSelector onSelect={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByText("Test Team")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("Test Team"));

    expect(mockOnSelect).toHaveBeenCalledWith(
      expect.objectContaining({
        SLACK_INTEGRATION_ID: "int-1",
        SLACK_TEAM_NAME: "Test Team",
        SLACK_TEAM_ID: "T123",
      }),
    );
  });

  it("shows empty state when no integrations are found", async () => {
    server.use(
      http.get("/api/slack/integrations", () => {
        return HttpResponse.json({
          success: true,
          data: [],
        });
      }),
    );

    render(<SlackAppSelector onSelect={mockOnSelect} />);

    await waitFor(
      () => {
        expect(
          screen.getAllByText(/No Slack Workspaces Bridged/i).length,
        ).toBeGreaterThan(0);
      },
      { timeout: 2000 },
    );
  });

  it("handles connect button click", async () => {
    const windowOpenSpy = vi.spyOn(window, "open").mockImplementation(
      () =>
        ({
          closed: false,
        }) as Window,
    );

    server.use(
      http.get("/api/slack/connect", () => {
        return HttpResponse.json({
          success: true,
          data: { authorization_url: "https://slack.com/oauth" },
        });
      }),
    );

    render(<SlackAppSelector onSelect={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByText("Test Team")).toBeInTheDocument();
    });

    const connectBtn = screen.getByText(/Bridge Workspace/i);
    fireEvent.click(connectBtn);

    await waitFor(() => {
      expect(windowOpenSpy).toHaveBeenCalledWith(
        "https://slack.com/oauth",
        "Connect Slack",
        expect.stringContaining("width=600"),
      );
    });

    windowOpenSpy.mockRestore();
  });

  it('shows SlackAppCreator when "Create New App" is clicked', async () => {
    render(<SlackAppSelector onSelect={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByText("Test Team")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /Manifest App/i }));

    await waitFor(() => {
      expect(screen.getAllByText(/Create Slack App/i).length).toBeGreaterThan(
        0,
      );
    });
    expect(screen.getByPlaceholderText(/My Webhook App/i)).toBeInTheDocument();
  });
});
