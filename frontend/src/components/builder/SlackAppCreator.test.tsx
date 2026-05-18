import React from "react";
import { render, screen, fireEvent, waitFor } from "../../test-utils";
import { SlackAppCreator } from "./SlackAppCreator";
import { server } from "../../../vitest.setup";
import { http, HttpResponse } from "msw";
import { vi, describe, it, expect, beforeEach } from "vitest";

describe("SlackAppCreator", () => {
  const mockOnAppCreated = vi.fn();
  const mockOnCancel = vi.fn();

  beforeEach(() => {
    mockOnAppCreated.mockClear();
    mockOnCancel.mockClear();
  });

  it('renders "info" step initially', () => {
    render(
      <SlackAppCreator
        webhookUrl="https://talos.io/webhook/123"
        eventTypes={["message.channels"]}
        onAppCreated={mockOnAppCreated}
        onCancel={mockOnCancel}
      />,
    );

    expect(screen.getAllByText(/Create Slack App/i).length).toBeGreaterThan(0);
    expect(screen.getByLabelText(/App Name \*/i)).toBeInTheDocument();
    expect(
      screen.getByText(/https:\/\/talos\.io\/webhook\/123/i),
    ).toBeInTheDocument();
  });

  it('moves to "token" step after info', () => {
    render(
      <SlackAppCreator
        webhookUrl="https://talos.io/webhook/123"
        eventTypes={["message.channels"]}
        onAppCreated={mockOnAppCreated}
        onCancel={mockOnCancel}
      />,
    );

    fireEvent.change(screen.getByLabelText(/App Name \*/i), {
      target: { value: "My App" },
    });
    fireEvent.click(screen.getByText(/Next: Authorize/i));

    expect(screen.getByText(/Authorization Required/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/User OAuth Token \*/i)).toBeInTheDocument();
  });

  it("successfully creates an app and shows credentials", async () => {
    server.use(
      http.post("/api/slack/apps/create", () => {
        return HttpResponse.json({
          success: true,
          app_id: "A123",
          client_id: "C123",
          client_secret: "secret",
          signing_secret: "sign",
          verification_token: "v123",
          bot_user_id: "U123",
        });
      }),
    );

    render(
      <SlackAppCreator
        webhookUrl="https://talos.io/webhook/123"
        eventTypes={["message.channels"]}
        onAppCreated={mockOnAppCreated}
        onCancel={mockOnCancel}
      />,
    );

    // Step 1: Info
    fireEvent.change(screen.getByLabelText(/App Name \*/i), {
      target: { value: "My App" },
    });
    fireEvent.click(screen.getByText(/Next: Authorize/i));

    // Step 2: Token
    // We cannot easily set value for uncontrolled input with ref, let's see how fireEvent.change works for it
    const tokenInput = screen.getByLabelText(/User OAuth Token \*/i);
    // Even if it's uncontrolled, setting the value property directly might work
    fireEvent.change(tokenInput, { target: { value: "xoxp-test-token" } });
    fireEvent.click(screen.getByText(/Create App/i));

    // Step 3: Success
    await waitFor(() => {
      expect(screen.getByText(/App Created Successfully/i)).toBeInTheDocument();
      expect(screen.getByText(/App ID:/i)).toBeInTheDocument();
      expect(screen.getByText("A123")).toBeInTheDocument();
    });

    expect(mockOnAppCreated).toHaveBeenCalledWith(
      expect.objectContaining({
        appId: "A123",
        botUserId: "U123",
      }),
    );
  });

  it("handles errors from the API", async () => {
    server.use(
      http.post("/api/slack/apps/create", () => {
        return HttpResponse.json(
          { success: false, error: "Invalid token" },
          { status: 400 },
        );
      }),
    );

    render(
      <SlackAppCreator
        webhookUrl="https://talos.io/webhook/123"
        eventTypes={["message.channels"]}
        onAppCreated={mockOnAppCreated}
        onCancel={mockOnCancel}
      />,
    );

    fireEvent.change(screen.getByLabelText(/App Name \*/i), {
      target: { value: "My App" },
    });
    fireEvent.click(screen.getByText(/Next: Authorize/i));

    const tokenInput = screen.getByLabelText(/User OAuth Token \*/i);
    fireEvent.change(tokenInput, { target: { value: "xoxp-invalid" } });
    fireEvent.click(screen.getByText(/Create App/i));

    await waitFor(() => {
      expect(screen.getByText(/Failed to Create App/i)).toBeInTheDocument();
      expect(
        screen.getByText(/Failed to create Slack app/i),
      ).toBeInTheDocument();
    });
  });
});
