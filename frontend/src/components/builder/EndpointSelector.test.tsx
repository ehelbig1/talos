import React from "react";
import { render, screen, fireEvent } from "../../test-utils";
import { EndpointSelector } from "./EndpointSelector";
import { vi, describe, it, expect, beforeEach } from "vitest";

describe("EndpointSelector", () => {
  const mockOnConfigure = vi.fn();
  const baseUrl = "https://api.example.com";

  const mockEndpoints = [
    {
      path: "/users/{id}",
      method: "GET",
      summary: "Get user profile",
      parameters: [
        {
          name: "id",
          in: "path" as const,
          required: true,
          type: "string",
          example: "123",
        },
        {
          name: "fields",
          in: "query" as const,
          required: false,
          type: "string",
        },
      ],
    },
    {
      path: "/users",
      method: "POST",
      summary: "Create user",
      requestBody: {
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["username"],
              properties: {
                username: { type: "string", example: "jdoe" },
                age: { type: "number" },
              },
            },
          },
        },
      },
    },
  ];

  beforeEach(() => {
    mockOnConfigure.mockClear();
  });

  it("renders endpoint list initially", () => {
    render(
      <EndpointSelector
        endpoints={mockEndpoints}
        baseUrl={baseUrl}
        onConfigure={mockOnConfigure}
      />,
    );
    expect(screen.getByText("Get user profile")).toBeInTheDocument();
    expect(screen.getByText("Create user")).toBeInTheDocument();
  });

  it("allows selecting an endpoint and configuring path parameters", () => {
    render(
      <EndpointSelector
        endpoints={mockEndpoints}
        baseUrl={baseUrl}
        onConfigure={mockOnConfigure}
      />,
    );

    fireEvent.click(screen.getByText("Get user profile"));

    expect(screen.getByText("/users/{id}")).toBeInTheDocument();
    expect(screen.getByText(/Isolated Path Variables/i)).toBeInTheDocument();

    // Check pre-filled example
    const pathInput = screen.getByPlaceholderText("123");
    expect(pathInput).toHaveValue("123");

    // Add query param (no example/default → placeholder is the fallback)
    fireEvent.change(screen.getByPlaceholderText("IDENTIFIER VALUE..."), {
      target: { value: "id,name" },
    });

    fireEvent.click(screen.getByText(/Finalize Configuration/i));

    expect(mockOnConfigure).toHaveBeenCalledWith({
      method: "GET",
      url: "https://api.example.com/users/123?fields=id%2Cname",
      headers: [],
    });
  });

  it("allows configuring request body", () => {
    render(
      <EndpointSelector
        endpoints={mockEndpoints}
        baseUrl={baseUrl}
        onConfigure={mockOnConfigure}
      />,
    );

    fireEvent.click(screen.getByText("Create user"));

    // Switch to Body tab
    fireEvent.click(screen.getByText(/Request Manifest/i));

    expect(screen.getByText("username")).toBeInTheDocument();

    // Fill form (example "jdoe" is uppercased into the placeholder)
    fireEvent.change(screen.getByPlaceholderText("JDOE"), {
      target: { value: "tester" },
    });

    fireEvent.click(screen.getByText(/Finalize Configuration/i));

    expect(mockOnConfigure).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "POST",
        url: "https://api.example.com/users",
        body: JSON.stringify({ username: "tester" }, null, 2),
      }),
    );

    // Should include Content-Type header
    const call = mockOnConfigure.mock.calls[0][0];
    expect(call.headers).toContainEqual({
      key: "Content-Type",
      value: "application/json",
    });
  });

  it("handles reset/cancel selection", () => {
    render(
      <EndpointSelector
        endpoints={mockEndpoints}
        baseUrl={baseUrl}
        onConfigure={mockOnConfigure}
      />,
    );

    fireEvent.click(screen.getByText("Get user profile"));
    expect(screen.getByText("/users/{id}")).toBeInTheDocument();

    fireEvent.click(screen.getByText("Abort"));
    expect(screen.getByText("Get user profile")).toBeInTheDocument();
  });
});
